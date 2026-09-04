"""Benannte Sperren fuer Operationen ohne Datenbank-Eindeutigkeit.

Die RADIUS-Tabellen kennen keine Unique-Constraints auf Benutzer- oder
Gruppennamen. Wo eine Pruefung und das anschliessende Schreiben zusammen
atomar sein muessen, dient eine anwendungseigene Sperre als Ersatz.
"""

from __future__ import annotations

import contextlib
import hashlib
from collections.abc import AsyncIterator

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_lock_engine
from app.core.errors import ConflictError
from app.core.identifiers import fold
from app.core.logging import get_logger

LOCK_PREFIX = "frm"
LOCK_TIMEOUT_SECONDS = 5

log = get_logger("locking")


def _lock_key(name: str) -> str:
    """Eindeutiger Schluessel innerhalb der 64 Zeichen von ``GET_LOCK``.

    Ein blosses Abschneiden liesse zwei lange Namen auf denselben Schluessel
    fallen - eine Umbenennung zwischen ihnen wartete dann auf sich selbst.

    Verglichen wird in der Vergleichsform der Datenbank: ``group:Staff`` und
    ``group:staff`` bezeichnen dieselben Zeilen, ergaeben aber verschiedene
    Schluessel - beide Aufrufer liefen dann gleichzeitig durch die Sperre.
    """
    folded = fold(name)
    digest = hashlib.sha256(folded.encode("utf-8")).hexdigest()[:16]
    readable = folded[:40]
    return f"{LOCK_PREFIX}:{readable}:{digest}"


@contextlib.asynccontextmanager
async def named_lock(session: AsyncSession, *names: str) -> AsyncIterator[None]:
    """Haelt MariaDB-``GET_LOCK``-Sperren fuer die Dauer des Blocks.

    Die Sperren laufen ueber eine eigene, fuer den ganzen Block gehaltene
    Verbindung. Ueber die Sitzung des Aufrufers gingen sie verloren, sobald
    dessen ``commit()`` die Verbindung an den Pool zurueckgibt - das
    anschliessende ``RELEASE_LOCK`` liefe dann auf einer fremden Verbindung und
    die Sperre bliebe haengen.

    Mehrere Namen werden auf *einer* Verbindung und in sortierter Reihenfolge
    erlangt. Geschachtelte Aufrufe brauchten je eine eigene Verbindung - bei
    einer Mitgliedschaftsliste waere der Sperrpool damit erschoepft - und zwei
    Aufrufer in verschiedener Reihenfolge liefen in eine Verklemmung.

    Laesst sich eine Sperre nicht erlangen, wird abgebrochen. Den Block trotzdem
    zu betreten waere schlimmer als ein Fehler: genau dann laeuft eine zweite,
    noch nicht festgeschriebene Aenderung - und beide wuerden schreiben.
    """
    wanted = {_lock_key(name): name for name in names}
    if not wanted:
        raise ValueError("named_lock benoetigt mindestens einen Namen")
    keys = sorted(wanted)

    # Eigener Pool, damit Sperrverbindungen nicht mit den Abfragen der Anfragen
    # um dieselben Plaetze konkurrieren. Bewusst nicht ``session.bind``: das ist
    # im Betrieb die Abfrage-Engine, die Trennung entfiele damit vollstaendig.
    # Tests richten beide ueber ``db.configure()`` auf dieselbe Engine.
    async with get_lock_engine().connect() as connection:
        held: list[str] = []
        try:
            for key in keys:
                acquired = bool(
                    await connection.scalar(
                        text("SELECT GET_LOCK(:key, :timeout)"),
                        {"key": key, "timeout": LOCK_TIMEOUT_SECONDS},
                    )
                )
                if not acquired:
                    log.warning("named_lock_timeout", key=key)
                    raise ConflictError(code="error.busy", details={"resource": wanted[key]})
                held.append(key)
            # MariaDB faehrt REPEATABLE READ: die Sitzung des Aufrufers hat
            # ihren Lesestand meist schon beim Lesen des Kontos festgelegt.
            # Wer hier auf die Sperre gewartet hat, saehe den soeben
            # festgeschriebenen Stand des anderen sonst nicht - beide Pruefungen
            # gingen durch und beide schrieben. Ein Rollback verwirft nur den
            # Lesestand; anstehende Aenderungen gibt es an dieser Stelle nicht.
            if session.in_transaction() and not (
                session.new or session.dirty or session.deleted
            ):
                await session.rollback()
            yield
        finally:
            # Gebunden statt eingesetzt: ein Name wie O'Reilly ergaebe sonst
            # ungueltiges SQL - und die Sperre bliebe an der Verbindung haengen.
            for key in reversed(held):
                await connection.execute(text("SELECT RELEASE_LOCK(:key)"), {"key": key})
