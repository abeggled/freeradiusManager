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
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from app.core.db import get_lock_engine
from app.core.errors import ConflictError
from app.core.logging import get_logger

LOCK_PREFIX = "frm"
LOCK_TIMEOUT_SECONDS = 5

log = get_logger("locking")


def _lock_key(name: str) -> str:
    """Eindeutiger Schluessel innerhalb der 64 Zeichen von ``GET_LOCK``.

    Ein blosses Abschneiden liesse zwei lange Namen auf denselben Schluessel
    fallen - eine Umbenennung zwischen ihnen wartete dann auf sich selbst.
    """
    digest = hashlib.sha256(name.encode("utf-8")).hexdigest()[:16]
    readable = name[:40]
    return f"{LOCK_PREFIX}:{readable}:{digest}"


@contextlib.asynccontextmanager
async def named_lock(session: AsyncSession, name: str) -> AsyncIterator[None]:
    """Haelt eine MariaDB-``GET_LOCK``-Sperre fuer die Dauer des Blocks.

    Die Sperre laeuft ueber eine eigene, fuer den ganzen Block gehaltene
    Verbindung. Ueber die Sitzung des Aufrufers ginge sie verloren, sobald
    dessen ``commit()`` die Verbindung an den Pool zurueckgibt - das
    anschliessende ``RELEASE_LOCK`` liefe dann auf einer fremden Verbindung und
    die Sperre bliebe haengen.

    Laesst sie sich nicht erlangen, wird abgebrochen. Den Block trotzdem zu
    betreten waere schlimmer als ein Fehler: genau dann laeuft eine zweite, noch
    nicht festgeschriebene Aenderung - und beide wuerden schreiben.
    """
    key = _lock_key(name)
    # Eigener Pool, damit Sperrverbindungen nicht mit den Abfragen der Anfragen
    # um dieselben Plaetze konkurrieren. In Tests zeigt er auf dieselbe Engine.
    engine = session.bind if isinstance(session.bind, AsyncEngine) else get_lock_engine()
    async with engine.connect() as connection:
        acquired = bool(
            await connection.scalar(
                text("SELECT GET_LOCK(:key, :timeout)"),
                {"key": key, "timeout": LOCK_TIMEOUT_SECONDS},
            )
        )
        if not acquired:
            log.warning("named_lock_timeout", key=key)
            raise ConflictError(code="error.busy", details={"resource": name})
        try:
            yield
        finally:
            # Gebunden statt eingesetzt: ein Name wie O'Reilly ergaebe sonst
            # ungueltiges SQL - und die Sperre bliebe an der Verbindung haengen.
            await connection.execute(text("SELECT RELEASE_LOCK(:key)"), {"key": key})
