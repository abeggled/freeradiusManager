"""Benannte Sperren fuer Operationen ohne Datenbank-Eindeutigkeit.

Die RADIUS-Tabellen kennen keine Unique-Constraints auf Benutzer- oder
Gruppennamen. Wo eine Pruefung und das anschliessende Schreiben zusammen
atomar sein muessen, dient eine anwendungseigene Sperre als Ersatz.
"""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger

LOCK_PREFIX = "frm"
LOCK_TIMEOUT_SECONDS = 5

log = get_logger("locking")


@contextlib.asynccontextmanager
async def named_lock(session: AsyncSession, name: str) -> AsyncIterator[bool]:
    """Haelt eine MariaDB-``GET_LOCK``-Sperre fuer die Dauer des Blocks.

    Kann die Sperre nicht erlangt werden, laeuft der Block trotzdem weiter: die
    Serialisierung ist eine Absicherung gegen ein seltenes Wettrennen, kein
    Grund, den Aufruf scheitern zu lassen.
    """
    key = f"{LOCK_PREFIX}:{name}"[:64]
    acquired = False
    try:
        acquired = bool(
            await session.scalar(
                text("SELECT GET_LOCK(:key, :timeout)"),
                {"key": key, "timeout": LOCK_TIMEOUT_SECONDS},
            )
        )
        if not acquired:
            log.warning("named_lock_timeout", key=key)
        yield acquired
    finally:
        if acquired:
            await session.execute(text("SELECT RELEASE_LOCK(:key)"), {"key": key})
