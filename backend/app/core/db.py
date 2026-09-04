"""Datenbankanbindung. Die Anwendung nutzt einen eigenen DB-Benutzer (NFR-1)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import Settings, settings

_engine: AsyncEngine | None = None
_lock_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def _use_english_month_names(engine: AsyncEngine) -> AsyncEngine:
    """Stellt ``lc_time_names`` je Verbindung auf Englisch.

    Der Statusfilter liest ``Expiration`` mit ``STR_TO_DATE(..., '%b', ...)``.
    Die Monatsnamen schreibt der Manager immer englisch; unter einer anderen
    Datenbank-Locale ergaebe die Umwandlung NULL und der Filter lieferte eine
    andere Menge als die Statusberechnung in Python (NFR-4).
    """

    @event.listens_for(engine.sync_engine, "connect")
    def _set_locale(dbapi_connection: Any, _record: Any) -> None:
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("SET SESSION lc_time_names = 'en_US'")
        finally:
            cursor.close()

    return engine


def create_engine(config: Settings | None = None) -> AsyncEngine:
    config = config or settings
    return _use_english_month_names(
        create_async_engine(
            config.database_url,
            echo=config.db_echo,
            # Bei aktiviertem Echo bleiben die gebundenen Werte aussen vor: sonst
            # stuenden Passwoerter und Secrets im Anwendungsprotokoll (NFR-1).
            hide_parameters=True,
            pool_size=config.db_pool_size,
            max_overflow=config.db_pool_max_overflow,
            pool_pre_ping=True,
            pool_recycle=1800,
        )
    )


def get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        _engine = create_engine()
    return _engine


def get_lock_engine() -> AsyncEngine:
    """Eigener, kleiner Pool fuer benannte Sperren.

    Wuerden sie sich den Abfragepool teilen, koennten mehrere gleichzeitige
    Anfragen alle Plaetze mit Sperrverbindungen belegen und keine mehr
    weiterarbeiten (siehe app/core/locking.py).
    """
    global _lock_engine
    if _lock_engine is None:
        _lock_engine = create_async_engine(
            settings.database_url,
            pool_size=settings.db_pool_size,
            max_overflow=settings.db_pool_max_overflow,
            pool_pre_ping=True,
            pool_recycle=1800,
            hide_parameters=True,
        )
    return _lock_engine


def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    global _sessionmaker
    if _sessionmaker is None:
        _sessionmaker = async_sessionmaker(get_engine(), expire_on_commit=False, autoflush=False)
    return _sessionmaker


def configure(engine: AsyncEngine) -> None:
    """Wird von Tests genutzt, um gegen eine Testcontainer-DB zu fahren."""
    global _engine, _lock_engine, _sessionmaker
    # Auch hier: die Tests sollen dieselbe Datumsauswertung sehen wie der
    # Betrieb (siehe ``_use_english_month_names``).
    _use_english_month_names(engine)
    _engine = engine
    _lock_engine = engine
    _sessionmaker = async_sessionmaker(engine, expire_on_commit=False, autoflush=False)


async def dispose() -> None:
    global _engine, _lock_engine, _sessionmaker
    if _engine is not None:
        await _engine.dispose()
    if _lock_engine is not None and _lock_engine is not _engine:
        await _lock_engine.dispose()
    _engine = None
    _lock_engine = None
    _sessionmaker = None


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI-Dependency: eine Session je Request, Commit durch die Services."""
    async with get_sessionmaker()() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
