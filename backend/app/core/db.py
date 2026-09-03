"""Datenbankanbindung. Die Anwendung nutzt einen eigenen DB-Benutzer (NFR-1)."""

from __future__ import annotations

from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import Settings, settings

_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def create_engine(config: Settings | None = None) -> AsyncEngine:
    config = config or settings
    return create_async_engine(
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


def get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        _engine = create_engine()
    return _engine


def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    global _sessionmaker
    if _sessionmaker is None:
        _sessionmaker = async_sessionmaker(get_engine(), expire_on_commit=False, autoflush=False)
    return _sessionmaker


def configure(engine: AsyncEngine) -> None:
    """Wird von Tests genutzt, um gegen eine Testcontainer-DB zu fahren."""
    global _engine, _sessionmaker
    _engine = engine
    _sessionmaker = async_sessionmaker(engine, expire_on_commit=False, autoflush=False)


async def dispose() -> None:
    global _engine, _sessionmaker
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _sessionmaker = None


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI-Dependency: eine Session je Request, Commit durch die Services."""
    async with get_sessionmaker()() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
