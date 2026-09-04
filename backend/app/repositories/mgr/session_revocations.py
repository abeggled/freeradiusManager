"""Abgemeldete Sitzungen (FR-10)."""

from __future__ import annotations

import datetime as dt

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.mgr import MgrSessionRevocation
from app.repositories._result import rowcount


class SessionRevocationRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def revoke(self, session_id: str, account_id: int, expires_at: dt.datetime) -> None:
        """Merkt eine Sitzungskennung als entwertet (idempotent)."""
        existing = await self.session.get(MgrSessionRevocation, session_id)
        if existing is not None:
            existing.expires_at = max(existing.expires_at, expires_at)
            return
        self.session.add(
            MgrSessionRevocation(
                session_id=session_id, account_id=account_id, expires_at=expires_at
            )
        )
        await self.session.flush()

    async def is_revoked(self, session_id: str) -> bool:
        stmt = (
            select(func.count())
            .select_from(MgrSessionRevocation)
            .where(MgrSessionRevocation.session_id == session_id)
        )
        return bool(await self.session.scalar(stmt))

    async def purge_expired(self, now: dt.datetime) -> int:
        """Entfernt Eintraege, deren Token ohnehin abgelaufen ist."""
        stmt = delete(MgrSessionRevocation).where(MgrSessionRevocation.expires_at < now)
        return rowcount(await self.session.execute(stmt))
