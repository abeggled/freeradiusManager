"""Audit-Log (``mgr_audit``, FR-9). Es gibt bewusst keine Update-/Delete-Methode
fuer einzelne Eintraege – nur das Aufraeumen nach Aufbewahrungsfrist."""

from __future__ import annotations

import datetime as dt

from sqlalchemy import ColumnElement, delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.mgr import MgrAudit
from app.repositories._result import rowcount


class AuditRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def add(self, entry: MgrAudit) -> MgrAudit:
        self.session.add(entry)
        await self.session.flush()
        return entry

    async def search(
        self,
        *,
        actor: str | None = None,
        action: str | None = None,
        object_type: str | None = None,
        object_id: str | None = None,
        date_from: dt.datetime | None = None,
        date_to: dt.datetime | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[MgrAudit], int]:
        conditions: list[ColumnElement[bool]] = []
        if actor:
            conditions.append(MgrAudit.actor_name == actor)
        if action:
            conditions.append(MgrAudit.action == action)
        if object_type:
            conditions.append(MgrAudit.object_type == object_type)
        if object_id:
            conditions.append(MgrAudit.object_id == object_id)
        if date_from:
            conditions.append(MgrAudit.ts >= date_from)
        if date_to:
            conditions.append(MgrAudit.ts <= date_to)

        stmt = (
            select(MgrAudit)
            .where(*conditions)
            .order_by(MgrAudit.id.desc())
            .limit(limit)
            .offset(offset)
        )
        total = int(
            await self.session.scalar(select(func.count()).select_from(MgrAudit).where(*conditions))
            or 0
        )
        return list((await self.session.scalars(stmt)).all()), total

    async def purge_older_than(self, cutoff: dt.datetime) -> int:
        stmt = delete(MgrAudit).where(MgrAudit.ts < cutoff)
        return rowcount(await self.session.execute(stmt))
