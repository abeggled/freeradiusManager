"""Metadaten zu Benutzern und Geraeten (``mgr_subject``)."""

from __future__ import annotations

from collections.abc import Sequence

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.mgr import MgrSubject, SubjectType
from app.repositories._result import rowcount


class SubjectRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get(self, username: str) -> MgrSubject | None:
        return await self.session.scalar(select(MgrSubject).where(MgrSubject.username == username))

    async def get_many(self, usernames: Sequence[str]) -> dict[str, MgrSubject]:
        if not usernames:
            return {}
        rows = await self.session.scalars(
            select(MgrSubject).where(MgrSubject.username.in_(usernames))
        )
        return {row.username: row for row in rows.all()}

    async def add(self, subject: MgrSubject) -> MgrSubject:
        self.session.add(subject)
        await self.session.flush()
        return subject

    async def ensure(
        self, username: str, subject_type: SubjectType = SubjectType.USER
    ) -> MgrSubject:
        existing = await self.get(username)
        if existing is not None:
            return existing
        return await self.add(MgrSubject(username=username, subject_type=subject_type))

    async def delete(self, username: str) -> int:
        stmt = delete(MgrSubject).where(MgrSubject.username == username)
        return rowcount(await self.session.execute(stmt))

    async def rename(self, old: str, new: str) -> None:
        await self.session.execute(
            update(MgrSubject).where(MgrSubject.username == old).values(username=new)
        )

    async def usernames_of_type(self, subject_type: SubjectType) -> list[str]:
        stmt = select(MgrSubject.username).where(MgrSubject.subject_type == subject_type)
        return list((await self.session.scalars(stmt)).all())
