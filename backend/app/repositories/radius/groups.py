"""Zugriff auf ``radgroupcheck``, ``radgroupreply`` und ``radusergroup`` (FR-2)."""

from __future__ import annotations

from collections.abc import Sequence

from sqlalchemy import delete, func, select, union, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.radius import RadGroupCheck, RadGroupReply, RadUserGroup
from app.repositories._result import rowcount


class GroupRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    # --- Gruppen ---------------------------------------------------------

    async def group_names(self) -> list[str]:
        """Alle Gruppen, die irgendwo referenziert werden."""
        stmt = union(
            select(RadGroupCheck.groupname.label("groupname")),
            select(RadGroupReply.groupname.label("groupname")),
            select(RadUserGroup.groupname.label("groupname")),
        )
        rows = await self.session.execute(select(stmt.c.groupname).order_by(stmt.c.groupname))
        return [r for r in rows.scalars().all() if r]

    async def exists(self, groupname: str) -> bool:
        for model in (RadGroupCheck, RadGroupReply, RadUserGroup):
            stmt = select(func.count()).select_from(model).where(model.groupname == groupname)
            if await self.session.scalar(stmt):
                return True
        return False

    async def check_attributes(self, groupname: str) -> Sequence[RadGroupCheck]:
        stmt = (
            select(RadGroupCheck)
            .where(RadGroupCheck.groupname == groupname)
            .order_by(RadGroupCheck.id)
        )
        return (await self.session.scalars(stmt)).all()

    async def reply_attributes(self, groupname: str) -> Sequence[RadGroupReply]:
        stmt = (
            select(RadGroupReply)
            .where(RadGroupReply.groupname == groupname)
            .order_by(RadGroupReply.id)
        )
        return (await self.session.scalars(stmt)).all()

    async def member_counts(self) -> dict[str, int]:
        stmt = select(RadUserGroup.groupname, func.count()).group_by(RadUserGroup.groupname)
        rows = (await self.session.execute(stmt)).all()
        return {str(name): int(count) for name, count in rows}

    async def member_count(self, groupname: str) -> int:
        stmt = (
            select(func.count())
            .select_from(RadUserGroup)
            .where(RadUserGroup.groupname == groupname)
        )
        return int(await self.session.scalar(stmt) or 0)

    async def members(self, groupname: str, limit: int, offset: int) -> list[str]:
        stmt = (
            select(RadUserGroup.username)
            .where(RadUserGroup.groupname == groupname)
            .order_by(RadUserGroup.username)
            .limit(limit)
            .offset(offset)
        )
        return list((await self.session.scalars(stmt)).all())

    async def add_check(self, groupname: str, attribute: str, op: str, value: str) -> RadGroupCheck:
        row = RadGroupCheck(groupname=groupname, attribute=attribute, op=op, value=value)
        self.session.add(row)
        await self.session.flush()
        return row

    async def add_reply(self, groupname: str, attribute: str, op: str, value: str) -> RadGroupReply:
        row = RadGroupReply(groupname=groupname, attribute=attribute, op=op, value=value)
        self.session.add(row)
        await self.session.flush()
        return row

    async def replace_attributes(
        self,
        groupname: str,
        checks: Sequence[tuple[str, str, str]],
        replies: Sequence[tuple[str, str, str]],
    ) -> None:
        await self.session.execute(
            delete(RadGroupCheck).where(RadGroupCheck.groupname == groupname)
        )
        await self.session.execute(
            delete(RadGroupReply).where(RadGroupReply.groupname == groupname)
        )
        for attribute, op, value in checks:
            self.session.add(
                RadGroupCheck(groupname=groupname, attribute=attribute, op=op, value=value)
            )
        for attribute, op, value in replies:
            self.session.add(
                RadGroupReply(groupname=groupname, attribute=attribute, op=op, value=value)
            )
        await self.session.flush()

    async def delete_group(self, groupname: str) -> None:
        for model in (RadGroupCheck, RadGroupReply, RadUserGroup):
            await self.session.execute(delete(model).where(model.groupname == groupname))

    async def rename_group(self, old: str, new: str) -> None:
        for model in (RadGroupCheck, RadGroupReply, RadUserGroup):
            await self.session.execute(
                update(model).where(model.groupname == old).values(groupname=new)
            )

    # --- Mitgliedschaften ------------------------------------------------

    async def memberships(self, username: str) -> Sequence[RadUserGroup]:
        stmt = (
            select(RadUserGroup)
            .where(RadUserGroup.username == username)
            .order_by(RadUserGroup.priority, RadUserGroup.groupname)
        )
        return (await self.session.scalars(stmt)).all()

    async def memberships_for(self, usernames: Sequence[str]) -> list[RadUserGroup]:
        if not usernames:
            return []
        stmt = (
            select(RadUserGroup)
            .where(RadUserGroup.username.in_(usernames))
            .order_by(RadUserGroup.priority)
        )
        return list((await self.session.scalars(stmt)).all())

    async def set_memberships(self, username: str, groups: Sequence[tuple[str, int]]) -> None:
        await self.session.execute(delete(RadUserGroup).where(RadUserGroup.username == username))
        for groupname, priority in groups:
            self.session.add(
                RadUserGroup(username=username, groupname=groupname, priority=priority)
            )
        await self.session.flush()

    async def add_membership(self, username: str, groupname: str, priority: int = 1) -> bool:
        """Fuegt eine Mitgliedschaft hinzu; ``False`` wenn sie bereits bestand."""
        stmt = select(RadUserGroup).where(
            RadUserGroup.username == username, RadUserGroup.groupname == groupname
        )
        if await self.session.scalar(stmt) is not None:
            return False
        self.session.add(RadUserGroup(username=username, groupname=groupname, priority=priority))
        await self.session.flush()
        return True

    async def remove_membership(self, username: str, groupname: str) -> int:
        stmt = delete(RadUserGroup).where(
            RadUserGroup.username == username, RadUserGroup.groupname == groupname
        )
        return rowcount(await self.session.execute(stmt))
