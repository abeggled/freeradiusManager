"""Zugriff auf ``radgroupcheck``, ``radgroupreply`` und ``radusergroup`` (FR-2)."""

from __future__ import annotations

from collections.abc import Sequence

from sqlalchemy import delete, func, select, union, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.identifiers import fold
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

    async def reply_attributes_for(
        self, groupnames: Sequence[str]
    ) -> dict[str, list[RadGroupReply]]:
        """Antwortattribute mehrerer Gruppen in einer Abfrage.

        Eine Abfrage je Gruppe waere bei mehreren hundert Gruppen der teuerste
        Teil des Seitenaufbaus (NFR-2).
        """
        if not groupnames:
            return {}
        rows = await self.session.scalars(
            select(RadGroupReply)
            .where(RadGroupReply.groupname.in_(set(groupnames)))
            .order_by(RadGroupReply.id)
        )
        grouped: dict[str, list[RadGroupReply]] = {}
        for row in rows.all():
            grouped.setdefault(row.groupname, []).append(row)
        return grouped

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

    async def distinct_members(self, groupname: str, limit: int) -> list[str]:
        """Verschiedene Mitglieder - unabhaengig von doppelten Zeilen.

        ``radusergroup`` kennt keine Eindeutigkeit. Ein Blick auf die ersten
        Zeilen zeigte bei vielen Dubletten desselben Benutzers nicht, ob es noch
        ein weiteres Mitglied gibt; die Unterscheidung gehoert deshalb in die
        Abfrage.
        """
        stmt = (
            select(RadUserGroup.username)
            .where(RadUserGroup.groupname == groupname)
            .distinct()
            .order_by(RadUserGroup.username)
            .limit(limit)
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
        """Ersetzt alle Mitgliedschaften eines Benutzers.

        Doppelte Gruppennamen werden zusammengefasst: ``radusergroup`` kennt
        keine Eindeutigkeit, doppelte Zeilen wuerden die Mitgliederzahl
        verfaelschen und die Attribute der Gruppe mehrfach anwenden. Verglichen
        wird in der Vergleichsform der Datenbank - ``Staff`` und ``staff``
        bezeichnen dieselbe Gruppe, ein reiner Zeichenkettenvergleich liesse
        beide Zeilen entstehen.
        """
        await self.session.execute(delete(RadUserGroup).where(RadUserGroup.username == username))
        seen: dict[str, tuple[str, int]] = {}
        for groupname, priority in groups:
            seen.setdefault(fold(groupname), (groupname, priority))
        for groupname, priority in seen.values():
            self.session.add(
                RadUserGroup(username=username, groupname=groupname, priority=priority)
            )
        await self.session.flush()

    async def add_membership(self, username: str, groupname: str, priority: int = 1) -> bool:
        """Fuegt eine Mitgliedschaft hinzu; ``False`` wenn sie bereits bestand.

        Aufrufer serialisieren Pruefung und Einfuegen ueber ``named_lock``:
        ``radusergroup`` kennt keine Eindeutigkeit, gleichzeitige Aufrufe wuerden
        sonst doppelte Zeilen erzeugen."""
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
