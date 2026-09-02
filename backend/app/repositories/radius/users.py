"""Zugriff auf ``radcheck``/``radreply``.

An das FreeRADIUS-Schema gebunden – bei Server-Upgrades zuerst hier pruefen.
"""

from __future__ import annotations

from collections.abc import Sequence

from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.radius import RadCheck, RadReply, RadUserGroup
from app.repositories._result import rowcount


class UserAttributeRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    # --- Lesen -----------------------------------------------------------

    async def check_attributes(self, username: str) -> Sequence[RadCheck]:
        stmt = select(RadCheck).where(RadCheck.username == username).order_by(RadCheck.id)
        return (await self.session.scalars(stmt)).all()

    async def reply_attributes(self, username: str) -> Sequence[RadReply]:
        stmt = select(RadReply).where(RadReply.username == username).order_by(RadReply.id)
        return (await self.session.scalars(stmt)).all()

    async def check_attributes_for(self, usernames: Sequence[str]) -> list[RadCheck]:
        if not usernames:
            return []
        stmt = select(RadCheck).where(RadCheck.username.in_(usernames))
        return list((await self.session.scalars(stmt)).all())

    async def exists(self, username: str) -> bool:
        stmt = select(func.count()).select_from(RadCheck).where(RadCheck.username == username)
        return bool(await self.session.scalar(stmt))

    async def find_check(self, username: str, attribute: str) -> RadCheck | None:
        stmt = select(RadCheck).where(
            RadCheck.username == username, RadCheck.attribute == attribute
        )
        return await self.session.scalar(stmt)

    async def usernames(self) -> list[str]:
        stmt = select(RadCheck.username).distinct().order_by(RadCheck.username)
        return list((await self.session.scalars(stmt)).all())

    # --- Schreiben -------------------------------------------------------

    async def set_check(self, username: str, attribute: str, op: str, value: str) -> RadCheck:
        """Setzt genau ein Check-Attribut (idempotent)."""
        row = await self.find_check(username, attribute)
        if row is None:
            row = RadCheck(username=username, attribute=attribute, op=op, value=value)
            self.session.add(row)
        else:
            row.op = op
            row.value = value
        await self.session.flush()
        return row

    async def add_check(self, username: str, attribute: str, op: str, value: str) -> RadCheck:
        """Fuegt ein weiteres Check-Attribut hinzu (Mehrfachwerte erlaubt)."""
        row = RadCheck(username=username, attribute=attribute, op=op, value=value)
        self.session.add(row)
        await self.session.flush()
        return row

    async def delete_check(self, username: str, attribute: str) -> int:
        stmt = delete(RadCheck).where(
            RadCheck.username == username, RadCheck.attribute == attribute
        )
        return rowcount(await self.session.execute(stmt))

    async def add_reply(self, username: str, attribute: str, op: str, value: str) -> RadReply:
        row = RadReply(username=username, attribute=attribute, op=op, value=value)
        self.session.add(row)
        await self.session.flush()
        return row

    async def delete_reply(self, username: str, attribute: str) -> int:
        stmt = delete(RadReply).where(
            RadReply.username == username, RadReply.attribute == attribute
        )
        return rowcount(await self.session.execute(stmt))

    async def delete_check_row(self, row_id: int) -> int:
        return rowcount(await self.session.execute(delete(RadCheck).where(RadCheck.id == row_id)))

    async def delete_reply_row(self, row_id: int) -> int:
        return rowcount(await self.session.execute(delete(RadReply).where(RadReply.id == row_id)))

    async def replace_replies(self, username: str, rows: Sequence[tuple[str, str, str]]) -> None:
        """Ersetzt alle Antwortattribute eines Benutzers in einem Rutsch."""
        await self.session.execute(delete(RadReply).where(RadReply.username == username))
        for attribute, op, value in rows:
            self.session.add(RadReply(username=username, attribute=attribute, op=op, value=value))
        await self.session.flush()

    async def delete_user(self, username: str) -> None:
        """Loescht Benutzer samt Antwortattributen und Gruppenzuordnungen."""
        for model in (RadCheck, RadReply, RadUserGroup):
            await self.session.execute(delete(model).where(model.username == username))

    async def rename(self, old: str, new: str) -> None:
        """Benennt einen Benutzer um. Muss zusammen mit ``mgr_subject`` in einer
        Transaktion laufen (Abschnitt 4.1)."""
        for model in (RadCheck, RadReply, RadUserGroup):
            await self.session.execute(
                update(model).where(model.username == old).values(username=new)
            )
