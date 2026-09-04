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
        """Ob der Benutzer Check-Attribute besitzt."""
        stmt = select(func.count()).select_from(RadCheck).where(RadCheck.username == username)
        return bool(await self.session.scalar(stmt))

    async def exists_anywhere(self, username: str) -> bool:
        """Ob der Name in irgendeiner RADIUS-Tabelle vorkommt.

        In einer Bestandsinstallation kann ein Name auch nur Antwortattribute
        oder Gruppenzuordnungen besitzen. Ein Neuanlegen wuerde diese sonst
        stillschweigend ueberschreiben.
        """
        for model in (RadCheck, RadReply, RadUserGroup):
            stmt = select(func.count()).select_from(model).where(model.username == username)
            if await self.session.scalar(stmt):
                return True
        return False

    async def stored_username(self, username: str) -> str | None:
        """Die tatsaechlich gespeicherte Schreibweise zu einem Namen.

        Die Standardkollation von MariaDB vergleicht ohne Ruecksicht auf Gross-
        und Kleinschreibung: ``exists_anywhere`` meldet dann Erfolg, waehrend der
        Aufrufer mit seiner eigenen Schreibweise weiterarbeitet - und Vergleiche
        gegen den gespeicherten Wert (etwa MAC gleich Passwort) scheitern.
        """
        for model in (RadCheck, RadReply, RadUserGroup):
            found = await self.session.scalar(
                select(model.username).where(model.username == username).limit(1)
            )
            if found is not None:
                return str(found)
        return None

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
        """Setzt genau ein Check-Attribut (idempotent).

        ``radcheck`` kennt keine Eindeutigkeit ueber (username, attribute);
        Bestandsdaten koennen mehrere Zeilen desselben Attributs enthalten.
        Deshalb werden alle Duplikate entfernt und genau eine Zeile geschrieben -
        sonst bliebe etwa ein altes Passwort weiter gueltig.
        """
        await self.session.execute(
            delete(RadCheck).where(RadCheck.username == username, RadCheck.attribute == attribute)
        )
        row = RadCheck(username=username, attribute=attribute, op=op, value=value)
        self.session.add(row)
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
