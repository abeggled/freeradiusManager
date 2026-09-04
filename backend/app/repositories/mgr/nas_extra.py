"""CoA-Zusatzdaten je NAS (``mgr_nas_extra``, FR-7)."""

from __future__ import annotations

from collections.abc import Sequence

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.mgr import MgrNasExtra
from app.repositories._result import rowcount


class NasExtraRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get(self, nasname: str) -> MgrNasExtra | None:
        return await self.session.scalar(select(MgrNasExtra).where(MgrNasExtra.nasname == nasname))

    async def get_many(self, nasnames: Sequence[str]) -> dict[str, MgrNasExtra]:
        if not nasnames:
            return {}
        rows = await self.session.scalars(
            select(MgrNasExtra).where(MgrNasExtra.nasname.in_(nasnames))
        )
        return {row.nasname: row for row in rows.all()}

    async def with_coa(self) -> list[MgrNasExtra]:
        """Alle Eintraege mit aktivem CoA - Basis fuer die Netzsuche (FR-7)."""
        rows = await self.session.scalars(
            select(MgrNasExtra).where(MgrNasExtra.coa_enabled.is_(True))
        )
        return list(rows.all())

    async def upsert(
        self,
        nasname: str,
        *,
        coa_enabled: bool | None = None,
        coa_port: int | None = None,
        coa_secret_enc: str | None = None,
        note: str | None = None,
    ) -> MgrNasExtra:
        row = await self.get(nasname)
        if row is None:
            row = MgrNasExtra(nasname=nasname)
            self.session.add(row)
        if coa_enabled is not None:
            row.coa_enabled = coa_enabled
        if coa_port is not None:
            row.coa_port = coa_port
        if coa_secret_enc is not None:
            row.coa_secret_enc = coa_secret_enc
        if note is not None:
            row.note = note
        await self.session.flush()
        return row

    async def rename(self, old: str, new: str) -> None:
        await self.session.execute(
            update(MgrNasExtra).where(MgrNasExtra.nasname == old).values(nasname=new)
        )

    async def delete(self, nasname: str) -> int:
        stmt = delete(MgrNasExtra).where(MgrNasExtra.nasname == nasname)
        return rowcount(await self.session.execute(stmt))
