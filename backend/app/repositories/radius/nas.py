"""Zugriff auf die ``nas``-Tabelle (FR-4)."""

from __future__ import annotations

import ipaddress
from collections.abc import Sequence

from sqlalchemy import delete, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.radius import Nas
from app.repositories._result import rowcount


class NasRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get(self, nas_id: int) -> Nas | None:
        return await self.session.get(Nas, nas_id)

    async def get_by_name(self, nasname: str) -> Nas | None:
        return await self.session.scalar(select(Nas).where(Nas.nasname == nasname))

    async def search(
        self, search: str | None = None, limit: int = 50, offset: int = 0
    ) -> tuple[Sequence[Nas], int]:
        stmt = select(Nas)
        count_stmt = select(func.count()).select_from(Nas)
        if search:
            pattern = f"%{search}%"
            condition = or_(
                Nas.nasname.like(pattern),
                Nas.shortname.like(pattern),
                Nas.description.like(pattern),
            )
            stmt = stmt.where(condition)
            count_stmt = count_stmt.where(condition)
        stmt = stmt.order_by(Nas.nasname).limit(limit).offset(offset)
        items = (await self.session.scalars(stmt)).all()
        total = int(await self.session.scalar(count_stmt) or 0)
        return items, total

    async def find_for_address(self, address: str) -> Nas | None:
        """NAS zu einer konkreten IP - exakt oder ueber das passende Netz.

        Bei mehreren passenden Netzen gewinnt das spezifischste.
        """
        exact = await self.get_by_name(address)
        if exact is not None:
            return exact
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return None
        rows = await self.session.scalars(select(Nas).where(Nas.nasname.like("%/%")))
        best: tuple[int, Nas] | None = None
        for row in rows.all():
            try:
                network = ipaddress.ip_network(row.nasname, strict=False)
            except ValueError:
                continue
            if ip in network and (best is None or network.prefixlen > best[0]):
                best = (network.prefixlen, row)
        return best[1] if best else None

    async def shortnames_for(self, nasnames: Sequence[str]) -> dict[str, str | None]:
        """Kurznamen mehrerer NAS in einer Abfrage - eine Runde je Adresse waere
        bei bis zu 200 Zeilen je Seite der teuerste Teil des Requests (NFR-2)."""
        if not nasnames:
            return {}
        rows = await self.session.execute(
            select(Nas.nasname, Nas.shortname).where(Nas.nasname.in_(set(nasnames)))
        )
        return {str(name): shortname for name, shortname in rows.all()}

    async def all_names(self) -> set[str]:
        return set((await self.session.scalars(select(Nas.nasname))).all())

    async def create(self, **values: object) -> Nas:
        row = Nas(**values)
        self.session.add(row)
        await self.session.flush()
        return row

    async def delete(self, nas_id: int) -> int:
        return rowcount(await self.session.execute(delete(Nas).where(Nas.id == nas_id)))
