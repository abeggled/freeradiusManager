"""Session-Uebersicht (FR-5).

Serverseitige Keyset-Paginierung, keine ungefilterten Vollabfragen (NFR-2).
"""

from __future__ import annotations

import re

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import NotFoundError
from app.core.mac import is_mac
from app.core.pagination import KeysetPage
from app.models.radius import RadAcct
from app.repositories.radius.acct import AccountingRepository, SessionFilter
from app.repositories.radius.nas import NasRepository
from app.schemas.sessions import SessionItem

_SSID_PATTERN = re.compile(r"[:\-]?([^:\-]{2,})$")


def extract_ssid(called_station_id: str | None) -> str | None:
    """Viele APs liefern ``<AP-MAC>:<SSID>`` in Called-Station-Id."""
    if not called_station_id:
        return None
    if ":" in called_station_id:
        candidate = called_station_id.rsplit(":", 1)[-1].strip()
        if candidate and not is_mac(candidate) and len(candidate) > 1:
            return candidate
    return None


class SessionService:
    def __init__(self, session: AsyncSession) -> None:
        self.repo = AccountingRepository(session)
        self.nas = NasRepository(session)

    async def _decorate(self, page: KeysetPage[RadAcct]) -> list[SessionItem]:
        shortnames = await self.nas.shortnames_for([row.nasipaddress for row in page.items])
        items: list[SessionItem] = []
        for row in page.items:
            item = SessionItem.model_validate(row)
            item.active = row.acctstoptime is None
            item.ssid = extract_ssid(row.calledstationid)
            item.nas_shortname = shortnames.get(row.nasipaddress)
            items.append(item)
        return items

    async def search(
        self, flt: SessionFilter, limit: int | None = None, cursor: str | None = None
    ) -> tuple[list[SessionItem], str | None, int]:
        page = await self.repo.search(flt, limit=limit, cursor=cursor)
        approx = await self.repo.count(flt)
        return await self._decorate(page), page.next_cursor, approx

    async def get(self, radacctid: int) -> SessionItem:
        row = await self.repo.get(radacctid)
        if row is None:
            raise NotFoundError(code="error.not_found", details={"radacctid": radacctid})
        page: KeysetPage[RadAcct] = KeysetPage(items=[row])
        return (await self._decorate(page))[0]

    async def terminate_causes(self) -> list[str]:
        return await self.repo.terminate_causes()
