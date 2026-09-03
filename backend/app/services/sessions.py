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
    """Viele APs liefern ``<AP-MAC>:<SSID>`` in Called-Station-Id.

    Eine reine BSSID in Doppelpunktschreibweise (``00:11:22:33:44:55``) enthaelt
    keine SSID - sonst gaebe das letzte Oktett eine erfundene SSID.
    """
    value = (called_station_id or "").strip()
    if not value or is_mac(value):
        return None
    if ":" not in value:
        return None
    candidate = value.rsplit(":", 1)[-1].strip()
    if candidate and not is_mac(candidate) and len(candidate) > 1:
        return candidate
    return None


class SessionService:
    def __init__(self, session: AsyncSession) -> None:
        self.repo = AccountingRepository(session)
        self.nas = NasRepository(session)

    async def _decorate(self, page: KeysetPage[RadAcct]) -> list[SessionItem]:
        addresses = [row.nasipaddress for row in page.items]
        shortnames = await self.nas.shortnames_for(addresses)
        # NAS duerfen als Netz eingetragen sein; ohne diese Aufloesung fehlte der
        # Kurzname genau dort, wo Diagnose und CoA ihn finden (FR-4).
        for address in {a for a in addresses if a and a not in shortnames}:
            match = await self.nas.find_for_address(address)
            if match is not None:
                shortnames[address] = match.shortname
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
