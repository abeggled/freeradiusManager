"""Accounting-Abfragen auf ``radacct`` (FR-5).

Alle Listenabfragen laufen mit Keyset-Pagination ueber ``radacctid`` und nutzen
die vorhandenen Indizes; ungefilterte Vollabfragen gibt es bewusst nicht (NFR-2).
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from typing import Any

from sqlalchemy import ColumnElement, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.pagination import KeysetPage, clamp_limit, decode_cursor, encode_cursor
from app.models.radius import RadAcct


@dataclass(slots=True)
class SessionFilter:
    username: str | None = None
    calling_station_id: str | None = None
    nas_ip_address: str | None = None
    called_station_id: str | None = None
    framed_ip_address: str | None = None
    terminate_cause: str | None = None
    start_from: dt.datetime | None = None
    start_to: dt.datetime | None = None
    active_only: bool = False


class AccountingRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    def _conditions(self, flt: SessionFilter) -> list[ColumnElement[bool]]:
        conditions: list[ColumnElement[bool]] = []
        if flt.username:
            conditions.append(RadAcct.username == flt.username)
        if flt.calling_station_id:
            conditions.append(RadAcct.callingstationid == flt.calling_station_id)
        if flt.nas_ip_address:
            conditions.append(RadAcct.nasipaddress == flt.nas_ip_address)
        if flt.called_station_id:
            conditions.append(RadAcct.calledstationid.like(f"%{flt.called_station_id}%"))
        if flt.framed_ip_address:
            conditions.append(RadAcct.framedipaddress == flt.framed_ip_address)
        if flt.terminate_cause:
            conditions.append(RadAcct.acctterminatecause == flt.terminate_cause)
        if flt.start_from:
            conditions.append(RadAcct.acctstarttime >= flt.start_from)
        if flt.start_to:
            conditions.append(RadAcct.acctstarttime <= flt.start_to)
        if flt.active_only:
            conditions.append(RadAcct.acctstoptime.is_(None))
        return conditions

    async def search(
        self, flt: SessionFilter, limit: int | None = None, cursor: str | None = None
    ) -> KeysetPage[RadAcct]:
        limit = clamp_limit(limit)
        stmt = select(RadAcct).where(*self._conditions(flt))
        position = decode_cursor(cursor)
        if position and "id" in position:
            stmt = stmt.where(RadAcct.radacctid < int(position["id"]))
        stmt = stmt.order_by(RadAcct.radacctid.desc()).limit(limit + 1)
        rows = list((await self.session.scalars(stmt)).all())
        next_cursor = None
        if len(rows) > limit:
            rows = rows[:limit]
            next_cursor = encode_cursor({"id": rows[-1].radacctid})
        return KeysetPage(items=rows, next_cursor=next_cursor, limit=limit)

    async def count(self, flt: SessionFilter, ceiling: int = 10_000) -> int:
        """Gedeckelte Zaehlung – eine exakte Gesamtzahl ueber Millionen Zeilen
        waere zu teuer (NFR-2)."""
        inner = select(RadAcct.radacctid).where(*self._conditions(flt)).limit(ceiling).subquery()
        return int(await self.session.scalar(select(func.count()).select_from(inner)) or 0)

    async def get(self, radacctid: int) -> RadAcct | None:
        return await self.session.get(RadAcct, radacctid)

    async def get_by_unique_id(self, acctuniqueid: str) -> RadAcct | None:
        stmt = select(RadAcct).where(RadAcct.acctuniqueid == acctuniqueid)
        return await self.session.scalar(stmt)

    async def active_for_user(self, username: str) -> list[RadAcct]:
        stmt = (
            select(RadAcct)
            .where(RadAcct.username == username, RadAcct.acctstoptime.is_(None))
            .order_by(RadAcct.radacctid.desc())
            .limit(50)
        )
        return list((await self.session.scalars(stmt)).all())

    async def last_session(self, username: str) -> RadAcct | None:
        stmt = (
            select(RadAcct)
            .where(RadAcct.username == username)
            .order_by(RadAcct.radacctid.desc())
            .limit(1)
        )
        return await self.session.scalar(stmt)

    async def terminate_causes(self) -> list[str]:
        stmt = (
            select(RadAcct.acctterminatecause)
            .where(RadAcct.acctterminatecause != "")
            .distinct()
            .limit(100)
        )
        return sorted(x for x in (await self.session.scalars(stmt)).all() if x)

    # --- Aggregation fuer den Hintergrundjob (NFR-2) ---------------------

    async def summary(self, since: dt.datetime) -> dict[str, Any]:
        active = await self.session.scalar(
            select(func.count()).select_from(RadAcct).where(RadAcct.acctstoptime.is_(None))
        )
        started = await self.session.scalar(
            select(func.count()).select_from(RadAcct).where(RadAcct.acctstarttime >= since)
        )
        traffic = (
            await self.session.execute(
                select(
                    func.coalesce(func.sum(RadAcct.acctinputoctets), 0),
                    func.coalesce(func.sum(RadAcct.acctoutputoctets), 0),
                ).where(RadAcct.acctstarttime >= since)
            )
        ).one()
        top_users = (
            await self.session.execute(
                select(RadAcct.username, func.count().label("sessions"))
                .where(RadAcct.acctstarttime >= since)
                .group_by(RadAcct.username)
                .order_by(func.count().desc())
                .limit(10)
            )
        ).all()
        top_nas = (
            await self.session.execute(
                select(RadAcct.nasipaddress, func.count().label("sessions"))
                .where(RadAcct.acctstarttime >= since)
                .group_by(RadAcct.nasipaddress)
                .order_by(func.count().desc())
                .limit(10)
            )
        ).all()
        return {
            "active_sessions": int(active or 0),
            "sessions_started": int(started or 0),
            "input_octets": int(traffic[0] or 0),
            "output_octets": int(traffic[1] or 0),
            "top_users": [{"username": u, "sessions": c} for u, c in top_users],
            "top_nas": [{"nasipaddress": n, "sessions": c} for n, c in top_nas],
        }
