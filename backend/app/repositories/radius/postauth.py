"""Auth-Log-Abfragen auf ``radpostauth`` (FR-6)."""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

from sqlalchemy import ColumnElement, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.pagination import KeysetPage, clamp_limit, cursor_position, encode_cursor
from app.models.radius import RadPostAuth

ACCEPT_VALUES = ("Access-Accept", "Accept")


@dataclass(slots=True)
class AuthLogFilter:
    username: str | None = None
    reply: str | None = None
    only_rejects: bool = False
    date_from: dt.datetime | None = None
    date_to: dt.datetime | None = None


class PostAuthRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    def _conditions(self, flt: AuthLogFilter) -> list[ColumnElement[bool]]:
        conditions: list[ColumnElement[bool]] = []
        if flt.username:
            conditions.append(RadPostAuth.username == flt.username)
        if flt.reply:
            conditions.append(RadPostAuth.reply == flt.reply)
        if flt.only_rejects:
            conditions.append(RadPostAuth.reply.notin_(ACCEPT_VALUES))
        if flt.date_from:
            conditions.append(RadPostAuth.authdate >= flt.date_from)
        if flt.date_to:
            conditions.append(RadPostAuth.authdate <= flt.date_to)
        return conditions

    async def search(
        self, flt: AuthLogFilter, limit: int | None = None, cursor: str | None = None
    ) -> KeysetPage[RadPostAuth]:
        limit = clamp_limit(limit)
        stmt = select(RadPostAuth).where(*self._conditions(flt))
        position = cursor_position(cursor)
        if position is not None:
            stmt = stmt.where(RadPostAuth.id < position)
        stmt = stmt.order_by(RadPostAuth.id.desc()).limit(limit + 1)
        rows = list((await self.session.scalars(stmt)).all())
        next_cursor = None
        if len(rows) > limit:
            rows = rows[:limit]
            next_cursor = encode_cursor({"id": rows[-1].id})
        return KeysetPage(items=rows, next_cursor=next_cursor, limit=limit)

    async def recent_for(self, username: str, limit: int = 20) -> list[RadPostAuth]:
        stmt = (
            select(RadPostAuth)
            .where(RadPostAuth.username == username)
            .order_by(RadPostAuth.id.desc())
            .limit(limit)
        )
        return list((await self.session.scalars(stmt)).all())

    async def summary(self, since: dt.datetime) -> dict[str, int]:
        rows = (
            await self.session.execute(
                select(RadPostAuth.reply, func.count())
                .where(RadPostAuth.authdate >= since)
                .group_by(RadPostAuth.reply)
            )
        ).all()
        result = {str(reply): int(count) for reply, count in rows}
        result["accepts"] = sum(v for k, v in result.items() if k in ACCEPT_VALUES)
        result["rejects"] = sum(
            v for k, v in result.items() if k not in ACCEPT_VALUES and k != "accepts"
        )
        return result

    async def unknown_subjects(self, since: dt.datetime, limit: int = 50) -> list[tuple[str, int]]:
        """Haeufig abgelehnte Benutzer/MACs – Basis fuer den Freigabe-Workflow
        aus Abschnitt 9 und fuer die Diagnose."""
        stmt = (
            select(RadPostAuth.username, func.count().label("attempts"))
            .where(RadPostAuth.authdate >= since, RadPostAuth.reply.notin_(ACCEPT_VALUES))
            .group_by(RadPostAuth.username)
            .order_by(func.count().desc())
            .limit(limit)
        )
        return [(str(u), int(c)) for u, c in (await self.session.execute(stmt)).all()]
