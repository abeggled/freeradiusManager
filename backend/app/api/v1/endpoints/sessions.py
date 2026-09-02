"""Session-Uebersicht (FR-5)."""

from __future__ import annotations

import datetime as dt

from fastapi import APIRouter

from app.api.deps import ReaderUser, SessionDep
from app.repositories.radius.acct import SessionFilter
from app.schemas.common import CursorMeta, CursorResponse
from app.schemas.sessions import SessionItem
from app.services.sessions import SessionService

router = APIRouter(prefix="/sessions", tags=["sessions"])


@router.get("", response_model=CursorResponse[SessionItem])
async def list_sessions(
    session: SessionDep,
    _: ReaderUser,
    username: str | None = None,
    calling_station_id: str | None = None,
    nas_ip_address: str | None = None,
    called_station_id: str | None = None,
    framed_ip_address: str | None = None,
    terminate_cause: str | None = None,
    start_from: dt.datetime | None = None,
    start_to: dt.datetime | None = None,
    active_only: bool = False,
    limit: int = 50,
    cursor: str | None = None,
) -> CursorResponse[SessionItem]:
    flt = SessionFilter(
        username=username,
        calling_station_id=calling_station_id,
        nas_ip_address=nas_ip_address,
        called_station_id=called_station_id,
        framed_ip_address=framed_ip_address,
        terminate_cause=terminate_cause,
        start_from=start_from,
        start_to=start_to,
        active_only=active_only,
    )
    items, next_cursor, approx = await SessionService(session).search(
        flt, limit=limit, cursor=cursor
    )
    return CursorResponse(
        items=items,
        meta=CursorMeta(limit=limit, next_cursor=next_cursor, approximate_total=approx),
    )


@router.get("/terminate-causes", response_model=list[str])
async def terminate_causes(session: SessionDep, _: ReaderUser) -> list[str]:
    return await SessionService(session).terminate_causes()


@router.get("/{radacctid}", response_model=SessionItem)
async def get_session(radacctid: int, session: SessionDep, _: ReaderUser) -> SessionItem:
    return await SessionService(session).get(radacctid)
