"""Auth-Log und Diagnose (FR-6)."""

from __future__ import annotations

import datetime as dt

from fastapi import APIRouter

from app.api.deps import Language, ReaderUser, SessionDep
from app.repositories.radius.postauth import AuthLogFilter
from app.schemas.common import CursorMeta, CursorResponse
from app.schemas.sessions import AuthLogItem, Diagnosis
from app.services.authlog import AuthLogService

router = APIRouter(prefix="/authlog", tags=["authlog"])


@router.get("", response_model=CursorResponse[AuthLogItem])
async def list_authlog(
    session: SessionDep,
    _: ReaderUser,
    username: str | None = None,
    reply: str | None = None,
    only_rejects: bool = False,
    date_from: dt.datetime | None = None,
    date_to: dt.datetime | None = None,
    limit: int = 50,
    cursor: str | None = None,
) -> CursorResponse[AuthLogItem]:
    flt = AuthLogFilter(
        username=username,
        reply=reply,
        only_rejects=only_rejects,
        date_from=date_from,
        date_to=date_to,
    )
    items, next_cursor = await AuthLogService(session).search(flt, limit=limit, cursor=cursor)
    return CursorResponse(items=items, meta=CursorMeta(limit=limit, next_cursor=next_cursor))


@router.get("/diagnose/{subject}", response_model=Diagnosis)
async def diagnose(
    subject: str, session: SessionDep, _: ReaderUser, language: Language, attempts: int = 20
) -> Diagnosis:
    """Klartext-Hinweise zu einem Benutzer oder einer MAC-Adresse (FR-6)."""
    return await AuthLogService(session).diagnose(subject, language=language, attempts=attempts)
