"""Audit-Log (FR-9). Nur lesend – ueber die API gibt es kein Loeschen."""

from __future__ import annotations

import datetime as dt
import json
from typing import Any

from fastapi import APIRouter, Query

from app.api.deps import ReaderUser, SessionDep
from app.core.dates import as_naive_utc
from app.core.pagination import MAX_PAGE_SIZE, clamp_limit
from app.repositories.mgr.audit import AuditRepository
from app.schemas.accounts import AuditItem
from app.schemas.common import PagedResponse, PageMeta

router = APIRouter(prefix="/audit", tags=["audit"])


def _load(raw: str | None) -> Any:
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


@router.get("", response_model=PagedResponse[AuditItem])
async def list_audit(
    session: SessionDep,
    _: ReaderUser,
    actor: str | None = None,
    action: str | None = None,
    object_type: str | None = None,
    object_id: str | None = None,
    date_from: dt.datetime | None = None,
    date_to: dt.datetime | None = None,
    limit: int = Query(default=50, ge=1, le=MAX_PAGE_SIZE),
    offset: int = Query(default=0, ge=0),
) -> PagedResponse[AuditItem]:
    limit = clamp_limit(limit)
    rows, total = await AuditRepository(session).search(
        actor=actor,
        action=action,
        object_type=object_type,
        object_id=object_id,
        date_from=as_naive_utc(date_from) if date_from else None,
        date_to=as_naive_utc(date_to) if date_to else None,
        limit=limit,
        offset=offset,
    )
    items = [
        AuditItem(
            id=row.id,
            ts=row.ts,
            actor_name=row.actor_name,
            actor_ip=row.actor_ip,
            action=row.action,
            object_type=row.object_type,
            object_id=row.object_id,
            result=row.result.value,
            message=row.message,
            before=_load(row.before_json),
            after=_load(row.after_json),
        )
        for row in rows
    ]
    return PagedResponse(items=items, meta=PageMeta(total=total, limit=limit, offset=offset))
