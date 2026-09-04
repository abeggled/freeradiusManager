"""NAS-Clients (FR-4) und CoA/Disconnect (FR-7)."""

from __future__ import annotations

from fastapi import APIRouter, Query, status

from app.api.deps import (
    AdminUser,
    ClientIp,
    Language,
    ReaderUser,
    SessionDep,
    WriterUser,
    coa_limiter,
)
from app.core.errors import PermissionDeniedError
from app.core.pagination import MAX_PAGE_SIZE, clamp_limit
from app.models.mgr import Role
from app.schemas.common import PagedResponse, PageMeta
from app.schemas.nas import (
    CoARequest,
    CoAResponse,
    NasCreate,
    NasListItem,
    NasUpdate,
    SecretReveal,
)
from app.services.coa import CoAService
from app.services.nas import NasService

router = APIRouter(prefix="/nas", tags=["nas"])


def _require_nas_access(principal: object) -> None:
    """Operatoren haben laut Abschnitt 2 keinen Zugriff auf NAS-Clients."""
    if getattr(principal, "role", None) is not Role.ADMINISTRATOR:
        raise PermissionDeniedError(code="error.forbidden")


@router.get("", response_model=PagedResponse[NasListItem])
async def list_nas(
    session: SessionDep,
    principal: ReaderUser,
    search: str | None = None,
    limit: int = Query(default=50, ge=1, le=MAX_PAGE_SIZE),
    offset: int = Query(default=0, ge=0),
) -> PagedResponse[NasListItem]:
    if principal.role is Role.OPERATOR:
        raise PermissionDeniedError(code="error.forbidden")
    limit = clamp_limit(limit)
    items, total = await NasService(session).search(search=search, limit=limit, offset=offset)
    return PagedResponse(items=items, meta=PageMeta(total=total, limit=limit, offset=offset))


@router.get("/{nas_id}", response_model=NasListItem)
async def get_nas(nas_id: int, session: SessionDep, principal: ReaderUser) -> NasListItem:
    if principal.role is Role.OPERATOR:
        raise PermissionDeniedError(code="error.forbidden")
    return await NasService(session).get(nas_id)


@router.post("", response_model=NasListItem, status_code=status.HTTP_201_CREATED)
async def create_nas(
    payload: NasCreate,
    session: SessionDep,
    actor: AdminUser,
    actor_ip: ClientIp,
    language: Language,
) -> NasListItem:
    item, _warnings = await NasService(session).create(
        payload, actor=actor, actor_ip=actor_ip, language=language
    )
    return item


@router.patch("/{nas_id}", response_model=NasListItem)
async def update_nas(
    nas_id: int,
    payload: NasUpdate,
    session: SessionDep,
    actor: AdminUser,
    actor_ip: ClientIp,
    language: Language,
) -> NasListItem:
    item, _warnings = await NasService(session).update(
        nas_id, payload, actor=actor, actor_ip=actor_ip, language=language
    )
    return item


@router.delete("/{nas_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_nas(
    nas_id: int, session: SessionDep, actor: AdminUser, actor_ip: ClientIp
) -> None:
    await NasService(session).delete(nas_id, actor=actor, actor_ip=actor_ip)


@router.post("/{nas_id}/secret", response_model=SecretReveal)
async def reveal_secret(
    nas_id: int, session: SessionDep, actor: AdminUser, actor_ip: ClientIp
) -> SecretReveal:
    """Anzeige des Shared Secret – Administratoren, mit Audit-Eintrag (FR-4)."""
    return await NasService(session).reveal_secret(nas_id, actor=actor, actor_ip=actor_ip)


@router.post("/coa", response_model=CoAResponse, tags=["sessions"])
async def send_coa(
    payload: CoARequest,
    session: SessionDep,
    actor: WriterUser,
    actor_ip: ClientIp,
    language: Language,
) -> CoAResponse:
    """Disconnect-Message bzw. CoA nach RFC 5176 (FR-7)."""
    coa_limiter.check(f"{actor.account_id}")
    return await CoAService(session).execute(
        payload, actor=actor, actor_ip=actor_ip, language=language
    )
