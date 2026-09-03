"""Manager-Benutzerverwaltung (Abschnitt 2, FR-10) – nur Administratoren."""

from __future__ import annotations

from fastapi import APIRouter, Query, status

from app.api.deps import AdminUser, ClientIp, CurrentUser, SessionDep
from app.core.pagination import MAX_PAGE_SIZE, clamp_limit
from app.schemas.accounts import (
    AccountCreate,
    AccountOut,
    AccountUpdate,
    PasswordChange,
)
from app.schemas.common import PagedResponse, PageMeta
from app.services.accounts import AccountService

router = APIRouter(prefix="/accounts", tags=["accounts"])


@router.get("", response_model=PagedResponse[AccountOut])
async def list_accounts(
    session: SessionDep,
    _: AdminUser,
    search: str | None = None,
    limit: int = Query(default=50, ge=1, le=MAX_PAGE_SIZE),
    offset: int = Query(default=0, ge=0),
) -> PagedResponse[AccountOut]:
    limit = clamp_limit(limit)
    items, total = await AccountService(session).search(search=search, limit=limit, offset=offset)
    return PagedResponse(items=items, meta=PageMeta(total=total, limit=limit, offset=offset))


@router.post("", response_model=AccountOut, status_code=status.HTTP_201_CREATED)
async def create_account(
    payload: AccountCreate, session: SessionDep, actor: AdminUser, actor_ip: ClientIp
) -> AccountOut:
    return await AccountService(session).create(payload, actor=actor, actor_ip=actor_ip)


@router.patch("/{account_id}", response_model=AccountOut)
async def update_account(
    account_id: int,
    payload: AccountUpdate,
    session: SessionDep,
    actor: AdminUser,
    actor_ip: ClientIp,
) -> AccountOut:
    return await AccountService(session).update(account_id, payload, actor=actor, actor_ip=actor_ip)


@router.delete("/{account_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_account(
    account_id: int, session: SessionDep, actor: AdminUser, actor_ip: ClientIp
) -> None:
    await AccountService(session).delete(account_id, actor=actor, actor_ip=actor_ip)


@router.put("/me/password", status_code=status.HTTP_204_NO_CONTENT)
async def change_own_password(
    payload: PasswordChange, session: SessionDep, actor: CurrentUser, actor_ip: ClientIp
) -> None:
    await AccountService(session).change_password(
        actor.account_id, payload, actor=actor, actor_ip=actor_ip
    )
