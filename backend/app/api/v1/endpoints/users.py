"""Benutzerverwaltung (FR-1) inkl. Bulk und Export (FR-8)."""

from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Query, Response, status

from app.api.deps import ClientIp, Language, ReaderUser, SessionDep, WriterUser
from app.core.pagination import MAX_PAGE_SIZE, clamp_limit
from app.models.mgr import SubjectType
from app.repositories.directory import SubjectFilter
from app.schemas.common import BulkResult, PagedResponse, PageMeta
from app.schemas.users import (
    BulkAction,
    PasswordSet,
    UserCreate,
    UserDetail,
    UserListItem,
    UserUpdate,
)
from app.services.importexport import ImportExportService
from app.services.users import UserService

router = APIRouter(prefix="/users", tags=["users"])


def _filter(
    search: str | None,
    group: str | None,
    status_: str | None,
    owner: str | None,
    subject_type: SubjectType | None = SubjectType.USER,
) -> SubjectFilter:
    return SubjectFilter(
        search=search,
        group=group,
        owner=owner,
        subject_type=subject_type,
        status=status_ or None,
    )


@router.get("", response_model=PagedResponse[UserListItem])
async def list_users(
    session: SessionDep,
    _: ReaderUser,
    search: str | None = None,
    group: str | None = None,
    status_filter: str | None = Query(default=None, alias="status"),
    owner: str | None = None,
    include_devices: bool = False,
    limit: int = Query(default=50, ge=1, le=MAX_PAGE_SIZE),
    offset: int = Query(default=0, ge=0),
) -> PagedResponse[UserListItem]:
    limit = clamp_limit(limit)
    flt = _filter(
        search, group, status_filter, owner, None if include_devices else SubjectType.USER
    )
    items, total = await UserService(session).search(flt, limit=limit, offset=offset)
    return PagedResponse(items=items, meta=PageMeta(total=total, limit=limit, offset=offset))


@router.get("/export")
async def export_users(
    session: SessionDep,
    _: ReaderUser,
    search: str | None = None,
    group: str | None = None,
    status_filter: str | None = Query(default=None, alias="status"),
    owner: str | None = None,
    include_devices: bool = False,
) -> Response:
    """CSV-Export der aktuellen Filterergebnisse (FR-8)."""
    flt = _filter(
        search, group, status_filter, owner, None if include_devices else SubjectType.USER
    )
    csv_text = await ImportExportService(session).export(flt)
    stamp = dt.datetime.now(tz=dt.UTC).strftime("%Y%m%d-%H%M")
    return Response(
        content=csv_text,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="benutzer-{stamp}.csv"'},
    )


@router.get("/{username}", response_model=UserDetail)
async def get_user(
    username: str, session: SessionDep, _: ReaderUser, language: Language
) -> UserDetail:
    return await UserService(session).get(username, language)


@router.post("", response_model=UserDetail, status_code=status.HTTP_201_CREATED)
async def create_user(
    payload: UserCreate,
    session: SessionDep,
    actor: WriterUser,
    actor_ip: ClientIp,
    language: Language,
) -> UserDetail:
    return await UserService(session).create(
        payload, actor=actor, actor_ip=actor_ip, language=language
    )


@router.patch("/{username}", response_model=UserDetail)
async def update_user(
    username: str,
    payload: UserUpdate,
    session: SessionDep,
    actor: WriterUser,
    actor_ip: ClientIp,
    language: Language,
) -> UserDetail:
    return await UserService(session).update(
        username, payload, actor=actor, actor_ip=actor_ip, language=language
    )


@router.put("/{username}/password", status_code=status.HTTP_204_NO_CONTENT)
async def set_user_password(
    username: str,
    payload: PasswordSet,
    session: SessionDep,
    actor: WriterUser,
    actor_ip: ClientIp,
) -> None:
    await UserService(session).set_password(username, payload, actor=actor, actor_ip=actor_ip)


@router.post("/{username}/disable", status_code=status.HTTP_204_NO_CONTENT)
async def disable_user(
    username: str, session: SessionDep, actor: WriterUser, actor_ip: ClientIp
) -> None:
    await UserService(session).set_disabled(username, True, actor=actor, actor_ip=actor_ip)


@router.post("/{username}/enable", status_code=status.HTTP_204_NO_CONTENT)
async def enable_user(
    username: str, session: SessionDep, actor: WriterUser, actor_ip: ClientIp
) -> None:
    await UserService(session).set_disabled(username, False, actor=actor, actor_ip=actor_ip)


@router.delete("/{username}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    username: str, session: SessionDep, actor: WriterUser, actor_ip: ClientIp
) -> None:
    await UserService(session).delete(username, actor=actor, actor_ip=actor_ip)


@router.post("/bulk", response_model=BulkResult)
async def bulk_action(
    payload: BulkAction,
    session: SessionDep,
    actor: WriterUser,
    actor_ip: ClientIp,
    search: str | None = None,
    group: str | None = None,
    status_filter: str | None = Query(default=None, alias="status"),
    owner: str | None = None,
    include_devices: bool = False,
) -> BulkResult:
    """Bulk-Aktionen (FR-8). ``filter_all`` wendet die Aktion auf die gesamte
    Filtermenge an – die betroffene Anzahl wird zurueckgemeldet (NFR-4).

    Der Filter entspricht dem der Listenansicht: ohne ``include_devices`` sind
    MAB-Geraete ausgenommen, damit eine Sammelaktion nie mehr Objekte trifft als
    zuvor angezeigt wurden.
    """
    flt = _filter(
        search, group, status_filter, owner, None if include_devices else SubjectType.USER
    )
    requested, succeeded, errors = await ImportExportService(session).bulk(
        payload, flt, actor=actor, actor_ip=actor_ip
    )
    return BulkResult(
        requested=requested,
        succeeded=succeeded,
        failed=len(errors),
        errors=errors,
    )
