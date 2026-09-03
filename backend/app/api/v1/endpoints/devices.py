"""MAB-Geraete (FR-3)."""

from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Query, Response, status

from app.api.deps import ClientIp, Language, ReaderUser, SessionDep, WriterUser
from app.core.mac import MAC_FORMATS
from app.core.pagination import clamp_limit
from app.models.mgr import SubjectType
from app.repositories.directory import SubjectFilter
from app.schemas.common import PagedResponse, PageMeta
from app.schemas.users import DeviceCreate, DeviceUpdate, UserDetail, UserListItem
from app.services.devices import DeviceService
from app.services.importexport import ImportExportService

router = APIRouter(prefix="/devices", tags=["devices"])


def _filter(
    search: str | None,
    group: str | None,
    location: str | None,
    device_type: str | None,
    status_: str | None,
) -> SubjectFilter:
    return SubjectFilter(
        search=search,
        group=group,
        location=location,
        device_type=device_type,
        subject_type=SubjectType.DEVICE,
        status=status_ or None,
    )


@router.get("", response_model=PagedResponse[UserListItem])
async def list_devices(
    session: SessionDep,
    _: ReaderUser,
    search: str | None = None,
    group: str | None = None,
    location: str | None = None,
    device_type: str | None = None,
    status_filter: str | None = Query(default=None, alias="status"),
    limit: int = 50,
    offset: int = 0,
) -> PagedResponse[UserListItem]:
    limit = clamp_limit(limit)
    flt = _filter(search, group, location, device_type, status_filter)
    items, total = await DeviceService(session).search(flt, limit=limit, offset=offset)
    return PagedResponse(items=items, meta=PageMeta(total=total, limit=limit, offset=offset))


@router.get("/mac-formats")
async def mac_formats(session: SessionDep, _: ReaderUser) -> dict[str, object]:
    return {
        "formats": [{"key": k, "example": v} for k, v in MAC_FORMATS.items()],
        "active": await DeviceService(session).mac_format(),
    }


@router.get("/export")
async def export_devices(
    session: SessionDep,
    _: ReaderUser,
    search: str | None = None,
    group: str | None = None,
    location: str | None = None,
    device_type: str | None = None,
    status_filter: str | None = Query(default=None, alias="status"),
) -> Response:
    flt = _filter(search, group, location, device_type, status_filter)
    csv_text = await ImportExportService(session).export(flt)
    stamp = dt.datetime.now(tz=dt.UTC).strftime("%Y%m%d-%H%M")
    return Response(
        content=csv_text,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="geraete-{stamp}.csv"'},
    )


@router.get("/{mac}", response_model=UserDetail)
async def get_device(
    mac: str, session: SessionDep, _: ReaderUser, language: Language
) -> UserDetail:
    return await DeviceService(session).get(mac, language)


@router.post("", response_model=UserDetail, status_code=status.HTTP_201_CREATED)
async def create_device(
    payload: DeviceCreate,
    session: SessionDep,
    actor: WriterUser,
    actor_ip: ClientIp,
    language: Language,
) -> UserDetail:
    return await DeviceService(session).create(
        payload, actor=actor, actor_ip=actor_ip, language=language
    )


@router.patch("/{mac}", response_model=UserDetail)
async def update_device(
    mac: str,
    payload: DeviceUpdate,
    session: SessionDep,
    actor: WriterUser,
    actor_ip: ClientIp,
    language: Language,
) -> UserDetail:
    return await DeviceService(session).update(
        mac, payload, actor=actor, actor_ip=actor_ip, language=language
    )


@router.post("/{mac}/disable", status_code=status.HTTP_204_NO_CONTENT)
async def disable_device(
    mac: str, session: SessionDep, actor: WriterUser, actor_ip: ClientIp
) -> None:
    await DeviceService(session).set_disabled(mac, True, actor=actor, actor_ip=actor_ip)


@router.post("/{mac}/enable", status_code=status.HTTP_204_NO_CONTENT)
async def enable_device(
    mac: str, session: SessionDep, actor: WriterUser, actor_ip: ClientIp
) -> None:
    await DeviceService(session).set_disabled(mac, False, actor=actor, actor_ip=actor_ip)


@router.delete("/{mac}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_device(
    mac: str, session: SessionDep, actor: WriterUser, actor_ip: ClientIp
) -> None:
    await DeviceService(session).delete(mac, actor=actor, actor_ip=actor_ip)
