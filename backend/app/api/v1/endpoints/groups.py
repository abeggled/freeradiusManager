"""Gruppen und Attribute (FR-2)."""

from __future__ import annotations

from fastapi import APIRouter, status

from app.api.deps import ClientIp, Language, ReaderUser, SessionDep, WriterUser
from app.core import radius_dict
from app.schemas.groups import (
    DictionaryEntry,
    DictionaryResponse,
    GroupCreate,
    GroupDetail,
    GroupListItem,
    GroupUpdate,
    MembershipChange,
)
from app.services.groups import GroupService

router = APIRouter(prefix="/groups", tags=["groups"])


@router.get("", response_model=list[GroupListItem])
async def list_groups(
    session: SessionDep, _: ReaderUser, search: str | None = None
) -> list[GroupListItem]:
    return await GroupService(session).search(search)


@router.get("/dictionary", response_model=DictionaryResponse)
async def dictionary(
    _: ReaderUser, language: Language, kind: str | None = None
) -> DictionaryResponse:
    """Vorschlagsliste bekannter Attribute – Vendor-Attribute bleiben erlaubt (FR-2)."""
    entries = [
        DictionaryEntry(
            name=a.name,
            kind=a.kind,
            value_type=a.value_type,
            values=list(a.values),
            description=(a.description_de if language == "de" else a.description_en) or None,
        )
        for a in radius_dict.suggestions(kind)
    ]
    return DictionaryResponse(
        attributes=entries,
        check_operators=list(radius_dict.CHECK_OPERATORS),
        reply_operators=list(radius_dict.REPLY_OPERATORS),
    )


@router.get("/{groupname}", response_model=GroupDetail)
async def get_group(groupname: str, session: SessionDep, _: ReaderUser) -> GroupDetail:
    return await GroupService(session).get(groupname)


@router.get("/{groupname}/members", response_model=list[str])
async def group_members(
    groupname: str, session: SessionDep, _: ReaderUser, limit: int = 50, offset: int = 0
) -> list[str]:
    return await GroupService(session).members(groupname, limit=limit, offset=offset)


@router.post("", response_model=GroupDetail, status_code=status.HTTP_201_CREATED)
async def create_group(
    payload: GroupCreate,
    session: SessionDep,
    actor: WriterUser,
    actor_ip: ClientIp,
    language: Language,
) -> GroupDetail:
    return await GroupService(session).create(
        payload, actor=actor, actor_ip=actor_ip, language=language
    )


@router.patch("/{groupname}", response_model=GroupDetail)
async def update_group(
    groupname: str,
    payload: GroupUpdate,
    session: SessionDep,
    actor: WriterUser,
    actor_ip: ClientIp,
    language: Language,
) -> GroupDetail:
    return await GroupService(session).update(
        groupname, payload, actor=actor, actor_ip=actor_ip, language=language
    )


@router.post("/{groupname}/members", response_model=dict)
async def change_members(
    groupname: str,
    payload: MembershipChange,
    session: SessionDep,
    actor: WriterUser,
    actor_ip: ClientIp,
) -> dict[str, int]:
    changed = await GroupService(session).change_membership(
        groupname, payload, actor=actor, actor_ip=actor_ip
    )
    return {"changed": changed}


@router.delete("/{groupname}", response_model=dict)
async def delete_group(
    groupname: str,
    session: SessionDep,
    actor: WriterUser,
    actor_ip: ClientIp,
    force: bool = False,
) -> dict[str, int]:
    """Loeschen erfordert bei belegten Gruppen ``force=true`` – die Anzahl der
    betroffenen Mitglieder wird vorher gemeldet (NFR-4)."""
    members = await GroupService(session).delete(
        groupname, actor=actor, actor_ip=actor_ip, force=force
    )
    return {"removed_memberships": members}
