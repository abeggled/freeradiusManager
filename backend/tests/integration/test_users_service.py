"""Benutzerverwaltung gegen eine echte MariaDB (FR-1, NFR-5)."""

from __future__ import annotations

import datetime as dt

import pytest
from sqlalchemy import select

from app.core.crypto import nt_hash
from app.core.errors import ConflictError, NotFoundError
from app.models.mgr import CredentialType, SubjectType
from app.models.radius import RadCheck, RadReply, RadUserGroup
from app.repositories.directory import SubjectFilter
from app.schemas.users import (
    MASKED,
    MembershipIn,
    PasswordSet,
    SubjectMeta,
    UserCreate,
    UserUpdate,
)
from app.services.users import UserService

pytestmark = pytest.mark.asyncio


async def _ensure_groups(session, actor, *names: str) -> None:
    """Mitgliedschaften setzen vorhandene Gruppen voraus (Phantomgruppen-Schutz)."""
    from app.schemas.groups import GroupCreate
    from app.services.groups import GroupService

    service = GroupService(session)
    for index, name in enumerate(names):
        await service.create(GroupCreate(groupname=name, vlan=str(100 + index)), actor=actor)


async def _create(session, actor, **kwargs):
    payload = UserCreate(username="anna", password="geheim123", **kwargs)
    return await UserService(session).create(payload, actor=actor)


async def test_create_writes_both_credential_attributes(session, admin_principal) -> None:
    detail = await _create(session, admin_principal, credential_type=CredentialType.BOTH)
    assert detail.status == "active"

    rows = (await session.scalars(select(RadCheck).where(RadCheck.username == "anna"))).all()
    by_name = {r.attribute: r for r in rows}
    assert by_name["Cleartext-Password"].value == "geheim123"
    assert by_name["Cleartext-Password"].op == ":="
    assert by_name["NT-Password"].value == nt_hash("geheim123")


async def test_credential_type_nt_only(session, admin_principal) -> None:
    await _create(session, admin_principal, credential_type=CredentialType.NT)
    rows = (await session.scalars(select(RadCheck).where(RadCheck.username == "anna"))).all()
    attributes = {r.attribute for r in rows}
    assert attributes == {"NT-Password"}


async def test_password_values_are_masked_in_api_payload(session, admin_principal) -> None:
    detail = await _create(session, admin_principal, credential_type=CredentialType.CLEARTEXT)
    values = {a.attribute: a.value for a in detail.check_attributes}
    assert values["Cleartext-Password"] == MASKED
    assert "geheim123" not in detail.model_dump_json()


async def test_switching_credential_type_removes_old_attribute(session, admin_principal) -> None:
    await _create(session, admin_principal, credential_type=CredentialType.BOTH)
    await UserService(session).set_password(
        "anna",
        PasswordSet(password="neu-geheim", credential_type=CredentialType.NT),
        actor=admin_principal,
    )
    rows = (await session.scalars(select(RadCheck).where(RadCheck.username == "anna"))).all()
    assert {r.attribute for r in rows} == {"NT-Password"}
    assert next(r for r in rows).value == nt_hash("neu-geheim")


async def test_vlan_creates_three_reply_attributes(session, admin_principal) -> None:
    await _create(session, admin_principal, vlan="42")
    rows = (await session.scalars(select(RadReply).where(RadReply.username == "anna"))).all()
    assert {(r.attribute, r.op, r.value) for r in rows} == {
        ("Tunnel-Type", ":=", "VLAN"),
        ("Tunnel-Medium-Type", ":=", "IEEE-802"),
        ("Tunnel-Private-Group-Id", ":=", "42"),
    }


async def test_disable_preserves_password_and_enable_restores(session, admin_principal) -> None:
    service = UserService(session)
    await _create(session, admin_principal)

    await service.set_disabled("anna", True, actor=admin_principal)
    detail = await service.get("anna")
    assert detail.status == "disabled"
    rows = (await session.scalars(select(RadCheck).where(RadCheck.username == "anna"))).all()
    by_name = {r.attribute: r.value for r in rows}
    assert by_name["Auth-Type"] == "Reject"
    assert by_name["Cleartext-Password"] == "geheim123"

    await service.set_disabled("anna", False, actor=admin_principal)
    detail = await service.get("anna")
    assert detail.status == "active"
    rows = (await session.scalars(select(RadCheck).where(RadCheck.username == "anna"))).all()
    assert "Auth-Type" not in {r.attribute for r in rows}


async def test_expiry_is_written_as_freeradius_date(session, admin_principal) -> None:
    expires = dt.datetime(2020, 1, 1, 12, 0)
    await _create(session, admin_principal, expires_at=expires)
    row = await session.scalar(
        select(RadCheck).where(RadCheck.username == "anna", RadCheck.attribute == "Expiration")
    )
    assert row.value == "01 Jan 2020 12:00:00"
    detail = await UserService(session).get("anna")
    assert detail.status == "expired"


async def test_rename_moves_radius_and_metadata(session, admin_principal) -> None:
    service = UserService(session)
    await _ensure_groups(session, admin_principal, "mitarbeiter")
    await _create(session, admin_principal, groups=[MembershipIn(groupname="mitarbeiter")])
    await service.update("anna", UserUpdate(username="anna.neu"), actor=admin_principal)

    assert not await service.attrs.exists("anna")
    assert await service.attrs.exists("anna.neu")
    assert await service.subjects.get("anna") is None
    assert await service.subjects.get("anna.neu") is not None
    memberships = (
        await session.scalars(select(RadUserGroup).where(RadUserGroup.username == "anna.neu"))
    ).all()
    assert [m.groupname for m in memberships] == ["mitarbeiter"]


async def test_duplicate_username_is_rejected(session, admin_principal) -> None:
    await _create(session, admin_principal)
    with pytest.raises(ConflictError):
        await _create(session, admin_principal)


async def test_delete_removes_all_radius_rows(session, admin_principal) -> None:
    service = UserService(session)
    await _ensure_groups(session, admin_principal, "g1")
    await _create(session, admin_principal, vlan="10", groups=[MembershipIn(groupname="g1")])
    await service.delete("anna", actor=admin_principal)

    for model in (RadCheck, RadReply, RadUserGroup):
        rows = (await session.scalars(select(model).where(model.username == "anna"))).all()
        assert rows == []
    with pytest.raises(NotFoundError):
        await service.get("anna")


async def test_search_filters_by_note_and_group(session, admin_principal) -> None:
    service = UserService(session)
    await _ensure_groups(session, admin_principal, "mitarbeiter")
    await service.create(
        UserCreate(
            username="anna",
            password="geheim123",
            groups=[MembershipIn(groupname="mitarbeiter")],
            meta=SubjectMeta(note="Aussendienst Zuerich", owner="it@example.org"),
        ),
        actor=admin_principal,
    )
    await service.create(UserCreate(username="bruno", password="geheim123"), actor=admin_principal)

    items, total = await service.search(SubjectFilter(search="Zuerich"))
    assert total == 1 and items[0].username == "anna"

    items, total = await service.search(SubjectFilter(group="mitarbeiter"))
    assert [i.username for i in items] == ["anna"]

    items, total = await service.search(SubjectFilter(subject_type=SubjectType.USER))
    assert total == 2
