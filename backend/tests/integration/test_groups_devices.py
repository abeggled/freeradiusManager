"""Gruppen (FR-2) und MAB-Geraete (FR-3)."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from app.core.errors import ConflictError, ValidationError
from app.models.mgr import SubjectType
from app.models.radius import RadCheck, RadGroupReply
from app.repositories.directory import SubjectFilter
from app.schemas.groups import GroupCreate, GroupUpdate, MembershipChange
from app.schemas.users import AttributeIn, DeviceCreate, DeviceUpdate, SubjectMeta
from app.services.devices import DeviceService
from app.services.groups import GroupService
from app.services.settings_service import KEY_MAC_FORMAT, SettingsService

pytestmark = pytest.mark.asyncio


async def test_group_vlan_dialog_writes_three_attributes(session, admin_principal) -> None:
    detail = await GroupService(session).create(
        GroupCreate(groupname="mitarbeiter", vlan="20"), actor=admin_principal
    )
    assert detail.vlan == "20"
    rows = (
        await session.scalars(select(RadGroupReply).where(RadGroupReply.groupname == "mitarbeiter"))
    ).all()
    assert {(r.attribute, r.value) for r in rows} == {
        ("Tunnel-Type", "VLAN"),
        ("Tunnel-Medium-Type", "IEEE-802"),
        ("Tunnel-Private-Group-Id", "20"),
    }


async def test_group_expert_mode_and_warnings(session, admin_principal) -> None:
    detail = await GroupService(session).create(
        GroupCreate(
            groupname="drucker",
            reply_attributes=[AttributeIn(attribute="Acme-Vendor-Attr", op=":=", value="x")],
        ),
        actor=admin_principal,
    )
    assert [w.code for w in detail.warnings] == ["warn.unknown_attribute"]


async def test_duplicate_group_rejected(session, admin_principal) -> None:
    service = GroupService(session)
    await service.create(GroupCreate(groupname="g1", vlan="10"), actor=admin_principal)
    with pytest.raises(ConflictError):
        await service.create(GroupCreate(groupname="g1"), actor=admin_principal)


async def test_group_delete_requires_force_when_members_exist(session, admin_principal) -> None:
    service = GroupService(session)
    await service.create(GroupCreate(groupname="g1", vlan="10"), actor=admin_principal)
    await service.change_membership(
        "g1", MembershipChange(usernames=["anna"], action="add"), actor=admin_principal
    )
    with pytest.raises(ValidationError):
        await service.delete("g1", actor=admin_principal)
    removed = await service.delete("g1", actor=admin_principal, force=True)
    assert removed == 1


async def test_group_rename_moves_memberships(session, admin_principal) -> None:
    service = GroupService(session)
    await service.create(GroupCreate(groupname="alt", vlan="10"), actor=admin_principal)
    await service.change_membership(
        "alt", MembershipChange(usernames=["anna"], action="add"), actor=admin_principal
    )
    await service.update("alt", GroupUpdate(groupname="neu"), actor=admin_principal)
    detail = await service.get("neu")
    assert detail.members == 1
    assert detail.vlan == "10"


async def test_device_username_follows_configured_mac_format(session, admin_principal) -> None:
    await SettingsService(session).update({KEY_MAC_FORMAT: "plain_lower"})
    await session.commit()

    detail = await DeviceService(session).create(
        DeviceCreate(mac="AA-BB-CC-DD-EE-FF", meta=SubjectMeta(location="Empfang")),
        actor=admin_principal,
    )
    assert detail.username == "aabbccddeeff"
    assert detail.subject_type is SubjectType.DEVICE
    assert any(w.code == "warn.mab_not_authentication" for w in detail.warnings)


async def test_device_password_defaults_to_mac(session, admin_principal) -> None:
    service = DeviceService(session)
    detail = await service.create(DeviceCreate(mac="aabbccddeeff"), actor=admin_principal)
    row = await session.scalar(
        select(RadCheck).where(
            RadCheck.username == detail.username,
            RadCheck.attribute == "Cleartext-Password",
        )
    )
    assert row.value == detail.username


async def test_device_list_excludes_regular_users(session, admin_principal) -> None:
    from app.schemas.users import UserCreate
    from app.services.users import UserService

    await UserService(session).create(
        UserCreate(username="anna", password="geheim123"), actor=admin_principal
    )
    await DeviceService(session).create(
        DeviceCreate(mac="aa:bb:cc:dd:ee:ff"), actor=admin_principal
    )

    devices, total = await DeviceService(session).search(SubjectFilter())
    assert total == 1
    assert devices[0].subject_type is SubjectType.DEVICE


async def test_device_rename_normalises_new_mac(session, admin_principal) -> None:
    service = DeviceService(session)
    await service.create(DeviceCreate(mac="aa:bb:cc:dd:ee:ff"), actor=admin_principal)
    detail = await service.update(
        "aa:bb:cc:dd:ee:ff",
        DeviceUpdate(mac="11-22-33-44-55-66"),
        actor=admin_principal,
    )
    assert detail.username == "11:22:33:44:55:66"


async def test_invalid_mac_is_rejected(session, admin_principal) -> None:
    with pytest.raises(ValidationError):
        await DeviceService(session).create(
            DeviceCreate(mac="keine-mac-adresse"), actor=admin_principal
        )
