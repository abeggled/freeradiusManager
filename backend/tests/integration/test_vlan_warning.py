"""Hinweis auf ein durch die Gruppe verdecktes VLAN (FR-1, FR-2, FR-3).

Belegt wurde das Verhalten von FreeRADIUS in
``tests/e2e/test_freeradius.py::test_group_vlan_wins_over_own_vlan``: die
Gruppe gewinnt. Hier geht es darum, dass die Anwendung darauf hinweist, statt
die wirkungslose Zuweisung stillschweigend anzunehmen.
"""

from __future__ import annotations

import pytest

from app.schemas.groups import GroupCreate
from app.schemas.users import AttributeIn, DeviceCreate, MembershipIn, UserCreate, UserUpdate
from app.services.devices import DeviceService
from app.services.groups import GroupService
from app.services.users import UserService

pytestmark = pytest.mark.asyncio

WARNING = "warn.vlan_overridden_by_group"


def _codes(warnings) -> set[str]:
    return {w.code for w in warnings}


async def test_own_vlan_with_group_vlan_warns(session, admin_principal) -> None:
    await GroupService(session).create(
        GroupCreate(groupname="w-drucker", vlan="30"), actor=admin_principal
    )

    detail = await UserService(session).create(
        UserCreate(
            username="w-anna",
            password="geheim123456",
            vlan="45",
            groups=[MembershipIn(groupname="w-drucker")],
        ),
        actor=admin_principal,
    )

    assert WARNING in _codes(detail.warnings)
    message = next(w.message for w in detail.warnings if w.code == WARNING)
    # Beide Werte gehoeren in den Text: sonst muesste man erst nachsehen,
    # welches VLAN denn nun greift.
    assert "45" in message and "30" in message and "w-drucker" in message


async def test_own_vlan_without_group_does_not_warn(session, admin_principal) -> None:
    detail = await UserService(session).create(
        UserCreate(username="w-bruno", password="geheim123456", vlan="45"),
        actor=admin_principal,
    )
    assert WARNING not in _codes(detail.warnings)


async def test_group_without_vlan_does_not_warn(session, admin_principal) -> None:
    # Eine Gruppe ganz ohne Attribut weist der Dienst ab; hier geht es um eine
    # Gruppe, die zwar Attribute setzt, aber kein VLAN.
    await GroupService(session).create(
        GroupCreate(
            groupname="w-ohne-vlan",
            reply_attributes=[AttributeIn(attribute="Filter-Id", op=":=", value="gast")],
        ),
        actor=admin_principal,
    )

    detail = await UserService(session).create(
        UserCreate(
            username="w-clara",
            password="geheim123456",
            vlan="45",
            groups=[MembershipIn(groupname="w-ohne-vlan")],
        ),
        actor=admin_principal,
    )
    assert WARNING not in _codes(detail.warnings)


async def test_identical_vlan_does_not_warn(session, admin_principal) -> None:
    """Dasselbe VLAN auf beiden Ebenen ist redundant, aber nicht widerspruechlich."""
    await GroupService(session).create(
        GroupCreate(groupname="w-gleich", vlan="30"), actor=admin_principal
    )

    detail = await UserService(session).create(
        UserCreate(
            username="w-dora",
            password="geheim123456",
            vlan="30",
            groups=[MembershipIn(groupname="w-gleich")],
        ),
        actor=admin_principal,
    )
    assert WARNING not in _codes(detail.warnings)


async def test_warning_also_on_later_group_assignment(session, admin_principal) -> None:
    """Die Falle entsteht genauso, wenn die Gruppe erst spaeter dazukommt."""
    users = UserService(session)
    await GroupService(session).create(
        GroupCreate(groupname="w-spaet", vlan="30"), actor=admin_principal
    )
    await users.create(
        UserCreate(username="w-emil", password="geheim123456", vlan="45"), actor=admin_principal
    )

    detail = await users.update(
        "w-emil",
        UserUpdate(groups=[MembershipIn(groupname="w-spaet")]),
        actor=admin_principal,
    )
    assert WARNING in _codes(detail.warnings)


async def test_device_create_warns_as_well(session, admin_principal) -> None:
    """Geraete gehen denselben Weg - dort ist die Kombination am naheliegendsten."""
    await GroupService(session).create(
        GroupCreate(groupname="w-mab", vlan="30"), actor=admin_principal
    )

    detail = await DeviceService(session).create(
        DeviceCreate(
            mac="aa:bb:cc:dd:ee:01",
            use_mac_as_password=True,
            vlan="45",
            groups=[MembershipIn(groupname="w-mab")],
        ),
        actor=admin_principal,
    )
    assert WARNING in _codes(detail.warnings)
