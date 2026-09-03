"""Regressionstests zu den Befunden aus dem Code-Review.

Jeder Test hält genau das Verhalten fest, das vorher fehlte.
"""

from __future__ import annotations

import datetime as dt

import pyotp
import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.core.config import settings
from app.core.crypto import SecretBox, hash_password
from app.core.errors import ConflictError, ValidationError
from app.main import create_app
from app.models.mgr import MgrAccount, MgrAudit, Role
from app.models.radius import RadAcct, RadCheck, RadGroupReply, RadReply, RadUserGroup
from app.repositories.directory import SubjectFilter
from app.schemas.groups import GroupCreate, GroupUpdate
from app.schemas.nas import CoARequest, NasCreate, NasUpdate
from app.schemas.users import (
    AttributeIn,
    DeviceCreate,
    DeviceUpdate,
    UserCreate,
)
from app.services.audit import AuditService
from app.services.coa import CoAService
from app.services.devices import DeviceService
from app.services.groups import GroupService
from app.services.importexport import ImportExportService
from app.services.nas import NasService
from app.services.users import UserService

pytestmark = pytest.mark.asyncio


# --- Gruppen ---------------------------------------------------------------


async def test_group_password_attributes_are_masked(session, admin_principal) -> None:
    """Der Expertenmodus lässt Passwort-Attribute zu; ausgeliefert werden sie nie."""
    service = GroupService(session)
    await service.create(
        GroupCreate(
            groupname="g1",
            check_attributes=[
                AttributeIn(attribute="Cleartext-Password", op=":=", value="streng-geheim")
            ],
        ),
        actor=admin_principal,
    )
    detail = await service.get("g1")
    values = {a.attribute: a.value for a in detail.check_attributes}
    assert values["Cleartext-Password"] == "********"
    assert "streng-geheim" not in detail.model_dump_json()


async def test_group_patch_keeps_omitted_collection(session, admin_principal) -> None:
    """Nur check_attributes zu senden darf die VLAN-Zuweisung nicht löschen."""
    service = GroupService(session)
    await service.create(GroupCreate(groupname="g1", vlan="20"), actor=admin_principal)

    await service.update(
        "g1",
        GroupUpdate(
            check_attributes=[AttributeIn(attribute="Simultaneous-Use", op=":=", value="1")]
        ),
        actor=admin_principal,
    )
    detail = await service.get("g1")
    assert detail.vlan == "20"
    assert [a.attribute for a in detail.check_attributes] == ["Simultaneous-Use"]

    # Umgekehrt ebenso: nur reply_attributes lässt die Prüfattribute stehen.
    await service.update(
        "g1",
        GroupUpdate(reply_attributes=[AttributeIn(attribute="Filter-Id", op=":=", value="x")]),
        actor=admin_principal,
    )
    detail = await service.get("g1")
    assert [a.attribute for a in detail.check_attributes] == ["Simultaneous-Use"]


async def test_group_without_attributes_is_rejected(session, admin_principal) -> None:
    """Eine attributlose Gruppe erzeugt keine Zeile und wäre nicht auffindbar."""
    with pytest.raises(ValidationError) as excinfo:
        await GroupService(session).create(GroupCreate(groupname="leer"), actor=admin_principal)
    assert excinfo.value.code == "error.group_empty"
    assert (await session.scalars(select(RadGroupReply))).all() == []


# --- Benutzer und Geräte ---------------------------------------------------


async def test_create_conflicts_with_reply_only_user(session, admin_principal) -> None:
    """Ein Bestandsname mit nur Antwortattributen darf nicht überschrieben werden."""
    session.add(RadReply(username="legacy", attribute="Filter-Id", op=":=", value="wichtig"))
    await session.commit()

    with pytest.raises(ConflictError):
        await UserService(session).create(
            UserCreate(username="legacy", password="geheim123"), actor=admin_principal
        )
    row = await session.scalar(select(RadReply).where(RadReply.username == "legacy"))
    assert row.value == "wichtig"


async def test_create_conflicts_with_membership_only_user(session, admin_principal) -> None:
    session.add(RadUserGroup(username="legacy", groupname="alt", priority=1))
    await session.commit()
    with pytest.raises(ConflictError):
        await UserService(session).create(
            UserCreate(username="legacy", password="geheim123"), actor=admin_principal
        )


async def test_device_rename_updates_mac_password(session, admin_principal) -> None:
    """Bei MAB ist die MAC auch das Passwort – nach dem Umbenennen muss es passen."""
    service = DeviceService(session)
    await service.create(DeviceCreate(mac="aa:bb:cc:dd:ee:ff"), actor=admin_principal)

    detail = await service.update(
        "aa:bb:cc:dd:ee:ff", DeviceUpdate(mac="11:22:33:44:55:66"), actor=admin_principal
    )
    assert detail.username == "11:22:33:44:55:66"

    row = await session.scalar(
        select(RadCheck).where(
            RadCheck.username == "11:22:33:44:55:66",
            RadCheck.attribute == "Cleartext-Password",
        )
    )
    assert row.value == "11:22:33:44:55:66"


async def test_user_rename_keeps_own_password(session, admin_principal) -> None:
    """Bei normalen Benutzern bleibt das Passwort beim Umbenennen unverändert."""
    from app.schemas.users import UserUpdate

    service = UserService(session)
    await service.create(UserCreate(username="anna", password="geheim123"), actor=admin_principal)
    await service.update("anna", UserUpdate(username="anna.neu"), actor=admin_principal)
    row = await session.scalar(
        select(RadCheck).where(
            RadCheck.username == "anna.neu", RadCheck.attribute == "Cleartext-Password"
        )
    )
    assert row.value == "geheim123"


# --- Filter und Bulk -------------------------------------------------------


async def test_status_filter_uses_radcheck(session, admin_principal) -> None:
    """Ein direkt in radcheck gesperrter Bestandsbenutzer zählt als gesperrt."""
    session.add_all(
        [
            RadCheck(username="legacy", attribute="Cleartext-Password", op=":=", value="x"),
            RadCheck(username="legacy", attribute="Auth-Type", op=":=", value="Reject"),
        ]
    )
    await session.commit()

    service = UserService(session)
    disabled, _ = await service.search(SubjectFilter(disabled=True))
    active, _ = await service.search(SubjectFilter(disabled=False))
    assert [i.username for i in disabled] == ["legacy"]
    assert active == []


async def test_bulk_over_filter_excludes_devices(session, client, admin_account) -> None:
    """„Auf gesamte Filtermenge“ darf ohne include_devices keine Geräte treffen."""
    await UserService(session).create(
        UserCreate(username="anna", password="geheim123"), actor=admin_account
    )
    await DeviceService(session).create(DeviceCreate(mac="aa:bb:cc:dd:ee:ff"), actor=admin_account)

    response = await client.post(
        "/api/v1/users/bulk", json={"action": "disable", "filter_all": True}
    )
    assert response.status_code == 200
    assert response.json()["requested"] == 1

    assert (await UserService(session).get("aa:bb:cc:dd:ee:ff")).status == "active"


# --- NAS und CoA -----------------------------------------------------------


async def test_nas_optional_fields_can_be_cleared(session, admin_principal) -> None:
    service = NasService(session)
    item, _ = await service.create(
        NasCreate(nasname="10.0.0.1", shortname="sw01", description="Etage 1", secret="s"),
        actor=admin_principal,
    )
    updated, _ = await service.update(
        item.id, NasUpdate(shortname=None, description=None), actor=admin_principal
    )
    assert updated.shortname is None
    assert updated.description is None


async def test_nas_update_keeps_secret_when_not_supplied(session, admin_principal) -> None:
    service = NasService(session)
    item, _ = await service.create(
        NasCreate(nasname="10.0.0.1", secret="topsecret"), actor=admin_principal
    )
    await service.update(item.id, NasUpdate(shortname="neu"), actor=admin_principal)
    revealed = await service.reveal_secret(item.id, actor=admin_principal)
    assert revealed.secret == "topsecret"


async def test_coa_resolves_nas_network(session, admin_principal, monkeypatch) -> None:
    """Ein als Netz eingetragenes NAS liefert das Secret, das Paket geht an die IP."""
    from app.services import coa as coa_module

    await NasService(session).create(
        NasCreate(
            nasname="192.0.2.0/24",
            secret="s",
            coa_enabled=True,
            coa_port=3799,
            coa_secret="coa-geheim",
        ),
        actor=admin_principal,
    )
    session.add(
        RadAcct(
            acctsessionid="s1",
            acctuniqueid="u1",
            username="anna",
            nasipaddress="192.0.2.10",
            acctstarttime=dt.datetime(2026, 9, 1, 8, 0),
            callingstationid="AA-BB-CC-DD-EE-FF",
        )
    )
    await session.commit()

    captured: dict[str, object] = {}

    def fake_send(host, port, secret, attributes, disconnect):
        captured.update(host=host, port=port, secret=secret)
        return 41, {}

    monkeypatch.setattr(coa_module, "_send_blocking", fake_send)
    result = await CoAService(session).execute(CoARequest(acctuniqueid="u1"), actor=admin_principal)
    assert result.ok
    assert captured["host"] == "192.0.2.10"
    assert captured["secret"] == "coa-geheim"


# --- Import ----------------------------------------------------------------


async def test_dry_run_reports_missing_password(session, admin_principal) -> None:
    """Was beim Import scheitert, muss schon die Vorschau als Fehler zeigen."""
    csv_text = "username,password\nanna,\n"
    service = ImportExportService(session)

    preview = await service.import_csv(csv_text, kind="user", dry_run=True, actor=admin_principal)
    assert preview.errors == 1
    assert preview.to_create == 0
    assert "password_required" in (preview.rows[0].message or "")

    applied = await service.import_csv(csv_text, kind="user", dry_run=False, actor=admin_principal)
    assert applied.errors == preview.errors


async def test_import_update_applies_password_and_disabled(session, admin_principal) -> None:
    """Bestehende Datensätze übernehmen auch Passwort, VLAN und Sperrzustand."""
    users = UserService(session)
    await users.create(UserCreate(username="anna", password="alt-geheim"), actor=admin_principal)

    csv_text = "username,password,vlan,disabled\nanna,neu-geheim,42,ja\n"
    report = await ImportExportService(session).import_csv(
        csv_text, kind="user", dry_run=False, actor=admin_principal
    )
    assert report.to_update == 1 and report.errors == 0

    detail = await users.get("anna")
    assert detail.status == "disabled"
    assert detail.vlan == "42"
    row = await session.scalar(
        select(RadCheck).where(
            RadCheck.username == "anna", RadCheck.attribute == "Cleartext-Password"
        )
    )
    assert row.value == "neu-geheim"


# --- Audit-Aufbewahrung ----------------------------------------------------


async def test_retention_worker_purges_once(session, admin_principal) -> None:
    from app.services.settings_service import KEY_AUDIT_RETENTION, SettingsService

    await UserService(session).create(
        UserCreate(username="anna", password="geheim123"), actor=admin_principal
    )
    entry = (await session.scalars(select(MgrAudit))).first()
    entry.ts = dt.datetime.now() - dt.timedelta(days=400)
    await SettingsService(session).update({KEY_AUDIT_RETENTION: 30})
    await session.commit()

    retention = int(await SettingsService(session).get(KEY_AUDIT_RETENTION))
    removed = await AuditService(session).purge(retention)
    await session.commit()
    assert removed >= 1


# --- Fixtures --------------------------------------------------------------


@pytest.fixture
def admin_account(admin_principal):
    return admin_principal


@pytest.fixture
async def client(session, engine):
    """Angemeldeter Administrator gegen die echte Anwendung."""
    settings.cookie_secure = False
    from app.api.deps import login_limiter

    login_limiter.clear()
    secret = pyotp.random_base32()
    session.add(
        MgrAccount(
            id=1,
            username="admin",
            role=Role.ADMINISTRATOR,
            password_hash=hash_password("ein-sicheres-passwort"),
            totp_enabled=True,
            totp_secret_enc=SecretBox(settings.coa_secret_key or settings.secret_key).encrypt(
                secret
            ),
        )
    )
    await session.commit()

    transport = ASGITransport(app=create_app())
    async with AsyncClient(transport=transport, base_url="http://testserver") as http:
        first = await http.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "ein-sicheres-passwort"},
        )
        await http.post(
            "/api/v1/auth/login/totp",
            json={"challenge": first.json()["challenge"], "totp_code": pyotp.TOTP(secret).now()},
        )
        yield http
