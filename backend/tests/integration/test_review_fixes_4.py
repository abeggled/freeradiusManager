"""Regressionstests zur vierten Review-Runde."""

from __future__ import annotations

import datetime as dt
from collections.abc import AsyncIterator

import pyotp
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app.core.config import Settings, settings
from app.core.crypto import SecretBox, hash_password
from app.main import create_app
from app.models.mgr import MgrAccount, Role
from app.models.radius import RadAcct
from app.repositories.directory import SubjectFilter
from app.schemas.nas import NasCreate
from app.schemas.users import DeviceCreate, SubjectMeta, UserCreate
from app.services.accounts import LOCKOUT_THRESHOLD
from app.services.authlog import AuthLogService
from app.services.devices import DeviceService
from app.services.importexport import ImportExportService
from app.services.nas import NasService
from app.services.settings_service import SettingsService
from app.services.users import UserService

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def client(engine) -> AsyncIterator[AsyncClient]:
    settings.cookie_secure = False
    from app.api.deps import login_ip_limiter, login_limiter

    login_limiter.clear()
    login_ip_limiter.clear()
    transport = ASGITransport(app=create_app())
    async with AsyncClient(transport=transport, base_url="http://testserver") as http:
        yield http


async def _account(session, username: str, role: Role, *, totp: bool = False):
    secret = pyotp.random_base32()
    account = MgrAccount(
        username=username,
        role=role,
        password_hash=hash_password("ein-sicheres-passwort"),
        totp_enabled=totp,
        totp_secret_enc=SecretBox(settings.coa_secret_key or settings.secret_key).encrypt(secret)
        if totp
        else None,
    )
    session.add(account)
    await session.commit()
    return account, secret


# --- Rate-Limits -----------------------------------------------------------


async def test_own_login_does_not_clear_the_ip_quota(session, client) -> None:
    """Eine eigene gültige Anmeldung darf fremde Fehlversuche nicht löschen."""
    await _account(session, "operator", Role.OPERATOR)

    for index in range(settings.login_ip_rate_limit - 1):
        await client.post(
            "/api/v1/auth/login", json={"username": f"raten{index}", "password": "falsch"}
        )
    ok = await client.post(
        "/api/v1/auth/login",
        json={"username": "operator", "password": "ein-sicheres-passwort"},
    )
    assert ok.status_code == 200

    blocked = await client.post(
        "/api/v1/auth/login", json={"username": "weiter", "password": "falsch"}
    )
    assert blocked.status_code == 429


async def test_new_challenge_does_not_reset_totp_failures(session, client) -> None:
    """Eine neue Challenge anzufordern darf die Fehlversuche nicht löschen."""
    account, _ = await _account(session, "admin", Role.ADMINISTRATOR, totp=True)

    for _ in range(LOCKOUT_THRESHOLD - 1):
        first = await client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "ein-sicheres-passwort"},
        )
        assert first.json()["status"] == "totp_required"
        await client.post(
            "/api/v1/auth/login/totp",
            json={"challenge": first.json()["challenge"], "totp_code": "000000"},
        )

    await session.refresh(account)
    assert account.failed_logins == LOCKOUT_THRESHOLD - 1


# --- Konfiguration ---------------------------------------------------------


@pytest.mark.asyncio(loop_scope="session")
async def test_production_requires_own_keys() -> None:
    with pytest.raises(Exception, match="FRM_SECRET_KEY"):
        Settings(environment="production", secret_key="", coa_secret_key="")
    ok = Settings(environment="production", secret_key="a" * 48, coa_secret_key="b" * 44)
    assert ok.environment == "production"


async def test_invalid_mac_format_falls_back_to_valid_key(session, monkeypatch) -> None:
    from app.core import mac as mac_module
    from app.services import settings_service

    monkeypatch.setattr(settings_service.app_settings, "default_mac_format", "unsinn")
    fmt = await SettingsService(session).mac_format()
    assert fmt in mac_module.MAC_FORMATS


# --- Diagnose --------------------------------------------------------------


async def test_diagnosis_accepts_nas_networks(session, admin_principal) -> None:
    """Ein als Netz eingetragenes NAS gilt nicht als unbekannt."""
    await NasService(session).create(
        NasCreate(nasname="192.0.2.0/24", shortname="netz", secret="s"), actor=admin_principal
    )
    await UserService(session).create(
        UserCreate(username="anna", password="geheim123"), actor=admin_principal
    )
    session.add(
        RadAcct(
            acctsessionid="s1",
            acctuniqueid="u1",
            username="anna",
            nasipaddress="192.0.2.5",
            acctstarttime=dt.datetime(2026, 9, 1, 8, 0),
            callingstationid="AA-BB-CC-DD-EE-FF",
        )
    )
    await session.commit()

    result = await AuthLogService(session).diagnose("anna")
    assert "diag.nas_unknown" not in {h.code for h in result.hints}


# --- Import und Export -----------------------------------------------------


async def test_malformed_row_is_reported_not_fatal(session, admin_principal) -> None:
    """Eine Zeile mit überzähligen Feldern darf den Import nicht abbrechen."""
    csv_text = "username,password\nanna,geheim123\nbruno,geheim456,zuviel\ncarla,geheim789\n"
    report = await ImportExportService(session).import_csv(
        csv_text, kind="user", dry_run=False, actor=admin_principal
    )
    assert report.total == 3
    assert report.errors == 1
    assert report.to_create == 2

    users = UserService(session)
    assert (await users.get("anna")).status == "active"
    assert (await users.get("carla")).status == "active"


async def test_cross_kind_import_is_rejected(session, admin_principal) -> None:
    """Ein Geräteimport darf einen Benutzer nicht stillschweigend vereinnahmen."""
    await UserService(session).create(
        UserCreate(username="aa:bb:cc:dd:ee:ff", password="geheim123"), actor=admin_principal
    )
    report = await ImportExportService(session).import_csv(
        "mac,location\naa:bb:cc:dd:ee:ff,Empfang\n",
        kind="device",
        dry_run=False,
        actor=admin_principal,
    )
    assert report.errors == 1
    assert report.to_update == 0
    assert "subject_type_mismatch" in (report.rows[0].message or "")

    preview = await ImportExportService(session).import_csv(
        "mac,location\naa:bb:cc:dd:ee:ff,Empfang\n",
        kind="device",
        dry_run=True,
        actor=admin_principal,
    )
    assert preview.errors == 1


async def test_export_neutralises_spreadsheet_formulas(session, admin_principal) -> None:
    """Frei wählbare Felder dürfen beim Öffnen keine Formel auslösen."""
    await UserService(session).create(
        UserCreate(
            username="anna",
            password="geheim123",
            meta=SubjectMeta(note='=HYPERLINK("http://example.org")', owner="+41"),
        ),
        actor=admin_principal,
    )
    csv_text = await ImportExportService(session).export(SubjectFilter())
    assert "'=HYPERLINK" in csv_text
    assert "'+41" in csv_text


# --- Geräte ----------------------------------------------------------------


async def test_device_metadata_survives_repeated_import(session, admin_principal) -> None:
    devices = DeviceService(session)
    await devices.create(
        DeviceCreate(mac="aa:bb:cc:dd:ee:ff", meta=SubjectMeta(location="Empfang")),
        actor=admin_principal,
    )
    await ImportExportService(session).import_csv(
        "mac,device_type\naa:bb:cc:dd:ee:ff,Drucker\n",
        kind="device",
        dry_run=False,
        actor=admin_principal,
    )
    detail = await devices.get("aa:bb:cc:dd:ee:ff")
    assert detail.location == "Empfang"
    assert detail.device_type == "Drucker"


# --- Mitgliedschaften ------------------------------------------------------


async def test_update_can_keep_multiple_groups(session, admin_principal) -> None:
    """Die Oberfläche sendet alle Mitgliedschaften; das Backend erhält sie."""
    from app.schemas.users import MembershipIn, UserUpdate

    users = UserService(session)
    await users.create(
        UserCreate(
            username="anna",
            password="geheim123",
            groups=[
                MembershipIn(groupname="a", priority=1),
                MembershipIn(groupname="b", priority=5),
            ],
        ),
        actor=admin_principal,
    )
    detail = await users.get("anna")
    await users.update(
        "anna",
        UserUpdate(
            groups=[
                MembershipIn(groupname=m.groupname, priority=m.priority) for m in detail.memberships
            ],
            vlan="20",
        ),
        actor=admin_principal,
    )
    updated = await users.get("anna")
    assert sorted(updated.groups) == ["a", "b"]
    assert {m.groupname: m.priority for m in updated.memberships} == {"a": 1, "b": 5}


# --- Aufbewahrung ----------------------------------------------------------


@pytest.mark.asyncio(loop_scope="session")
async def test_retention_worker_is_started() -> None:
    """Der Job muss tatsächlich in der Lifespan hängen, nicht nur existieren."""
    import inspect

    from app import main

    source = inspect.getsource(main.lifespan)
    assert "retention_worker" in source
    assert callable(main.retention_worker)
