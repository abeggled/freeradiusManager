"""Regressionstests zur dritten Review-Runde."""

from __future__ import annotations

import datetime as dt
from collections.abc import AsyncIterator

import pyotp
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.core.config import settings
from app.core.crypto import SecretBox, hash_password
from app.core.errors import AuthenticationError, ValidationError
from app.main import create_app
from app.models.mgr import MgrAccount, MgrAudit, Role
from app.models.radius import RadUserGroup
from app.repositories.directory import SubjectFilter
from app.schemas.users import BulkAction, DeviceCreate, UserCreate
from app.services.accounts import LOCKOUT_THRESHOLD, AccountService
from app.services.devices import DeviceService
from app.services.importexport import ImportExportService
from app.services.settings_service import KEY_MAC_FORMAT, SettingsService
from app.services.stats import StatsService
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


# --- Anmeldung -------------------------------------------------------------


async def test_username_rotation_does_not_reset_the_limit(session, client) -> None:
    """Ein neuer Name je Versuch darf kein frisches Kontingent geben."""
    await _account(session, "operator", Role.OPERATOR)
    last = None
    for index in range(settings.login_ip_rate_limit + 1):
        last = await client.post(
            "/api/v1/auth/login",
            json={"username": f"raten{index}", "password": "falsch"},
        )
    assert last is not None
    assert last.status_code == 429
    assert last.json()["code"] == "error.rate_limited"


async def test_combined_login_reaches_lockout(session, client) -> None:
    """Passwort und TOTP in einem Aufruf: der Zaehler darf nicht zurückspringen.

    Zuvor setzte die erfolgreiche Passwortpruefung den Zaehler jedes Mal auf
    null, sodass die Kontosperre auf diesem Weg nie erreichbar war.
    """
    from app.api.deps import login_ip_limiter, login_limiter

    account, _ = await _account(session, "admin", Role.ADMINISTRATOR, totp=True)
    for _ in range(LOCKOUT_THRESHOLD):
        response = await client.post(
            "/api/v1/auth/login",
            json={
                "username": "admin",
                "password": "ein-sicheres-passwort",
                "totp_code": "000000",
            },
        )
        assert response.status_code == 401

    await session.refresh(account)
    assert account.failed_logins >= LOCKOUT_THRESHOLD
    assert account.locked_until is not None

    # Ohne das greifende Rate-Limit bliebe die Kontosperre der wirksame Schutz.
    login_limiter.clear()
    login_ip_limiter.clear()
    blocked = await client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "ein-sicheres-passwort", "totp_code": "000000"},
    )
    assert blocked.json()["code"] == "error.account_locked"


async def test_successful_login_clears_the_counter(session, client) -> None:
    account, secret = await _account(session, "admin", Role.ADMINISTRATOR, totp=True)
    await client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "ein-sicheres-passwort", "totp_code": "000000"},
    )
    ok = await client.post(
        "/api/v1/auth/login",
        json={
            "username": "admin",
            "password": "ein-sicheres-passwort",
            "totp_code": pyotp.TOTP(secret).now(),
        },
    )
    assert ok.status_code == 200
    await session.refresh(account)
    assert account.failed_logins == 0


async def test_totp_limit_is_per_account(session, client) -> None:
    """Hinter einem NAT darf ein Konto nicht die anderen aussperren."""
    _, first_secret = await _account(session, "admin1", Role.ADMINISTRATOR, totp=True)
    _, second_secret = await _account(session, "admin2", Role.ADMINISTRATOR, totp=True)

    first = await client.post(
        "/api/v1/auth/login", json={"username": "admin1", "password": "ein-sicheres-passwort"}
    )
    for _ in range(settings.login_rate_limit):
        await client.post(
            "/api/v1/auth/login/totp",
            json={"challenge": first.json()["challenge"], "totp_code": "000000"},
        )

    second = await client.post(
        "/api/v1/auth/login", json={"username": "admin2", "password": "ein-sicheres-passwort"}
    )
    ok = await client.post(
        "/api/v1/auth/login/totp",
        json={
            "challenge": second.json()["challenge"],
            "totp_code": pyotp.TOTP(second_secret).now(),
        },
    )
    assert ok.status_code == 200
    del first_secret


async def test_oidc_does_not_bind_existing_local_account(session, client, monkeypatch) -> None:
    """Eine fremde Identität darf das Bootstrap-Konto nicht übernehmen."""
    from app.api.v1.endpoints import auth as auth_endpoint
    from app.services.oidc import OidcService

    account, _ = await _account(session, "admin", Role.ADMINISTRATOR)
    settings.oidc_enabled = True
    monkeypatch.setattr(
        OidcService,
        "exchange",
        lambda self, code, verifier, nonce: _claims(),
    )
    monkeypatch.setattr(OidcService, "map_role", lambda self, claims: "auditor")
    try:
        client.cookies.set(auth_endpoint.OIDC_STATE_COOKIE, "state|verifier|nonce")
        response = await client.get(
            "/api/v1/auth/oidc/callback?code=abc&state=state", follow_redirects=False
        )
        assert response.status_code == 401
        assert response.json()["code"] == "error.oidc_account_conflict"
    finally:
        settings.oidc_enabled = False

    await session.refresh(account)
    assert account.role is Role.ADMINISTRATOR
    assert account.oidc_subject is None


async def _claims() -> dict[str, str]:
    return {"sub": "subject-1", "preferred_username": "admin"}


async def test_last_administrator_survives_role_mapping(session) -> None:
    account, _ = await _account(session, "admin", Role.ADMINISTRATOR)
    with pytest.raises(ValidationError) as excinfo:
        await AccountService(session).apply_mapped_role(account, Role.AUDITOR)
    assert excinfo.value.code == "error.last_administrator"


async def test_account_fields_can_be_cleared(session, admin_principal) -> None:
    from app.schemas.accounts import AccountCreate, AccountUpdate

    service = AccountService(session)
    created = await service.create(
        AccountCreate(
            username="helpdesk",
            password="ein-sicheres-passwort",
            email="a@example.org",
            display_name="Anna",
        ),
        actor=admin_principal,
    )
    updated = await service.update(
        created.id, AccountUpdate(email=None, display_name=None), actor=admin_principal
    )
    assert updated.email is None
    assert updated.display_name is None


# --- Bulk und Export -------------------------------------------------------


async def test_bulk_expiry_requires_a_date(session, admin_principal) -> None:
    """Ohne Datum würde die gesamte Auswahl sofort ablaufen."""
    await UserService(session).create(
        UserCreate(username="anna", password="geheim123"), actor=admin_principal
    )
    with pytest.raises(ValidationError) as excinfo:
        await ImportExportService(session).bulk(
            BulkAction(action="set_expiry", usernames=["anna"]),
            SubjectFilter(),
            actor=admin_principal,
        )
    assert excinfo.value.details["field"] == "expires_at"
    assert (await UserService(session).get("anna")).expires_at is None


async def test_bulk_audit_records_affected_usernames(session, admin_principal) -> None:
    users = UserService(session)
    for name in ("anna", "bruno"):
        await users.create(UserCreate(username=name, password="geheim123"), actor=admin_principal)

    await ImportExportService(session).bulk(
        BulkAction(action="assign_group", usernames=["anna", "bruno"], groupname="g1"),
        SubjectFilter(),
        actor=admin_principal,
    )
    entry = await session.scalar(select(MgrAudit).where(MgrAudit.action == "bulk.assign_group"))
    assert "anna" in (entry.after_json or "")
    assert "bruno" in (entry.after_json or "")

    per_object = (
        await session.scalars(select(MgrAudit).where(MgrAudit.action == "user.assign_group"))
    ).all()
    assert {e.object_id for e in per_object} == {"anna", "bruno"}


async def test_export_above_cap_is_rejected(session, admin_principal) -> None:
    users = UserService(session)
    for index in range(4):
        await users.create(
            UserCreate(username=f"user{index}", password="geheim123"), actor=admin_principal
        )
    with pytest.raises(ValidationError) as excinfo:
        await ImportExportService(session).export(SubjectFilter(), cap=2)
    assert excinfo.value.code == "error.selection_too_large"


# --- Verzeichnis und Statistik --------------------------------------------


async def test_membership_only_subject_is_readable(session) -> None:
    """Was die Liste zeigt, muss auch aufrufbar sein."""
    session.add(RadUserGroup(username="nur-gruppe", groupname="g1", priority=1))
    await session.commit()

    detail = await UserService(session).get("nur-gruppe")
    assert detail.groups == ["g1"]


async def test_dashboard_counts_match_the_listings(session, admin_principal) -> None:
    users = UserService(session)
    await users.create(UserCreate(username="anna", password="geheim123"), actor=admin_principal)
    await DeviceService(session).create(
        DeviceCreate(mac="aa:bb:cc:dd:ee:ff"), actor=admin_principal
    )

    stats = await StatsService(session).compute()
    listed_users, users_total = await users.search(SubjectFilter(subject_type=None))
    assert stats["users_total"] == 1
    assert stats["devices_total"] == 1
    assert users_total == 2  # Benutzer und Gerät zusammen
    assert len(listed_users) == 2


# --- MAC-Format ------------------------------------------------------------


async def test_device_stays_addressable_after_format_change(session, admin_principal) -> None:
    """Bestehende Geräte behalten ihren Namen; sie müssen trotzdem erreichbar sein."""
    devices = DeviceService(session)
    created = await devices.create(DeviceCreate(mac="aa:bb:cc:dd:ee:ff"), actor=admin_principal)
    assert created.username == "aa:bb:cc:dd:ee:ff"

    await SettingsService(session).update({KEY_MAC_FORMAT: "hyphen_upper"})
    await session.commit()

    detail = await devices.get("aa:bb:cc:dd:ee:ff")
    assert detail.username == "aa:bb:cc:dd:ee:ff"

    await devices.set_disabled("AA-BB-CC-DD-EE-FF", True, actor=admin_principal)
    assert (await devices.get("aabbccddeeff")).status == "disabled"


async def test_import_does_not_duplicate_after_format_change(session, admin_principal) -> None:
    devices = DeviceService(session)
    await devices.create(DeviceCreate(mac="aa:bb:cc:dd:ee:ff"), actor=admin_principal)
    await SettingsService(session).update({KEY_MAC_FORMAT: "plain_lower"})
    await session.commit()

    report = await ImportExportService(session).import_csv(
        "mac,location\nAA-BB-CC-DD-EE-FF,Empfang\n",
        kind="device",
        dry_run=False,
        actor=admin_principal,
    )
    assert report.to_update == 1 and report.to_create == 0

    items, total = await devices.search(SubjectFilter())
    assert total == 1
    assert items[0].location == "Empfang"


async def test_new_device_uses_the_configured_format(session, admin_principal) -> None:
    await SettingsService(session).update({KEY_MAC_FORMAT: "plain_lower"})
    await session.commit()
    detail = await DeviceService(session).create(
        DeviceCreate(mac="11-22-33-44-55-66"), actor=admin_principal
    )
    assert detail.username == "112233445566"


# --- Gruppen ---------------------------------------------------------------


async def test_member_listing_rejects_invalid_paging(session, client) -> None:
    """Unsinnige Seitenparameter sind ein Eingabefehler, kein Serverfehler."""
    await _account(session, "auditor", Role.AUDITOR)
    await client.post(
        "/api/v1/auth/login", json={"username": "auditor", "password": "ein-sicheres-passwort"}
    )
    rejected = await client.get("/api/v1/groups/g1/members?limit=1000000&offset=-5")
    assert rejected.status_code == 422
    assert rejected.json()["code"] == "error.validation"

    ok = await client.get("/api/v1/groups/g1/members?limit=50&offset=0")
    assert ok.status_code == 200
    assert ok.json() == []


async def test_challenge_rejected_when_locked(session) -> None:
    account, _ = await _account(session, "admin", Role.ADMINISTRATOR, totp=True)
    service = AccountService(session)
    challenge = service.challenge_for(account)
    account.locked_until = dt.datetime.now() + dt.timedelta(minutes=5)
    await session.commit()
    with pytest.raises(AuthenticationError):
        await service.account_from_challenge(challenge)
