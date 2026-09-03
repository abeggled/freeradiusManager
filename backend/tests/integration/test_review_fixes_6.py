"""Regressionstests zur siebten Review-Runde."""

from __future__ import annotations

from collections.abc import AsyncIterator

import pyotp
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.core.config import settings
from app.core.crypto import SecretBox, hash_password
from app.core.errors import NotFoundError
from app.main import create_app
from app.models.mgr import MgrAccount, MgrAudit, Role
from app.models.radius import RadUserGroup
from app.schemas.groups import GroupCreate
from app.schemas.users import DeviceCreate, UserCreate
from app.services.accounts import AccountService
from app.services.authlog import AuthLogService
from app.services.devices import DeviceService
from app.services.groups import GroupService
from app.services.settings_service import KEY_MAC_FORMAT, SettingsService
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


# --- Rechteausweitung ------------------------------------------------------


async def test_promotion_requires_a_new_login(session, client) -> None:
    """Eine nur mit Passwort begonnene Sitzung darf nicht zum Administrator werden."""
    account, _ = await _account(session, "operator", Role.OPERATOR)
    await client.post(
        "/api/v1/auth/login",
        json={"username": "operator", "password": "ein-sicheres-passwort"},
    )
    assert (await client.get("/api/v1/auth/me")).status_code == 200

    account.role = Role.ADMINISTRATOR
    await session.commit()

    response = await client.get("/api/v1/accounts")
    assert response.status_code == 401
    assert response.json()["code"] == "error.reauthentication_required"


async def test_totp_reset_ends_privileged_sessions(session, client) -> None:
    """Ohne aktiven zweiten Faktor endet eine Administratorsitzung."""
    account, secret = await _account(session, "admin", Role.ADMINISTRATOR, totp=True)
    first = await client.post(
        "/api/v1/auth/login", json={"username": "admin", "password": "ein-sicheres-passwort"}
    )
    await client.post(
        "/api/v1/auth/login/totp",
        json={"challenge": first.json()["challenge"], "totp_code": pyotp.TOTP(secret).now()},
    )
    assert (await client.get("/api/v1/accounts")).status_code == 200

    account.totp_enabled = False
    account.totp_secret_enc = None
    await session.commit()

    response = await client.get("/api/v1/accounts")
    assert response.status_code == 401


async def test_enrollment_login_clears_failures(session, client) -> None:
    """Auch der Einrichtungsweg schliesst eine Anmeldung vollständig ab."""
    account, _ = await _account(session, "admin", Role.ADMINISTRATOR)
    for _ in range(3):
        await client.post("/api/v1/auth/login", json={"username": "admin", "password": "falsch"})
    await session.commit()
    await session.refresh(account)
    assert account.failed_logins == 3

    first = await client.post(
        "/api/v1/auth/login", json={"username": "admin", "password": "ein-sicheres-passwort"}
    )
    challenge = first.json()["challenge"]
    setup = await client.post(f"/api/v1/auth/totp/enroll?challenge={challenge}")
    confirmed = await client.post(
        "/api/v1/auth/totp/confirm",
        json={
            "challenge": challenge,
            "totp_code": pyotp.TOTP(setup.json()["secret"]).now(),
        },
    )
    assert confirmed.status_code == 200
    # Neue Lesetransaktion: InnoDB liefert sonst den alten Snapshot
    # (REPEATABLE READ) und der Test saehe die Aenderung nicht.
    await session.commit()
    await session.refresh(account)
    assert account.failed_logins == 0


async def test_oidc_role_change_is_audited(session) -> None:
    account, _ = await _account(session, "oidc", Role.OPERATOR)
    await _account(session, "admin", Role.ADMINISTRATOR)

    await AccountService(session).apply_mapped_role(account, Role.AUDITOR, actor_ip="203.0.113.9")
    entry = await session.scalar(select(MgrAudit).where(MgrAudit.action == "account.role_mapped"))
    assert entry is not None
    assert "operator" in (entry.before_json or "")
    assert "auditor" in (entry.after_json or "")


# --- Geräte ----------------------------------------------------------------


async def test_create_does_not_duplicate_after_format_change(session, admin_principal) -> None:
    devices = DeviceService(session)
    await devices.create(DeviceCreate(mac="aa:bb:cc:dd:ee:ff"), actor=admin_principal)
    await SettingsService(session).update({KEY_MAC_FORMAT: "plain_lower"})
    await session.commit()

    with pytest.raises(Exception) as excinfo:
        await devices.create(DeviceCreate(mac="AA-BB-CC-DD-EE-FF"), actor=admin_principal)
    assert "user_exists" in str(excinfo.value)


async def test_device_endpoints_reject_regular_users(session, admin_principal) -> None:
    """Ein Benutzer mit MAC-förmigem Namen ist kein Gerät."""
    await UserService(session).create(
        UserCreate(username="aa:bb:cc:dd:ee:ff", password="geheim123"), actor=admin_principal
    )
    devices = DeviceService(session)
    for action in (
        lambda: devices.delete("aa:bb:cc:dd:ee:ff", actor=admin_principal),
        lambda: devices.set_disabled("aa:bb:cc:dd:ee:ff", True, actor=admin_principal),
    ):
        with pytest.raises(NotFoundError):
            await action()

    assert (await UserService(session).get("aa:bb:cc:dd:ee:ff")).status == "active"


# --- Diagnose und Gruppen --------------------------------------------------


async def test_diagnosis_knows_membership_only_subjects(session) -> None:
    session.add(RadUserGroup(username="nur-gruppe", groupname="g1", priority=1))
    await session.commit()

    result = await AuthLogService(session).diagnose("nur-gruppe")
    assert result.exists is True
    codes = {h.code for h in result.hints}
    assert "diag.user_unknown" not in codes
    assert "diag.no_credentials" in codes


async def test_deleting_a_missing_group_is_rejected(session, admin_principal) -> None:
    with pytest.raises(NotFoundError):
        await GroupService(session).delete("gibtsnicht", actor=admin_principal)
    entries = (
        await session.scalars(select(MgrAudit).where(MgrAudit.action == "group.delete"))
    ).all()
    assert entries == []


async def test_existing_group_can_still_be_deleted(session, admin_principal) -> None:
    service = GroupService(session)
    await service.create(GroupCreate(groupname="g1", vlan="10"), actor=admin_principal)
    assert await service.delete("g1", actor=admin_principal, force=True) == 0


# --- Paginierung -----------------------------------------------------------


async def test_reported_limit_matches_the_page_size(session, client) -> None:
    await _account(session, "auditor", Role.AUDITOR)
    await client.post(
        "/api/v1/auth/login",
        json={"username": "auditor", "password": "ein-sicheres-passwort"},
    )
    for path in ("/api/v1/sessions?limit=1000", "/api/v1/authlog?limit=1000"):
        response = await client.get(path)
        assert response.status_code == 200
        assert response.json()["meta"]["limit"] == 200


# --- Schemapruefung --------------------------------------------------------


async def test_schema_check_requires_every_mapped_column(engine) -> None:
    """Eine Spalte, die das ORM selektiert, muss beim Start verlangt werden."""
    from sqlalchemy import text

    from app.repositories.radius.schema import REQUIRED_COLUMNS, inspect_schema

    assert "realm" in REQUIRED_COLUMNS["radacct"]
    assert "class" in REQUIRED_COLUMNS["radpostauth"]

    async with engine.begin() as connection:
        await connection.execute(text("ALTER TABLE radacct DROP COLUMN realm"))
    try:
        async with engine.connect() as connection:
            database = str(await connection.scalar(text("SELECT DATABASE()")))
            report = await inspect_schema(connection, database)
        assert not report.ok
        assert report.missing_columns["radacct"] == ["realm"]
    finally:
        async with engine.begin() as connection:
            await connection.execute(
                text("ALTER TABLE radacct ADD COLUMN realm VARCHAR(64) DEFAULT ''")
            )


async def test_index_html_carries_the_configured_base_path(tmp_path, monkeypatch) -> None:
    """Unter einem Präfix müssen Asset- und API-Adressen mitwandern."""
    from app import main

    static = tmp_path / "static"
    (static / "assets").mkdir(parents=True)
    (static / "index.html").write_text('<base href="/" />\n<script src="./assets/a.js">', "utf-8")

    monkeypatch.setattr(main, "STATIC_DIR", static)
    monkeypatch.setattr(main.settings, "root_path", "/manager")
    monkeypatch.setattr(main.settings, "schema_check_on_startup", False)

    app = main.create_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as http:
        response = await http.get("/irgendeine/route")
    assert response.status_code == 200
    assert '<base href="/manager/" />' in response.text
    # Relative Asset-Pfade lösen darüber auf.
    assert "./assets/a.js" in response.text
