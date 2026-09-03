"""API-Ebene: Anmeldung, RBAC und die wichtigsten Endpunkte (FR-10, Abschnitt 2)."""

from __future__ import annotations

from collections.abc import AsyncIterator

import pyotp
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app.core.config import settings
from app.core.crypto import SecretBox, hash_password
from app.main import create_app
from app.models.mgr import MgrAccount, Role

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def client(engine) -> AsyncIterator[AsyncClient]:
    settings.cookie_secure = False
    from app.api.deps import login_limiter

    login_limiter.clear()
    app = create_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as http:
        yield http


async def _account(
    session, username: str, role: Role, password: str = "ein-sicheres-passwort", totp: bool = False
) -> MgrAccount:
    secret = pyotp.random_base32()
    account = MgrAccount(
        username=username,
        role=role,
        password_hash=hash_password(password),
        totp_enabled=totp,
        totp_secret_enc=SecretBox(settings.coa_secret_key or settings.secret_key).encrypt(secret)
        if totp
        else None,
    )
    session.add(account)
    await session.commit()
    account.plain_totp_secret = secret  # type: ignore[attr-defined]
    return account


async def _login(client: AsyncClient, username: str, password: str = "ein-sicheres-passwort"):
    return await client.post(
        "/api/v1/auth/login", json={"username": username, "password": password}
    )


async def test_health_endpoints(client: AsyncClient) -> None:
    assert (await client.get("/healthz")).json() == {"status": "ok"}
    assert (await client.get("/readyz")).json() == {"status": "ok"}


async def test_login_sets_httponly_cookie(session, client: AsyncClient) -> None:
    await _account(session, "operator", Role.OPERATOR)
    response = await _login(client, "operator")
    assert response.status_code == 200
    assert response.json()["status"] == "authenticated"
    cookie = response.headers["set-cookie"].lower()
    assert "httponly" in cookie
    assert "samesite=lax" in cookie

    me = await client.get("/api/v1/auth/me")
    assert me.json()["username"] == "operator"


async def test_login_with_wrong_password_returns_error_structure(
    session, client: AsyncClient
) -> None:
    await _account(session, "operator", Role.OPERATOR)
    response = await client.post(
        "/api/v1/auth/login", json={"username": "operator", "password": "falsch"}
    )
    assert response.status_code == 401
    body = response.json()
    assert body["code"] == "error.invalid_credentials"
    assert body["message"] and "details" in body


async def test_error_message_is_translated(session, client: AsyncClient) -> None:
    await _account(session, "operator", Role.OPERATOR)
    german = await client.post(
        "/api/v1/auth/login", json={"username": "operator", "password": "falsch"}
    )
    english = await client.post(
        "/api/v1/auth/login?lang=en", json={"username": "operator", "password": "falsch"}
    )
    assert german.json()["message"] != english.json()["message"]


async def test_totp_is_required_when_enabled(session, client: AsyncClient) -> None:
    account = await _account(session, "admin", Role.ADMINISTRATOR, totp=True)
    first = await _login(client, "admin")
    assert first.json()["status"] == "totp_required"
    challenge = first.json()["challenge"]

    wrong = await client.post(
        "/api/v1/auth/login/totp", json={"challenge": challenge, "totp_code": "000000"}
    )
    assert wrong.status_code == 401

    code = pyotp.TOTP(account.plain_totp_secret).now()
    ok = await client.post(
        "/api/v1/auth/login/totp", json={"challenge": challenge, "totp_code": code}
    )
    assert ok.status_code == 200
    assert (await client.get("/api/v1/auth/me")).json()["role"] == "administrator"


async def test_administrator_without_totp_must_enroll(session, client: AsyncClient) -> None:
    await _account(session, "admin", Role.ADMINISTRATOR)
    response = await _login(client, "admin")
    assert response.json()["status"] == "totp_setup_required"

    challenge = response.json()["challenge"]
    setup = await client.post("/api/v1/auth/totp/enroll", json={"challenge": challenge})
    assert setup.status_code == 200
    secret = setup.json()["secret"]
    assert setup.json()["provisioning_uri"].startswith("otpauth://totp/")

    confirmed = await client.post(
        "/api/v1/auth/totp/confirm",
        json={"challenge": challenge, "totp_code": pyotp.TOTP(secret).now()},
    )
    assert confirmed.status_code == 200
    assert (await client.get("/api/v1/auth/me")).json()["totp_enabled"] is True


async def test_unauthenticated_access_is_rejected(client: AsyncClient) -> None:
    response = await client.get("/api/v1/users")
    assert response.status_code == 401
    assert response.json()["code"] == "error.unauthenticated"


async def test_auditor_cannot_write(session, client: AsyncClient) -> None:
    await _account(session, "auditor", Role.AUDITOR)
    await _login(client, "auditor")

    assert (await client.get("/api/v1/users")).status_code == 200
    created = await client.post("/api/v1/users", json={"username": "anna", "password": "geheim123"})
    assert created.status_code == 403
    assert created.json()["code"] == "error.forbidden"


async def test_operator_has_no_access_to_nas(session, client: AsyncClient) -> None:
    await _account(session, "operator", Role.OPERATOR)
    await _login(client, "operator")
    assert (await client.get("/api/v1/nas")).status_code == 403


async def test_operator_can_manage_users(session, client: AsyncClient) -> None:
    await _account(session, "operator", Role.OPERATOR)
    await _login(client, "operator")

    created = await client.post(
        "/api/v1/users",
        json={"username": "anna", "password": "geheim123", "vlan": "20"},
    )
    assert created.status_code == 201
    body = created.json()
    assert body["vlan"] == "20"
    assert all(
        a["value"] == "********"
        for a in body["check_attributes"]
        if a["attribute"].endswith("Password")
    )

    assert (await client.post("/api/v1/users/anna/disable")).status_code == 204
    assert (await client.get("/api/v1/users/anna")).json()["status"] == "disabled"

    listing = await client.get("/api/v1/users?search=anna")
    assert listing.json()["meta"]["total"] == 1

    export = await client.get("/api/v1/users/export")
    assert export.headers["content-type"].startswith("text/csv")
    assert "geheim123" not in export.text

    assert (await client.delete("/api/v1/users/anna")).status_code == 204


async def test_account_management_is_admin_only(session, client: AsyncClient) -> None:
    await _account(session, "operator", Role.OPERATOR)
    await _login(client, "operator")
    assert (await client.get("/api/v1/accounts")).status_code == 403


async def test_dictionary_endpoint_lists_vlan_attributes(session, client: AsyncClient) -> None:
    await _account(session, "auditor", Role.AUDITOR)
    await _login(client, "auditor")
    body = (await client.get("/api/v1/groups/dictionary")).json()
    names = {a["name"] for a in body["attributes"]}
    assert {"Tunnel-Type", "Tunnel-Medium-Type", "Tunnel-Private-Group-Id"} <= names
    assert ":=" in body["check_operators"]


async def test_logout_clears_cookie(session, client: AsyncClient) -> None:
    await _account(session, "operator", Role.OPERATOR)
    await _login(client, "operator")
    assert (await client.post("/api/v1/auth/logout")).status_code == 204
    assert (await client.get("/api/v1/auth/me")).status_code == 401


async def test_login_rate_limit(session, client: AsyncClient) -> None:
    await _account(session, "operator", Role.OPERATOR)
    for _ in range(settings.login_rate_limit):
        await client.post("/api/v1/auth/login", json={"username": "operator", "password": "falsch"})
    blocked = await client.post(
        "/api/v1/auth/login", json={"username": "operator", "password": "falsch"}
    )
    assert blocked.status_code == 429
    assert blocked.json()["code"] == "error.rate_limited"


async def test_unknown_api_path_returns_error_object(client: AsyncClient) -> None:
    """Der SPA-Fallback darf API-Pfade nicht mit HTML beantworten."""
    response = await client.get("/api/v1/gibtsnicht")
    assert response.status_code == 404
    assert response.json()["code"] == "error.not_found"
