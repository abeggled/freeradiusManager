"""Regressionstests zu den sicherheitsrelevanten Befunden aus dem Review."""

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
from app.services.accounts import AccountService

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def client(engine) -> AsyncIterator[AsyncClient]:
    settings.cookie_secure = False
    from app.api.deps import login_limiter

    login_limiter.clear()
    transport = ASGITransport(app=create_app())
    async with AsyncClient(transport=transport, base_url="http://testserver") as http:
        yield http


async def _account(
    session, username: str, role: Role, *, totp: bool = False
) -> tuple[MgrAccount, str]:
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


async def _login(client: AsyncClient, username: str = "operator"):
    return await client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": "ein-sicheres-passwort"},
    )


async def test_disabling_account_revokes_existing_session(session, client) -> None:
    """Ein bereits ausgestelltes Cookie darf ein deaktiviertes Konto nicht weitertragen."""
    account, _ = await _account(session, "operator", Role.OPERATOR)
    await _login(client)
    assert (await client.get("/api/v1/auth/me")).status_code == 200

    account.is_active = False
    await session.commit()

    response = await client.get("/api/v1/users")
    assert response.status_code == 401
    assert response.json()["code"] == "error.unauthenticated"


async def test_role_change_ends_the_running_session(session, client) -> None:
    """Eine Rollenaenderung beendet die Sitzung sofort.

    Der Entzug wirkt damit ohne Verzoegerung; umgekehrt kann eine Erweiterung
    nicht ohne neue Anmeldung mit zweitem Faktor wirksam werden.
    """
    account, _ = await _account(session, "operator", Role.OPERATOR)
    await _login(client)
    created = await client.post("/api/v1/users", json={"username": "anna", "password": "geheim123"})
    assert created.status_code == 201

    account.role = Role.AUDITOR
    await session.commit()

    blocked = await client.post(
        "/api/v1/users", json={"username": "bruno", "password": "geheim123"}
    )
    assert blocked.status_code == 401
    assert blocked.json()["code"] == "error.reauthentication_required"


async def test_deleted_account_cannot_continue_session(session, client) -> None:
    account, _ = await _account(session, "operator", Role.OPERATOR)
    await _login(client)
    await session.delete(account)
    await session.commit()
    assert (await client.get("/api/v1/auth/me")).status_code == 401


async def test_password_alone_cannot_replace_existing_totp(session, client) -> None:
    """Wer nur das Passwort kennt, darf den zweiten Faktor nicht neu setzen."""
    _, secret = await _account(session, "admin", Role.ADMINISTRATOR, totp=True)
    first = await _login(client, "admin")
    assert first.json()["status"] == "totp_required"
    challenge = first.json()["challenge"]

    hijack = await client.post("/api/v1/auth/totp/enroll", json={"challenge": challenge})
    assert hijack.status_code == 401
    assert hijack.json()["code"] == "error.unauthenticated"

    # Der reguläre Weg mit dem bestehenden Faktor funktioniert weiterhin.
    ok = await client.post(
        "/api/v1/auth/login/totp",
        json={"challenge": challenge, "totp_code": pyotp.TOTP(secret).now()},
    )
    assert ok.status_code == 200


async def test_enrolled_account_cannot_re_enroll_itself(session, client) -> None:
    """Auch angemeldet ersetzt niemand seinen aktiven Faktor ohne Administrator."""
    _, secret = await _account(session, "admin", Role.ADMINISTRATOR, totp=True)
    first = await _login(client, "admin")
    await client.post(
        "/api/v1/auth/login/totp",
        json={"challenge": first.json()["challenge"], "totp_code": pyotp.TOTP(secret).now()},
    )
    response = await client.post("/api/v1/auth/me/totp/enroll")
    assert response.status_code == 409
    assert response.json()["code"] == "error.totp_already_enrolled"


async def test_totp_failures_count_towards_lockout(session) -> None:
    """Der zweite Faktor darf nicht unbegrenzt oft geraten werden."""
    from app.core.errors import AuthenticationError
    from app.services.accounts import LOCKOUT_THRESHOLD

    account, _ = await _account(session, "admin", Role.ADMINISTRATOR, totp=True)
    service = AccountService(session)
    for _ in range(LOCKOUT_THRESHOLD):
        with pytest.raises(AuthenticationError):
            await service.verify_totp_code(account, "000000")

    assert account.failed_logins >= LOCKOUT_THRESHOLD
    with pytest.raises(AuthenticationError) as excinfo:
        await service.authenticate("admin", "ein-sicheres-passwort")
    assert excinfo.value.code == "error.account_locked"


async def test_forwarded_for_is_ignored_without_trusted_proxy(session, client) -> None:
    """Ohne konfigurierte Proxys darf ein gefälschter Header das Limit nicht umgehen."""
    await _account(session, "operator", Role.OPERATOR)
    for index in range(settings.login_rate_limit):
        await client.post(
            "/api/v1/auth/login",
            json={"username": "operator", "password": "falsch"},
            headers={"X-Forwarded-For": f"203.0.113.{index}"},
        )
    blocked = await client.post(
        "/api/v1/auth/login",
        json={"username": "operator", "password": "falsch"},
        headers={"X-Forwarded-For": "203.0.113.250"},
    )
    assert blocked.status_code == 429


async def test_forwarded_for_is_used_behind_trusted_proxy(session) -> None:
    """Hinter einem eingetragenen Proxy zählt die weitergereichte Adresse."""
    from app.api import deps

    original = settings.trusted_proxies
    settings.trusted_proxies = ["127.0.0.0/8"]
    deps._trusted_networks.cache_clear()
    try:
        request = _fake_request("127.0.0.1", "198.51.100.7, 127.0.0.1")
        assert deps.client_ip(request) == "198.51.100.7"

        untrusted = _fake_request("198.51.100.9", "203.0.113.1")
        assert deps.client_ip(untrusted) == "198.51.100.9"
    finally:
        settings.trusted_proxies = original
        deps._trusted_networks.cache_clear()


def _fake_request(peer: str, forwarded: str):
    from starlette.datastructures import Headers
    from starlette.requests import Request

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "client": (peer, 12345),
        "headers": Headers({"x-forwarded-for": forwarded}).raw,
        "query_string": b"",
    }
    return Request(scope)


async def test_oidc_callback_rejects_disabled_account(session, client, monkeypatch) -> None:
    """Deaktivierte Konten dürfen sich auch über OIDC nicht neu anmelden."""
    from app.api.v1.endpoints import auth as auth_endpoint
    from app.services.oidc import OidcService

    account, _ = await _account(session, "oidc-user", Role.OPERATOR)
    account.oidc_subject = "subject-1"
    account.is_active = False
    await session.commit()

    settings.oidc_enabled = True
    monkeypatch.setattr(OidcService, "exchange", lambda self, code, verifier, nonce: _claims())
    monkeypatch.setattr(OidcService, "map_role", lambda self, claims: "operator")
    try:
        client.cookies.set(auth_endpoint.OIDC_STATE_COOKIE, "state|verifier|nonce")
        response = await client.get(
            "/api/v1/auth/oidc/callback?code=abc&state=state", follow_redirects=False
        )
        assert response.status_code == 401
        assert response.json()["code"] == "error.account_disabled"
    finally:
        settings.oidc_enabled = False


async def _claims() -> dict[str, str]:
    return {"sub": "subject-1", "preferred_username": "oidc-user"}
