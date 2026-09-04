"""Regressionstests zur fünften Review-Runde."""

from __future__ import annotations

import datetime as dt
from collections.abc import AsyncIterator

import pyotp
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app.core.config import settings
from app.core.crypto import SecretBox, hash_password
from app.core.errors import AuthenticationError
from app.main import create_app
from app.models.mgr import MgrAccount, Role
from app.repositories.directory import SubjectFilter
from app.schemas.users import MembershipIn, SubjectMeta, UserCreate
from app.services.accounts import LOCKOUT_THRESHOLD, AccountService
from app.services.importexport import ImportExportService
from app.services.users import UserService

pytestmark = pytest.mark.asyncio


async def _ensure_groups(session, actor, *names: str) -> None:
    """Mitgliedschaften setzen vorhandene Gruppen voraus (Phantomgruppen-Schutz)."""
    from app.schemas.groups import GroupCreate
    from app.services.groups import GroupService

    service = GroupService(session)
    for index, name in enumerate(names):
        await service.create(GroupCreate(groupname=name, vlan=str(100 + index)), actor=actor)


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


async def test_further_attempts_do_not_extend_the_lockout(session) -> None:
    """Sonst liesse sich ein Konto ohne Passwortkenntnis dauerhaft blockieren."""
    account, _ = await _account(session, "operator", Role.OPERATOR)
    service = AccountService(session)

    for _ in range(LOCKOUT_THRESHOLD):
        with pytest.raises(AuthenticationError):
            await service.authenticate("operator", "falsch")

    first_deadline = account.locked_until
    assert first_deadline is not None

    with pytest.raises(AuthenticationError):
        await service.authenticate("operator", "falsch")
    assert account.locked_until == first_deadline


async def test_unknown_username_performs_the_same_work(session) -> None:
    """Ohne Vergleichs-Hash wäre an der Antwortzeit ablesbar, welche Konten es gibt."""
    from app.services import accounts as accounts_module

    calls: list[str | None] = []
    # Argon2 laeuft in einem Worker-Thread (``verify_password_async``); geprueft
    # wird weiterhin, dass ueberhaupt gegen einen Hash verglichen wird.
    original = accounts_module.verify_password_async

    async def counting(password: str, password_hash: str | None) -> bool:
        calls.append(password_hash)
        return await original(password, password_hash)

    accounts_module.verify_password_async = counting  # type: ignore[assignment]
    try:
        with pytest.raises(AuthenticationError):
            await AccountService(session).authenticate("gibtsnicht", "egal")
    finally:
        accounts_module.verify_password_async = original  # type: ignore[assignment]

    assert calls and calls[0] is not None
    assert calls[0].startswith("$argon2id$")


async def test_background_requests_do_not_extend_the_session(session, client) -> None:
    """Ein offenes Dashboard darf den Idle-Timeout nicht aushebeln."""
    await _account(session, "operator", Role.OPERATOR)
    await client.post(
        "/api/v1/auth/login",
        json={"username": "operator", "password": "ein-sicheres-passwort"},
    )

    background = await client.get("/api/v1/stats", headers={"X-Background-Refresh": "1"})
    assert background.status_code == 200
    assert "set-cookie" not in background.headers

    foreground = await client.get("/api/v1/users")
    assert foreground.status_code == 200
    assert "set-cookie" in foreground.headers


async def test_oidc_token_without_subject_is_rejected(session, client, monkeypatch) -> None:
    from app.api.v1.endpoints import auth as auth_endpoint
    from app.services.oidc import OidcService

    settings.oidc_enabled = True
    monkeypatch.setattr(
        OidcService, "exchange", lambda self, code, verifier, nonce: _claims_without_sub()
    )
    monkeypatch.setattr(OidcService, "map_role", lambda self, claims: "operator")
    try:
        client.cookies.set(auth_endpoint.OIDC_STATE_COOKIE, "state|verifier|nonce")
        response = await client.get(
            "/api/v1/auth/oidc/callback?code=abc&state=state", follow_redirects=False
        )
        assert response.status_code == 401
    finally:
        settings.oidc_enabled = False


async def _claims_without_sub() -> dict[str, str]:
    return {"preferred_username": "ohne-subject"}


async def test_error_language_follows_the_selected_ui_language(session, client) -> None:
    """Die Oberflächensprache gilt auch für Fehlermeldungen des Kontos."""
    await _account(session, "operator", Role.OPERATOR)
    await client.post(
        "/api/v1/auth/login",
        json={"username": "operator", "password": "ein-sicheres-passwort"},
    )
    client.cookies.set("frm_lang", "en")
    response = await client.get("/api/v1/users/gibtsnicht")
    assert response.status_code == 404
    assert response.json()["message"] == "The requested record was not found."


# --- Import ----------------------------------------------------------------


async def test_row_error_does_not_poison_the_session(session, admin_principal) -> None:
    """Ein von der Datenbank abgewiesener Wert darf die Folgezeilen nicht mitreissen."""
    too_long = "x" * 200
    csv_text = (
        "username,password,note\n"
        "anna,geheim123,ok\n"
        f"{too_long},geheim123,zu lang\n"
        "carla,geheim789,ok\n"
    )
    report = await ImportExportService(session).import_csv(
        csv_text, kind="user", dry_run=False, actor=admin_principal
    )
    assert report.errors == 1
    assert report.to_create == 2

    users = UserService(session)
    assert (await users.get("anna")).status == "active"
    assert (await users.get("carla")).status == "active"


async def test_preview_reports_schema_violations(session, admin_principal) -> None:
    """Was das Schema ablehnt, muss schon die Vorschau melden."""
    csv_text = "username,password\n" + "x" * 200 + ",geheim123\n"
    preview = await ImportExportService(session).import_csv(
        csv_text, kind="user", dry_run=True, actor=admin_principal
    )
    assert preview.errors == 1
    assert preview.to_create == 0


async def test_export_keeps_membership_priorities(session, admin_principal) -> None:
    """Export, bearbeiten, importieren darf die Reihenfolge nicht auf 1 setzen."""
    users = UserService(session)
    await _ensure_groups(session, admin_principal, "a", "b")
    await users.create(
        UserCreate(
            username="anna",
            password="geheim123",
            groups=[
                MembershipIn(groupname="a", priority=1),
                MembershipIn(groupname="b", priority=7),
            ],
            meta=SubjectMeta(note="x"),
        ),
        actor=admin_principal,
    )
    csv_text = await ImportExportService(session).export(SubjectFilter())
    assert "b:7" in csv_text

    await ImportExportService(session).import_csv(
        'username,groups\nanna,"a,b:7"\n',
        kind="user",
        dry_run=False,
        actor=admin_principal,
    )
    detail = await users.get("anna")
    assert {m.groupname: m.priority for m in detail.memberships} == {"a": 1, "b": 7}


async def test_list_items_expose_priorities(session, admin_principal) -> None:
    await _ensure_groups(session, admin_principal, "b")
    await UserService(session).create(
        UserCreate(
            username="anna",
            password="geheim123",
            groups=[MembershipIn(groupname="b", priority=3)],
        ),
        actor=admin_principal,
    )
    items, _ = await UserService(session).search(SubjectFilter())
    assert items[0].memberships[0].priority == 3


async def test_session_detail_endpoint_is_reachable(session, client) -> None:
    """Die Detailansicht der Oberfläche nutzt diesen Endpunkt (FR-5)."""
    from app.models.radius import RadAcct

    await _account(session, "auditor", Role.AUDITOR)
    await client.post(
        "/api/v1/auth/login",
        json={"username": "auditor", "password": "ein-sicheres-passwort"},
    )
    row = RadAcct(
        acctsessionid="s1",
        acctuniqueid="u1",
        username="anna",
        nasipaddress="10.0.0.1",
        acctstarttime=dt.datetime(2026, 9, 1, 8, 0),
        callingstationid="AA-BB-CC-DD-EE-FF",
        calledstationid="00-11-22-33-44-55:WLAN",
        nasportid="Gi1/0/7",
    )
    session.add(row)
    await session.commit()

    response = await client.get(f"/api/v1/sessions/{row.radacctid}")
    assert response.status_code == 200
    body = response.json()
    assert body["nasportid"] == "Gi1/0/7"
    assert body["ssid"] == "WLAN"


# --- Sechste Runde ---------------------------------------------------------


async def test_bulk_item_failure_does_not_poison_the_session(session, admin_principal) -> None:
    """Ein von der Datenbank abgewiesener Gruppenname darf den Rest nicht mitreissen."""
    from app.schemas.users import BulkAction

    users = UserService(session)
    for name in ("anna", "bruno"):
        await users.create(UserCreate(username=name, password="geheim123"), actor=admin_principal)

    # Das Schema weist einen solchen Namen inzwischen selbst ab (zehnte Runde).
    # Geprueft wird hier die Widerstandsfaehigkeit des Dienstes, deshalb wird die
    # Anforderung direkt gebaut, ohne die Eingangsvalidierung.
    payload = BulkAction.model_construct(
        action="assign_group",
        usernames=["anna", "bruno"],
        filter_all=False,
        groupname="g" * 200,
        priority=1,
        expires_at=None,
    )
    requested, succeeded, errors = await ImportExportService(session).bulk(
        payload,
        SubjectFilter(),
        actor=admin_principal,
    )
    assert requested == 2
    assert succeeded == 0
    assert len(errors) == 2


async def test_bulk_audit_payload_is_capped(session, admin_principal) -> None:
    """Die TEXT-Spalte fasst rund 64 KiB; die Namen werden begrenzt abgelegt."""
    from sqlalchemy import select

    from app.models.mgr import MgrAudit
    from app.schemas.users import BulkAction
    from app.services.importexport import AUDIT_NAME_LIMIT

    users = UserService(session)
    names = [f"user{index:04d}" for index in range(AUDIT_NAME_LIMIT + 5)]
    for name in names:
        await users.create(UserCreate(username=name, password="geheim123"), actor=admin_principal)

    await ImportExportService(session).bulk(
        BulkAction(action="disable", usernames=names), SubjectFilter(), actor=admin_principal
    )
    entry = await session.scalar(select(MgrAudit).where(MgrAudit.action == "bulk.disable"))
    assert '"usernames_truncated": true' in (entry.after_json or "")
    assert len(entry.after_json or "") < 60_000


async def test_reply_only_subject_can_get_credentials(session, admin_principal) -> None:
    """Was sichtbar und aufrufbar ist, muss auch ein Passwort erhalten können."""
    from sqlalchemy import select

    from app.models.radius import RadCheck, RadReply
    from app.schemas.users import PasswordSet

    session.add(RadReply(username="legacy", attribute="Filter-Id", op=":=", value="x"))
    await session.commit()

    users = UserService(session)
    await users.set_password("legacy", PasswordSet(password="geheim123"), actor=admin_principal)
    row = await session.scalar(
        select(RadCheck).where(
            RadCheck.username == "legacy", RadCheck.attribute == "Cleartext-Password"
        )
    )
    assert row.value == "geheim123"

    await users.set_disabled("legacy", True, actor=admin_principal)
    assert (await users.get("legacy")).status == "disabled"


async def test_status_filter_covers_expired_and_missing_credentials(
    session, admin_principal
) -> None:
    """Der Aktiv-Filter darf keine abgelaufenen Objekte enthalten."""
    from app.models.radius import RadReply

    users = UserService(session)
    await users.create(UserCreate(username="aktiv", password="geheim123"), actor=admin_principal)
    await users.create(
        UserCreate(
            username="abgelaufen",
            password="geheim123",
            expires_at=dt.datetime(2020, 1, 1, 12, 0),
        ),
        actor=admin_principal,
    )
    session.add(RadReply(username="ohne-passwort", attribute="Filter-Id", op=":=", value="x"))
    await session.commit()

    active, _ = await users.search(SubjectFilter(status="active"))
    expired, _ = await users.search(SubjectFilter(status="expired"))
    without, _ = await users.search(SubjectFilter(status="no_credentials"))

    assert [i.username for i in active] == ["aktiv"]
    assert [i.username for i in expired] == ["abgelaufen"]
    assert [i.username for i in without] == ["ohne-passwort"]


async def test_broken_cursor_is_ignored(session, client) -> None:
    """Ein manipulierter Cursor darf keinen Serverfehler erzeugen."""
    import base64

    await _account(session, "auditor", Role.AUDITOR)
    await client.post(
        "/api/v1/auth/login",
        json={"username": "auditor", "password": "ein-sicheres-passwort"},
    )
    broken = base64.urlsafe_b64encode(b'{"id":null}').decode().rstrip("=")
    for path in (f"/api/v1/sessions?cursor={broken}", f"/api/v1/authlog?cursor={broken}"):
        response = await client.get(path)
        assert response.status_code == 200


async def test_rate_limiter_evicts_expired_buckets() -> None:
    """Frei wählbare Schlüssel dürfen den Speicher nicht unbegrenzt füllen."""
    import time as time_module

    from app.core.ratelimit import RateLimiter

    limiter = RateLimiter(limit=5, window_seconds=0)
    for index in range(50):
        limiter.check(f"name{index}")
    time_module.sleep(0.01)
    limiter.check("noch-einer")
    assert limiter.tracked_keys() <= 2


async def test_jwks_is_reloaded_after_key_rotation(monkeypatch) -> None:
    """Nach einer Schlüsselrotation dürfen Anmeldungen nicht dauerhaft scheitern."""
    from app.services import oidc as oidc_module
    from app.services.oidc import OidcService

    oidc_module._jwks_cache.clear()
    loads: list[bool] = []

    async def fake_jwks(jwks_uri: str, *, force: bool = False) -> str:
        loads.append(force)
        return "neuer-schluesselsatz" if force else "alter-schluesselsatz"

    def fake_decode(self, id_token: str, key_set: str, expected_issuer: str):
        if key_set == "alter-schluesselsatz":
            raise ValueError("unbekannte kid")
        return {"iss": expected_issuer, "nonce": "n", "aud": "client", "sub": "s"}

    monkeypatch.setattr(OidcService, "_jwks", staticmethod(fake_jwks))
    monkeypatch.setattr(OidcService, "_decode", fake_decode)
    settings.oidc_client_id = "client"

    service = OidcService()
    claims = await service._verify_id_token(
        "token", "n", {"jwks_uri": "https://idp/jwks", "issuer": "https://idp"}
    )
    assert claims["sub"] == "s"
    assert loads == [False, True]
