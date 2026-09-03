"""Regressionstests zur achten Review-Runde."""

from __future__ import annotations

import datetime as dt
from collections.abc import AsyncIterator

import pyotp
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.core.config import settings
from app.core.crypto import SecretBox, hash_password, nt_hash
from app.core.errors import ConflictError, ValidationError
from app.main import create_app
from app.models.mgr import CredentialType, MgrAccount, Role
from app.models.radius import RadAcct, RadCheck
from app.schemas.nas import NasCreate
from app.schemas.users import DeviceCreate, DeviceUpdate, UserCreate, UserUpdate
from app.services.devices import DeviceService
from app.services.importexport import ImportExportService
from app.services.nas import NasService
from app.services.sessions import SessionService, extract_ssid
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


# --- Sitzungen -------------------------------------------------------------


async def test_password_change_invalidates_older_sessions(session, client) -> None:
    """Ein gestohlenes Cookie darf eine Passwortänderung nicht überleben."""
    account, _ = await _account(session, "operator", Role.OPERATOR)
    await client.post(
        "/api/v1/auth/login",
        json={"username": "operator", "password": "ein-sicheres-passwort"},
    )
    assert (await client.get("/api/v1/auth/me")).status_code == 200

    account.password_changed_at = dt.datetime.now() + dt.timedelta(seconds=5)
    await session.commit()

    response = await client.get("/api/v1/auth/me")
    assert response.status_code == 401
    assert response.json()["code"] == "error.reauthentication_required"


async def test_oidc_administrator_passes_the_mfa_gate(session, client, monkeypatch) -> None:
    """Bei OIDC verantwortet der Provider den zweiten Faktor."""
    from app.api.v1.endpoints import auth as auth_endpoint
    from app.services.oidc import OidcService

    settings.oidc_enabled = True
    monkeypatch.setattr(
        OidcService, "exchange", lambda self, code, verifier, nonce: _admin_claims()
    )
    monkeypatch.setattr(OidcService, "map_role", lambda self, claims: "administrator")
    try:
        client.cookies.set(auth_endpoint.OIDC_STATE_COOKIE, "state|verifier|nonce")
        redirect = await client.get(
            "/api/v1/auth/oidc/callback?code=abc&state=state", follow_redirects=False
        )
        assert redirect.status_code == 303
    finally:
        settings.oidc_enabled = False

    me = await client.get("/api/v1/auth/me")
    assert me.status_code == 200
    assert me.json()["role"] == "administrator"
    assert (await client.get("/api/v1/accounts")).status_code == 200


async def _admin_claims() -> dict[str, str]:
    return {"sub": "idp-admin", "preferred_username": "idp-admin"}


# --- Benutzer --------------------------------------------------------------


async def test_disable_preserves_a_configured_auth_type(session, admin_principal) -> None:
    """Eine bestehende Auth-Type-Vorgabe überlebt eine vorübergehende Sperre."""
    users = UserService(session)
    await users.create(UserCreate(username="anna", password="geheim123"), actor=admin_principal)
    await users.attrs.set_check("anna", "Auth-Type", ":=", "PAP")
    await session.commit()

    await users.set_disabled("anna", True, actor=admin_principal)
    row = await session.scalar(
        select(RadCheck).where(RadCheck.username == "anna", RadCheck.attribute == "Auth-Type")
    )
    assert row.value == "Reject"

    await users.set_disabled("anna", False, actor=admin_principal)
    row = await session.scalar(
        select(RadCheck).where(RadCheck.username == "anna", RadCheck.attribute == "Auth-Type")
    )
    assert row is not None
    assert row.value == "PAP"


async def test_disable_without_previous_auth_type_removes_the_row(session, admin_principal) -> None:
    users = UserService(session)
    await users.create(UserCreate(username="anna", password="geheim123"), actor=admin_principal)
    await users.set_disabled("anna", True, actor=admin_principal)
    await users.set_disabled("anna", False, actor=admin_principal)

    row = await session.scalar(
        select(RadCheck).where(RadCheck.username == "anna", RadCheck.attribute == "Auth-Type")
    )
    assert row is None


async def test_active_session_count_is_exact(session, admin_principal) -> None:
    """Der Zähler darf nicht an der Abrufgrenze hängen bleiben."""
    users = UserService(session)
    await users.create(UserCreate(username="anna", password="geheim123"), actor=admin_principal)
    for index in range(60):
        session.add(
            RadAcct(
                acctsessionid=f"s{index}",
                acctuniqueid=f"u{index}",
                username="anna",
                nasipaddress="10.0.0.1",
                acctstarttime=dt.datetime(2026, 9, 1, 8, 0),
                callingstationid="AA-BB-CC-DD-EE-FF",
            )
        )
    await session.commit()

    assert (await users.get("anna")).active_sessions == 60


async def test_credential_type_change_reconciles_attributes(session, admin_principal) -> None:
    """Der gemeldete Typ muss zu den gespeicherten Attributen passen."""
    users = UserService(session)
    await users.create(
        UserCreate(username="anna", password="geheim123", credential_type=CredentialType.BOTH),
        actor=admin_principal,
    )

    await users.update("anna", UserUpdate(credential_type=CredentialType.NT), actor=admin_principal)
    rows = (await session.scalars(select(RadCheck).where(RadCheck.username == "anna"))).all()
    attributes = {r.attribute: r.value for r in rows}
    assert set(attributes) == {"NT-Password"}
    assert attributes["NT-Password"] == nt_hash("geheim123")

    # Aus dem Hash lässt sich kein Klartext gewinnen: der Wechsel wird abgelehnt.
    with pytest.raises(ValidationError) as excinfo:
        await users.update(
            "anna", UserUpdate(credential_type=CredentialType.BOTH), actor=admin_principal
        )
    assert excinfo.value.code == "error.credential_type_needs_password"


async def test_credential_type_from_cleartext_can_add_nt(session, admin_principal) -> None:
    users = UserService(session)
    await users.create(
        UserCreate(username="anna", password="geheim123", credential_type=CredentialType.CLEARTEXT),
        actor=admin_principal,
    )
    await users.update(
        "anna", UserUpdate(credential_type=CredentialType.BOTH), actor=admin_principal
    )
    rows = (await session.scalars(select(RadCheck).where(RadCheck.username == "anna"))).all()
    assert {r.attribute for r in rows} == {"Cleartext-Password", "NT-Password"}


# --- Sessions und NAS ------------------------------------------------------


async def test_bare_bssid_yields_no_ssid() -> None:
    assert extract_ssid("00:11:22:33:44:55") is None
    assert extract_ssid("00-11-22-33-44-55:Firmen-WLAN") == "Firmen-WLAN"
    assert extract_ssid("00:11:22:33:44:55:Firmen-WLAN") == "Firmen-WLAN"


async def test_session_list_resolves_network_nas(session, admin_principal) -> None:
    await NasService(session).create(
        NasCreate(nasname="192.0.2.0/24", shortname="netz", secret="s"), actor=admin_principal
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

    from app.repositories.radius.acct import SessionFilter

    items, _, _ = await SessionService(session).search(SessionFilter())
    assert items[0].nas_shortname == "netz"


async def test_terminate_causes_use_a_bounded_window(session) -> None:
    """Alte Zeilen dürfen keinen vollen Tabellenscan erzwingen."""
    now = dt.datetime.now()
    session.add(
        RadAcct(
            acctsessionid="alt",
            acctuniqueid="alt",
            username="anna",
            nasipaddress="10.0.0.1",
            acctstarttime=now - dt.timedelta(days=400),
            acctterminatecause="Alt-Grund",
            callingstationid="AA-BB-CC-DD-EE-FF",
        )
    )
    session.add(
        RadAcct(
            acctsessionid="neu",
            acctuniqueid="neu",
            username="anna",
            nasipaddress="10.0.0.1",
            acctstarttime=now,
            acctterminatecause="User-Request",
            callingstationid="AA-BB-CC-DD-EE-FF",
        )
    )
    await session.commit()

    causes = await SessionService(session).terminate_causes()
    assert causes == ["User-Request"]


# --- Geräte und Import -----------------------------------------------------


async def test_rename_detects_alternate_format_duplicate(session, admin_principal) -> None:
    devices = DeviceService(session)
    await devices.create(DeviceCreate(mac="aa:bb:cc:dd:ee:ff"), actor=admin_principal)
    await devices.create(DeviceCreate(mac="11:22:33:44:55:66"), actor=admin_principal)
    await SettingsService(session).update({KEY_MAC_FORMAT: "plain_lower"})
    await session.commit()

    with pytest.raises(ConflictError):
        await devices.update(
            "11:22:33:44:55:66", DeviceUpdate(mac="AA-BB-CC-DD-EE-FF"), actor=admin_principal
        )


async def test_failed_row_is_not_counted_as_success(session, admin_principal) -> None:
    """Eine abgewiesene Zeile darf nicht zugleich als Erfolg gemeldet werden."""
    csv_text = "username,password,note\nanna,geheim123,ok\n" + "x" * 200 + ",geheim123,zu lang\n"
    report = await ImportExportService(session).import_csv(
        csv_text, kind="user", dry_run=False, actor=admin_principal
    )
    assert report.total == 2
    assert report.errors == 1
    assert report.to_create == 1
    assert len([r for r in report.rows if r.action == "create"]) == 1


# --- Neunte Runde ----------------------------------------------------------


async def test_metadata_length_is_validated(session, admin_principal) -> None:
    """Zu lange Werte sind ein Eingabefehler, kein Serverfehler."""
    from pydantic import ValidationError as PydanticValidationError

    with pytest.raises(PydanticValidationError):
        UserCreate(username="anna", password="geheim123", meta={"location": "x" * 200})


async def test_identifiers_with_slashes_are_rejected() -> None:
    """Ein Schrägstrich liesse sich über die REST-Pfade nicht adressieren."""
    from pydantic import ValidationError as PydanticValidationError

    from app.schemas.groups import GroupCreate

    with pytest.raises(PydanticValidationError):
        UserCreate(username="domain/user", password="geheim123")
    with pytest.raises(PydanticValidationError):
        GroupCreate(groupname="a/b", vlan="10")


async def test_patch_keeps_other_password_attributes(session, admin_principal) -> None:
    """Bestandsbenutzer mit Crypt-Password dürfen ihn nicht verlieren."""
    from app.schemas.users import AttributeIn

    users = UserService(session)
    await users.create(UserCreate(username="anna", password="geheim123"), actor=admin_principal)
    await users.attrs.add_check("anna", "Crypt-Password", ":=", "$1$abc")
    await session.commit()

    await users.update(
        "anna",
        UserUpdate(
            check_attributes=[AttributeIn(attribute="Simultaneous-Use", op=":=", value="1")]
        ),
        actor=admin_principal,
    )
    rows = (await session.scalars(select(RadCheck).where(RadCheck.username == "anna"))).all()
    assert "Crypt-Password" in {r.attribute for r in rows}


async def test_export_import_roundtrip_is_lossless(session, admin_principal) -> None:
    """Exportieren, bearbeiten, importieren darf Werte nicht verändern."""
    from app.repositories.directory import SubjectFilter

    users = UserService(session)
    await users.create(
        UserCreate(
            username="anna",
            password="geheim123",
            groups=[{"groupname": "-guest", "priority": 1}],
            meta={"note": "=SUMME(A1)"},
        ),
        actor=admin_principal,
    )
    csv_text = await ImportExportService(session).export(SubjectFilter())
    assert "'-guest" in csv_text

    await ImportExportService(session).import_csv(
        csv_text.replace("username,", "username,").replace("\n", "\n", 1),
        kind="user",
        dry_run=False,
        actor=admin_principal,
    )
    detail = await users.get("anna")
    assert detail.groups == ["-guest"]
    assert detail.note == "=SUMME(A1)"


async def test_sessions_can_be_filtered_by_nas_shortname(session, admin_principal) -> None:
    """In der Liste steht der Kurzname; danach muss sich auch filtern lassen."""
    from app.repositories.radius.acct import SessionFilter

    await NasService(session).create(
        NasCreate(nasname="10.0.0.7", shortname="sw07", secret="s"), actor=admin_principal
    )
    session.add(
        RadAcct(
            acctsessionid="s1",
            acctuniqueid="u1",
            username="anna",
            nasipaddress="10.0.0.7",
            acctstarttime=dt.datetime(2026, 9, 1, 8, 0),
            callingstationid="AA-BB-CC-DD-EE-FF",
        )
    )
    await session.commit()

    items, _, _ = await SessionService(session).search(SessionFilter(nas_ip_address="sw07"))
    assert [i.username for i in items] == ["anna"]

    by_ip, _, _ = await SessionService(session).search(SessionFilter(nas_ip_address="10.0.0.7"))
    assert len(by_ip) == 1


async def test_negative_offset_is_a_validation_error(session, client) -> None:
    await _account(session, "auditor", Role.AUDITOR)
    await client.post(
        "/api/v1/auth/login",
        json={"username": "auditor", "password": "ein-sicheres-passwort"},
    )
    response = await client.get("/api/v1/users?offset=-1")
    assert response.status_code == 422
    assert response.json()["code"] == "error.validation"
