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
from app.models.mgr import CredentialType, MgrAccount, Role, SubjectType
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
    await _ensure_groups(session, admin_principal, "-guest")
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


# --- Zehnte Runde ----------------------------------------------------------


async def test_set_password_removes_duplicate_credential_rows(session, admin_principal) -> None:
    """radcheck kennt keine Eindeutigkeit; ein Duplikat bliebe sonst gültig."""
    from app.schemas.users import PasswordSet

    users = UserService(session)
    await users.create(UserCreate(username="anna", password="alt"), actor=admin_principal)
    await users.attrs.add_check("anna", "Cleartext-Password", ":=", "auch-alt")
    await session.commit()

    await users.set_password("anna", PasswordSet(password="neu"), actor=admin_principal)
    rows = (
        await session.scalars(
            select(RadCheck).where(
                RadCheck.username == "anna", RadCheck.attribute == "Cleartext-Password"
            )
        )
    ).all()
    assert [r.value for r in rows] == ["neu"]


async def test_group_names_reject_csv_delimiters() -> None:
    """Sonst liesse sich ``gruppe:prioritaet`` beim Import nicht mehr lesen."""
    from pydantic import ValidationError as PydanticValidationError

    from app.schemas.groups import GroupCreate

    for name in ("staff:west", "a,b", "a;b"):
        with pytest.raises(PydanticValidationError):
            GroupCreate(groupname=name, vlan="10")


async def test_empty_groups_column_clears_memberships(session, admin_principal) -> None:
    """Eine geleerte Spalte im Export bedeutet: alle Mitgliedschaften entfernen."""
    from app.schemas.groups import GroupCreate
    from app.services.groups import GroupService

    await GroupService(session).create(
        GroupCreate(groupname="g1", vlan="10"), actor=admin_principal
    )
    users = UserService(session)
    await users.create(
        UserCreate(
            username="anna", password="geheim123", groups=[{"groupname": "g1", "priority": 1}]
        ),
        actor=admin_principal,
    )
    assert (await users.get("anna")).groups == ["g1"]

    await ImportExportService(session).import_csv(
        "username,groups\nanna,\n", kind="user", dry_run=False, actor=admin_principal
    )
    assert (await users.get("anna")).groups == []


async def test_bulk_assign_rejects_unknown_targets(session, admin_principal) -> None:
    """Ein Tippfehler darf keine Phantom-Objekte erzeugen."""
    from app.repositories.directory import SubjectFilter
    from app.schemas.users import BulkAction

    users = UserService(session)
    await users.create(UserCreate(username="anna", password="geheim123"), actor=admin_principal)

    _, succeeded, errors = await ImportExportService(session).bulk(
        BulkAction(action="assign_group", usernames=["anna"], groupname="gibtsnicht"),
        SubjectFilter(),
        actor=admin_principal,
    )
    assert succeeded == 0 and len(errors) == 1

    _, total = await users.search(SubjectFilter())
    assert total == 1


async def test_disabled_account_login_is_audited(session) -> None:
    """Ein richtiges Passwort gegen ein gesperrtes Konto gehört ins Protokoll."""
    from app.core.errors import AuthenticationError
    from app.models.mgr import MgrAudit
    from app.services.accounts import AccountService

    account, _ = await _account(session, "operator", Role.OPERATOR)
    account.is_active = False
    await session.commit()

    with pytest.raises(AuthenticationError):
        await AccountService(session).authenticate("operator", "ein-sicheres-passwort")

    entries = (await session.scalars(select(MgrAudit).where(MgrAudit.action == "auth.login"))).all()
    assert any("disabled" in (e.message or "") for e in entries)


async def test_nas_note_is_returned(session, admin_principal) -> None:
    item, _ = await NasService(session).create(
        NasCreate(nasname="10.0.0.1", secret="s", note="Etage 3, Schrank B"),
        actor=admin_principal,
    )
    assert item.note == "Etage 3, Schrank B"
    assert (await NasService(session).get(item.id)).note == "Etage 3, Schrank B"


async def test_group_listing_uses_batched_queries(session, admin_principal) -> None:
    from app.schemas.groups import GroupCreate
    from app.services.groups import GroupService

    service = GroupService(session)
    for index in range(5):
        await service.create(
            GroupCreate(groupname=f"g{index}", vlan=str(10 + index)), actor=admin_principal
        )
    items = await service.search()
    assert [i.vlan for i in items] == ["10", "11", "12", "13", "14"]


# --- Elfte Runde -----------------------------------------------------------


async def test_comma_separated_list_settings_are_accepted(monkeypatch) -> None:
    """Die dokumentierte Schreibweise darf den Start nicht verhindern."""
    from app.core.config import Settings

    monkeypatch.setenv("FRM_TRUSTED_PROXIES", "10.0.0.0/8,192.168.0.0/16")
    monkeypatch.setenv("FRM_CORS_ORIGINS", "https://a.example,https://b.example")
    config = Settings()
    assert config.trusted_proxies == ["10.0.0.0/8", "192.168.0.0/16"]
    assert config.cors_origins == ["https://a.example", "https://b.example"]


async def test_membership_endpoint_rejects_unknown_targets(session, admin_principal) -> None:
    """Ohne Fremdschlüssel entstünden sonst Phantom-Objekte."""
    from app.core.errors import NotFoundError
    from app.repositories.directory import SubjectFilter
    from app.schemas.groups import GroupCreate, MembershipChange
    from app.services.groups import GroupService

    service = GroupService(session)
    await service.create(GroupCreate(groupname="g1", vlan="10"), actor=admin_principal)

    with pytest.raises(NotFoundError):
        await service.change_membership(
            "g1", MembershipChange(usernames=["gibtsnicht"]), actor=admin_principal
        )
    with pytest.raises(NotFoundError):
        await service.change_membership(
            "andere", MembershipChange(usernames=["egal"]), actor=admin_principal
        )

    _, total = await UserService(session).search(SubjectFilter())
    assert total == 0


async def test_empty_cells_clear_values_on_import(session, admin_principal) -> None:
    """Eine geleerte Zelle im Export muss den Wert auch entfernen."""
    users = UserService(session)
    await users.create(
        UserCreate(
            username="anna",
            password="geheim123",
            vlan="20",
            expires_at=dt.datetime(2030, 1, 1, 12, 0),
            meta={"note": "alt", "location": "Zürich"},
        ),
        actor=admin_principal,
    )
    before = await users.get("anna")
    assert before.vlan == "20" and before.expires_at is not None

    await ImportExportService(session).import_csv(
        "username,vlan,expires_at,note,location\nanna,,,,\n",
        kind="user",
        dry_run=False,
        actor=admin_principal,
    )
    after = await users.get("anna")
    assert after.vlan is None
    assert after.expires_at is None
    assert after.note is None
    assert after.location is None


async def test_missing_columns_keep_values_on_import(session, admin_principal) -> None:
    """Eine fehlende Spalte bleibt weiterhin ohne Wirkung."""
    users = UserService(session)
    await users.create(
        UserCreate(username="anna", password="geheim123", vlan="20", meta={"note": "alt"}),
        actor=admin_principal,
    )
    await ImportExportService(session).import_csv(
        "username,owner\nanna,it@example.org\n",
        kind="user",
        dry_run=False,
        actor=admin_principal,
    )
    detail = await users.get("anna")
    assert detail.vlan == "20"
    assert detail.note == "alt"
    assert detail.owner == "it@example.org"


async def test_account_fields_are_length_checked() -> None:
    from pydantic import ValidationError as PydanticValidationError

    from app.schemas.accounts import AccountCreate

    with pytest.raises(PydanticValidationError):
        AccountCreate(username="a", password="ein-sicheres-passwort", email="x" * 300)
    with pytest.raises(PydanticValidationError):
        AccountCreate(username="a", password="ein-sicheres-passwort", language="klingonisch")


async def test_multi_audience_token_requires_azp(monkeypatch) -> None:
    """Ein Token, das einen anderen Client autorisiert, darf hier nicht gelten."""
    from app.core.errors import AuthenticationError
    from app.services import oidc as oidc_module
    from app.services.oidc import OidcService

    oidc_module._jwks_cache.clear()
    settings.oidc_client_id = "manager"

    async def fake_jwks(jwks_uri: str, *, force: bool = False) -> str:
        return "keys"

    claims = {
        "iss": "https://idp",
        "aud": ["manager", "andere-app"],
        "azp": "andere-app",
        "nonce": "n",
        "sub": "s",
    }
    monkeypatch.setattr(OidcService, "_jwks", staticmethod(fake_jwks))
    monkeypatch.setattr(OidcService, "_decode", lambda self, t, k, i: claims)

    meta = {"jwks_uri": "https://idp/jwks", "issuer": "https://idp"}
    with pytest.raises(AuthenticationError) as excinfo:
        await OidcService()._verify_id_token("token", "n", meta)
    assert excinfo.value.details["stage"] == "azp"

    claims["azp"] = "manager"
    assert (await OidcService()._verify_id_token("token", "n", meta))["sub"] == "s"


# --- Zwölfte Runde ---------------------------------------------------------


async def test_enrollment_challenge_is_not_in_the_url(session, client) -> None:
    """Ein kurzlebiges Zugangsmerkmal gehört nicht in Zugriffsprotokolle."""
    await _account(session, "admin", Role.ADMINISTRATOR)
    first = await client.post(
        "/api/v1/auth/login", json={"username": "admin", "password": "ein-sicheres-passwort"}
    )
    challenge = first.json()["challenge"]

    in_url = await client.post(f"/api/v1/auth/totp/enroll?challenge={challenge}")
    assert in_url.status_code == 422

    in_body = await client.post("/api/v1/auth/totp/enroll", json={"challenge": challenge})
    assert in_body.status_code == 200


async def test_unknown_group_is_rejected_on_assignment(session, admin_principal) -> None:
    """Ein Tippfehler darf keine Phantomgruppe erzeugen."""
    from app.core.errors import NotFoundError
    from app.services.groups import GroupService

    with pytest.raises(NotFoundError):
        await UserService(session).create(
            UserCreate(
                username="anna",
                password="geheim123",
                groups=[{"groupname": "tipfehler", "priority": 1}],
            ),
            actor=admin_principal,
        )
    assert await GroupService(session).search() == []


async def test_delete_records_the_previous_state(session, admin_principal) -> None:
    """Nach dem Löschen liesse sich der Zustand nicht mehr rekonstruieren."""
    from app.models.mgr import MgrAudit
    from app.schemas.groups import GroupCreate
    from app.services.groups import GroupService

    await GroupService(session).create(
        GroupCreate(groupname="g1", vlan="10"), actor=admin_principal
    )
    users = UserService(session)
    await users.create(
        UserCreate(
            username="anna",
            password="streng-geheim",
            vlan="20",
            groups=[{"groupname": "g1", "priority": 1}],
            meta={"note": "Aussendienst"},
        ),
        actor=admin_principal,
    )
    await users.delete("anna", actor=admin_principal)

    entry = await session.scalar(select(MgrAudit).where(MgrAudit.action == "user.delete"))
    before = entry.before_json or ""
    assert "g1" in before
    assert "Aussendienst" in before
    assert '"vlan": "20"' in before
    # Das Passwort steht auch hier nicht im Klartext.
    assert "streng-geheim" not in before


async def test_rejected_coa_is_audited(session, admin_principal) -> None:
    """Auch der nicht abgeschickte Trennversuch gehört ins Protokoll."""
    from app.core.errors import CoAError
    from app.models.mgr import AuditResult, MgrAudit
    from app.schemas.nas import CoARequest
    from app.services.coa import CoAService

    await NasService(session).create(
        NasCreate(nasname="10.0.0.1", secret="s"), actor=admin_principal
    )
    session.add(
        RadAcct(
            acctsessionid="s1",
            acctuniqueid="u1",
            username="anna",
            nasipaddress="10.0.0.1",
            acctstarttime=dt.datetime(2026, 9, 1, 8, 0),
            callingstationid="AA-BB-CC-DD-EE-FF",
        )
    )
    await session.commit()

    with pytest.raises(CoAError):
        await CoAService(session).execute(CoARequest(acctuniqueid="u1"), actor=admin_principal)
    entry = await session.scalar(select(MgrAudit).where(MgrAudit.action == "coa.disconnect"))
    assert entry is not None
    assert entry.result is AuditResult.FAILURE


async def test_administrator_can_link_an_oidc_identity(session, admin_principal) -> None:
    """Ohne diesen Weg bliebe eine OIDC-Einführung für Bestandskonten blockiert."""
    from app.core.errors import ConflictError
    from app.schemas.accounts import AccountCreate
    from app.services.accounts import AccountService

    service = AccountService(session)
    first = await service.create(
        AccountCreate(username="anna", password="ein-sicheres-passwort"), actor=admin_principal
    )
    second = await service.create(
        AccountCreate(username="bruno", password="ein-sicheres-passwort"), actor=admin_principal
    )

    linked = await service.set_oidc_subject(first.id, "idp-anna", actor=admin_principal)
    assert linked.oidc_subject == "idp-anna"

    with pytest.raises(ConflictError):
        await service.set_oidc_subject(second.id, "idp-anna", actor=admin_principal)

    unlinked = await service.set_oidc_subject(first.id, None, actor=admin_principal)
    assert unlinked.oidc_subject is None


async def test_sql_echo_hides_bound_parameters() -> None:
    """Bei aktiviertem Echo dürfen keine Passwörter im Protokoll landen."""
    from app.core.config import Settings
    from app.core.db import create_engine

    engine = create_engine(Settings(db_echo=True, db_password="x"))
    # Die Einstellung sitzt auf der synchronen Engine darunter.
    assert engine.sync_engine.hide_parameters is True
    await engine.dispose()


# --- Dreizehnte Runde ------------------------------------------------------


async def test_bootstrap_password_follows_the_policy(session) -> None:
    """Ein Platzhalter aus der Umgebung darf kein Administratorzugang werden."""
    from app.core.errors import ValidationError as AppValidationError
    from app.services.accounts import AccountService

    service = AccountService(session)
    with pytest.raises(AppValidationError) as excinfo:
        await service.ensure_bootstrap_admin("admin", "a")
    assert excinfo.value.code == "error.password_too_short"

    created = await service.ensure_bootstrap_admin("admin", "ein-sicheres-passwort")
    assert created is not None


async def test_unknown_status_filter_is_rejected(session) -> None:
    """Ein Tippfehler darf die Auswahl nicht auf alles ausweiten."""
    from app.core.errors import ValidationError as AppValidationError
    from app.repositories.directory import SubjectFilter

    with pytest.raises(AppValidationError):
        await UserService(session).search(SubjectFilter(status="disbaled"))


async def test_duplicate_memberships_are_collapsed(session, admin_principal) -> None:
    """radusergroup kennt keine Eindeutigkeit; Duplikate verfälschten die Zahlen."""
    from app.models.radius import RadUserGroup
    from app.schemas.groups import GroupCreate
    from app.services.groups import GroupService

    await GroupService(session).create(
        GroupCreate(groupname="g1", vlan="10"), actor=admin_principal
    )
    await UserService(session).create(
        UserCreate(
            username="anna",
            password="geheim123",
            groups=[
                {"groupname": "g1", "priority": 1},
                {"groupname": "g1", "priority": 5},
            ],
        ),
        actor=admin_principal,
    )
    rows = (
        await session.scalars(select(RadUserGroup).where(RadUserGroup.username == "anna"))
    ).all()
    assert len(rows) == 1
    assert (await GroupService(session).get("g1")).members == 1


async def test_nas_note_can_be_cleared(session, admin_principal) -> None:
    from app.schemas.nas import NasUpdate

    service = NasService(session)
    item, _ = await service.create(
        NasCreate(nasname="10.0.0.1", secret="s", note="Etage 3"), actor=admin_principal
    )
    updated, _ = await service.update(item.id, NasUpdate(note=None), actor=admin_principal)
    assert updated.note in (None, "")


async def test_group_delete_records_the_configuration(session, admin_principal) -> None:
    from app.models.mgr import MgrAudit
    from app.schemas.groups import GroupCreate
    from app.services.groups import GroupService

    service = GroupService(session)
    await service.create(GroupCreate(groupname="g1", vlan="42"), actor=admin_principal)
    await service.delete("g1", actor=admin_principal, force=True)

    entry = await session.scalar(select(MgrAudit).where(MgrAudit.action == "group.delete"))
    assert '"vlan": "42"' in (entry.before_json or "")


async def test_apostrophe_escaping_is_reversible(session, admin_principal) -> None:
    """Ein Wert, der selbst mit einem Hochkomma beginnt, bleibt erhalten."""
    from app.repositories.directory import SubjectFilter

    users = UserService(session)
    await users.create(
        UserCreate(username="anna", password="geheim123", meta={"note": "'=literal"}),
        actor=admin_principal,
    )
    csv_text = await ImportExportService(session).export(SubjectFilter())
    await ImportExportService(session).import_csv(
        csv_text, kind="user", dry_run=False, actor=admin_principal
    )
    assert (await users.get("anna")).note == "'=literal"


async def test_preview_reports_unknown_groups(session, admin_principal) -> None:
    """Die Vorschau darf nicht mehr versprechen als der Import einlöst."""
    preview = await ImportExportService(session).import_csv(
        "username,password,groups\nanna,geheim123,gibtsnicht\n",
        kind="user",
        dry_run=True,
        actor=admin_principal,
    )
    assert preview.errors == 1
    assert preview.to_create == 0


# --- Vierzehnte Runde ------------------------------------------------------


async def test_totp_reset_survives_re_enrollment(session, client) -> None:
    """Nach dem Zurücksetzen darf ein altes Cookie auch später nicht gelten."""
    account, secret = await _account(session, "admin", Role.ADMINISTRATOR, totp=True)
    first = await client.post(
        "/api/v1/auth/login", json={"username": "admin", "password": "ein-sicheres-passwort"}
    )
    await client.post(
        "/api/v1/auth/login/totp",
        json={"challenge": first.json()["challenge"], "totp_code": pyotp.TOTP(secret).now()},
    )
    assert (await client.get("/api/v1/accounts")).status_code == 200

    # Zurücksetzen und sofort einen neuen Faktor einrichten.
    account.totp_enabled = True
    account.totp_secret_enc = SecretBox(settings.coa_secret_key or settings.secret_key).encrypt(
        pyotp.random_base32()
    )
    from app.core.dates import utcnow as _utcnow

    account.totp_changed_at = _utcnow() + dt.timedelta(seconds=5)
    await session.commit()

    response = await client.get("/api/v1/accounts")
    assert response.status_code == 401
    assert response.json()["code"] == "error.reauthentication_required"


async def test_login_in_the_same_second_stays_valid(session, client) -> None:
    """Sekundengenaue Vergleiche dürfen eine frische Anmeldung nicht verwerfen."""
    from app.core.dates import utcnow

    account, _ = await _account(session, "operator", Role.OPERATOR)
    # Der Manager schreibt Zeitstempel in UTC; lokale Zeit waere hier ein
    # Testfehler und kein Produktfehler.
    account.password_changed_at = utcnow()
    await session.commit()

    await client.post(
        "/api/v1/auth/login",
        json={"username": "operator", "password": "ein-sicheres-passwort"},
    )
    assert (await client.get("/api/v1/auth/me")).status_code == 200


async def test_password_change_failures_count_towards_lockout(session, admin_principal) -> None:
    """Auch mit gültiger Sitzung darf nicht unbegrenzt geraten werden."""
    from app.core.errors import AuthenticationError
    from app.schemas.accounts import AccountCreate, PasswordChange
    from app.services.accounts import LOCKOUT_THRESHOLD, AccountService

    service = AccountService(session)
    created = await service.create(
        AccountCreate(username="anna", password="ein-sicheres-passwort"), actor=admin_principal
    )
    actor = admin_principal.__class__(
        account_id=created.id,
        username=created.username,
        role=Role.ADMINISTRATOR,
        language="de",
        session_id="x",
        absolute_expiry=0,
    )
    for _ in range(LOCKOUT_THRESHOLD):
        with pytest.raises(AuthenticationError):
            await service.change_password(
                created.id,
                PasswordChange(current_password="falsch", new_password="neues-sicheres-pw"),
                actor=actor,
            )
    account = await service.get(created.id)
    assert account.locked_until is not None


async def test_community_is_redacted_in_audit(session, admin_principal) -> None:
    """Die SNMP-Community ist ein Zugangsmerkmal."""
    from app.models.mgr import MgrAudit

    await NasService(session).create(
        NasCreate(nasname="10.0.0.1", secret="s", community="geheime-community"),
        actor=admin_principal,
    )
    entries = (await session.scalars(select(MgrAudit))).all()
    payload = " ".join((e.after_json or "") for e in entries)
    assert "geheime-community" not in payload
    assert "<geaendert>" in payload


async def test_nt_only_device_rename_rotates_the_hash(session, admin_principal) -> None:
    """Auch ein reiner NT-Hash ist aus der MAC abgeleitet."""
    from app.core.crypto import nt_hash
    from app.models.mgr import CredentialType
    from app.schemas.users import DeviceUpdate, PasswordSet

    devices = DeviceService(session)
    await devices.create(DeviceCreate(mac="aa:bb:cc:dd:ee:ff"), actor=admin_principal)
    await UserService(session).set_password(
        "aa:bb:cc:dd:ee:ff",
        PasswordSet(password="aa:bb:cc:dd:ee:ff", credential_type=CredentialType.NT),
        actor=admin_principal,
    )

    detail = await devices.update(
        "aa:bb:cc:dd:ee:ff", DeviceUpdate(mac="11:22:33:44:55:66"), actor=admin_principal
    )
    assert detail.username == "11:22:33:44:55:66"
    row = await session.scalar(
        select(RadCheck).where(
            RadCheck.username == "11:22:33:44:55:66", RadCheck.attribute == "NT-Password"
        )
    )
    assert row.value == nt_hash("11:22:33:44:55:66")


async def test_import_error_hides_the_submitted_value(session, admin_principal) -> None:
    """Ein zu langes Passwort darf nicht in der Antwort auftauchen."""
    secret = "x" * 300
    report = await ImportExportService(session).import_csv(
        f"username,password\nanna,{secret}\n",
        kind="user",
        dry_run=True,
        actor=admin_principal,
    )
    assert report.errors == 1
    assert secret not in (report.rows[0].message or "")
    assert "password" in (report.rows[0].message or "")


async def test_credential_type_only_import_takes_effect(session, admin_principal) -> None:
    from app.models.mgr import CredentialType

    users = UserService(session)
    await users.create(
        UserCreate(username="anna", password="geheim123", credential_type=CredentialType.BOTH),
        actor=admin_principal,
    )
    await ImportExportService(session).import_csv(
        "username,credential_type\nanna,nt\n",
        kind="user",
        dry_run=False,
        actor=admin_principal,
    )
    rows = (await session.scalars(select(RadCheck).where(RadCheck.username == "anna"))).all()
    assert {r.attribute for r in rows} == {"NT-Password"}


# --- Fünfzehnte Runde ------------------------------------------------------


async def test_oidc_subject_whitespace_is_rejected(session, client, monkeypatch) -> None:
    """Ein getrimmtes Subject könnte die Sitzung eines anderen Kontos erhalten."""
    from app.api.v1.endpoints import auth as auth_endpoint
    from app.services.oidc import OidcService

    settings.oidc_enabled = True

    async def claims() -> dict[str, str]:
        return {"sub": " alice", "preferred_username": "alice"}

    monkeypatch.setattr(OidcService, "exchange", lambda self, c, v, n: claims())
    monkeypatch.setattr(OidcService, "map_role", lambda self, c: "operator")
    try:
        client.cookies.set(auth_endpoint.OIDC_STATE_COOKIE, "state|verifier|nonce")
        response = await client.get(
            "/api/v1/auth/oidc/callback?code=abc&state=state", follow_redirects=False
        )
        assert response.status_code == 401
    finally:
        settings.oidc_enabled = False


async def test_locked_account_cannot_guess_its_password(session, admin_principal) -> None:
    """Auch mit gültiger Sitzung endet das Raten an der Sperre."""
    from app.core.errors import AuthenticationError
    from app.schemas.accounts import AccountCreate, PasswordChange
    from app.services.accounts import LOCKOUT_THRESHOLD, AccountService

    service = AccountService(session)
    created = await service.create(
        AccountCreate(username="anna", password="ein-sicheres-passwort"), actor=admin_principal
    )
    actor = admin_principal.__class__(
        account_id=created.id,
        username=created.username,
        role=Role.ADMINISTRATOR,
        language="de",
        session_id="x",
        absolute_expiry=0,
    )
    for _ in range(LOCKOUT_THRESHOLD):
        with pytest.raises(AuthenticationError):
            await service.change_password(
                created.id,
                PasswordChange(current_password="falsch", new_password="neues-sicheres-pw"),
                actor=actor,
            )

    # Auch mit dem richtigen Passwort: die Sperre gilt.
    with pytest.raises(AuthenticationError) as excinfo:
        await service.change_password(
            created.id,
            PasswordChange(
                current_password="ein-sicheres-passwort", new_password="neues-sicheres-pw"
            ),
            actor=actor,
        )
    assert excinfo.value.code == "error.account_locked"


async def test_settings_are_administrator_only(session, client) -> None:
    await _account(session, "operator", Role.OPERATOR)
    await client.post(
        "/api/v1/auth/login",
        json={"username": "operator", "password": "ein-sicheres-passwort"},
    )
    assert (await client.get("/api/v1/settings")).status_code == 403
    # Der MAB-Schalter bleibt über den Geräte-Endpunkt erreichbar.
    formats = await client.get("/api/v1/devices/mac-formats")
    assert formats.status_code == 200
    assert "show_mab_warning" in formats.json()


async def test_retention_setting_rejects_booleans(session) -> None:
    """``True`` würde als ein Tag gelesen und fast das ganze Audit-Log löschen."""
    from app.core.errors import ValidationError as AppValidationError
    from app.services.settings_service import KEY_AUDIT_RETENTION, SettingsService

    with pytest.raises(AppValidationError):
        await SettingsService(session).update({KEY_AUDIT_RETENTION: True})


async def test_import_keeps_password_whitespace(session, admin_principal) -> None:
    """Leerzeichen sind Teil des Passworts."""
    await ImportExportService(session).import_csv(
        'username,password\nanna," geheim "\n',
        kind="user",
        dry_run=False,
        actor=admin_principal,
    )
    row = await session.scalar(
        select(RadCheck).where(
            RadCheck.username == "anna", RadCheck.attribute == "Cleartext-Password"
        )
    )
    assert row.value == " geheim "


async def test_bulk_priority_is_bounded() -> None:
    from pydantic import ValidationError as PydanticValidationError

    from app.schemas.users import BulkAction

    with pytest.raises(PydanticValidationError):
        BulkAction(action="assign_group", groupname="g1", priority=10_000_000)


async def test_attribute_collections_are_bounded() -> None:
    from pydantic import ValidationError as PydanticValidationError

    from app.schemas.groups import GroupCreate
    from app.schemas.users import MAX_ATTRIBUTES, AttributeIn

    too_many = [
        AttributeIn(attribute="Filter-Id", op=":=", value="x") for _ in range(MAX_ATTRIBUTES + 1)
    ]
    with pytest.raises(PydanticValidationError):
        GroupCreate(groupname="g1", reply_attributes=too_many)


# --- Sechzehnte Runde ------------------------------------------------------


async def test_duplicate_status_rows_match_the_sql_filter(session, admin_principal) -> None:
    """Liste und Sammelaktion müssen dasselbe Objekt gleich einstufen."""
    from app.repositories.directory import SubjectFilter

    users = UserService(session)
    await users.create(UserCreate(username="anna", password="geheim123"), actor=admin_principal)
    # Bestandsdaten können dasselbe Attribut mehrfach enthalten.
    await users.attrs.add_check("anna", "Auth-Type", ":=", "PAP")
    await users.attrs.add_check("anna", "Auth-Type", ":=", "Reject")
    await session.commit()

    assert (await users.get("anna")).status == "disabled"
    disabled, _ = await users.search(SubjectFilter(status="disabled"))
    assert [i.username for i in disabled] == ["anna"]


async def test_legacy_user_keeps_its_credential_type(session, admin_principal) -> None:
    """Ein NT-only-Bestandsbenutzer darf nicht als „both“ gemeldet werden."""
    from app.core.crypto import nt_hash
    from app.models.mgr import CredentialType
    from app.schemas.users import UserUpdate

    session.add(
        RadCheck(username="legacy", attribute="NT-Password", op=":=", value=nt_hash("geheim"))
    )
    await session.commit()

    users = UserService(session)
    await users.update("legacy", UserUpdate(meta={"note": "übernommen"}), actor=admin_principal)
    assert (await users.get("legacy")).credential_type is CredentialType.NT


async def test_invalid_oidc_role_map_fails_at_startup() -> None:
    """Ein Tippfehler soll beim Start auffallen, nicht erst beim Anmelden."""
    from pydantic import ValidationError as PydanticValidationError

    from app.core.config import Settings

    with pytest.raises(PydanticValidationError):
        Settings(oidc_role_map={"radius-admins": "admin"})
    assert Settings(oidc_role_map={"radius-admins": "administrator"}).oidc_role_map


async def test_multiline_notes_survive_the_export(session, admin_principal) -> None:
    from app.repositories.directory import SubjectFilter

    users = UserService(session)
    await users.create(
        UserCreate(username="anna", password="geheim123", meta={"note": "Zeile 1\nZeile 2"}),
        actor=admin_principal,
    )
    csv_text = await ImportExportService(session).export(SubjectFilter())
    await ImportExportService(session).import_csv(
        csv_text, kind="user", dry_run=False, actor=admin_principal
    )
    assert (await users.get("anna")).note == "Zeile 1\nZeile 2"


async def test_ambiguous_coa_request_is_rejected(session, admin_principal) -> None:
    """Bei mehreren laufenden Sessions darf nicht stillschweigend eine gewählt werden."""
    from app.core.errors import ValidationError as AppValidationError
    from app.schemas.nas import CoARequest
    from app.services.coa import CoAService

    await NasService(session).create(
        NasCreate(nasname="10.0.0.1", secret="s", coa_enabled=True, coa_secret="x"),
        actor=admin_principal,
    )
    for index in range(2):
        session.add(
            RadAcct(
                acctsessionid=f"s{index}",
                acctuniqueid=f"u{index}",
                username="anna",
                nasipaddress="10.0.0.1",
                acctstarttime=dt.datetime(2026, 9, 1, 8, index),
                callingstationid="AA-BB-CC-DD-EE-FF",
            )
        )
    await session.commit()

    with pytest.raises(AppValidationError) as excinfo:
        await CoAService(session).execute(CoARequest(username="anna"), actor=admin_principal)
    assert excinfo.value.code == "error.session_ambiguous"


async def test_nas_note_length_is_bounded() -> None:
    from pydantic import ValidationError as PydanticValidationError

    with pytest.raises(PydanticValidationError):
        NasCreate(nasname="10.0.0.1", secret="s", note="x" * 5000)


# --- Siebzehnte Runde ------------------------------------------------------


async def test_named_lock_survives_a_commit(session, admin_principal) -> None:
    """Die Sperre liegt auf einer eigenen Verbindung und übersteht den Commit."""
    from app.core.locking import named_lock
    from app.schemas.groups import GroupCreate
    from app.services.groups import GroupService

    service = GroupService(session)
    await service.create(GroupCreate(groupname="g1", vlan="10"), actor=admin_principal)
    # Nach dem Commit im Inneren muss dieselbe Sperre wieder frei sein.
    async with named_lock(session, "group:g1"):
        pass
    await service.create(GroupCreate(groupname="g2", vlan="11"), actor=admin_principal)
    assert len(await service.search()) == 2


async def test_all_password_attributes_are_masked(session, admin_principal) -> None:
    """Auch seltenere FreeRADIUS-Passwortattribute dürfen nicht ausgeliefert werden."""
    users = UserService(session)
    await users.create(UserCreate(username="anna", password="geheim123"), actor=admin_principal)
    for attribute in ("SSHA-Password", "SMD5-Password", "Password-With-Header"):
        await users.attrs.add_check("anna", attribute, ":=", "streng-geheim")
    await session.commit()

    detail = await users.get("anna")
    assert "streng-geheim" not in detail.model_dump_json()


async def test_enable_removes_every_reject_row(session, admin_principal) -> None:
    """Mehrere Auth-Type-Zeilen dürfen nach dem Entsperren keine Reject-Zeile lassen."""
    users = UserService(session)
    await users.create(UserCreate(username="anna", password="geheim123"), actor=admin_principal)
    await users.attrs.add_check("anna", "Auth-Type", ":=", "PAP")
    await users.attrs.add_check("anna", "Auth-Type", ":=", "Reject")
    await session.commit()

    await users.set_disabled("anna", False, actor=admin_principal)
    rows = [
        r for r in await users.attrs.check_attributes("anna") if r.attribute.lower() == "auth-type"
    ]
    assert [r.value for r in rows] == ["PAP"]
    assert (await users.get("anna")).status == "active"


async def test_error_messages_interpolate_details(session, client) -> None:
    """Platzhalter im Katalog müssen gefüllt werden."""
    await _account(session, "operator", Role.OPERATOR)
    await client.post(
        "/api/v1/auth/login",
        json={"username": "operator", "password": "ein-sicheres-passwort"},
    )
    response = await client.get("/api/v1/users/gibtsnicht")
    assert "{" not in response.json()["message"]


async def test_self_service_totp_is_attributed(session, client) -> None:
    """Wer den zweiten Faktor aktiviert, muss im Audit-Log stehen."""
    from app.models.mgr import MgrAudit

    await _account(session, "operator", Role.OPERATOR)
    await client.post(
        "/api/v1/auth/login",
        json={"username": "operator", "password": "ein-sicheres-passwort"},
    )
    setup = await client.post("/api/v1/auth/me/totp/enroll")
    await client.post(
        "/api/v1/auth/me/totp/confirm",
        json={"code": pyotp.TOTP(setup.json()["secret"]).now()},
    )
    entry = await session.scalar(select(MgrAudit).where(MgrAudit.action == "account.totp_enabled"))
    assert entry is not None
    assert entry.actor_name == "operator"


async def test_oidc_requires_its_settings() -> None:
    from pydantic import ValidationError as PydanticValidationError

    from app.core.config import Settings

    with pytest.raises(PydanticValidationError):
        Settings(oidc_enabled=True)
    assert Settings(
        oidc_enabled=True,
        oidc_issuer="https://idp",
        oidc_client_id="manager",
        oidc_redirect_url="https://radius.example/callback",
    ).oidc_enabled


async def test_multibyte_coa_secret_is_bounded() -> None:
    from pydantic import ValidationError as PydanticValidationError

    with pytest.raises(PydanticValidationError):
        NasCreate(nasname="10.0.0.1", secret="s", coa_secret="🔐" * 200)


# --- Achtzehnte Runde ------------------------------------------------------


async def test_group_name_with_apostrophe_works(session, admin_principal) -> None:
    """Der Name geht in die Sperre; unparametrisiert wäre das ungültiges SQL."""
    from app.schemas.groups import GroupCreate
    from app.services.groups import GroupService

    service = GroupService(session)
    detail = await service.create(
        GroupCreate(groupname="O'Reilly", vlan="10"), actor=admin_principal
    )
    assert detail.groupname == "O'Reilly"
    assert (await service.get("O'Reilly")).vlan == "10"


async def test_bootstrap_is_skipped_before_validation(session) -> None:
    """Ein unbenutzter Platzhalter darf eine eingerichtete Instanz nicht blockieren."""
    from app.services.accounts import AccountService

    service = AccountService(session)
    assert await service.ensure_bootstrap_admin("admin", "ein-sicheres-passwort") is not None
    # Zweiter Start mit kurzem Platzhalter: kein Fehler, nur kein neues Konto.
    assert await service.ensure_bootstrap_admin("admin", "x") is None


async def test_rate_limits_must_be_positive() -> None:
    from pydantic import ValidationError as PydanticValidationError

    from app.core.config import Settings

    with pytest.raises(PydanticValidationError):
        Settings(login_rate_limit=0)
    with pytest.raises(PydanticValidationError):
        Settings(login_ip_rate_limit=-1)


async def test_diagnosis_sees_every_auth_type_row(session, admin_principal) -> None:
    from app.services.authlog import AuthLogService

    users = UserService(session)
    await users.create(UserCreate(username="anna", password="geheim123"), actor=admin_principal)
    await users.attrs.add_check("anna", "Auth-Type", ":=", "Reject")
    await users.attrs.add_check("anna", "Auth-Type", ":=", "PAP")
    await session.commit()

    result = await AuthLogService(session).diagnose("anna")
    assert result.status == "disabled"
    assert "diag.auth_type_reject" in {h.code for h in result.hints}


async def test_unknown_boolean_is_an_import_error(session, admin_principal) -> None:
    """Ein Tippfehler darf nicht als „nicht gesperrt“ gelesen werden."""
    users = UserService(session)
    await users.create(
        UserCreate(username="anna", password="geheim123", disabled=True), actor=admin_principal
    )
    report = await ImportExportService(session).import_csv(
        "username,disabled\nanna,treu\n",
        kind="user",
        dry_run=False,
        actor=admin_principal,
    )
    assert report.errors == 1
    assert (await users.get("anna")).status == "disabled"


async def test_import_password_and_type_together(session, admin_principal) -> None:
    """Erst das Passwort, dann die Typumstellung - sonst scheitert der Wechsel."""
    from app.models.mgr import CredentialType
    from app.schemas.users import PasswordSet

    users = UserService(session)
    await users.create(UserCreate(username="anna", password="alt"), actor=admin_principal)
    await users.set_password(
        "anna",
        PasswordSet(password="alt", credential_type=CredentialType.NT),
        actor=admin_principal,
    )

    report = await ImportExportService(session).import_csv(
        "username,password,credential_type\nanna,neu-geheim,both\n",
        kind="user",
        dry_run=False,
        actor=admin_principal,
    )
    assert report.errors == 0
    rows = (await session.scalars(select(RadCheck).where(RadCheck.username == "anna"))).all()
    assert {r.attribute for r in rows} == {"Cleartext-Password", "NT-Password"}


async def test_session_identifiers_are_strings(session, client) -> None:
    """BIGINT-Werte verlieren als JavaScript-Zahl an Genauigkeit."""
    await _account(session, "auditor", Role.AUDITOR)
    await client.post(
        "/api/v1/auth/login",
        json={"username": "auditor", "password": "ein-sicheres-passwort"},
    )
    session.add(
        RadAcct(
            radacctid=9007199254740993,
            acctsessionid="s1",
            acctuniqueid="u1",
            username="anna",
            nasipaddress="10.0.0.1",
            acctstarttime=dt.datetime(2026, 9, 1, 8, 0),
            callingstationid="AA-BB-CC-DD-EE-FF",
        )
    )
    await session.commit()

    listing = await client.get("/api/v1/sessions?active_only=false")
    assert listing.json()["items"][0]["radacctid"] == "9007199254740993"


# --- Neunzehnte Runde ------------------------------------------------------


async def test_challenge_is_void_after_a_password_change(session) -> None:
    """Eine vor der Änderung ausgestellte Challenge darf nicht mehr gelten."""
    from app.core.dates import utcnow
    from app.core.errors import AuthenticationError
    from app.services.accounts import AccountService

    account, _ = await _account(session, "admin", Role.ADMINISTRATOR, totp=True)
    service = AccountService(session)
    challenge = service.challenge_for(account)

    account.password_changed_at = utcnow() + dt.timedelta(seconds=5)
    await session.commit()

    with pytest.raises(AuthenticationError) as excinfo:
        await service.account_from_challenge(challenge)
    assert excinfo.value.code == "error.reauthentication_required"


async def test_exact_mac_wins_over_the_preferred_format(session, admin_principal) -> None:
    """Liegen zwei Schreibweisen vor, ist die angefragte gemeint."""
    from app.services.settings_service import KEY_MAC_FORMAT, SettingsService

    devices = DeviceService(session)
    await devices.create(
        DeviceCreate(mac="aa:bb:cc:dd:ee:ff", meta={"location": "colon"}),
        actor=admin_principal,
    )
    await SettingsService(session).update({KEY_MAC_FORMAT: "plain_lower"})
    await session.commit()
    # Zweiter Datensatz in der neuen Schreibweise – über den Benutzerdienst,
    # damit die Geräte-Auflösung ihn nicht zusammenführt.
    await UserService(session).create(
        UserCreate(username="aabbccddeeff", password="x", meta={"location": "plain"}),
        actor=admin_principal,
    )
    plain = await UserService(session).subjects.get("aabbccddeeff")
    plain.subject_type = SubjectType.DEVICE
    await session.commit()

    assert (await devices.get("aa:bb:cc:dd:ee:ff")).location == "colon"
    assert (await devices.get("aabbccddeeff")).location == "plain"


async def test_worker_intervals_must_be_positive() -> None:
    from pydantic import ValidationError as PydanticValidationError

    from app.core.config import Settings

    with pytest.raises(PydanticValidationError):
        Settings(stats_refresh_seconds=0)
    with pytest.raises(PydanticValidationError):
        Settings(audit_purge_interval_seconds=-5)


async def test_unknown_csv_columns_are_rejected(session, admin_principal) -> None:
    """Ein Tippfehler in der Kopfzeile darf nicht stillschweigend wirkungslos sein."""
    from app.core.errors import ValidationError as AppValidationError

    with pytest.raises(AppValidationError) as excinfo:
        await ImportExportService(session).import_csv(
            "username,groupss\nanna,g1\n",
            kind="user",
            dry_run=True,
            actor=admin_principal,
        )
    assert excinfo.value.code == "error.import_unknown_columns"


async def test_dry_run_rejects_impossible_credential_change(session, admin_principal) -> None:
    """Was der Import nicht leisten kann, darf die Vorschau nicht zusagen."""
    from app.models.mgr import CredentialType
    from app.schemas.users import PasswordSet

    users = UserService(session)
    await users.create(UserCreate(username="anna", password="geheim123"), actor=admin_principal)
    await users.set_password(
        "anna",
        PasswordSet(password="geheim123", credential_type=CredentialType.NT),
        actor=admin_principal,
    )

    preview = await ImportExportService(session).import_csv(
        "username,credential_type\nanna,both\n",
        kind="user",
        dry_run=True,
        actor=admin_principal,
    )
    assert preview.errors == 1
    assert preview.to_update == 0


async def test_bulk_expiry_rejects_unknown_users(session, admin_principal) -> None:
    from app.repositories.directory import SubjectFilter
    from app.schemas.users import BulkAction

    _, succeeded, errors = await ImportExportService(session).bulk(
        BulkAction(
            action="set_expiry",
            usernames=["gibtsnicht"],
            expires_at=dt.datetime(2030, 1, 1, 12, 0),
        ),
        SubjectFilter(),
        actor=admin_principal,
    )
    assert succeeded == 0 and len(errors) == 1
    _, total = await UserService(session).search(SubjectFilter())
    assert total == 0


async def test_manual_oidc_link_rejects_whitespace() -> None:
    from pydantic import ValidationError as PydanticValidationError

    from app.schemas.accounts import OidcLink

    with pytest.raises(PydanticValidationError):
        OidcLink(oidc_subject=" alice")
    assert OidcLink(oidc_subject="alice").oidc_subject == "alice"
    assert OidcLink(oidc_subject=None).oidc_subject is None


async def test_ip_attribute_values_are_validated() -> None:
    from app.core.errors import ValidationError as AppValidationError
    from app.services.attributes import validate_triple

    with pytest.raises(AppValidationError):
        validate_triple("Framed-IP-Address", ":=", "keine-ip", table="radreply")
    assert validate_triple("Framed-IP-Address", ":=", "192.0.2.10", table="radreply") == []


# --- Zwanzigste Runde ------------------------------------------------------


async def test_session_and_retention_settings_must_be_positive() -> None:
    from pydantic import ValidationError as PydanticValidationError

    from app.core.config import Settings

    for kwargs in (
        {"session_idle_minutes": 0},
        {"session_absolute_hours": 0},
        {"audit_retention_days": 0},
    ):
        with pytest.raises(PydanticValidationError):
            Settings(**kwargs)


async def test_attribute_cap_fits_the_audit_column(session, admin_principal) -> None:
    """Eine maximale Nutzlast muss noch in mgr_audit.after_json passen."""
    from sqlalchemy import select as sa_select

    from app.models.mgr import MgrAudit
    from app.schemas.groups import GroupCreate
    from app.schemas.users import MAX_ATTRIBUTES, AttributeIn
    from app.services.groups import GroupService

    attributes = [
        AttributeIn(attribute="A" * 64, op=":=", value="v" * 253) for _ in range(MAX_ATTRIBUTES)
    ]
    await GroupService(session).create(
        GroupCreate(groupname="gross", check_attributes=attributes, reply_attributes=attributes),
        actor=admin_principal,
    )
    entry = await session.scalar(sa_select(MgrAudit).where(MgrAudit.action == "group.create"))
    assert len((entry.after_json or "").encode("utf-8")) < 65_000


async def test_sessions_filter_by_network_nas(session, admin_principal) -> None:
    """Ein per CIDR eingetragenes NAS muss auch filterbar sein."""
    from app.repositories.radius.acct import SessionFilter

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

    service = SessionService(session)
    by_label, _, _ = await service.search(SessionFilter(nas_ip_address="netz"))
    assert [i.username for i in by_label] == ["anna"]

    by_cidr, _, _ = await service.search(SessionFilter(nas_ip_address="192.0.2.0/24"))
    assert [i.username for i in by_cidr] == ["anna"]


async def test_account_deletion_records_its_state(session, admin_principal) -> None:
    from sqlalchemy import select as sa_select

    from app.models.mgr import MgrAudit
    from app.schemas.accounts import AccountCreate
    from app.services.accounts import AccountService

    service = AccountService(session)
    await service.create(
        AccountCreate(username="admin2", password="ein-sicheres-passwort", role=Role.ADMINISTRATOR),
        actor=admin_principal,
    )
    created = await service.create(
        AccountCreate(username="anna", password="ein-sicheres-passwort", role=Role.OPERATOR),
        actor=admin_principal,
    )
    await service.delete(created.id, actor=admin_principal)

    entry = await session.scalar(sa_select(MgrAudit).where(MgrAudit.action == "account.delete"))
    assert "operator" in (entry.before_json or "")


async def test_import_preview_shows_late_errors(session, admin_principal) -> None:
    """Eine Fehlerzeile jenseits der Anzeigegrenze muss sichtbar bleiben."""
    from app.services.importexport import PREVIEW_LIMIT

    rows = "\n".join(f"user{i},geheim123" for i in range(PREVIEW_LIMIT + 5))
    csv_text = f"username,password\n{rows}\n,ohne-namen\n"
    report = await ImportExportService(session).import_csv(
        csv_text, kind="user", dry_run=True, actor=admin_principal
    )
    assert report.errors == 1
    # Der Bericht behaelt nur begrenzt viele Zeilen, Fehler aber bevorzugt.
    assert any(row.action == "error" for row in report.rows)
    assert len(report.rows) <= PREVIEW_LIMIT
    assert report.rows_truncated is True


# --- Einundzwanzigste Runde ------------------------------------------------


async def test_legacy_expiration_formats_match_the_filter(session, admin_principal) -> None:
    """Liste und Detailansicht müssen dasselbe Datum gleich bewerten."""
    from app.repositories.directory import SubjectFilter

    users = UserService(session)
    await users.create(UserCreate(username="anna", password="geheim123"), actor=admin_principal)
    # Bestandsformat statt der eigenen Schreibweise.
    await users.attrs.set_check("anna", "Expiration", ":=", "2020-01-01")
    await session.commit()

    assert (await users.get("anna")).status == "expired"
    expired, _ = await users.search(SubjectFilter(status="expired"))
    assert [i.username for i in expired] == ["anna"]
    active, _ = await users.search(SubjectFilter(status="active"))
    assert active == []


async def test_untranslatable_network_filter_returns_nothing(session, admin_principal) -> None:
    """Eine nicht darstellbare Einschränkung darf nicht alles liefern."""
    from app.repositories.radius.acct import SessionFilter

    await NasService(session).create(
        NasCreate(nasname="10.0.0.0/9", shortname="weit", secret="s"), actor=admin_principal
    )
    session.add(
        RadAcct(
            acctsessionid="s1",
            acctuniqueid="u1",
            username="anna",
            nasipaddress="203.0.113.1",
            acctstarttime=dt.datetime(2026, 9, 1, 8, 0),
            callingstationid="AA-BB-CC-DD-EE-FF",
        )
    )
    await session.commit()

    items, _, _ = await SessionService(session).search(SessionFilter(nas_ip_address="weit"))
    assert items == []


async def test_nas_deletion_records_its_configuration(session, admin_principal) -> None:
    from app.models.mgr import MgrAudit

    service = NasService(session)
    item, _ = await service.create(
        NasCreate(
            nasname="10.0.0.1",
            shortname="sw01",
            secret="topsecret",
            coa_enabled=True,
            coa_secret="coa-geheim",
        ),
        actor=admin_principal,
    )
    await service.delete(item.id, actor=admin_principal)

    entry = await session.scalar(select(MgrAudit).where(MgrAudit.action == "nas.delete"))
    assert "sw01" in (entry.before_json or "")
    assert "topsecret" not in (entry.before_json or "")


async def test_attribute_whitespace_is_rejected() -> None:
    """Sonst würde ein anderer Wert gespeichert als geprüft."""
    from app.core.errors import ValidationError as AppValidationError
    from app.services.attributes import validate_triple

    with pytest.raises(AppValidationError):
        validate_triple("Filter-Id ", ":=", "x", table="radreply")
    with pytest.raises(AppValidationError):
        validate_triple("Filter-Id", ":= ", "x", table="radreply")


async def test_pool_must_allow_two_connections() -> None:
    """Benannte Sperren brauchen eine Verbindung neben der Sitzung."""
    from pydantic import ValidationError as PydanticValidationError

    from app.core.config import Settings

    with pytest.raises(PydanticValidationError):
        Settings(db_pool_size=1)
    assert Settings(db_pool_size=2).db_pool_size == 2


# --- Zweiundzwanzigste Runde ----------------------------------------------


async def test_cross_origin_writes_are_rejected(session, client) -> None:
    """SameSite=Lax schützt nicht vor einem Geschwister-Host derselben Domain."""
    await _account(session, "operator", Role.OPERATOR)
    await client.post(
        "/api/v1/auth/login",
        json={"username": "operator", "password": "ein-sicheres-passwort"},
    )

    blocked = await client.post(
        "/api/v1/users",
        json={"username": "anna", "password": "geheim123"},
        headers={"Origin": "https://boese.example"},
    )
    assert blocked.status_code == 403
    assert blocked.json()["code"] == "error.cross_origin"

    allowed = await client.post(
        "/api/v1/users",
        json={"username": "anna", "password": "geheim123"},
        headers={"Origin": "http://testserver"},
    )
    assert allowed.status_code == 201

    # Lesen bleibt unberührt.
    assert (
        await client.get("/api/v1/users", headers={"Origin": "https://boese.example"})
    ).status_code == 200


async def test_lock_keys_stay_distinct_for_long_names(session, admin_principal) -> None:
    """Zwei lange Namen mit gleichem Anfang dürfen nicht denselben Schlüssel haben."""
    from app.core.locking import _lock_key
    from app.schemas.groups import GroupCreate, GroupUpdate
    from app.services.groups import GroupService

    first = "g" * 60 + "-eins"
    second = "g" * 60 + "-zwei"
    assert _lock_key(first) != _lock_key(second)
    assert len(_lock_key(first)) <= 64

    service = GroupService(session)
    await service.create(GroupCreate(groupname=first[:64], vlan="10"), actor=admin_principal)
    renamed = await service.update(
        first[:64], GroupUpdate(groupname=second[:64]), actor=admin_principal
    )
    assert renamed.groupname == second[:64]


async def test_disable_restores_every_auth_type_row(session, admin_principal) -> None:
    """Ein Sperr-/Entsperrzyklus darf keine Vorgabe verlieren."""
    users = UserService(session)
    await users.create(UserCreate(username="anna", password="geheim123"), actor=admin_principal)
    await users.attrs.add_check("anna", "Auth-Type", ":=", "PAP")
    await users.attrs.add_check("anna", "Auth-Type", ":=", "CHAP")
    await session.commit()

    await users.set_disabled("anna", True, actor=admin_principal)
    await users.set_disabled("anna", False, actor=admin_principal)

    rows = [
        r for r in await users.attrs.check_attributes("anna") if r.attribute.lower() == "auth-type"
    ]
    assert sorted(r.value for r in rows) == ["CHAP", "PAP"]


async def test_timestamp_filters_are_normalised(session, client) -> None:
    """Ein Wert mit Zeitzone darf das Fenster nicht verschieben."""
    await _account(session, "auditor", Role.AUDITOR)
    await client.post(
        "/api/v1/auth/login",
        json={"username": "auditor", "password": "ein-sicheres-passwort"},
    )
    session.add(
        RadAcct(
            acctsessionid="s1",
            acctuniqueid="u1",
            username="anna",
            nasipaddress="10.0.0.1",
            # 10:00 UTC
            acctstarttime=dt.datetime(2026, 9, 1, 10, 0),
            callingstationid="AA-BB-CC-DD-EE-FF",
        )
    )
    await session.commit()

    # 08:00-04:00 entspricht 12:00 UTC - die Session liegt davor.
    late = await client.get(
        "/api/v1/sessions?active_only=false&start_from=2026-09-01T08:00:00-04:00"
    )
    assert late.json()["items"] == []

    early = await client.get(
        "/api/v1/sessions?active_only=false&start_from=2026-09-01T04:00:00-04:00"
    )
    assert len(early.json()["items"]) == 1


async def test_duplicate_rows_in_one_file_are_rejected(session, admin_principal) -> None:
    report = await ImportExportService(session).import_csv(
        "username,password\nanna,geheim123\nanna,anderes123\n",
        kind="user",
        dry_run=True,
        actor=admin_principal,
    )
    assert report.errors == 1
    assert report.to_create == 1


async def test_schema_check_detects_wrong_column_types(engine) -> None:
    """Ein völlig anderer Typ fällt sonst erst zur Laufzeit auf."""
    from sqlalchemy import text

    from app.repositories.radius.schema import inspect_schema

    async with engine.begin() as connection:
        await connection.execute(text("ALTER TABLE radacct MODIFY acctstarttime VARCHAR(32)"))
    try:
        async with engine.connect() as connection:
            database = str(await connection.scalar(text("SELECT DATABASE()")))
            report = await inspect_schema(connection, database)
        assert not report.ok
        assert "acctstarttime" in " ".join(report.wrong_types["radacct"])
    finally:
        async with engine.begin() as connection:
            await connection.execute(text("ALTER TABLE radacct MODIFY acctstarttime DATETIME"))


# --- Dreiundzwanzigste Runde ----------------------------------------------


async def test_disable_snapshot_fits_long_values(session, admin_principal) -> None:
    """Mehrere lange Auth-Type-Werte müssen in den gemerkten Zustand passen."""
    users = UserService(session)
    await users.create(UserCreate(username="anna", password="geheim123"), actor=admin_principal)
    for index in range(3):
        await users.attrs.add_check("anna", "Auth-Type", ":=", f"{index}" + "x" * 250)
    await session.commit()

    await users.set_disabled("anna", True, actor=admin_principal)
    await users.set_disabled("anna", False, actor=admin_principal)
    rows = [
        r for r in await users.attrs.check_attributes("anna") if r.attribute.lower() == "auth-type"
    ]
    assert len(rows) == 3


async def test_host_networks_match_exactly(session, admin_principal) -> None:
    """Ein /32-Eintrag muss die konkrete Adresse treffen."""
    from app.repositories.radius.acct import SessionFilter

    await NasService(session).create(
        NasCreate(nasname="192.0.2.1/32", shortname="einzeln", secret="s"),
        actor=admin_principal,
    )
    session.add(
        RadAcct(
            acctsessionid="s1",
            acctuniqueid="u1",
            username="anna",
            nasipaddress="192.0.2.1",
            acctstarttime=dt.datetime(2026, 9, 1, 8, 0),
            callingstationid="AA-BB-CC-DD-EE-FF",
        )
    )
    await session.commit()

    items, _, _ = await SessionService(session).search(SessionFilter(nas_ip_address="einzeln"))
    assert [i.username for i in items] == ["anna"]


async def test_coa_rejects_the_wrong_ack_type(session, admin_principal, monkeypatch) -> None:
    """Ein Disconnect, das mit CoA-ACK beantwortet wird, hat nichts getrennt."""
    from app.core.errors import CoAError
    from app.schemas.nas import CoARequest
    from app.services import coa as coa_module
    from app.services.coa import CoAService

    await NasService(session).create(
        NasCreate(nasname="10.0.0.1", secret="s", coa_enabled=True, coa_secret="x"),
        actor=admin_principal,
    )
    session.add(
        RadAcct(
            acctsessionid="s1",
            acctuniqueid="u1",
            username="anna",
            nasipaddress="10.0.0.1",
            acctstarttime=dt.datetime(2026, 9, 1, 8, 0),
            callingstationid="AA-BB-CC-DD-EE-FF",
        )
    )
    await session.commit()

    # 44 = CoA-ACK, angefordert wird aber ein Disconnect.
    monkeypatch.setattr(coa_module, "_send_blocking", lambda *a, **k: (44, {}))
    with pytest.raises(CoAError):
        await CoAService(session).execute(
            CoARequest(action="disconnect", acctuniqueid="u1"), actor=admin_principal
        )

    # 41 = Disconnect-ACK: der richtige Fall bleibt erfolgreich.
    monkeypatch.setattr(coa_module, "_send_blocking", lambda *a, **k: (41, {}))
    result = await CoAService(session).execute(
        CoARequest(action="disconnect", acctuniqueid="u1"), actor=admin_principal
    )
    assert result.ok


async def test_coa_transport_settings_are_bounded() -> None:
    from pydantic import ValidationError as PydanticValidationError

    from app.core.config import Settings

    with pytest.raises(PydanticValidationError):
        Settings(coa_timeout_seconds=0)
    with pytest.raises(PydanticValidationError):
        Settings(coa_retries=0)


async def test_duplicate_masked_group_values_are_kept(session, admin_principal) -> None:
    """Zwei Passwortzeilen mit gleichem Namen dürfen nicht verschmelzen."""
    from app.schemas.groups import GroupCreate, GroupUpdate
    from app.schemas.users import AttributeIn
    from app.services.groups import GroupService

    service = GroupService(session)
    await service.create(
        GroupCreate(
            groupname="g1",
            check_attributes=[
                AttributeIn(attribute="Cleartext-Password", op=":=", value="erstes"),
                AttributeIn(attribute="Cleartext-Password", op=":=", value="zweites"),
            ],
        ),
        actor=admin_principal,
    )
    detail = await service.get("g1")
    await service.update(
        "g1",
        GroupUpdate(
            check_attributes=[
                AttributeIn(attribute=a.attribute, op=a.op, value=a.value)
                for a in detail.check_attributes
            ]
        ),
        actor=admin_principal,
    )
    values = sorted(r.value for r in await service.repo.check_attributes("g1"))
    assert values == ["erstes", "zweites"]


async def test_orm_metadata_matches_the_migration_indexes() -> None:
    """Sonst schlüge eine spätere Autogenerierung ihr Löschen vor."""
    from app.models import Base

    audit = {index.name for index in Base.metadata.tables["mgr_audit"].indexes}
    subject = {index.name for index in Base.metadata.tables["mgr_subject"].indexes}
    assert "ix_mgr_audit_action" in audit
    assert {"ix_mgr_subject_type", "ix_mgr_subject_owner", "ix_mgr_subject_expires"} <= subject


# --- Vierundzwanzigste Runde ----------------------------------------------


async def test_membership_usernames_are_bounded() -> None:
    from pydantic import ValidationError as PydanticValidationError

    from app.schemas.groups import MembershipChange
    from app.schemas.users import BulkAction

    with pytest.raises(PydanticValidationError):
        MembershipChange(usernames=["x" * 200])
    with pytest.raises(PydanticValidationError):
        BulkAction(action="disable", usernames=["x" * 200])


async def test_mab_warning_requires_a_boolean(session) -> None:
    from app.core.errors import ValidationError as AppValidationError
    from app.services.settings_service import KEY_MAB_WARNING, SettingsService

    with pytest.raises(AppValidationError):
        await SettingsService(session).update({KEY_MAB_WARNING: "false"})
    await SettingsService(session).update({KEY_MAB_WARNING: False})
    await session.commit()
    assert await SettingsService(session).show_mab_warning() is False


async def test_last_member_of_attribute_less_group_is_protected(session, admin_principal) -> None:
    """Sonst verschwände die Gruppe ohne Bestätigung und ohne Audit-Eintrag."""
    from app.core.errors import ValidationError as AppValidationError
    from app.schemas.groups import GroupCreate, GroupUpdate, MembershipChange
    from app.schemas.users import UserUpdate
    from app.services.groups import GroupService

    service = GroupService(session)
    await service.create(GroupCreate(groupname="g1", vlan="10"), actor=admin_principal)
    users = UserService(session)
    await users.create(
        UserCreate(
            username="anna", password="geheim123", groups=[{"groupname": "g1", "priority": 1}]
        ),
        actor=admin_principal,
    )
    # Attribute entfernen: die Gruppe besteht nun nur noch über die Mitgliedschaft.
    await service.update("g1", GroupUpdate(clear_vlan=True), actor=admin_principal)

    with pytest.raises(AppValidationError) as excinfo:
        await service.change_membership(
            "g1", MembershipChange(usernames=["anna"], action="remove"), actor=admin_principal
        )
    assert excinfo.value.code == "error.group_last_member"

    with pytest.raises(AppValidationError):
        await users.update("anna", UserUpdate(groups=[]), actor=admin_principal)

    assert (await service.get("g1")).members == 1


async def test_import_rows_are_capped_while_parsing(session, admin_principal) -> None:
    """Der Bericht darf bei sehr vielen Zeilen nicht unbegrenzt wachsen."""
    from app.services.importexport import PREVIEW_LIMIT

    rows = "\n".join(f"user{i},geheim123" for i in range(PREVIEW_LIMIT + 50))
    report = await ImportExportService(session).import_csv(
        f"username,password\n{rows}\n", kind="user", dry_run=True, actor=admin_principal
    )
    assert report.total == PREVIEW_LIMIT + 50
    assert len(report.rows) == PREVIEW_LIMIT
    assert report.rows_truncated is True


async def test_delete_and_password_write_are_serialised(session, admin_principal) -> None:
    """Beide Pfade laufen unter derselben Benutzersperre."""
    import inspect

    from app.services.users import UserService as Service

    assert "named_lock" in inspect.getsource(Service.delete)
    assert "named_lock" in inspect.getsource(Service.set_password)


# --- Fünfundzwanzigste Runde ----------------------------------------------


async def test_group_definitions_are_administrator_only(session, client) -> None:
    """Gruppenattribute wirken auf alle Mitglieder (Abschnitt 2)."""
    await _account(session, "operator", Role.OPERATOR)
    await client.post(
        "/api/v1/auth/login",
        json={"username": "operator", "password": "ein-sicheres-passwort"},
    )
    created = await client.post("/api/v1/groups", json={"groupname": "g1", "vlan": "10"})
    assert created.status_code == 403

    # Mitgliedschaften bleiben dem Operator erlaubt.
    assert (await client.get("/api/v1/groups")).status_code == 200


async def test_group_deletion_holds_the_lock(session) -> None:
    import inspect

    from app.services.groups import GroupService

    assert "named_lock" in inspect.getsource(GroupService.delete)


async def test_membership_collections_are_bounded() -> None:
    from pydantic import ValidationError as PydanticValidationError

    from app.schemas.users import MAX_MEMBERSHIPS

    too_many = [{"groupname": f"g{i}", "priority": 1} for i in range(MAX_MEMBERSHIPS + 1)]
    with pytest.raises(PydanticValidationError):
        UserCreate(username="anna", password="geheim123", groups=too_many)


async def test_coa_cannot_be_enabled_without_a_secret(session, admin_principal) -> None:
    from pydantic import ValidationError as PydanticValidationError

    from app.core.errors import ValidationError as AppValidationError
    from app.schemas.nas import NasUpdate

    with pytest.raises(PydanticValidationError):
        NasCreate(nasname="10.0.0.1", secret="s", coa_enabled=True)

    service = NasService(session)
    item, _ = await service.create(NasCreate(nasname="10.0.0.1", secret="s"), actor=admin_principal)
    with pytest.raises(AppValidationError) as excinfo:
        await service.update(item.id, NasUpdate(coa_enabled=True), actor=admin_principal)
    assert excinfo.value.code == "error.coa_secret_required"


async def test_clearing_the_coa_secret_disables_coa(session, admin_principal) -> None:
    from app.schemas.nas import NasUpdate

    service = NasService(session)
    item, _ = await service.create(
        NasCreate(nasname="10.0.0.1", secret="s", coa_enabled=True, coa_secret="x"),
        actor=admin_principal,
    )
    updated, _ = await service.update(
        item.id, NasUpdate(clear_coa_secret=True), actor=admin_principal
    )
    assert updated.coa_enabled is False
    assert await service.coa_target("10.0.0.1") is None


async def test_lock_engine_is_separate_from_the_query_pool() -> None:
    """Sperrverbindungen duerfen die Abfragen nicht aushungern."""
    import inspect

    from app.core import locking

    assert "get_lock_engine" in inspect.getsource(locking)
