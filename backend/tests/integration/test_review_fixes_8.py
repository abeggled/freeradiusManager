"""Regressionstests zur neunten Review-Runde."""

from __future__ import annotations

import datetime as dt

import pytest
from pydantic import ValidationError as PydanticValidationError
from sqlalchemy import select

from app.core.errors import ValidationError
from app.core.security import Principal
from app.models.radius import RadAcct, RadCheck
from app.repositories.radius.acct import AccountingRepository, SessionFilter
from app.schemas.nas import NasCreate, NasUpdate
from app.schemas.users import DeviceCreate, MembershipIn, UserCreate
from app.services.authlog import AuthLogService
from app.services.settings_service import (
    KEY_ACCT_RETENTION_HINT,
    KEY_AUDIT_RETENTION,
    MAX_RETENTION_DAYS,
    SettingsService,
)
from app.services.users import UserService

pytestmark = pytest.mark.asyncio


async def test_device_membership_list_is_bounded() -> None:
    """Ohne Obergrenze scheiterte die Validierung selbst - mit einem 500."""
    too_many = [MembershipIn(groupname=f"g{i}") for i in range(51)]
    with pytest.raises(PydanticValidationError):
        DeviceCreate(mac="aa:bb:cc:dd:ee:ff", groups=too_many)


@pytest.mark.parametrize("ports", [-1, 2_147_483_648])
async def test_nas_ports_stay_within_the_column_range(ports: int) -> None:
    """Zu grosse Werte scheiterten erst beim Schreiben, mit einem 500."""
    with pytest.raises(PydanticValidationError):
        NasCreate(nasname="10.0.0.1", secret="s", ports=ports)
    with pytest.raises(PydanticValidationError):
        NasUpdate(ports=ports)


async def test_nas_ports_accept_the_upper_bound() -> None:
    assert NasCreate(nasname="10.0.0.1", secret="s", ports=2_147_483_647).ports == 2_147_483_647


@pytest.mark.parametrize("key", [KEY_AUDIT_RETENTION, KEY_ACCT_RETENTION_HINT])
async def test_retention_days_have_an_upper_bound(session, key: str) -> None:
    """``timedelta`` laeuft darueber ueber; der Aufraeumjob scheiterte dann dauerhaft."""
    service = SettingsService(session)
    with pytest.raises(ValidationError):
        await service.update({key: MAX_RETENTION_DAYS + 1})

    # Der Grenzwert selbst bleibt zulaessig und ist rechenbar.
    await service.update({key: MAX_RETENTION_DAYS})
    assert dt.timedelta(days=MAX_RETENTION_DAYS)


async def test_disable_holds_the_lifecycle_lock(session, admin_principal) -> None:
    """Sperren laeuft unter derselben Sperre wie Loeschen und Passwortwechsel."""
    import inspect

    source = inspect.getsource(UserService.set_disabled)
    assert 'named_lock(self.session, f"user:{username}")' in source

    service = UserService(session)
    await service.create(UserCreate(username="anna", password="geheim123"), actor=admin_principal)
    await service.set_disabled("anna", True, actor=admin_principal)
    rows = (
        await session.scalars(
            select(RadCheck).where(RadCheck.username == "anna", RadCheck.attribute == "Auth-Type")
        )
    ).all()
    assert [row.value for row in rows] == ["Reject"]


async def test_called_station_filter_is_an_exact_match(session) -> None:
    """Die beidseitige Wildcard schloss jede Indexnutzung aus (NFR-2)."""
    session.add_all(
        [
            RadAcct(
                acctsessionid="s1",
                acctuniqueid="u1",
                username="anna",
                nasipaddress="10.0.0.1",
                calledstationid="AA-BB-CC-DD-EE-FF:wlan",
            ),
            RadAcct(
                acctsessionid="s2",
                acctuniqueid="u2",
                username="anna",
                nasipaddress="10.0.0.1",
                calledstationid="11-22-33-44-55-66:wlan",
            ),
        ]
    )
    await session.commit()

    repo = AccountingRepository(session)
    page = await repo.search(SessionFilter(called_station_id="AA-BB-CC-DD-EE-FF:wlan"))
    assert [row.acctuniqueid for row in page.items] == ["u1"]

    partial = await repo.search(SessionFilter(called_station_id="wlan"))
    assert partial.items == []


async def test_diagnosis_reports_the_nas_shortname(session, admin_principal) -> None:
    """Ohne den Kurznamen zeigte allein die Diagnose die rohe Adresse."""
    from app.services.nas import NasService

    await NasService(session).create(
        NasCreate(nasname="10.0.0.1", shortname="ap-eg", secret="s"), actor=admin_principal
    )
    await UserService(session).create(
        UserCreate(username="anna", password="geheim123"), actor=admin_principal
    )
    session.add(
        RadAcct(
            acctsessionid="s1",
            acctuniqueid="u1",
            username="anna",
            nasipaddress="10.0.0.1",
            calledstationid="AA-BB-CC-DD-EE-FF:wlan",
        )
    )
    await session.commit()

    result = await AuthLogService(session).diagnose("anna")
    assert result.last_session is not None
    assert result.last_session.nas_shortname == "ap-eg"


# --- Zehnte Runde ---------------------------------------------------------


async def test_named_lock_uses_the_dedicated_engine() -> None:
    """``session.bind`` ist im Betrieb die Abfrage-Engine - die Trennung entfiele."""
    import inspect

    from app.core import locking

    source = inspect.getsource(locking.named_lock)
    # Kommentarzeilen erwaehnen ``session.bind`` als das, was gerade nicht
    # verwendet wird; geprueft wird der Code.
    code = "\n".join(line for line in source.splitlines() if not line.lstrip().startswith("#"))
    assert "get_lock_engine()" in code
    assert "session.bind" not in code


async def test_named_lock_takes_several_names_on_one_connection(session) -> None:
    """Geschachtelte Aufrufe braeuchten je eine Verbindung; der Sperrpool ist klein."""
    from app.core.locking import named_lock

    async with named_lock(session, "group:b", "group:a", "user:anna"):
        pass

    with pytest.raises(ValueError):
        async with named_lock(session):
            pass


async def test_creating_a_user_locks_its_target_groups(session, admin_principal) -> None:
    """Sonst konnte eine geloeschte Gruppe als Mitgliedschaftsgruppe zurueckkehren."""
    import inspect

    source = inspect.getsource(UserService.create)
    assert "_lock_names(payload.username, payload.groups)" in source
    assert "named_lock" in inspect.getsource(UserService.update)

    from app.schemas.groups import GroupCreate
    from app.services.groups import GroupService

    await GroupService(session).create(
        GroupCreate(groupname="wlan", vlan="10"), actor=admin_principal
    )
    service = UserService(session)
    detail = await service.create(
        UserCreate(
            username="anna",
            password="geheim123",
            groups=[MembershipIn(groupname="wlan", priority=7)],
        ),
        actor=admin_principal,
    )
    assert [(m.groupname, m.priority) for m in detail.memberships] == [("wlan", 7)]


async def test_membership_removal_runs_under_the_group_lock() -> None:
    """Zwei gleichzeitige Entfernungen liessen die attributlose Gruppe verschwinden."""
    import inspect

    from app.services.groups import GroupService

    source = inspect.getsource(GroupService.change_membership)
    assert source.count("named_lock") == 1
    assert 'if payload.action == "add"' not in source


@pytest.mark.parametrize("value", ["2001:db8::1", "::1"])
async def test_ipv6_is_rejected_for_ipv4_radius_attributes(value: str) -> None:
    """``ipaddr`` ist im Woerterbuch der Vier-Byte-Typ; FreeRADIUS koennte IPv6 nicht kodieren."""
    from app.services.attributes import validate_triple

    with pytest.raises(ValidationError):
        validate_triple("Framed-IP-Address", ":=", value, table="radreply")

    # IPv4 bleibt zulaessig.
    validate_triple("Framed-IP-Address", ":=", "10.0.0.1", table="radreply")


async def test_bootstrap_username_is_validated(session) -> None:
    """Ein zu langer Wert aus der Umgebung liefe sonst in einen Datenbankfehler."""
    from app.services.accounts import AccountService

    service = AccountService(session)
    with pytest.raises(ValidationError):
        await service.ensure_bootstrap_admin("a" * 65, "ein-sicheres-passwort")
    with pytest.raises(ValidationError):
        await service.ensure_bootstrap_admin("   ", "ein-sicheres-passwort")

    account = await service.ensure_bootstrap_admin("admin", "ein-sicheres-passwort")
    assert account is not None


async def test_cookie_domain_ignores_the_request_host_for_csrf() -> None:
    """Ein Cookie fuer die Elterndomain geht an jeden Host darunter."""
    from starlette.datastructures import Headers
    from starlette.requests import Request

    from app.api.csrf import _expected
    from app.core.config import settings as app_settings

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/",
        "scheme": "https",
        "server": ("radius.example.org", 443),
        "client": ("10.0.0.1", 1234),
        "headers": Headers({"host": "evil.example.org"}).raw,
        "query_string": b"",
    }
    request = Request(scope)

    original_domain = app_settings.cookie_domain
    original_allowed = app_settings.allowed_origins
    try:
        app_settings.cookie_domain = None
        assert "https://evil.example.org" in _expected(request)

        app_settings.cookie_domain = ".example.org"
        app_settings.allowed_origins = ["https://radius.example.org"]
        expected = _expected(request)
        assert expected == {"https://radius.example.org"}
    finally:
        app_settings.cookie_domain = original_domain
        app_settings.allowed_origins = original_allowed


async def test_cookie_domain_requires_configured_origins() -> None:
    """Ohne eingetragene Herkunft wiese die Pruefung jeden Schreibzugriff ab."""
    from pydantic import ValidationError as PydanticValidationError

    from app.core.config import Settings

    with pytest.raises(PydanticValidationError):
        Settings(cookie_domain=".example.org", allowed_origins=[], cors_origins=[])

    Settings(cookie_domain=".example.org", allowed_origins=["https://radius.example.org"])


# --- Elfte Runde ----------------------------------------------------------


async def test_membership_replacement_locks_the_groups_being_left(session, admin_principal) -> None:
    """Sonst loeschten zwei Aufrufe gleichzeitig die letzten zwei Mitgliedschaften."""
    import inspect

    from app.schemas.groups import GroupCreate
    from app.schemas.users import UserUpdate
    from app.services.groups import GroupService

    source = inspect.getsource(UserService.update)
    assert "self.groups.memberships(username)" in source

    groups = GroupService(session)
    await groups.create(GroupCreate(groupname="alt", vlan="10"), actor=admin_principal)
    await groups.create(GroupCreate(groupname="neu", vlan="20"), actor=admin_principal)

    users = UserService(session)
    await users.create(
        UserCreate(
            username="anna",
            password="geheim123",
            groups=[MembershipIn(groupname="alt", priority=3)],
        ),
        actor=admin_principal,
    )
    detail = await users.update(
        "anna",
        UserUpdate(groups=[MembershipIn(groupname="neu", priority=5)]),
        actor=admin_principal,
    )
    assert [(m.groupname, m.priority) for m in detail.memberships] == [("neu", 5)]


async def test_bulk_group_name_is_bounded() -> None:
    """Ein ueberlanger Name sprengte die TEXT-Spalte des Sammel-Audit-Eintrags."""
    from app.schemas.users import BulkAction

    with pytest.raises(PydanticValidationError):
        BulkAction(action="assign_group", usernames=["anna"], groupname="g" * 65)
    with pytest.raises(PydanticValidationError):
        BulkAction(action="assign_group", usernames=["anna"], groupname="a:b")

    assert BulkAction(action="assign_group", usernames=["anna"], groupname="wlan").groupname


async def test_device_resolution_returns_the_stored_spelling(session, admin_principal) -> None:
    """Sonst erkennt das Umbenennen nicht mehr, dass die MAC das Passwort ist."""
    from app.services.devices import DeviceService

    service = DeviceService(session)
    await service.create(DeviceCreate(mac="aa:bb:cc:dd:ee:ff"), actor=admin_principal)

    assert await service.resolve("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"

    # Und damit zieht die Umbenennung das Passwort weiterhin mit.
    from app.schemas.users import DeviceUpdate

    await service.update(
        await service.resolve("AA:BB:CC:DD:EE:FF"),
        DeviceUpdate(mac="11:22:33:44:55:66"),
        actor=admin_principal,
    )
    password = await session.scalar(
        select(RadCheck.value).where(
            RadCheck.username == "11:22:33:44:55:66",
            RadCheck.attribute == "Cleartext-Password",
        )
    )
    assert password == "11:22:33:44:55:66"


@pytest.mark.parametrize("value", ["4294967296", "-1", "1099511627776"])
async def test_integer_attributes_stay_in_the_radius_range(value: str) -> None:
    """RADIUS kodiert ``integer`` in vier Byte ohne Vorzeichen (RFC 2865)."""
    from app.services.attributes import validate_triple

    with pytest.raises(ValidationError):
        validate_triple("Session-Timeout", ":=", value, table="radreply")

    validate_triple("Session-Timeout", ":=", "4294967295", table="radreply")


# --- Zwoelfte Runde -------------------------------------------------------


async def test_failed_import_row_does_not_commit_the_password(session, admin_principal) -> None:
    """Scheitert ein spaeterer Teilschritt, darf das Passwort nicht stehenbleiben."""
    from app.services.importexport import ImportExportService

    users = UserService(session)
    # Attributlose Gruppe mit genau einem Mitglied: das Leeren der Gruppenspalte
    # scheitert an ``error.group_last_member``.
    await users.create(UserCreate(username="anna", password="geheim123"), actor=admin_principal)
    await users.groups.add_membership("anna", "nur-mitglieder", 1)
    await session.commit()

    before = await session.scalar(
        select(RadCheck.value).where(
            RadCheck.username == "anna", RadCheck.attribute == "Cleartext-Password"
        )
    )

    csv = "username,password,groups\nanna,neues-passwort,\n"
    report = await ImportExportService(session).import_csv(
        csv, kind="user", dry_run=False, actor=admin_principal
    )
    assert report.errors == 1

    after = await session.scalar(
        select(RadCheck.value).where(
            RadCheck.username == "anna", RadCheck.attribute == "Cleartext-Password"
        )
    )
    assert after == before


async def test_lock_keys_follow_the_database_collation() -> None:
    """``group:Staff`` und ``group:staff`` bezeichnen dieselben Zeilen."""
    from app.core.locking import _lock_key

    assert _lock_key("group:Staff") == _lock_key("group:staff")
    assert _lock_key("group:staff") != _lock_key("group:students")


async def test_import_detects_case_equivalent_duplicates(session, admin_principal) -> None:
    """Sonst versprach die Vorschau zwei Neuanlagen und der Import ueberschrieb."""
    from app.services.importexport import ImportExportService

    csv = "username,password\nAlice,geheim123456\nalice,anderes123456\n"
    report = await ImportExportService(session).import_csv(
        csv, kind="user", dry_run=True, actor=admin_principal
    )
    assert report.errors == 1


async def test_memberships_are_deduplicated_like_the_database(session, admin_principal) -> None:
    """Zwei Zeilen verfaelschten die Mitgliederzahl und wendeten Attribute doppelt an."""
    from app.repositories.radius.groups import GroupRepository

    repo = GroupRepository(session)
    await repo.set_memberships("anna", [("Staff", 1), ("staff", 2)])
    await session.commit()
    assert len(await repo.memberships("anna")) == 1


async def test_non_octet_nas_networks_are_matched(session) -> None:
    """Ein als /25 eingetragenes NAS lieferte in der Sessionliste gar keinen Treffer."""
    from app.repositories.radius.acct import AccountingRepository, SessionFilter

    session.add_all(
        [
            RadAcct(
                acctsessionid="s1",
                acctuniqueid="u1",
                username="anna",
                nasipaddress="192.0.2.130",
            ),
            RadAcct(
                acctsessionid="s2",
                acctuniqueid="u2",
                username="anna",
                nasipaddress="192.0.2.10",
            ),
        ]
    )
    await session.commit()

    page = await AccountingRepository(session).search(
        SessionFilter(nas_networks=["192.0.2.128/25"])
    )
    assert [row.acctuniqueid for row in page.items] == ["u1"]


async def test_password_change_clears_the_failure_counter(session) -> None:
    """Sonst traegt das Konto die Fehlversuche in die erzwungene Neuanmeldung mit."""
    from app.core.crypto import hash_password
    from app.models.mgr import MgrAccount, Role
    from app.schemas.accounts import PasswordChange
    from app.services.accounts import AccountService

    account = MgrAccount(
        username="operator",
        role=Role.OPERATOR,
        password_hash=hash_password("ein-sicheres-passwort"),
        failed_logins=9,
    )
    session.add(account)
    await session.commit()

    service = AccountService(session)
    principal = Principal(
        account_id=account.id,
        username=account.username,
        role=Role.OPERATOR,
        language="de",
        session_id="test",
        absolute_expiry=0,
    )
    await service.change_password(
        account.id,
        PasswordChange(
            current_password="ein-sicheres-passwort", new_password="noch-ein-sicheres-passwort"
        ),
        actor=principal,
    )
    await session.refresh(account)
    assert account.failed_logins == 0
    assert account.locked_until is None


async def test_totp_confirmation_is_serialised_against_resets() -> None:
    """Ein Reset dazwischen liesse "TOTP aktiv, ohne Geheimnis" zurueck."""
    import inspect

    from app.services.accounts import AccountService

    assert "account-totp:" in inspect.getsource(AccountService.confirm_totp)
    assert "account-totp:" in inspect.getsource(AccountService.update)
    assert "account-totp:" in inspect.getsource(AccountService.start_totp_enrollment)


async def test_force_delete_records_the_members(session, admin_principal) -> None:
    """Ohne die Namen liesse sich nicht feststellen, wer die Policy verloren hat."""
    from sqlalchemy import select as sa_select

    from app.models.mgr import MgrAudit
    from app.schemas.groups import GroupCreate
    from app.services.groups import GroupService

    groups = GroupService(session)
    await groups.create(GroupCreate(groupname="wlan", vlan="10"), actor=admin_principal)
    users = UserService(session)
    for name in ("anna", "bruno"):
        await users.create(
            UserCreate(
                username=name,
                password="geheim123",
                groups=[MembershipIn(groupname="wlan")],
            ),
            actor=admin_principal,
        )

    await groups.delete("wlan", actor=admin_principal, force=True)
    entry = await session.scalar(
        sa_select(MgrAudit)
        .where(MgrAudit.action == "group.delete")
        .order_by(MgrAudit.id.desc())
        .limit(1)
    )
    assert entry is not None
    import json as _json

    before = _json.loads(entry.before_json or "{}")
    assert sorted(before["members"]) == ["anna", "bruno"]
    assert before["members_truncated"] is False


async def test_import_rejects_too_many_rows(session, admin_principal) -> None:
    """Die Groessenbeschraenkung des Uploads begrenzt die Zeilenzahl nicht."""
    from app.services.importexport import MAX_IMPORT_ROWS, ImportExportService

    rows = "\n".join(f"user{index:06d},geheim123456" for index in range(MAX_IMPORT_ROWS + 1))
    csv = f"username,password\n{rows}\n"
    with pytest.raises(ValidationError) as excinfo:
        await ImportExportService(session).import_csv(
            csv, kind="user", dry_run=True, actor=admin_principal
        )
    assert excinfo.value.code == "error.import_too_many_rows"


# --- Dreizehnte Runde -----------------------------------------------------


async def test_identifier_folding_ignores_accents() -> None:
    """Die Standardkollation vergleicht auch akzentunempfindlich."""
    from app.core.identifiers import fold
    from app.core.locking import _lock_key

    assert fold("café") == fold("CAFE")
    assert _lock_key("group:café") == _lock_key("group:Cafe")
    assert _lock_key("group:cafe") != _lock_key("group:kafe")


async def test_expired_lockout_grants_a_fresh_attempt_window(session) -> None:
    """Sonst loeste der erste Fehlversuch danach sofort die naechste Sperre aus."""
    from app.core.crypto import hash_password
    from app.core.dates import utcnow
    from app.models.mgr import MgrAccount, Role
    from app.services.accounts import LOCKOUT_THRESHOLD, AccountService

    account = MgrAccount(
        username="operator",
        role=Role.OPERATOR,
        password_hash=hash_password("ein-sicheres-passwort"),
        failed_logins=LOCKOUT_THRESHOLD,
        locked_until=utcnow() - dt.timedelta(minutes=1),
    )
    session.add(account)
    await session.commit()

    result = await AccountService(session).authenticate("operator", "ein-sicheres-passwort")
    assert result.failed_logins == 0
    assert result.locked_until is None


async def test_last_member_guard_follows_the_collation(session, admin_principal) -> None:
    """Das DELETE trifft ``Alice`` auch bei der Eingabe ``alice``."""
    from app.schemas.groups import MembershipChange
    from app.services.groups import GroupService

    users = UserService(session)
    await users.create(UserCreate(username="Alice", password="geheim123"), actor=admin_principal)
    await users.groups.add_membership("Alice", "nur-mitglieder", 1)
    await session.commit()

    with pytest.raises(ValidationError) as excinfo:
        await GroupService(session).change_membership(
            "nur-mitglieder",
            MembershipChange(action="remove", usernames=["alice"]),
            actor=admin_principal,
        )
    assert excinfo.value.code == "error.group_last_member"


async def test_session_revocation_sees_subsecond_changes() -> None:
    """Eine Passwortaenderung in derselben Sekunde muss die Sitzung verwerfen."""
    from app.core.security import create_session_token, principal_from_token
    from app.models.mgr import Role as AccountRole

    token, _ = create_session_token(1, "admin", AccountRole.ADMINISTRATOR, "de")
    claims = principal_from_token(token)
    assert isinstance(claims.auth_at, float)

    # Der Zeitstempel der Spalte fuehrt ebenfalls Bruchteile.
    from app.models.mgr import MgrAccount

    column = MgrAccount.__table__.c.password_changed_at
    assert getattr(column.type, "fsp", None) == 6


async def test_membership_addition_locks_the_user(session, admin_principal) -> None:
    """Ein gleichzeitiges Loeschen liesse sonst einen Phantom-Benutzer entstehen."""
    import inspect

    from app.services.groups import GroupService

    source = inspect.getsource(GroupService.change_membership)
    assert 'f"user:{name}"' in source


async def test_totp_code_is_accepted_only_once(session) -> None:
    """Ein abgefangener Code liesse sich sonst im Prueffenster erneut einloesen."""
    import pyotp

    from app.core.config import settings as app_settings
    from app.core.crypto import SecretBox, hash_password
    from app.models.mgr import MgrAccount, Role
    from app.services.accounts import AccountService

    secret = pyotp.random_base32()
    account = MgrAccount(
        username="admin",
        role=Role.ADMINISTRATOR,
        password_hash=hash_password("ein-sicheres-passwort"),
        totp_enabled=True,
        totp_secret_enc=SecretBox(app_settings.coa_secret_key or app_settings.secret_key).encrypt(
            secret
        ),
    )
    session.add(account)
    await session.commit()

    service = AccountService(session)
    code = pyotp.TOTP(secret).now()
    await service.verify_totp_code(account, code)
    assert account.totp_last_counter is not None

    from app.core.errors import AuthenticationError

    with pytest.raises(AuthenticationError) as excinfo:
        await service.verify_totp_code(account, code)
    assert excinfo.value.code == "error.totp_invalid"
