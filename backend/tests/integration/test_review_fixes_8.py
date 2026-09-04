"""Regressionstests zur neunten Review-Runde."""

from __future__ import annotations

import datetime as dt

import pytest
import pytest_asyncio
from pydantic import ValidationError as PydanticValidationError
from sqlalchemy import func, select

from app.core.errors import ValidationError
from app.core.identifiers import fold
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


@pytest_asyncio.fixture
async def client(engine):
    """HTTP-Client gegen die vollstaendige Anwendung (inkl. Middleware)."""
    from httpx import ASGITransport, AsyncClient

    from app.api.deps import login_ip_limiter, login_limiter
    from app.core.config import settings as app_settings
    from app.main import create_app

    app_settings.cookie_secure = False
    login_limiter.clear()
    login_ip_limiter.clear()
    transport = ASGITransport(app=create_app())
    async with AsyncClient(transport=transport, base_url="http://testserver") as http:
        yield http


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


# --- Vierzehnte Runde -----------------------------------------------------


async def test_challenge_is_revoked_by_a_same_second_password_change(session) -> None:
    """Sonst bliebe die Challenge trotz Passwortwechsel ihre volle Laufzeit gueltig."""
    from app.core.crypto import hash_password
    from app.core.dates import utcnow
    from app.core.errors import AuthenticationError
    from app.models.mgr import MgrAccount, Role
    from app.services.accounts import AccountService

    account = MgrAccount(
        username="admin",
        role=Role.ADMINISTRATOR,
        password_hash=hash_password("ein-sicheres-passwort"),
    )
    session.add(account)
    await session.commit()

    service = AccountService(session)
    challenge = service.challenge_for(account)
    # Wechsel in derselben Sekunde, aber danach.
    account.password_changed_at = utcnow()
    await session.commit()

    with pytest.raises(AuthenticationError) as excinfo:
        await service.account_from_challenge(challenge)
    assert excinfo.value.code == "error.reauthentication_required"


async def test_group_summary_joins_with_the_collation(session, admin_principal) -> None:
    """Attribut- und Mitgliedschaftszeilen koennen verschiedene Schreibweisen fuehren."""
    from app.schemas.groups import GroupCreate
    from app.services.groups import GroupService

    groups = GroupService(session)
    await groups.create(GroupCreate(groupname="Staff", vlan="10"), actor=admin_principal)
    await groups.repo.add_membership("anna", "staff", 1)
    await session.commit()

    item = next(g for g in await groups.search() if fold(g.groupname) == "staff")
    assert item.members == 1
    assert item.vlan == "10"


async def test_exact_nas_address_does_not_match_neighbours(session, admin_principal) -> None:
    """ "10.0.0.1" darf nicht auch die Sitzungen von "10.0.0.10" liefern."""
    from app.schemas.nas import NasCreate
    from app.services.nas import NasService
    from app.services.sessions import SessionService

    nas = NasService(session)
    await nas.create(
        NasCreate(nasname="10.0.0.1", shortname="ap-1", secret="s"), actor=admin_principal
    )
    await nas.create(
        NasCreate(nasname="10.0.0.10", shortname="ap-10", secret="s"), actor=admin_principal
    )

    addresses, networks = await SessionService(session).resolve_nas_filter("10.0.0.1")
    assert addresses == ["10.0.0.1"]
    assert networks == []

    # Ueber den Kurznamen bleibt die Teiltextsuche erhalten.
    addresses, _ = await SessionService(session).resolve_nas_filter("ap-1")
    assert sorted(addresses) == ["10.0.0.1", "10.0.0.10"]


# --- Fuenfzehnte Runde ----------------------------------------------------


async def test_reactivating_an_account_does_not_revive_old_tokens(session, client) -> None:
    """Ohne Generationszaehler galten dieselben Token nach der Reaktivierung wieder."""
    from app.core.crypto import hash_password
    from app.models.mgr import MgrAccount, Role
    from app.schemas.accounts import AccountUpdate
    from app.services.accounts import AccountService

    account = MgrAccount(
        username="operator",
        role=Role.OPERATOR,
        password_hash=hash_password("ein-sicheres-passwort"),
    )
    session.add(account)
    await session.commit()

    login = await client.post(
        "/api/v1/auth/login",
        json={"username": "operator", "password": "ein-sicheres-passwort"},
    )
    assert login.status_code == 200
    assert (await client.get("/api/v1/auth/me")).status_code == 200

    principal = Principal(
        account_id=account.id,
        username="admin",
        role=Role.ADMINISTRATOR,
        language="de",
        session_id="test",
        absolute_expiry=0,
    )
    service = AccountService(session)
    await service.update(account.id, AccountUpdate(is_active=False), actor=principal)
    await service.update(account.id, AccountUpdate(is_active=True), actor=principal)

    blocked = await client.get("/api/v1/auth/me")
    assert blocked.status_code == 401
    assert blocked.json()["code"] == "error.reauthentication_required"


async def test_unknown_enum_value_warns_instead_of_failing() -> None:
    """Die Wertelisten sind eine Auswahl; ein harter Fehler wiese Gueltiges ab."""
    from app.services.attributes import validate_triple

    warnings = validate_triple("Tunnel-Type", ":=", "garbage", table="radgroupreply")
    assert [w.code for w in warnings] == ["warn.unknown_enum_value"]

    assert validate_triple("Tunnel-Type", ":=", "VLAN", table="radgroupreply") == []
    assert validate_triple("Tunnel-Type", ":=", "13", table="radgroupreply") == []


async def test_deleting_a_user_records_vanishing_groups(session, admin_principal) -> None:
    """Eine nur ueber diese Mitgliedschaft bestehende Gruppe verschwindet mit."""
    from sqlalchemy import select as sa_select

    from app.models.mgr import MgrAudit

    users = UserService(session)
    await users.create(UserCreate(username="anna", password="geheim123"), actor=admin_principal)
    await users.groups.add_membership("anna", "nur-mitglieder", 1)
    await session.commit()

    await users.delete("anna", actor=admin_principal)

    entry = await session.scalar(
        sa_select(MgrAudit)
        .where(MgrAudit.action == "group.delete", MgrAudit.object_id == "nur-mitglieder")
        .limit(1)
    )
    assert entry is not None


async def test_bulk_expiry_runs_under_the_user_lock() -> None:
    """Ein gleichzeitiges Loeschen liesse sonst einen Benutzer ohne Anmeldedaten entstehen."""
    import inspect

    from app.services.importexport import ImportExportService

    source = inspect.getsource(ImportExportService._bulk_one)
    assert "_set_expiry_locked" in source
    assert 'named_lock(self.session, f"user:{username}")' in source


async def test_download_refreshes_the_session_cookie(session, client) -> None:
    """Der Endpunkt gibt ein eigenes Response-Objekt zurueck; FastAPI verwirft dessen Header."""
    from app.core.crypto import hash_password
    from app.models.mgr import MgrAccount, Role

    session.add(
        MgrAccount(
            username="operator",
            role=Role.OPERATOR,
            password_hash=hash_password("ein-sicheres-passwort"),
        )
    )
    await session.commit()
    await client.post(
        "/api/v1/auth/login",
        json={"username": "operator", "password": "ein-sicheres-passwort"},
    )

    response = await client.get("/api/v1/users/export")
    assert response.status_code == 200
    assert "frm_session" in response.headers.get("set-cookie", "")


# --- Sechzehnte Runde -----------------------------------------------------


async def test_dictionary_names_the_reserved_check_attributes(session, client) -> None:
    """Die Oberflaeche blendet sie im Expertenmodus aus."""
    from app.core.crypto import hash_password
    from app.models.mgr import MgrAccount, Role
    from app.services.users import RESERVED_CHECK_ATTRIBUTES

    session.add(
        MgrAccount(
            username="operator",
            role=Role.OPERATOR,
            password_hash=hash_password("ein-sicheres-passwort"),
        )
    )
    await session.commit()
    await client.post(
        "/api/v1/auth/login",
        json={"username": "operator", "password": "ein-sicheres-passwort"},
    )

    response = await client.get("/api/v1/groups/dictionary")
    assert response.status_code == 200
    names = set(response.json()["reserved_check_attributes"])
    assert names == set(RESERVED_CHECK_ATTRIBUTES)
    assert "cleartext-password" in names
    assert "auth-type" in names


async def test_unlinking_oidc_revokes_the_session(session) -> None:
    """Sonst blieben die ueber diese Identitaet ausgestellten Sitzungen gueltig."""
    from app.core.crypto import hash_password
    from app.models.mgr import MgrAccount, Role
    from app.services.accounts import AccountService

    account = MgrAccount(
        username="oidc-user",
        role=Role.OPERATOR,
        password_hash=hash_password("ein-sicheres-passwort"),
        oidc_subject="subject-1",
    )
    session.add(account)
    await session.commit()
    before = account.session_epoch

    principal = Principal(
        account_id=account.id,
        username="admin",
        role=Role.ADMINISTRATOR,
        language="de",
        session_id="test",
        absolute_expiry=0,
    )
    await AccountService(session).set_oidc_subject(account.id, None, actor=principal)
    await session.refresh(account)
    assert account.session_epoch == before + 1


async def test_challenge_is_bound_to_the_session_epoch(session) -> None:
    """Eine vor der Sperrung angeforderte Challenge darf danach nicht gelten."""
    from app.core.crypto import hash_password
    from app.core.errors import AuthenticationError
    from app.models.mgr import MgrAccount, Role
    from app.services.accounts import AccountService

    account = MgrAccount(
        username="admin",
        role=Role.ADMINISTRATOR,
        password_hash=hash_password("ein-sicheres-passwort"),
    )
    session.add(account)
    await session.commit()

    service = AccountService(session)
    challenge = service.challenge_for(account)
    account.session_epoch += 1
    await session.commit()

    with pytest.raises(AuthenticationError) as excinfo:
        await service.account_from_challenge(challenge)
    assert excinfo.value.code == "error.reauthentication_required"


async def test_user_list_joins_memberships_with_the_collation(session, admin_principal) -> None:
    """Sonst fehlte die Mitgliedschaft in Liste und Export - und ein Reimport entfernte sie."""
    from app.repositories.directory import SubjectFilter

    users = UserService(session)
    await users.create(UserCreate(username="Alice", password="geheim123"), actor=admin_principal)
    await users.groups.add_membership("alice", "wlan", 1)
    await session.commit()

    items, _ = await users.search(SubjectFilter())
    entry = next(i for i in items if fold(i.username) == "alice")
    assert entry.groups == ["wlan"]


async def test_diagnosis_reports_a_group_level_reject(session, admin_principal) -> None:
    """FreeRADIUS wendet die Check-Attribute der Gruppe an; die Diagnose muss das nennen."""
    from app.schemas.groups import AttributeIn, GroupCreate
    from app.services.groups import GroupService

    await GroupService(session).create(
        GroupCreate(
            groupname="gesperrt",
            check_attributes=[AttributeIn(attribute="Auth-Type", op=":=", value="Reject")],
        ),
        actor=admin_principal,
    )
    users = UserService(session)
    await users.create(
        UserCreate(
            username="anna",
            password="geheim123",
            groups=[MembershipIn(groupname="gesperrt")],
        ),
        actor=admin_principal,
    )

    result = await AuthLogService(session).diagnose("anna")
    assert result.status == "disabled"
    assert any(h.code == "diag.auth_type_reject" for h in result.hints)


async def test_responses_forbid_framing(client) -> None:
    """Ohne diesen Kopf liesse sich die Oberflaeche fuer Clickjacking einbetten."""
    response = await client.get("/healthz")
    assert response.headers["content-security-policy"] == "frame-ancestors 'none'"
    assert response.headers["x-frame-options"] == "DENY"


async def test_session_cookie_is_scoped_to_the_root_path(session, client) -> None:
    """Unter einem Praefix ginge das Cookie sonst an jede andere Anwendung des Hosts."""
    from app.api import deps
    from app.core.config import settings as app_settings

    original = app_settings.root_path
    try:
        app_settings.root_path = "/manager"
        assert deps.cookie_path() == "/manager/"
    finally:
        app_settings.root_path = original
    assert deps.cookie_path() == "/"


# --- Siebzehnte Runde -----------------------------------------------------


async def test_oversized_import_writes_nothing(session, admin_principal) -> None:
    """Die Zeilen schreiben einzeln fest; ein Abbruch im Lauf liesse sie bestehen."""
    from app.services.importexport import MAX_IMPORT_ROWS, ImportExportService

    rows = "\n".join(f"user{index:06d},geheim123456" for index in range(MAX_IMPORT_ROWS + 1))
    csv = f"username,password\n{rows}\n"
    with pytest.raises(ValidationError) as excinfo:
        await ImportExportService(session).import_csv(
            csv, kind="user", dry_run=False, actor=admin_principal
        )
    assert excinfo.value.code == "error.import_too_many_rows"

    written = await session.scalar(select(func.count()).select_from(RadCheck))
    assert written == 0


async def test_membership_replacement_accepts_another_spelling(session, admin_principal) -> None:
    """ "staff" und "Staff" bezeichnen dieselbe Gruppe - das ist keine Entfernung."""
    from app.schemas.users import UserUpdate

    users = UserService(session)
    await users.create(UserCreate(username="anna", password="geheim123"), actor=admin_principal)
    await users.groups.add_membership("anna", "staff", 1)
    await session.commit()

    detail = await users.update(
        "anna",
        UserUpdate(groups=[MembershipIn(groupname="Staff", priority=1)]),
        actor=admin_principal,
    )
    assert [m.groupname for m in detail.memberships] == ["Staff"]


async def test_totp_enrollment_start_is_audited(session) -> None:
    """Ein abgebrochener Versuch hinterliesse sonst gar keinen Eintrag (FR-9)."""
    from sqlalchemy import select as sa_select

    from app.core.crypto import hash_password
    from app.models.mgr import MgrAccount, MgrAudit, Role
    from app.services.accounts import AccountService

    account = MgrAccount(
        username="admin",
        role=Role.ADMINISTRATOR,
        password_hash=hash_password("ein-sicheres-passwort"),
    )
    session.add(account)
    await session.commit()

    await AccountService(session).start_totp_enrollment(account)
    entry = await session.scalar(
        sa_select(MgrAudit).where(MgrAudit.action == "account.totp_enrollment_started").limit(1)
    )
    assert entry is not None
    assert "secret" not in (entry.after_json or "")


async def test_bulk_assignment_checks_inside_the_lock() -> None:
    """Ein Loeschen zwischen Pruefung und Einfuegen erzeugte einen Phantom-Benutzer."""
    import inspect

    from app.services.importexport import ImportExportService

    source = inspect.getsource(ImportExportService._bulk_one)
    lock_at = source.index('named_lock(self.session, f"group:{groupname}", f"user:{username}")')
    check_at = source.index("exists_anywhere(", lock_at)
    assert check_at > lock_at


@pytest.mark.parametrize("value", ["not-a-date", "31 Foo 2026"])
async def test_date_attributes_are_validated(value: str) -> None:
    """Ein unlesbarer Wert bliebe gespeichert, waehrend die Sperre nie greift."""
    from app.services.attributes import validate_triple

    with pytest.raises(ValidationError):
        validate_triple("Expiration", ":=", value, table="radgroupcheck")

    validate_triple("Expiration", ":=", "31 Dec 2026 23:59:59", table="radgroupcheck")


async def test_audit_payload_is_bounded_by_bytes(session, admin_principal) -> None:
    """``after_json`` fasst 65 535 *Bytes*; mehrbytige Zeichen sprengen eine Zeichengrenze."""
    from app.services.audit import MAX_PAYLOAD_BYTES, _dump

    dumped = _dump({"value": "ä" * 60_000})
    assert dumped is not None
    assert len(dumped.encode("utf-8")) <= MAX_PAYLOAD_BYTES
    assert '"truncated": true' in dumped

    small = _dump({"value": "kurz"})
    assert small == '{"value": "kurz"}'


async def test_challenge_length_is_bounded() -> None:
    """Ohne Grenze liesse sich die Signaturpruefung beliebig beschaeftigen."""
    from app.schemas.accounts import MAX_CHALLENGE_LENGTH, TotpLoginRequest

    with pytest.raises(PydanticValidationError):
        TotpLoginRequest(challenge="x" * (MAX_CHALLENGE_LENGTH + 1), totp_code="123456")


async def test_invalid_challenge_consumes_the_ip_quota(session, client) -> None:
    """Sonst liefen ungueltige Challenges unbegrenzt durch die Signaturpruefung."""
    from app.core.config import settings as app_settings

    last = None
    for _ in range(app_settings.login_ip_rate_limit + 1):
        last = await client.post(
            "/api/v1/auth/login/totp",
            json={"challenge": "ungueltig", "totp_code": "000000"},
        )
    assert last is not None
    assert last.status_code == 429


# --- Achtzehnte Runde -----------------------------------------------------


async def test_import_stops_reading_at_the_row_cap() -> None:
    """``list(reader)`` baute vorher Millionen Zeilen-Dicts vor der Pruefung."""
    import inspect

    from app.services.importexport import ImportExportService

    source = inspect.getsource(ImportExportService.import_csv)
    assert "itertools.islice(reader, MAX_IMPORT_ROWS + 1)" in source


async def test_enrollment_code_cannot_be_replayed(session) -> None:
    """Challenge und Code liessen sich im Prueffenster erneut einloesen."""
    import pyotp

    from app.core.config import settings as app_settings
    from app.core.crypto import SecretBox, hash_password
    from app.core.errors import ConflictError
    from app.models.mgr import MgrAccount, Role
    from app.services.accounts import AccountService

    account = MgrAccount(
        username="admin",
        role=Role.ADMINISTRATOR,
        password_hash=hash_password("ein-sicheres-passwort"),
    )
    session.add(account)
    await session.commit()

    service = AccountService(session)
    setup = await service.start_totp_enrollment(account)
    del setup
    secret = SecretBox(app_settings.coa_secret_key or app_settings.secret_key).decrypt(
        str(account.totp_secret_enc)
    )
    code = pyotp.TOTP(secret).now()
    await service.confirm_totp(account, code)
    assert account.totp_enabled is True

    with pytest.raises(ConflictError) as excinfo:
        await service.confirm_totp(account, code)
    assert excinfo.value.code == "error.totp_already_enrolled"


async def test_import_row_creates_metadata_only_under_the_lock() -> None:
    """Ein Loeschen dazwischen liesse den Datensatz sonst wieder entstehen."""
    import inspect

    from app.services.importexport import ImportExportService

    write_row = inspect.getsource(ImportExportService._write_row)
    assert "subjects.ensure" not in write_row

    apply_row = inspect.getsource(UserService.apply_row)
    lock_at = apply_row.index("named_lock")
    assert apply_row.index("self.subjects.ensure(", lock_at) > lock_at


async def test_named_lock_refreshes_the_read_snapshot() -> None:
    """REPEATABLE READ: der Wartende saehe den soeben geschriebenen Stand sonst nicht."""
    import inspect

    from app.core import locking

    assert "session.rollback()" in inspect.getsource(locking.named_lock)


async def test_octet_counters_are_serialised_as_text(session) -> None:
    """Oberhalb von 2^53 rundete JavaScript den Wert stillschweigend."""
    from app.repositories.radius.acct import AccountingRepository, SessionFilter
    from app.services.sessions import SessionService

    huge = 9_007_199_254_740_993  # 2^53 + 1
    session.add(
        RadAcct(
            acctsessionid="s1",
            acctuniqueid="u1",
            username="anna",
            nasipaddress="10.0.0.1",
            acctinputoctets=huge,
            acctoutputoctets=huge,
        )
    )
    await session.commit()

    assert await AccountingRepository(session).get(1) is not None
    items, _, _ = await SessionService(session).search(SessionFilter())
    assert items[0].acctinputoctets == str(huge)
    assert items[0].acctoutputoctets == str(huge)


# --- Neunzehnte Runde -----------------------------------------------------


async def test_password_reset_removes_legacy_credentials(session, admin_principal) -> None:
    """Ein alter Crypt-Hash galt sonst je nach Methode weiter."""
    from app.schemas.users import PasswordSet

    users = UserService(session)
    await users.create(UserCreate(username="anna", password="geheim123"), actor=admin_principal)
    await users.attrs.add_check("anna", "Crypt-Password", ":=", "$1$alt")
    await session.commit()

    await users.set_password("anna", PasswordSet(password="neu-geheim123"), actor=admin_principal)

    rows = (await session.scalars(select(RadCheck).where(RadCheck.username == "anna"))).all()
    assert not any(r.attribute.lower() == "crypt-password" for r in rows)


async def test_masked_reply_values_are_preserved(session, admin_principal) -> None:
    """Der Expertenmodus schickt alle Reply-Zeilen zurueck, auch die maskierten."""
    from app.models.radius import RadReply
    from app.schemas.users import AttributeIn, UserUpdate

    users = UserService(session)
    await users.create(UserCreate(username="anna", password="geheim123"), actor=admin_principal)
    await users.attrs.add_reply("anna", "Cleartext-Password", ":=", "reply-geheim")
    await session.commit()

    detail = await users.get("anna")
    masked = [
        AttributeIn(attribute=a.attribute, op=a.op, value=a.value) for a in detail.reply_attributes
    ]
    masked.append(AttributeIn(attribute="Filter-Id", op=":=", value="std"))
    await users.update("anna", UserUpdate(reply_attributes=masked), actor=admin_principal)

    stored = await session.scalar(
        select(RadReply.value).where(
            RadReply.username == "anna", RadReply.attribute == "Cleartext-Password"
        )
    )
    assert stored == "reply-geheim"


async def test_effective_expiration_is_exported(session, admin_principal) -> None:
    """Sonst zeigte die Ansicht ein kuenftiges Datum zu einem abgelaufenen Status."""
    users = UserService(session)
    await users.create(UserCreate(username="anna", password="geheim123"), actor=admin_principal)
    await users.attrs.add_check("anna", "Expiration", ":=", "31 Dec 2030 00:00:00")
    await users.attrs.add_check("anna", "Expiration", ":=", "01 Jan 2020 00:00:00")
    await session.commit()

    detail = await users.get("anna")
    assert detail.status == "expired"
    assert detail.expires_at is not None
    assert detail.expires_at.year == 2020


async def test_dry_run_reports_the_last_membership_guard(session, admin_principal) -> None:
    """Die Vorschau meldete eine Zeile als gueltig, die der Import abweist."""
    from app.services.importexport import ImportExportService

    users = UserService(session)
    await users.create(UserCreate(username="anna", password="geheim123"), actor=admin_principal)
    await users.groups.add_membership("anna", "nur-mitglieder", 1)
    await session.commit()

    report = await ImportExportService(session).import_csv(
        "username,groups\nanna,\n", kind="user", dry_run=True, actor=admin_principal
    )
    assert report.errors == 1


async def test_successful_totp_login_frees_the_password_quota(session, client) -> None:
    """Sonst blieb je vollstaendiger Anmeldung ein Treffer der Passwortstufe stehen."""
    import pyotp

    from app.api.deps import login_limiter
    from app.core.config import settings as app_settings
    from app.core.crypto import SecretBox, hash_password
    from app.models.mgr import MgrAccount, Role

    secret = pyotp.random_base32()
    session.add(
        MgrAccount(
            username="admin",
            role=Role.ADMINISTRATOR,
            password_hash=hash_password("ein-sicheres-passwort"),
            totp_enabled=True,
            totp_secret_enc=SecretBox(
                app_settings.coa_secret_key or app_settings.secret_key
            ).encrypt(secret),
        )
    )
    await session.commit()

    first = await client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "ein-sicheres-passwort"},
    )
    assert first.json()["status"] == "totp_required"
    done = await client.post(
        "/api/v1/auth/login/totp",
        json={"challenge": first.json()["challenge"], "totp_code": pyotp.TOTP(secret).now()},
    )
    assert done.status_code == 200, done.text

    # Kein Treffer der Passwortstufe bleibt zurueck; die Schluessel enthalten
    # neben der Adresse den Kontonamen.
    assert login_limiter.tracked_keys() == 0


async def test_expired_lockout_is_cleared_before_password_change(session) -> None:
    """Sonst loeste der erste Tippfehler danach sofort die naechste Sperre aus."""
    from app.core.crypto import hash_password
    from app.core.dates import utcnow
    from app.models.mgr import MgrAccount, Role
    from app.schemas.accounts import PasswordChange
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

    principal = Principal(
        account_id=account.id,
        username=account.username,
        role=Role.OPERATOR,
        language="de",
        session_id="test",
        absolute_expiry=0,
    )
    await AccountService(session).change_password(
        account.id,
        PasswordChange(
            current_password="ein-sicheres-passwort", new_password="noch-ein-sicheres-passwort"
        ),
        actor=principal,
    )
    await session.refresh(account)
    assert account.failed_logins == 0
    assert account.locked_until is None


# --- Zwanzigste Runde -----------------------------------------------------


async def test_forwarded_address_must_be_an_ip(monkeypatch) -> None:
    """Ein frei waehlbarer Wert ergaebe je Versuch einen neuen Limiter-Schluessel."""
    from starlette.datastructures import Headers
    from starlette.requests import Request

    from app.api import deps
    from app.core.config import settings as app_settings

    def _request(forwarded: str) -> Request:
        return Request(
            {
                "type": "http",
                "method": "POST",
                "path": "/",
                "client": ("127.0.0.1", 1234),
                "headers": Headers({"x-forwarded-for": forwarded}).raw,
                "query_string": b"",
            }
        )

    original = app_settings.trusted_proxies
    app_settings.trusted_proxies = ["127.0.0.0/8"]
    deps._trusted_networks.cache_clear()
    try:
        assert deps.client_ip(_request("x" * 200)) == "127.0.0.1"
        assert deps.client_ip(_request("nicht-ip, 127.0.0.1")) == "127.0.0.1"
        assert deps.client_ip(_request("198.51.100.7, 127.0.0.1")) == "198.51.100.7"
        # Angehaengter Port und geklammertes IPv6 werden abgetrennt.
        assert deps.client_ip(_request("198.51.100.7:1234")) == "198.51.100.7"
        assert deps.client_ip(_request("[2001:db8::1]:443")) == "2001:db8::1"
    finally:
        app_settings.trusted_proxies = original
        deps._trusted_networks.cache_clear()


async def test_credential_type_change_removes_legacy_rows(session, admin_principal) -> None:
    """Ein Crypt-Hash blieb sonst nutzbar, obwohl der Manager "nt" meldet."""
    from app.schemas.users import UserUpdate

    users = UserService(session)
    await users.create(UserCreate(username="anna", password="geheim123"), actor=admin_principal)
    await users.attrs.add_check("anna", "Crypt-Password", ":=", "$1$alt")
    await session.commit()

    await users.update("anna", UserUpdate(credential_type="nt"), actor=admin_principal)
    rows = (await session.scalars(select(RadCheck).where(RadCheck.username == "anna"))).all()
    names = {r.attribute.lower() for r in rows}
    assert "crypt-password" not in names
    assert "cleartext-password" not in names
    assert "nt-password" in names


async def test_totp_reset_clears_the_replay_marker(session) -> None:
    """Sonst wiese die Bestaetigung des neuen Faktors den ersten Code ab."""
    from app.core.crypto import hash_password
    from app.models.mgr import MgrAccount, Role
    from app.schemas.accounts import AccountUpdate
    from app.services.accounts import AccountService

    account = MgrAccount(
        username="admin",
        role=Role.ADMINISTRATOR,
        password_hash=hash_password("ein-sicheres-passwort"),
        totp_enabled=True,
        totp_secret_enc="egal",
        totp_last_counter=123456,
    )
    session.add(account)
    await session.commit()

    principal = Principal(
        account_id=account.id,
        username="admin",
        role=Role.ADMINISTRATOR,
        language="de",
        session_id="test",
        absolute_expiry=0,
    )
    await AccountService(session).update(
        account.id, AccountUpdate(reset_totp=True), actor=principal
    )
    await session.refresh(account)
    assert account.totp_last_counter is None


async def test_delete_verifies_the_group_lock_set() -> None:
    """Eine erst danach entstandene Mitgliedschaft liefe ohne ihre Gruppensperre."""
    import inspect

    source = inspect.getsource(UserService._groups_vanishing_with)
    assert "error.busy" in source
    assert "locked" in inspect.signature(UserService._delete_locked).parameters


# --- Einundzwanzigste Runde -----------------------------------------------


async def test_pbkdf2_password_is_masked(session, admin_principal) -> None:
    """FreeRADIUS 3 kennt das Attribut; unmaskiert waere es ein Rateansatz."""
    from app.core import radius_dict
    from app.schemas.users import MASKED

    assert radius_dict.is_password_attribute("PBKDF2-Password")

    users = UserService(session)
    await users.create(UserCreate(username="anna", password="geheim123"), actor=admin_principal)
    await users.attrs.add_check("anna", "PBKDF2-Password", ":=", "$pbkdf2$geheim")
    await session.commit()

    detail = await users.get("anna")
    value = next(a.value for a in detail.check_attributes if a.attribute == "PBKDF2-Password")
    assert value == MASKED


async def test_oidc_issuer_keeps_its_trailing_slash() -> None:
    """Der ``iss``-Claim wird exakt geprueft; ein gekuerzter Wert wiese alles ab."""
    import inspect

    from app.services.oidc import OidcService

    source = inspect.getsource(OidcService._verify_id_token)
    assert 'meta.get("issuer") or self.config.oidc_issuer)' in source
    assert 'rstrip("/")' not in source


async def test_duplicate_csv_columns_are_rejected(session, admin_principal) -> None:
    """``DictReader`` behaelt sonst stillschweigend nur die letzte Spalte."""
    from app.services.importexport import ImportExportService

    with pytest.raises(ValidationError) as excinfo:
        await ImportExportService(session).import_csv(
            "username,password,Password\nanna,a,b\n",
            kind="user",
            dry_run=True,
            actor=admin_principal,
        )
    assert excinfo.value.code == "error.import_duplicate_columns"


async def test_bulk_audit_records_the_device_type(session, admin_principal) -> None:
    """Fest verdrahtet waere die Filterung des Audit-Logs falsch."""
    from sqlalchemy import select as sa_select

    from app.models.mgr import MgrAudit
    from app.repositories.directory import SubjectFilter
    from app.schemas.users import BulkAction, DeviceCreate
    from app.services.devices import DeviceService
    from app.services.importexport import ImportExportService

    await DeviceService(session).create(
        DeviceCreate(mac="aa:bb:cc:dd:ee:ff"), actor=admin_principal
    )
    await ImportExportService(session).bulk(
        BulkAction(
            action="set_expiry",
            usernames=["aa:bb:cc:dd:ee:ff"],
            expires_at=dt.datetime(2030, 1, 1, tzinfo=dt.UTC),
        ),
        SubjectFilter(),
        actor=admin_principal,
    )

    entry = await session.scalar(
        sa_select(MgrAudit).where(MgrAudit.action == "user.set_expiry").limit(1)
    )
    assert entry is not None
    assert entry.object_type == "device"


# --- Zweiundzwanzigste Runde ----------------------------------------------


async def test_duplicate_header_check_is_linear() -> None:
    """``count()`` je Spalte war quadratisch und blockierte den Worker."""
    import inspect

    from app.services.importexport import ImportExportService

    source = inspect.getsource(ImportExportService.import_csv)
    assert "collections.Counter" in source
    assert "headers.count(" not in source


async def test_self_service_enrollment_names_the_actor(session, client) -> None:
    """Der Eintrag war der einzige Beleg fuer den Geheimniswechsel - ohne Urheber."""
    from sqlalchemy import select as sa_select

    from app.core.crypto import hash_password
    from app.models.mgr import MgrAccount, MgrAudit, Role

    session.add(
        MgrAccount(
            username="operator",
            role=Role.OPERATOR,
            password_hash=hash_password("ein-sicheres-passwort"),
        )
    )
    await session.commit()
    await client.post(
        "/api/v1/auth/login",
        json={"username": "operator", "password": "ein-sicheres-passwort"},
    )
    response = await client.post(
        "/api/v1/auth/me/totp/enroll",
        json={"current_password": "ein-sicheres-passwort"},
    )
    assert response.status_code == 200

    entry = await session.scalar(
        sa_select(MgrAudit).where(MgrAudit.action == "account.totp_enrollment_started").limit(1)
    )
    assert entry is not None
    assert entry.actor_name == "operator"


async def test_login_limiter_key_follows_the_collation(session, client) -> None:
    """ "Admin" und "admin" sind dasselbe Konto; zwei Schluessel liefen auseinander."""
    import pyotp

    from app.api.deps import login_limiter
    from app.core.config import settings as app_settings
    from app.core.crypto import SecretBox, hash_password
    from app.models.mgr import MgrAccount, Role

    secret = pyotp.random_base32()
    session.add(
        MgrAccount(
            username="admin",
            role=Role.ADMINISTRATOR,
            password_hash=hash_password("ein-sicheres-passwort"),
            totp_enabled=True,
            totp_secret_enc=SecretBox(
                app_settings.coa_secret_key or app_settings.secret_key
            ).encrypt(secret),
        )
    )
    await session.commit()

    first = await client.post(
        "/api/v1/auth/login",
        json={"username": "Admin", "password": "ein-sicheres-passwort"},
    )
    assert first.json()["status"] == "totp_required"
    done = await client.post(
        "/api/v1/auth/login/totp",
        json={"challenge": first.json()["challenge"], "totp_code": pyotp.TOTP(secret).now()},
    )
    assert done.status_code == 200, done.text
    assert login_limiter.tracked_keys() == 0


async def test_duplicate_membership_rows_still_protect_the_group(session, admin_principal) -> None:
    """Zwei Zeilen desselben Benutzers galten sonst als zwei Mitglieder."""
    from sqlalchemy import insert

    from app.models.radius import RadUserGroup
    from app.schemas.groups import MembershipChange
    from app.services.groups import GroupService

    users = UserService(session)
    await users.create(UserCreate(username="anna", password="geheim123"), actor=admin_principal)
    # Bewusst am ORM vorbei: die Identity Map fasste zwei Zeilen mit gleichem
    # (username, groupname) zusammen - genau der Zustand, den ``radusergroup``
    # ohne Eindeutigkeit zulaesst, entstuende dabei nicht.
    await session.execute(
        insert(RadUserGroup),
        [
            {"username": "anna", "groupname": "nur-mitglieder", "priority": 1},
            {"username": "anna", "groupname": "nur-mitglieder", "priority": 2},
        ],
    )
    await session.commit()
    assert len(await users.groups.members("nur-mitglieder", limit=10, offset=0)) == 2

    with pytest.raises(ValidationError) as excinfo:
        await GroupService(session).change_membership(
            "nur-mitglieder",
            MembershipChange(action="remove", usernames=["anna"]),
            actor=admin_principal,
        )
    assert excinfo.value.code == "error.group_last_member"


async def test_oversized_body_is_rejected_before_parsing(client) -> None:
    """Starlette laege die Datei sonst vollstaendig ab, bevor der Endpunkt laeuft."""
    from app.api.upload_limit import MAX_BODY_BYTES

    response = await client.post(
        "/api/v1/imports/user",
        content=b"x",
        headers={
            "content-type": "text/csv",
            "content-length": str(MAX_BODY_BYTES + 1),
        },
    )
    assert response.status_code == 413
    assert response.json()["code"] == "error.payload_too_large"


# --- Dreiundzwanzigste Runde ----------------------------------------------


async def test_argon2_runs_off_the_event_loop() -> None:
    """Direkt in der Ereignisschleife blockierte jede Anmeldung den ganzen Prozess."""
    import inspect

    from app.core import crypto
    from app.services import accounts as accounts_module

    assert "asyncio.to_thread" in inspect.getsource(crypto.verify_password_async)
    source = inspect.getsource(accounts_module.AccountService.authenticate)
    assert "await verify_password_async(" in source
    assert "verify_password(" not in source.replace("verify_password_async(", "")


async def test_upload_limit_leaves_room_for_multipart_overhead() -> None:
    """Eine Datei genau in Maximalgroesse ergibt einen groesseren Anfragekoerper."""
    from app.api.upload_limit import MAX_BODY_BYTES, MAX_UPLOAD_BYTES
    from app.api.v1.endpoints.imports import MAX_BYTES

    assert MAX_BYTES == MAX_UPLOAD_BYTES
    assert MAX_BODY_BYTES > MAX_UPLOAD_BYTES


async def test_distinct_members_look_past_duplicate_rows(session, admin_principal) -> None:
    """Viele Dubletten verdeckten sonst ein weiteres Mitglied."""
    from sqlalchemy import insert

    from app.models.radius import RadUserGroup
    from app.schemas.groups import MembershipChange
    from app.services.groups import GroupService

    users = UserService(session)
    for name in ("anna", "zora"):
        await users.create(UserCreate(username=name, password="geheim123"), actor=admin_principal)
    await session.execute(
        insert(RadUserGroup),
        [
            {"username": "anna", "groupname": "nur-mitglieder", "priority": index}
            for index in range(25)
        ]
        + [{"username": "zora", "groupname": "nur-mitglieder", "priority": 1}],
    )
    await session.commit()

    # "zora" steht hinter 25 Dubletten von "anna"; das Entfernen ist zulaessig.
    changed = await GroupService(session).change_membership(
        "nur-mitglieder",
        MembershipChange(action="remove", usernames=["anna"]),
        actor=admin_principal,
    )
    assert changed == 25


async def test_lowercase_reject_is_recognised(session, admin_principal) -> None:
    """Der SQL-Statusfilter erkennt die Zeile; Python meldete den Benutzer als aktiv."""
    users = UserService(session)
    await users.create(UserCreate(username="anna", password="geheim123"), actor=admin_principal)
    await users.attrs.add_check("anna", "Auth-Type", ":=", "reject")
    await session.commit()

    detail = await users.get("anna")
    assert detail.status == "disabled"

    await users.set_disabled("anna", False, actor=admin_principal)
    rows = (
        await session.scalars(
            select(RadCheck).where(RadCheck.username == "anna", RadCheck.attribute == "Auth-Type")
        )
    ).all()
    assert rows == []


async def test_nas_update_and_delete_share_a_lock() -> None:
    """Ein Loeschen dazwischen liesse eine verwaiste mgr_nas_extra-Zeile zurueck."""
    import inspect

    from app.services.nas import NasService

    assert 'named_lock(self.session, f"nas:{nas_id}")' in inspect.getsource(NasService.update)
    assert 'named_lock(self.session, f"nas:{nas_id}")' in inspect.getsource(NasService.delete)


# --- Vierundzwanzigste Runde ----------------------------------------------


async def test_locked_account_row_is_read_fresh() -> None:
    """Aus der Identity Map kaeme der Stand von vor der Sperre."""
    import inspect

    from app.repositories.mgr.accounts import AccountRepository

    for method in (AccountRepository.get_for_update, AccountRepository.get_by_username):
        assert "populate_existing=True" in inspect.getsource(method)


async def test_totp_replay_marker_survives_a_stale_identity_map(session) -> None:
    """Ein zuvor geladenes Objekt darf die Wiedereinsatz-Marke nicht verdecken."""
    import pyotp
    from sqlalchemy import update as sa_update

    from app.core.config import settings as app_settings
    from app.core.crypto import SecretBox, hash_password
    from app.core.errors import AuthenticationError
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

    # Wie ein zweiter, gleichzeitiger Vorgang: die Marke steht in der Datenbank,
    # das geladene Objekt kennt sie noch nicht.
    counter = int(dt.datetime.now(tz=dt.UTC).timestamp() // 30)
    await session.execute(
        sa_update(MgrAccount).where(MgrAccount.id == account.id).values(totp_last_counter=counter)
    )
    await session.commit()

    with pytest.raises(AuthenticationError):
        await AccountService(session).verify_totp_code(account, pyotp.TOTP(secret).now())


# --- Fuenfundzwanzigste Runde ---------------------------------------------


async def test_logout_revokes_the_session_server_side(session, client) -> None:
    """Eine kopierte Kennung blieb sonst bis zur absoluten Gueltigkeit brauchbar."""
    from app.core.config import settings as app_settings
    from app.core.crypto import hash_password
    from app.models.mgr import MgrAccount, Role

    session.add(
        MgrAccount(
            username="operator",
            role=Role.OPERATOR,
            password_hash=hash_password("ein-sicheres-passwort"),
        )
    )
    await session.commit()
    await client.post(
        "/api/v1/auth/login",
        json={"username": "operator", "password": "ein-sicheres-passwort"},
    )
    stolen = client.cookies.get(app_settings.cookie_name)
    assert stolen

    assert (await client.post("/api/v1/auth/logout")).status_code == 204

    # Die kopierte Kennung wird weiterhin abgewiesen.
    client.cookies.set(app_settings.cookie_name, stolen)
    blocked = await client.get("/api/v1/auth/me")
    assert blocked.status_code == 401
    assert blocked.json()["code"] == "error.unauthenticated"


async def test_opaque_origin_is_rejected(session, client) -> None:
    """``Origin: null`` ist eine Angabe, keine fehlende - sonst greift der curl-Zweig."""
    from app.core.crypto import hash_password
    from app.models.mgr import MgrAccount, Role

    session.add(
        MgrAccount(
            username="operator",
            role=Role.OPERATOR,
            password_hash=hash_password("ein-sicheres-passwort"),
        )
    )
    await session.commit()
    await client.post(
        "/api/v1/auth/login",
        json={"username": "operator", "password": "ein-sicheres-passwort"},
    )

    response = await client.post(
        "/api/v1/users",
        json={"username": "anna", "password": "geheim123"},
        headers={"Origin": "null"},
    )
    assert response.status_code == 403
    assert response.json()["code"] == "error.cross_origin"


async def test_self_service_enrollment_requires_the_password(session, client) -> None:
    """Mit einem gestohlenen Cookie liesse sich sonst ein fremder Faktor einrichten."""
    from app.core.crypto import hash_password
    from app.models.mgr import MgrAccount, Role

    session.add(
        MgrAccount(
            username="operator",
            role=Role.OPERATOR,
            password_hash=hash_password("ein-sicheres-passwort"),
        )
    )
    await session.commit()
    await client.post(
        "/api/v1/auth/login",
        json={"username": "operator", "password": "ein-sicheres-passwort"},
    )

    wrong = await client.post("/api/v1/auth/me/totp/enroll", json={"current_password": "falsch"})
    assert wrong.status_code == 401

    ok = await client.post(
        "/api/v1/auth/me/totp/enroll",
        json={"current_password": "ein-sicheres-passwort"},
    )
    assert ok.status_code == 200


async def test_group_reject_shows_in_list_and_filter(session, admin_principal) -> None:
    """Liste, Detailansicht und Filter muessen dieselbe wirksame Policy sehen."""
    from app.repositories.directory import SubjectFilter
    from app.schemas.groups import AttributeIn, GroupCreate
    from app.services.groups import GroupService

    await GroupService(session).create(
        GroupCreate(
            groupname="gesperrt",
            check_attributes=[AttributeIn(attribute="Auth-Type", op=":=", value="Reject")],
        ),
        actor=admin_principal,
    )
    users = UserService(session)
    await users.create(
        UserCreate(
            username="anna",
            password="geheim123",
            groups=[MembershipIn(groupname="gesperrt")],
        ),
        actor=admin_principal,
    )

    assert (await users.get("anna")).status == "disabled"
    items, _ = await users.search(SubjectFilter())
    assert next(i for i in items if i.username == "anna").status == "disabled"
    filtered, _ = await users.search(SubjectFilter(status="disabled"))
    assert [i.username for i in filtered] == ["anna"]


async def test_expiration_parsing_ignores_the_process_locale() -> None:
    """``%b`` liest ``strptime`` in der Locale des Prozesses."""
    import locale

    from app.core.dates import from_expiration

    original = locale.setlocale(locale.LC_TIME)
    try:
        for candidate in ("de_DE.UTF-8", "de_DE", "C"):
            try:
                locale.setlocale(locale.LC_TIME, candidate)
                break
            except locale.Error:
                continue
        assert from_expiration("31 Dec 2026 23:59:00") == dt.datetime(2026, 12, 31, 23, 59)
    finally:
        locale.setlocale(locale.LC_TIME, original)


async def test_import_preserves_whitespace_in_notes(session, admin_principal) -> None:
    """Der Export-Bearbeiten-Import-Weg darf eine Notiz nicht beschneiden."""
    from app.services.importexport import ImportExportService

    await ImportExportService(session).import_csv(
        'username,password,note\nanna,geheim123456,"  mit Rand  "\n',
        kind="user",
        dry_run=False,
        actor=admin_principal,
    )
    subject = await UserService(session).subjects.get("anna")
    assert subject is not None
    assert subject.note == "  mit Rand  "


# --- Sechsundzwanzigste Runde ---------------------------------------------


async def test_scoped_ipv6_is_rejected() -> None:
    """Eine Zone beliebiger Laenge ergaebe je Versuch einen neuen Limiter-Schluessel."""
    from starlette.datastructures import Headers
    from starlette.requests import Request

    from app.api import deps
    from app.core.config import settings as app_settings

    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/",
            "client": ("127.0.0.1", 1234),
            "headers": Headers({"x-forwarded-for": "fe80::1%" + "a" * 100}).raw,
            "query_string": b"",
        }
    )
    original = app_settings.trusted_proxies
    app_settings.trusted_proxies = ["127.0.0.0/8"]
    deps._trusted_networks.cache_clear()
    try:
        assert deps.client_ip(request) == "127.0.0.1"
    finally:
        app_settings.trusted_proxies = original
        deps._trusted_networks.cache_clear()


async def test_oidc_admin_needs_a_provider_mfa_claim(session, client, monkeypatch) -> None:
    """Ein Provider mit reiner Passwortanmeldung umginge sonst die 2FA-Pflicht."""
    from app.api.v1.endpoints import auth as auth_endpoint
    from app.core.config import settings as app_settings
    from app.services.oidc import OidcService

    async def _claims() -> dict[str, object]:
        return {"sub": "idp-admin", "preferred_username": "idp-admin"}

    app_settings.oidc_enabled = True
    monkeypatch.setattr(OidcService, "exchange", lambda self, code, verifier, nonce: _claims())
    monkeypatch.setattr(OidcService, "map_role", lambda self, claims: "administrator")
    try:
        client.cookies.set(auth_endpoint.OIDC_STATE_COOKIE, "state|verifier|nonce")
        response = await client.get(
            "/api/v1/auth/oidc/callback?code=abc&state=state", follow_redirects=False
        )
        assert response.status_code == 401
        assert response.json()["code"] == "error.reauthentication_required"
    finally:
        app_settings.oidc_enabled = False


async def test_provider_mfa_claim_detection() -> None:
    """``amr`` nach RFC 8176, ergaenzend ``acr``."""
    from app.core.config import settings as app_settings
    from app.services.oidc import provider_confirmed_mfa

    assert provider_confirmed_mfa({"amr": ["pwd", "otp"]}) is True
    assert provider_confirmed_mfa({"amr": ["pwd"]}) is False
    assert provider_confirmed_mfa({}) is False

    original = app_settings.oidc_mfa_acr_values
    app_settings.oidc_mfa_acr_values = ["urn:example:2fa"]
    try:
        assert provider_confirmed_mfa({"acr": "urn:example:2fa"}) is True
    finally:
        app_settings.oidc_mfa_acr_values = original


async def test_session_carries_the_verification_time(session, client) -> None:
    """Eine Passwortaenderung waehrend der Anmeldung muss die Sitzung verwerfen."""
    from app.core.crypto import hash_password
    from app.core.dates import utcnow
    from app.models.mgr import MgrAccount, Role

    account = MgrAccount(
        username="operator",
        role=Role.OPERATOR,
        password_hash=hash_password("ein-sicheres-passwort"),
    )
    session.add(account)
    await session.commit()

    login = await client.post(
        "/api/v1/auth/login",
        json={"username": "operator", "password": "ein-sicheres-passwort"},
    )
    assert login.status_code == 200

    # Aenderung *nach* der Ausstellung: die Sitzung ist zu verwerfen.
    account.password_changed_at = utcnow() + dt.timedelta(seconds=1)
    await session.commit()
    blocked = await client.get("/api/v1/auth/me")
    assert blocked.status_code == 401


async def test_self_service_confirmation_is_rate_limited(session, client) -> None:
    """Mit gestohlener Sitzung liess sich ein begonnener Faktor unbegrenzt raten."""
    from app.core.crypto import hash_password
    from app.models.mgr import MgrAccount, Role

    session.add(
        MgrAccount(
            username="operator",
            role=Role.OPERATOR,
            password_hash=hash_password("ein-sicheres-passwort"),
        )
    )
    await session.commit()
    await client.post(
        "/api/v1/auth/login",
        json={"username": "operator", "password": "ein-sicheres-passwort"},
    )
    await client.post(
        "/api/v1/auth/me/totp/enroll",
        json={"current_password": "ein-sicheres-passwort"},
    )

    from app.core.config import settings as app_settings

    codes = set()
    for _ in range(app_settings.login_rate_limit + 1):
        response = await client.post("/api/v1/auth/me/totp/confirm", json={"code": "000000"})
        codes.add(response.json().get("code"))
        if response.status_code == 429:
            break
    # Entweder das Kontingent oder die Kontosperre greift - unbegrenztes Raten
    # ist in keinem Fall moeglich.
    assert "error.rate_limited" in codes or "error.account_locked" in codes


async def test_oidc_only_account_cannot_be_unlinked(session) -> None:
    """Ohne lokales Passwort waere die Verknuepfung der einzige Zugang."""
    from app.models.mgr import MgrAccount, Role
    from app.services.accounts import AccountService

    account = MgrAccount(
        username="idp-user",
        role=Role.OPERATOR,
        oidc_subject="subject-1",
        password_hash=None,
    )
    session.add(account)
    await session.commit()

    principal = Principal(
        account_id=account.id,
        username="admin",
        role=Role.ADMINISTRATOR,
        language="de",
        session_id="test",
        absolute_expiry=0,
    )
    with pytest.raises(ValidationError) as excinfo:
        await AccountService(session).set_oidc_subject(account.id, None, actor=principal)
    assert excinfo.value.code == "error.oidc_unlink_without_password"


async def test_group_can_be_renamed_by_case_only(session, admin_principal) -> None:
    """Sonst liesse sich die Schreibweise nur ueber Loeschen und Neuanlegen aendern."""
    from app.schemas.groups import GroupCreate, GroupUpdate
    from app.services.groups import GroupService

    groups = GroupService(session)
    await groups.create(GroupCreate(groupname="Staff", vlan="10"), actor=admin_principal)
    detail = await groups.update("Staff", GroupUpdate(groupname="staff"), actor=admin_principal)
    assert detail.groupname == "staff"
