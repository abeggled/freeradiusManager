"""Regressionstests zur neunten Review-Runde."""

from __future__ import annotations

import datetime as dt

import pytest
from pydantic import ValidationError as PydanticValidationError
from sqlalchemy import select

from app.core.errors import ValidationError
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
