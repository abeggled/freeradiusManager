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
