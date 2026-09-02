"""NAS (FR-4), Sessions (FR-5), Auth-Log/Diagnose (FR-6), Audit (FR-9)."""

from __future__ import annotations

import datetime as dt

import pytest
from sqlalchemy import select

from app.core.errors import PermissionDeniedError
from app.models.mgr import MgrAudit
from app.models.radius import RadAcct, RadPostAuth
from app.repositories.radius.acct import SessionFilter
from app.repositories.radius.postauth import AuthLogFilter
from app.schemas.nas import MASKED_SECRET, NasCreate, NasUpdate
from app.schemas.users import UserCreate
from app.services.authlog import AuthLogService
from app.services.nas import NasService
from app.services.sessions import SessionService
from app.services.users import UserService

pytestmark = pytest.mark.asyncio


async def _session_row(session, **kwargs):
    defaults = {
        "acctsessionid": "sess-1",
        "acctuniqueid": "uniq-1",
        "username": "anna",
        "nasipaddress": "10.0.0.1",
        "acctstarttime": dt.datetime(2026, 9, 1, 8, 0),
        "callingstationid": "AA-BB-CC-DD-EE-FF",
        "calledstationid": "00-11-22-33-44-55:Firmen-WLAN",
        "framedipaddress": "192.168.10.5",
        "acctinputoctets": 1000,
        "acctoutputoctets": 2000,
    }
    defaults.update(kwargs)
    row = RadAcct(**defaults)
    session.add(row)
    await session.commit()
    return row


async def test_nas_secret_is_masked_and_reveal_is_audited(session, admin_principal) -> None:
    service = NasService(session)
    item, warnings = await service.create(
        NasCreate(nasname="10.0.0.1", shortname="sw01", secret="topsecret"),
        actor=admin_principal,
    )
    assert item.secret == MASKED_SECRET
    assert [w.code for w in warnings] == ["warn.nas_reload"]

    revealed = await service.reveal_secret(item.id, actor=admin_principal)
    assert revealed.secret == "topsecret"

    entries = (
        await session.scalars(select(MgrAudit).where(MgrAudit.action == "nas.reveal_secret"))
    ).all()
    assert len(entries) == 1
    assert entries[0].actor_name == "admin"


async def test_operator_cannot_reveal_secret(session, admin_principal, operator_principal) -> None:
    service = NasService(session)
    item, _ = await service.create(
        NasCreate(nasname="10.0.0.2", secret="topsecret"), actor=admin_principal
    )
    with pytest.raises(PermissionDeniedError):
        await service.reveal_secret(item.id, actor=operator_principal)


async def test_coa_secret_is_encrypted_at_rest(session, admin_principal) -> None:
    service = NasService(session)
    await service.create(
        NasCreate(
            nasname="10.0.0.3",
            secret="s",
            coa_enabled=True,
            coa_port=3799,
            coa_secret="coa-geheim",
        ),
        actor=admin_principal,
    )
    extra = await service.extra.get("10.0.0.3")
    assert extra.coa_secret_enc.startswith("gcm1:")
    assert "coa-geheim" not in extra.coa_secret_enc
    assert await service.coa_target("10.0.0.3") == ("10.0.0.3", 3799, "coa-geheim")


async def test_coa_target_none_without_configuration(session, admin_principal) -> None:
    service = NasService(session)
    await service.create(NasCreate(nasname="10.0.0.4", secret="s"), actor=admin_principal)
    assert await service.coa_target("10.0.0.4") is None


async def test_nas_update_can_clear_coa_secret(session, admin_principal) -> None:
    service = NasService(session)
    item, _ = await service.create(
        NasCreate(nasname="10.0.0.5", secret="s", coa_enabled=True, coa_secret="x"),
        actor=admin_principal,
    )
    await service.update(item.id, NasUpdate(clear_coa_secret=True), actor=admin_principal)
    assert await service.coa_target("10.0.0.5") is None


async def test_session_list_filters_and_decorates(session, admin_principal) -> None:
    await NasService(session).create(
        NasCreate(nasname="10.0.0.1", shortname="sw01", secret="s"), actor=admin_principal
    )
    await _session_row(session)
    await _session_row(
        session,
        acctsessionid="sess-2",
        acctuniqueid="uniq-2",
        username="bruno",
        callingstationid="11-22-33-44-55-66",
        acctstoptime=dt.datetime(2026, 9, 1, 9, 0),
        acctterminatecause="User-Request",
    )

    items, cursor, approx = await SessionService(session).search(SessionFilter(active_only=True))
    assert [i.username for i in items] == ["anna"]
    assert items[0].active is True
    assert items[0].ssid == "Firmen-WLAN"
    assert items[0].nas_shortname == "sw01"
    assert approx == 1
    assert cursor is None

    items, _, _ = await SessionService(session).search(
        SessionFilter(calling_station_id="AA-BB-CC-DD-EE-FF")
    )
    assert len(items) == 1


async def test_session_keyset_pagination(session) -> None:
    for index in range(5):
        await _session_row(
            session, acctsessionid=f"s{index}", acctuniqueid=f"u{index}", username=f"user{index}"
        )
    service = SessionService(session)
    first, cursor, _ = await service.search(SessionFilter(), limit=2)
    assert len(first) == 2 and cursor
    second, cursor2, _ = await service.search(SessionFilter(), limit=2, cursor=cursor)
    assert len(second) == 2
    assert {i.radacctid for i in first} & {i.radacctid for i in second} == set()
    assert cursor2


async def test_diagnose_unknown_user(session) -> None:
    result = await AuthLogService(session).diagnose("gibtsnicht")
    codes = {h.code for h in result.hints}
    assert result.exists is False
    assert "diag.user_unknown" in codes


async def test_diagnose_reports_reject_and_missing_nas(session, admin_principal) -> None:
    await UserService(session).create(
        UserCreate(username="anna", password="geheim123", disabled=True), actor=admin_principal
    )
    await _session_row(session, nasipaddress="10.9.9.9")
    session.add(
        RadPostAuth(
            username="anna",
            pass_="",
            reply="Access-Reject",
            authdate=dt.datetime(2026, 9, 1, 8, 5),
        )
    )
    await session.commit()

    result = await AuthLogService(session).diagnose("anna")
    codes = {h.code for h in result.hints}
    assert result.status == "disabled"
    assert "diag.auth_type_reject" in codes
    assert "diag.nas_unknown" in codes
    assert "diag.recent_rejects" in codes
    assert len(result.attempts) == 1


async def test_diagnose_uses_group_vlan(session, admin_principal) -> None:
    from app.schemas.groups import GroupCreate
    from app.schemas.users import MembershipIn
    from app.services.groups import GroupService

    await GroupService(session).create(
        GroupCreate(groupname="mitarbeiter", vlan="20"), actor=admin_principal
    )
    await UserService(session).create(
        UserCreate(
            username="anna",
            password="geheim123",
            groups=[MembershipIn(groupname="mitarbeiter")],
        ),
        actor=admin_principal,
    )
    result = await AuthLogService(session).diagnose("anna")
    assert result.vlan == "20"
    assert "diag.no_vlan" not in {h.code for h in result.hints}


async def test_diagnose_is_translated(session, admin_principal) -> None:
    await UserService(session).create(
        UserCreate(username="anna", password="geheim123"), actor=admin_principal
    )
    german = await AuthLogService(session).diagnose("anna", language="de")
    english = await AuthLogService(session).diagnose("anna", language="en")
    de_text = next(h.message for h in german.hints if h.code == "diag.no_attempts")
    en_text = next(h.message for h in english.hints if h.code == "diag.no_attempts")
    assert de_text != en_text
    assert "anna" in de_text and "anna" in en_text


async def test_authlog_filter_only_rejects(session) -> None:
    session.add_all(
        [
            RadPostAuth(
                username="anna", pass_="", reply="Access-Accept", authdate=dt.datetime.now()
            ),
            RadPostAuth(
                username="anna", pass_="", reply="Access-Reject", authdate=dt.datetime.now()
            ),
        ]
    )
    await session.commit()
    items, _ = await AuthLogService(session).search(AuthLogFilter(only_rejects=True))
    assert [i.reply for i in items] == ["Access-Reject"]
    assert items[0].accepted is False
