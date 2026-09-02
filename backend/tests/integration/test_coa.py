"""CoA/Disconnect (FR-7). Der Netzwerkversand wird ersetzt, geprueft wird die
Fachlogik: Zielaufloesung, Attribute, Fehlerbehandlung und Audit."""

from __future__ import annotations

import datetime as dt
from typing import Any

import pytest
from sqlalchemy import select

from app.core.errors import CoAError, NotFoundError
from app.models.mgr import AuditResult, MgrAudit
from app.models.radius import RadAcct
from app.schemas.nas import CoARequest, NasCreate
from app.services import coa as coa_module
from app.services.coa import CoAService
from app.services.nas import NasService

pytestmark = pytest.mark.asyncio

DISCONNECT_ACK = 41
DISCONNECT_NAK = 42
COA_ACK = 44


async def _prepare(session, admin_principal, *, coa: bool = True) -> RadAcct:
    await NasService(session).create(
        NasCreate(
            nasname="10.0.0.1",
            secret="s",
            coa_enabled=coa,
            coa_port=3799,
            coa_secret="coa-geheim" if coa else None,
        ),
        actor=admin_principal,
    )
    row = RadAcct(
        acctsessionid="sess-1",
        acctuniqueid="uniq-1",
        username="anna",
        nasipaddress="10.0.0.1",
        acctstarttime=dt.datetime(2026, 9, 1, 8, 0),
        callingstationid="AA-BB-CC-DD-EE-FF",
        calledstationid="00-11-22-33-44-55:WLAN",
        framedipaddress="192.168.10.5",
    )
    session.add(row)
    await session.commit()
    return row


async def test_disconnect_sends_expected_attributes(session, admin_principal, monkeypatch) -> None:
    await _prepare(session, admin_principal)
    captured: dict[str, Any] = {}

    def fake_send(host, port, secret, attributes, disconnect):
        captured.update(
            host=host, port=port, secret=secret, attributes=attributes, disconnect=disconnect
        )
        return DISCONNECT_ACK, {}

    monkeypatch.setattr(coa_module, "_send_blocking", fake_send)

    result = await CoAService(session).execute(
        CoARequest(action="disconnect", acctuniqueid="uniq-1"), actor=admin_principal
    )
    assert result.ok is True
    assert captured["host"] == "10.0.0.1"
    assert captured["port"] == 3799
    assert captured["secret"] == "coa-geheim"
    assert captured["disconnect"] is True
    assert captured["attributes"]["User-Name"] == "anna"
    assert captured["attributes"]["Acct-Session-Id"] == "sess-1"


async def test_coa_sets_vlan_attributes(session, admin_principal, monkeypatch) -> None:
    await _prepare(session, admin_principal)
    captured: dict[str, Any] = {}

    def fake_send(host, port, secret, attributes, disconnect):
        captured.update(attributes=attributes, disconnect=disconnect)
        return COA_ACK, {}

    monkeypatch.setattr(coa_module, "_send_blocking", fake_send)
    result = await CoAService(session).execute(
        CoARequest(action="coa", acctuniqueid="uniq-1", vlan="42"), actor=admin_principal
    )
    assert result.ok is True
    assert captured["disconnect"] is False
    assert captured["attributes"]["Tunnel-Type"] == (0, 13)
    assert captured["attributes"]["Tunnel-Medium-Type"] == (0, 6)
    assert captured["attributes"]["Tunnel-Private-Group-Id"] == (0, "42")


async def test_nak_is_reported_and_audited(session, admin_principal, monkeypatch) -> None:
    await _prepare(session, admin_principal)
    monkeypatch.setattr(
        coa_module, "_send_blocking", lambda *a, **k: (DISCONNECT_NAK, {"Error-Cause": "503"})
    )
    with pytest.raises(CoAError) as excinfo:
        await CoAService(session).execute(CoARequest(acctuniqueid="uniq-1"), actor=admin_principal)
    assert excinfo.value.code == "error.coa_nak"

    entry = (
        await session.scalars(select(MgrAudit).where(MgrAudit.action == "coa.disconnect"))
    ).one()
    assert entry.result is AuditResult.FAILURE


async def test_timeout_is_translated_to_error_code(session, admin_principal, monkeypatch) -> None:
    await _prepare(session, admin_principal)

    def raise_timeout(*args, **kwargs):
        raise TimeoutError("timed out")

    monkeypatch.setattr(coa_module, "_send_blocking", raise_timeout)
    with pytest.raises(CoAError) as excinfo:
        await CoAService(session).execute(CoARequest(acctuniqueid="uniq-1"), actor=admin_principal)
    assert excinfo.value.code == "error.coa_timeout"


async def test_missing_coa_configuration_is_rejected(session, admin_principal) -> None:
    await _prepare(session, admin_principal, coa=False)
    with pytest.raises(CoAError) as excinfo:
        await CoAService(session).execute(CoARequest(acctuniqueid="uniq-1"), actor=admin_principal)
    assert excinfo.value.code == "error.coa_not_configured"


async def test_closed_session_cannot_be_disconnected(session, admin_principal) -> None:
    row = await _prepare(session, admin_principal)
    row.acctstoptime = dt.datetime(2026, 9, 1, 9, 0)
    await session.commit()
    with pytest.raises(NotFoundError):
        await CoAService(session).execute(CoARequest(acctuniqueid="uniq-1"), actor=admin_principal)
