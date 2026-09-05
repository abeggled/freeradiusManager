"""Bezeichnung eines Subjekts in Sessions, Auth-Log und Diagnose (FR-3, FR-5, FR-6).

``radacct`` und ``radpostauth`` kennen nur den Benutzernamen - bei MAB-Geraeten
also die MAC-Adresse. Ohne die Bezeichnung aus ``mgr_subject`` liesse sich in
diesen Ansichten nicht erkennen, um welches Geraet es geht.
"""

from __future__ import annotations

import datetime as dt

import pytest
from sqlalchemy import text

from app.repositories.mgr.subjects import SubjectRepository
from app.repositories.radius.acct import SessionFilter
from app.repositories.radius.postauth import AuthLogFilter
from app.schemas.users import DeviceCreate, SubjectMeta
from app.services.authlog import AuthLogService
from app.services.devices import DeviceService
from app.services.sessions import SessionService

pytestmark = pytest.mark.asyncio

MAC = "aa:bb:cc:dd:ee:10"
LABEL = "Drucker 2. OG Nord"


async def _device(session, actor) -> None:
    await DeviceService(session).create(
        DeviceCreate(
            mac=MAC,
            use_mac_as_password=True,
            meta=SubjectMeta(display_name=LABEL),
        ),
        actor=actor,
    )


async def _session_row(session, username: str = MAC) -> None:
    await session.execute(
        text(
            "INSERT INTO radacct (acctsessionid, acctuniqueid, username, nasipaddress, "
            "callingstationid, calledstationid, acctstarttime) "
            "VALUES ('s1', 'u1', :name, '10.0.10.5', 'aa-bb-cc-dd-ee-10', 'ap', :ts)"
        ),
        {"name": username, "ts": dt.datetime.now(tz=dt.UTC).replace(tzinfo=None)},
    )


async def _authlog_row(session, username: str = MAC) -> None:
    await session.execute(
        text(
            "INSERT INTO radpostauth (username, pass, reply, authdate) "
            "VALUES (:name, '', 'Access-Accept', :ts)"
        ),
        {"name": username, "ts": dt.datetime.now(tz=dt.UTC).replace(tzinfo=None)},
    )


async def test_session_carries_the_label(session, admin_principal) -> None:
    await _device(session, admin_principal)
    await _session_row(session)

    items, _, _ = await SessionService(session).search(SessionFilter())

    assert [i.subject_name for i in items] == [LABEL]


async def test_session_without_label_stays_empty(session, admin_principal) -> None:
    await DeviceService(session).create(
        DeviceCreate(mac="aa:bb:cc:dd:ee:11", use_mac_as_password=True), actor=admin_principal
    )
    await _session_row(session, "aa:bb:cc:dd:ee:11")

    items, _, _ = await SessionService(session).search(SessionFilter())

    assert [i.subject_name for i in items] == [None]


async def test_label_is_found_despite_a_different_spelling(session, admin_principal) -> None:
    """Das NAS meldet die MAC in eigener Schreibweise.

    ``radacct`` fuehrt sie so, wie sie gesendet wurde; die Kollation der
    Datenbank vergleicht ohne Ruecksicht darauf. Ein reiner
    Zeichenkettenvergleich in Python liesse die Bezeichnung hier verschwinden.
    """
    await _device(session, admin_principal)
    await _session_row(session, MAC.upper())

    items, _, _ = await SessionService(session).search(SessionFilter())

    assert [i.subject_name for i in items] == [LABEL]


async def test_auth_log_carries_the_label(session, admin_principal) -> None:
    await _device(session, admin_principal)
    await _authlog_row(session)

    items, _ = await AuthLogService(session).search(AuthLogFilter())

    assert [i.subject_name for i in items] == [LABEL]


async def test_diagnosis_carries_the_label(session, admin_principal) -> None:
    await _device(session, admin_principal)
    await _authlog_row(session)

    diagnosis = await AuthLogService(session).diagnose(MAC)

    assert diagnosis.subject_name == LABEL


async def test_lookup_returns_folded_keys(session, admin_principal) -> None:
    await _device(session, admin_principal)

    names = await SubjectRepository(session).display_names_for([MAC.upper()])

    assert names == {MAC: LABEL}


async def test_lookup_without_names_is_empty(session) -> None:
    """Kein Datensatz, keine Abfrage - und kein leerer IN-Ausdruck."""
    assert await SubjectRepository(session).display_names_for([]) == {}
