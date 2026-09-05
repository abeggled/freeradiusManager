"""Erkennung nicht-UTC-Zeitstempel (FR-5, FR-6).

Der Manager schreibt eigene Zeitstempel in UTC, FreeRADIUS schreibt Ortszeit -
``radpostauth.authdate`` ueber ``%S`` in der Zone des RADIUS-Prozesses, die
Zeiten in ``radacct`` ueber ``FROM_UNIXTIME`` in der Zone der Datenbanksitzung.
Weicht eine davon ab, sind Auth-Log und Sessions um den Versatz verschoben,
ohne dass etwas fehlschlaegt.
"""

from __future__ import annotations

import datetime as dt

import pytest
from sqlalchemy import text

from app.repositories.radius.timecheck import TOLERANCE_SECONDS, TimeReport, inspect_time

pytestmark = pytest.mark.asyncio


async def test_utc_session_is_accepted(engine) -> None:
    async with engine.connect() as connection:
        await connection.execute(text("SET time_zone = '+00:00'"))
        report = await inspect_time(connection)

    assert report.db_offset_seconds == 0
    assert report.database_is_utc
    assert report.ok


async def test_shifted_session_is_reported(engine) -> None:
    """Der Fall aus dem Betrieb: Datenbank auf Europe/Zurich im Sommer."""
    async with engine.connect() as connection:
        await connection.execute(text("SET time_zone = '+02:00'"))
        report = await inspect_time(connection)

    assert report.db_offset_seconds == 7200
    assert not report.database_is_utc
    assert not report.ok
    assert report.as_details()["db_offset_seconds"] == 7200


async def test_authdate_in_the_future_is_reported(engine) -> None:
    """Eine Anmeldung kann nicht in der Zukunft stattgefunden haben."""
    future = dt.datetime.now(tz=dt.UTC).replace(tzinfo=None) + dt.timedelta(hours=2)
    async with engine.begin() as connection:
        await connection.execute(text("SET time_zone = '+00:00'"))
        await connection.execute(
            text(
                "INSERT INTO radpostauth (username, pass, reply, authdate) "
                "VALUES ('zeitreisender', '', 'Access-Accept', :ts)"
            ),
            {"ts": future},
        )
        report = await inspect_time(connection)

    assert report.authdate_ahead_seconds is not None
    assert report.authdate_ahead_seconds > TOLERANCE_SECONDS
    assert report.authdate_in_future
    assert not report.ok


async def test_recent_authdate_is_accepted(engine) -> None:
    past = dt.datetime.now(tz=dt.UTC).replace(tzinfo=None) - dt.timedelta(minutes=5)
    async with engine.begin() as connection:
        await connection.execute(text("SET time_zone = '+00:00'"))
        await connection.execute(
            text(
                "INSERT INTO radpostauth (username, pass, reply, authdate) "
                "VALUES ('anna', '', 'Access-Accept', :ts)"
            ),
            {"ts": past},
        )
        report = await inspect_time(connection)

    assert not report.authdate_in_future
    assert report.ok


async def test_empty_table_yields_no_verdict(engine) -> None:
    """Ohne Zeile laesst sich ueber die Zone von FreeRADIUS nichts sagen."""
    async with engine.connect() as connection:
        await connection.execute(text("SET time_zone = '+00:00'"))
        report = await inspect_time(connection)

    assert report.authdate_ahead_seconds is None
    assert not report.authdate_in_future


async def test_missing_offset_is_not_silently_accepted() -> None:
    """Ohne ermittelten Versatz gilt die Datenbank nicht als geprueft."""
    report = TimeReport()
    assert not report.database_is_utc
    assert not report.ok
