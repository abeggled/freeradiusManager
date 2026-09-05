"""Pruefung, ob Zeitstempel in UTC entstehen (FR-5, FR-6).

Der Manager schreibt seine eigenen Zeitstempel ausdruecklich in UTC und liefert
alle Zeitangaben ohne Zonenangabe aus; die Oberflaeche liest sie als UTC. Die
Spalten von FreeRADIUS entstehen dagegen an anderer Stelle:

* ``radpostauth.authdate`` formatiert FreeRADIUS selbst (``%S`` in
  ``queries.conf``) - in der Ortszeit des RADIUS-Prozesses.
* Die Zeiten in ``radacct`` entstehen ueber ``FROM_UNIXTIME(...)`` - in der
  Ortszeit der Datenbanksitzung.

Steht eine davon nicht auf UTC, sind Auth-Log und Sessions um den Zonenversatz
verschoben, ohne dass irgendetwas fehlschlaegt. Genau das soll hier auffallen.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

TOLERANCE_SECONDS = 60
"""Unterhalb dieser Grenze gilt der Versatz als Gangungenauigkeit, nicht als Zone."""


@dataclass(frozen=True)
class TimeReport:
    db_offset_seconds: int | None = None
    """Versatz der Datenbanksitzung gegenueber UTC. ``None``: nicht ermittelbar."""

    authdate_ahead_seconds: int | None = None
    """Wie weit der juengste ``authdate`` in der Zukunft liegt. ``None``: keine Zeile."""

    @property
    def database_is_utc(self) -> bool:
        return self.db_offset_seconds is not None and abs(self.db_offset_seconds) <= (
            TOLERANCE_SECONDS
        )

    @property
    def authdate_in_future(self) -> bool:
        """Ein Anmeldeversuch in der Zukunft ist immer falsch.

        Die Pruefung schlaegt nur nach Osten aus: schreibt FreeRADIUS westlich
        von UTC, sehen seine Zeitstempel wie aeltere aus und lassen sich nicht
        von tatsaechlich aelteren unterscheiden.
        """
        return self.authdate_ahead_seconds is not None and (
            self.authdate_ahead_seconds > TOLERANCE_SECONDS
        )

    @property
    def ok(self) -> bool:
        return self.database_is_utc and not self.authdate_in_future

    def as_details(self) -> dict[str, object]:
        return {
            "db_offset_seconds": self.db_offset_seconds,
            "authdate_ahead_seconds": self.authdate_ahead_seconds,
        }


async def inspect_time(connection: AsyncConnection) -> TimeReport:
    offset = await connection.scalar(text("SELECT TIMESTAMPDIFF(SECOND, UTC_TIMESTAMP(), NOW())"))
    # Beide Werte stammen aus derselben Abfrage: der Gang der Anwendungsuhr
    # geht hier nicht ein, gemessen wird allein die Zone der Sitzung.
    newest = await connection.scalar(text("SELECT MAX(authdate) FROM radpostauth"))
    ahead: int | None = None
    if isinstance(newest, dt.datetime):
        now = dt.datetime.now(tz=dt.UTC).replace(tzinfo=None)
        ahead = int((newest - now).total_seconds())
    return TimeReport(
        db_offset_seconds=None if offset is None else int(offset),
        authdate_ahead_seconds=ahead,
    )
