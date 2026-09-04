"""Schemas fuer Sessions (FR-5) und Auth-Log/Diagnose (FR-6)."""

from __future__ import annotations

import datetime as dt

from pydantic import BaseModel, ConfigDict, Field, field_validator


class SessionItem(BaseModel):
    """Eine Accounting-Zeile.

    ``radacctid`` ist ein BIGINT und wird als Zeichenkette ausgeliefert:
    JavaScript verlaert oberhalb von 2^53 an Genauigkeit und der Client wuerde
    eine benachbarte Session ansprechen.
    """

    model_config = ConfigDict(from_attributes=True)

    radacctid: str
    acctsessionid: str
    acctuniqueid: str
    username: str
    nasipaddress: str
    nasportid: str | None = None
    nasporttype: str | None = None
    callingstationid: str
    calledstationid: str
    framedipaddress: str | None = None
    acctstarttime: dt.datetime | None = None
    acctupdatetime: dt.datetime | None = None
    acctstoptime: dt.datetime | None = None
    acctsessiontime: int | None = None
    # BIGINT wie ``radacctid``: eine lange Sitzung mit hohem Durchsatz
    # ueberschreitet 2^53, und JavaScript rundete den Wert stillschweigend -
    # das angezeigte Volumen waere falsch.
    acctinputoctets: str | None = None
    acctoutputoctets: str | None = None
    acctterminatecause: str | None = None
    active: bool = False
    ssid: str | None = None
    nas_shortname: str | None = None

    @field_validator("radacctid", mode="before")
    @classmethod
    def _as_text(cls, value: object) -> str:
        return str(value)

    @field_validator("acctinputoctets", "acctoutputoctets", mode="before")
    @classmethod
    def _octets_as_text(cls, value: object) -> str | None:
        return None if value is None else str(value)


class AuthLogItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    """Ebenfalls BIGINT - siehe ``SessionItem.radacctid``."""

    username: str
    reply: str
    authdate: dt.datetime
    accepted: bool = False

    @field_validator("id", mode="before")
    @classmethod
    def _as_text(cls, value: object) -> str:
        return str(value)


class DiagnosisHint(BaseModel):
    code: str
    message: str
    severity: str = "info"


class Diagnosis(BaseModel):
    subject: str
    exists: bool
    status: str
    hints: list[DiagnosisHint] = Field(default_factory=list)
    attempts: list[AuthLogItem] = Field(default_factory=list)
    last_session: SessionItem | None = None
    groups: list[str] = Field(default_factory=list)
    vlan: str | None = None


class StatsResponse(BaseModel):
    computed_at: dt.datetime | None = None
    stale: bool = False
    active_sessions: int = 0
    sessions_started: int = 0
    input_octets: str = "0"
    output_octets: str = "0"
    """Ebenfalls als Zeichenkette - siehe ``SessionItem.acctinputoctets``.

    Die Summe eines Tages sprengt bei hohem Durchsatz ebenso 2^53."""
    accepts: int = 0
    rejects: int = 0
    top_users: list[dict[str, object]] = Field(default_factory=list)
    top_nas: list[dict[str, object]] = Field(default_factory=list)
    top_rejected: list[dict[str, object]] = Field(default_factory=list)
    users_total: int = 0
    devices_total: int = 0
    groups_total: int = 0
    nas_total: int = 0

    @field_validator("input_octets", "output_octets", mode="before")
    @classmethod
    def _octets_as_text(cls, value: object) -> str:
        return str(value if value is not None else 0)
