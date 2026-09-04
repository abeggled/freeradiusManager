"""Schemas fuer NAS-Clients (FR-4) und CoA (FR-7)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

MASKED_SECRET = "********"


class NasListItem(BaseModel):
    id: int
    nasname: str
    shortname: str | None = None
    type: str | None = None
    ports: int | None = None
    server: str | None = None
    description: str | None = None
    secret: str | None = None
    coa_enabled: bool = False
    coa_port: int = 3799
    has_coa_secret: bool = False
    note: str | None = None


class NasCreate(BaseModel):
    nasname: str = Field(min_length=1, max_length=128)
    shortname: str | None = Field(default=None, max_length=32)
    type: str = Field(default="other", max_length=30)
    ports: int | None = None
    secret: str = Field(min_length=1, max_length=60)
    server: str | None = Field(default=None, max_length=64)
    community: str | None = Field(default=None, max_length=50)
    description: str | None = Field(default=None, max_length=200)
    coa_enabled: bool = False
    coa_port: int = Field(default=3799, ge=1, le=65535)
    coa_secret: str | None = Field(default=None, max_length=253)
    note: str | None = Field(default=None, max_length=4000)


class NasUpdate(BaseModel):
    nasname: str | None = Field(default=None, max_length=128)
    shortname: str | None = Field(default=None, max_length=32)
    type: str | None = Field(default=None, max_length=30)
    ports: int | None = None
    secret: str | None = Field(default=None, max_length=60)
    server: str | None = Field(default=None, max_length=64)
    community: str | None = Field(default=None, max_length=50)
    description: str | None = Field(default=None, max_length=200)
    coa_enabled: bool | None = None
    coa_port: int | None = Field(default=None, ge=1, le=65535)
    coa_secret: str | None = Field(default=None, max_length=253)
    clear_coa_secret: bool = False
    note: str | None = Field(default=None, max_length=4000)


class SecretReveal(BaseModel):
    """Anzeige des Shared Secret – nur fuer Administratoren, mit Audit-Eintrag."""

    nasname: str
    secret: str


class CoARequest(BaseModel):
    action: Literal["disconnect", "coa"] = "disconnect"
    acctuniqueid: str | None = None
    radacctid: int | None = None
    username: str | None = None
    vlan: str | None = None
    """Nur fuer ``action = coa``: neue VLAN-Zuweisung."""


class CoAResponse(BaseModel):
    ok: bool
    action: str
    nas: str
    code: str | None = None
    message: str
    attributes: dict[str, str] = Field(default_factory=dict)
