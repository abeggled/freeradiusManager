"""Schemas fuer NAS-Clients (FR-4) und CoA (FR-7)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator

MASKED_SECRET = "********"

MAX_COA_SECRET_BYTES = 200
"""Obergrenze in UTF-8-Bytes.

Nach AES-GCM und Base64 muss der Wert in die 512 Zeichen von
``mgr_nas_extra.coa_secret_enc`` passen; mehrbytige Zeichen sprengen eine reine
Zeichengrenze."""


def _check_secret(value: str | None) -> str | None:
    if value is not None and len(value.encode("utf-8")) > MAX_COA_SECRET_BYTES:
        raise ValueError(f"coa_secret darf hoechstens {MAX_COA_SECRET_BYTES} Bytes umfassen")
    return value


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

    @field_validator("coa_secret")
    @classmethod
    def _bytes(cls, value: str | None) -> str | None:
        return _check_secret(value)


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

    @field_validator("coa_secret")
    @classmethod
    def _bytes(cls, value: str | None) -> str | None:
        return _check_secret(value)


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
