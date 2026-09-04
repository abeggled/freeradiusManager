"""Schemas fuer Manager-Konten, Anmeldung und Audit (FR-9, FR-10)."""

from __future__ import annotations

import datetime as dt
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.constants import MAX_ACCOUNT_USERNAME_LENGTH, MIN_PASSWORD_LENGTH
from app.models.mgr import Role


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=MAX_ACCOUNT_USERNAME_LENGTH)
    password: str = Field(min_length=1, max_length=256)
    totp_code: str | None = Field(default=None, max_length=10)


class TotpLoginRequest(BaseModel):
    challenge: str
    totp_code: str = Field(min_length=6, max_length=10)


class TotpEnrollRequest(BaseModel):
    """Die Challenge ist ein kurzlebiges Zugangsmerkmal.

    Sie gehoert deshalb in den Rumpf: eine URL landet regelmaessig in
    Zugriffsprotokollen von Reverse-Proxys und liesse sich dort mitlesen.
    """

    challenge: str


class LoginResponse(BaseModel):
    status: str = "authenticated"
    challenge: str | None = None
    account: AccountOut | None = None


class AccountOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: str | None = None
    display_name: str | None = None
    role: Role
    is_active: bool
    totp_enabled: bool
    language: str
    last_login_at: dt.datetime | None = None
    created_at: dt.datetime | None = None
    oidc_subject: str | None = None


class AccountCreate(BaseModel):
    """Laengen entsprechen den Spalten in ``mgr_account``."""

    username: str = Field(min_length=1, max_length=MAX_ACCOUNT_USERNAME_LENGTH)
    password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=256)
    role: Role = Role.AUDITOR
    email: str | None = Field(default=None, max_length=255)
    display_name: str | None = Field(default=None, max_length=128)
    language: Literal["de", "en"] = "de"


class AccountUpdate(BaseModel):
    email: str | None = Field(default=None, max_length=255)
    display_name: str | None = Field(default=None, max_length=128)
    role: Role | None = None
    is_active: bool | None = None
    language: Literal["de", "en"] | None = None
    reset_totp: bool = False


class OidcLink(BaseModel):
    """Verknuepft ein bestehendes lokales Konto mit einer OIDC-Identitaet.

    Die Verknuepfung erfolgt bewusst durch einen Administrator: eine
    automatische Bindung ueber den Benutzernamen liesse sich vom Provider aus
    missbrauchen (siehe ``error.oidc_account_conflict``).
    """

    oidc_subject: str | None = Field(default=None, max_length=255)
    """``None`` loest eine bestehende Verknuepfung."""

    @field_validator("oidc_subject")
    @classmethod
    def _check(cls, value: str | None) -> str | None:
        """Dieselbe Pruefung wie im Callback.

        Ein Wert mit Leerraum liesse sich verknuepfen, koennte sich aber nie
        anmelden - die API meldete einen Erfolg ohne Wirkung.
        """
        if value is None:
            return None
        if not value or value != value.strip():
            raise ValueError("oidc_subject darf keinen fuehrenden oder anhaengenden Leerraum haben")
        return value


class PasswordChange(BaseModel):
    current_password: str
    new_password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=256)


class TotpSetupResponse(BaseModel):
    secret: str
    provisioning_uri: str


class TotpActivate(BaseModel):
    code: str = Field(min_length=6, max_length=10)


class AuditItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ts: dt.datetime
    actor_name: str
    actor_ip: str | None = None
    action: str
    object_type: str
    object_id: str | None = None
    result: str
    message: str | None = None
    before: dict[str, Any] | list[Any] | None = None
    after: dict[str, Any] | list[Any] | None = None


LoginResponse.model_rebuild()
