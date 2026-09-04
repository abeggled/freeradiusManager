"""Schemas fuer Benutzer und MAB-Geraete (FR-1, FR-3)."""

from __future__ import annotations

import datetime as dt
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.mgr import CredentialType, SubjectType
from app.schemas.common import ApiWarning

MASKED = "********"

MAX_MEMBERSHIPS = 50
"""Obergrenze der Mitgliedschaften je Anfrage.

Der vollstaendige Vorgang wird ins Audit-Log geschrieben; ohne Grenze koennte
eine gueltige Anfrage die TEXT-Spalte sprengen."""

MAX_ATTRIBUTES = 50
"""Obergrenze je Attributsammlung.

Der vollstaendige Vorgang wird ins Audit-Log geschrieben; ``mgr_audit.after_json``
ist eine TEXT-Spalte mit rund 64 KiB. Zwei Sammlungen zu je 50 Tripeln mit den
zulaessigen Feldlaengen bleiben mit deutlichem Abstand darunter - 200 taeten es
nicht, und der Audit-Eintrag risse den ganzen Vorgang mit."""


def validate_identifier(value: str, field: str) -> str:
    """Prueft einen Namen, der spaeter in einem Pfadsegment steht.

    Ein Schraegstrich liesse sich ueber die REST-Ressourcen nicht mehr
    adressieren: der Datensatz waere sichtbar, aber weder auf- noch aufrufbar.
    Deshalb wird er beim Anlegen abgewiesen statt spaeter zu einem 404 zu fuehren.
    """
    value = value.strip()
    if not value:
        raise ValueError(f"{field} darf nicht leer sein")
    if "/" in value or "\\" in value:
        raise ValueError(f"{field} darf keinen Schraegstrich enthalten")
    return value


def validate_groupname(value: str) -> str:
    """Gruppennamen zusaetzlich ohne CSV-Trennzeichen.

    Der Import kodiert Mitgliedschaften als ``gruppe:prioritaet``, getrennt durch
    Komma oder Semikolon. Ein Name mit diesen Zeichen liesse sich nicht mehr
    eindeutig lesen (FR-8).
    """
    value = validate_identifier(value, "groupname")
    for character in (":", ",", ";"):
        if character in value:
            raise ValueError(f"groupname darf kein '{character}' enthalten")
    return value


UserStatus = Literal["active", "disabled", "expired", "no_credentials"]


class AttributeIn(BaseModel):
    attribute: str = Field(min_length=1, max_length=64)
    op: str = Field(default=":=", max_length=2)
    value: str = Field(default="", max_length=253)


class AttributeOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    attribute: str
    op: str
    value: str


class MembershipIn(BaseModel):
    groupname: str = Field(min_length=1, max_length=64)
    priority: int = Field(default=1, ge=0, le=10_000)

    @field_validator("groupname")
    @classmethod
    def _check(cls, value: str) -> str:
        return validate_groupname(value)


class MembershipOut(BaseModel):
    groupname: str
    priority: int


class SubjectMeta(BaseModel):
    """Metadaten zu Benutzern und Geraeten.

    Die Laengen entsprechen den Spalten in ``mgr_subject``; ohne sie erzeugte ein
    zu langer Wert einen allgemeinen Serverfehler statt einer Validierungsmeldung.
    """

    display_name: str | None = Field(default=None, max_length=128)
    note: str | None = Field(default=None, max_length=4000)
    owner: str | None = Field(default=None, max_length=128)
    device_type: str | None = Field(default=None, max_length=64)
    location: str | None = Field(default=None, max_length=128)
    inventory_no: str | None = Field(default=None, max_length=64)


class UserListItem(BaseModel):
    username: str
    subject_type: SubjectType
    display_name: str | None = None
    owner: str | None = None
    note: str | None = None
    location: str | None = None
    device_type: str | None = None
    inventory_no: str | None = None
    groups: list[str] = Field(default_factory=list)
    memberships: list[MembershipOut] = Field(default_factory=list)
    status: UserStatus
    expires_at: dt.datetime | None = None
    credential_type: CredentialType | None = None
    has_metadata: bool = True


class UserDetail(UserListItem):
    check_attributes: list[AttributeOut] = Field(default_factory=list)
    reply_attributes: list[AttributeOut] = Field(default_factory=list)
    vlan: str | None = None
    active_sessions: int = 0
    last_auth: dt.datetime | None = None
    last_auth_reply: str | None = None
    created_at: dt.datetime | None = None
    updated_at: dt.datetime | None = None
    warnings: list[ApiWarning] = Field(default_factory=list)


class UserCreate(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str | None = Field(default=None, max_length=253)
    credential_type: CredentialType | None = None
    expires_at: dt.datetime | None = None
    groups: list[MembershipIn] = Field(default_factory=list, max_length=MAX_MEMBERSHIPS)
    vlan: str | None = Field(default=None, max_length=64)
    meta: SubjectMeta = Field(default_factory=SubjectMeta)
    reply_attributes: list[AttributeIn] = Field(default_factory=list, max_length=MAX_ATTRIBUTES)
    check_attributes: list[AttributeIn] = Field(default_factory=list, max_length=MAX_ATTRIBUTES)
    disabled: bool = False

    @field_validator("username")
    @classmethod
    def _strip(cls, value: str) -> str:
        return validate_identifier(value, "username")


class UserUpdate(BaseModel):
    username: str | None = Field(default=None, max_length=64)

    @field_validator("username")
    @classmethod
    def _strip(cls, value: str | None) -> str | None:
        return None if value is None else validate_identifier(value, "username")

    credential_type: CredentialType | None = None
    expires_at: dt.datetime | None = None
    clear_expiry: bool = False
    groups: list[MembershipIn] | None = Field(default=None, max_length=MAX_MEMBERSHIPS)
    vlan: str | None = Field(default=None, max_length=64)
    clear_vlan: bool = False
    meta: SubjectMeta | None = None
    reply_attributes: list[AttributeIn] | None = Field(default=None, max_length=MAX_ATTRIBUTES)
    check_attributes: list[AttributeIn] | None = Field(default=None, max_length=MAX_ATTRIBUTES)


class PasswordSet(BaseModel):
    password: str = Field(min_length=1, max_length=253)
    credential_type: CredentialType | None = None


class DeviceCreate(BaseModel):
    """MAB-Geraet (FR-3). Der Benutzername ist die normalisierte MAC-Adresse."""

    mac: str = Field(min_length=6, max_length=32)
    use_mac_as_password: bool = True
    password: str | None = Field(default=None, max_length=253)
    expires_at: dt.datetime | None = None
    groups: list[MembershipIn] = Field(default_factory=list, max_length=MAX_MEMBERSHIPS)
    vlan: str | None = Field(default=None, max_length=64)
    meta: SubjectMeta = Field(default_factory=SubjectMeta)
    disabled: bool = False


class DeviceUpdate(BaseModel):
    mac: str | None = Field(default=None, max_length=32)
    expires_at: dt.datetime | None = None
    clear_expiry: bool = False
    groups: list[MembershipIn] | None = Field(default=None, max_length=MAX_MEMBERSHIPS)
    vlan: str | None = Field(default=None, max_length=64)
    clear_vlan: bool = False
    meta: SubjectMeta | None = None


class BulkAction(BaseModel):
    usernames: list[Annotated[str, Field(min_length=1, max_length=64)]] = Field(
        default_factory=list, max_length=5000
    )
    filter_all: bool = False
    action: Literal["disable", "enable", "delete", "assign_group", "remove_group", "set_expiry"]
    groupname: str | None = Field(default=None, min_length=1, max_length=64)
    priority: int = Field(default=1, ge=0, le=10_000)

    @field_validator("groupname")
    @classmethod
    def _check_groupname(cls, value: str | None) -> str | None:
        # Ohne Grenze landete ein ueberlanger Wert im Sammel-Audit-Eintrag und
        # sprengte die TEXT-Spalte - mit einem allgemeinen 500 nach bereits
        # ausgefuehrten Einzelaktionen.
        return None if value is None else validate_groupname(value)

    expires_at: dt.datetime | None = None
