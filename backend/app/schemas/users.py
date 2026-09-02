"""Schemas fuer Benutzer und MAB-Geraete (FR-1, FR-3)."""

from __future__ import annotations

import datetime as dt
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.mgr import CredentialType, SubjectType
from app.schemas.common import ApiWarning

MASKED = "********"

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


class MembershipOut(BaseModel):
    groupname: str
    priority: int


class SubjectMeta(BaseModel):
    display_name: str | None = None
    note: str | None = None
    owner: str | None = None
    device_type: str | None = None
    location: str | None = None
    inventory_no: str | None = None


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
    status: UserStatus
    expires_at: dt.datetime | None = None
    credential_type: CredentialType | None = None
    has_metadata: bool = True


class UserDetail(UserListItem):
    check_attributes: list[AttributeOut] = Field(default_factory=list)
    reply_attributes: list[AttributeOut] = Field(default_factory=list)
    memberships: list[MembershipOut] = Field(default_factory=list)
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
    groups: list[MembershipIn] = Field(default_factory=list)
    vlan: str | None = Field(default=None, max_length=64)
    meta: SubjectMeta = Field(default_factory=SubjectMeta)
    reply_attributes: list[AttributeIn] = Field(default_factory=list)
    check_attributes: list[AttributeIn] = Field(default_factory=list)
    disabled: bool = False

    @field_validator("username")
    @classmethod
    def _strip(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("username darf nicht leer sein")
        return value


class UserUpdate(BaseModel):
    username: str | None = Field(default=None, max_length=64)
    credential_type: CredentialType | None = None
    expires_at: dt.datetime | None = None
    clear_expiry: bool = False
    groups: list[MembershipIn] | None = None
    vlan: str | None = None
    clear_vlan: bool = False
    meta: SubjectMeta | None = None
    reply_attributes: list[AttributeIn] | None = None
    check_attributes: list[AttributeIn] | None = None


class PasswordSet(BaseModel):
    password: str = Field(min_length=1, max_length=253)
    credential_type: CredentialType | None = None


class DeviceCreate(BaseModel):
    """MAB-Geraet (FR-3). Der Benutzername ist die normalisierte MAC-Adresse."""

    mac: str = Field(min_length=6, max_length=32)
    use_mac_as_password: bool = True
    password: str | None = None
    expires_at: dt.datetime | None = None
    groups: list[MembershipIn] = Field(default_factory=list)
    vlan: str | None = None
    meta: SubjectMeta = Field(default_factory=SubjectMeta)
    disabled: bool = False


class DeviceUpdate(BaseModel):
    mac: str | None = None
    expires_at: dt.datetime | None = None
    clear_expiry: bool = False
    groups: list[MembershipIn] | None = None
    vlan: str | None = None
    clear_vlan: bool = False
    meta: SubjectMeta | None = None


class BulkAction(BaseModel):
    usernames: list[str] = Field(default_factory=list, max_length=5000)
    filter_all: bool = False
    action: Literal["disable", "enable", "delete", "assign_group", "remove_group", "set_expiry"]
    groupname: str | None = None
    priority: int = 1
    expires_at: dt.datetime | None = None
