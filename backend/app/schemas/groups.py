"""Schemas fuer Gruppen (FR-2)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator

from app.schemas.common import ApiWarning
from app.schemas.users import AttributeIn, AttributeOut, validate_groupname


class GroupListItem(BaseModel):
    groupname: str
    members: int = 0
    vlan: str | None = None


class GroupDetail(GroupListItem):
    check_attributes: list[AttributeOut] = Field(default_factory=list)
    reply_attributes: list[AttributeOut] = Field(default_factory=list)
    warnings: list[ApiWarning] = Field(default_factory=list)


class GroupCreate(BaseModel):
    groupname: str = Field(min_length=1, max_length=64)

    @field_validator("groupname")
    @classmethod
    def _check(cls, value: str) -> str:
        return validate_groupname(value)

    vlan: str | None = Field(default=None, max_length=64)
    clear_vlan: bool = False
    check_attributes: list[AttributeIn] = Field(default_factory=list)
    reply_attributes: list[AttributeIn] = Field(default_factory=list)


class GroupUpdate(BaseModel):
    groupname: str | None = Field(default=None, max_length=64)

    @field_validator("groupname")
    @classmethod
    def _check(cls, value: str | None) -> str | None:
        return None if value is None else validate_groupname(value)

    vlan: str | None = None
    clear_vlan: bool = False
    check_attributes: list[AttributeIn] | None = None
    reply_attributes: list[AttributeIn] | None = None


class MembershipChange(BaseModel):
    usernames: list[str] = Field(default_factory=list, max_length=5000)
    action: Literal["add", "remove"] = "add"
    priority: int = Field(default=1, ge=0, le=10_000)


class DictionaryEntry(BaseModel):
    name: str
    kind: str
    value_type: str
    values: list[str] = Field(default_factory=list)
    description: str | None = None


class DictionaryResponse(BaseModel):
    attributes: list[DictionaryEntry]
    check_operators: list[str]
    reply_operators: list[str]
