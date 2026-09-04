"""Gemeinsame Schemas: Fehlerstruktur, Seiten, Warnungen."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ErrorResponse(BaseModel):
    """Konsistente Fehlerstruktur (Abschnitt 6.3)."""

    code: str = Field(examples=["error.not_found"])
    message: str
    details: dict[str, Any] = Field(default_factory=dict)


class ApiWarning(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    code: str
    message: str
    attribute: str | None = None


class PageMeta(BaseModel):
    total: int
    limit: int
    offset: int


class PagedResponse[T](BaseModel):
    items: list[T]
    meta: PageMeta


class CursorMeta(BaseModel):
    limit: int
    next_cursor: str | None = None
    approximate_total: int | None = None


class CursorResponse[T](BaseModel):
    items: list[T]
    meta: CursorMeta


class BulkResult(BaseModel):
    requested: int
    succeeded: int
    failed: int
    errors: list[dict[str, Any]] = Field(default_factory=list)


class OperationResult(BaseModel):
    ok: bool = True
    message: str | None = None
    warnings: list[ApiWarning] = Field(default_factory=list)
