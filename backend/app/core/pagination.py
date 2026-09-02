"""Paginierung. Fuer ``radacct``/``radpostauth`` wird Keyset-Pagination genutzt,
damit auch bei mehreren Millionen Zeilen indexgestuetzt gearbeitet wird (NFR-2)."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from typing import Any

MAX_PAGE_SIZE = 200
DEFAULT_PAGE_SIZE = 50


def encode_cursor(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, separators=(",", ":"), default=str).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_cursor(cursor: str | None) -> dict[str, Any] | None:
    if not cursor:
        return None
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
        value = json.loads(raw)
    except Exception:  # noqa: BLE001 - defekter Cursor wird ignoriert
        return None
    return value if isinstance(value, dict) else None


@dataclass
class Page[T]:
    """Offset-basierte Seite fuer kleine Konfigurationstabellen."""

    items: list[T] = field(default_factory=list)
    total: int = 0
    limit: int = DEFAULT_PAGE_SIZE
    offset: int = 0


@dataclass
class KeysetPage[T]:
    """Keyset-Seite fuer die grossen Accounting-Tabellen."""

    items: list[T] = field(default_factory=list)
    next_cursor: str | None = None
    limit: int = DEFAULT_PAGE_SIZE


def clamp_limit(limit: int | None) -> int:
    if not limit or limit < 1:
        return DEFAULT_PAGE_SIZE
    return min(limit, MAX_PAGE_SIZE)
