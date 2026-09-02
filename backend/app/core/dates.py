"""Umwandlung zwischen ``datetime`` und dem Format des ``Expiration``-Attributs.

FreeRADIUS (``rlm_expiration``) erwartet ein Datum in der Form
``31 Dec 2026 23:59:00``; die Monatsnamen sind englisch und locale-unabhaengig.
"""

from __future__ import annotations

import datetime as dt

MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")

_PARSE_FORMATS = (
    "%d %b %Y %H:%M:%S",
    "%d %b %Y %H:%M",
    "%d %b %Y",
    "%b %d %Y %H:%M:%S",
    "%b %d %Y",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d",
)


def to_expiration(value: dt.datetime) -> str:
    value = as_naive_utc(value)
    return f"{value.day:02d} {MONTHS[value.month - 1]} {value.year} {value:%H:%M:%S}"


def from_expiration(value: str) -> dt.datetime | None:
    value = (value or "").strip()
    if not value:
        return None
    for fmt in _PARSE_FORMATS:
        try:
            return dt.datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None


def as_naive_utc(value: dt.datetime) -> dt.datetime:
    """MariaDB-DATETIME-Spalten sind zeitzonenlos; intern wird UTC gefuehrt."""
    if value.tzinfo is not None:
        return value.astimezone(dt.UTC).replace(tzinfo=None)
    return value


def utcnow() -> dt.datetime:
    return dt.datetime.now(tz=dt.UTC).replace(tzinfo=None)
