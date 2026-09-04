"""Umwandlung zwischen ``datetime`` und dem Format des ``Expiration``-Attributs.

FreeRADIUS (``rlm_expiration``) erwartet ein Datum in der Form
``31 Dec 2026 23:59:00``; die Monatsnamen sind englisch und locale-unabhaengig.
"""

from __future__ import annotations

import datetime as dt
import re

MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")

_MONTH_NUMBERS = {name.lower(): index for index, name in enumerate(MONTHS, start=1)}

# Nur Formate ohne Monatsnamen: ``%b`` liest ``strptime`` in der Locale des
# Prozesses. Unter einer nicht-englischen ``LC_TIME`` scheiterte damit genau
# das Format, das ``to_expiration`` selbst schreibt.
_PARSE_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d",
)

# ``31 Dec 2026 23:59:00`` und ``Dec 31 2026`` - der Monatsname wird ueber die
# feste englische Tabelle aufgeloest.
_NAMED_MONTH_PATTERNS = (
    re.compile(
        r"^(?P<day>\d{1,2})\s+(?P<month>[A-Za-z]{3})\s+(?P<year>\d{4})"
        r"(?:\s+(?P<hour>\d{1,2}):(?P<minute>\d{2})(?::(?P<second>\d{2}))?)?$"
    ),
    re.compile(
        r"^(?P<month>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+(?P<year>\d{4})"
        r"(?:\s+(?P<hour>\d{1,2}):(?P<minute>\d{2})(?::(?P<second>\d{2}))?)?$"
    ),
)


def _from_named_month(value: str) -> dt.datetime | None:
    for pattern in _NAMED_MONTH_PATTERNS:
        match = pattern.match(value)
        if match is None:
            continue
        month = _MONTH_NUMBERS.get(match.group("month").lower())
        if month is None:
            return None
        try:
            return dt.datetime(
                int(match.group("year")),
                month,
                int(match.group("day")),
                int(match.group("hour") or 0),
                int(match.group("minute") or 0),
                int(match.group("second") or 0),
            )
        except ValueError:
            return None
    return None


def to_expiration(value: dt.datetime) -> str:
    value = as_naive_utc(value)
    return f"{value.day:02d} {MONTHS[value.month - 1]} {value.year} {value:%H:%M:%S}"


def from_expiration(value: str) -> dt.datetime | None:
    value = (value or "").strip()
    if not value:
        return None
    named = _from_named_month(value)
    if named is not None:
        return named
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
