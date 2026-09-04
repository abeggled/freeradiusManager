"""Expiration-Format von rlm_expiration."""

from __future__ import annotations

import datetime as dt

from app.core.dates import from_expiration, to_expiration


def test_roundtrip() -> None:
    value = dt.datetime(2026, 12, 31, 23, 59, 0)
    text = to_expiration(value)
    assert text == "31 Dec 2026 23:59:00"
    assert from_expiration(text) == value


def test_parses_common_variants() -> None:
    assert from_expiration("1 Jan 2027") == dt.datetime(2027, 1, 1)
    assert from_expiration("Jan 1 2027") == dt.datetime(2027, 1, 1)
    assert from_expiration("2027-01-01 08:30:00") == dt.datetime(2027, 1, 1, 8, 30)
    assert from_expiration("Unsinn") is None
    assert from_expiration("") is None


def test_timezone_is_normalised_to_utc() -> None:
    aware = dt.datetime(2026, 6, 1, 12, 0, tzinfo=dt.timezone(dt.timedelta(hours=2)))
    assert to_expiration(aware) == "01 Jun 2026 10:00:00"
