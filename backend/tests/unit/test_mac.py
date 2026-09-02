"""MAC-Normalisierung (FR-3)."""

from __future__ import annotations

import pytest

from app.core.errors import ValidationError
from app.core.mac import format_mac, is_mac, matches_format


@pytest.mark.parametrize(
    ("fmt", "expected"),
    [
        ("plain_lower", "aabbccddeeff"),
        ("plain_upper", "AABBCCDDEEFF"),
        ("colon_lower", "aa:bb:cc:dd:ee:ff"),
        ("colon_upper", "AA:BB:CC:DD:EE:FF"),
        ("hyphen_lower", "aa-bb-cc-dd-ee-ff"),
        ("hyphen_upper", "AA-BB-CC-DD-EE-FF"),
        ("dot_lower", "aabb.ccdd.eeff"),
        ("dot_upper", "AABB.CCDD.EEFF"),
    ],
)
def test_format_mac(fmt: str, expected: str) -> None:
    assert format_mac("AA:BB:CC:DD:EE:FF", fmt) == expected
    assert format_mac("aabbccddeeff", fmt) == expected


def test_invalid_mac_raises() -> None:
    for value in ("", "aabbccddee", "not-a-mac", "aabbccddeeffgg"):
        with pytest.raises(ValidationError):
            format_mac(value)
        assert not is_mac(value)


def test_matches_format() -> None:
    assert matches_format("aa:bb:cc:dd:ee:ff", "colon_lower")
    assert not matches_format("AA:BB:CC:DD:EE:FF", "colon_lower")
    assert not matches_format("keine-mac", "colon_lower")
