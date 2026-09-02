"""SSID-Extraktion aus Called-Station-Id (FR-5)."""

from __future__ import annotations

from app.services.sessions import extract_ssid


def test_extracts_ssid_from_called_station_id() -> None:
    assert extract_ssid("00-11-22-33-44-55:Firmen-WLAN") == "Firmen-WLAN"


def test_returns_none_without_ssid_part() -> None:
    assert extract_ssid("00-11-22-33-44-55") is None
    assert extract_ssid("") is None
    assert extract_ssid(None) is None
