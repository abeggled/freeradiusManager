"""Kein Klartext-Passwort im Audit-Log (NFR-1, FR-9)."""

from __future__ import annotations

from app.services.audit import REDACTED, redact


def test_redacts_known_secret_fields() -> None:
    payload = {
        "username": "anna",
        "password": "s3hr-geheim",
        "coa_secret": "abc",
        "note": "Notebook",
    }
    result = redact(payload)
    assert result["password"] == REDACTED
    assert result["coa_secret"] == REDACTED
    assert result["username"] == "anna"
    assert result["note"] == "Notebook"


def test_redacts_password_attribute_rows() -> None:
    payload = {
        "check_attributes": [
            {"attribute": "Cleartext-Password", "op": ":=", "value": "s3hr-geheim"},
            {"attribute": "Simultaneous-Use", "op": ":=", "value": "1"},
        ]
    }
    rows = redact(payload)["check_attributes"]
    assert rows[0]["value"] == REDACTED
    assert rows[1]["value"] == "1"


def test_empty_secret_stays_empty() -> None:
    assert redact({"password": None})["password"] is None
