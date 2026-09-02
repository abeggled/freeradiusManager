"""Attributvalidierung und VLAN-Vorlage (FR-2)."""

from __future__ import annotations

import pytest

from app.core.errors import ValidationError
from app.services.attributes import validate_triple, vlan_triples


def test_vlan_triples_match_specification() -> None:
    triples = vlan_triples("42")
    assert [(t.attribute, t.op, t.value) for t in triples] == [
        ("Tunnel-Type", ":=", "VLAN"),
        ("Tunnel-Medium-Type", ":=", "IEEE-802"),
        ("Tunnel-Private-Group-Id", ":=", "42"),
    ]


def test_warns_about_equals_in_check_table() -> None:
    warnings = validate_triple("Simultaneous-Use", "=", "1", table="radcheck")
    assert any(w.code == "warn.op_equals_in_check" for w in warnings)


def test_unknown_attribute_only_warns() -> None:
    warnings = validate_triple("Acme-Custom-Attr", ":=", "x", table="radreply")
    assert [w.code for w in warnings] == ["warn.unknown_attribute"]


def test_rejects_invalid_operator_for_reply() -> None:
    with pytest.raises(ValidationError) as excinfo:
        validate_triple("Filter-Id", "=~", "x", table="radgroupreply")
    assert excinfo.value.code == "error.invalid_operator"


def test_rejects_non_integer_value() -> None:
    with pytest.raises(ValidationError):
        validate_triple("Session-Timeout", ":=", "viele", table="radreply")


def test_password_attribute_warns_about_cleartext() -> None:
    warnings = validate_triple("Cleartext-Password", ":=", "geheim", table="radcheck")
    assert any(w.code == "warn.cleartext_stored" for w in warnings)
