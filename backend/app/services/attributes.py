"""Validierung von Attribut/Operator/Wert-Tripeln (FR-2).

Unbekannte Attributnamen werden nur gewarnt, nicht gesperrt – Vendor-Attribute
sollen weiterhin pflegbar bleiben.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.core import radius_dict
from app.core.errors import ValidationError
from app.core.i18n import translate


@dataclass(slots=True)
class AttributeWarning:
    code: str
    message: str
    attribute: str


@dataclass(slots=True)
class Triple:
    attribute: str
    op: str
    value: str


def validate_triple(
    attribute: str, op: str, value: str, *, table: str, language: str = "de"
) -> list[AttributeWarning]:
    """Prueft ein Tripel und liefert Warnungen. Harte Fehler werfen ``ValidationError``."""
    attribute = (attribute or "").strip()
    op = (op or "").strip()
    if not attribute:
        raise ValidationError(code="error.validation", details={"field": "attribute"})

    allowed = (
        radius_dict.CHECK_OPERATORS if table.endswith("check") else radius_dict.REPLY_OPERATORS
    )
    if op not in allowed:
        raise ValidationError(
            code="error.invalid_operator",
            details={"operator": op, "allowed": list(allowed), "table": table},
        )

    warnings: list[AttributeWarning] = []
    if table.endswith("check") and op == "=":
        warnings.append(
            AttributeWarning(
                code="warn.op_equals_in_check",
                message=translate("warn.op_equals_in_check", language),
                attribute=attribute,
            )
        )
    info = radius_dict.known(attribute)
    if info is None:
        warnings.append(
            AttributeWarning(
                code="warn.unknown_attribute",
                message=translate("warn.unknown_attribute", language, attribute=attribute),
                attribute=attribute,
            )
        )
    elif info.value_type == "integer" and value and not value.lstrip("-").isdigit():
        raise ValidationError(
            code="error.validation",
            details={"attribute": attribute, "expected": "integer", "value": value},
        )
    if radius_dict.is_password_attribute(attribute) and table.endswith("check"):
        warnings.append(
            AttributeWarning(
                code="warn.cleartext_stored",
                message=translate("warn.cleartext_stored", language),
                attribute=attribute,
            )
        )
    return warnings


def vlan_triples(vlan: str) -> list[Triple]:
    """Die drei Attribute einer VLAN-Zuweisung (FR-2)."""
    return [
        Triple("Tunnel-Type", ":=", "VLAN"),
        Triple("Tunnel-Medium-Type", ":=", "IEEE-802"),
        Triple("Tunnel-Private-Group-Id", ":=", str(vlan)),
    ]


def extract_vlan(triples: list[Triple]) -> str | None:
    for triple in triples:
        if triple.attribute.lower() == "tunnel-private-group-id":
            return triple.value
    return None
