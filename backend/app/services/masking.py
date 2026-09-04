"""Maskierung von Passwortwerten vor der Auslieferung.

NFR-1 verlangt, dass kein Klartextpasswort im API-Response auftaucht. Weil der
Expertenmodus (FR-2) auch Passwort-Attribute an Gruppen zulaesst, gilt das nicht
nur fuer Benutzer-, sondern ebenso fuer Gruppenattribute.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol

from app.core import radius_dict
from app.schemas.users import MASKED, AttributeOut


class AttributeRow(Protocol):
    id: int
    attribute: str
    op: str
    value: str


def mask_attributes(rows: Sequence[AttributeRow]) -> list[AttributeOut]:
    """Ersetzt die Werte von Passwort-Attributen durch einen Platzhalter."""
    return [
        AttributeOut(
            id=row.id,
            attribute=row.attribute,
            op=row.op,
            value=MASKED if radius_dict.is_password_attribute(row.attribute) else row.value,
        )
        for row in rows
    ]


def stored_values(rows: Sequence[AttributeRow]) -> dict[tuple[str, str], list[str]]:
    """Vorhandene Werte je (Attribut, Operator) in ihrer Reihenfolge."""
    stored: dict[tuple[str, str], list[str]] = {}
    for row in rows:
        stored.setdefault((row.attribute.lower(), row.op), []).append(row.value)
    return stored


def unmask(
    attribute: str, op: str, value: str, stored: dict[tuple[str, str], list[str]]
) -> str | None:
    """Loest einen zurueckgeschickten Platzhalter in den gespeicherten Wert auf.

    ``None`` bedeutet: kein Platzhalter oder kein passender Bestandswert - der
    Aufrufer verwendet dann den uebergebenen Wert.

    Der Reihe nach entnommen, damit mehrere Zeilen desselben Attributs ihre
    eigenen Werte behalten.
    """
    if not is_masked(attribute, value):
        return None
    queue = stored.get((attribute.lower(), op))
    if not queue:
        queue = next(
            (
                values
                for (name, _op), values in stored.items()
                if name == attribute.lower() and values
            ),
            None,
        )
    return queue.pop(0) if queue else None


def is_masked(attribute: str, value: str) -> bool:
    """Ob ein eingehender Wert nur der zuvor ausgelieferte Platzhalter ist.

    Ein Client, der einen maskierten Datensatz unveraendert zuruecksendet, darf
    das echte Passwort nicht durch Sternchen ersetzen - das wuerde die
    Authentifizierung sofort zerstoeren.
    """
    return value == MASKED and radius_dict.is_password_attribute(attribute)
