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
