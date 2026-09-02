"""MAC-Normalisierung (FR-3).

Das Zielformat ist konfigurierbar, damit es zur ``policy.d``-Normalisierung des
Servers passt (z. B. ``rewrite.called_station_id``).
"""

from __future__ import annotations

import re

from app.core.errors import ValidationError

MAC_FORMATS: dict[str, str] = {
    "plain_lower": "aabbccddeeff",
    "plain_upper": "AABBCCDDEEFF",
    "colon_lower": "aa:bb:cc:dd:ee:ff",
    "colon_upper": "AA:BB:CC:DD:EE:FF",
    "hyphen_lower": "aa-bb-cc-dd-ee-ff",
    "hyphen_upper": "AA-BB-CC-DD-EE-FF",
    "dot_lower": "aabb.ccdd.eeff",
    "dot_upper": "AABB.CCDD.EEFF",
}

_SEPARATORS = re.compile(r"[\s:.\-]")
_TWELVE_HEX = re.compile(r"^[0-9a-fA-F]{12}$")


def extract_hex(value: str) -> str:
    """Entfernt uebliche Trenner und prueft auf genau zwoelf Hexziffern.

    Es werden bewusst nur Trennzeichen entfernt: ``aabbccddeeffgg`` ist keine
    gueltige MAC und darf nicht stillschweigend gekuerzt werden.
    """
    cleaned = _SEPARATORS.sub("", value or "")
    if not _TWELVE_HEX.match(cleaned):
        raise ValidationError(code="error.invalid_mac", details={"value": value})
    return cleaned.lower()


def is_mac(value: str) -> bool:
    return bool(_TWELVE_HEX.match(_SEPARATORS.sub("", value or "")))


def format_mac(value: str, fmt: str = "colon_lower") -> str:
    if fmt not in MAC_FORMATS:
        raise ValidationError(code="error.validation", details={"format": fmt})
    hexdigits = extract_hex(value)
    upper = fmt.endswith("_upper")
    if fmt.startswith("plain"):
        out = hexdigits
    elif fmt.startswith("colon"):
        out = ":".join(hexdigits[i : i + 2] for i in range(0, 12, 2))
    elif fmt.startswith("hyphen"):
        out = "-".join(hexdigits[i : i + 2] for i in range(0, 12, 2))
    else:  # dot
        out = ".".join(hexdigits[i : i + 4] for i in range(0, 12, 4))
    return out.upper() if upper else out


def matches_format(value: str, fmt: str) -> bool:
    try:
        return format_mac(value, fmt) == value
    except ValidationError:
        return False
