"""Wörterbuch bekannter RADIUS-Attribute und Operator-Validierung (FR-2).

Vendor-Attribute werden bewusst nicht hart gesperrt – unbekannte Namen erzeugen
nur eine Warnung.
"""

from __future__ import annotations

from dataclasses import dataclass

CHECK_OPERATORS = ("==", ":=", "+=", "!=", ">", ">=", "<", "<=", "=~", "!~", "=*", "!*", "=")
REPLY_OPERATORS = ("=", ":=", "+=")


@dataclass(frozen=True)
class AttributeInfo:
    name: str
    kind: str  # "check" | "reply" | "both"
    value_type: str  # "string" | "integer" | "ipaddr" | "date" | "enum"
    values: tuple[str, ...] = ()
    description_de: str = ""
    description_en: str = ""


_ATTRIBUTES: tuple[AttributeInfo, ...] = (
    AttributeInfo(
        "Cleartext-Password",
        "check",
        "string",
        description_de="Passwort im Klartext, Basis für PAP/MSCHAPv2",
        description_en="Cleartext password, basis for PAP/MSCHAPv2",
    ),
    AttributeInfo(
        "NT-Password",
        "check",
        "string",
        description_de="NT-Hash für PEAP/MSCHAPv2",
        description_en="NT hash for PEAP/MSCHAPv2",
    ),
    AttributeInfo("MD5-Password", "check", "string"),
    AttributeInfo("SHA2-Password", "check", "string"),
    AttributeInfo("Crypt-Password", "check", "string"),
    AttributeInfo(
        "Auth-Type",
        "check",
        "enum",
        ("Accept", "Reject", "Local", "PAP", "CHAP", "MS-CHAP", "EAP"),
        description_de="Erzwingt eine Authentifizierungsentscheidung",
        description_en="Forces an authentication decision",
    ),
    AttributeInfo(
        "Expiration",
        "check",
        "date",
        description_de="Ablaufdatum des Zugangs",
        description_en="Account expiry date",
    ),
    AttributeInfo("Simultaneous-Use", "check", "integer"),
    AttributeInfo("Login-Time", "check", "string"),
    AttributeInfo("Calling-Station-Id", "check", "string"),
    AttributeInfo("Called-Station-Id", "check", "string"),
    AttributeInfo("NAS-IP-Address", "check", "ipaddr"),
    AttributeInfo("NAS-Identifier", "check", "string"),
    AttributeInfo("Pool-Name", "check", "string"),
    AttributeInfo("User-Name", "both", "string"),
    AttributeInfo(
        "Tunnel-Type",
        "reply",
        "enum",
        ("VLAN", "GRE", "IP-IP", "L2TP", "PPTP"),
        description_de="Für VLAN-Zuweisung auf VLAN setzen",
        description_en="Set to VLAN for VLAN assignment",
    ),
    AttributeInfo(
        "Tunnel-Medium-Type",
        "reply",
        "enum",
        ("IEEE-802", "IP", "IPv6"),
        description_de="Für VLAN-Zuweisung auf IEEE-802 setzen",
        description_en="Set to IEEE-802 for VLAN assignment",
    ),
    AttributeInfo(
        "Tunnel-Private-Group-Id",
        "reply",
        "string",
        description_de="VLAN-ID oder VLAN-Name",
        description_en="VLAN ID or VLAN name",
    ),
    AttributeInfo(
        "Service-Type",
        "reply",
        "enum",
        ("Framed-User", "Login-User", "Call-Check", "Administrative-User"),
    ),
    AttributeInfo("Framed-Protocol", "reply", "enum", ("PPP", "SLIP")),
    AttributeInfo("Framed-IP-Address", "reply", "ipaddr"),
    AttributeInfo("Framed-IP-Netmask", "reply", "ipaddr"),
    AttributeInfo("Framed-MTU", "reply", "integer"),
    AttributeInfo("Filter-Id", "reply", "string"),
    AttributeInfo("Reply-Message", "reply", "string"),
    AttributeInfo("Session-Timeout", "reply", "integer"),
    AttributeInfo("Idle-Timeout", "reply", "integer"),
    AttributeInfo("Termination-Action", "reply", "enum", ("Default", "RADIUS-Request")),
    AttributeInfo("Acct-Interim-Interval", "reply", "integer"),
    AttributeInfo("Class", "reply", "string"),
    AttributeInfo("Egress-VLANID", "reply", "integer"),
    AttributeInfo("Egress-VLAN-Name", "reply", "string"),
    AttributeInfo("Cisco-AVPair", "both", "string"),
    AttributeInfo("Aruba-User-Role", "reply", "string"),
    AttributeInfo("Aruba-User-Vlan", "reply", "integer"),
    AttributeInfo("Juniper-Switching-Filter", "reply", "string"),
    AttributeInfo("Mikrotik-Group", "reply", "string"),
    AttributeInfo("HP-Port-Auth-Mode-DOT1X", "reply", "integer"),
    AttributeInfo("Fortinet-Group-Name", "reply", "string"),
)

BY_NAME: dict[str, AttributeInfo] = {a.name.lower(): a for a in _ATTRIBUTES}

VLAN_ATTRIBUTES = ("Tunnel-Type", "Tunnel-Medium-Type", "Tunnel-Private-Group-Id")
PASSWORD_ATTRIBUTES = frozenset(
    {
        "cleartext-password",
        "nt-password",
        "md5-password",
        "sha2-password",
        "crypt-password",
        "user-password",
        "password",
    }
)


def known(attribute: str) -> AttributeInfo | None:
    return BY_NAME.get(attribute.lower())


def is_password_attribute(attribute: str) -> bool:
    return attribute.lower() in PASSWORD_ATTRIBUTES


def suggestions(kind: str | None = None) -> list[AttributeInfo]:
    if kind in (None, "all"):
        return list(_ATTRIBUTES)
    return [a for a in _ATTRIBUTES if a.kind in (kind, "both")]
