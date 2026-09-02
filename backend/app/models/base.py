"""Deklarative Basis. RADIUS- und mgr_-Modelle teilen sich die Metadaten,
Alembic filtert die RADIUS-Tabellen jedoch bewusst aus (siehe alembic/env.py)."""

from __future__ import annotations

from sqlalchemy.orm import DeclarativeBase

RADIUS_TABLES = frozenset(
    {
        "radcheck",
        "radreply",
        "radgroupcheck",
        "radgroupreply",
        "radusergroup",
        "radacct",
        "radpostauth",
        "nas",
    }
)


class Base(DeclarativeBase):
    """Gemeinsame Basisklasse aller ORM-Modelle."""


def is_radius_table(name: str) -> bool:
    return name in RADIUS_TABLES
