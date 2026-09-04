"""Vorgabewerte der Enum-Spalten an die gespeicherten Namen angleichen.

Das ORM legt Enum-Werte unter ihrem *Namen* ab (``USER``, ``BOTH`` …), die
Migrationen 0001 setzten als Vorgabe jedoch die kleingeschriebenen Werte. Eine
Zeile, die eine andere Anwendung ohne ausdrueckliche Angabe einfuegt, waere
danach nicht lesbar. Die Anwendung selbst schreibt immer ausdruecklich; die
Angleichung entfernt lediglich diese Inkonsistenz.

Revision ID: 0005
Revises: 0004
Create Date: 2026-09-04
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

COLUMNS = (
    ("mgr_account", "role", 16, "AUDITOR", "auditor"),
    ("mgr_audit", "result", 8, "SUCCESS", "success"),
    ("mgr_subject", "subject_type", 8, "USER", "user"),
    ("mgr_subject", "credential_type", 16, "BOTH", "both"),
)


def upgrade() -> None:
    for table, column, length, name, _value in COLUMNS:
        op.alter_column(
            table,
            column,
            existing_type=sa.String(length),
            server_default=name,
            existing_nullable=False,
        )


def downgrade() -> None:
    for table, column, length, _name, value in COLUMNS:
        op.alter_column(
            table,
            column,
            existing_type=sa.String(length),
            server_default=value,
            existing_nullable=False,
        )
