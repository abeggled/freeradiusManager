"""OIDC-Subject fallunterscheidend speichern.

OIDC-Subjects unterscheiden Gross- und Kleinschreibung. Mit der voreingestellten
Kollation koennte ein Provider-Subject "Alice" das Konto von "alice" oeffnen.

Revision ID: 0003
Revises: 0002
Create Date: 2026-09-04
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.alter_column(
        "mgr_account",
        "oidc_subject",
        existing_type=sa.String(255),
        type_=sa.String(255, collation="utf8mb4_bin"),
        existing_nullable=True,
    )


def downgrade() -> None:
    op.alter_column(
        "mgr_account",
        "oidc_subject",
        existing_type=sa.String(255, collation="utf8mb4_bin"),
        type_=sa.String(255),
        existing_nullable=True,
    )
