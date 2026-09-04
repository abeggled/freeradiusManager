"""``disabled_state`` als TEXT.

Bestandsdaten koennen mehrere ``Auth-Type``-Zeilen mit je bis zu 253 Zeichen
enthalten; der gemerkte Zustand passte dann nicht in 300 Zeichen und das Sperren
scheiterte mit einem Datenbankfehler.

Revision ID: 0006
Revises: 0005
Create Date: 2026-09-04
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.alter_column(
        "mgr_subject",
        "disabled_state",
        existing_type=sa.String(300),
        type_=sa.Text(),
        existing_nullable=True,
    )


def downgrade() -> None:
    op.alter_column(
        "mgr_subject",
        "disabled_state",
        existing_type=sa.Text(),
        type_=sa.String(300),
        existing_nullable=True,
    )
