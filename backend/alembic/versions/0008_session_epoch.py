"""Sitzungsgeneration je Konto.

Ein deaktiviertes Konto wies seine Token nur solange ab, wie ``is_active``
falsch blieb; nach der Reaktivierung galten dieselben Token wieder. Ebenso
lebte eine Sitzung wieder auf, wenn die Rolle weg und zurueck geaendert wurde.
Der Zaehler wird bei solchen Aenderungen erhoeht und im Token mitgefuehrt.

Revision ID: 0008
Revises: 0007
Create Date: 2026-09-04
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "mgr_account",
        sa.Column("session_epoch", sa.BigInteger(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    op.drop_column("mgr_account", "session_epoch")
