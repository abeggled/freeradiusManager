"""Zeitpunkt der letzten TOTP-Aenderung festhalten.

Ohne diesen Zeitstempel wuerde eine vor dem Zuruecksetzen gestohlene Sitzung
wieder gueltig, sobald ein neuer Faktor eingerichtet ist.

Revision ID: 0004
Revises: 0003
Create Date: 2026-09-04
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("mgr_account", sa.Column("totp_changed_at", sa.DateTime(), nullable=True))


def downgrade() -> None:
    op.drop_column("mgr_account", "totp_changed_at")
