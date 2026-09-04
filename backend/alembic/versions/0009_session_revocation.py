"""Abgemeldete Sitzungen serverseitig entwerten.

Das Abmelden loeschte bisher nur das Cookie im Browser. Eine zuvor kopierte
Kennung blieb bis zur absoluten Gueltigkeit brauchbar und liess sich sogar
weiter verlaengern. Diese Tabelle haelt die abgemeldeten Sitzungskennungen fest,
bis sie ohnehin abgelaufen waeren; der Aufraeumjob entfernt sie danach.

Revision ID: 0009
Revises: 0008
Create Date: 2026-09-04
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import mysql

from alembic import op

revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "mgr_session_revocation",
        sa.Column("session_id", sa.String(64), primary_key=True),
        sa.Column("account_id", mysql.INTEGER(unsigned=True), nullable=False),
        # Bis wann der Eintrag noetig ist: danach ist das Token ohnehin
        # abgelaufen und die Zeile nur noch Ballast.
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        mysql_engine="InnoDB",
        mysql_charset="utf8mb4",
    )
    op.create_index(
        "ix_mgr_session_revocation_expires_at", "mgr_session_revocation", ["expires_at"]
    )


def downgrade() -> None:
    op.drop_index("ix_mgr_session_revocation_expires_at", table_name="mgr_session_revocation")
    op.drop_table("mgr_session_revocation")
