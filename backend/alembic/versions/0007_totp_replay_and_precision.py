"""Sekundenbruchteile fuer den Sitzungsentzug und Schutz vor TOTP-Wiedereinsatz.

``password_changed_at`` und ``totp_changed_at`` wurden als ``DATETIME`` ohne
Bruchteile gefuehrt. Eine Aenderung in derselben Sekunde, in der eine Sitzung
ausgestellt wurde, verwarf diese deshalb nicht - das Cookie blieb bis zur
absoluten Gueltigkeit brauchbar.

``totp_last_counter`` haelt das zuletzt angenommene Zeitfenster fest; ohne diese
Marke liesse sich ein abgefangener Code innerhalb des Prueffensters mehrfach
einloesen.

Revision ID: 0007
Revises: 0006
Create Date: 2026-09-04
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import mysql

from alembic import op

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_PRECISE = ("password_changed_at", "totp_changed_at")


def upgrade() -> None:
    for column in _PRECISE:
        op.alter_column(
            "mgr_account",
            column,
            existing_type=mysql.DATETIME(),
            type_=mysql.DATETIME(fsp=6),
            existing_nullable=True,
        )
    op.add_column(
        "mgr_account",
        sa.Column("totp_last_counter", sa.BigInteger(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("mgr_account", "totp_last_counter")
    for column in _PRECISE:
        op.alter_column(
            "mgr_account",
            column,
            existing_type=mysql.DATETIME(fsp=6),
            type_=mysql.DATETIME(),
            existing_nullable=True,
        )
