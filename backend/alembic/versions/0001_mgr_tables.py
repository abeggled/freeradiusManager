"""Manager-Tabellen anlegen (mgr_account, mgr_audit, mgr_subject, mgr_nas_extra,
mgr_setting, mgr_stats_snapshot).

Das FreeRADIUS-Schema wird nicht angefasst (Abschnitt 4.1).

Revision ID: 0001
Revises:
Create Date: 2026-09-02
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ROLE = sa.Enum("administrator", "operator", "auditor", native_enum=False, length=16)
SUBJECT_TYPE = sa.Enum("user", "device", native_enum=False, length=8)
CREDENTIAL_TYPE = sa.Enum("cleartext", "nt", "both", native_enum=False, length=16)
AUDIT_RESULT = sa.Enum("success", "failure", native_enum=False, length=8)


def upgrade() -> None:
    op.create_table(
        "mgr_account",
        sa.Column("id", sa.dialects.mysql.INTEGER(unsigned=True), primary_key=True),
        sa.Column("username", sa.String(64), nullable=False),
        sa.Column("email", sa.String(255)),
        sa.Column("display_name", sa.String(128)),
        sa.Column("password_hash", sa.String(255)),
        sa.Column("totp_secret_enc", sa.String(512)),
        sa.Column("totp_enabled", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("role", ROLE, nullable=False, server_default="auditor"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("1")),
        sa.Column("language", sa.String(5), nullable=False, server_default="de"),
        sa.Column("oidc_subject", sa.String(255)),
        sa.Column("last_login_at", sa.DateTime()),
        sa.Column("failed_logins", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("locked_until", sa.DateTime()),
        sa.Column("password_changed_at", sa.DateTime()),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column(
            "updated_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"),
        ),
        sa.UniqueConstraint("username", name="uq_mgr_account_username"),
        sa.UniqueConstraint("oidc_subject", name="uq_mgr_account_oidc_subject"),
        mysql_engine="InnoDB",
        mysql_charset="utf8mb4",
    )

    op.create_table(
        "mgr_audit",
        sa.Column("id", sa.dialects.mysql.INTEGER(unsigned=True), primary_key=True),
        sa.Column("ts", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("actor_id", sa.dialects.mysql.INTEGER(unsigned=True)),
        sa.Column("actor_name", sa.String(64), nullable=False, server_default="system"),
        sa.Column("actor_ip", sa.String(45)),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("object_type", sa.String(32), nullable=False),
        sa.Column("object_id", sa.String(128)),
        sa.Column("result", AUDIT_RESULT, nullable=False, server_default="success"),
        sa.Column("message", sa.String(512)),
        sa.Column("before_json", sa.Text()),
        sa.Column("after_json", sa.Text()),
        mysql_engine="InnoDB",
        mysql_charset="utf8mb4",
    )
    op.create_index("ix_mgr_audit_object", "mgr_audit", ["object_type", "object_id"])
    op.create_index("ix_mgr_audit_ts_id", "mgr_audit", ["ts", "id"])
    op.create_index("ix_mgr_audit_action", "mgr_audit", ["action"])

    op.create_table(
        "mgr_subject",
        sa.Column("id", sa.dialects.mysql.INTEGER(unsigned=True), primary_key=True),
        sa.Column("username", sa.String(64), nullable=False),
        sa.Column("subject_type", SUBJECT_TYPE, nullable=False, server_default="user"),
        sa.Column("credential_type", CREDENTIAL_TYPE, nullable=False, server_default="both"),
        sa.Column("display_name", sa.String(128)),
        sa.Column("note", sa.Text()),
        sa.Column("owner", sa.String(128)),
        sa.Column("device_type", sa.String(64)),
        sa.Column("location", sa.String(128)),
        sa.Column("inventory_no", sa.String(64)),
        sa.Column("expires_at", sa.DateTime()),
        sa.Column("disabled_at", sa.DateTime()),
        sa.Column("created_by", sa.String(64)),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column(
            "updated_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"),
        ),
        sa.UniqueConstraint("username", name="uq_mgr_subject_username"),
        mysql_engine="InnoDB",
        mysql_charset="utf8mb4",
    )
    op.create_index("ix_mgr_subject_type", "mgr_subject", ["subject_type"])
    op.create_index("ix_mgr_subject_owner", "mgr_subject", ["owner"])
    op.create_index("ix_mgr_subject_expires", "mgr_subject", ["expires_at"])

    op.create_table(
        "mgr_nas_extra",
        sa.Column("id", sa.dialects.mysql.INTEGER(unsigned=True), primary_key=True),
        sa.Column("nasname", sa.String(128), nullable=False),
        sa.Column("coa_enabled", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("coa_port", sa.Integer(), nullable=False, server_default=sa.text("3799")),
        sa.Column("coa_secret_enc", sa.String(512)),
        sa.Column("note", sa.Text()),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column(
            "updated_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"),
        ),
        sa.UniqueConstraint("nasname", name="uq_mgr_nas_extra_nasname"),
        mysql_engine="InnoDB",
        mysql_charset="utf8mb4",
    )

    op.create_table(
        "mgr_setting",
        sa.Column("key", sa.String(64), primary_key=True),
        sa.Column("value_json", sa.Text(), nullable=False),
        sa.Column("updated_by", sa.String(64)),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column(
            "updated_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"),
        ),
        mysql_engine="InnoDB",
        mysql_charset="utf8mb4",
    )

    op.create_table(
        "mgr_stats_snapshot",
        sa.Column("id", sa.dialects.mysql.INTEGER(unsigned=True), primary_key=True),
        sa.Column("key", sa.String(64), nullable=False),
        sa.Column("computed_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.UniqueConstraint("key", name="uq_mgr_stats_snapshot_key"),
        mysql_engine="InnoDB",
        mysql_charset="utf8mb4",
    )


def downgrade() -> None:
    op.drop_table("mgr_stats_snapshot")
    op.drop_table("mgr_setting")
    op.drop_table("mgr_nas_extra")
    op.drop_index("ix_mgr_subject_expires", table_name="mgr_subject")
    op.drop_index("ix_mgr_subject_owner", table_name="mgr_subject")
    op.drop_index("ix_mgr_subject_type", table_name="mgr_subject")
    op.drop_table("mgr_subject")
    op.drop_index("ix_mgr_audit_action", table_name="mgr_audit")
    op.drop_index("ix_mgr_audit_ts_id", table_name="mgr_audit")
    op.drop_index("ix_mgr_audit_object", table_name="mgr_audit")
    op.drop_table("mgr_audit")
    op.drop_table("mgr_account")
