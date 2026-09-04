"""Manager-eigene Tabellen (Praefix ``mgr_``), ausschliesslich von Alembic verwaltet."""

from __future__ import annotations

import datetime as dt
import enum

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Enum,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects import mysql
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class Role(enum.StrEnum):
    """Globale Rollen gemaess Abschnitt 2 der Spezifikation."""

    ADMINISTRATOR = "administrator"
    OPERATOR = "operator"
    AUDITOR = "auditor"


class SubjectType(enum.StrEnum):
    USER = "user"
    DEVICE = "device"


class CredentialType(enum.StrEnum):
    """Welche Credential-Attribute fuer diesen Benutzer gepflegt werden (FR-1)."""

    CLEARTEXT = "cleartext"
    NT = "nt"
    BOTH = "both"


class AuditResult(enum.StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"


class TimestampMixin:
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime, nullable=False, server_default=func.now()
    )
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime, nullable=False, server_default=func.now(), onupdate=func.now()
    )


class MgrAccount(TimestampMixin, Base):
    """Manager-Benutzer (FR-10)."""

    __tablename__ = "mgr_account"

    id: Mapped[int] = mapped_column(mysql.INTEGER(unsigned=True), primary_key=True)
    username: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    email: Mapped[str | None] = mapped_column(String(255))
    display_name: Mapped[str | None] = mapped_column(String(128))
    password_hash: Mapped[str | None] = mapped_column(String(255))
    totp_secret_enc: Mapped[str | None] = mapped_column(String(512))
    totp_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    role: Mapped[Role] = mapped_column(
        Enum(Role, native_enum=False, length=16), nullable=False, default=Role.AUDITOR
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    language: Mapped[str] = mapped_column(String(5), nullable=False, default="de")
    oidc_subject: Mapped[str | None] = mapped_column(
        # Binaere Kollation: OIDC-Subjects unterscheiden Gross- und
        # Kleinschreibung. Mit der voreingestellten Kollation koennte "Alice"
        # die Sitzung von "alice" erhalten.
        String(255, collation="utf8mb4_bin"),
        unique=True,
    )
    last_login_at: Mapped[dt.datetime | None] = mapped_column(DateTime)
    failed_logins: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_until: Mapped[dt.datetime | None] = mapped_column(DateTime)
    # Mit Sekundenbruchteilen: sonst verwirft eine Aenderung in derselben
    # Sekunde, in der die Sitzung ausgestellt wurde, diese nicht.
    password_changed_at: Mapped[dt.datetime | None] = mapped_column(mysql.DATETIME(fsp=6))
    totp_changed_at: Mapped[dt.datetime | None] = mapped_column(mysql.DATETIME(fsp=6))
    """Zeitpunkt der letzten Aenderung des zweiten Faktors.

    Aeltere Sitzungen werden dadurch auch dann ungueltig, wenn nach einem
    Zuruecksetzen sofort ein neuer Faktor eingerichtet wird."""
    session_epoch: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0, server_default="0"
    )
    """Generation der gueltigen Sitzungen.

    Wird bei einer Rollen- oder Statusaenderung erhoeht. Ohne sie lebten Token
    eines deaktivierten Kontos nach der Reaktivierung wieder auf, ebenso eine
    Administratorsitzung nach einer Rollenaenderung hin und zurueck."""
    totp_last_counter: Mapped[int | None] = mapped_column(BigInteger)
    """Zuletzt angenommenes TOTP-Zeitfenster.

    Ohne diese Marke liesse sich ein abgefangener Code innerhalb des
    Prueffensters ein zweites Mal einloesen und eine weitere Sitzung erzeugen."""


class MgrAudit(Base):
    """Audit-Log (FR-9). Ueber die UI nicht loeschbar."""

    __tablename__ = "mgr_audit"
    __table_args__ = (
        Index("ix_mgr_audit_object", "object_type", "object_id"),
        Index("ix_mgr_audit_ts_id", "ts", "id"),
        Index("ix_mgr_audit_action", "action"),
    )

    id: Mapped[int] = mapped_column(mysql.INTEGER(unsigned=True), primary_key=True)
    ts: Mapped[dt.datetime] = mapped_column(DateTime, nullable=False, server_default=func.now())
    actor_id: Mapped[int | None] = mapped_column(mysql.INTEGER(unsigned=True))
    actor_name: Mapped[str] = mapped_column(String(64), nullable=False, default="system")
    actor_ip: Mapped[str | None] = mapped_column(String(45))
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    object_type: Mapped[str] = mapped_column(String(32), nullable=False)
    object_id: Mapped[str | None] = mapped_column(String(128))
    result: Mapped[AuditResult] = mapped_column(
        Enum(AuditResult, native_enum=False, length=8), nullable=False, default=AuditResult.SUCCESS
    )
    message: Mapped[str | None] = mapped_column(String(512))
    before_json: Mapped[str | None] = mapped_column(Text)
    after_json: Mapped[str | None] = mapped_column(Text)


class MgrSubject(TimestampMixin, Base):
    """Metadaten zu Benutzern und MAB-Geraeten, verknuepft ueber ``username``."""

    __tablename__ = "mgr_subject"
    # Die Indizes stehen auch in der Migration; ohne sie hier wuerde eine
    # spaetere Autogenerierung ihr Loeschen vorschlagen.
    __table_args__ = (
        UniqueConstraint("username", name="uq_mgr_subject_username"),
        Index("ix_mgr_subject_type", "subject_type"),
        Index("ix_mgr_subject_owner", "owner"),
        Index("ix_mgr_subject_expires", "expires_at"),
    )

    id: Mapped[int] = mapped_column(mysql.INTEGER(unsigned=True), primary_key=True)
    username: Mapped[str] = mapped_column(String(64), nullable=False)
    subject_type: Mapped[SubjectType] = mapped_column(
        Enum(SubjectType, native_enum=False, length=8), nullable=False, default=SubjectType.USER
    )
    credential_type: Mapped[CredentialType] = mapped_column(
        Enum(CredentialType, native_enum=False, length=16),
        nullable=False,
        default=CredentialType.BOTH,
    )
    display_name: Mapped[str | None] = mapped_column(String(128))
    note: Mapped[str | None] = mapped_column(Text)
    owner: Mapped[str | None] = mapped_column(String(128))
    device_type: Mapped[str | None] = mapped_column(String(64))
    location: Mapped[str | None] = mapped_column(String(128))
    inventory_no: Mapped[str | None] = mapped_column(String(64))
    expires_at: Mapped[dt.datetime | None] = mapped_column(DateTime)
    disabled_at: Mapped[dt.datetime | None] = mapped_column(DateTime)
    disabled_state: Mapped[str | None] = mapped_column(Text)
    """Vor dem Sperren vorhandenes ``Auth-Type``-Tripel als JSON.

    Ohne diese Notiz wuerde eine voruebergehende Sperre eine bestehende
    ``Auth-Type``-Vorgabe dauerhaft entfernen (FR-1)."""
    created_by: Mapped[str | None] = mapped_column(String(64))


class MgrNasExtra(TimestampMixin, Base):
    """CoA-Port und -Secret je NAS (FR-7). Secret AES-GCM-verschluesselt (NFR-1)."""

    __tablename__ = "mgr_nas_extra"
    __table_args__ = (UniqueConstraint("nasname", name="uq_mgr_nas_extra_nasname"),)

    id: Mapped[int] = mapped_column(mysql.INTEGER(unsigned=True), primary_key=True)
    nasname: Mapped[str] = mapped_column(String(128), nullable=False)
    coa_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    coa_port: Mapped[int] = mapped_column(Integer, nullable=False, default=3799)
    coa_secret_enc: Mapped[str | None] = mapped_column(String(512))
    note: Mapped[str | None] = mapped_column(Text)


class MgrSetting(TimestampMixin, Base):
    """Instanzweite Einstellungen als JSON-Wert je Schluessel."""

    __tablename__ = "mgr_setting"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value_json: Mapped[str] = mapped_column(Text, nullable=False)
    updated_by: Mapped[str | None] = mapped_column(String(64))


class MgrStatsSnapshot(Base):
    """Ergebnis des Aggregations-Hintergrundjobs (NFR-2)."""

    __tablename__ = "mgr_stats_snapshot"

    id: Mapped[int] = mapped_column(mysql.INTEGER(unsigned=True), primary_key=True)
    key: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    computed_at: Mapped[dt.datetime] = mapped_column(
        DateTime, nullable=False, server_default=func.now()
    )
    payload_json: Mapped[str] = mapped_column(Text, nullable=False)
