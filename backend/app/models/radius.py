"""Abbildung des FreeRADIUS-Schemas (raddb/mods-config/sql/main/mysql/schema.sql).

Das Schema wird strukturell nicht veraendert (Abschnitt 4.1 der Spezifikation).
Diese Modelle bilden es nur ab; Alembic verwaltet sie nicht.
"""

from __future__ import annotations

import datetime as dt

from sqlalchemy import BigInteger, DateTime, Integer, String
from sqlalchemy.dialects import mysql
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class _AttributeRow:
    """Gemeinsame Spalten der vier Attributtabellen."""

    attribute: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    op: Mapped[str] = mapped_column(String(2), nullable=False, default="==")
    value: Mapped[str] = mapped_column(String(253), nullable=False, default="")


class RadCheck(_AttributeRow, Base):
    __tablename__ = "radcheck"

    id: Mapped[int] = mapped_column(mysql.INTEGER(unsigned=True), primary_key=True)
    username: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)


class RadReply(_AttributeRow, Base):
    __tablename__ = "radreply"

    id: Mapped[int] = mapped_column(mysql.INTEGER(unsigned=True), primary_key=True)
    username: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)


class RadGroupCheck(_AttributeRow, Base):
    __tablename__ = "radgroupcheck"

    id: Mapped[int] = mapped_column(mysql.INTEGER(unsigned=True), primary_key=True)
    groupname: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)


class RadGroupReply(_AttributeRow, Base):
    __tablename__ = "radgroupreply"

    id: Mapped[int] = mapped_column(mysql.INTEGER(unsigned=True), primary_key=True)
    groupname: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)


class RadUserGroup(Base):
    """Mitgliedschaften.

    Das offizielle FreeRADIUS-Schema kennt hier bewusst *keine* ``id``-Spalte;
    die Tabelle besteht nur aus ``username``, ``groupname`` und ``priority``.
    Fuer das ORM dient das Paar aus Benutzer und Gruppe als Schluessel - eine
    zusaetzliche Spalte zu verlangen wuerde den Manager auf Bestandsinstallationen
    unbrauchbar machen (Abschnitt 4.1).
    """

    __tablename__ = "radusergroup"

    username: Mapped[str] = mapped_column(
        String(64), nullable=False, default="", index=True, primary_key=True
    )
    groupname: Mapped[str] = mapped_column(String(64), nullable=False, default="", primary_key=True)
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class RadAcct(Base):
    __tablename__ = "radacct"

    radacctid: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    acctsessionid: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    acctuniqueid: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    username: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    realm: Mapped[str | None] = mapped_column(String(64), default="")
    nasipaddress: Mapped[str] = mapped_column(String(15), nullable=False, default="", index=True)
    nasportid: Mapped[str | None] = mapped_column(String(32))
    nasporttype: Mapped[str | None] = mapped_column(String(32))
    acctstarttime: Mapped[dt.datetime | None] = mapped_column(DateTime, index=True)
    acctupdatetime: Mapped[dt.datetime | None] = mapped_column(DateTime)
    acctstoptime: Mapped[dt.datetime | None] = mapped_column(DateTime, index=True)
    acctinterval: Mapped[int | None] = mapped_column(Integer)
    acctsessiontime: Mapped[int | None] = mapped_column(mysql.INTEGER(unsigned=True))
    acctauthentic: Mapped[str | None] = mapped_column(String(32))
    connectinfo_start: Mapped[str | None] = mapped_column(String(128))
    connectinfo_stop: Mapped[str | None] = mapped_column(String(128))
    acctinputoctets: Mapped[int | None] = mapped_column(BigInteger)
    acctoutputoctets: Mapped[int | None] = mapped_column(BigInteger)
    calledstationid: Mapped[str] = mapped_column(String(50), nullable=False, default="")
    callingstationid: Mapped[str] = mapped_column(
        String(50), nullable=False, default="", index=True
    )
    acctterminatecause: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    servicetype: Mapped[str | None] = mapped_column(String(32))
    framedprotocol: Mapped[str | None] = mapped_column(String(32))
    framedipaddress: Mapped[str] = mapped_column(String(15), nullable=False, default="")
    framedipv6address: Mapped[str] = mapped_column(String(45), nullable=False, default="")
    framedipv6prefix: Mapped[str] = mapped_column(String(45), nullable=False, default="")
    framedinterfaceid: Mapped[str] = mapped_column(String(44), nullable=False, default="")
    delegatedipv6prefix: Mapped[str] = mapped_column(String(45), nullable=False, default="")
    class_: Mapped[str | None] = mapped_column("class", String(64))


class RadPostAuth(Base):
    __tablename__ = "radpostauth"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    pass_: Mapped[str] = mapped_column("pass", String(64), nullable=False, default="")
    reply: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    authdate: Mapped[dt.datetime] = mapped_column(DateTime, nullable=False, index=True)
    class_: Mapped[str | None] = mapped_column("class", String(64))


class Nas(Base):
    __tablename__ = "nas"

    id: Mapped[int] = mapped_column(mysql.INTEGER(unsigned=True), primary_key=True)
    nasname: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    shortname: Mapped[str | None] = mapped_column(String(32))
    type: Mapped[str | None] = mapped_column(String(30), default="other")
    ports: Mapped[int | None] = mapped_column(Integer)
    secret: Mapped[str] = mapped_column(String(60), nullable=False, default="secret")
    server: Mapped[str | None] = mapped_column(String(64))
    community: Mapped[str | None] = mapped_column(String(50))
    description: Mapped[str | None] = mapped_column(String(200), default="RADIUS Client")
