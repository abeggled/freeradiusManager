"""Kollation der ``mgr_``-Tabellen an das RADIUS-Schema angleichen.

Die Tabellen wurden mit ``mysql_charset="utf8mb4"`` ohne Kollation angelegt.
Gibt man MariaDB nur den Zeichensatz, waehlt es dessen Standardkollation und
uebergeht die Vorgabe der Datenbank - seit MariaDB 11.5 ist das
``utf8mb4_uca1400_ai_ci``. Gegen eine bestehende FreeRADIUS-Datenbank, deren
Tabellen ueblicherweise ``utf8mb4_general_ci`` oder ``utf8mb4_unicode_ci``
fuehren, entstanden damit zwei Kollationen nebeneinander. Jede Abfrage ueber
beide Seiten - schon die Benutzerliste vereinigt ``radcheck`` und
``mgr_subject`` - scheiterte mit ``Illegal mix of collations``.

Diese Migration richtet die ``mgr_``-Tabellen an der Kollation der
RADIUS-Tabellen aus. Umgekehrt waere es falsch: das FreeRADIUS-Schema bleibt
unangetastet (Spezifikation, Abschnitt 4.1).

Revision ID: 0010
Revises: 0009
Create Date: 2026-09-05
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from sqlalchemy import text
from sqlalchemy.engine import Connection

from alembic import op

revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

REFERENCE_TABLE = "radcheck"
"""Massgeblich ist das RADIUS-Schema; ``radcheck`` gibt es in jeder Installation."""

MGR_TABLES = (
    # Neue mgr_-Tabelle? Hier eintragen - sonst faellt sie aus der Angleichung
    # heraus und bringt die Mischung zurueck.
    "mgr_account",
    "mgr_audit",
    "mgr_nas_extra",
    "mgr_session_revocation",
    "mgr_setting",
    "mgr_stats_snapshot",
    "mgr_subject",
)

_SAFE_NAME = re.compile(r"\A[A-Za-z0-9_]+\Z")
"""Kollationsnamen gehen unquotiert in die Anweisung - hier wird das geprueft.

Der Wert stammt aus ``information_schema`` und ist damit nicht von aussen
bestimmbar; die Pruefung stellt sicher, dass das so bleibt."""


def _collation(connection: Connection, table: str) -> str | None:
    return connection.execute(
        text(
            "SELECT table_collation FROM information_schema.tables "
            "WHERE table_schema = DATABASE() AND table_name = :name"
        ),
        {"name": table},
    ).scalar()


def upgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name != "mysql":
        return

    target = _collation(connection, REFERENCE_TABLE)
    if not target or not _SAFE_NAME.match(target):
        # Ohne RADIUS-Schema gibt es nichts, woran man ausrichten koennte. Die
        # Migration darf daran nicht scheitern: sie laeuft auch, bevor das
        # Schema eingespielt ist.
        return
    charset = target.split("_", 1)[0]
    if not _SAFE_NAME.match(charset):
        return

    for table in MGR_TABLES:
        current = _collation(connection, table)
        if current is None or current == target:
            continue
        op.execute(f"ALTER TABLE `{table}` CONVERT TO CHARACTER SET {charset} COLLATE {target}")


def downgrade() -> None:
    """Bewusst wirkungslos.

    Die urspruengliche Kollation je Tabelle ist nicht festgehalten, und ein
    Zurueckdrehen stellte genau den Zustand wieder her, der den Betrieb
    unmoeglich machte. Die Migration ist damit in beide Richtungen gefahrlos.
    """
