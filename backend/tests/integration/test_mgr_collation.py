"""Angleichen der Kollation an das RADIUS-Schema (Migration 0010).

Die ``mgr_``-Tabellen entstanden mit ``mysql_charset`` ohne Kollation. MariaDB
waehlt dann die Standardkollation des Zeichensatzes und uebergeht die Vorgabe
der Datenbank; seit 11.5 ist das ``utf8mb4_uca1400_ai_ci``. Gegen eine
bestehende FreeRADIUS-Datenbank standen damit zwei Kollationen nebeneinander,
und schon die Benutzerliste - sie vereinigt ``radcheck`` und ``mgr_subject`` -
scheiterte mit ``Illegal mix of collations``.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import create_engine, text

MIGRATION = (
    Path(__file__).resolve().parents[2] / "alembic" / "versions" / "0010_align_mgr_collation.py"
)


def _module():
    spec = importlib.util.spec_from_file_location("migration_0010", MIGRATION)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _collation(connection, table: str) -> str | None:
    return connection.execute(
        text(
            "SELECT table_collation FROM information_schema.tables "
            "WHERE table_schema = DATABASE() AND table_name = :name"
        ),
        {"name": table},
    ).scalar()


def _run_upgrade(connection) -> None:
    context = MigrationContext.configure(connection)
    operations = Operations(context)
    with Operations.context(operations):
        _module().upgrade()


@pytest.fixture
def sync_connection(prepared_database: str):
    engine = create_engine(prepared_database)
    with engine.begin() as connection:
        yield connection
    engine.dispose()


def test_diverging_collation_is_aligned_to_the_radius_schema(sync_connection) -> None:
    module = _module()
    reference = _collation(sync_connection, module.REFERENCE_TABLE)
    assert reference is not None

    # Eine abweichende Kollation erzwingen - genau der Zustand, den ein Manager
    # gegen eine bestehende Datenbank auf MariaDB >= 11.5 erzeugte.
    other = "utf8mb4_bin" if reference != "utf8mb4_bin" else "utf8mb4_unicode_ci"
    sync_connection.execute(
        text(f"ALTER TABLE mgr_subject CONVERT TO CHARACTER SET utf8mb4 COLLATE {other}")
    )
    assert _collation(sync_connection, "mgr_subject") == other

    _run_upgrade(sync_connection)

    for table in module.MGR_TABLES:
        assert _collation(sync_connection, table) == reference, table


def test_upgrade_is_idempotent(sync_connection) -> None:
    """Ein zweiter Lauf darf nichts mehr anfassen - und nicht scheitern."""
    module = _module()
    reference = _collation(sync_connection, module.REFERENCE_TABLE)

    _run_upgrade(sync_connection)
    _run_upgrade(sync_connection)

    for table in module.MGR_TABLES:
        assert _collation(sync_connection, table) == reference, table


def test_union_over_both_schemas_works_afterwards(sync_connection) -> None:
    """Die Abfrage, an der es in der Praxis scheiterte.

    Geprueft wird, dass sie ueberhaupt laeuft - ``Illegal mix of collations``
    ist ein Fehler beim Ausfuehren, kein leeres Ergebnis. Auf den Inhalt kommt
    es nicht an: die Tabellen werden fuer diesen Test nicht geleert.
    """
    _run_upgrade(sync_connection)

    sync_connection.execute(
        text("SELECT username FROM radcheck UNION SELECT username FROM mgr_subject")
    ).all()


def test_missing_reference_table_is_tolerated(sync_connection) -> None:
    """Ohne RADIUS-Schema gibt es nichts, woran man ausrichten koennte.

    Die Migration darf daran nicht scheitern - sonst liesse sich der Manager
    nicht vorbereiten, bevor das Schema eingespielt ist.
    """
    module = _module()
    assert _collation(sync_connection, "gibt_es_nicht") is None
    assert module._collation(sync_connection, "gibt_es_nicht") is None


def test_collation_names_are_checked_before_use(sync_connection) -> None:
    """Der Name geht unquotiert in die Anweisung; die Pruefung bleibt bestehen."""
    module = _module()
    assert module._SAFE_NAME.match("utf8mb4_unicode_ci")
    assert not module._SAFE_NAME.match("utf8mb4; DROP TABLE mgr_account")
    assert not module._SAFE_NAME.match("utf8mb4_unicode_ci`")
