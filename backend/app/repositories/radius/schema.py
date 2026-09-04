"""Pruefung des vorausgesetzten FreeRADIUS-Schemas (Abschnitt 4.2).

Beim Start wird geprueft, ob die erwarteten Tabellen und Spalten existieren.
Bei Abweichungen verweigert die Anwendung den Betrieb mit klarer Meldung.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection


def _mapped_columns() -> dict[str, set[str]]:
    """Alle Spalten, die die ORM-Modelle tatsaechlich selektieren.

    Aus den Modellen abgeleitet statt von Hand gepflegt: eine Liste, die nur
    einen Teil nennt, liesse ein unvollstaendiges Schema den Start passieren und
    erst zur Laufzeit mit "unknown column" scheitern.
    """
    from app.models import Base
    from app.models.base import RADIUS_TABLES

    return {
        name: {column.name.lower() for column in table.columns}
        for name, table in Base.metadata.tables.items()
        if name in RADIUS_TABLES
    }


REQUIRED_COLUMNS: dict[str, set[str]] = _mapped_columns()

RECOMMENDED_INDEX_COLUMNS: dict[str, set[str]] = {
    "radacct": {"username", "callingstationid", "acctstarttime", "acctstoptime"},
    "radpostauth": {"username", "authdate"},
}


# Erwartete Datentypfamilien je Spalte. Verglichen wird die Familie, nicht die
# genaue Deklaration: Laengen und Vorzeichen unterscheiden sich zwischen
# FreeRADIUS-Versionen, ein voellig anderer Typ (etwa TEXT statt DATETIME) ist
# dagegen ein echtes Problem und faellt sonst erst zur Laufzeit auf.
EXPECTED_TYPES: dict[str, dict[str, tuple[str, ...]]] = {
    "radacct": {
        "radacctid": ("bigint", "int"),
        "acctstarttime": ("datetime", "timestamp"),
        "acctstoptime": ("datetime", "timestamp"),
        "acctupdatetime": ("datetime", "timestamp"),
        "acctinputoctets": ("bigint", "int"),
        "acctoutputoctets": ("bigint", "int"),
        "username": ("varchar", "char"),
        "nasipaddress": ("varchar", "char"),
    },
    "radpostauth": {
        "id": ("bigint", "int"),
        "authdate": ("datetime", "timestamp"),
        "username": ("varchar", "char"),
    },
    "radcheck": {"username": ("varchar", "char"), "value": ("varchar", "char", "text")},
    "radreply": {"username": ("varchar", "char"), "value": ("varchar", "char", "text")},
    "radusergroup": {"username": ("varchar", "char"), "priority": ("int", "smallint", "bigint")},
    "nas": {"nasname": ("varchar", "char"), "secret": ("varchar", "char")},
}


@dataclass
class SchemaReport:
    ok: bool = True
    missing_tables: list[str] = field(default_factory=list)
    missing_columns: dict[str, list[str]] = field(default_factory=dict)
    missing_indexes: dict[str, list[str]] = field(default_factory=dict)
    wrong_types: dict[str, list[str]] = field(default_factory=dict)

    def as_details(self) -> dict[str, object]:
        return {
            "missing_tables": self.missing_tables,
            "missing_columns": self.missing_columns,
            "missing_indexes": self.missing_indexes,
            "wrong_types": self.wrong_types,
        }

    def summary(self) -> str:
        parts: list[str] = []
        if self.missing_tables:
            parts.append("fehlende Tabellen: " + ", ".join(sorted(self.missing_tables)))
        if self.missing_columns:
            parts.append(
                "fehlende Spalten: "
                + ", ".join(f"{t}({', '.join(c)})" for t, c in sorted(self.missing_columns.items()))
            )
        if self.wrong_types:
            parts.append(
                "unerwartete Spaltentypen: "
                + ", ".join(f"{t}({', '.join(c)})" for t, c in sorted(self.wrong_types.items()))
            )
        return "; ".join(parts) or "Schema in Ordnung"


async def inspect_schema(connection: AsyncConnection, database: str) -> SchemaReport:
    report = SchemaReport()

    rows = (
        await connection.execute(
            text(
                "SELECT table_name, column_name, data_type FROM information_schema.columns "
                "WHERE table_schema = :db"
            ),
            {"db": database},
        )
    ).all()
    present: dict[str, set[str]] = {}
    types: dict[str, dict[str, str]] = {}
    for table, column, data_type in rows:
        name = str(table).lower()
        present.setdefault(name, set()).add(str(column).lower())
        types.setdefault(name, {})[str(column).lower()] = str(data_type).lower()

    for table, columns in REQUIRED_COLUMNS.items():
        if table not in present:
            report.missing_tables.append(table)
            continue
        missing = sorted(columns - present[table])
        if missing:
            report.missing_columns[table] = missing

    for table, expected in EXPECTED_TYPES.items():
        if table in report.missing_tables:
            continue
        actual = types.get(table, {})
        wrong = sorted(
            f"{column} ist {actual[column]}, erwartet {'/'.join(families)}"
            for column, families in expected.items()
            if column in actual and not actual[column].startswith(families)
        )
        if wrong:
            report.wrong_types[table] = wrong

    if not report.missing_tables and not report.missing_columns:
        index_rows = (
            await connection.execute(
                text(
                    "SELECT table_name, column_name FROM information_schema.statistics "
                    "WHERE table_schema = :db AND seq_in_index = 1"
                ),
                {"db": database},
            )
        ).all()
        indexed: dict[str, set[str]] = {}
        for table, column in index_rows:
            indexed.setdefault(str(table).lower(), set()).add(str(column).lower())
        for table, columns in RECOMMENDED_INDEX_COLUMNS.items():
            missing = sorted(columns - indexed.get(table, set()))
            if missing:
                report.missing_indexes[table] = missing

    report.ok = not report.missing_tables and not report.missing_columns and not report.wrong_types
    return report
