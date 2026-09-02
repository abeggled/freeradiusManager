"""Pruefung des vorausgesetzten FreeRADIUS-Schemas (Abschnitt 4.2).

Beim Start wird geprueft, ob die erwarteten Tabellen und Spalten existieren.
Bei Abweichungen verweigert die Anwendung den Betrieb mit klarer Meldung.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

REQUIRED_COLUMNS: dict[str, set[str]] = {
    "radcheck": {"id", "username", "attribute", "op", "value"},
    "radreply": {"id", "username", "attribute", "op", "value"},
    "radgroupcheck": {"id", "groupname", "attribute", "op", "value"},
    "radgroupreply": {"id", "groupname", "attribute", "op", "value"},
    "radusergroup": {"username", "groupname", "priority"},
    "radacct": {
        "radacctid",
        "acctsessionid",
        "acctuniqueid",
        "username",
        "nasipaddress",
        "acctstarttime",
        "acctstoptime",
        "acctsessiontime",
        "acctinputoctets",
        "acctoutputoctets",
        "callingstationid",
        "calledstationid",
        "acctterminatecause",
        "framedipaddress",
    },
    "radpostauth": {"id", "username", "pass", "reply", "authdate"},
    "nas": {"id", "nasname", "shortname", "type", "secret"},
}

RECOMMENDED_INDEX_COLUMNS: dict[str, set[str]] = {
    "radacct": {"username", "callingstationid", "acctstarttime", "acctstoptime"},
    "radpostauth": {"username", "authdate"},
}


@dataclass
class SchemaReport:
    ok: bool = True
    missing_tables: list[str] = field(default_factory=list)
    missing_columns: dict[str, list[str]] = field(default_factory=dict)
    missing_indexes: dict[str, list[str]] = field(default_factory=dict)

    def as_details(self) -> dict[str, object]:
        return {
            "missing_tables": self.missing_tables,
            "missing_columns": self.missing_columns,
            "missing_indexes": self.missing_indexes,
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
        return "; ".join(parts) or "Schema in Ordnung"


async def inspect_schema(connection: AsyncConnection, database: str) -> SchemaReport:
    report = SchemaReport()

    rows = (
        await connection.execute(
            text(
                "SELECT table_name, column_name FROM information_schema.columns "
                "WHERE table_schema = :db"
            ),
            {"db": database},
        )
    ).all()
    present: dict[str, set[str]] = {}
    for table, column in rows:
        present.setdefault(str(table).lower(), set()).add(str(column).lower())

    for table, columns in REQUIRED_COLUMNS.items():
        if table not in present:
            report.missing_tables.append(table)
            continue
        missing = sorted(columns - present[table])
        if missing:
            report.missing_columns[table] = missing

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

    report.ok = not report.missing_tables and not report.missing_columns
    return report
