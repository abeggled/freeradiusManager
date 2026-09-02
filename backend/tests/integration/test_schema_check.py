"""Schemapruefung beim Start (Abschnitt 4.2)."""

from __future__ import annotations

import pytest
from sqlalchemy import text

from app.repositories.radius.schema import inspect_schema

pytestmark = pytest.mark.asyncio


async def _database_name(connection) -> str:
    return str(await connection.scalar(text("SELECT DATABASE()")))


async def test_valid_schema_passes(engine) -> None:
    async with engine.connect() as connection:
        report = await inspect_schema(connection, await _database_name(connection))
    assert report.ok
    assert report.missing_tables == []
    assert report.missing_indexes == {}


async def test_missing_table_is_reported(engine) -> None:
    async with engine.begin() as connection:
        await connection.execute(text("RENAME TABLE radpostauth TO radpostauth_backup"))
    try:
        async with engine.connect() as connection:
            report = await inspect_schema(connection, await _database_name(connection))
        assert not report.ok
        assert "radpostauth" in report.missing_tables
        assert "radpostauth" in report.summary()
    finally:
        async with engine.begin() as connection:
            await connection.execute(text("RENAME TABLE radpostauth_backup TO radpostauth"))


async def test_missing_column_is_reported(engine) -> None:
    async with engine.begin() as connection:
        await connection.execute(text("ALTER TABLE radcheck DROP COLUMN op"))
    try:
        async with engine.connect() as connection:
            report = await inspect_schema(connection, await _database_name(connection))
        assert not report.ok
        assert report.missing_columns["radcheck"] == ["op"]
    finally:
        async with engine.begin() as connection:
            await connection.execute(
                text("ALTER TABLE radcheck ADD COLUMN op CHAR(2) NOT NULL DEFAULT '=='")
            )
