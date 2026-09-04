"""Test-Fixtures.

Backend-Tests laufen gegen eine echte MariaDB (Testcontainers), nicht gegen
SQLite – das Verhalten der RADIUS-Tabellen soll realistisch geprueft werden (NFR-5).

Schema-Aufbau erfolgt einmalig ueber eine synchrone Verbindung; je Test wird eine
frische Async-Engine samt geleerter Tabellen bereitgestellt.
"""

from __future__ import annotations

import os

# Muss vor dem ersten Import von app.core.config gesetzt sein: im
# Produktivbetrieb verlangt die Konfiguration eigenstaendige Schluessel.
os.environ.setdefault("FRM_ENVIRONMENT", "test")
from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import pytest
import pytest_asyncio
from sqlalchemy import create_engine, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

SCHEMA_SQL = Path(__file__).resolve().parents[2] / "docker" / "radius-schema.sql"

RADIUS_TABLES = (
    "radcheck",
    "radreply",
    "radgroupcheck",
    "radgroupreply",
    "radusergroup",
    "radacct",
    "radpostauth",
    "nas",
)
MGR_TABLES = (
    "mgr_audit",
    "mgr_subject",
    "mgr_nas_extra",
    "mgr_setting",
    "mgr_stats_snapshot",
    "mgr_account",
)
ALL_TABLES = RADIUS_TABLES + MGR_TABLES


def _statements(sql: str) -> list[str]:
    cleaned = "\n".join(line for line in sql.splitlines() if not line.strip().startswith("--"))
    return [s.strip() for s in cleaned.split(";") if s.strip()]


@pytest.fixture(autouse=True)
def _reset_rate_limiters():
    """Die Zaehler sind Prozesszustand und leben ueber Tests hinweg.

    Ohne dieses Zuruecksetzen erschoepft ein Test, der das Kontingent absichtlich
    ausreizt, das Limit fuer alle nachfolgenden - und zwar nur in der vollen
    Suite, nicht bei einzelner Ausfuehrung.
    """
    from app.api.deps import login_ip_limiter, login_limiter

    login_limiter.clear()
    login_ip_limiter.clear()
    yield
    login_limiter.clear()
    login_ip_limiter.clear()


@pytest.fixture(scope="session")
def sync_database_url() -> Iterator[str]:
    """Startet MariaDB als Container, sofern keine URL vorgegeben ist."""
    external = os.environ.get("FRM_TEST_DATABASE_URL")
    if external:
        yield external
        return

    try:
        from testcontainers.mysql import MySqlContainer
    except ImportError:  # pragma: no cover
        pytest.skip("testcontainers ist nicht installiert")

    container = MySqlContainer(
        "mariadb:11.4", username="radmgr", password="radmgr", dbname="radius"
    )
    container.start()
    try:
        yield (
            f"mysql+pymysql://radmgr:radmgr@{container.get_container_host_ip()}:"
            f"{container.get_exposed_port(3306)}/radius?charset=utf8mb4"
        )
    finally:
        container.stop()


@pytest.fixture(scope="session")
def prepared_database(sync_database_url: str) -> str:
    """Legt das RADIUS-Schema und die mgr_-Tabellen einmalig an."""
    from app.models import Base
    from app.models.base import is_radius_table

    engine = create_engine(sync_database_url)
    with engine.begin() as connection:
        for statement in _statements(SCHEMA_SQL.read_text(encoding="utf-8")):
            connection.execute(text(statement))
        tables = [t for name, t in Base.metadata.tables.items() if not is_radius_table(name)]
        Base.metadata.create_all(connection, tables=tables)
    engine.dispose()
    return sync_database_url


@pytest.fixture
def truncated(prepared_database: str) -> str:
    engine = create_engine(prepared_database)
    with engine.begin() as connection:
        connection.execute(text("SET FOREIGN_KEY_CHECKS = 0"))
        for table in ALL_TABLES:
            connection.execute(text(f"TRUNCATE TABLE {table}"))
        connection.execute(text("SET FOREIGN_KEY_CHECKS = 1"))
    engine.dispose()
    return prepared_database.replace("mysql+pymysql://", "mysql+aiomysql://")


@pytest_asyncio.fixture
async def engine(truncated: str) -> AsyncIterator[object]:
    from app.core import db as db_module

    async_engine = create_async_engine(truncated, pool_pre_ping=True)
    db_module.configure(async_engine)
    try:
        yield async_engine
    finally:
        await async_engine.dispose()


@pytest_asyncio.fixture
async def session(engine) -> AsyncIterator[AsyncSession]:
    async with AsyncSession(engine, expire_on_commit=False) as db_session:
        yield db_session


@pytest.fixture
def admin_principal():
    from app.core.security import Principal
    from app.models.mgr import Role

    return Principal(
        account_id=1,
        username="admin",
        role=Role.ADMINISTRATOR,
        language="de",
        session_id="test",
        absolute_expiry=0,
    )


@pytest.fixture
def operator_principal():
    from app.core.security import Principal
    from app.models.mgr import Role

    return Principal(
        account_id=2,
        username="helpdesk",
        role=Role.OPERATOR,
        language="de",
        session_id="test",
        absolute_expiry=0,
    )
