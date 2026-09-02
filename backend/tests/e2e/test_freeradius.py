"""End-to-End gegen einen echten FreeRADIUS-Container (NFR-5).

Der Test legt Benutzer, Gruppe und VLAN ueber den Manager an und authentifiziert
anschliessend mit ``radtest`` gegen einen ``freeradius``-Container, der dieselbe
Datenbank ueber ``rlm_sql`` liest.

Ausfuehren mit ``pytest -m e2e``; ohne erreichbaren Docker-Daemon wird
uebersprungen.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from pathlib import Path

import pytest
import pytest_asyncio
from sqlalchemy import create_engine, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from app.core.security import Principal
from app.models.mgr import Role
from app.schemas.groups import GroupCreate
from app.schemas.users import MembershipIn, UserCreate
from app.services.authlog import AuthLogService
from app.services.groups import GroupService
from app.services.users import UserService

pytestmark = [pytest.mark.e2e, pytest.mark.asyncio]

REPO_ROOT = Path(__file__).resolve().parents[3]
SCHEMA_SQL = REPO_ROOT / "docker" / "radius-schema.sql"
SQL_MODULE = REPO_ROOT / "docker" / "freeradius" / "mods-enabled-sql"

RADIUS_IMAGE = "freeradius/freeradius-server:3.2.7"
MARIADB_IMAGE = "mariadb:11.4"
CLIENT_SECRET = "testing123"


def _statements(sql: str) -> list[str]:
    cleaned = "\n".join(line for line in sql.splitlines() if not line.strip().startswith("--"))
    return [s.strip() for s in cleaned.split(";") if s.strip()]


@pytest.fixture(scope="module")
def radius_stack() -> Iterator[tuple[str, object]]:
    """MariaDB und FreeRADIUS in einem gemeinsamen Docker-Netz."""
    docker = pytest.importorskip("docker")
    testcontainers_core = pytest.importorskip("testcontainers.core.container")
    from testcontainers.core.network import Network

    try:
        docker.from_env().ping()
    except Exception as exc:  # noqa: BLE001 - ohne Docker wird uebersprungen
        pytest.skip(f"Docker nicht verfuegbar: {exc}")

    container_cls = testcontainers_core.DockerContainer
    network = Network()
    network.create()

    database = (
        container_cls(MARIADB_IMAGE)
        .with_env("MARIADB_ROOT_PASSWORD", "root")
        .with_env("MARIADB_DATABASE", "radius")
        .with_env("MARIADB_USER", "radmgr")
        .with_env("MARIADB_PASSWORD", "radmgr")
        .with_exposed_ports(3306)
        .with_network(network)
        .with_network_aliases("db")
    )
    database.start()

    url = (
        f"mysql+pymysql://radmgr:radmgr@{database.get_container_host_ip()}:"
        f"{database.get_exposed_port(3306)}/radius?charset=utf8mb4"
    )
    _wait_for_database(url)

    engine = create_engine(url)
    with engine.begin() as connection:
        for statement in _statements(SCHEMA_SQL.read_text(encoding="utf-8")):
            connection.execute(text(statement))
    engine.dispose()

    # Die mgr_-Tabellen kommen aus der echten Migration – damit wird zugleich
    # geprueft, dass Alembic das RADIUS-Schema unangetastet laesst (Abschnitt 4.2).
    _run_migrations(url)

    radius = (
        container_cls(RADIUS_IMAGE)
        .with_volume_mapping(str(SQL_MODULE), "/etc/raddb/mods-enabled/sql", "ro")
        .with_network(network)
        .with_command("radiusd -f -l stdout")
    )
    radius.start()
    _wait_for_radius(radius)

    try:
        yield url.replace("mysql+pymysql://", "mysql+aiomysql://"), radius
    finally:
        radius.stop()
        database.stop()
        network.remove()


def _run_migrations(sync_url: str) -> None:
    from alembic.config import Config

    from alembic import command

    config = Config(str(REPO_ROOT / "backend" / "alembic.ini"))
    config.set_main_option("script_location", str(REPO_ROOT / "backend" / "alembic"))
    config.set_main_option("sqlalchemy.url", sync_url)
    command.upgrade(config, "head")


def _wait_for_database(url: str, timeout: int = 120) -> None:
    deadline = time.time() + timeout
    last: Exception | None = None
    while time.time() < deadline:
        try:
            engine = create_engine(url, pool_pre_ping=True)
            with engine.connect() as connection:
                connection.execute(text("SELECT 1"))
            engine.dispose()
            return
        except Exception as exc:  # noqa: BLE001 - Startphase des Containers
            last = exc
            time.sleep(2)
    raise RuntimeError(f"MariaDB nicht erreichbar: {last}")


def _wait_for_radius(container: object, timeout: int = 90) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        logs = container.get_logs()[0].decode("utf-8", "replace")  # type: ignore[attr-defined]
        if "Ready to process requests" in logs:
            return
        if "Errors reading or parsing" in logs:
            raise RuntimeError(f"FreeRADIUS-Start fehlgeschlagen:\n{logs[-2000:]}")
        time.sleep(2)
    raise RuntimeError("FreeRADIUS wurde nicht bereit")


def radtest(container: object, username: str, password: str) -> str:
    result = container.exec(  # type: ignore[attr-defined]
        ["radtest", username, password, "127.0.0.1", "0", CLIENT_SECRET]
    )
    return result.output.decode("utf-8", "replace")


@pytest_asyncio.fixture
async def manager_session(radius_stack) -> AsyncSession:
    url, _ = radius_stack
    engine = create_async_engine(url, pool_pre_ping=True)
    async with AsyncSession(engine, expire_on_commit=False) as session:
        yield session
    await engine.dispose()


@pytest.fixture
def actor() -> Principal:
    return Principal(
        account_id=1,
        username="admin",
        role=Role.ADMINISTRATOR,
        language="de",
        session_id="e2e",
        absolute_expiry=0,
    )


async def test_user_created_via_manager_authenticates(radius_stack, manager_session, actor) -> None:
    _, radius = radius_stack

    await GroupService(manager_session).create(
        GroupCreate(groupname="vlan20", vlan="20"), actor=actor
    )
    await UserService(manager_session).create(
        UserCreate(
            username="e2e-anna",
            password="geheim123",
            groups=[MembershipIn(groupname="vlan20")],
        ),
        actor=actor,
    )

    output = radtest(radius, "e2e-anna", "geheim123")
    assert "Access-Accept" in output
    assert 'Tunnel-Private-Group-Id:0 = "20"' in output
    assert "Tunnel-Type:0 = VLAN" in output


async def test_disabled_user_is_rejected_and_visible_in_diagnosis(
    radius_stack, manager_session, actor
) -> None:
    _, radius = radius_stack
    users = UserService(manager_session)

    await users.create(UserCreate(username="e2e-bruno", password="geheim123"), actor=actor)
    assert "Access-Accept" in radtest(radius, "e2e-bruno", "geheim123")

    await users.set_disabled("e2e-bruno", True, actor=actor)
    assert "Access-Reject" in radtest(radius, "e2e-bruno", "geheim123")

    diagnosis = await AuthLogService(manager_session).diagnose("e2e-bruno")
    assert diagnosis.status == "disabled"
    assert "diag.auth_type_reject" in {hint.code for hint in diagnosis.hints}
    assert any(not attempt.accepted for attempt in diagnosis.attempts)

    await users.set_disabled("e2e-bruno", False, actor=actor)
    assert "Access-Accept" in radtest(radius, "e2e-bruno", "geheim123")


async def test_wrong_password_is_rejected(radius_stack, manager_session, actor) -> None:
    _, radius = radius_stack
    await UserService(manager_session).create(
        UserCreate(username="e2e-carla", password="geheim123"), actor=actor
    )
    assert "Access-Reject" in radtest(radius, "e2e-carla", "falsch")
