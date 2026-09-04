"""Aufbau der Datenbank-URL."""

from __future__ import annotations

from app.core.config import Settings


def test_credentials_with_reserved_characters_are_encoded() -> None:
    """Generierte Passwoerter enthalten regelmaessig @, / oder %."""
    config = Settings(db_user="rad@mgr", db_password="p@ss/wo#rd%1", db_host="db", db_name="radius")
    assert "rad%40mgr" in config.database_url
    assert "p%40ss%2Fwo%23rd%251" in config.database_url
    assert config.database_url.endswith("@db:3306/radius?charset=utf8mb4")
    assert config.sync_database_url.startswith("mysql+pymysql://")


def test_plain_credentials_stay_readable() -> None:
    config = Settings(db_user="radmgr", db_password="radmgr", db_host="db", db_name="radius")
    assert config.database_url == ("mysql+aiomysql://radmgr:radmgr@db:3306/radius?charset=utf8mb4")
