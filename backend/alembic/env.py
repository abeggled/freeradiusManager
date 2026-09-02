"""Alembic verwaltet ausschliesslich die ``mgr_``-Tabellen (Abschnitt 4.2).

Das FreeRADIUS-Schema wird als vorhanden vorausgesetzt und hier bewusst
ausgefiltert – so bleiben die offiziellen Schema-Dateien des Servers nutzbar.
"""

from __future__ import annotations

from logging.config import fileConfig
from typing import Any

from sqlalchemy import engine_from_config, pool

from alembic import context
from app.core.config import settings
from app.models import Base, is_radius_table

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Eine bereits gesetzte URL (alembic.ini oder programmatischer Aufruf) hat Vorrang;
# sonst gilt die Konfiguration aus der Umgebung (12-Factor, NFR-3).
if not config.get_main_option("sqlalchemy.url", None):
    config.set_main_option("sqlalchemy.url", settings.sync_database_url)
target_metadata = Base.metadata


def include_object(
    obj: Any, name: str | None, type_: str, reflected: bool, compare_to: Any
) -> bool:
    if type_ == "table" and name is not None:
        return not is_radius_table(name)
    if type_ in ("index", "unique_constraint", "foreign_key_constraint"):
        table = getattr(obj, "table", None)
        if table is not None and is_radius_table(table.name):
            return False
    return True


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        include_object=include_object,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            include_object=include_object,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
