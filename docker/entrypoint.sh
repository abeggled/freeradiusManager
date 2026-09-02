#!/bin/sh
# Startskript des Anwendungscontainers.
#
# Vor dem Start werden die Manager-Tabellen migriert. Das RADIUS-Schema bleibt
# unangetastet – Alembic filtert es aus (Spezifikation, Abschnitt 4.2).
set -eu

if [ "${FRM_RUN_MIGRATIONS:-1}" = "1" ]; then
    echo "{\"event\":\"migrating\",\"level\":\"info\"}"
    alembic upgrade head
fi

exec "$@"
