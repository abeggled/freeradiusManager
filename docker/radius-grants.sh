#!/bin/bash
# ---------------------------------------------------------------------------
# Getrennte Datenbankkonten fuer die Evaluierungsumgebung.
#
# Die Spezifikation (NFR-1) verlangt, dass der Manager nicht das Konto von
# FreeRADIUS verwendet. Der Compose-Stapel bildet das nach: FreeRADIUS erhaelt
# ausschliesslich Rechte auf die RADIUS-Tabellen und sieht die mgr_-Tabellen
# gar nicht.
#
# Als Skript statt als .sql, damit Benutzername, Passwort und Datenbankname aus
# der Umgebung stammen. Fest verdrahtete Werte passten nicht zu den in der .env
# gesetzten Zugangsdaten - FreeRADIUS koennte sich dann nicht anmelden.
#
# Wird nach dem Schema ausgefuehrt (Dateiname sortiert nach 10-radius-schema).
# ---------------------------------------------------------------------------
set -euo pipefail

radius_user="${RADIUS_DB_USER:-freeradius}"
radius_password="${RADIUS_DB_PASSWORD:-freeradius}"
database="${MARIADB_DATABASE:-radius}"

# Zeichenketten fuer SQL maskieren; die Werte stammen aus der .env und duerfen
# die Anweisung nicht verlassen.
quote() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\'/\\\'}"
  printf '%s' "$value"
}

# Bezeichner stehen in Backticks; ein enthaltenes Backtick wird verdoppelt.
quote_ident() {
  local value="$1"
  printf '%s' "${value//\`/\`\`}"
}

user_sql="'$(quote "${radius_user}")'@'%'"
password_sql="'$(quote "${radius_password}")'"
db_sql="\`$(quote_ident "${database}")\`"

grant() {
  printf 'GRANT %s ON %s.%s TO %s;\n' "$1" "${db_sql}" "$2" "${user_sql}"
}

# Das Passwort kommt ueber die Umgebung des Clients, nicht ueber die
# Kommandozeile: Argumente sind in der Prozessliste sichtbar.
{
  printf 'CREATE USER IF NOT EXISTS %s IDENTIFIED BY %s;\n' "${user_sql}" "${password_sql}"

  # Lesen fuer die Autorisierung
  for table in radcheck radreply radgroupcheck radgroupreply radusergroup nas; do
    grant SELECT "${table}"
  done

  # Schreiben fuer Accounting und Post-Auth
  grant "SELECT, INSERT, UPDATE, DELETE" radacct
  grant "SELECT, INSERT" radpostauth

  printf 'FLUSH PRIVILEGES;\n'
} | MYSQL_PWD="${MARIADB_ROOT_PASSWORD:-}" mariadb --protocol=socket -uroot
