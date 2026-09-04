-- ---------------------------------------------------------------------------
-- Getrennte Datenbankkonten fuer die Evaluierungsumgebung.
--
-- Die Spezifikation (NFR-1) verlangt, dass der Manager nicht das Konto von
-- FreeRADIUS verwendet. Der Compose-Stapel bildet das nach: FreeRADIUS erhaelt
-- ausschliesslich Rechte auf die RADIUS-Tabellen und sieht die mgr_-Tabellen
-- gar nicht.
--
-- Wird nach dem Schema ausgefuehrt (Dateiname sortiert nach 10-radius-schema).
-- ---------------------------------------------------------------------------

CREATE USER IF NOT EXISTS 'freeradius'@'%' IDENTIFIED BY 'freeradius';

-- Lesen fuer die Autorisierung
GRANT SELECT ON radius.radcheck TO 'freeradius'@'%';
GRANT SELECT ON radius.radreply TO 'freeradius'@'%';
GRANT SELECT ON radius.radgroupcheck TO 'freeradius'@'%';
GRANT SELECT ON radius.radgroupreply TO 'freeradius'@'%';
GRANT SELECT ON radius.radusergroup TO 'freeradius'@'%';
GRANT SELECT ON radius.nas TO 'freeradius'@'%';

-- Schreiben fuer Accounting und Post-Auth
GRANT SELECT, INSERT, UPDATE, DELETE ON radius.radacct TO 'freeradius'@'%';
GRANT SELECT, INSERT ON radius.radpostauth TO 'freeradius'@'%';

FLUSH PRIVILEGES;
