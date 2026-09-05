# Schritt für Schritt: Installation auf einer Debian-13-VM

Vollständige Einrichtung von MariaDB, FreeRADIUS und dem freeradiusManager auf
einer frischen Debian 13 (Trixie) – alles aus Debian-Paketen, ohne Container.
Der Manager läuft als Python-Anwendung unter `systemd`.

Ergänzend beschreibt [INSTALLATION.md](INSTALLATION.md) die Anbindung von UniFi
und die VLAN-Zuweisung; die Schritte 12 und 13 verweisen darauf.

**Annahmen der Beispiele** – bitte durchgängig ersetzen:

| Platzhalter | Beispielwert |
| --- | --- |
| Hostname des Managers | `radius.example.org` |
| Netz der Access Points / Switches | `10.0.10.0/24` |
| Datenbank | `radius` |

Alle Befehle als `root` oder mit `sudo`.

---

## 1. System vorbereiten

```bash
apt update && apt full-upgrade -y
apt install -y ca-certificates curl git
timedatectl set-timezone Europe/Zurich
```

Eine korrekte Uhrzeit ist nicht optional: TOTP-Codes, Ablaufdaten und die
Session-Laufzeit hängen daran. `systemd-timesyncd` ist in Debian bereits aktiv –
prüfen mit `timedatectl status` (erwartet: `System clock synchronized: yes`).

---

## 2. MariaDB installieren

```bash
apt install -y mariadb-server
mariadb-secure-installation
```

Bei `mariadb-secure-installation` genügen die Vorgaben; das Root-Konto meldet
sich unter Debian über den Unix-Socket an, ein Root-Passwort ist nicht nötig.

Die Datenbank bleibt lokal. Nur wenn FreeRADIUS oder der Manager auf einer
anderen VM laufen, in `/etc/mysql/mariadb.conf.d/50-server.cnf` die
`bind-address` anpassen und den Zugriff per Firewall auf diese Hosts begrenzen.

---

## 3. Datenbank und Konten anlegen

```bash
mariadb
```

```sql
CREATE DATABASE radius CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

Die Kollation muss auf `_ci` enden – der Manager vergleicht ohne Rücksicht auf
Gross- und Kleinschreibung: `Staff` und `staff` bezeichnen dieselbe Gruppe,
`Max` und `max` denselben Benutzer.

Die RADIUS-Tabellen erben diese Kollation beim Schema-Import, und die
`mgr_`-Tabellen werden von Migration `0010` daran ausgerichtet. Beide Seiten
tragen damit dieselbe – nötig, weil schon die Benutzerliste `radcheck` und
`mgr_subject` in einer Abfrage vereinigt.

Drei getrennte Konten – der Manager darf nicht das Konto von FreeRADIUS
verwenden (Spezifikation, NFR-1):

```sql
-- 1) FreeRADIUS: liest zur Autorisierung, schreibt Accounting und Post-Auth
CREATE USER 'freeradius'@'localhost' IDENTIFIED BY 'GEHEIM-1';

-- 2) Manager im Betrieb: kein DDL, Accounting und Auth-Log nur lesend
CREATE USER 'radmgr'@'localhost' IDENTIFIED BY 'GEHEIM-2';

-- 3) Nur für die Migration; wird in Schritt 10 wieder gelöscht
CREATE USER 'radmgr_migrate'@'localhost' IDENTIFIED BY 'GEHEIM-3';
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, DROP, REFERENCES
  ON radius.* TO 'radmgr_migrate'@'localhost';
```

> **Die Rechte auf die einzelnen Tabellen folgen erst in Schritt 5.** MariaDB
> weist ein `GRANT` auf eine Tabelle, die es noch nicht gibt, mit
> `ERROR 1146 … doesn't exist` ab – die RADIUS-Tabellen entstehen aber erst mit
> dem Schema-Import. Nur `radmgr_migrate` bekommt sein Recht schon hier, weil es
> auf der ganzen Datenbank (`radius.*`) liegt und keine Tabelle voraussetzt.

`\q` beendet den Client.

---

## 4. FreeRADIUS installieren

```bash
apt install -y freeradius freeradius-mysql freeradius-utils
```

* `freeradius-mysql` liefert `rlm_sql_mysql` – ohne das Paket findet der Server
  den Treiber nicht.
* `freeradius-utils` liefert `radtest` und `radclient` für die Prüfschritte.

Konfigurationsverzeichnis unter Debian: `/etc/freeradius/3.0` (der Pfad heisst
auch bei FreeRADIUS 3.2 so). Der Dienst läuft als Benutzer `freerad`.

---

## 5. RADIUS-Schema einspielen und Rechte vergeben

Das Schema stammt aus der Installation selbst, nicht aus diesem Projekt:

```bash
mariadb radius < /etc/freeradius/3.0/mods-config/sql/main/mysql/schema.sql
```

Prüfen:

```bash
mariadb -e "SHOW TABLES;" radius
```

Erwartet werden `nas`, `radacct`, `radcheck`, `radgroupcheck`, `radgroupreply`,
`radpostauth`, `radreply` und `radusergroup`.

> `docker/radius-schema.sql` aus diesem Repository ist nur eine Nachbildung für
> Entwicklung und Tests. Gegen eine echte Installation gilt das Schema des
> Servers.

Prüfen, dass die Tabellen die Kollation der Datenbank geerbt haben:

```bash
mariadb -N -B -e "SELECT DISTINCT TABLE_COLLATION FROM information_schema.TABLES \
                  WHERE TABLE_SCHEMA='radius';"
```

Erwartet wird genau eine Zeile mit einer `_ci`-Kollation. Erscheinen mehrere,
ist das kein Hindernis – Migration `0010` in Schritt 10 gleicht die
`mgr_`-Tabellen an die RADIUS-Seite an.

Danach – und erst jetzt – die Rechte auf die einzelnen Tabellen. MariaDB kennt
keine Tabellen-Wildcards, deshalb die lange Liste:

```bash
mariadb radius <<'SQL'
GRANT SELECT ON radius.radcheck      TO 'freeradius'@'localhost';
GRANT SELECT ON radius.radreply      TO 'freeradius'@'localhost';
GRANT SELECT ON radius.radgroupcheck TO 'freeradius'@'localhost';
GRANT SELECT ON radius.radgroupreply TO 'freeradius'@'localhost';
GRANT SELECT ON radius.radusergroup  TO 'freeradius'@'localhost';
GRANT SELECT ON radius.nas           TO 'freeradius'@'localhost';
GRANT SELECT, INSERT, UPDATE, DELETE ON radius.radacct     TO 'freeradius'@'localhost';
GRANT SELECT, INSERT                 ON radius.radpostauth TO 'freeradius'@'localhost';

GRANT SELECT ON radius.radacct     TO 'radmgr'@'localhost';
GRANT SELECT ON radius.radpostauth TO 'radmgr'@'localhost';
GRANT SELECT, INSERT, UPDATE, DELETE ON radius.radcheck      TO 'radmgr'@'localhost';
GRANT SELECT, INSERT, UPDATE, DELETE ON radius.radreply      TO 'radmgr'@'localhost';
GRANT SELECT, INSERT, UPDATE, DELETE ON radius.radgroupcheck TO 'radmgr'@'localhost';
GRANT SELECT, INSERT, UPDATE, DELETE ON radius.radgroupreply TO 'radmgr'@'localhost';
GRANT SELECT, INSERT, UPDATE, DELETE ON radius.radusergroup  TO 'radmgr'@'localhost';
GRANT SELECT, INSERT, UPDATE, DELETE ON radius.nas           TO 'radmgr'@'localhost';
SQL
```

Kontrollieren – die Ausgabe muss mehr als nur `GRANT USAGE ON *.*` enthalten:

```bash
mariadb -e "SHOW GRANTS FOR 'freeradius'@'localhost';"
```

Die `mgr_`-Tabellen fehlen hier bewusst: sie entstehen erst in Schritt 10 und
werden dort freigegeben.

---

## 6. FreeRADIUS an die Datenbank binden

Modul aktivieren:

```bash
ln -s ../mods-available/sql /etc/freeradius/3.0/mods-enabled/sql
```

In `/etc/freeradius/3.0/mods-available/sql` die folgenden Werte setzen (die
Datei enthält die Einträge bereits, teils auskommentiert):

```
	dialect = "mysql"
	driver = "rlm_sql_${dialect}"

	server = "localhost"
	port = 3306
	login = "freeradius"
	password = "GEHEIM-1"
	radius_db = "radius"

	# NAS-Clients aus der Tabelle "nas" lesen - der Manager pflegt sie dort (FR-4)
	read_clients = yes
	client_table = "nas"

	read_groups = yes
```

> **Den `tls`-Block in `mysql { … }` auskommentiert lassen.** Die Datei enthält
> einen Beispielblock mit Pfaden wie `/etc/ssl/certs/my_ca.crt`. Sobald darin
> eine Datei gesetzt ist, schaltet FreeRADIUS TLS zur Datenbank ein und bricht
> mit `Unable to check file … No such file or directory` und
> `Instantiation failed for module "sql"` ab. Bei einer lokalen MariaDB wird
> TLS nicht gebraucht:
>
> ```
> 	mysql {
> 		#tls {
> 		#	ca_file = "/etc/ssl/certs/my_ca.crt"
> 		#	...
> 		#}
> 		warnings = auto
> 	}
> ```
>
> Liegt die Datenbank auf einem anderen Host und soll TLS verwenden, `ca_file`
> auf das echte CA-Zertifikat zeigen lassen und die Zeilen für
> Client-Zertifikate auskommentiert lassen.

Die Datei enthält jetzt ein Passwort:

```bash
chown root:freerad /etc/freeradius/3.0/mods-available/sql
chmod 640 /etc/freeradius/3.0/mods-available/sql
```

In `/etc/freeradius/3.0/sites-enabled/default` **und**
`/etc/freeradius/3.0/sites-enabled/inner-tunnel` jeweils in den Abschnitten
`authorize`, `accounting`, `session` und `post-auth` die Zeile mit `sql`
entkommentieren **und das führende Minus entfernen**:

```
	#	-sql        ->        	sql
```

Das Minus unterdrückt Fehler des Moduls. Mit ihm liefe der Server auch dann
weiter, wenn die Datenbankverbindung falsch konfiguriert ist – jede Anmeldung
schlüge fehl, ohne dass das Log den Grund nennt.

---

## 7. EAP für WPA-Enterprise

In `/etc/freeradius/3.0/mods-available/eap`:

```
	default_eap_type = peap
```

PEAP/MSCHAPv2 ist der Weg, den Windows-, macOS-, iOS- und Android-Clients über
UniFi gehen. MSCHAPv2 verlangt ein umkehrbar gespeichertes Passwort – im Manager
also den Credential-Typ `Cleartext-Password` oder `NT-Password`.

Für den Produktivbetrieb das Serverzertifikat in `/etc/freeradius/3.0/certs`
durch eines ersetzen, dem die Clients vertrauen. Die mitgelieferten
Testzertifikate sind öffentlich bekannt und taugen nur für den ersten Testlauf.

---

## 8. FreeRADIUS prüfen

Testbenutzer direkt in der Datenbank anlegen (später übernimmt das der Manager):

```bash
mariadb radius -e "INSERT INTO radcheck (username, attribute, op, value)
                   VALUES ('testuser', 'Cleartext-Password', ':=', 'testpw');"
```

Dienst anhalten und im Vordergrund mit Debug-Ausgabe starten:

```bash
systemctl stop freeradius
freeradius -X
```

Im Log müssen erscheinen:

* `rlm_sql (sql): Connected new DB handle` – die Datenbankverbindung steht.
* die aus der Datenbank gelesene Client-Liste (bei leerer `nas`-Tabelle noch keine).

In einer zweiten Sitzung:

```bash
radtest testuser testpw 127.0.0.1 0 testing123
```

Erwartet wird `Received Access-Accept`. `testing123` ist das Shared Secret des
vordefinierten Clients `localhost` aus `clients.conf` – es gilt nur für Anfragen
von 127.0.0.1 und bleibt für die spätere Diagnose nützlich.

Danach `Ctrl-C` und:

```bash
systemctl start freeradius
systemctl enable freeradius
```

Testbenutzer wieder entfernen:

```bash
mariadb radius -e "DELETE FROM radcheck WHERE username = 'testuser';"
```

---

## 9. Manager: Quellcode und Abhängigkeiten

```bash
apt install -y python3 python3-venv python3-dev build-essential libffi-dev \
               pkg-config nodejs npm
```

Versionen prüfen – der Manager verlangt Python ≥ 3.12 und baut die Oberfläche
mit Node ≥ 20:

```bash
python3 --version && node --version
```

Dienstkonto und Quellcode:

```bash
useradd --system --home-dir /opt/freeradius-manager --shell /usr/sbin/nologin frm
git clone https://github.com/abeggled/freeradiusManager.git /opt/freeradius-manager
```

Oberfläche bauen – die Ausgabe landet in `backend/static`, von wo das Backend
sie ausliefert:

```bash
cd /opt/freeradius-manager/frontend
npm ci
npm run build
```

Virtuelle Umgebung und Installation. Die Installation erfolgt **editierbar**
(`-e`): das Backend sucht die Oberfläche relativ zum Quellverzeichnis, bei einer
Kopie nach `site-packages` bliebe die Weboberfläche leer.

```bash
python3 -m venv /opt/freeradius-manager/.venv
/opt/freeradius-manager/.venv/bin/pip install --upgrade pip
/opt/freeradius-manager/.venv/bin/pip install -e /opt/freeradius-manager/backend
chown -R frm:frm /opt/freeradius-manager
```

---

## 10. Konfiguration und Migration

Zwei Schlüssel erzeugen – ohne sie startet der Manager im Produktivbetrieb
bewusst nicht:

```bash
python3 -c "import secrets; print('FRM_SECRET_KEY=' + secrets.token_urlsafe(48))"
python3 -c "import base64,os; print('FRM_COA_SECRET_KEY=' + base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip('='))"
```

`/etc/freeradius-manager.env` anlegen (Format: `SCHLUESSEL=Wert`, ohne
Anführungszeichen, ohne `export`):

```ini
FRM_ENVIRONMENT=production

FRM_DB_HOST=127.0.0.1
FRM_DB_PORT=3306
FRM_DB_NAME=radius
FRM_DB_USER=radmgr
FRM_DB_PASSWORD=GEHEIM-2

FRM_SECRET_KEY=...aus dem Befehl oben...
FRM_COA_SECRET_KEY=...aus dem Befehl oben...

# Hinter dem Reverse-Proxy aus Schritt 12
FRM_COOKIE_SECURE=true
FRM_TRUSTED_PROXIES=127.0.0.1/32
FRM_ALLOWED_ORIGINS=https://radius.example.org

# Nur wirksam, solange noch kein Administrator existiert
FRM_BOOTSTRAP_ADMIN_USERNAME=admin
FRM_BOOTSTRAP_ADMIN_PASSWORD=EinLangesStartpasswort

# Muss zum MAC-Format in UniFi passen (Schritt 13)
FRM_DEFAULT_MAC_FORMAT=colon_lower
```

Die Datei enthält Schlüssel und Passwörter:

```bash
chown root:frm /etc/freeradius-manager.env
chmod 640 /etc/freeradius-manager.env
```

Jetzt die `mgr_`-Tabellen anlegen – einmalig mit dem Migrationskonto, weil das
Betriebskonto dauerhaft keine DDL-Rechte haben soll:

```bash
cd /opt/freeradius-manager/backend
set -a; . /etc/freeradius-manager.env; set +a
FRM_DB_USER=radmgr_migrate FRM_DB_PASSWORD=GEHEIM-3 \
  /opt/freeradius-manager/.venv/bin/alembic upgrade head
```

Alembic fasst ausschliesslich die `mgr_`-Tabellen an; das RADIUS-Schema bleibt
unverändert. Anschliessend dem Betriebskonto die neuen Tabellen freigeben und
das Migrationskonto löschen:

```bash
mariadb
```

```sql
GRANT SELECT, INSERT, UPDATE, DELETE ON radius.mgr_account            TO 'radmgr'@'localhost';
GRANT SELECT, INSERT, UPDATE, DELETE ON radius.mgr_audit              TO 'radmgr'@'localhost';
GRANT SELECT, INSERT, UPDATE, DELETE ON radius.mgr_subject            TO 'radmgr'@'localhost';
GRANT SELECT, INSERT, UPDATE, DELETE ON radius.mgr_nas_extra          TO 'radmgr'@'localhost';
GRANT SELECT, INSERT, UPDATE, DELETE ON radius.mgr_setting            TO 'radmgr'@'localhost';
GRANT SELECT, INSERT, UPDATE, DELETE ON radius.mgr_stats_snapshot     TO 'radmgr'@'localhost';
GRANT SELECT, INSERT, UPDATE, DELETE ON radius.mgr_session_revocation TO 'radmgr'@'localhost';
GRANT SELECT ON radius.alembic_version TO 'radmgr'@'localhost';

DROP USER 'radmgr_migrate'@'localhost';
```

---

## 11. systemd-Unit

`/etc/systemd/system/freeradius-manager.service`:

```ini
[Unit]
Description=freeradiusManager
Documentation=https://github.com/abeggled/freeradiusManager
After=network-online.target mariadb.service
Wants=network-online.target
Requires=mariadb.service

[Service]
Type=exec
User=frm
Group=frm
WorkingDirectory=/opt/freeradius-manager/backend
EnvironmentFile=/etc/freeradius-manager.env
Environment=PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
ExecStart=/opt/freeradius-manager/.venv/bin/uvicorn app.main:app \
          --host 127.0.0.1 --port 8000 \
          --proxy-headers --forwarded-allow-ips=127.0.0.1
Restart=on-failure
RestartSec=5

# Haertung
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

[Install]
WantedBy=multi-user.target
```

Der Dienst hört bewusst nur auf `127.0.0.1` – erreichbar wird er über den
Reverse-Proxy aus Schritt 12. `ProtectSystem=strict` macht das Dateisystem
schreibgeschützt; die Anwendung schreibt nichts ausserhalb der Datenbank.

Migrationen laufen bewusst **nicht** beim Start: das Betriebskonto hat keine
DDL-Rechte. Nach einem Update wird Schritt 10 wiederholt.

```bash
systemctl daemon-reload
systemctl enable --now freeradius-manager
systemctl status freeradius-manager --no-pager
```

`Type=exec` meldet den Dienst als gestartet, sobald der Prozess läuft – nicht
erst, wenn uvicorn den Port gebunden hat. Ein `curl` direkt danach liefe ins
Leere. Deshalb mit Wiederholung prüfen:

```bash
curl -fsS --retry 10 --retry-delay 1 --retry-connrefused http://127.0.0.1:8000/healthz && echo
curl -fsS http://127.0.0.1:8000/readyz && echo
```

Beide müssen `{"status":"ok"}` liefern; `readyz` prüft zusätzlich die
Datenbankverbindung. Antwortet der Port gar nicht, nennt das Journal den Grund:

```bash
ss -lntp | grep 8000
journalctl -u freeradius-manager -n 60 --no-pager
```

Laufende Ausgabe: `journalctl -u freeradius-manager -f`.

---

## 12. Reverse-Proxy mit TLS

Die Oberfläche gehört nicht unverschlüsselt ins Netz – das Session-Cookie ist
mit `FRM_COOKIE_SECURE=true` ohne TLS gar nicht verwendbar.

```bash
apt install -y nginx
```

`/etc/nginx/sites-available/freeradius-manager`:

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name radius.example.org;

    ssl_certificate     /etc/ssl/certs/radius.example.org.pem;
    ssl_certificate_key /etc/ssl/private/radius.example.org.key;

    # CSV-Import: das Backend erlaubt 5 MiB je Datei. Die Vorgabe von nginx
    # liegt bei 1 MiB und wiese groessere Importe schon hier ab.
    client_max_body_size 6m;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host              $host;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

server {
    listen 80;
    server_name radius.example.org;
    return 301 https://$host$request_uri;
}
```

```bash
ln -s /etc/nginx/sites-available/freeradius-manager /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx
```

`FRM_TRUSTED_PROXIES=127.0.0.1/32` sorgt dafür, dass der Manager das
`X-Forwarded-For` von nginx auswertet. Ohne diesen Eintrag stünde in Audit-Log
und Rate-Limits immer `127.0.0.1` – und mit einem zu weiten Eintrag liessen sich
die Limits mit gefälschten Headern umgehen.

---

## 13. Erste Anmeldung

`https://radius.example.org` aufrufen und mit `FRM_BOOTSTRAP_ADMIN_USERNAME` /
`FRM_BOOTSTRAP_ADMIN_PASSWORD` anmelden. Der Administrator muss beim ersten Mal
TOTP einrichten – ohne zweiten Faktor kommt er nicht in die Anwendung.

Danach in `/etc/freeradius-manager.env` `FRM_BOOTSTRAP_ADMIN_PASSWORD` leeren
und `systemctl restart freeradius-manager`. Der Wert wirkt zwar nur, solange
kein aktiver Administrator existiert, hat aber keinen Grund mehr, auf der
Platte zu stehen.

Nächste Schritte in der Oberfläche:

1. **NAS anlegen** – für UniFi genügt ein Eintrag mit dem Netz der Access
   Points, z. B. `10.0.10.0/24`, plus Shared Secret.
2. **Gruppe mit VLAN anlegen** – der geführte Dialog setzt `Tunnel-Type`,
   `Tunnel-Medium-Type` und `Tunnel-Private-Group-Id` gemeinsam.
3. **Benutzer anlegen** und der Gruppe zuordnen.

Details zu UniFi und zur VLAN-Zuweisung: [INSTALLATION.md, Abschnitte 6 und
7](INSTALLATION.md#6-unifi-als-nas).

> **Nach jeder NAS-Änderung** muss FreeRADIUS die Client-Liste neu lesen:
> `systemctl reload freeradius`. Der Manager weist darauf hin, startet den
> Dienst aber nicht selbst.

---

## 14. Firewall

```bash
apt install -y nftables
```

Freizugeben sind:

| Port | Protokoll | Von |
| --- | --- | --- |
| 1812 | UDP | Netz der Access Points und Switches |
| 1813 | UDP | dasselbe Netz (Accounting) |
| 443 | TCP | Netz der Administratoren |
| 22 | TCP | Netz der Administratoren |

Ausgehend muss der Manager die NAS-Geräte auf **UDP 3799** erreichen, sonst
bleiben Disconnect und VLAN-Wechsel per CoA wirkungslos. Port 3306 bleibt
lokal – die Datenbank wird von aussen nicht gebraucht.

---

## 15. Ende-zu-Ende prüfen

```bash
# 1. Im Manager einen Benutzer anlegen, dann:
radtest BENUTZER PASSWORT 127.0.0.1 0 testing123
```

Erwartet wird `Access-Accept`; bei zugewiesenem VLAN enthält die Antwort die
drei Tunnel-Attribute. Für den echten Client-Weg (PEAP/MSCHAPv2) eignet sich
`eapol_test` aus `wpa_supplicant`.

Danach in der Oberfläche:

* **Diagnose** zeigt die Einträge aus `radpostauth` samt Klartext-Hinweis.
* **Sessions** zeigt laufende und beendete Sessions aus `radacct` – gefüllt nur,
  wenn im UniFi-RADIUS-Profil auch ein Accounting-Server eingetragen ist.

---

## 16. Betrieb

**Aktualisieren:**

```bash
cd /opt/freeradius-manager
git pull
cd frontend && npm ci && npm run build
/opt/freeradius-manager/.venv/bin/pip install -e /opt/freeradius-manager/backend
chown -R frm:frm /opt/freeradius-manager
# Migration wie in Schritt 10, mit einem temporaeren DDL-Konto
systemctl restart freeradius-manager
```

**Sichern** – die Datenbank enthält Benutzer, Shared Secrets und das Audit-Log:

```bash
mariadb-dump --single-transaction --routines radius > /var/backups/radius-$(date +%F).sql
```

Mitzusichern sind ausserdem `/etc/freeradius-manager.env` (ohne
`FRM_COA_SECRET_KEY` sind die gespeicherten CoA-Secrets nicht mehr
entschlüsselbar) und `/etc/freeradius/3.0`.

**Verschlüsselung auf Speicherebene** ist empfohlen: `Cleartext-Password` und
Shared Secrets können anwendungsseitig nicht verschlüsselt werden, weil
FreeRADIUS sie im Klartext lesen muss. Der Schutz liegt bei den DB-Rechten aus
den Schritten 3 und 5, der Plattenverschlüsselung und der restriktiven Anzeige
in der Oberfläche.

---

## 17. Wenn etwas nicht funktioniert

| Symptom | Ursache |
| --- | --- |
| `Access denied for user 'freeradius'@'localhost' to database 'radius'` | Tabellenrechte fehlen – das Passwort stimmt (sonst stuende dort `using password: YES`). Die `GRANT`-Zeilen aus Schritt 5 nachholen |
| `Instantiation failed for module "sql"`, davor `Unable to check file … my_ca.crt` | der `tls`-Block in `mysql { … }` ist aktiv; bei lokaler Datenbank auskommentieren |
| `freeradius -X` meldet `Connection refused` bei SQL | falsche Zugangsdaten in `mods-available/sql`, oder das Modul ist mit `-sql` eingebunden und verschluckt den Fehler |
| `Ignoring request … unknown client` | Gerät fehlt in der `nas`-Tabelle, oder nach der Änderung kein `systemctl reload freeradius` |
| `Access-Reject` trotz vorhandenem Benutzer | Passwort-Attribut passt nicht zur Methode: PEAP/MSCHAPv2 verlangt `Cleartext-Password` oder `NT-Password` |
| `curl` auf Port 8000 scheitert, der Dienst ist aber `active (running)` | zu früh gemessen: uvicorn bindet den Port erst nach dem Start. Mit `--retry-connrefused` prüfen; bleibt es dabei, `journalctl -u freeradius-manager` lesen |
| `Illegal mix of collations for operation 'UNION'` | `mgr_`- und RADIUS-Tabellen haben verschiedene Kollationen. Migration `0010` gleicht das an – `alembic upgrade head` nachholen (Schritt 10) |
| `radius_schema_missing_indexes` im Log | nur ein Hinweis; der Betrieb läuft. Die genannten Indizes beschleunigen Sessions- und Diagnose-Ansicht bei grossen Datenmengen |
| Manager startet nicht, `FRM_SECRET_KEY` wird verlangt | Schlüssel fehlt in `/etc/freeradius-manager.env`, oder die Datei ist für `frm` nicht lesbar |
| Manager startet nicht, meldet Schemaabweichung | in der Datenbank liegt ein abweichendes `rlm_sql`-Schema – FreeRADIUS-Version prüfen |
| Oberfläche bleibt weiss, API antwortet | `npm run build` fehlte, oder das Backend wurde ohne `-e` installiert und findet `backend/static` nicht |
| Anmeldung schlägt mit CSRF-Fehler fehl | `FRM_ALLOWED_ORIGINS` passt nicht zur aufgerufenen Adresse |
| Audit-Log zeigt immer `127.0.0.1` | `FRM_TRUSTED_PROXIES` fehlt, oder nginx setzt `X-Forwarded-For` nicht |
| CSV-Import bricht bei grossen Dateien ab | `client_max_body_size` in nginx zu klein |
| CoA ohne Wirkung | am NAS nicht aktiviert, falsches CoA-Secret, oder UDP 3799 ausgehend blockiert |
