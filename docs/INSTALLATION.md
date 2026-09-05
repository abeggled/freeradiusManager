# Installation: MariaDB, FreeRADIUS und der Manager

Diese Anleitung beschreibt, wie eine FreeRADIUS-Instanz mit MariaDB-Backend
aufgesetzt wird, so dass sie vom freeradiusManager verwaltet und in einer
UniFi-Umgebung als RADIUS-Server verwendet werden kann – einschliesslich der
VLAN-Zuweisung.

Der Manager verändert die Konfiguration von FreeRADIUS **nicht**. Er schreibt
ausschliesslich in die Tabellen des `rlm_sql`-Moduls; die
Authentifizierungsentscheidung trifft weiterhin FreeRADIUS allein
(Spezifikation, Abschnitt 4.1).

## 1. Aufbau

```
UniFi AP / Switch  --1812/1813 UDP-->  FreeRADIUS  --3306-->  MariaDB
       ^                                                        ^
       +----------------3799 UDP (CoA/DM)-----------------------+---- Manager (HTTPS)
```

| Komponente | Rolle | Datenbankkonto |
| --- | --- | --- |
| FreeRADIUS | prüft Anmeldungen, schreibt Accounting | `freeradius` – nur RADIUS-Tabellen |
| Manager | pflegt Benutzer, Gruppen, NAS, sendet CoA | `radmgr` – RADIUS- und `mgr_`-Tabellen |
| UniFi AP/Switch | NAS/RADIUS-Client | – |

Getrennte Datenbankkonten sind Vorgabe (NFR-1): FreeRADIUS darf die
`mgr_`-Tabellen nicht sehen, der Manager braucht kein Konto mit
Accounting-Schreibrechten auf Systemebene.

## 2. Schnellweg: Evaluierungsumgebung

Für einen Testaufbau genügt der mitgelieferte Compose-Stapel – er enthält
MariaDB, FreeRADIUS 3.2 und den Manager, bereits mit getrennten
Datenbankkonten:

```bash
cp .env.example .env && docker compose up -d --build
```

Details siehe [README](../README.md#schnellstart-evaluierung). Wer produktiv
gegen eigene Dienste fährt, folgt den Abschnitten 3 bis 6.

## 3. MariaDB einrichten

Getestet mit MariaDB 10.6 und 11.4.

```bash
sudo apt install mariadb-server
sudo mariadb-secure-installation
```

Datenbank anlegen:

```sql
CREATE DATABASE radius CHARACTER SET utf8mb4;
```

Bewusst ohne `COLLATE`: `schema.sql` von FreeRADIUS setzt an seinen Tabellen
`DEFAULT CHARSET=utf8mb4` ohne Kollation, sie erhalten damit die Vorgabe des
Servers. Weicht die Vorgabe der Datenbank davon ab, bekämen die
`mgr_`-Tabellen eine andere – Abfragen über beide Seiten scheiterten mit
`Illegal mix of collations`. Nach dem Schema-Import die Vorgabe angleichen:

```bash
mariadb -N -B -e "SELECT TABLE_COLLATION FROM information_schema.TABLES \
                  WHERE TABLE_SCHEMA='radius' AND TABLE_NAME='radcheck';"
mariadb -e "ALTER DATABASE radius CHARACTER SET utf8mb4 COLLATE <ausgegebener Wert>;"
```

Der Wert muss auf `_ci` enden – der Manager vergleicht Benutzer- und
Gruppennamen ohne Rücksicht auf Gross- und Kleinschreibung.

Soll die Datenbank auf einem anderen Host laufen als FreeRADIUS, in
`/etc/mysql/mariadb.conf.d/50-server.cnf` `bind-address` anpassen und den
Zugriff über die Firewall auf die beteiligten Hosts begrenzen. Verschlüsselung
auf Speicherebene ist empfohlen: `Cleartext-Password` und Shared Secrets liegen
technisch bedingt unverschlüsselt in der Datenbank.

## 4. FreeRADIUS installieren und an SQL binden

```bash
sudo apt install freeradius freeradius-mysql
```

Pfade im Folgenden für Debian/Ubuntu (`/etc/freeradius/3.0`); bei
RHEL-Derivaten `/etc/raddb`.

### 4.1 Schema einspielen

Das Schema stammt aus der Installation selbst, nicht aus diesem Projekt:

```bash
sudo mariadb radius < /etc/freeradius/3.0/mods-config/sql/main/mysql/schema.sql
```

> `docker/radius-schema.sql` in diesem Repository ist eine Nachbildung für
> Entwicklung und Tests. Gegen eine echte Installation gilt das Schema des
> Servers.

### 4.2 Datenbankkonto für FreeRADIUS

Nur die Rechte, die der Dienst tatsächlich braucht:

```sql
CREATE USER 'freeradius'@'10.0.0.%' IDENTIFIED BY '...';

GRANT SELECT ON radius.radcheck      TO 'freeradius'@'10.0.0.%';
GRANT SELECT ON radius.radreply      TO 'freeradius'@'10.0.0.%';
GRANT SELECT ON radius.radgroupcheck TO 'freeradius'@'10.0.0.%';
GRANT SELECT ON radius.radgroupreply TO 'freeradius'@'10.0.0.%';
GRANT SELECT ON radius.radusergroup  TO 'freeradius'@'10.0.0.%';
GRANT SELECT ON radius.nas           TO 'freeradius'@'10.0.0.%';

GRANT SELECT, INSERT, UPDATE, DELETE ON radius.radacct     TO 'freeradius'@'10.0.0.%';
GRANT SELECT, INSERT                 ON radius.radpostauth TO 'freeradius'@'10.0.0.%';
```

### 4.3 Modul `sql` aktivieren

```bash
sudo ln -s ../mods-available/sql /etc/freeradius/3.0/mods-enabled/sql
```

In `/etc/freeradius/3.0/mods-available/sql` setzen:

```
sql {
	dialect = "mysql"
	driver = "rlm_sql_${dialect}"

	server = "127.0.0.1"
	port = 3306
	login = "freeradius"
	password = "..."
	radius_db = "radius"

	# NAS-Clients aus der Tabelle "nas" lesen - der Manager pflegt sie dort (FR-4).
	read_clients = yes
	client_table = "nas"

	read_groups = yes
	group_attribute = "SQL-Group"

	$INCLUDE ${modconfdir}/${.:name}/main/${dialect}/queries.conf
}
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

Die Datei enthält ein Passwort:

```bash
sudo chown root:freerad /etc/freeradius/3.0/mods-available/sql
sudo chmod 640 /etc/freeradius/3.0/mods-available/sql
```

In `sites-enabled/default` und `sites-enabled/inner-tunnel` das vorangestellte
Minus vor `sql` in den Abschnitten `authorize`, `accounting`, `session` und
`post-auth` entfernen (`-sql` → `sql`). Mit dem Minus werden Fehler des Moduls
stillschweigend übergangen – auch eine falsche Zugangsangabe.

### 4.4 EAP für WPA-Enterprise

UniFi nutzt für WPA2/3-Enterprise in der Regel PEAP/MSCHAPv2. In
`mods-available/eap`:

```
default_eap_type = peap
```

MSCHAPv2 verlangt ein umkehrbar gespeichertes Passwort – im Manager also den
Credential-Typ `Cleartext-Password` oder `NT-Password`. Für den Produktivbetrieb
das Selbstsignat in `certs/` durch ein Zertifikat einer Stelle ersetzen, der die
Clients vertrauen; die mitgelieferten Testzertifikate sind öffentlich bekannt.

### 4.5 Probelauf

```bash
sudo systemctl stop freeradius && sudo freeradius -X
```

Im Log muss `rlm_sql (sql): Connected new DB handle` erscheinen und – bei
`read_clients = yes` – die Liste der aus der Datenbank gelesenen Clients.
Danach `Ctrl-C` und `sudo systemctl start freeradius`.

## 5. Manager anbinden

Datenbankkonto und `mgr_`-Tabellen wie im README beschrieben anlegen
([Betrieb gegen eine bestehende Installation](../README.md#betrieb-gegen-eine-bestehende-installation)),
dann den Container mit `FRM_DB_HOST`, `FRM_DB_NAME`, `FRM_DB_USER`,
`FRM_DB_PASSWORD` sowie `FRM_SECRET_KEY` und `FRM_COA_SECRET_KEY` starten. Beim
Start prüft der Manager das RADIUS-Schema und verweigert bei Abweichungen den
Betrieb mit einer klaren Meldung.

Der Manager muss die Datenbank erreichen; FreeRADIUS selbst spricht er nur für
CoA/Disconnect an (Abschnitt 7).

## 6. UniFi als NAS

### 6.1 Jeder AP und Switch ist ein eigener RADIUS-Client

UniFi-Geräte senden Anfragen mit ihrer **eigenen** Adresse als Absender, nicht
über den Controller. Jedes Gerät braucht deshalb einen Eintrag in der
`nas`-Tabelle. Im Manager unter *NAS* anlegen:

| Feld | Wert |
| --- | --- |
| `nasname` | IP des Geräts, oder das Netz der Access Points als CIDR, z. B. `10.0.10.0/24` |
| `shortname` | frei, z. B. `unifi-ap-og` |
| `type` | `other` |
| `secret` | Shared Secret, höchstens 60 Zeichen (Spaltenbreite) |

Ein CIDR-Eintrag erspart eine Zeile je Access Point. Für CoA wird das Secret
über das passende Netz gefunden, das Paket aber an die konkrete Adresse der
Session gesendet.

> **NAS-Änderungen wirken erst nach einem Reload von `radiusd`.** Der Manager
> weist darauf hin, startet den Dienst aber nicht selbst:
> `sudo systemctl reload freeradius`.

### 6.2 RADIUS-Profil im UniFi Network Application

*Settings → Profiles → RADIUS → Create New* (Menüpfad je nach Version):

* **Authentication Server**: IP des FreeRADIUS-Hosts, Port `1812`, Shared Secret
  wie in der `nas`-Tabelle.
* **Accounting Server**: derselbe Host, Port `1813`. Ohne Accounting bleibt die
  Sessions-Ansicht des Managers leer (`radacct` wird nicht befüllt).
* **RADIUS Assigned VLAN Support**: für *Wireless Networks* und/oder *Wired
  Networks* einschalten – ohne das verwirft UniFi die VLAN-Attribute.

WLAN verknüpfen: *Settings → WiFi → \<Netz\> → Security → WPA Enterprise*, dort
das Profil auswählen. Für kabelgebundenes NAC ein Port-Profil mit 802.1X-Control
verwenden.

### 6.3 MAC-Authentifizierung (MAB)

Für Drucker, Kameras und IP-Telefone bietet UniFi im RADIUS-Profil eine
MAC-Authentifizierung mit wählbarem MAC-Format. Dieses Format muss zu dem
passen, das der Manager beim Anlegen von Geräten verwendet
(`FRM_DEFAULT_MAC_FORMAT`, Vorgabe `colon_lower` = `aa:bb:cc:dd:ee:ff`) –
andernfalls findet FreeRADIUS die Kennung nicht.

Im Manager unter *Geräte* anlegen; die MAC ist zugleich Benutzername und, wenn
gewünscht, Passwort. MAB ist keine Authentifizierung im eigentlichen Sinn – die
MAC ist beobachtbar und fälschbar.

## 7. VLAN-Zuweisung

Ein VLAN wird über drei Antwortattribute zugewiesen (RFC 3580):

| Attribut | Wert |
| --- | --- |
| `Tunnel-Type` | `VLAN` |
| `Tunnel-Medium-Type` | `IEEE-802` |
| `Tunnel-Private-Group-Id` | VLAN-ID, z. B. `20` |

Der Manager setzt alle drei gemeinsam: im geführten Dialog einer Gruppe oder
eines Benutzers genügt die Eingabe der VLAN-ID.

**Empfohlen ist die Zuweisung über Gruppen** (`radgroupreply`): Benutzer werden
Mitglied, das VLAN steht an einer Stelle. Eine Zuweisung direkt am Benutzer
(`radreply`) gewinnt gegenüber der Gruppe und ist als Ausnahme gedacht. Bei
mehreren Gruppen entscheidet die Priorität der Mitgliedschaft – der kleinere
Wert wird zuerst ausgewertet.

Vorbedingungen auf UniFi-Seite:

* Das VLAN muss im Controller als Netz existieren und am Switch-Port bzw. am
  AP-Uplink anliegen (Trunk / „All“-Port-Profil).
* `Tunnel-Private-Group-Id` als **numerische** VLAN-ID eintragen; VLAN-Namen
  versteht UniFi nicht.
* Ohne eingeschaltetes *RADIUS Assigned VLAN Support* landet der Client im VLAN
  des Netzes, nicht im zugewiesenen.

### CoA: VLAN im Betrieb wechseln

Der Manager kann eine laufende Session trennen oder ihr ein neues VLAN zuweisen
(RFC 5176). Dafür beim NAS-Eintrag *CoA aktivieren*, Port `3799` (UniFi-Vorgabe)
und das CoA-Secret hinterlegen – der Manager legt es AES-GCM-verschlüsselt ab.
Der Manager muss den AP bzw. Switch auf UDP 3799 erreichen.

## 8. Prüfen

```bash
# Benutzer im Manager anlegen, dann vom FreeRADIUS-Host aus:
radtest benutzer passwort 127.0.0.1 0 testing123
```

Erwartet wird `Access-Accept`; bei einer VLAN-Zuweisung enthält die Antwort die
drei Tunnel-Attribute. Für PEAP/MSCHAPv2 – also den Weg, den UniFi-Clients
gehen – eignet sich `eapol_test` aus `wpa_supplicant`.

Danach im Manager:

* *Diagnose* zeigt die Einträge aus `radpostauth` mit Klartext-Hinweis je
  Benutzer und MAC.
* *Sessions* zeigt laufende und historische Sessions aus `radacct` – füllt sich
  nur, wenn das Accounting im UniFi-Profil eingetragen ist.

## 9. Häufige Ursachen bei Fehlern

| Symptom | Ursache |
| --- | --- |
| `Access denied for user … to database 'radius'` | Tabellenrechte fehlen; ein `GRANT` auf eine noch nicht existierende Tabelle wird mit `ERROR 1146` abgewiesen – Schema vor den Rechten einspielen |
| `Instantiation failed for module "sql"`, davor `Unable to check file … my_ca.crt` | der `tls`-Block in `mysql { … }` ist aktiv; bei lokaler Datenbank auskommentieren |
| `Ignoring request … unknown client` | AP/Switch fehlt in `nas`, oder `radiusd` wurde nach der Änderung nicht neu geladen |
| `Access-Reject`, obwohl Benutzer existiert | Passwort-Attribut passt nicht zur Methode: PEAP/MSCHAPv2 verlangt `Cleartext-Password` oder `NT-Password` |
| MAB schlägt fehl, Benutzer sichtbar | MAC-Format in UniFi und `FRM_DEFAULT_MAC_FORMAT` weichen ab |
| Client authentifiziert, landet im falschen VLAN | *RADIUS Assigned VLAN Support* aus, VLAN am Port nicht getaggt, oder VLAN-Name statt ID |
| Sessions-Ansicht bleibt leer | kein Accounting-Server im UniFi-Profil, oder `sql` fehlt im Abschnitt `accounting` |
| `Illegal mix of collations for operation 'UNION'` | `mgr_`- und RADIUS-Tabellen haben verschiedene Kollationen; die `mgr_`-Seite mit `ALTER TABLE … CONVERT TO CHARACTER SET utf8mb4 COLLATE …` angleichen |
| Manager startet nicht, meldet Schemaabweichung | Datenbank enthält ein abweichendes `rlm_sql`-Schema – Version von FreeRADIUS prüfen |
| CoA ohne Wirkung | CoA am NAS nicht aktiviert, falsches Secret, oder UDP 3799 auf dem Weg blockiert |
