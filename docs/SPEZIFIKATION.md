# freeradiusManager – Spezifikation

**Version:** 0.1 (Entwurf)
**Datum:** 2026-09-02
**Status:** zur Abstimmung

---

## 1. Zielsetzung

`freeradiusManager` ist eine Web-Anwendung zur Verwaltung eines bestehenden FreeRADIUS-Servers,
der als Authentifizierungsinstanz für **802.1X (WPA2/3-Enterprise, kabelgebundenes NAC)**
betrieben wird.

Der Manager schreibt und liest direkt im SQL-Schema des `rlm_sql`-Moduls (MySQL/MariaDB).
FreeRADIUS selbst bleibt unverändert und ist weiterhin die einzige Instanz, die
Authentifizierungsentscheidungen trifft.

### 1.1 Kernnutzen

1. Benutzer, Geräte und Gruppen ohne SQL-Kenntnisse verwalten.
2. VLAN-Zuweisungen und RADIUS-Attribute nachvollziehbar pflegen.
3. Fehlersuche bei abgelehnten Anmeldungen ("Warum kommt das Notebook nicht ins WLAN?").
4. Übersicht über laufende und historische Sessions inkl. Zwangstrennung per CoA.

### 1.2 Abgrenzung (Nicht-Ziele)

| Nicht im Umfang | Begründung |
| --- | --- |
| Verwaltung von `radiusd.conf`, `sites-enabled`, `mods-available` | Konfigurationsdateien bleiben Sache der Systemadministration/Ansible. Ein Web-Editor für Serverkonfiguration ist ein eigenes Risiko- und Testthema. |
| Ersatz oder Reimplementierung des RADIUS-Protokolls | Der Manager ist kein RADIUS-Server. Ausnahme: CoA/Disconnect als Client (siehe FR-7). |
| Hotspot-/Voucher-Verwaltung, Abrechnung, Prepaid | Bewusst ausgeklammert (anderer Einsatzzweck, andere Datenmodelle). |
| Vollwertige CA / PKI für EAP-TLS | Für v1 ausgeschlossen, als Ausbaustufe vorgemerkt (siehe Abschnitt 9). |
| Multi-Tenancy | v1 verwaltet genau eine FreeRADIUS-Installation. |

---

## 2. Rollen

| Rolle | Berechtigungen |
| --- | --- |
| **Administrator** | Vollzugriff inkl. NAS-Clients, Manager-Benutzerverwaltung, Systemeinstellungen. |
| **Operator** (Helpdesk) | Benutzer/Geräte anlegen, sperren, entsperren, Gruppen zuweisen, Sessions einsehen und trennen. Kein Zugriff auf NAS-Clients und Shared Secrets. |
| **Auditor** | Ausschließlich lesend, inkl. Audit-Log. Keine Sichtbarkeit von Passwort- oder Secret-Feldern. |

Rollen sind global (nicht objektbezogen). Objektbezogene Berechtigungen sind eine mögliche
Ausbaustufe, verkomplizieren aber das Datenmodell erheblich und sind für v1 nicht vorgesehen.

---

## 3. Funktionale Anforderungen

### FR-1 Benutzerverwaltung

* Anlegen, Bearbeiten, Löschen von Benutzern (`radcheck`, `radreply`).
* Unterstützte Credential-Typen:
  * `Cleartext-Password` – notwendig für EAP-TTLS/PAP und als Basis für MSCHAPv2.
  * `NT-Password` – für PEAP/MSCHAPv2, wird vom Manager aus dem Passwort erzeugt.
  * `Auth-Type := Reject` – zum Sperren, ohne den Datensatz zu löschen.
* Sperren/Entsperren als eigene Aktion, die den Zustand vorher konserviert.
* Ablaufdatum (`Expiration`) optional pro Benutzer.
* Freitext-Notiz und Verantwortlicher (in Manager-eigener Tabelle, nicht in `radcheck`).
* Suche über Benutzername, Notiz, Gruppe, MAC.

> **Designhinweis:** PEAP/MSCHAPv2 verlangt zwingend, dass der Server das Passwort in
> umkehrbarer Form (Klartext oder NT-Hash) vorhält. Das ist eine Eigenschaft des Protokolls,
> keine Schwäche des Managers – muss aber in der Sicherheitsbetrachtung (Abschnitt 5.1)
> und in der UI explizit adressiert werden.

### FR-2 Gruppen und Attribute

* Verwaltung von `radgroupcheck`, `radgroupreply`, `radusergroup` inkl. Priorität.
* Geführter Dialog für die häufigste Aufgabe – **VLAN-Zuweisung**:
  * `Tunnel-Type = VLAN`
  * `Tunnel-Medium-Type = IEEE-802`
  * `Tunnel-Private-Group-Id = <VLAN-ID oder Name>`
* Expertenmodus für beliebige Attribut/Operator/Wert-Tripel mit Validierung der Operatoren
  (`:=`, `==`, `+=`, `=*` …) und Warnung bei typischen Fehlern (z. B. `=` statt `:=` in `radcheck`).
* Attributnamen werden gegen ein hinterlegtes Wörterbuch geprüft (Vorschlagsliste,
  keine harte Sperre für Vendor-Attribute).

### FR-3 Geräte / MAC Authentication Bypass

* Eigene Ansicht für MAB-Geräte (Drucker, IP-Telefone, Kameras), technisch Benutzer mit
  MAC-Adresse als Benutzername.
* Konfigurierbares MAC-Format (z. B. `aabbccddeeff`, `aa:bb:cc:dd:ee:ff`, `AA-BB-CC-DD-EE-FF`),
  damit das Format zur `policy.d`-Normalisierung des Servers passt.
* Pflegbare Metadaten: Gerätetyp, Standort, Inventarnummer, Verantwortlicher, Ablaufdatum.
* Warnung in der UI, dass MAB keine echte Authentifizierung darstellt.

### FR-4 NAS-Clients

* Verwaltung der `nas`-Tabelle: Kurzname, IP/Netz, Typ, Shared Secret, Beschreibung.
* Shared Secrets sind in der UI standardmäßig maskiert; Anzeige nur für Administratoren
  und mit Eintrag im Audit-Log.
* Hinweis zum Nachladen: Änderungen an der `nas`-Tabelle greifen erst nach einem
  `radiusd`-Neustart bzw. `clients`-Reload – der Manager zeigt das als Hinweis an,
  führt aber v1 keinen Neustart aus.

### FR-5 Session-Übersicht (Accounting)

* Liste laufender Sessions aus `radacct` (`acctstoptime IS NULL`).
* Historie mit Filtern: Benutzer, MAC (`callingstationid`), NAS, Zeitraum, Terminate-Cause.
* Detailansicht einer Session: Start/Ende, Dauer, Volumen, Framed-IP, NAS-Port, SSID (soweit geliefert).
* Serverseitige Paginierung; keine ungefilterten Vollabfragen (siehe NFR-2).

### FR-6 Auth-Log und Diagnose

* Auswertung von `radpostauth`: erfolgreiche und abgelehnte Anmeldungen.
* Diagnose-Ansicht pro Benutzer/MAC: letzte N Versuche, verwendetes NAS, Ergebnis,
  daraus abgeleitete Klartext-Hinweise (z. B. „Benutzer existiert nicht",
  „Auth-Type := Reject gesetzt", „NAS unbekannt").
* Ziel: Der Helpdesk soll die häufigsten Fälle ohne `radiusd -X` lösen können.

### FR-7 Disconnect / Change of Authorization

* Trennen einer laufenden Session per Disconnect-Message nach RFC 5176 (UDP/3799).
* CoA zur Neuzuweisung eines VLAN, sofern das NAS es unterstützt.
* Voraussetzung: pro NAS hinterlegtes CoA-Secret und -Port.
* Jede Aktion wird im Audit-Log erfasst; Fehlschläge (Timeout, NAK) werden angezeigt.

### FR-8 Import / Export

* CSV-Import für Benutzer und MAB-Geräte mit Vorschau, Validierung und Dry-Run.
* CSV-Export der aktuellen Filterergebnisse.
* Bulk-Aktionen: Gruppe zuweisen, sperren, Ablaufdatum setzen, löschen.

### FR-9 Audit-Log

* Jede schreibende Aktion wird protokolliert: Zeitpunkt, Manager-Benutzer, Objekt,
  Aktion, Vorher-/Nachher-Werte (Passwörter und Secrets nur als „geändert" markiert).
* Nicht löschbar über die UI; Aufbewahrungsdauer konfigurierbar.

### FR-10 Anmeldung am Manager

* Lokale Konten mit Argon2id-Hash und Pflicht zu 2FA (TOTP) für Administratoren.
* Optional OIDC-Anbindung (Authorization Code + PKCE), Rollen-Mapping über Claims.
* Session-Cookies `HttpOnly`, `Secure`, `SameSite=Lax`; Idle-Timeout konfigurierbar.

---

## 4. Datenmodell

### 4.1 Grundsatz

Das FreeRADIUS-Schema (`radcheck`, `radreply`, `radgroupcheck`, `radgroupreply`,
`radusergroup`, `radacct`, `radpostauth`, `nas`) wird **strukturell nicht verändert**.
Keine zusätzlichen Spalten, keine geänderten Typen – damit bleiben Server-Upgrades und
die offiziellen Schema-Dateien nutzbar.

Alle Zusatzinformationen liegen in eigenen Tabellen mit Präfix `mgr_`:

| Tabelle | Zweck |
| --- | --- |
| `mgr_account` | Manager-Benutzer, Passwort-Hash, TOTP-Secret, Rolle |
| `mgr_audit` | Audit-Log |
| `mgr_subject` | Metadaten zu Benutzern/Geräten (Notiz, Typ, Standort, Owner, Ablauf), Verknüpfung über `username` |
| `mgr_nas_extra` | CoA-Port und CoA-Secret je NAS |
| `mgr_setting` | Instanzweite Einstellungen (MAC-Format, Aufbewahrungsfristen) |

Verknüpfung erfolgt über `username` bzw. `nasname` als natürlicher Schlüssel, da das
FreeRADIUS-Schema keine stabilen Surrogatschlüssel für diese Beziehungen anbietet.
Umbenennungen eines Benutzers müssen daher transaktional beide Seiten anfassen.

### 4.2 Migrationen

Alembic verwaltet ausschließlich die `mgr_`-Tabellen. Das RADIUS-Schema wird als
vorhanden vorausgesetzt; beim Start prüft die Anwendung dessen Existenz und Version
und verweigert bei Abweichungen den Betrieb mit einer klaren Fehlermeldung.

---

## 5. Nicht-funktionale Anforderungen

### NFR-1 Sicherheit

* Die Anwendung verbindet sich mit einem **eigenen DB-Benutzer**, nicht mit dem
  FreeRADIUS-Konto. Rechte: `SELECT` auf `radacct`/`radpostauth`,
  `SELECT/INSERT/UPDATE/DELETE` auf den Konfigurationstabellen, Vollzugriff auf `mgr_*`.
* Shared Secrets und Klartextpasswörter müssen für FreeRADIUS lesbar bleiben und können
  daher **nicht** anwendungsseitig verschlüsselt werden. Schutz erfolgt über
  DB-Zugriffsrechte, Verschlüsselung at rest auf Speicherebene und restriktive UI-Anzeige.
  Diese Einschränkung wird im Betriebshandbuch explizit dokumentiert.
* CoA-Secrets in `mgr_nas_extra` werden dagegen anwendungsseitig verschlüsselt
  (AES-GCM, Schlüssel aus Umgebungsvariable/Secret-Store), da nur der Manager sie liest.
* Kein Klartext-Passwort im API-Response, in Logs oder im Audit-Log.
* Rate Limiting auf Login- und CoA-Endpunkte.

### NFR-2 Performance

* `radacct` erreicht in Produktivumgebungen leicht mehrere Millionen Zeilen.
  Alle Abfragen laufen indexgestützt (`username`, `callingstationid`, `acctstarttime`,
  `acctstoptime`) und mit Keyset-Pagination.
* Zielwert: Listenansichten unter 500 ms bei 5 Mio. Accounting-Datensätzen.
* Aggregationen (Statistiken) laufen als Hintergrundjob, nicht synchron im Request.

### NFR-3 Betrieb

* Auslieferung als Docker-Images plus `docker-compose.yml` für die Evaluierung.
* Konfiguration ausschließlich über Umgebungsvariablen (12-Factor).
* Health-Endpunkte `/healthz` (Liveness) und `/readyz` (inkl. DB-Prüfung).
* Strukturierte JSON-Logs.

### NFR-4 Bedienung

* Oberfläche auf Deutsch und Englisch (i18n von Beginn an, kein Nachrüsten).
* Responsive bis Tablet-Breite; Desktop ist der primäre Anwendungsfall.
* Destruktive Aktionen mit Bestätigung und Angabe der betroffenen Objektzahl.

### NFR-5 Qualität

* Backend-Tests gegen eine echte MariaDB (Testcontainers), nicht gegen SQLite –
  das Verhalten der RADIUS-Tabellen soll realistisch geprüft werden.
* Integrationstest gegen einen echten `freeradius`-Container: Benutzer über den Manager
  anlegen, mit `radtest`/`eapol_test` authentifizieren.
* Zielabdeckung Backend >= 80 % Zeilen, Fokus auf Attribut- und Berechtigungslogik.

---

## 6. Architektur

```
Browser ──HTTPS──> Reverse Proxy ──> FastAPI (Uvicorn) ──┬── MariaDB (RADIUS + mgr_*)
                                          │              │
                                          │              └── FreeRADIUS liest dieselbe DB
                                          └──UDP/3799──> NAS (CoA/Disconnect)
```

### 6.1 Technologie

| Ebene | Wahl |
| --- | --- |
| Backend | Python 3.12, FastAPI, SQLAlchemy 2.0 (async), Alembic, Pydantic v2 |
| Datenbank | MariaDB 10.11+ / MySQL 8 |
| RADIUS-Client | `pyrad` für CoA/Disconnect |
| Frontend | React 18 + TypeScript, Vite, TanStack Query, TanStack Table |
| Auth | JWT im HttpOnly-Cookie, optional OIDC via `authlib` |
| Tests | pytest, pytest-asyncio, Testcontainers, Playwright (E2E-Kernpfade) |
| CI | GitHub Actions: Lint (ruff, mypy, eslint), Test, Build, Image-Push |

### 6.2 Schichtung im Backend

```
api/          FastAPI-Router, Request/Response-Schemas
services/     Fachlogik (Benutzer, Gruppen, Sessions, CoA)
repositories/ SQLAlchemy-Zugriff, getrennt nach radius/* und mgr/*
models/       ORM-Modelle
core/         Konfiguration, Security, Audit, i18n
```

Die Trennung `repositories/radius` vs. `repositories/mgr` ist bewusst: Nur der erste Teil
ist an ein fremdes Schema gebunden und muss bei FreeRADIUS-Upgrades geprüft werden.

### 6.3 API

* REST unter `/api/v1`, OpenAPI-Schema automatisch generiert.
* Ressourcen: `/users`, `/devices`, `/groups`, `/nas`, `/sessions`, `/authlog`, `/audit`, `/accounts`.
* Konsistente Fehlerstruktur (`{code, message, details}`), Fehlercodes übersetzbar.

---

## 7. Vorausgesetzte Umgebung

* FreeRADIUS 3.2.x mit aktiviertem `rlm_sql` (Dialekt MySQL) und `sql`-Modul in
  `authorize`, `accounting`, `post-auth`.
* Schema entsprechend `raddb/mods-config/sql/main/mysql/schema.sql`.
* `nas`-Tabelle aktiv (`read_clients = yes`).
* Netzwerkzugriff vom Manager zu den NAS auf UDP/3799 für CoA (optional).

---

## 8. Meilensteine

| Meilenstein | Inhalt |
| --- | --- |
| **M1 – Fundament** | Projektgerüst, CI, Auth am Manager, RBAC, Audit-Log, Benutzerverwaltung (FR-1), Gruppen (FR-2) |
| **M2 – Betriebsfähig** | MAB-Geräte (FR-3), NAS-Verwaltung (FR-4), Sessions (FR-5), Auth-Log (FR-6) |
| **M3 – Komfort** | CoA/Disconnect (FR-7), Import/Export und Bulk (FR-8), i18n-Vervollständigung, Statistiken |

M1 ist bewusst so geschnitten, dass danach bereits ein produktiv nutzbarer,
auditierbarer Kern existiert.

---

## 9. Mögliche Ausbaustufen

* EAP-TLS: Verwaltung von Client-Zertifikaten, Ausstellung über eine interne CA,
  CRL-Pflege. Deutlicher Sicherheitsgewinn gegenüber MSCHAPv2, aber eigenständiges Teilprojekt.
* Automatische Erkennung unbekannter Geräte aus `radpostauth` mit Freigabe-Workflow.
* Anbindung an ein Inventarsystem für Gerätemetadaten.
* Konfigurations-Reload von FreeRADIUS über eine definierte Schnittstelle.
* Read-Replica-Anbindung für Reporting.

---

## 10. Offene Punkte

1. **Passwortstrategie:** Soll `Cleartext-Password` überhaupt gespeichert werden, oder
   ausschließlich `NT-Password` (schließt EAP-TTLS/PAP aus, reduziert aber die Angriffsfläche)?
2. **Benutzerquelle:** Bleiben die Benutzer dauerhaft in SQL, oder ist mittelfristig
   LDAP/AD als Quelle vorgesehen? Das ändert die Rolle von FR-1 grundlegend.
3. **Bestandsdaten:** Gibt es eine bestehende Installation mit Altdaten, deren Konventionen
   (MAC-Format, Gruppennamen) übernommen werden müssen?
4. **Größenordnung:** Anzahl Benutzer, Geräte, NAS und täglicher Anmeldungen – relevant für NFR-2.
5. **Betriebsumgebung:** Docker/Compose, Kubernetes oder klassische VM mit systemd?
