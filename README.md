# freeradiusManager

Web-Anwendung zur Verwaltung eines **bestehenden** FreeRADIUS-Servers, der als
Authentifizierungsinstanz für 802.1X (WPA2/3-Enterprise, kabelgebundenes NAC)
betrieben wird. Der Manager liest und schreibt direkt im SQL-Schema des
`rlm_sql`-Moduls; FreeRADIUS selbst bleibt unverändert und trifft weiterhin
allein die Authentifizierungsentscheidungen.

Grundlage der Umsetzung ist [docs/SPEZIFIKATION.md](docs/SPEZIFIKATION.md).

## Funktionsumfang

| Bereich | Inhalt |
| --- | --- |
| Benutzer (FR-1) | Anlegen, Bearbeiten, Sperren/Entsperren, Ablaufdatum, Notiz und Verantwortlicher; Credential-Typ pro Benutzer wählbar (`Cleartext-Password`, `NT-Password` oder beides) |
| Gruppen (FR-2) | `radgroupcheck`/`radgroupreply`/`radusergroup` inkl. Priorität, geführter VLAN-Dialog und Expertenmodus mit Operator-Validierung |
| Geräte (FR-3) | MAB-Geräte mit konfigurierbarem MAC-Format und Inventar-Metadaten |
| NAS (FR-4) | `nas`-Tabelle, maskierte Shared Secrets, Anzeige nur für Administratoren mit Audit-Eintrag |
| Sessions (FR-5) | Laufende und historische Sessions aus `radacct` mit Keyset-Pagination |
| Diagnose (FR-6) | `radpostauth`-Auswertung und Klartext-Hinweise pro Benutzer/MAC |
| CoA (FR-7) | Disconnect-Message und VLAN-Neuzuweisung nach RFC 5176 |
| Import/Export (FR-8) | CSV mit Vorschau und Dry-Run, CSV-Export der Filtermenge, Bulk-Aktionen |
| Audit (FR-9) | Vollständiges Protokoll aller schreibenden Aktionen, ohne Passwörter |
| Anmeldung (FR-10) | Lokale Konten (Argon2id), TOTP-Pflicht für Administratoren, optional OIDC |

## Schnellstart (Evaluierung)

Voraussetzungen: Docker und Docker Compose.

```bash
cp .env.example .env
```

In der `.env` `FRM_SECRET_KEY`, `FRM_COA_SECRET_KEY` und
`FRM_BOOTSTRAP_ADMIN_PASSWORD` setzen – ohne die beiden Schlüssel startet der
Stapel bewusst nicht. Schlüssel erzeugen:

```bash
python3 -c "import base64,os; print(base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip('='))"
```

Danach den Stapel starten:

```bash
docker compose up -d --build
```

Die Oberfläche läuft anschliessend auf <http://localhost:8000>, die OpenAPI-Doku
unter `/api/docs`. Beim ersten Start wird der Administrator aus
`FRM_BOOTSTRAP_ADMIN_*` angelegt; er muss beim ersten Anmelden TOTP einrichten.

Der Stapel enthält zur Evaluierung auch einen FreeRADIUS-Container auf derselben
Datenbank. Eine im Manager angelegte Kennung lässt sich damit direkt prüfen:

```bash
docker compose exec freeradius radtest BENUTZER PASSWORT 127.0.0.1 0 testing123
```

> Die Datei `docker/radius-schema.sql` ist eine eigenständig verfasste,
> funktional gleichwertige Nachbildung des FreeRADIUS-Schemas für Entwicklung
> und Tests. Gegen eine **bestehende** Installation wird sie nicht verwendet –
> dort gilt das Schema des Servers (Spezifikation, Abschnitt 7); den
> entsprechenden Mount in `docker-compose.yml` dann entfernen.

## Betrieb gegen eine bestehende Installation

1. Eigenen Datenbankbenutzer anlegen (NFR-1) – nicht das FreeRADIUS-Konto verwenden:

   ```sql
   CREATE USER 'radmgr'@'%' IDENTIFIED BY '...';
   GRANT SELECT ON radius.radacct TO 'radmgr'@'%';
   GRANT SELECT ON radius.radpostauth TO 'radmgr'@'%';
   GRANT SELECT, INSERT, UPDATE, DELETE ON radius.radcheck TO 'radmgr'@'%';
   GRANT SELECT, INSERT, UPDATE, DELETE ON radius.radreply TO 'radmgr'@'%';
   GRANT SELECT, INSERT, UPDATE, DELETE ON radius.radgroupcheck TO 'radmgr'@'%';
   GRANT SELECT, INSERT, UPDATE, DELETE ON radius.radgroupreply TO 'radmgr'@'%';
   GRANT SELECT, INSERT, UPDATE, DELETE ON radius.radusergroup TO 'radmgr'@'%';
   GRANT SELECT, INSERT, UPDATE, DELETE ON radius.nas TO 'radmgr'@'%';
   GRANT ALL PRIVILEGES ON `radius`.`mgr\_%` TO 'radmgr'@'%';
   ```

2. Container mit den Umgebungsvariablen aus `.env.example` starten. Beim Start
   migriert der Manager ausschliesslich seine eigenen `mgr_`-Tabellen und prüft
   das RADIUS-Schema; bei Abweichungen verweigert er den Betrieb mit einer
   klaren Meldung (Abschnitt 4.2).
3. Den Manager hinter einen TLS-Reverse-Proxy stellen und `FRM_COOKIE_SECURE=true`
   belassen. Damit Audit-Log und Rate-Limits die echte Client-Adresse sehen, das
   Netz des Proxys in `FRM_TRUSTED_PROXIES` eintragen – nur von dort wird
   `X-Forwarded-For` ausgewertet.

### Bekannte betriebliche Einschränkungen

* **Klartextpasswörter.** PEAP/MSCHAPv2 verlangt, dass der Server das Passwort
  umkehrbar vorhält. `Cleartext-Password` und Shared Secrets können deshalb
  nicht anwendungsseitig verschlüsselt werden; der Schutz erfolgt über
  DB-Rechte, Verschlüsselung auf Speicherebene und die restriktive Anzeige in
  der Oberfläche. CoA- und TOTP-Secrets liest nur der Manager und werden daher
  mit AES-GCM verschlüsselt abgelegt.
* **NAS-Änderungen** wirken erst nach einem Neustart bzw. `clients`-Reload von
  `radiusd`. Der Manager weist darauf hin, führt aber keinen Neustart aus.
* **Rate Limiting** zählt prozesslokal. Bei mehreren Instanzen begrenzt jede
  Instanz für sich; ein gemeinsames Backend (Redis) ist als Ausbaustufe
  vorgesehen.
* **TOTP zurücksetzen** kann nur ein Administrator (`reset_totp` in der
  Kontenverwaltung). Ein bereits eingerichteter zweiter Faktor lässt sich weder
  über die Anmeldung noch über das eigene Profil ersetzen.
* **Aufbewahrung des Audit-Logs** setzt ein Hintergrundjob durch; das Intervall
  steuert `FRM_AUDIT_PURGE_INTERVAL_SECONDS` (Vorgabe: alle sechs Stunden).
* **Betrieb unter einem Pfadpräfix** über `FRM_ROOT_PATH` (z. B. `/manager`): das
  Backend setzt `<base href>` in der ausgelieferten `index.html`, woraus die
  Oberfläche Asset- und API-Adressen ableitet.

## Entwicklung

### Backend

```bash
cd backend
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/uvicorn app.main:app --reload
```

Tests laufen gegen eine echte MariaDB (Testcontainers), nicht gegen SQLite:

```bash
cd backend && .venv/bin/pytest --cov=app
```

Der End-to-End-Test startet zusätzlich einen echten `freeradius`-Container und
authentifiziert mit `radtest`:

```bash
cd backend && .venv/bin/pytest -m e2e tests/e2e
```

### Frontend

```bash
cd frontend
npm install
npm run dev    # Vite auf 5173, /api wird auf localhost:8000 weitergeleitet
npm run build  # Ausgabe nach backend/static, wird vom Backend ausgeliefert
```

### Struktur

```
backend/app/
  api/            FastAPI-Router, Dependencies, Fehlerbehandlung
  services/       Fachlogik (Benutzer, Gruppen, Sessions, CoA, Import/Export)
  repositories/
    radius/       an das FreeRADIUS-Schema gebunden – bei Server-Upgrades prüfen
    mgr/          eigene mgr_-Tabellen
    directory.py  übergreifende Listenabfragen
  models/         ORM-Modelle
  core/           Konfiguration, Security, Krypto, i18n, Paginierung
frontend/src/     React 18, TanStack Query/Table, i18n de/en
docker/           Schema-Fixture, FreeRADIUS-Modulkonfiguration, Entrypoint
```

## Lizenz

MIT – siehe [LICENSE](LICENSE).
