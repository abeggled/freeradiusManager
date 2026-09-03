# Umsetzungsstand zur Spezifikation v0.1

Stand: 2026-09-03. Diese Datei ordnet die Anforderungen der
[Spezifikation](SPEZIFIKATION.md) dem umgesetzten Code zu und hält die
getroffenen Entscheidungen fest.

## Beantwortete offene Punkte (Abschnitt 10)

| Punkt | Entscheidung |
| --- | --- |
| 1. Passwortstrategie | Credential-Typ **pro Benutzer wählbar**: `cleartext`, `nt` oder `both`. Der Instanz-Default steht in `mgr_setting.default_credential_type`. |
| 2. Benutzerquelle | Benutzer bleiben **dauerhaft in SQL**; keine LDAP-Vorkehrungen im Datenmodell. |
| 3. Bestandsdaten | Grüne Wiese. MAC-Format ist konfigurierbar, Vorgabe `aa:bb:cc:dd:ee:ff`. |
| 4. Größenordnung | Keine Vorgabe; die Zielwerte aus NFR-2 gelten (Keyset-Pagination, gedeckelte Zählung). |
| 5. Betriebsumgebung | Docker-Images plus `docker-compose.yml`. |

## Anforderungen

| Anforderung | Ort |
| --- | --- |
| FR-1 Benutzer | `backend/app/services/users.py`, `api/v1/endpoints/users.py` |
| FR-2 Gruppen und Attribute | `services/groups.py`, `services/attributes.py`, `core/radius_dict.py` |
| FR-3 MAB-Geräte | `services/devices.py`, `core/mac.py` |
| FR-4 NAS-Clients | `services/nas.py`, `repositories/radius/nas.py` |
| FR-5 Sessions | `services/sessions.py`, `repositories/radius/acct.py` |
| FR-6 Auth-Log und Diagnose | `services/authlog.py`, `repositories/radius/postauth.py` |
| FR-7 CoA/Disconnect | `services/coa.py`, `app/resources/dictionary` |
| FR-8 Import/Export und Bulk | `services/importexport.py`, `api/v1/endpoints/imports.py` |
| FR-9 Audit-Log | `services/audit.py`, `repositories/mgr/audit.py` |
| FR-10 Anmeldung | `services/accounts.py`, `services/oidc.py`, `core/security.py` |
| NFR-1 Sicherheit | `core/crypto.py` (Argon2id, AES-GCM, NT-Hash), `core/ratelimit.py`, Maskierung in `services/users.py` und `services/audit.py` |
| NFR-2 Performance | `core/pagination.py`, Keyset-Abfragen in `repositories/radius/acct.py`, Hintergrundjob in `services/stats.py` |
| NFR-3 Betrieb | `Dockerfile`, `docker-compose.yml`, `/healthz`, `/readyz`, `core/logging.py` |
| NFR-4 Bedienung | `frontend/src/i18n/`, `components/ui.tsx` (`ConfirmDialog` mit Objektzahl) |
| NFR-5 Qualität | `backend/tests/` – Testcontainers-MariaDB, `tests/e2e` mit `radtest` |

## Bewusste Abweichungen und Ergänzungen

1. **`docker/radius-schema.sql` ist eine Nachbildung.** Das offizielle
   FreeRADIUS-Schema steht unter der GPL; dieses Repository ist MIT-lizenziert.
   Die Datei ist deshalb eigenständig verfasst und funktional gleichwertig
   (Spalten und Indizes richten sich nach `queries.conf`). Sie dient
   ausschliesslich Entwicklung, Test und Evaluierung – produktiv gilt das Schema
   der FreeRADIUS-Installation.

2. **`repositories/directory.py` als dritte Schicht.** Die Spezifikation trennt
   `repositories/radius` und `repositories/mgr`. Die Listenansichten brauchen
   jedoch beide Seiten in einer Abfrage, weil ein Benutzer auch ohne
   Manager-Metadaten existieren kann. Diese eine Datei überspannt daher bewusst
   beide Schemata und ist entsprechend dokumentiert.

3. **Keine Klartextpasswörter in API-Antworten.** NFR-1 verlangt das; deshalb
   maskiert der Manager Passwortattribute für **alle** Rollen, nicht nur für
   Auditoren.

4. **Gedeckelte Zählung bei Sessions.** Eine exakte Gesamtzahl über Millionen
   Zeilen wäre zu teuer. `/sessions` liefert `approximate_total` (bis 10 000)
   und paginiert über einen Keyset-Cursor.

5. **TOTP-Pflicht als eigener Anmeldeschritt.** Ein Administrator ohne TOTP
   erhält beim Anmelden `totp_setup_required` und ein kurzlebiges Challenge-Token;
   erst nach bestätigter Einrichtung wird eine Session ausgestellt.

6. **Statistiken aus einem Snapshot.** Der Hintergrundjob schreibt nach
   `mgr_stats_snapshot`; die Oberfläche kennzeichnet veraltete Werte. Für einen
   sofortigen Neuaufbau gibt es `POST /api/v1/stats/refresh` (Administrator).

## Was nicht umgesetzt ist

Die Nicht-Ziele aus Abschnitt 1.2 und die Ausbaustufen aus Abschnitt 9 –
insbesondere EAP-TLS/CA, Multi-Tenancy, objektbezogene Berechtigungen und ein
Konfigurations-Reload von FreeRADIUS. `mgr_nas_extra` und der Freigabe-Workflow
für unbekannte Geräte sind datenseitig vorbereitet
(`PostAuthRepository.unknown_subjects`), aber ohne eigene Oberfläche.

## Nachträge aus dem Code-Review

Drei Runden eines automatisierten Reviews meldeten 19, 14 und 13 Befunde; alle
sind behoben und mit Regressionstests abgesichert (`test_security_fixes.py`,
`test_review_fixes.py`, `test_review_fixes_2.py`, `test_review_fixes_3.py`
unter `backend/tests/integration/`).

Sicherheitsrelevant und daher hervorgehoben:

1. **Sitzungen folgen dem Kontozustand.** Rolle und Aktivstatus stammen bei jedem
   Request aus `mgr_account`, nicht aus dem JWT. Deaktivieren, Löschen oder
   Herabstufen wirkt sofort, statt erst nach Ablauf der absoluten Gültigkeit.
2. **Zweiter Faktor ist nicht übernehmbar.** Die Challenge der Ersteinrichtung
   hat einen eigenen Scope; ein Token aus der normalen Anmeldung kann einen
   aktiven Faktor nicht mehr ersetzen. Zurücksetzen bleibt Administratoren
   vorbehalten. Fehlversuche am zweiten Faktor zählen auf dieselbe Kontosperre
   ein wie falsche Passwörter.
3. **`X-Forwarded-For` wird nur vertrauenswürdigen Proxys geglaubt**
   (`FRM_TRUSTED_PROXIES`). Vorher liess sich das Rate-Limit mit einem
   gefälschten Header umgehen.
4. **OIDC prüft `is_active`.** Ein deaktiviertes Konto konnte sich zuvor über
   einen erneuten OIDC-Callback sofort neu anmelden.
5. **Passwort-Attribute an Gruppen werden maskiert.** Der Expertenmodus lässt sie
   zu; ausgeliefert wurden sie bis dahin im Klartext.

Fachlich ebenso wichtig:

* Ein PATCH auf eine Gruppe löscht die jeweils nicht gesendete Attributsammlung
  nicht mehr mit; eine Gruppe ohne jedes Attribut wird abgelehnt, statt scheinbar
  angelegt zu werden.
* Beim Anlegen eines Benutzers wird über alle drei RADIUS-Tabellen geprüft, damit
  Bestandsnamen mit nur Antwortattributen oder Gruppen nicht überschrieben werden.
* Sammelaktionen über die Filtermenge schliessen MAB-Geräte aus, solange die
  Liste sie nicht anzeigt.
* Der Statusfilter wertet `Auth-Type := Reject` in `radcheck` aus statt nur
  `mgr_subject.disabled_at`.
* Beim Umbenennen eines MAB-Geräts zieht das MAC-Passwort mit.
* Der CSV-Dry-Run durchläuft dieselbe Validierung wie der Import; bestehende
  Datensätze übernehmen jetzt auch `password`, `vlan` und `disabled`.
* NAS-Felder lassen sich wieder leeren; CoA findet das Secret auch bei
  Netz-Einträgen (`192.0.2.0/24`) und sendet an die konkrete Session-IP.
* Die Aufbewahrungsfrist des Audit-Logs setzt ein Hintergrundjob durch.
* `attempts` der Diagnose ist begrenzt; CSV-Exporte folgen den aktiven Filtern.
* Die FreeRADIUS-Modulkonfiguration liest die Zugangsdaten aus der Umgebung,
  sodass ein geändertes `DB_PASSWORD` den mitgelieferten Server nicht mehr
  abhängt.

Aus der zweiten Runde kamen weitere Punkte hinzu:

* **`radusergroup` hat im offiziellen Schema keine `id`-Spalte.** Das ORM-Modell
  verlangte sie, und die Test-Fixture verdeckte das – auf einer Bestandsinstallation
  wären Mitgliedschaften damit unbenutzbar gewesen. Modell und Fixture bilden das
  Schema jetzt korrekt ab.
* **Maskierte Passwörter werden nicht zurückgeschrieben.** Das war eine Regression
  aus der ersten Runde: der Editor sendete den Platzhalter zurück, das Backend hätte
  ihn gespeichert. Eingehende Platzhalter behalten nun den gespeicherten Wert.
* **Die Kontosperre greift auch am zweiten Faktor**; zuvor liess sich mit derselben
  Challenge weiterraten, und ein richtiger Code hob die Sperre wieder auf.
* **Die Datenbank-URL wird über SQLAlchemy gebaut** – Zugangsdaten mit `@`, `/`,
  `#` oder `%` funktionieren jetzt.
* **Das ID-Token wird an den Aussteller gebunden** (`iss` gegen die Discovery-Metadaten).
* **Die Audit-Redaktion nutzt dasselbe Wörterbuch wie die API-Maskierung**, sodass
  auch `User-Password` und `Password` erfasst sind.
* Listen und Exporte umfassen Bestandsnamen aus `radreply` und `radusergroup`;
  Sammelaktionen über die Filtermenge werden oberhalb der Obergrenze abgelehnt
  statt stillschweigend gekürzt.
* Ein Update darf die letzte Zeile einer Gruppe nicht entfernen; CSV-Importe ohne
  Metadatenspalten löschen vorhandene Angaben nicht mehr.
* `pyrad` meldet Zeitüberschreitungen über eine eigene Exception-Klasse – sie wird
  jetzt als Timeout und nicht als allgemeiner Fehler ausgewiesen.
* NAS-Kurznamen einer Session-Seite kommen aus einer einzigen Abfrage statt aus
  bis zu 200 Einzelabfragen.
* Die Einstellung `show_mab_warning` wirkt tatsächlich, und nach dem Setzen eines
  Passworts aktualisiert die Oberfläche Status und Attributliste.

Die dritte Runde betraf vor allem die Anmeldung:

* **Ein zweites, IP-weites Limit** ergänzt die Grenze je Konto. Zuvor genügte ein
  neuer Benutzername je Versuch, um beliebig viele Passwörter durchzuprobieren.
* **Der Fehlerzähler wird erst nach vollständigem Erfolg zurückgesetzt.** Beim
  kombinierten Weg (Passwort und TOTP in einem Aufruf) setzte die erfolgreiche
  Passwortprüfung ihn zuvor jedes Mal auf null – die Kontosperre war damit auf
  diesem Weg nie erreichbar.
* **Das TOTP-Limit zählt je Konto statt je IP.** Hinter einem NAT hätten sich die
  Benutzer sonst gegenseitig ausgesperrt.
* **OIDC bindet keine bestehenden lokalen Konten mehr implizit.** Eine
  fremdverwaltete Kennung namens `admin` hätte sonst das Bootstrap-Konto
  übernehmen und herabstufen können; zusätzlich ist der letzte Administrator
  gegen ein Rollen-Mapping geschützt.
* **Eine Sammelaktion `set_expiry` ohne Datum wird abgelehnt**, statt die gesamte
  bestätigte Menge sofort ablaufen zu lassen. Das Audit-Log hält jetzt auch die
  betroffenen Benutzernamen fest, nicht nur Zähler.
* **Geräte bleiben nach einer Umstellung des MAC-Formats erreichbar**: die
  Auflösung sucht die gespeicherte Schreibweise, statt blind neu zu formatieren.
  Damit erzeugt auch ein Import keine Dublette desselben Geräts.
* Geräte haben eine eigene Detailseite und sind damit nach dem Anlegen
  bearbeitbar; Exporte oberhalb der Obergrenze werden abgelehnt statt gekürzt;
  die Dashboard-Zahlen stammen aus derselben Menge wie die Listen; Mitgliederlisten
  und Kontofelder verhalten sich wie die übrigen Endpunkte.

## Prüfschritte

```bash
cd backend && .venv/bin/ruff check app alembic tests && .venv/bin/mypy app
cd backend && .venv/bin/pytest --cov=app          # Unit + Integration
cd backend && .venv/bin/pytest -m e2e tests/e2e   # gegen echten freeradius
cd frontend && npm run lint && npm run build
```
