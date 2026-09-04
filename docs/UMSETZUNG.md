# Umsetzungsstand zur Spezifikation v0.1

Stand: 2026-09-04. Diese Datei ordnet die Anforderungen der
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

Fünfundzwanzig Runden eines automatisierten Reviews meldeten 19, 14, 13, 13, 10,
11, 12, 11, 10, 10, 9, 9, 11, 12, 10, 8, 11, 8, 10, 8, 7, 7, 9, 7 und 9 Befunde;
alle sind behoben und mit Regressionstests abgesichert (`test_security_fixes.py`
sowie `test_review_fixes.py` bis `test_review_fixes_7.py` unter
`backend/tests/integration/`). Die Zahl der als P1 eingestuften Befunde ging
dabei von 9 auf null zurück; die späteren Runden betreffen zunehmend Nebenpfade,
Nebenläufigkeit und Bedienkomfort.

Drei Befunde der vierten Runde betrafen unvollständige Korrekturen aus früheren
Runden – der Hintergrundjob für die Aufbewahrungsfrist war nie gestartet worden,
das neue IP-Limit hob sich nach jeder erfolgreichen Anmeldung selbst auf, und die
strukturierte Datenbank-URL scheiterte an der Interpolation von Alembic. Das ist
in den Tests jetzt jeweils direkt abgesichert.

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

Die vierte Runde:

* **Keine Schlüssel-Vorgabewerte mehr.** `docker-compose.yml` verlangt
  `FRM_SECRET_KEY` und `FRM_COA_SECRET_KEY`; im Produktivbetrieb verweigert auch
  die Anwendung selbst den Start ohne eigenständige Schlüssel. Zuvor hätte der
  dokumentierte Schnellstart mit öffentlich bekannten Konstanten laufen können.
* **Alembic verträgt jetzt Sonderzeichen in den Zugangsdaten.** Die strukturierte
  URL enthält Prozentzeichen, die für die Interpolation von `ConfigParser`
  verdoppelt werden müssen – sonst scheiterte `alembic upgrade head` genau bei
  den Zugangsdaten, für die die vorherige Runde die Kodierung eingeführt hatte.
* **Der Aufbewahrungsjob läuft tatsächlich.** Er war in Runde 1 geschrieben, aber
  nie in die Lifespan eingehängt worden; ein Test prüft das nun direkt.
* **Fehlversuche am zweiten Faktor bleiben erhalten**, auch wenn eine neue
  Challenge angefordert wird, und eine eigene erfolgreiche Anmeldung leert nicht
  mehr das IP-weite Kontingent.
* Fehlerhafte CSV-Zeilen brechen den Import nicht mehr ab, Typkollisionen werden
  schon in der Vorschau gemeldet, und Exportwerte, die eine Tabellenkalkulation
  als Formel lesen würde, werden entschärft.
* Die Diagnose erkennt NAS-Netzeinträge; ein ungültiges MAC-Format fällt auf
  einen gültigen Wert zurück; die Detailseiten erhalten alle Gruppenmitgliedschaften.
* Auditoren bekommen keine Schaltflächen mehr angeboten, die zwangsläufig mit
  403 enden – die Durchsetzung bleibt unverändert im Backend.

Die fünfte Runde:

* **Ein offenes Dashboard verlängert die Sitzung nicht mehr.** Die Statistikabfrage
  läuft im Minutentakt und hätte den Idle-Timeout unbegrenzt hinausgeschoben; sie
  kennzeichnet sich jetzt als Hintergrundlauf, und das Backend erneuert dafür kein
  Cookie.
* **Ein abgewiesener Import bricht nicht mehr den ganzen Lauf ab.** Ein von der
  Datenbank zurückgewiesener Wert hinterliess die Sitzung im Fehlerzustand,
  wodurch alle Folgezeilen und der Audit-Eintrag scheiterten. Zusätzlich prüft die
  Vorschau nun dieselben Schemas wie der Schreibvorgang.
* **OIDC-Token ohne `sub` werden abgelehnt** – sonst wären alle solchen Token auf
  demselben lokalen Konto gelandet.
* **Weitere Fehlversuche verlängern eine laufende Kontosperre nicht**, und
  unbekannte Benutzernamen erzeugen denselben Rechenaufwand wie vorhandene.
* Fehlermeldungen folgen der umgeschalteten Oberflächensprache; Exporte behalten
  abweichende Gruppenprioritäten; eine gewechselte Importdatei verwirft die alte
  Vorschau; Sessions haben eine Detailansicht.

Die sechste Runde:

* **Das Sammel-Audit sprengt die Spalte nicht mehr.** Bei mehreren tausend
  Objekten hätten alle Namen die `TEXT`-Spalte überschritten und die Aktion wäre
  nach vollständiger Wirkung mit 500 geendet. Die Namen sind jetzt begrenzt und
  als gekürzt markiert; jede Einzeländerung hat ohnehin einen eigenen Eintrag.
* **Der JWKS-Cache läuft ab und wird bei unbekanntem Schlüssel neu geladen.**
  Nach einer routinemässigen Schlüsselrotation des Identity-Providers wären sonst
  alle OIDC-Anmeldungen bis zum Neustart unmöglich gewesen.
* **Der Aktiv-Filter bildet die vollständige Statusberechnung ab** – abgelaufene
  Objekte und solche ohne Passwort zählen nicht mehr als aktiv, weder in der
  Liste noch in einer daraus bestätigten Sammelaktion.
* Der Rate-Limiter räumt abgelaufene Schlüssel auf; die Prüfung auf den letzten
  Administrator läuft unter einer Zeilensperre; ein defekter Cursor führt nicht
  mehr zu einem Serverfehler.
* Bestandsnamen ohne `radcheck`-Eintrag lassen sich sperren, löschen und mit
  einem Passwort versehen – sie waren sichtbar, aber nicht bedienbar.
* Ein fehlgeschlagenes Element einer Sammelaktion setzt die Sitzung zurück.
* Die Oberfläche leitet Asset- und API-Adressen aus `<base href>` ab, das das
  Backend auf `FRM_ROOT_PATH` setzt; das Sprachcookie wird beim Start
  abgeglichen; Sessions haben Zeitraumfilter.

Die siebte Runde:

* **Eine Rollenänderung beendet die laufende Sitzung.** Zuvor übernahm der
  Manager die neue Rolle sofort aus der Datenbank – eine nur mit Passwort
  begonnene Operator-Sitzung wurde damit zur Administrator-Sitzung, entgegen der
  2FA-Pflicht. Das Token merkt sich nun, ob ein zweiter Faktor geprüft wurde;
  Rollenwechsel und ein zurückgesetztes TOTP erzwingen eine neue Anmeldung.
* **Der Gruppeneditor filtert nur die drei VLAN-Attribute heraus.** Vorher hätte
  das Speichern im Expertenmodus jedes andere `Tunnel-*`-Attribut gelöscht.
* **Die Schemaprüfung leitet sich aus den ORM-Modellen ab** statt aus einer von
  Hand gepflegten Teilliste. Ein Schema ohne `radacct.realm` oder
  `radpostauth.class` wird jetzt beim Start abgewiesen, statt erst zur Laufzeit
  mit „unknown column“ zu scheitern.
* Geräte-Endpunkte prüfen den Objekttyp, und das Anlegen läuft über dieselbe
  Auflösung wie Lesen und Ändern; die Diagnose kennt reine Gruppenzuordnungen;
  das Löschen einer nicht vorhandenen Gruppe ist ein 404 statt eines
  Erfolgseintrags im Audit-Log.
* Der Einrichtungsweg für TOTP schliesst die Anmeldung vollständig ab; von OIDC
  ausgelöste Rollenwechsel stehen im Audit-Log; die gemeldete Seitengrösse
  entspricht der gelieferten.
* Der Router kennt den Basispfad; eine geänderte Filterung leert die Auswahl für
  Sammelaktionen.

Die achte Runde:

* **Eine Passwortänderung verwirft ältere Sitzungen.** Das Token führt den
  Anmeldezeitpunkt mit; liegt er vor `password_changed_at`, endet die Sitzung.
  Ein gestohlenes Cookie überlebte den Passwortwechsel sonst bis zur absoluten
  Gültigkeit.
* **OIDC-Administratoren kommen wieder an der 2FA-Schranke vorbei.** Die Sperre
  aus Runde 7 hätte frisch angelegte OIDC-Konten ausgesperrt; für solche
  Sitzungen verantwortet der Identity-Provider den zweiten Faktor.
* **Das Container-Image wird erst nach dem End-to-End-Test veröffentlicht.**
* **Sperren verändert die Authentifizierungskonfiguration nicht mehr dauerhaft.**
  Ein vorhandenes `Auth-Type` (etwa `PAP`) wird gemerkt und beim Entsperren
  zurückgeschrieben (neue Spalte `mgr_subject.disabled_state`, Migration 0002).
* **Ein Wechsel des Credential-Typs gleicht die Attribute ab** statt nur die
  Notiz zu ändern; ein Wechsel, der Klartext verlangt, wird mit klarer Meldung
  abgelehnt, weil er aus dem NT-Hash nicht herleitbar ist.
* Die Zahl laufender Sessions kommt aus einem `COUNT` statt aus einer begrenzten
  Liste; die Terminate-Cause-Liste nutzt ein Zeitfenster statt eines vollen
  Tabellenscans; Sessionlisten lösen NAS-Netzeinträge auf; eine reine BSSID
  ergibt keine erfundene SSID.
* Eine Geräteumbenennung erkennt Dubletten in anderen MAC-Schreibweisen; eine
  abgewiesene Importzeile zählt nicht mehr zugleich als Erfolg.

Die neunte Runde:

* **Die Rechtevergabe im Betriebshandbuch war falsch.** MariaDB behandelt
  ``radius.`mgr\_%``` als Tabellennamen, nicht als Muster – der so eingerichtete
  Benutzer hätte keinen Zugriff auf eine einzige `mgr_`-Tabelle gehabt. Die
  Anleitung nennt jetzt ein separates Migrationskonto und die konkreten
  Tabellen; beides ist gegen eine echte MariaDB durchgespielt.
* **Optionale Einstellungen erreichen den Container.** OIDC liess sich über den
  dokumentierten `.env`-Weg nicht aktivieren, weil Compose die Variablen nur
  interpoliert hat; ein `env_file`-Eintrag reicht sie nun durch.
* **Eine beendete Sitzung führt sofort zur Anmeldemaske**, statt eine tote
  Oberfläche stehen zu lassen.
* Metadatenfelder haben Längengrenzen passend zu den Spalten; Namen mit
  Schrägstrich werden abgewiesen, statt später über die REST-Pfade unerreichbar
  zu sein; negative Seitenoffsets sind ein Eingabefehler.
* Beim Ersetzen von Prüfattributen bleiben alle bekannten Passwortattribute
  geschützt, nicht nur die zwei häufigsten.
* Der Export-Bearbeiten-Import-Weg ist verlustfrei: die Formel-Entschärfung wird
  beim Import wieder entfernt.
* Sessions lassen sich über den angezeigten NAS-Kurznamen filtern; NAS-Netze
  werden beim Aufbau einer Seite gesammelt aufgelöst statt einzeln abgefragt.

Die zehnte Runde:

* **Fehlversuche werden unter einer Zeilensperre gezählt.** Gleichzeitige
  Versuche hätten denselben Zählerstand gelesen und geschrieben – die Sperre
  wäre bei verteilten Quellen nie erreicht worden. Dasselbe gilt für den
  zweiten Faktor.
* **Ein Passwortwechsel entfernt Duplikate.** `radcheck` erzwingt keine
  Eindeutigkeit; eine zweite `Cleartext-Password`-Zeile aus einer Altinstallation
  hätte das alte Passwort weiter gültig gelassen.
* Gruppennamen dürfen keine CSV-Trennzeichen mehr enthalten, damit
  `gruppe:priorität` eindeutig bleibt; die Gruppenanlage ist über eine benannte
  Sperre serialisiert, da die RADIUS-Tabellen keine Eindeutigkeit kennen.
* Die Gruppenliste lädt die Antwortattribute in einer Abfrage statt je Gruppe.
* Eine geleerte `groups`-Spalte entfernt die Mitgliedschaften, statt sie
  stillschweigend zu behalten; Sammelaktionen prüfen Benutzer und Gruppe, statt
  aus einem Tippfehler Phantom-Objekte zu erzeugen.
* Anmeldeversuche gegen gesperrte oder deaktivierte Konten stehen im Audit-Log;
  überlange OIDC-Benutzernamen werden abgewiesen; die NAS-Notiz wird ausgeliefert.

Die elfte Runde (keine P1-Befunde mehr):

* **Kommagetrennte Listeneinstellungen brachen den Start.** `FRM_TRUSTED_PROXIES`
  in der dokumentierten Schreibweise wurde von pydantic-settings als JSON gelesen
  – die Anwendung startete nicht. Die Felder sind jetzt als „nicht dekodieren“
  markiert.
* Mitgliedschaften über `POST /groups/{name}/members` prüfen Gruppe und Benutzer,
  statt aus einem Tippfehler Phantom-Objekte zu erzeugen.
* Beim CSV-Import unterscheidet eine fehlende Spalte von einer vorhandenen, aber
  leeren Zelle: nur letztere löscht Wert, VLAN, Ablaufdatum oder Metadaten.
* Kontofelder haben Längengrenzen; die Sprache ist auf `de`/`en` beschränkt.
* Ein OIDC-Token mit mehreren Audiences muss zusätzlich `azp` auf diesen Client
  setzen; die automatische Kontoanlage steht im Audit-Log.
* Session-Aktionen nutzen die Zeilen-ID, weil `acctuniqueid` im Schema leer sein
  darf; das Zurücksetzen von TOTP verlangt eine Bestätigung.

Die zwölfte Runde:

* **Die TOTP-Challenge steht nicht mehr in der URL.** Als Query-Parameter wäre
  dieses kurzlebige Zugangsmerkmal in jedem Zugriffsprotokoll gelandet und dort
  innerhalb seiner Gültigkeit wiederverwendbar gewesen; sie geht jetzt im Rumpf.
* **Die administrative OIDC-Verknüpfung existiert.** Der Callback lehnt eine
  automatische Bindung bewusst ab – bislang fehlte aber der dokumentierte Weg,
  ein Bestandskonto von Hand zu verknüpfen (`PUT /accounts/{id}/oidc`).
* Mitgliedschaften prüfen die Gruppe auch beim Anlegen und Ändern eines
  Benutzers; ein Tippfehler erzeugt keine Phantomgruppe mehr. **Hinweis:** damit
  müssen Gruppen vor der Zuweisung existieren, auch beim CSV-Import.
* Das Audit-Log hält beim Löschen den vollständigen vorherigen Zustand fest und
  protokolliert auch CoA-Versuche, die vor dem Versand abgewiesen werden.
* Bei aktiviertem SQL-Echo werden gebundene Werte nicht mehr protokolliert.
* OIDC-Claims werden auf die Spaltenbreite gekürzt; das CoA-Secret ist auch bei
  Änderungen begrenzt; das Deaktivieren eines Kontos verlangt eine Bestätigung.

Die dreizehnte Runde:

* **Eine abgemeldete Ansicht erzeugte eine Endlosschleife.** Der 401-Haken aus
  Runde 11 lud auch die Sitzungsabfrage neu, deren eigene 401-Antwort ihn wieder
  auslöste. Er lässt diese Abfrage jetzt aus.
* **Ein unbekannter Statusfilter weitete die Auswahl auf alles aus.** Mit
  `filter_all` hätte ein Tippfehler wie `status=disbaled` eine Sammelaktion auf
  sämtliche Objekte angewandt; solche Werte werden nun abgewiesen.
* **Das Bootstrap-Passwort unterliegt der Passwortrichtlinie.** Ein Platzhalter
  in der Umgebung wäre sonst ein Administratorzugang mit ratbarem Passwort.
* **`oidc_subject` wird fallunterscheidend gespeichert** (Migration 0003); mit
  der voreingestellten Kollation hätte „Alice“ die Sitzung von „alice“ erhalten.
* Ablaufdaten werden in SQL gegen `UTC_TIMESTAMP()` verglichen, nicht gegen die
  Sitzungszeitzone der Datenbank.
* Doppelte Gruppenangaben werden zusammengefasst; die Import-Vorschau prüft die
  Gruppen wie der Schreibvorgang; die Formel-Entschärfung ist auch bei Werten
  umkehrbar, die selbst mit einem Hochkomma beginnen.
* Das Audit-Log hält beim Löschen einer Gruppe deren Konfiguration fest; eine
  NAS-Notiz lässt sich wieder entfernen; der Credential-Typ ist beim Setzen
  eines Passworts in der Oberfläche wählbar.

Die vierzehnte Runde:

* **Ein zurückgesetztes TOTP entwertet Sitzungen dauerhaft.** Bisher galt eine
  vorher gestohlene Sitzung wieder, sobald ein neuer Faktor eingerichtet war;
  das Token trägt jetzt den Zeitpunkt der letzten TOTP-Änderung
  (Migration 0004).
* **Die SNMP-Community steht nicht mehr im Audit-Log.** Sie ist ein
  Zugangsmerkmal und wird auch sonst nicht ausgeliefert.
* Die benannte Sperre bricht bei Zeitüberschreitung ab, statt den serialisierten
  Abschnitt ungeschützt zu betreten.
* Ein Anmeldeversuch in derselben Sekunde wie eine Passwortänderung bleibt
  gültig (sekundengenauer Vergleich).
* Fehlversuche beim Ändern des eigenen Passworts zählen auf die Kontosperre ein
  und stehen im Audit-Log.
* Ein Gerät mit reinem NT-Hash bekommt beim Umbenennen den neuen Hash; ein
  CSV-Import, der nur den Credential-Typ ändert, wirkt jetzt.
* Importfehler nennen Feld und Fehlerart statt des eingereichten Werts – ein zu
  langes Passwort stand sonst in der Antwort.
* Überlange OIDC-Subjects werden abgewiesen; Gerätepasswörter und Prioritäten
  sind bereits im Request begrenzt; das CoA-Secret lässt sich in der Oberfläche
  entfernen.

Die fünfzehnte Runde:

* **Die TOTP-Einrichtung aus dem eigenen Profil funktioniert wieder.** Die
  Änderung aus Runde 14 setzte die Generation schon beim Start und beendete
  damit die laufende Sitzung mitten im Vorgang; der Zeitstempel wird jetzt erst
  bei der Bestätigung gesetzt. Ein administratives Zurücksetzen wirkt weiterhin
  sofort.
* **OIDC-Subjects werden unverändert übernommen.** Ein getrimmter Wert hätte
  ` alice` die Sitzung von `alice` verschafft.
* Die Kontosperre gilt auch beim Ändern des eigenen Passworts.
* Umbenennen einer Gruppe und das Hinzufügen einer Mitgliedschaft laufen unter
  derselben Sperre wie das Anlegen.
* `GET /settings` ist Administratoren vorbehalten; den MAB-Schalter liefert der
  Geräte-Endpunkt für alle Rollen.
* `true` wird nicht mehr als Aufbewahrungsdauer akzeptiert – Python liest es
  sonst als ein Tag und der Job hätte fast das ganze Audit-Log gelöscht.
* Passwörter behalten beim Import ihre Leerzeichen; Attributmengen und
  Bulk-Prioritäten sind begrenzt.

Die sechzehnte Runde (keine P1-Befunde):

* Die Sperre beim Umbenennen einer Gruppe wird bis zum Commit gehalten; der
  Fehlerzähler beim Passwortwechsel steht unter einer Zeilensperre.
* Mehrfach vorhandene `Auth-Type`- oder `Expiration`-Zeilen werden in der
  Detailansicht genauso bewertet wie im SQL-Filter – sonst zeigte die Liste
  „aktiv“, während eine Sammelaktion dasselbe Objekt erfasste.
* Ein Bestandsbenutzer ohne Manager-Metadaten übernimmt seinen tatsächlichen
  Credential-Typ, statt pauschal als `both` geführt zu werden.
* Ein ungültiges `FRM_OIDC_ROLE_MAP` bricht den Start ab, statt jede passende
  Anmeldung in einem Serverfehler enden zu lassen.
* Mehrzeilige Notizen überstehen den Export; NAS-Notizen sind längenbegrenzt.
* Eine CoA-Anfrage nur mit Benutzernamen wird abgewiesen, wenn mehrere Sessions
  laufen – zuvor traf es stillschweigend die zuletzt begonnene.

Die siebzehnte Runde:

* **Die benannte Sperre liegt auf einer eigenen Verbindung.** Über die Sitzung
  des Aufrufers ging sie beim Commit an den Pool zurück; das `RELEASE_LOCK` lief
  dann auf einer fremden Verbindung und die Sperre blieb hängen.
* **Alle FreeRADIUS-Passwortattribute werden maskiert**, nicht nur die
  häufigsten – `SSHA-Password`, `SMD5-Password` und `Password-With-Header`
  standen zuvor im Klartext in API-Antwort und Audit-Log.
* Beim Entsperren werden gezielt die `Reject`-Zeilen entfernt; eine daneben
  bestehende Vorgabe wie `PAP` bleibt erhalten.
* Fehlermeldungen füllen die Platzhalter des Katalogs; zuvor stand dort wörtlich
  `{cap}` oder `{username}`.
* Aktiviertes OIDC ohne Aussteller, Client-ID oder Redirect-URL bricht den Start
  ab; die Selbstbedienung beim zweiten Faktor steht mit Namen im Audit-Log.
* Geräte-Schemas, CoA-Secrets (nach Bytes) und Notizen sind begrenzt; ein
  abgelaufener Download führt zur Anmeldemaske; ein angezeigtes NAS-Secret wird
  nach dem Speichern verworfen.

Die achtzehnte Runde (keine P1-Befunde):

* Die Freigabe der benannten Sperre ist parametrisiert – ein Gruppenname wie
  `O'Reilly` erzeugte sonst ungültiges SQL, nachdem die Änderung bereits
  festgeschrieben war.
* Der Bootstrap prüft zuerst, ob überhaupt ein Konto entstehen soll; ein
  inzwischen unbenutzter Platzhalter blockierte sonst den Start.
* Rate-Limits müssen positiv sein, sonst schlüge jede Anmeldung fehl.
* Die Diagnose bewertet wie die Liste alle `Auth-Type`- und
  `Expiration`-Zeilen.
* Ein unbekannter Wahrheitswert im CSV ist ein Fehler, statt als „nicht
  gesperrt“ gelesen zu werden; ein Import mit Passwort *und* Typwechsel schreibt
  erst das Passwort.
* Sammelaktionen legen Mitgliedschaften unter derselben Sperre an wie die
  Gruppenverwaltung.
* `radacctid` und die Auth-Log-ID werden als Zeichenkette ausgeliefert: als
  JavaScript-Zahl verlören BIGINT-Werte an Genauigkeit und die Oberfläche
  spräche eine benachbarte Session an.

Die neunzehnte Runde (keine P1-Befunde):

* Eine vor einer Passwortänderung ausgestellte TOTP-Challenge gilt nicht mehr.
* Die Geräte-Auflösung nimmt die angefragte Schreibweise, bevor sie normalisiert –
  bei zwei Formaten desselben Geräts war sonst der falsche Datensatz gemeint.
* Ein `PATCH` auf eine Gruppe läuft vollständig unter deren Sperre; zwei
  gleichzeitige Änderungen überschrieben sich sonst gegenseitig.
* Arbeitsintervalle der Hintergrundjobs müssen positiv sein.
* Unbekannte CSV-Spalten sind ein Fehler; die Vorschau prüft auch einen
  Typwechsel gegen den Bestand; `set_expiry` legt keine Phantom-Benutzer an.
* Eine manuelle OIDC-Verknüpfung mit Leerraum wird abgewiesen – sie hätte sich
  nie anmelden können.
* Werte für IP-Attribute werden geprüft; der Gruppendialog bleibt offen, solange
  Warnungen anzuzeigen sind.
* Die Vorgabewerte der Enum-Spalten in den Migrationen entsprechen jetzt den
  gespeicherten Namen (Migration 0005).

Die zwanzigste Runde:

* Sitzungslaufzeiten und die Aufbewahrungsdauer müssen positiv sein – bei `0`
  wäre jede Anmeldung sofort abgelaufen bzw. das Audit-Log beim ersten Lauf des
  Hintergrundjobs leer.
* Die Obergrenze für Attributsammlungen ist so gewählt, dass auch eine maximale
  Nutzlast in die Audit-Spalte passt (50 statt 200 je Sammlung).
* Mitgliedschaften laufen unter derselben Sperre wie Umbenennen und Löschen der
  Gruppe; sonst konnte eine Zuordnung unter dem alten Namen entstehen und die
  Gruppe wiederauferstehen lassen.
* Sessions lassen sich auch über per CIDR eingetragene NAS filtern.
* Das Löschen eines Kontos hält dessen Rolle und Zustand im Audit-Log fest.
* Die Import-Vorschau zeigt Fehlerzeilen vollständig, auch jenseits der
  Anzeigegrenze.
* VLAN-Werte sind auch beim Gruppen-Update begrenzt.

Die einundzwanzigste Runde (keine P1-Befunde):

* Der SQL-Statusfilter liest dieselben Datumsformate wie die Detailansicht;
  ein Bestandswert wie `2026-09-01` wurde sonst unterschiedlich bewertet.
* Ein NAS-Netz, das sich nicht in ein SQL-Prädikat übersetzen lässt, liefert
  eine leere Menge statt aller Sessions.
* Das Löschen eines NAS hält dessen Konfiguration im Audit-Log fest (ohne das
  Shared Secret).
* Attributnamen und Operatoren mit Leerraum werden abgewiesen, statt geprüft und
  dann anders gespeichert zu werden.
* Der Verbindungspool muss zwei gleichzeitige Verbindungen zulassen, weil
  benannte Sperren eine eigene benötigen.
* Ein falsches aktuelles Passwort oder ein falscher TOTP-Code führt nicht mehr
  zur Anmeldemaske – das sind behebbare Formularfehler, keine beendete Sitzung.
* Das Sperren eines Benutzers oder Geräts verlangt eine Bestätigung.

Die zweiundzwanzigste Runde (keine P1-Befunde):

* **Schreibende Anfragen fremder Herkunft werden abgewiesen.** `SameSite=Lax`
  schützt nicht vor einem Geschwister-Host derselben registrierbaren Domain;
  eine Herkunftsprüfung ergänzt das Cookie (`FRM_ALLOWED_ORIGINS` für weitere
  erlaubte Adressen).
* Ein Sperr-/Entsperrzyklus erhält alle `Auth-Type`-Zeilen, nicht nur die erste.
* Sperrschlüssel werden gehasht statt abgeschnitten – zwei lange Namen mit
  gleichem Anfang hätten sonst denselben Schlüssel und eine Umbenennung zwischen
  ihnen wartete auf sich selbst.
* Zeitgrenzen der Filter werden nach UTC normalisiert; ein Wert mit Zeitzone
  verschob das Fenster.
* Ein Name darf in einer Importdatei nur einmal vorkommen.
* Die Startprüfung vergleicht auch die Spaltentypen des RADIUS-Schemas.
* Die Namensliste im Audit-Eintrag einer Mitgliedschaftsänderung ist begrenzt.

Die dreiundzwanzigste Runde (keine P1-Befunde):

* Eine CoA-Antwort des falschen Typs gilt nicht mehr als Erfolg – ein Disconnect,
  das mit einem CoA-ACK beantwortet wird, hat nichts getrennt.
* CoA-Zeitgrenze und Versuchszahl müssen positiv sein.
* Der gemerkte `Auth-Type`-Zustand liegt in einer `TEXT`-Spalte (Migration 0006);
  mehrere lange Werte sprengten die bisherige Grenze.
* Ein `/32`-NAS wird als Gleichheit statt als Präfix gefiltert.
* Die Sperre der Sammelaktion hält bis zum Commit; die Fehlerzeilen der Vorschau
  sind begrenzt.
* Doppelte maskierte Gruppenattribute behalten ihre einzelnen Werte.
* Die im Modell deklarierten Indizes entsprechen den Migrationen, damit eine
  spätere Autogenerierung sie nicht zum Löschen vorschlägt.

Die vierundzwanzigste Runde (keine P1-Befunde):

* Der Importbericht behält nur eine begrenzte Zahl Zeilen – bereits beim Lesen,
  nicht erst in der Antwort; Fehlerzeilen werden dabei bevorzugt.
* Löschen und Passwortwechsel eines Benutzers laufen unter derselben Sperre.
* Die letzte Mitgliedschaft einer attributlosen Gruppe lässt sich nicht
  entfernen – die Gruppe verschwände sonst ohne Bestätigung und ohne Eintrag im
  Audit-Log.
* Benutzernamen in Sammelaktionen sind auch einzeln längenbegrenzt.
* `show_mab_warning` verlangt einen echten Wahrheitswert.
* Das Einschränken einer Rolle verlangt eine Bestätigung, weil es die Sitzung
  des Kontos beendet.

Die fünfundzwanzigste Runde:

* **Gruppendefinitionen sind Administratoren vorbehalten.** Ein Operator konnte
  bisher `radgroupcheck`/`radgroupreply` beliebig ändern – also die Policy aller
  Mitglieder. Mitgliedschaften darf er weiterhin pflegen (Abschnitt 2).
* **Der Compose-Stapel trennt die Datenbankkonten.** FreeRADIUS bekommt ein
  eigenes Konto mit Rechten nur auf die RADIUS-Tabellen; die `mgr_`-Tabellen
  sieht es nicht mehr (`docker/radius-grants.sh`, gegen den laufenden Stapel
  geprüft).
* Benannte Sperren laufen über einen eigenen Verbindungspool, damit sie die
  Abfragen der Anfragen nicht aushungern.
* Das Löschen einer Gruppe hält dieselbe Sperre wie Anlegen und Ändern.
* CoA lässt sich nicht ohne Secret einschalten; ein entferntes Secret schaltet
  CoA ab.
* Mitgliedschaftslisten sind begrenzt.
* Die Oberfläche bietet alle vier Statusfilter, eine Bedienoberfläche für die
  OIDC-Verknüpfung und verwirft ein angezeigtes NAS-Secret beim Löschen.

### Neunte Runde

* **Der Compose-Stapel legt das FreeRADIUS-Konto mit den konfigurierten
  Zugangsdaten an.** Die Rechtevergabe war fest auf `freeradius`/`freeradius`
  verdrahtet, während Compose `RADIUS_DB_USER`/`RADIUS_DB_PASSWORD` an den
  Dienst reichte – mit der `.env.example` konnte FreeRADIUS sich nicht anmelden.
  Aus der `.sql` wurde `docker/radius-grants.sh`, das Benutzer, Passwort und
  Datenbankname aus der Umgebung übernimmt und für SQL maskiert (gegen den
  laufenden Stapel mit abweichenden Zugangsdaten samt Anführungszeichen im
  Passwort geprüft).
* **Sperren und Entsperren halten dieselbe Lebenszyklus-Sperre wie Löschen.**
  Sonst konnte ein gleichzeitiges Löschen dazwischentreten und der Benutzer
  stand anschließend als reine `Auth-Type := Reject`-Zeile wieder da.
* **Die Gruppenseite verlangt jetzt Administratorrechte.** Seit der achten Runde
  setzt das Backend dafür `AdminUser` durch; die Oberfläche bot einem Operator
  weiterhin Schaltflächen an, die zwangsläufig mit 403 endeten.
* **Der Filter auf `Called-Station-Id` vergleicht exakt** statt mit beidseitiger
  Wildcard. Die Spalte trägt im FreeRADIUS-Schema keinen Index, das wir nicht
  ändern; die alte Form las bei jeder Abfrage die ganze `radacct` (NFR-2). Die
  SSID ist laut Spezifikation ein Anzeigewert, kein Filter.
* Die Diagnose meldet den NAS-Kurznamen der letzten Session – bisher zeigte sie
  als einzige Ansicht die rohe Adresse.
* Aufbewahrungsfristen haben eine Obergrenze (36 500 Tage). Größere Werte ließen
  `timedelta` überlaufen: die API meldete Erfolg, der Aufräumjob scheiterte
  danach bei jedem Lauf.
* `nas.ports` ist auf den Wertebereich der Spalte begrenzt und die
  Gruppenliste beim Anlegen eines Geräts auf dieselbe Länge wie überall sonst –
  beides scheiterte vorher erst beim Schreiben, mit einem allgemeinen 500.

### Zehnte Runde

* **Benannte Sperren nutzen jetzt tatsächlich den eigenen Pool.** Im Betrieb ist
  `session.bind` die Abfrage-Engine – die Bedingung wählte damit immer den
  Abfragepool, die in der achten Runde eingeführte Trennung war wirkungslos.
* **`named_lock` nimmt mehrere Namen auf einer Verbindung**, sortiert. Geschachtelte
  Aufrufe brauchten je eine Verbindung (eine Mitgliedschaftsliste hätte den
  Sperrpool erschöpft) und zwei Aufrufer in unterschiedlicher Reihenfolge liefen
  in eine Verklemmung.
* **Anlegen und Ändern eines Benutzers sperren auch die Zielgruppen.** Wurde eine
  Gruppe zwischen Existenzprüfung und Schreiben gelöscht, liess die neue
  `radusergroup`-Zeile sie als reine Mitgliedschaftsgruppe wieder auferstehen.
* **Das Entfernen einer Mitgliedschaft läuft unter der Gruppensperre** – in der
  Gruppenverwaltung wie in den Sammelaktionen. Zwei gleichzeitige Aufrufe sahen
  sonst beide noch zwei Mitglieder und löschten anschliessend beide; die
  attributlose Gruppe verschwand trotz der Schutzprüfung.
* **`ipaddr`-Attribute nehmen nur noch IPv4 an.** Das RADIUS-Wörterbuch führt
  `NAS-IP-Address` und `Framed-IP-Address` als Vier-Byte-Typ; ein IPv6-Wert war
  bisher speicherbar, aber für FreeRADIUS weder lesbar noch kodierbar.
* **Der Bootstrap-Administrator wird vor dem Einfügen geprüft.** Ein zu langer
  `FRM_BOOTSTRAP_ADMIN_USERNAME` umging die Schemavalidierung und liess den
  ersten Start mit einem Datenbankfehler scheitern.
* **Die Herkunftsprüfung traut dem Host-Header nicht mehr, wenn
  `FRM_COOKIE_DOMAIN` gesetzt ist.** Genau dann geht das Sitzungscookie an jeden
  Host der Domain – die vom Aufrufer gesetzte Adresse als eigene zu übernehmen
  hob den Schutz auf. In dieser Betriebsart verlangt die Konfiguration jetzt
  eingetragene Herkünfte, mit einem Startfehler statt einem 403 im Betrieb.
* **Die Oberfläche kann Mitgliedschafts-Prioritäten setzen.** Benutzer- und
  Gerätedetail, beide Anlegedialoge und die Sammelaktion bieten jetzt ein Feld
  für `radusergroup.priority`; bisher schrieb jedes Speichern den Wert 1 zurück.

### Elfte Runde

* **Das Ersetzen der Mitgliedschaften sperrt auch die verlassenen Gruppen.** Die
  Sperrliste enthielt nur die Zielgruppen; zwei gleichzeitige Änderungen an
  verschiedenen Benutzern sahen beide noch zwei Mitglieder und löschten dann
  beide. Eine Mitgliedschaft, die erst nach dem Setzen der Sperren entsteht,
  führt jetzt zu `error.busy` statt zu einer ungesicherten Löschung.
* **`DeviceService.resolve` liefert die gespeicherte Schreibweise.** Die
  Standardkollation vergleicht ohne Rücksicht auf Gross-/Kleinschreibung: bei
  einem Aufruf mit `AA:BB:…` gab die Auflösung bisher die Schreibweise des
  Aufrufers zurück, das Umbenennen erkannte danach nicht mehr, dass die MAC
  zugleich das Passwort ist – MAB schlug fehl (FR-3).
* **`integer`-Attribute sind auf den RADIUS-Wertebereich begrenzt** (vier Byte
  ohne Vorzeichen, RFC 2865). Bisher wurde nur die Zeichenform geprüft.
* **Der Gruppenname einer Sammelaktion ist begrenzt** wie in allen anderen
  Schemas; ein überlanger Wert sprengte sonst die TEXT-Spalte des
  Sammel-Audit-Eintrags – nach bereits ausgeführten Einzelaktionen.
* **Eine mit Warnung angelegte Gruppe wechselt in den Bearbeitungsmodus.** Der
  Dialog blieb offen, damit die Warnung lesbar bleibt; ein zweites Speichern
  lief aber erneut als POST und scheiterte an `group_exists`.
* **Das Profil bietet die TOTP-Einrichtung nicht mehr an, wenn der Faktor aktiv
  ist.** Die Schaltfläche endete zwangsläufig mit `error.totp_already_enrolled`.

### Zwölfte Runde

* **Eine Importzeile läuft in einer Transaktion.** Passwort, Aktualisierung und
  Sperrzustand schrieben je einzeln fest; scheiterte ein späterer Teilschritt,
  blieb das neue Passwort stehen, obwohl der Bericht die Zeile als Fehler
  meldete (FR-8). `UserService.apply_row` hält alle Teilschritte unter derselben
  Sperre und schreibt einmal fest.
* **Namensvergleiche folgen der Datenbank-Kollation.** Die Standardkollation
  vergleicht ohne Rücksicht auf Gross-/Kleinschreibung; Sperrschlüssel,
  Dublettenerkennung im Import und das Zusammenfassen von Mitgliedschaften
  verglichen dagegen Zeichenketten exakt. `Staff` und `staff` liefen so
  gleichzeitig durch dieselbe Sperre bzw. erzeugten zwei `radusergroup`-Zeilen.
* **NAS-Netze abseits der Oktettgrenzen werden gefiltert.** Ein als `/25` oder
  `/12` eingetragenes NAS wurde angezeigt und für CoA korrekt zugeordnet, als
  Filter lieferte es aber gar keinen Treffer.
* **TOTP-Einrichtung, -Bestätigung und administratives Zurücksetzen sind
  serialisiert.** Ein Reset dazwischen liess das Konto als „TOTP aktiv, ohne
  Geheimnis“ zurück – eine Anmeldung wäre danach unmöglich gewesen.
* **Ein erfolgreicher Passwortwechsel leert den Fehlerzähler.** Sonst trug das
  Konto frühere Fehlversuche in die erzwungene Neuanmeldung mit und ein
  einzelner Tippfehler sperrte es.
* **Das erzwungene Löschen einer Gruppe protokolliert die Mitglieder** (begrenzt
  und mit Kürzungsmarke); die reine Anzahl liess nicht erkennen, wer die Policy
  verloren hat (FR-9).
* **Der Import ist auf 10 000 Zeilen begrenzt** – wie Sammelaktionen und Export.
  Die Grössenbeschränkung des Uploads begrenzte die Zeilenzahl nicht.
* Der Gruppendialog speichert nicht, solange die Details noch laden: ein Klick in
  diesem Moment hätte VLAN und Attribute der Gruppe geleert.

### Dreizehnte Runde

* **Ein TOTP-Code gilt nur einmal.** `mgr_account.totp_last_counter` hält das
  zuletzt angenommene Zeitfenster fest (Migration 0007). Ein abgefangener Code
  liess sich bisher innerhalb des Prüffensters ein zweites Mal einlösen und
  erzeugte eine weitere Sitzung.
* **Der Sitzungsentzug arbeitet mit Sekundenbruchteilen.** `password_changed_at`
  und `totp_changed_at` sind jetzt `DATETIME(6)`, `auth_at` steht als
  Gleitkommazahl im Token. Eine Passwortänderung oder ein TOTP-Reset in
  derselben Sekunde, in der die Sitzung ausgestellt wurde, verwarf diese sonst
  nicht – das Cookie blieb bis zur absoluten Gültigkeit brauchbar.
  Migration 0007 wurde gegen eine echte MariaDB in beide Richtungen geprüft.
* **Eine abgelaufene Kontosperre setzt den Fehlerzähler zurück.** Sonst löste der
  erste Fehlversuch danach – auch am zweiten Faktor – sofort die nächste
  15-Minuten-Sperre aus.
* **Der Vergleich von Bezeichnern ignoriert auch Akzente**, wie die
  Standardkollation. `café` und `cafe` ergaben sonst verschiedene
  Sperrschlüssel, obwohl die Datenbank dieselbe Zeile meint.
* **Der Schutz der letzten Mitgliedschaft vergleicht wie die Datenbank.** Ein
  gespeichertes `Alice` liess sich mit `alice` entfernen, ohne dass die Prüfung
  es als letzte Mitgliedschaft erkannte – die attributlose Gruppe verschwand
  ohne `group.delete`.
* **Mitgliedschaftsänderungen halten auch die Lebenszyklus-Sperre der Benutzer.**
  Ein gleichzeitiges Löschen liess sonst einen Phantom-Benutzer ohne
  Anmeldedaten zurück.

### Vierzehnte Runde

* **Auch die TOTP-Challenge trägt Sekundenbruchteile.** `iat` ist laut JWT eine
  ganze Sekunde; eine Passwortänderung in derselben Sekunde liess die Challenge
  deshalb weiterlaufen – bei einer laufenden TOTP-Ersteinrichtung sogar bis zur
  fertigen Sitzung.
* **Die Gruppenübersicht verbindet ihre Teilabfragen über die Vergleichsform.**
  Attributzeilen (`Staff`) und Mitgliedschaften (`staff`) können verschiedene
  Schreibweisen führen; die Übersicht meldete dann null Mitglieder.
* **Eine als Filter eingegebene NAS-Adresse wird exakt behandelt.** `10.0.0.1`
  lieferte über die Teiltextsuche auch die Sitzungen von `10.0.0.10`. Die Suche
  über Kurz- und Anzeigenamen bleibt unverändert.

### Fünfzehnte Runde

* **Rollen- und Statusänderungen entziehen Sitzungen dauerhaft.**
  `mgr_account.session_epoch` (Migration 0008) wird bei einer Rollen- oder
  Statusänderung erhöht und im Token mitgeführt. Bisher lebten die Token eines
  deaktivierten Kontos nach der Reaktivierung wieder auf – und eine
  Administratorsitzung nach einer Rollenänderung hin und zurück.
  Migration 0008 wurde gegen eine echte MariaDB in beide Richtungen geprüft.
* **Der CSV-Download frischt das Sitzungscookie wieder auf.** Der Endpunkt gibt
  ein eigenes Response-Objekt zurück; FastAPI verwarf damit den `Set-Cookie` der
  Abhängigkeit. Das Cookie setzt jetzt eine Middleware am Ende der Kette.
* **Enum-Werte werden gegen das Wörterbuch geprüft.** Bewusst als Warnung, nicht
  als Fehler: die Wertelisten sind eine kuratierte Auswahl (`Auth-Type` nimmt
  jeden konfigurierten Modulnamen an), ein harter Fehler wiese gültige
  Konfigurationen ab.
* **Das Löschen eines Benutzers protokolliert verschwindende Gruppen.** Bestand
  eine Gruppe nur über diese eine Mitgliedschaft, verschwand sie bisher ohne
  jeden Eintrag; das Löschen deswegen zu verweigern wäre eine Sackgasse, deshalb
  wird der Wegfall als `group.delete` festgehalten (FR-9).
* **Die Sammelaktion `set_expiry` läuft unter der Lebenszyklus-Sperre.** Ein
  gleichzeitiges Löschen liess sonst einen Benutzer aus Metadaten und
  `Expiration`-Zeile ohne Anmeldedaten entstehen.
* **Die Benutzerdetailansicht hat einen Expertenmodus** für `radcheck`- und
  `radreply`-Zeilen. Regeln wie `Simultaneous-Use` oder `Filter-Id` liessen sich
  bisher nur ausserhalb der Anwendung setzen, obwohl die API sie unterstützt.
* Der Schutz des letzten Administrators greift beim Deaktivieren nur noch für
  Administratorkonten – vorher prüfte er auch beim Deaktivieren eines Operators.

### Sechzehnte Runde

* **Authentifizierungs-Cookies gelten nur unter dem Basispfad.** Läuft der
  Manager hinter `FRM_ROOT_PATH=/manager`, ging das Sitzungscookie mit `/` an
  jede andere Anwendung desselben Hosts – deren Upstream sah das JWT im
  Cookie-Header. Gleiches galt für das OIDC-State-Cookie.
* **Die Oberfläche lässt sich nicht mehr einbetten.** `Content-Security-Policy:
  frame-ancestors 'none'` und `X-Frame-Options: DENY` (dazu `nosniff` und
  `Referrer-Policy`). Ohne sie hätte ein Nachbarhost derselben Domain den
  Manager in einen Rahmen laden können – das Cookie ging mit `SameSite=Lax`
  weiterhin mit und ein Klick darin stammte für die Herkunftsprüfung vom
  Manager selbst.
* **Das Lösen einer OIDC-Verknüpfung entzieht Sitzungen sofort.** Bisher blieben
  die über diese Identität ausgestellten Sitzungen bis zum Ablauf gültig.
* **Auch die TOTP-Challenge trägt die Sitzungsgeneration.** Eine vor einer
  Deaktivierung angeforderte Challenge liess sich sonst nach der Reaktivierung
  innerhalb ihrer fünf Minuten noch einlösen.
* **Die Benutzerliste verbindet Mitgliedschaften über die Vergleichsform.**
  Anmeldedaten als `Alice` und Mitgliedschaft als `alice` gehören zum selben
  Benutzer; die Liste und der CSV-Export liessen die Mitgliedschaft sonst weg –
  und ein Reimport dieser Datei entfernte sie dann tatsächlich.
* **Die Diagnose wertet die Check-Attribute der Gruppen mit aus.** Ein
  `Auth-Type := Reject` oder abgelaufenes `Expiration` auf Gruppenebene ist der
  tatsächliche Grund für einen Access-Reject; die Diagnose meldete den Benutzer
  bisher als aktiv (FR-6).
* **Der Expertenmodus der Benutzerdetailansicht blendet reservierte Zeilen aus.**
  Passwort-, `Auth-Type`- und `Expiration`-Zeilen weist das Backend als
  reserviert ab; unverändert zurückgeschickt scheiterte jede andere Änderung.
  Die Liste kommt aus dem Wörterbuch-Endpunkt, damit beide Seiten dieselbe
  Menge verwenden.
* Die Warnung einer Gruppenanlage bleibt beim Wechsel in den Bearbeitungsmodus
  sichtbar.

### Siebzehnte Runde

* **Der Import prüft die Zeilenzahl, bevor er irgendetwas schreibt.** Die Grenze
  wirkte bisher erst während des Durchlaufs; bei einem echten Import blieben die
  ersten 10 000 Änderungen bestehen, obwohl die Antwort nur einen Fehler meldete.
* **Die Sammelzuordnung prüft die Existenz innerhalb der Sperre.** Ein
  gleichzeitiges Löschen zwischen Prüfung und Einfügen liess sonst einen
  Phantom-Benutzer ohne Anmeldedaten entstehen.
* **Audit-Nutzlasten sind nach Bytes begrenzt.** `mgr_audit.after_json` fasst
  65 535 *Bytes*; 50 Check- und 50 Reply-Werte mit mehrbytigen Zeichen sprengten
  die Spalte und rissen den ganzen Vorgang mit. Zu grosse Nutzlasten werden mit
  einer Kürzungsmarke abgelegt.
* **Der Vergleich der gewünschten Gruppen folgt der Kollation.** Eine bestehende
  Mitgliedschaft `staff` und der angeforderte Name `Staff` galten als Entfernung
  – der Schutz der letzten Mitgliedschaft wies eine inhaltlich unveränderte
  Anfrage ab.
* **`date`-Attribute werden geprüft.** Ein `Expiration := not-a-date` im
  Expertenmodus blieb gespeichert, während die gemeinte Sperre nie griff.
* **Der Beginn der TOTP-Einrichtung wird protokolliert.** Ein abgebrochener
  Versuch hinterliess bisher gar keinen Eintrag, obwohl dabei ein Geheimnis
  dauerhaft geschrieben wird (FR-9).
* **Das IP-Kontingent greift vor dem Dekodieren der TOTP-Challenge**, und deren
  Länge ist begrenzt. Ungültige Challenges liefen sonst unbegrenzt durch die
  Signaturprüfung, ohne das Kontingent zu verbrauchen.
* **Nach der eigenen TOTP-Einrichtung führt die Oberfläche zur Anmeldung.** Die
  Bestätigung entwertet das eigene Cookie; die Oberfläche blieb bisher mit den
  alten Daten stehen und erst die nächste Aktion lief ins Leere.
* Der Expertenmodus der Benutzerdetailansicht ist erst verfügbar, wenn die Liste
  der reservierten Attribute geladen ist.
* Die Rate-Limiter werden zwischen Tests zurückgesetzt: ein Test, der das
  Kontingent absichtlich ausreizt, beeinflusste sonst die nachfolgenden.

### Achtzehnte Runde

* **Benannte Sperren erneuern den Lesestand.** MariaDB fährt `REPEATABLE READ`;
  die Sitzung hatte ihren Snapshot meist schon beim Lesen des Kontos festgelegt.
  Wer auf die Sperre wartete, sah den soeben festgeschriebenen Stand des anderen
  nicht – beide Prüfungen gingen durch und beide schrieben.
* **Der Import liest höchstens 10 001 Zeilen ein.** `list(reader)` baute bei
  einer kompakten Datei innerhalb der Upload-Grenze Millionen Zeilen-Dicts,
  bevor die Prüfung überhaupt lief.
* **Metadaten einer Importzeile entstehen erst unter der Lebenszyklus-Sperre.**
  Ein gleichzeitiges Löschen zwischen Einstufung und Schreiben liess den
  Datensatz sonst als Metadatenrumpf – oder mit Passwort – wieder entstehen.
* **Auch die Bestätigung der TOTP-Einrichtung weist Wiedereinsatz ab.**
  Challenge und Code liessen sich innerhalb des Prüffensters erneut einlösen und
  erzeugten eine weitere Sitzung.
* **Byte-Zähler werden als Zeichenkette ausgeliefert** (`acctinputoctets`,
  `acctoutputoctets` und die Tagessummen). Oberhalb von 2^53 rundete JavaScript
  sie stillschweigend; die Oberfläche rechnet jetzt mit `BigInt`.
* **Ein Passwortwechsel im Profil führt zur Anmeldung zurück.** Er entwertet das
  eigene Cookie; die Oberfläche blieb sonst sichtbar, aber unbenutzbar.
* Der Expertenmodus des Gruppendialogs ist gesperrt, solange die Details laden –
  ein dort begonnener Entwurf hätte die geladenen Attribute überschrieben.
* Die Benutzerdetailansicht zeigt die Warnungen der Speicherung; die
  anschliessend neu geladene Ansicht enthält sie nicht mehr.

### Neunzehnte Runde

* **Ein Passwortwechsel entfernt alle bisherigen Anmeldedaten.** Bisher wurden
  nur `Cleartext-Password` und `NT-Password` gelöscht; ein importierter Benutzer
  mit `Crypt-`, `MD5-` oder `SSHA-Password` behielt sein altes Geheimnis, und je
  nach Authentifizierungsmethode galt weiterhin das alte Passwort.
* **Maskierte `radreply`-Werte bleiben erhalten.** Der neue Expertenmodus
  schickt alle Reply-Zeilen zurück; ein Passwort-Attribut dort wurde dabei
  dauerhaft durch Sternchen ersetzt. Die Auflösung liegt jetzt in
  `app/services/masking.py` und wird von Gruppen und Benutzern geteilt.
* **Exportiert wird das wirksame, also früheste Ablaufdatum.** Bei mehreren
  `Expiration`-Zeilen zeigte die Ansicht ein künftiges Datum zu einem
  abgelaufenen Status – ein Reimport dieses Exports reaktivierte den Benutzer.
* **Die Import-Vorschau prüft den Schutz der letzten Mitgliedschaft.** Eine
  Zeile mit leerer Gruppenspalte galt als gültig und scheiterte erst beim
  Schreiben.
* **Eine vollständige TOTP-Anmeldung gibt auch das Kontingent der Passwortstufe
  frei.** Sonst blieb je Anmeldung ein Treffer stehen und die elfte korrekte
  Anmeldung innerhalb des Fensters wurde abgewiesen.
* **Eine abgelaufene Sperre wird auch vor dem Passwortwechsel aufgehoben** – wie
  beim Anmelden; sonst löste der erste Tippfehler danach sofort die nächste
  Sperre aus.
* Der Gruppendialog zeigt nach einer Umbenennung mit Warnung auf den neuen
  Namen; jede Korrektur lief sonst als PATCH auf den alten Pfad.

### Zwanzigste Runde

* **Weitergereichte Client-Adressen werden geprüft.** Hinter einem eingetragenen
  Proxy war der Wert von `X-Forwarded-For` bisher beliebig: jede Variante ergab
  einen neuen Schlüssel im Rate-Limiter, und ein Wert über 45 Zeichen sprengte
  `mgr_audit.actor_ip` – der Audit-Eintrag riss den Fehlversuch mit zurück und
  das Passwortraten wäre unbegrenzt gewesen. Angehängte Ports und geklammertes
  IPv6 werden abgetrennt, alles andere verworfen.
* **Auch ein reiner Typwechsel entfernt Bestands-Anmeldedaten.** Ein
  `Crypt-`, `MD5-` oder `SSHA-Password` blieb sonst nutzbar, obwohl der Manager
  einen anderen Typ meldet; ohne Klartextquelle wird der Wechsel jetzt
  abgewiesen, statt einen Typ ohne passende Daten zu melden.
* **Die Wiedereinsatz-Marke wird mit dem Geheimnis zurückgesetzt.** Nach einem
  administrativen Reset wies die Bestätigung des neuen Faktors den ersten
  richtigen Code als Wiedereinsatz ab.
* **Das Löschen prüft die gehaltenen Gruppensperren.** Eine erst nach dem Setzen
  der Sperren entstandene Mitgliedschaft führt zu `error.busy` statt zu einer
  ungesicherten Löschung – wie im Aktualisierungspfad.

### Einundzwanzigste Runde

* **`PBKDF2-Password` wird als Passwort-Attribut erkannt.** FreeRADIUS 3
  unterstützt es; im Wörterbuch fehlte es, damit stand der Verifier unmaskiert
  in API-Antwort und Audit-Log (NFR-1).
* **Der OIDC-Aussteller wird exakt geprüft.** Ein abgeschnittener Schrägstrich
  liess jeden Rückruf scheitern, obwohl derselbe Aussteller beim Abruf der
  Discovery-Metadaten akzeptiert wurde.
* **Doppelte CSV-Spalten werden abgewiesen.** `DictReader` behielt still nur die
  letzte; eine unbeabsichtigt angewandte Passwortspalte tauchte in keiner
  Meldung auf.
* **Sammelaktionen protokollieren den richtigen Objekttyp.** `object_type` war
  fest auf `user` verdrahtet, auch für Geräte – die Filterung des Audit-Logs
  ordnete den Vorgang damit falsch ein (FR-9).

### Zweiundzwanzigste Runde

* **Die Grössenbeschränkung greift vor dem Multipart-Parser.** Starlette hatte
  die Datei bisher schon vollständig eingelesen – grosse Dateien landen dabei in
  einer temporären Datei –, bevor der Endpunkt sie prüfen konnte. Eine
  Middleware weist zu grosse Körper jetzt anhand von `Content-Length` ab und
  zählt bei `chunked` mit. Im Produktivbetrieb gehört dieselbe Schranke
  zusätzlich in den Reverse-Proxy.
* **Der Schutz der letzten Mitgliedschaft zählt verschiedene Benutzer.**
  `radusergroup` kennt keine Eindeutigkeit; zwei Zeilen desselben Benutzers
  galten als zwei Mitglieder und die Gruppe verschwand beim Entfernen trotz der
  Prüfung.
* **Die Prüfung doppelter CSV-Spalten läuft in linearer Zeit.** Ein `count()` je
  Spalte war quadratisch und konnte den Worker beschäftigen.
* **Die Selbstbedienungs-Einrichtung wird dem Aufrufer zugeordnet.** Der Eintrag
  ist der einzige Beleg für den Geheimniswechsel und stand bisher ohne Urheber
  und ohne Adresse im Protokoll (FR-9).
* **Die Limiter-Schlüssel folgen der Vergleichsform.** Eine Anmeldung als
  `Admin` zählte auf einen anderen Schlüssel als die Freigabe für `admin`; nach
  zehn erfolgreichen Anmeldungen kam ein 429.
* Die Anmeldemaske bietet einen Weg zurück, wenn die Challenge abgelaufen ist –
  sonst wiederholte jeder Versuch dieselbe abgelaufene Challenge.

### Dreiundzwanzigste Runde

* **Argon2 läuft in einem Worker-Thread.** Die absichtlich rechen- und
  speicherintensive Prüfung lief direkt in der Ereignisschleife; während einer
  Anmeldung konnte der Prozess keine andere Anfrage beantworten – auch keine
  Health-Checks (NFR-2).
* **NAS-Änderung und -Löschung teilen eine Sperre.** Ein gleichzeitiges Löschen
  zwischen Lesen und Schreiben liess sonst eine verwaiste `mgr_nas_extra`-Zeile
  zurück und meldete Erfolg für ein nicht mehr vorhandenes NAS.
* **Die Zahl verschiedener Mitglieder kommt aus der Datenbank** (`DISTINCT …
  LIMIT 2`). Viele doppelte Zeilen desselben Benutzers verdeckten sonst ein
  weiteres Mitglied und das Entfernen wurde fälschlich abgewiesen.
* **`Auth-Type := reject` wird unabhängig von der Schreibweise erkannt.** Der
  SQL-Statusfilter erfasste die Zeile, die Prüfung in Python nicht – die Liste
  zeigte gesperrt, die Detailansicht aktiv, und das Entsperren liess die Zeile
  stehen.
* **Die Schranke für den Anfragekörper lässt Platz für den Multipart-Overhead.**
  Eine Datei genau in Maximalgrösse wurde sonst mit 413 abgewiesen, obwohl der
  Endpunkt sie akzeptiert hätte.
* Der Gruppendialog sendet VLAN-Felder nur, wenn der Assistent bearbeitet wurde;
  sonst überschrieb jedes andere Speichern die vorhandenen Tunnel-Attribute.

### Vierundzwanzigste Runde

* **Eine gesperrte Kontozeile wird beim Sperren neu eingelesen**
  (`populate_existing`). Lag das Objekt schon in der Identity Map – etwa weil
  `account_from_challenge` es zuvor geladen hat –, gab SQLAlchemy den alten
  Stand zurück: der Wartende sah weder den fortgeschriebenen Fehlerzähler noch
  die Wiedereinsatz-Marke des anderen Vorgangs und konnte denselben TOTP-Code
  ein zweites Mal einlösen.

### Fünfundzwanzigste Runde

* **Das Abmelden entwertet die Sitzung auch serverseitig.** Bisher wurde nur das
  Cookie im Browser gelöscht; eine zuvor kopierte Kennung blieb bis zur
  absoluten Gültigkeit brauchbar und liess sich weiter verlängern. Die neue
  Tabelle `mgr_session_revocation` (Migration 0009) hält abgemeldete Kennungen
  bis zu ihrem ohnehin eintretenden Ablauf; der Aufräumjob entfernt sie danach.
  Migration 0009 wurde gegen eine echte MariaDB in beide Richtungen geprüft.
* **`Origin: null` wird abgewiesen.** Ein Browser sendet das aus einem
  Sandbox-Kontext; als fehlende Angabe behandelt lief die Anfrage in den Zweig
  für Nicht-Browser und war erlaubt – obwohl das Sitzungscookie mitgeht.
* **Die Ersteinrichtung des zweiten Faktors verlangt das Passwort erneut.** Mit
  einem gestohlenen Cookie liess sich sonst ein nur dem Angreifer bekannter
  Faktor einrichten; die Bestätigung hätte die Sitzung des Opfers beendet und es
  bis zum Zurücksetzen ausgesperrt.
* **Die Statusberechnung berücksichtigt die Check-Attribute der Gruppen** – in
  der Detailansicht, in der Liste *und* im SQL-Filter. Ein `Auth-Type := Reject`
  auf Gruppenebene lehnt FreeRADIUS ab, die Oberfläche meldete „aktiv“ und eine
  Sammelaktion traf eine andere Menge als angezeigt.
* **`Expiration` wird ohne Prozess-Locale gelesen.** `%b` interpretiert
  `strptime` in der Locale des Prozesses; unter einer nicht-englischen `LC_TIME`
  scheiterte genau das Format, das die Anwendung selbst schreibt.
* **Freitextfelder behalten ihre Leerzeichen beim Import.** Der Weg
  Export → Bearbeiten → Import beschnitt Notizen stillschweigend.

### Sechsundzwanzigste Runde

* **Eine OIDC-Administratorsitzung gilt nur mit belegtem zweitem Faktor als
  mehrstufig.** Der Rückruf setzte `mfa` bedingungslos, und `current_principal`
  nimmt OIDC-Sitzungen von der TOTP-Pflicht aus – ein Provider mit reiner
  Passwortanmeldung umging sie damit. Ausgewertet werden jetzt `amr` (RFC 8176)
  und optional `acr`, konfigurierbar über `FRM_OIDC_MFA_AMR_VALUES` und
  `FRM_OIDC_MFA_ACR_VALUES`.
* **Das Token trägt den Zeitpunkt der Prüfung der Anmeldedaten**, nicht den der
  Ausstellung. Eine Passwortänderung dazwischen liess sonst eine Sitzung
  bestehen, die mit dem bereits entwerteten Passwort zustande kam.
* **IPv6-Adressen mit Zone werden abgewiesen.** Python nimmt eine beliebig lange
  Zone an; ein frei wählbarer Anhang ergab je Versuch einen neuen Schlüssel im
  Rate-Limiter und sprengte `mgr_audit.actor_ip`.
* **Die Bestätigung im eigenen Profil ist begrenzt** wie der Anmeldeweg, und
  Fehlversuche zählen auf die Kontosperre ein. Mit einer gestohlenen Sitzung
  liess sich ein begonnener Faktor sonst unbegrenzt erraten.
* **Ein OIDC-Konto ohne lokales Passwort lässt sich nicht entkoppeln.** Solche
  Konten bekommen jetzt gar kein lokales Passwort (statt eines zufälligen, das
  wie ein Zugang aussieht); das Lösen der Verknüpfung wird abgewiesen, bis ein
  Administrator ein Passwort gesetzt hat.
* **Eine Gruppe lässt sich in ihrer Schreibweise umbenennen.** Die
  Existenzprüfung fand unter der Kollation die Gruppe selbst und meldete
  `group_exists`.

### Siebenundzwanzigste Runde

* **Konten ohne lokales Passwort kosten dieselbe Rechenzeit.** Bei ihnen kehrte
  die Prüfung sofort zurück, während ein unbekannter Name den teuren
  Vergleichs-Hash durchlief – an der Antwortzeit war ablesbar, welche Kennung
  nur über OIDC anmeldet.
* **Das Entsperren meldet eine geerbte Gruppensperre.** Stammt der `Reject` aus
  einer Gruppe, meldete der Vorgang Erfolg und protokollierte `user.enable`,
  während die Liste weiter „gesperrt“ zeigte.
* **Das angezeigte Ablaufdatum berücksichtigt die Gruppen.** Status und Datum
  gingen auseinander: der Benutzer galt als abgelaufen, das Datum war leer.
* **Der Export enthält `vlan` und `disabled`.** Ein Reimport legte ein
  gesperrtes MAB-Gerät mit VLAN sonst aktiv und ohne VLAN wieder an – `status`
  liest der Import bewusst nicht.
* **Ungültige `FRM_TRUSTED_PROXIES` brechen den Start ab.** Ein still
  verworfener Tippfehler liess hinter dem Proxy für alle Anfragen dessen
  Adresse zählen: das IP-weite Kontingent traf alle Benutzer gemeinsam.
* **Ein NAS lässt sich in seiner Schreibweise umbenennen** – die Kollision war
  das NAS selbst.
* Das Entfernen des CoA-Secrets schaltet CoA in der Oberfläche mit ab; das
  Backend weist die Kombination sonst ab.

### Achtundzwanzigste Runde

* **Die TOTP-Sitzung trägt den Zeitstempel der Challenge**, also den der
  Passwortprüfung. Aus dem zweiten Schritt abgeleitet erschien sie neuer als
  eine dazwischen festgeschriebene Passwortänderung und blieb gültig.
* **Der SQL-Statusfilter liest englische Monatsnamen unabhängig von der
  Datenbank-Locale.** `lc_time_names` wird je Verbindung auf `en_US` gesetzt;
  sonst ergab `STR_TO_DATE(..., '%b', ...)` NULL und der Filter lieferte eine
  andere Menge als die Statusberechnung in Python (NFR-4).
* **Das Abmelden wird protokolliert** (`auth.logout`); sonst liess es sich nicht
  vom Ablauf oder einem administrativen Entzug unterscheiden (FR-9).
* **Das Entfernen einer Mitgliedschaft setzt eine vorhandene Gruppe voraus.** Ein
  Tippfehler meldete Erfolg und schrieb einen Audit-Eintrag für ein Objekt, das
  es nie gab.
* **Ein Benutzer lässt sich in seiner Schreibweise umbenennen** – wie Gruppen
  und NAS seit der vorigen Runde.
* Der Expertenmodus des Gruppendialogs erhält die VLAN-Zeilen, solange der
  Assistent nicht bearbeitet wurde; sonst löschte ein Speichern die
  VLAN-Policy.

## Prüfschritte

```bash
cd backend && .venv/bin/ruff check app alembic tests && .venv/bin/mypy app
cd backend && .venv/bin/pytest --cov=app          # Unit + Integration
cd backend && .venv/bin/pytest -m e2e tests/e2e   # gegen echten freeradius
cd frontend && npm run lint && npm run build
```
