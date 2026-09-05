# Änderungsprotokoll

Das Format folgt lose [Keep a Changelog](https://keepachangelog.com/de/1.1.0/).
Die Versionsnummern sind kalenderbasiert: `JJJJ.M.PATCH`.

## 2026.9.1 – 2026-09-05

### Hinzugefügt

* **Bezeichnung für MAB-Geräte.** `mgr_subject.display_name` liess sich bisher
  nur über den CSV-Import befüllen; die Geräteoberfläche bot das Feld nicht an.
  Es ist jetzt beim Anlegen und Bearbeiten pflegbar und erscheint in der
  Geräteliste, in den Sessions samt Detaildialog, im Auth-Log und im Kopf der
  Diagnose. In `radacct` und `radpostauth` steht bei einem MAB-Gerät nur die
  MAC-Adresse – ohne die Bezeichnung war dort nicht erkennbar, um welches
  Gerät es geht.

  Die Zuordnung erfolgt über die Vergleichsform des Namens: das NAS meldet die
  MAC in eigener Schreibweise, die von der gespeicherten abweichen kann.
  Geladen wird je Seite einmal, nicht je Zeile.

* Der CSV-Vorlage für Geräte fehlte die Spalte `display_name`. Gelesen wurde
  sie bereits.

### Dokumentation

* [docs/INSTALLATION.md](docs/INSTALLATION.md) beschreibt jetzt die
  CoA-Einrichtung auf der UniFi-Seite: der Accounting-Server als Voraussetzung,
  *Enable RADIUS DAS/DAC (CoA)* am WLAN statt am RADIUS-Profil, die Herkunft
  des CoA-Secrets, die Einschränkung auf die Absenderadresse sowie ein
  `tcpdump` zur Prüfung.

## 2026.9.0 – 2026-09-05

Erste Veröffentlichung. Der Manager verwaltet einen **bestehenden**
FreeRADIUS-Server über dessen `rlm_sql`-Schema; das Schema selbst bleibt
unverändert, die Authentifizierungsentscheidung trifft weiterhin FreeRADIUS
allein.

### Funktionsumfang

| Bereich | Inhalt |
| --- | --- |
| Benutzer (FR-1) | Anlegen, Bearbeiten, Sperren, Ablaufdatum, Notiz und Verantwortlicher; Credential-Typ je Benutzer (`Cleartext-Password`, `NT-Password` oder beides) |
| Gruppen (FR-2) | `radgroupcheck`/`radgroupreply`/`radusergroup` inkl. Priorität, geführter VLAN-Dialog und Expertenmodus mit Operator-Validierung |
| Geräte (FR-3) | MAB-Geräte mit konfigurierbarem MAC-Format und Inventar-Metadaten |
| NAS (FR-4) | `nas`-Tabelle, maskierte Shared Secrets, Anzeige nur für Administratoren und stets mit Audit-Eintrag |
| Sessions (FR-5) | Laufende und historische Sessions aus `radacct` mit Keyset-Pagination |
| Diagnose (FR-6) | Auswertung von `radpostauth` mit Klartext-Hinweisen je Benutzer und MAC |
| CoA (FR-7) | Disconnect-Message und VLAN-Neuzuweisung nach RFC 5176 |
| Import/Export (FR-8) | CSV mit Vorschau und Dry-Run, Export der Filtermenge, Bulk-Aktionen |
| Audit (FR-9) | Vollständiges Protokoll aller schreibenden Aktionen, ohne Passwörter |
| Anmeldung (FR-10) | Lokale Konten mit Argon2id, TOTP-Pflicht für Administratoren, optional OIDC |

### Sicherheit

* Eigenes Datenbankkonto für den Manager, getrennt von dem von FreeRADIUS.
* Session-Cookie host-only, `HttpOnly`, `SameSite=Lax`; serverseitiger
  Sitzungsentzug über `mgr_session_revocation` und eine Generationszählung je
  Konto.
* CoA- und TOTP-Secrets mit AES-GCM verschlüsselt; Shared Secrets und
  Klartextpasswörter können es nicht sein, weil FreeRADIUS sie lesen muss –
  geschützt über Datenbankrechte und die Anzeige in der Oberfläche.
* Schutz vor TOTP-Wiedereinsatz, Rate-Limits je Benutzer und je Absenderadresse.

### Aus der ersten Inbetriebnahme

Die folgenden Punkte stammen aus dem Aufbau einer echten Installation auf
Debian 13 und sind noch in diese Veröffentlichung eingeflossen:

* **Kollation** – die `mgr_`-Tabellen entstanden mit einem Zeichensatz ohne
  Kollation und erhielten dadurch die Vorgabe des Servers statt die der
  Datenbank. Gegen eine bestehende FreeRADIUS-Datenbank auf MariaDB ≥ 11.5
  scheiterte damit jede Abfrage über beide Seiten mit `Illegal mix of
  collations`. Migration `0010` gleicht sie an.
* **Zeitzone** – der Manager schreibt UTC, FreeRADIUS schreibt Ortszeit. Der
  Start prüft die Zone jetzt und warnt, statt die Annahme stillschweigend zu
  treffen.
* **VLAN-Vorrang** – setzt ein Datensatz ein eigenes VLAN und weist eine seiner
  Gruppen ein anderes zu, gewinnt die Gruppe. Belegt gegen
  `freeradius-server:3.2.7`; die Oberfläche warnt jetzt vor der wirkungslosen
  Kombination.
* **Zwei-Faktor-Einrichtung** – QR-Code zum Scannen, und die Einmalcode-Felder
  sind so ausgezeichnet, dass Passwortmanager sie erkennen.

### Dokumentation

* [docs/INSTALLATION.md](docs/INSTALLATION.md) – Anbindung an eine bestehende
  Installation, UniFi als NAS, VLAN-Zuweisung.
* [docs/DEBIAN13.md](docs/DEBIAN13.md) – Schritt-für-Schritt-Installation auf
  einer Debian-13-VM, ohne Container.

### Bekannte Einschränkungen

* Rate Limiting zählt prozesslokal; bei mehreren Instanzen begrenzt jede für
  sich.
* NAS-Änderungen wirken erst nach einem Reload von `radiusd`; der Manager weist
  darauf hin, führt ihn aber nicht aus.
* Ein bereits eingerichteter zweiter Faktor lässt sich nur durch einen
  Administrator zurücksetzen.
