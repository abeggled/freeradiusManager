"""CSV-Import/-Export und Bulk-Aktionen (FR-8).

Der Import laeuft zweistufig: ``dry_run`` liefert eine Vorschau mit Validierung,
erst der zweite Aufruf schreibt. Destruktive Bulk-Aktionen melden die Anzahl der
betroffenen Objekte zurueck (NFR-4).
"""

from __future__ import annotations

import collections
import csv
import datetime as dt
import io
import itertools
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import ValidationError as PydanticValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dates import from_expiration, to_expiration
from app.core.errors import NotFoundError, ValidationError
from app.core.identifiers import fold
from app.core.locking import named_lock
from app.core.mac import is_mac
from app.core.security import Principal
from app.models.mgr import CredentialType, SubjectType
from app.repositories.directory import SubjectFilter
from app.schemas.users import (
    BulkAction,
    DeviceCreate,
    MembershipIn,
    PasswordSet,
    SubjectMeta,
    UserCreate,
    UserListItem,
    UserUpdate,
)
from app.services.audit import AuditService
from app.services.devices import DeviceService
from app.services.users import UserService

USER_COLUMNS = (
    "username",
    "password",
    "credential_type",
    "groups",
    "vlan",
    "expires_at",
    "display_name",
    "owner",
    "note",
    "disabled",
)
DEVICE_COLUMNS = (
    "mac",
    "groups",
    "vlan",
    "expires_at",
    "device_type",
    "location",
    "inventory_no",
    "owner",
    "note",
    "disabled",
)
AUDIT_NAME_LIMIT = 200
"""Hoechstzahl im Sammel-Audit protokollierter Namen (TEXT-Spalte, ~64 KiB)."""

EXPORT_COLUMNS = (
    "username",
    "subject_type",
    "status",
    "groups",
    # Schreibbare Policy-Felder: ohne sie legte ein Reimport das Geraet aktiv
    # und ohne VLAN wieder an (``status`` liest der Import bewusst nicht).
    "vlan",
    "disabled",
    "display_name",
    "owner",
    "device_type",
    "location",
    "inventory_no",
    "note",
    "expires_at",
    "credential_type",
)

# Die Spalten des Exports gehoeren dazu, damit der Weg exportieren, bearbeiten,
# importieren funktioniert. Rein informative Spalten wie ``status`` werden dabei
# gelesen und ignoriert - im Gegensatz zu einem Tippfehler, der auffallen soll.
ALLOWED_USER_COLUMNS = frozenset(USER_COLUMNS) | frozenset(EXPORT_COLUMNS) | {"username"}
ALLOWED_DEVICE_COLUMNS = frozenset(DEVICE_COLUMNS) | frozenset(EXPORT_COLUMNS) | {"mac", "username"}


TRUE_VALUES = frozenset({"1", "true", "ja", "yes", "y", "wahr"})
FALSE_VALUES = frozenset({"0", "false", "nein", "no", "n", "falsch"})


def _parse_bool(value: str | None) -> bool:
    """Liest einen Wahrheitswert streng.

    Alles Unbekannte als "falsch" zu lesen waere gefaehrlich: aus einem
    Tippfehler wie ``disabled=treu`` wuerde ein stillschweigendes Entsperren.
    """
    text = str(value or "").strip().lower()
    if text in TRUE_VALUES:
        return True
    if text in FALSE_VALUES or not text:
        return False
    raise ValidationError(code="error.validation", details={"disabled": value})


def _parse_date(value: str | None) -> dt.datetime | None:
    value = (value or "").strip()
    if not value:
        return None
    parsed = from_expiration(value)
    if parsed is not None:
        return parsed
    try:
        return dt.datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValidationError(code="error.validation", details={"expires_at": value}) from exc


GROUP_DELIMITERS = ",;:"
"""Trennzeichen der Mitgliedschaftsspalte.

Neue Gruppennamen duerfen sie nicht enthalten (``validate_groupname``). In einer
Bestandsinstallation koennen sie aber vorkommen - dort ist ``corp:guest`` ein
gueltiger Name. Deshalb werden sie beim Export maskiert.
"""


def _escape_groupname(name: str) -> str:
    """Maskiert Trennzeichen mit einem Rueckstrich."""
    escaped = name.replace("\\", "\\\\")
    for character in GROUP_DELIMITERS:
        escaped = escaped.replace(character, f"\\{character}")
    return escaped


def _split_groups(value: str) -> list[str]:
    """Teilt an unmaskierten Kommata und Semikola."""
    chunks: list[str] = []
    current: list[str] = []
    escaped = False
    for character in value:
        if escaped:
            current.append(character)
            escaped = False
            continue
        if character == "\\":
            escaped = True
            current.append(character)
            continue
        if character in ",;":
            chunks.append("".join(current))
            current = []
            continue
        current.append(character)
    chunks.append("".join(current))
    return chunks


def _split_priority(chunk: str) -> tuple[str, str]:
    """Trennt am letzten unmaskierten Doppelpunkt."""
    position = -1
    escaped = False
    for index, character in enumerate(chunk):
        if escaped:
            escaped = False
            continue
        if character == "\\":
            escaped = True
            continue
        if character == ":":
            position = index
    if position < 0:
        return chunk, ""
    return chunk[:position], chunk[position + 1 :]


def _unescape_groupname(name: str) -> str:
    out: list[str] = []
    escaped = False
    for character in name:
        if escaped:
            out.append(character)
            escaped = False
            continue
        if character == "\\":
            escaped = True
            continue
        out.append(character)
    return "".join(out)


def _format_groups(item: UserListItem) -> str:
    """Serialisiert Mitgliedschaften inklusive abweichender Prioritaet."""
    priorities = {m.groupname: m.priority for m in item.memberships}
    return ",".join(
        _escape_groupname(name)
        if priorities.get(name, 1) == 1
        else f"{_escape_groupname(name)}:{priorities[name]}"
        for name in item.groups
    )


def _parse_groups(value: str | None) -> list[MembershipIn]:
    if not value:
        return []
    out: list[MembershipIn] = []
    for chunk in _split_groups(str(value)):
        raw = _unescape(chunk.strip())
        if not raw:
            continue
        name, priority = _split_priority(raw)
        name = _unescape_groupname(name).strip()
        if not name:
            continue
        if priority:
            out.append(MembershipIn(groupname=name, priority=int(priority or 1)))
        else:
            out.append(MembershipIn(groupname=name))
    return out


@dataclass
class ParsedRow:
    """Eine CSV-Zeile, uebersetzt in die Schemas der Services."""

    username: str
    groups: list[MembershipIn]
    groups_supplied: bool
    expiry_supplied: bool
    vlan_supplied: bool
    expires_at: dt.datetime | None
    vlan: str | None
    password: str | None
    credential_type: CredentialType | None
    disabled: bool
    meta: SubjectMeta
    supplied: set[str]

    def summary(self) -> dict[str, Any]:
        return {
            "username": self.username,
            "groups": [g.groupname for g in self.groups],
            "vlan": self.vlan,
            "expires_at": self.expires_at,
            "disabled": self.disabled if "disabled" in self.supplied else None,
        }


@dataclass
class ImportRow:
    line: int
    action: Literal["create", "update", "skip", "error"]
    username: str
    message: str | None = None
    values: dict[str, Any] = field(default_factory=dict)


MAX_IMPORT_ROWS = 10_000
"""Obergrenze der Zeilen je Import.

Die Groessenbeschraenkung des Uploads begrenzt die Zeilenzahl nicht: eine
kompakte Datei enthaelt leicht Hunderttausende gueltiger Datensaetze, von denen
jeder mehrere Abfragen ausloest. Dieselbe Groesse wie bei Sammelaktionen und
Export (NFR-2).
"""

PREVIEW_LIMIT = 500
"""Hoechstzahl behaltener Berichtszeilen.

Eine 5-MB-Datei kann Millionen kurzer Zeilen enthalten; ohne Grenze schon beim
Lesen entstuenden ebenso viele Objekte im Speicher.
"""


@dataclass
class ImportReport:
    dry_run: bool
    total: int = 0
    to_create: int = 0
    to_update: int = 0
    errors: int = 0
    rows: list[ImportRow] = field(default_factory=list)
    rows_truncated: bool = False

    def add_row(self, row: ImportRow) -> None:
        """Behaelt Fehlerzeilen bevorzugt und insgesamt hoechstens ``PREVIEW_LIMIT``."""
        if len(self.rows) < PREVIEW_LIMIT:
            self.rows.append(row)
            return
        self.rows_truncated = True
        if row.action != "error":
            return
        for index, existing in enumerate(self.rows):
            if existing.action != "error":
                self.rows[index] = row
                return


META_FIELDS = ("display_name", "note", "owner", "device_type", "location", "inventory_no")


def _meta_from(row: dict[str, str]) -> SubjectMeta:
    """Baut die Metadaten aus den vorhandenen Spalten.

    Entscheidend ist die Anwesenheit der Spalte, nicht ihr Inhalt: eine fehlende
    Spalte laesst den Wert unangetastet, eine vorhandene leere Zelle loescht ihn.
    Ohne diese Unterscheidung waere weder das eine noch das andere moeglich.
    """
    present: dict[str, str | None] = {
        field: (row[field] or None) for field in META_FIELDS if field in row
    }
    return SubjectMeta(**present)


def _sanitised(error: PydanticValidationError) -> str:
    """Feld und Fehlerart ohne den eingereichten Wert."""
    return (
        "; ".join(
            f"{'.'.join(str(part) for part in item['loc'])}: {item['type']}"
            for item in error.errors()
        )
        or "error.validation"
    )


def _unescape(value: str) -> str:
    """Nimmt die Entschaerfung des Exports zurueck.

    Der Export stellt Werten, die eine Tabellenkalkulation als Formel lesen
    wuerde, ein Hochkomma voran. Ohne diesen Schritt waere der dokumentierte Weg
    "exportieren, bearbeiten, importieren" nicht verlustfrei.
    """
    if len(value) > 1 and value[0] == "'" and value[1] in ("=", "+", "-", "@", "'", "\t", "\r"):
        return value[1:]
    return value


def _normalise_row(raw: dict[str | None, Any]) -> dict[str, str]:
    """Vereinheitlicht Spaltennamen und Werte einer CSV-Zeile."""
    row: dict[str, str] = {}
    for key, value in raw.items():
        if key is None:
            # Ueberzaehlige Felder ohne Kopfzeile: klarer Fehler statt Absturz.
            raise ValidationError(
                code="error.import_invalid", details={"reason": "zu viele Spalten"}
            )
        if isinstance(value, list):
            raise ValidationError(
                code="error.import_invalid", details={"reason": "zu viele Spalten"}
            )
        column = key.strip().lower()
        cell = value or ""
        if column == "password":
            # Passwoerter bleiben vollstaendig unveraendert: fuehrende oder
            # anhaengende Leerzeichen sind Teil des Werts.
            row[column] = cell
        elif column in META_FIELDS:
            # Freitextfelder ebenso: der Export-Bearbeiten-Import-Weg darf eine
            # Notiz nicht stillschweigend beschneiden. Die Maskierung des
            # Exports wird trotzdem zurueckgenommen.
            row[column] = _unescape(cell)
        else:
            # Bezeichner und strukturierte Felder werden getrimmt; ein
            # versehentliches Leerzeichen ergaebe sonst einen anderen Namen.
            row[column] = _unescape(cell.strip())
    return row


def _parse_row(row: dict[str, str], *, username: str, require_password: bool) -> ParsedRow:
    """Uebersetzt eine CSV-Zeile in die Schemas der Services.

    Wird sowohl im Dry-Run als auch beim Schreiben aufgerufen, damit die
    Vorschau dieselben Validierungsfehler meldet wie der spaetere Import.
    """
    credential_raw = (row.get("credential_type") or "").lower()
    if credential_raw and credential_raw not in {c.value for c in CredentialType}:
        raise ValidationError(
            code="error.validation",
            details={"field": "credential_type", "value": credential_raw},
        )
    password = row.get("password") or None
    if require_password and not password:
        # Ohne Passwort schluege das spaetere Anlegen fehl; das muss schon die
        # Vorschau zeigen und nicht erst der Schreibvorgang.
        raise ValidationError(code="error.password_required", details={"username": username})

    return ParsedRow(
        username=username,
        groups=_parse_groups(row.get("groups")),
        # Eine vorhandene, aber leere Spalte bedeutet "alle entfernen"; eine
        # fehlende Spalte laesst die Mitgliedschaften unangetastet.
        groups_supplied="groups" in row,
        expires_at=_parse_date(row.get("expires_at")),
        expiry_supplied="expires_at" in row,
        vlan=row.get("vlan") or None,
        vlan_supplied="vlan" in row,
        password=password,
        credential_type=CredentialType(credential_raw) if credential_raw else None,
        disabled=_parse_bool(row.get("disabled")),
        meta=_meta_from(row),
        supplied={key for key, value in row.items() if value},
    )


class ImportExportService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.users = UserService(session)
        self.devices = DeviceService(session)
        self.audit = AuditService(session)

    # --- Import ----------------------------------------------------------

    async def import_csv(
        self,
        content: str,
        *,
        kind: Literal["user", "device"],
        dry_run: bool,
        actor: Principal,
        actor_ip: str | None = None,
        language: str = "de",
    ) -> ImportReport:
        try:
            dialect: Any = csv.Sniffer().sniff(content[:4096], delimiters=",;\t")
        except csv.Error:
            dialect = csv.excel
        reader = csv.DictReader(io.StringIO(content), dialect=dialect)
        if reader.fieldnames is None:
            raise ValidationError(code="error.import_invalid")

        # Ein Tippfehler in der Kopfzeile wuerde sonst stillschweigend ignoriert
        # und die Zeile trotzdem als "aktualisiert" gemeldet.
        allowed = ALLOWED_USER_COLUMNS if kind == "user" else ALLOWED_DEVICE_COLUMNS
        headers = [(name or "").strip().lower() for name in reader.fieldnames]
        # ``DictReader`` behaelt bei doppelten Spalten stillschweigend nur die
        # letzte; Namen, die sich nur in Gross-/Kleinschreibung oder Leerzeichen
        # unterscheiden, fallen spaeter ebenso zusammen. Eine unbeabsichtigt
        # angewandte Passwortspalte taucht dabei in keiner Meldung auf.
        counts = collections.Counter(name for name in headers if name)
        duplicates = sorted(name for name, count in counts.items() if count > 1)
        if duplicates:
            raise ValidationError(
                code="error.import_duplicate_columns", details={"columns": duplicates}
            )
        unknown = sorted(set(headers) - allowed - {""})
        if unknown:
            raise ValidationError(
                code="error.import_unknown_columns",
                details={"columns": unknown, "allowed": sorted(allowed)},
            )

        report = ImportReport(dry_run=dry_run)
        # Ein Name darf in derselben Datei nur einmal vorkommen: sonst meldete
        # die Vorschau mehrere Neuanlagen, waehrend der Import ab der zweiten
        # Zeile ueberschriebe - Vorschau und Ergebnis gingen auseinander.
        # Verglichen wird wie in der Datenbank: "Alice" und "alice" bezeichnen
        # denselben Datensatz.
        seen_usernames: set[str] = set()

        # Vollstaendig einlesen, bevor irgendetwas geschrieben wird: die Zeilen
        # schreiben einzeln fest, ein Abbruch mitten im Lauf liesse die ersten
        # 10 000 Aenderungen bestehen und meldete dennoch nur einen Fehler.
        # Die Datei liegt ohnehin vollstaendig im Speicher (Upload-Grenze).
        # Nur bis zur Grenze plus eins lesen: ``list(reader)`` baute bei einer
        # kompakten Datei innerhalb der Upload-Grenze Millionen Zeilen-Dicts,
        # bevor die Pruefung ueberhaupt liefe.
        try:
            raw_rows = list(itertools.islice(reader, MAX_IMPORT_ROWS + 1))
        except csv.Error as exc:
            # Etwa ein Feld ueber der Feldgrenze des csv-Moduls: das ist eine
            # unbrauchbare Datei, kein Serverfehler.
            raise ValidationError(
                code="error.import_invalid", details={"reason": str(exc)}
            ) from exc
        if len(raw_rows) > MAX_IMPORT_ROWS:
            raise ValidationError(
                code="error.import_too_many_rows",
                details={"maximum": MAX_IMPORT_ROWS},
            )

        for index, raw in enumerate(raw_rows, start=2):
            report.total += 1
            row: dict[str, str] = {}
            try:
                # Auch das Normalisieren gehoert in den Fehlerzweig: eine Zeile
                # mit ueberzaehligen Feldern legt sie unter dem Schluessel None
                # als Liste ab und liesse den ganzen Request abbrechen, nachdem
                # vorherige Zeilen bereits geschrieben wurden.
                row = _normalise_row(raw)
                if kind == "device":
                    identifier = row.get("mac") or row.get("username") or ""
                    if not is_mac(identifier):
                        raise ValidationError(
                            code="error.invalid_mac", details={"value": identifier}
                        )
                    # ueber resolve(), damit ein Formatwechsel keine Dubletten
                    # desselben physischen Geraets erzeugt.
                    username = await self.devices.resolve(identifier)
                else:
                    username = row.get("username", "")
                    if not username:
                        raise ValidationError(
                            code="error.validation", details={"field": "username"}
                        )

                if fold(username) in seen_usernames:
                    raise ValidationError(
                        code="error.import_duplicate_row", details={"username": username}
                    )
                seen_usernames.add(fold(username))

                subject = await self.users.subjects.get(username)
                expected_type = SubjectType.DEVICE if kind == "device" else SubjectType.USER
                if subject is not None and subject.subject_type is not expected_type:
                    # Schon in der Vorschau melden: sonst hiesse die Zeile
                    # "aktualisiert" und das Objekt bliebe in der Liste der
                    # importierten Art trotzdem unsichtbar.
                    raise ValidationError(
                        code="error.subject_type_mismatch",
                        details={
                            "username": username,
                            "expected": expected_type.value,
                            "actual": subject.subject_type.value,
                        },
                    )
                exists = await self.users.attrs.exists_anywhere(username) or subject is not None
                # Das Uebersetzen validiert bereits; beim Dry-Run passiert damit
                # dasselbe wie beim Schreiben, nur ohne Schreibzugriff.
                parsed = _parse_row(
                    row,
                    username=username,
                    require_password=not exists and kind == "user",
                )
                # Wirft dieselben Validierungsfehler wie der Schreibvorgang.
                self._payloads(parsed, kind, exists)
                # Ein Typwechsel ohne Passwort haengt vom Bestand ab; auch das
                # gehoert in die Vorschau.
                if exists and parsed.credential_type is not None and not parsed.password:
                    await self.users.check_credential_change(username, parsed.credential_type)
                # Auch die Existenz der Gruppen wird schon hier geprueft, damit
                # die Vorschau nicht mehr meldet als der Import leistet.
                for membership in parsed.groups:
                    if not await self.users.groups.exists(membership.groupname):
                        raise NotFoundError(
                            code="error.not_found",
                            details={"groupname": membership.groupname},
                        )
                # Der Schutz der letzten Mitgliedschaft haengt vom Bestand ab
                # und griffe sonst erst beim Schreiben - die Vorschau meldete
                # eine Zeile als gueltig, die der Import abweist.
                if exists and parsed.groups_supplied:
                    wanted = {fold(g.groupname) for g in parsed.groups}
                    for current in await self.users.groups.memberships(username):
                        if fold(current.groupname) not in wanted:
                            await self.users.guard_last_membership(
                                current.groupname, username
                            )

                if not dry_run:
                    # Erst schreiben, dann zaehlen: ein von der Datenbank
                    # abgewiesener Datensatz darf nicht zugleich als Erfolg und
                    # als Fehler im Bericht stehen.
                    await self._write_row(parsed, kind, exists, actor, actor_ip, language)

                if exists:
                    report.to_update += 1
                else:
                    report.to_create += 1
                report.add_row(
                    ImportRow(
                        line=index,
                        action="update" if exists else "create",
                        username=username,
                        values=parsed.summary(),
                    )
                )
            except PydanticValidationError as exc:
                # Pydantic nennt in der Meldung den Eingabewert - bei einem zu
                # langen Passwort stuende es damit in der API-Antwort.
                await self.session.rollback()
                report.errors += 1
                report.add_row(
                    ImportRow(
                        line=index,
                        action="error",
                        username=row.get("username") or row.get("mac", ""),
                        message=_sanitised(exc),
                    )
                )
            except Exception as exc:  # noqa: BLE001 - jede Zeile wird einzeln gemeldet
                # Ein abgewiesener Schreibvorgang laesst die Sitzung in einem
                # Fehlerzustand zurueck; ohne Rollback scheiterte danach jede
                # weitere Zeile und am Ende der Audit-Eintrag.
                await self.session.rollback()
                report.errors += 1
                report.add_row(
                    ImportRow(
                        line=index,
                        action="error",
                        username=row.get("username") or row.get("mac", ""),
                        message=str(exc),
                    )
                )

        if not dry_run:
            await self.audit.log(
                action=f"import.{kind}",
                object_type=kind,
                actor=actor,
                actor_ip=actor_ip,
                after={
                    "total": report.total,
                    "created": report.to_create,
                    "updated": report.to_update,
                    "errors": report.errors,
                },
            )
            await self.session.commit()
        return report

    def _payloads(
        self, parsed: ParsedRow, kind: Literal["user", "device"], exists: bool
    ) -> list[object]:
        """Baut die Schemas, die der Schreibvorgang verwenden wuerde.

        Wird auch im Dry-Run aufgerufen: nur so meldet die Vorschau dieselben
        Laengen- und Wertfehler wie der spaetere Import.
        """
        if not exists:
            if kind == "device":
                return [
                    DeviceCreate(
                        mac=parsed.username,
                        use_mac_as_password=parsed.password is None,
                        password=parsed.password,
                        expires_at=parsed.expires_at,
                        groups=parsed.groups,
                        vlan=parsed.vlan,
                        meta=parsed.meta,
                        disabled=parsed.disabled,
                    )
                ]
            return [
                UserCreate(
                    username=parsed.username,
                    password=parsed.password,
                    credential_type=parsed.credential_type,
                    expires_at=parsed.expires_at,
                    groups=parsed.groups,
                    vlan=parsed.vlan,
                    meta=parsed.meta,
                    disabled=parsed.disabled,
                )
            ]

        payloads: list[object] = [
            UserUpdate(
                credential_type=parsed.credential_type,
                expires_at=parsed.expires_at,
                groups=parsed.groups if parsed.groups_supplied else None,
                vlan=parsed.vlan,
                meta=parsed.meta,
            )
        ]
        if parsed.password:
            payloads.append(
                PasswordSet(password=parsed.password, credential_type=parsed.credential_type)
            )
        return payloads

    async def _write_row(
        self,
        parsed: ParsedRow,
        kind: Literal["user", "device"],
        exists: bool,
        actor: Principal,
        actor_ip: str | None,
        language: str,
    ) -> None:
        """Schreibt eine Zeile ueber die regulaeren Service-Operationen.

        Aktualisierungen laufen bewusst durch ``update``/``set_password``/
        ``set_disabled`` statt an den Services vorbei - sonst blieben Spalten wie
        ``password``, ``vlan`` oder ``disabled`` bei bestehenden Datensaetzen
        wirkungslos, obwohl der Bericht die Zeile als aktualisiert meldet.
        """
        if not exists:
            await self._create_row(parsed, kind, actor, actor_ip, language)
            return

        # Alle Teilschritte einer Zeile in einer Transaktion und unter der
        # Lebenszyklus-Sperre (siehe ``UserService.apply_row``): sonst bliebe ein
        # bereits geschriebenes Passwort stehen, waehrend der Bericht die Zeile
        # als Fehler meldet - und ein gleichzeitiges Loeschen zwischen
        # Existenzpruefung und Schreiben liesse den Datensatz wieder entstehen.
        await self.users.apply_row(
            parsed.username,
            subject_type=SubjectType.DEVICE if kind == "device" else SubjectType.USER,
            password=(
                PasswordSet(password=parsed.password, credential_type=parsed.credential_type)
                if parsed.password
                else None
            ),
            payload=UserUpdate(
                # Der Credential-Typ wird mitgefuehrt: sonst bliebe eine Zeile,
                # die nur ihn aendert, ohne jede Wirkung.
                credential_type=parsed.credential_type if not parsed.password else None,
                expires_at=parsed.expires_at,
                # Vorhandene, aber leere Zelle: ausdruecklich loeschen.
                clear_expiry=parsed.expiry_supplied and parsed.expires_at is None,
                groups=parsed.groups if parsed.groups_supplied else None,
                vlan=parsed.vlan,
                clear_vlan=parsed.vlan_supplied and parsed.vlan is None,
                meta=parsed.meta,
            ),
            disabled=parsed.disabled if "disabled" in parsed.supplied else None,
            actor=actor,
            actor_ip=actor_ip,
            language=language,
        )

    async def _create_row(
        self,
        parsed: ParsedRow,
        kind: Literal["user", "device"],
        actor: Principal,
        actor_ip: str | None,
        language: str,
    ) -> None:
        if kind == "device":
            await self.devices.create(
                DeviceCreate(
                    mac=parsed.username,
                    use_mac_as_password=parsed.password is None,
                    password=parsed.password,
                    expires_at=parsed.expires_at,
                    groups=parsed.groups,
                    vlan=parsed.vlan,
                    meta=parsed.meta,
                    disabled=parsed.disabled,
                ),
                actor=actor,
                actor_ip=actor_ip,
                language=language,
            )
            return

        await self.users.create(
            UserCreate(
                username=parsed.username,
                password=parsed.password,
                credential_type=parsed.credential_type,
                expires_at=parsed.expires_at,
                groups=parsed.groups,
                vlan=parsed.vlan,
                meta=parsed.meta,
                disabled=parsed.disabled,
            ),
            actor=actor,
            actor_ip=actor_ip,
            language=language,
        )

    # --- Export ----------------------------------------------------------

    async def export(self, flt: SubjectFilter, cap: int = 10_000) -> str:
        """Exportiert genau die aktuelle Filtermenge - ohne Passwoerter (NFR-1).

        Oberhalb von ``cap`` wird abgelehnt statt gekuerzt: eine unvollstaendige
        Datei, die wie ein vollstaendiger Export aussieht, ist schlimmer als ein
        klarer Fehler.
        """
        items, total = await self.users.search(flt, limit=cap, offset=0)
        if total > cap:
            raise ValidationError(
                code="error.selection_too_large", details={"cap": cap, "total": total}
            )
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=list(EXPORT_COLUMNS), extrasaction="ignore")
        writer.writeheader()
        for item in items:
            writer.writerow(
                {
                    "username": self._safe(item.username),
                    "subject_type": item.subject_type.value,
                    "status": item.status,
                    # ``gruppe:prioritaet`` wie beim Import, damit ein
                    # Export-Bearbeiten-Import die Reihenfolge nicht auf 1 setzt.
                    "groups": self._safe(_format_groups(item)),
                    "display_name": self._safe(item.display_name or ""),
                    "owner": self._safe(item.owner or ""),
                    "device_type": self._safe(item.device_type or ""),
                    "location": self._safe(item.location or ""),
                    "inventory_no": self._safe(item.inventory_no or ""),
                    # Der CSV-Writer setzt mehrzeilige Werte in Anfuehrungszeichen;
                    # ein Ersetzen wuerde gueltige Notizen dauerhaft veraendern.
                    "note": self._safe(item.note or ""),
                    "vlan": self._safe(item.vlan or ""),
                    # Der eigene Sperrzustand, nicht der aus einer Gruppe: sonst
                    # schriebe ein Reimport die Gruppenpolicy beim Benutzer fest.
                    "disabled": "true" if item.disabled else "false",
                    # Das eigene Datum, nicht das wirksame: ein Reimport machte
                    # aus einer Gruppenfrist sonst eine eigene, die sich mit der
                    # Gruppe nicht mehr aendern liesse.
                    "expires_at": (
                        item.own_expires_at.isoformat() if item.own_expires_at else ""
                    ),
                    "credential_type": item.credential_type.value if item.credential_type else "",
                }
            )
        return buffer.getvalue()

    @staticmethod
    def _safe(value: str) -> str:
        """Entschaerft Werte, die eine Tabellenkalkulation als Formel liest.

        Benutzernamen und Notizen sind frei waehlbar; ein fuehrendes ``=`` wuerde
        beim Oeffnen des Exports auf einem fremden Arbeitsplatz ausgewertet.
        """
        # Auch ein bereits fuehrendes Hochkomma wird verdoppelt, damit sich der
        # Zusatz beim Import eindeutig wieder entfernen laesst.
        if value and value[0] in ("=", "+", "-", "@", "'", "\t", "\r"):
            return "'" + value
        return value

    @staticmethod
    def template(kind: Literal["user", "device"]) -> str:
        columns = USER_COLUMNS if kind == "user" else DEVICE_COLUMNS
        buffer = io.StringIO()
        csv.writer(buffer).writerow(columns)
        return buffer.getvalue()

    # --- Bulk-Aktionen ---------------------------------------------------

    async def bulk(
        self,
        payload: BulkAction,
        flt: SubjectFilter,
        *,
        actor: Principal,
        actor_ip: str | None = None,
    ) -> tuple[int, int, list[dict[str, Any]]]:
        if payload.action == "set_expiry" and payload.expires_at is None:
            # Ohne Datum wuerde ein Klick die gesamte bestaetigte Menge sofort
            # ablaufen lassen - das ist keine sinnvolle Vorgabe (NFR-4).
            raise ValidationError(code="error.validation", details={"field": "expires_at"})
        if payload.action in ("assign_group", "remove_group") and not payload.groupname:
            raise ValidationError(code="error.validation", details={"field": "groupname"})

        usernames = list(payload.usernames)
        if payload.filter_all:
            usernames = await self.users.directory.all_usernames(flt)
        if not usernames:
            return 0, 0, []

        succeeded: list[str] = []
        errors: list[dict[str, Any]] = []
        for username in usernames:
            try:
                await self._bulk_one(username, payload, actor=actor, actor_ip=actor_ip)
                succeeded.append(username)
            except Exception as exc:  # noqa: BLE001 - Sammelmeldung je Objekt
                # Wie beim Import: ohne Rollback bliebe die Sitzung im
                # Fehlerzustand und jede weitere Zeile scheiterte ebenfalls.
                await self.session.rollback()
                errors.append({"username": username, "error": str(exc)})

        await self.audit.log(
            action=f"bulk.{payload.action}",
            object_type="user",
            actor=actor,
            actor_ip=actor_ip,
            after={
                "count": len(usernames),
                "succeeded": len(succeeded),
                "failed": len(errors),
                "groupname": payload.groupname,
                "expires_at": payload.expires_at,
                # Die betroffenen Namen gehoeren ins Protokoll (FR-9), aber
                # begrenzt: ``mgr_audit.after_json`` ist eine TEXT-Spalte und
                # fasst rund 64 KiB. Jede Einzelaenderung hat ohnehin einen
                # eigenen Eintrag, ueber den sich die Zuordnung herstellen laesst.
                "usernames": succeeded[:AUDIT_NAME_LIMIT],
                "usernames_truncated": len(succeeded) > AUDIT_NAME_LIMIT,
                "failed_usernames": [e["username"] for e in errors[:AUDIT_NAME_LIMIT]],
            },
        )
        await self.session.commit()
        return len(usernames), len(succeeded), errors

    async def _set_expiry_locked(
        self,
        username: str,
        expires: dt.datetime,
        actor: Principal,
        actor_ip: str | None,
    ) -> None:
        # Wie bei den uebrigen Sammelaktionen: ein Tippfehler darf keinen
        # Datensatz ohne Anmeldedaten erzeugen.
        if not await self.users.attrs.exists_anywhere(
            username
        ) and not await self.users.subjects.get(username):
            raise NotFoundError(code="error.not_found", details={"username": username})
        subject = await self.users.subjects.ensure(username)
        subject.expires_at = expires
        await self.users.attrs.set_check(username, "Expiration", ":=", to_expiration(expires))
        await self.audit.log(
            action="user.set_expiry",
            object_type=subject.subject_type.value,
            object_id=username,
            actor=actor,
            actor_ip=actor_ip,
            after={"expires_at": expires},
        )
        await self.session.commit()

    async def _object_type(self, username: str) -> str:
        """Benutzer oder Geraet - fest verdrahtet waere die Filterung falsch."""
        subject = await self.users.subjects.get(username)
        return subject.subject_type.value if subject else SubjectType.USER.value

    async def _log_membership(
        self,
        action: str,
        username: str,
        groupname: str,
        actor: Principal,
        actor_ip: str | None,
    ) -> None:
        await self.audit.log(
            action=f"user.{action}",
            object_type=await self._object_type(username),
            object_id=username,
            actor=actor,
            actor_ip=actor_ip,
            after={"groupname": groupname},
        )

    async def _bulk_one(
        self,
        username: str,
        payload: BulkAction,
        *,
        actor: Principal,
        actor_ip: str | None,
    ) -> None:
        if payload.action == "disable":
            await self.users.set_disabled(username, True, actor=actor, actor_ip=actor_ip)
        elif payload.action == "enable":
            await self.users.set_disabled(username, False, actor=actor, actor_ip=actor_ip)
        elif payload.action == "delete":
            await self.users.delete(username, actor=actor, actor_ip=actor_ip)
        elif payload.action in ("assign_group", "remove_group"):
            groupname = str(payload.groupname)
            if payload.action == "assign_group":
                # Dieselbe Sperre wie Umbenennen und Loeschen der Gruppe: sonst
                # koennte eine Mitgliedschaft nach einer Umbenennung unter dem
                # alten Namen entstehen und die Gruppe wiederauferstehen lassen.
                # Die Sperre umschliesst Pruefung, Einfuegen *und* Commit: sonst
                # saehe die naechste Anfrage die Zeile nicht und legte eine
                # zweite an - und ein gleichzeitiges Loeschen zwischen Pruefung
                # und Einfuegen liesse einen Phantom-Benutzer entstehen.
                async with named_lock(self.session, f"group:{groupname}", f"user:{username}"):
                    # Ohne diese Pruefung entstuenden aus einem Tippfehler ein
                    # Phantom-Benutzer und eine Phantom-Gruppe, beide ohne Inhalt.
                    if not await self.users.attrs.exists_anywhere(
                        username
                    ) and not await self.users.subjects.get(username):
                        raise NotFoundError(code="error.not_found", details={"username": username})
                    if not await self.users.groups.exists(groupname):
                        raise NotFoundError(
                            code="error.not_found", details={"groupname": groupname}
                        )
                    await self.users.groups.add_membership(username, groupname, payload.priority)
                    await self._log_membership(payload.action, username, groupname, actor, actor_ip)
                    await self.session.commit()
            else:
                # Ebenfalls unter der Gruppensperre: zwei gleichzeitige
                # Entfernungen saehen sonst beide noch zwei Mitglieder und
                # loeschten anschliessend beide - die attributlose Gruppe
                # verschwaende trotz der Schutzpruefung.
                async with named_lock(self.session, f"group:{groupname}", f"user:{username}"):
                    # Auch hier: ein Tippfehler meldete sonst fuer jeden
                    # ausgewaehlten Benutzer eine erfolgreiche Entfernung an
                    # einem Objekt, das es nie gab (FR-9).
                    if not await self.users.groups.exists(groupname):
                        raise NotFoundError(
                            code="error.not_found", details={"groupname": groupname}
                        )
                    await self.users.guard_last_membership(groupname, username)
                    removed = await self.users.groups.remove_membership(username, groupname)
                    if not removed:
                        # Kein Mitglied - oder ein Tippfehler im Namen. Als
                        # Erfolg gezaehlt behauptete der Bericht eine Aenderung,
                        # die nie stattfand (FR-9).
                        raise NotFoundError(
                            code="error.not_found",
                            details={"username": username, "groupname": groupname},
                        )
                    await self._log_membership(payload.action, username, groupname, actor, actor_ip)
                    await self.session.commit()
        elif payload.action == "set_expiry":
            expires = payload.expires_at
            if expires is None:
                raise ValidationError(code="error.validation", details={"field": "expires_at"})
            # Unter der Lebenszyklus-Sperre: ein gleichzeitiges Loeschen
            # zwischen Pruefung und Schreiben liesse hier sonst einen Benutzer
            # aus Metadaten und Expiration-Zeile ohne Anmeldedaten entstehen.
            async with named_lock(self.session, f"user:{username}"):
                await self._set_expiry_locked(username, expires, actor, actor_ip)
