"""CSV-Import/-Export und Bulk-Aktionen (FR-8).

Der Import laeuft zweistufig: ``dry_run`` liefert eine Vorschau mit Validierung,
erst der zweite Aufruf schreibt. Destruktive Bulk-Aktionen melden die Anzahl der
betroffenen Objekte zurueck (NFR-4).
"""

from __future__ import annotations

import csv
import datetime as dt
import io
from dataclasses import dataclass, field
from typing import Any, Literal

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dates import from_expiration, to_expiration
from app.core.errors import NotFoundError, ValidationError
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
    "display_name",
    "owner",
    "device_type",
    "location",
    "inventory_no",
    "note",
    "expires_at",
    "credential_type",
)


def _parse_bool(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "ja", "yes", "y", "wahr"}


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


def _format_groups(item: UserListItem) -> str:
    """Serialisiert Mitgliedschaften inklusive abweichender Prioritaet."""
    priorities = {m.groupname: m.priority for m in item.memberships}
    return ",".join(
        name if priorities.get(name, 1) == 1 else f"{name}:{priorities[name]}"
        for name in item.groups
    )


def _parse_groups(value: str | None) -> list[MembershipIn]:
    if not value:
        return []
    out: list[MembershipIn] = []
    for chunk in str(value).replace(";", ",").split(","):
        name = _unescape(chunk.strip())
        if not name:
            continue
        if ":" in name:
            group, _, priority = name.partition(":")
            out.append(MembershipIn(groupname=group.strip(), priority=int(priority or 1)))
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


@dataclass
class ImportReport:
    dry_run: bool
    total: int = 0
    to_create: int = 0
    to_update: int = 0
    errors: int = 0
    rows: list[ImportRow] = field(default_factory=list)


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
        row[key.strip().lower()] = _unescape((value or "").strip())
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

        report = ImportReport(dry_run=dry_run)

        for index, raw in enumerate(reader, start=2):
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
                # Auch die Existenz der Gruppen wird schon hier geprueft, damit
                # die Vorschau nicht mehr meldet als der Import leistet.
                for membership in parsed.groups:
                    if not await self.users.groups.exists(membership.groupname):
                        raise NotFoundError(
                            code="error.not_found",
                            details={"groupname": membership.groupname},
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
                report.rows.append(
                    ImportRow(
                        line=index,
                        action="update" if exists else "create",
                        username=username,
                        values=parsed.summary(),
                    )
                )
            except Exception as exc:  # noqa: BLE001 - jede Zeile wird einzeln gemeldet
                # Ein abgewiesener Schreibvorgang laesst die Sitzung in einem
                # Fehlerzustand zurueck; ohne Rollback scheiterte danach jede
                # weitere Zeile und am Ende der Audit-Eintrag.
                await self.session.rollback()
                report.errors += 1
                report.rows.append(
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

        subject_type = SubjectType.DEVICE if kind == "device" else SubjectType.USER
        await self.users.subjects.ensure(parsed.username, subject_type)
        await self.users.update(
            parsed.username,
            UserUpdate(
                expires_at=parsed.expires_at,
                # Vorhandene, aber leere Zelle: ausdruecklich loeschen.
                clear_expiry=parsed.expiry_supplied and parsed.expires_at is None,
                groups=parsed.groups if parsed.groups_supplied else None,
                vlan=parsed.vlan,
                clear_vlan=parsed.vlan_supplied and parsed.vlan is None,
                meta=parsed.meta,
            ),
            actor=actor,
            actor_ip=actor_ip,
            language=language,
        )
        if parsed.password:
            await self.users.set_password(
                parsed.username,
                PasswordSet(password=parsed.password, credential_type=parsed.credential_type),
                actor=actor,
                actor_ip=actor_ip,
            )
        if "disabled" in parsed.supplied:
            await self.users.set_disabled(
                parsed.username, parsed.disabled, actor=actor, actor_ip=actor_ip
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
                    "note": self._safe((item.note or "").replace("\n", " ")),
                    "expires_at": item.expires_at.isoformat() if item.expires_at else "",
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
                # Ohne diese Pruefung entstuenden aus einem Tippfehler ein
                # Phantom-Benutzer und eine Phantom-Gruppe, beide ohne Inhalt.
                if not await self.users.attrs.exists_anywhere(
                    username
                ) and not await self.users.subjects.get(username):
                    raise NotFoundError(code="error.not_found", details={"username": username})
                if not await self.users.groups.exists(groupname):
                    raise NotFoundError(code="error.not_found", details={"groupname": groupname})
                await self.users.groups.add_membership(username, groupname, payload.priority)
            else:
                await self.users.groups.remove_membership(username, groupname)
            await self.audit.log(
                action=f"user.{payload.action}",
                object_type="user",
                object_id=username,
                actor=actor,
                actor_ip=actor_ip,
                after={"groupname": groupname},
            )
            await self.session.commit()
        elif payload.action == "set_expiry":
            expires = payload.expires_at
            if expires is None:
                raise ValidationError(code="error.validation", details={"field": "expires_at"})
            subject = await self.users.subjects.ensure(username)
            subject.expires_at = expires
            await self.users.attrs.set_check(username, "Expiration", ":=", to_expiration(expires))
            await self.audit.log(
                action="user.set_expiry",
                object_type="user",
                object_id=username,
                actor=actor,
                actor_ip=actor_ip,
                after={"expires_at": expires},
            )
            await self.session.commit()
