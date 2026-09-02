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

from app.core.dates import from_expiration, to_expiration, utcnow
from app.core.errors import ValidationError
from app.core.mac import format_mac, is_mac
from app.core.security import Principal
from app.models.mgr import CredentialType, SubjectType
from app.repositories.directory import SubjectFilter
from app.schemas.users import BulkAction, DeviceCreate, MembershipIn, SubjectMeta, UserCreate
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


def _parse_groups(value: str | None) -> list[MembershipIn]:
    if not value:
        return []
    out: list[MembershipIn] = []
    for chunk in str(value).replace(";", ",").split(","):
        name = chunk.strip()
        if not name:
            continue
        if ":" in name:
            group, _, priority = name.partition(":")
            out.append(MembershipIn(groupname=group.strip(), priority=int(priority or 1)))
        else:
            out.append(MembershipIn(groupname=name))
    return out


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
        mac_format = await self.devices.mac_format()

        for index, raw in enumerate(reader, start=2):
            row = {(k or "").strip().lower(): (v or "").strip() for k, v in raw.items()}
            report.total += 1
            try:
                if kind == "device":
                    identifier = row.get("mac") or row.get("username") or ""
                    if not is_mac(identifier):
                        raise ValidationError(
                            code="error.invalid_mac", details={"value": identifier}
                        )
                    username = format_mac(identifier, mac_format)
                else:
                    username = row.get("username", "")
                    if not username:
                        raise ValidationError(
                            code="error.validation", details={"field": "username"}
                        )

                exists = await self.users.attrs.exists(username) or bool(
                    await self.users.subjects.get(username)
                )
                values: dict[str, Any] = {
                    "username": username,
                    "groups": [g.groupname for g in _parse_groups(row.get("groups"))],
                    "vlan": row.get("vlan") or None,
                    "expires_at": _parse_date(row.get("expires_at")),
                }
                if exists:
                    report.to_update += 1
                else:
                    report.to_create += 1
                report.rows.append(
                    ImportRow(
                        line=index,
                        action="update" if exists else "create",
                        username=username,
                        values=values,
                    )
                )

                if not dry_run:
                    await self._write_row(kind, row, username, exists, actor, actor_ip, language)
            except Exception as exc:  # noqa: BLE001 - jede Zeile wird einzeln gemeldet
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

    async def _write_row(
        self,
        kind: Literal["user", "device"],
        row: dict[str, str],
        username: str,
        exists: bool,
        actor: Principal,
        actor_ip: str | None,
        language: str,
    ) -> None:
        groups = _parse_groups(row.get("groups"))
        expires = _parse_date(row.get("expires_at"))
        meta = SubjectMeta(
            display_name=row.get("display_name") or None,
            note=row.get("note") or None,
            owner=row.get("owner") or None,
            device_type=row.get("device_type") or None,
            location=row.get("location") or None,
            inventory_no=row.get("inventory_no") or None,
        )
        if exists:
            subject = await self.users.subjects.ensure(
                username, SubjectType.DEVICE if kind == "device" else SubjectType.USER
            )
            for key, value in meta.model_dump(exclude_none=True).items():
                setattr(subject, key, value)
            if groups:
                await self.users.groups.set_memberships(
                    username, [(g.groupname, g.priority) for g in groups]
                )
            if expires:
                subject.expires_at = expires
                await self.users.attrs.set_check(
                    username, "Expiration", ":=", to_expiration(expires)
                )
            await self.session.commit()
            return

        if kind == "device":
            await self.devices.create(
                DeviceCreate(
                    mac=username,
                    use_mac_as_password=True,
                    expires_at=expires,
                    groups=groups,
                    vlan=row.get("vlan") or None,
                    meta=meta,
                    disabled=_parse_bool(row.get("disabled")),
                ),
                actor=actor,
                actor_ip=actor_ip,
                language=language,
            )
            return

        credential_raw = (row.get("credential_type") or "").lower()
        credential = (
            CredentialType(credential_raw)
            if credential_raw in {c.value for c in CredentialType}
            else None
        )
        await self.users.create(
            UserCreate(
                username=username,
                password=row.get("password") or None,
                credential_type=credential,
                expires_at=expires,
                groups=groups,
                vlan=row.get("vlan") or None,
                meta=meta,
                disabled=_parse_bool(row.get("disabled")),
            ),
            actor=actor,
            actor_ip=actor_ip,
            language=language,
        )

    # --- Export ----------------------------------------------------------

    async def export(self, flt: SubjectFilter, cap: int = 10_000) -> str:
        """Exportiert genau die aktuelle Filtermenge – ohne Passwoerter (NFR-1)."""
        items, _ = await self.users.search(flt, limit=cap, offset=0)
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=list(EXPORT_COLUMNS), extrasaction="ignore")
        writer.writeheader()
        for item in items:
            writer.writerow(
                {
                    "username": item.username,
                    "subject_type": item.subject_type.value,
                    "status": item.status,
                    "groups": ",".join(item.groups),
                    "display_name": item.display_name or "",
                    "owner": item.owner or "",
                    "device_type": item.device_type or "",
                    "location": item.location or "",
                    "inventory_no": item.inventory_no or "",
                    "note": (item.note or "").replace("\n", " "),
                    "expires_at": item.expires_at.isoformat() if item.expires_at else "",
                    "credential_type": item.credential_type.value if item.credential_type else "",
                }
            )
        return buffer.getvalue()

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
        usernames = list(payload.usernames)
        if payload.filter_all:
            usernames = await self.users.directory.all_usernames(flt)
        if not usernames:
            return 0, 0, []

        succeeded = 0
        errors: list[dict[str, Any]] = []
        for username in usernames:
            try:
                await self._bulk_one(username, payload, actor=actor, actor_ip=actor_ip)
                succeeded += 1
            except Exception as exc:  # noqa: BLE001 - Sammelmeldung je Objekt
                errors.append({"username": username, "error": str(exc)})

        await self.audit.log(
            action=f"bulk.{payload.action}",
            object_type="user",
            actor=actor,
            actor_ip=actor_ip,
            after={
                "count": len(usernames),
                "succeeded": succeeded,
                "failed": len(errors),
                "groupname": payload.groupname,
            },
        )
        await self.session.commit()
        return len(usernames), succeeded, errors

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
        elif payload.action == "assign_group":
            if not payload.groupname:
                raise ValidationError(code="error.validation", details={"field": "groupname"})
            await self.users.groups.add_membership(username, payload.groupname, payload.priority)
            await self.session.commit()
        elif payload.action == "remove_group":
            if not payload.groupname:
                raise ValidationError(code="error.validation", details={"field": "groupname"})
            await self.users.groups.remove_membership(username, payload.groupname)
            await self.session.commit()
        elif payload.action == "set_expiry":
            expires = payload.expires_at or utcnow()
            subject = await self.users.subjects.ensure(username)
            subject.expires_at = expires
            await self.users.attrs.set_check(username, "Expiration", ":=", to_expiration(expires))
            await self.session.commit()
