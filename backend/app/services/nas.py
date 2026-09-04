"""NAS-Clients (FR-4).

Shared Secrets sind in der UI standardmaessig maskiert; die Anzeige ist
Administratoren vorbehalten und erzeugt einen Audit-Eintrag.
"""

from __future__ import annotations

import ipaddress

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings as app_settings
from app.core.crypto import SecretBox
from app.core.errors import (
    ConflictError,
    NotFoundError,
    PermissionDeniedError,
    ValidationError,
)
from app.core.i18n import translate
from app.core.locking import named_lock
from app.core.security import Principal
from app.models.mgr import MgrNasExtra
from app.repositories.mgr.nas_extra import NasExtraRepository
from app.repositories.radius.nas import NasRepository
from app.schemas.common import ApiWarning
from app.schemas.nas import MASKED_SECRET, NasCreate, NasListItem, NasUpdate, SecretReveal
from app.services.audit import AuditService


class NasService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.repo = NasRepository(session)
        self.extra = NasExtraRepository(session)
        self.audit = AuditService(session)

    @staticmethod
    def _box() -> SecretBox:
        return SecretBox(app_settings.coa_secret_key or app_settings.secret_key)

    def _to_item(self, row: object, extra: object | None) -> NasListItem:
        return NasListItem(
            id=row.id,  # type: ignore[attr-defined]
            nasname=row.nasname,  # type: ignore[attr-defined]
            shortname=row.shortname,  # type: ignore[attr-defined]
            type=row.type,  # type: ignore[attr-defined]
            ports=row.ports,  # type: ignore[attr-defined]
            server=row.server,  # type: ignore[attr-defined]
            description=row.description,  # type: ignore[attr-defined]
            secret=MASKED_SECRET,
            coa_enabled=bool(getattr(extra, "coa_enabled", False)),
            coa_port=int(getattr(extra, "coa_port", 3799) or 3799),
            has_coa_secret=bool(getattr(extra, "coa_secret_enc", None)),
            note=getattr(extra, "note", None),
        )

    async def search(
        self, search: str | None = None, limit: int = 50, offset: int = 0
    ) -> tuple[list[NasListItem], int]:
        rows, total = await self.repo.search(search=search, limit=limit, offset=offset)
        extras = await self.extra.get_many([r.nasname for r in rows])
        return [self._to_item(r, extras.get(r.nasname)) for r in rows], total

    async def get(self, nas_id: int) -> NasListItem:
        row = await self.repo.get(nas_id)
        if row is None:
            raise NotFoundError(code="error.not_found", details={"id": nas_id})
        return self._to_item(row, await self.extra.get(row.nasname))

    async def create(
        self,
        payload: NasCreate,
        *,
        actor: Principal,
        actor_ip: str | None = None,
        language: str = "de",
    ) -> tuple[NasListItem, list[ApiWarning]]:
        if await self.repo.get_by_name(payload.nasname) is not None:
            raise ConflictError(code="error.nas_exists", details={"nasname": payload.nasname})
        row = await self.repo.create(
            nasname=payload.nasname,
            shortname=payload.shortname,
            type=payload.type,
            ports=payload.ports,
            secret=payload.secret,
            server=payload.server,
            community=payload.community,
            description=payload.description,
        )
        await self.extra.upsert(
            payload.nasname,
            coa_enabled=payload.coa_enabled,
            coa_port=payload.coa_port,
            coa_secret_enc=(
                self._box().encrypt(payload.coa_secret) if payload.coa_secret else None
            ),
            note=payload.note,
        )
        await self.audit.log(
            action="nas.create",
            object_type="nas",
            object_id=payload.nasname,
            actor=actor,
            actor_ip=actor_ip,
            after=payload.model_dump(mode="json"),
        )
        await self.session.commit()
        return self._to_item(row, await self.extra.get(payload.nasname)), [
            ApiWarning(code="warn.nas_reload", message=translate("warn.nas_reload", language))
        ]

    async def update(
        self,
        nas_id: int,
        payload: NasUpdate,
        *,
        actor: Principal,
        actor_ip: str | None = None,
        language: str = "de",
    ) -> tuple[NasListItem, list[ApiWarning]]:
        # Unter derselben Sperre wie das Loeschen: sonst koennte ein
        # gleichzeitiges Loeschen zwischen Lesen und Schreiben liegen. Eine
        # reine CoA-Aenderung legte dann eine verwaiste mgr_nas_extra-Zeile an
        # und meldete Erfolg fuer ein nicht mehr vorhandenes NAS.
        async with named_lock(self.session, f"nas:{nas_id}"):
            return await self._update_locked(
                nas_id, payload, actor=actor, actor_ip=actor_ip, language=language
            )

    async def _update_locked(
        self,
        nas_id: int,
        payload: NasUpdate,
        *,
        actor: Principal,
        actor_ip: str | None,
        language: str,
    ) -> tuple[NasListItem, list[ApiWarning]]:
        row = await self.repo.get(nas_id)
        if row is None:
            raise NotFoundError(code="error.not_found", details={"id": nas_id})
        before = self._to_item(row, await self.extra.get(row.nasname)).model_dump(mode="json")
        old_name = row.nasname

        if payload.nasname and payload.nasname != old_name:
            if await self.repo.get_by_name(payload.nasname) is not None:
                raise ConflictError(code="error.nas_exists", details={"nasname": payload.nasname})
            row.nasname = payload.nasname
            await self.extra.rename(old_name, payload.nasname)

        # ``model_fields_set`` unterscheidet "nicht gesendet" von "ausdruecklich
        # auf null gesetzt" - sonst liessen sich optionale Felder zwar setzen,
        # aber nie wieder leeren.
        supplied = payload.model_fields_set
        for field in ("shortname", "type", "ports", "server", "community", "description"):
            if field in supplied:
                setattr(row, field, getattr(payload, field))
        if payload.secret:
            row.secret = payload.secret

        secret_enc: str | None = None
        if payload.clear_coa_secret:
            secret_enc = ""
        elif payload.coa_secret:
            secret_enc = self._box().encrypt(payload.coa_secret)
        # CoA laesst sich nur einschalten, wenn ein Secret vorliegt oder mitkommt.
        if payload.coa_enabled and not payload.coa_secret:
            current = await self.extra.get(row.nasname)
            if current is None or not current.coa_secret_enc:
                raise ValidationError(
                    code="error.coa_secret_required", details={"nasname": row.nasname}
                )

        await self.extra.upsert(
            row.nasname,
            coa_enabled=payload.coa_enabled,
            coa_port=payload.coa_port,
            coa_secret_enc=secret_enc if secret_enc is not None else None,
            # "" statt None, wenn das Feld ausdruecklich auf null gesetzt wurde:
            # sonst liesse sich eine Notiz setzen, aber nie wieder entfernen.
            note=("" if payload.note is None else payload.note)
            if "note" in payload.model_fields_set
            else None,
        )
        if payload.clear_coa_secret:
            extra = await self.extra.get(row.nasname)
            if extra is not None:
                extra.coa_secret_enc = None
                # Ohne Secret ist CoA nicht benutzbar; der Schalter wird
                # mitgezogen, statt einen wirkungslosen Zustand zu melden.
                extra.coa_enabled = False

        await self.audit.log(
            action="nas.update",
            object_type="nas",
            object_id=row.nasname,
            actor=actor,
            actor_ip=actor_ip,
            before=before,
            after=payload.model_dump(mode="json", exclude_unset=True),
        )
        await self.session.commit()
        return self._to_item(row, await self.extra.get(row.nasname)), [
            ApiWarning(code="warn.nas_reload", message=translate("warn.nas_reload", language))
        ]

    async def delete(self, nas_id: int, *, actor: Principal, actor_ip: str | None = None) -> None:
        async with named_lock(self.session, f"nas:{nas_id}"):
            await self._delete_locked(nas_id, actor=actor, actor_ip=actor_ip)

    async def _delete_locked(
        self, nas_id: int, *, actor: Principal, actor_ip: str | None
    ) -> None:
        row = await self.repo.get(nas_id)
        if row is None:
            raise NotFoundError(code="error.not_found", details={"id": nas_id})
        nasname = row.nasname
        # Vollstaendiger Zustand vor dem Loeschen; das Shared Secret bleibt dabei
        # maskiert (NFR-1).
        before = self._to_item(row, await self.extra.get(nasname)).model_dump(mode="json")
        await self.repo.delete(nas_id)
        await self.extra.delete(nasname)
        await self.audit.log(
            action="nas.delete",
            object_type="nas",
            object_id=nasname,
            actor=actor,
            actor_ip=actor_ip,
            before=before,
        )
        await self.session.commit()

    async def reveal_secret(
        self, nas_id: int, *, actor: Principal, actor_ip: str | None = None
    ) -> SecretReveal:
        """Anzeige des Shared Secret. Nur Administratoren, immer mit Audit-Eintrag."""
        if not actor.is_admin:
            raise PermissionDeniedError(code="error.forbidden")
        row = await self.repo.get(nas_id)
        if row is None:
            raise NotFoundError(code="error.not_found", details={"id": nas_id})
        await self.audit.log(
            action="nas.reveal_secret",
            object_type="nas",
            object_id=row.nasname,
            actor=actor,
            actor_ip=actor_ip,
            message="Shared Secret angezeigt",
        )
        await self.session.commit()
        return SecretReveal(nasname=row.nasname, secret=row.secret)

    async def coa_target(self, nas_ip_address: str) -> tuple[str, int, str] | None:
        """Liefert (Host, CoA-Port, CoA-Secret) fuer die NAS-IP einer Session.

        NAS-Clients duerfen als Netz eingetragen sein (z. B. ``192.0.2.0/24``).
        Das Secret wird dann ueber das passende Netz gefunden, das Paket aber an
        die konkrete IP der Session gesendet - ein Netz ist kein gueltiges
        UDP-Ziel (FR-7).
        """
        extra = await self.extra.get(nas_ip_address)
        if extra is None:
            extra = await self._extra_by_network(nas_ip_address)
        if extra is None or not extra.coa_enabled or not extra.coa_secret_enc:
            return None
        return nas_ip_address, extra.coa_port, self._box().decrypt(extra.coa_secret_enc)

    async def _extra_by_network(self, nas_ip_address: str) -> MgrNasExtra | None:
        """Sucht den NAS-Eintrag, dessen Netz die angegebene Adresse enthaelt."""
        try:
            address = ipaddress.ip_address(nas_ip_address)
        except ValueError:
            return None
        candidates = await self.extra.with_coa()
        matches: list[tuple[int, MgrNasExtra]] = []
        for candidate in candidates:
            if "/" not in candidate.nasname:
                continue
            try:
                network = ipaddress.ip_network(candidate.nasname, strict=False)
            except ValueError:
                continue
            if address in network:
                matches.append((network.prefixlen, candidate))
        if not matches:
            return None
        # Das spezifischste Netz gewinnt.
        return max(matches, key=lambda item: item[0])[1]
