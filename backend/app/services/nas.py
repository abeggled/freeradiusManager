"""NAS-Clients (FR-4).

Shared Secrets sind in der UI standardmaessig maskiert; die Anzeige ist
Administratoren vorbehalten und erzeugt einen Audit-Eintrag.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings as app_settings
from app.core.crypto import SecretBox
from app.core.errors import ConflictError, NotFoundError, PermissionDeniedError
from app.core.i18n import translate
from app.core.security import Principal
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

        for field in ("shortname", "type", "ports", "secret", "server", "community", "description"):
            value = getattr(payload, field)
            if value is not None:
                setattr(row, field, value)

        secret_enc: str | None = None
        if payload.clear_coa_secret:
            secret_enc = ""
        elif payload.coa_secret:
            secret_enc = self._box().encrypt(payload.coa_secret)
        await self.extra.upsert(
            row.nasname,
            coa_enabled=payload.coa_enabled,
            coa_port=payload.coa_port,
            coa_secret_enc=secret_enc if secret_enc is not None else None,
            note=payload.note,
        )
        if payload.clear_coa_secret:
            extra = await self.extra.get(row.nasname)
            if extra is not None:
                extra.coa_secret_enc = None

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
        row = await self.repo.get(nas_id)
        if row is None:
            raise NotFoundError(code="error.not_found", details={"id": nas_id})
        nasname = row.nasname
        await self.repo.delete(nas_id)
        await self.extra.delete(nasname)
        await self.audit.log(
            action="nas.delete",
            object_type="nas",
            object_id=nasname,
            actor=actor,
            actor_ip=actor_ip,
            before={"nasname": nasname},
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

    async def coa_target(self, nasname: str) -> tuple[str, int, str] | None:
        """Liefert (Host, CoA-Port, CoA-Secret) fuer ein NAS, sofern konfiguriert."""
        extra = await self.extra.get(nasname)
        if extra is None or not extra.coa_enabled or not extra.coa_secret_enc:
            return None
        return nasname, extra.coa_port, self._box().decrypt(extra.coa_secret_enc)
