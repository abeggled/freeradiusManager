"""Systemeinstellungen (``mgr_setting``) – nur Administratoren."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter

from app.api.deps import AdminUser, ClientIp, SessionDep
from app.core.mac import MAC_FORMATS
from app.models.mgr import CredentialType
from app.services.audit import AuditService
from app.services.settings_service import SettingsService

router = APIRouter(prefix="/settings", tags=["settings"])


@router.get("")
async def read_settings(session: SessionDep, _: AdminUser) -> dict[str, Any]:
    """Systemeinstellungen - wie das Aendern den Administratoren vorbehalten
    (Abschnitt 2). Einzelne Werte, die die Oberflaeche fuer alle Rollen braucht,
    liefern die jeweiligen Fachendpunkte."""
    return {
        "values": await SettingsService(session).all(),
        "options": {
            "mac_format": [{"key": k, "example": v} for k, v in MAC_FORMATS.items()],
            "credential_type": [c.value for c in CredentialType],
        },
    }


@router.put("")
async def update_settings(
    values: dict[str, Any], session: SessionDep, actor: AdminUser, actor_ip: ClientIp
) -> dict[str, Any]:
    service = SettingsService(session)
    before = await service.all()
    updated = await service.update(values, updated_by=actor.username)
    await AuditService(session).log(
        action="settings.update",
        object_type="setting",
        actor=actor,
        actor_ip=actor_ip,
        before=before,
        after=updated,
    )
    await session.commit()
    return updated
