"""Instanzweite Einstellungen (``mgr_setting``)."""

from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings as app_settings
from app.core.errors import ValidationError
from app.core.mac import MAC_FORMATS
from app.models.mgr import CredentialType
from app.repositories.mgr.settings_repo import SettingRepository

KEY_MAC_FORMAT = "mac_format"
KEY_DEFAULT_CREDENTIAL = "default_credential_type"
KEY_AUDIT_RETENTION = "audit_retention_days"
KEY_ACCT_RETENTION_HINT = "accounting_retention_days"
KEY_MAB_WARNING = "show_mab_warning"

FALLBACK_MAC_FORMAT = "colon_lower"

DEFAULTS: dict[str, Any] = {
    KEY_MAC_FORMAT: app_settings.default_mac_format,
    KEY_DEFAULT_CREDENTIAL: app_settings.default_credential_type,
    KEY_AUDIT_RETENTION: app_settings.audit_retention_days,
    KEY_ACCT_RETENTION_HINT: 365,
    KEY_MAB_WARNING: True,
}


class SettingsService:
    def __init__(self, session: AsyncSession) -> None:
        self.repo = SettingRepository(session)

    async def all(self) -> dict[str, Any]:
        stored = await self.repo.all()
        return {**DEFAULTS, **stored}

    async def get(self, key: str) -> Any:
        value = await self.repo.get(key)
        return DEFAULTS.get(key) if value is None else value

    async def mac_format(self) -> str:
        """Gespeichertes Format, sonst der Instanz-Default.

        Der Rueckfall muss selbst gueltig sein: ein unsinniger Wert in
        ``FRM_DEFAULT_MAC_FORMAT`` legte sonst jede Geraetefunktion lahm.
        """
        value = await self.get(KEY_MAC_FORMAT)
        if value in MAC_FORMATS:
            return str(value)
        if app_settings.default_mac_format in MAC_FORMATS:
            return app_settings.default_mac_format
        return FALLBACK_MAC_FORMAT

    async def show_mab_warning(self) -> bool:
        return bool(await self.get(KEY_MAB_WARNING))

    async def default_credential_type(self) -> CredentialType:
        value = await self.get(KEY_DEFAULT_CREDENTIAL)
        try:
            return CredentialType(value)
        except ValueError:
            return CredentialType.BOTH

    async def update(self, values: dict[str, Any], updated_by: str | None = None) -> dict[str, Any]:
        for key, value in values.items():
            if key not in DEFAULTS:
                raise ValidationError(code="error.validation", details={"key": key})
            if key == KEY_MAC_FORMAT and value not in MAC_FORMATS:
                raise ValidationError(
                    code="error.validation",
                    details={"key": key, "allowed": sorted(MAC_FORMATS)},
                )
            if key == KEY_DEFAULT_CREDENTIAL and value not in {c.value for c in CredentialType}:
                raise ValidationError(code="error.validation", details={"key": key})
            if key in (KEY_AUDIT_RETENTION, KEY_ACCT_RETENTION_HINT) and (
                not isinstance(value, int) or value < 1
            ):
                raise ValidationError(code="error.validation", details={"key": key})
            await self.repo.set(key, value, updated_by)
        return await self.all()
