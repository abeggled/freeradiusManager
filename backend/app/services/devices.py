"""MAB-Geraete (FR-3).

Technisch sind das Benutzer, deren Benutzername die normalisierte MAC-Adresse ist.
Das Zielformat ist konfigurierbar, damit es zur ``policy.d``-Normalisierung des
Servers passt.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import NotFoundError
from app.core.i18n import translate
from app.core.mac import format_mac
from app.core.security import Principal
from app.models.mgr import CredentialType, SubjectType
from app.repositories.directory import SubjectFilter
from app.schemas.common import ApiWarning
from app.schemas.users import (
    DeviceCreate,
    DeviceUpdate,
    UserCreate,
    UserDetail,
    UserListItem,
    UserUpdate,
)
from app.services.users import UserService


class DeviceService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.users = UserService(session)

    async def mac_format(self) -> str:
        return await self.users.settings.mac_format()

    async def normalise(self, mac: str) -> str:
        return format_mac(mac, await self.mac_format())

    async def search(
        self, flt: SubjectFilter, limit: int = 50, offset: int = 0
    ) -> tuple[list[UserListItem], int]:
        flt.subject_type = SubjectType.DEVICE
        return await self.users.search(flt, limit=limit, offset=offset)

    async def get(self, mac: str, language: str = "de") -> UserDetail:
        username = await self.normalise(mac)
        detail = await self.users.get(username, language)
        if detail.subject_type is not SubjectType.DEVICE:
            raise NotFoundError(code="error.not_found", details={"mac": mac})
        return detail

    async def create(
        self,
        payload: DeviceCreate,
        *,
        actor: Principal,
        actor_ip: str | None = None,
        language: str = "de",
    ) -> UserDetail:
        username = await self.normalise(payload.mac)
        password = payload.password or (username if payload.use_mac_as_password else None)
        detail = await self.users.create(
            UserCreate(
                username=username,
                password=password,
                credential_type=CredentialType.CLEARTEXT,
                expires_at=payload.expires_at,
                groups=payload.groups,
                vlan=payload.vlan,
                meta=payload.meta,
                disabled=payload.disabled,
            ),
            actor=actor,
            actor_ip=actor_ip,
            subject_type=SubjectType.DEVICE,
            language=language,
        )
        detail.warnings.append(
            ApiWarning(
                code="warn.mab_not_authentication",
                message=translate("warn.mab_not_authentication", language),
            )
        )
        return detail

    async def update(
        self,
        mac: str,
        payload: DeviceUpdate,
        *,
        actor: Principal,
        actor_ip: str | None = None,
        language: str = "de",
    ) -> UserDetail:
        username = await self.normalise(mac)
        new_username = await self.normalise(payload.mac) if payload.mac else None
        return await self.users.update(
            username,
            UserUpdate(
                username=new_username,
                expires_at=payload.expires_at,
                clear_expiry=payload.clear_expiry,
                groups=payload.groups,
                vlan=payload.vlan,
                clear_vlan=payload.clear_vlan,
                meta=payload.meta,
            ),
            actor=actor,
            actor_ip=actor_ip,
            language=language,
        )

    async def delete(self, mac: str, *, actor: Principal, actor_ip: str | None = None) -> None:
        username = await self.normalise(mac)
        await self.users.delete(username, actor=actor, actor_ip=actor_ip)

    async def set_disabled(
        self, mac: str, disabled: bool, *, actor: Principal, actor_ip: str | None = None
    ) -> None:
        username = await self.normalise(mac)
        await self.users.set_disabled(username, disabled, actor=actor, actor_ip=actor_ip)
