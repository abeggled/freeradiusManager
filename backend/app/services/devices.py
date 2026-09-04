"""MAB-Geraete (FR-3).

Technisch sind das Benutzer, deren Benutzername die normalisierte MAC-Adresse ist.
Das Zielformat ist konfigurierbar, damit es zur ``policy.d``-Normalisierung des
Servers passt.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import NotFoundError
from app.core.mac import MAC_FORMATS, format_mac
from app.core.security import Principal
from app.models.mgr import CredentialType, SubjectType
from app.repositories.directory import SubjectFilter
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
        """Zielformat fuer neu angelegte Geraete."""
        return format_mac(mac, await self.mac_format())

    async def resolve(self, mac: str) -> str:
        """Findet den gespeicherten Benutzernamen zu einer MAC.

        Das eingestellte Format kann sich aendern, bestehende Datensaetze
        behalten aber ihren Namen. Deshalb wird die MAC in allen bekannten
        Schreibweisen gesucht und nur dann neu formatiert, wenn es den Datensatz
        noch nicht gibt - sonst waeren vorhandene Geraete nach einer Umstellung
        weder aufrufbar noch aenderbar (FR-3).
        """
        # Die genaue Schreibweise des Aufrufers zuerst: liegen dieselbe MAC in
        # zwei Formaten vor, ist sonst nicht der gemeinte Datensatz gemeint.
        exact = mac.strip()
        if exact:
            stored = await self._stored(exact)
            if stored is not None:
                return stored

        preferred = await self.normalise(mac)
        stored = await self._stored(preferred)
        if stored is not None:
            return stored
        for fmt in MAC_FORMATS:
            candidate = format_mac(mac, fmt)
            if candidate == preferred:
                continue
            stored = await self._stored(candidate)
            if stored is not None:
                return stored
        return preferred

    async def _stored(self, username: str) -> str | None:
        """Die gespeicherte Schreibweise, nicht die des Aufrufers.

        Die Kollation vergleicht ohne Ruecksicht auf Gross- und Kleinschreibung.
        Gaebe man hier ``AA:BB:...`` zurueck, obwohl ``aa:bb:...`` gespeichert
        ist, erkennte ``_rename`` beim Umbenennen nicht mehr, dass die MAC
        zugleich das Passwort ist - MAB schluege danach fehl (FR-3).
        """
        found = await self.users.attrs.stored_username(username)
        if found is not None:
            return found
        subject = await self.users.subjects.get(username)
        return subject.username if subject is not None else None

    async def search(
        self, flt: SubjectFilter, limit: int = 50, offset: int = 0
    ) -> tuple[list[UserListItem], int]:
        flt.subject_type = SubjectType.DEVICE
        return await self.users.search(flt, limit=limit, offset=offset)

    async def get(self, mac: str, language: str = "de") -> UserDetail:
        username = await self.resolve(mac)
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
        # ueber resolve(): sonst entstuende nach einem Formatwechsel ein zweiter
        # Datensatz fuer dasselbe physische Geraet.
        username = await self.resolve(payload.mac)
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
        # ``UserService.get`` haengt den Hinweis bereits an, sofern die
        # Einstellung ihn vorsieht - hier wird nichts doppelt ergaenzt.
        return detail

    async def _device_username(self, mac: str) -> str:
        """Loest die MAC auf und stellt sicher, dass es ein Geraet ist.

        Ein Benutzer mit MAC-foermigem Namen darf nicht ueber die
        Geraete-Endpunkte veraendert oder geloescht werden.
        """
        username = await self.resolve(mac)
        subject = await self.users.subjects.get(username)
        if subject is None or subject.subject_type is not SubjectType.DEVICE:
            raise NotFoundError(code="error.not_found", details={"mac": mac})
        return username

    async def update(
        self,
        mac: str,
        payload: DeviceUpdate,
        *,
        actor: Principal,
        actor_ip: str | None = None,
        language: str = "de",
    ) -> UserDetail:
        username = await self._device_username(mac)
        # ueber resolve(): ein Zielname, der bereits in einer anderen
        # Schreibweise existiert, darf nicht als frei gelten.
        new_username = await self.resolve(payload.mac) if payload.mac else None
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
        username = await self._device_username(mac)
        await self.users.delete(username, actor=actor, actor_ip=actor_ip)

    async def set_disabled(
        self, mac: str, disabled: bool, *, actor: Principal, actor_ip: str | None = None
    ) -> None:
        username = await self._device_username(mac)
        await self.users.set_disabled(username, disabled, actor=actor, actor_ip=actor_ip)
