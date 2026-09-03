"""Benutzerverwaltung (FR-1) und Gruppenzuordnung.

Die Credential-Typen sind pro Benutzer waehlbar (``mgr_subject.credential_type``);
der Instanz-Default kommt aus ``mgr_setting``.

Klartextpasswoerter verlassen die Anwendung nie: Werte von Passwort-Attributen
werden in jeder API-Antwort maskiert (NFR-1).
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Sequence

from sqlalchemy.ext.asyncio import AsyncSession

from app.core import radius_dict
from app.core.crypto import nt_hash
from app.core.dates import from_expiration, to_expiration, utcnow
from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.core.i18n import translate
from app.core.security import Principal
from app.models.mgr import CredentialType, MgrSubject, SubjectType
from app.models.radius import RadCheck
from app.repositories.directory import DirectoryRepository, SubjectFilter
from app.repositories.mgr.subjects import SubjectRepository
from app.repositories.radius.acct import AccountingRepository
from app.repositories.radius.groups import GroupRepository
from app.repositories.radius.postauth import ACCEPT_VALUES, PostAuthRepository
from app.repositories.radius.users import UserAttributeRepository
from app.schemas.common import ApiWarning
from app.schemas.users import (
    AttributeIn,
    MembershipIn,
    MembershipOut,
    PasswordSet,
    SubjectMeta,
    UserCreate,
    UserDetail,
    UserListItem,
    UserStatus,
    UserUpdate,
)
from app.services.attributes import validate_triple, vlan_triples
from app.services.audit import AuditService
from app.services.masking import mask_attributes
from app.services.settings_service import SettingsService

AUTH_TYPE = "Auth-Type"
EXPIRATION = "Expiration"
REJECT = "Reject"

CREDENTIAL_ATTRIBUTES = {
    CredentialType.CLEARTEXT: ("Cleartext-Password",),
    CredentialType.NT: ("NT-Password",),
    CredentialType.BOTH: ("Cleartext-Password", "NT-Password"),
}


class UserService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.attrs = UserAttributeRepository(session)
        self.groups = GroupRepository(session)
        self.subjects = SubjectRepository(session)
        self.directory = DirectoryRepository(session)
        self.acct = AccountingRepository(session)
        self.postauth = PostAuthRepository(session)
        self.settings = SettingsService(session)
        self.audit = AuditService(session)

    # ------------------------------------------------------------------
    # Lesen
    # ------------------------------------------------------------------

    async def search(
        self, flt: SubjectFilter, limit: int = 50, offset: int = 0
    ) -> tuple[list[UserListItem], int]:
        rows, total = await self.directory.search(flt, limit=limit, offset=offset)
        usernames = [row.username for row in rows]

        memberships = await self.groups.memberships_for(usernames)
        by_user: dict[str, list[MembershipOut]] = {}
        for m in memberships:
            by_user.setdefault(m.username, []).append(
                MembershipOut(groupname=m.groupname, priority=m.priority)
            )

        checks = await self.attrs.check_attributes_for(usernames)
        checks_by_user: dict[str, list[RadCheck]] = {}
        for check in checks:
            checks_by_user.setdefault(check.username, []).append(check)

        items: list[UserListItem] = []
        for row in rows:
            subject = row.subject
            user_checks = checks_by_user.get(row.username, [])
            items.append(
                UserListItem(
                    username=row.username,
                    subject_type=subject.subject_type if subject else SubjectType.USER,
                    display_name=subject.display_name if subject else None,
                    owner=subject.owner if subject else None,
                    note=subject.note if subject else None,
                    location=subject.location if subject else None,
                    device_type=subject.device_type if subject else None,
                    inventory_no=subject.inventory_no if subject else None,
                    groups=sorted(m.groupname for m in by_user.get(row.username, [])),
                    memberships=sorted(
                        by_user.get(row.username, []), key=lambda m: (m.priority, m.groupname)
                    ),
                    status=self._status(user_checks),
                    expires_at=self._expiry(user_checks, subject),
                    credential_type=subject.credential_type if subject else None,
                    has_metadata=subject is not None,
                )
            )
        return items, total

    async def get(self, username: str, language: str = "de") -> UserDetail:
        checks = list(await self.attrs.check_attributes(username))
        replies = list(await self.attrs.reply_attributes(username))
        subject = await self.subjects.get(username)
        memberships = await self.groups.memberships(username)
        # Eine reine Gruppenzuordnung genuegt als Nachweis: solche Bestandsnamen
        # erscheinen in der Liste und muessen dort auch aufrufbar sein.
        if not checks and not replies and subject is None and not memberships:
            raise NotFoundError(code="error.not_found", details={"username": username})

        active = await self.acct.active_for_user(username)
        recent = await self.postauth.recent_for(username, limit=1)
        vlan = next(
            (r.value for r in replies if r.attribute.lower() == "tunnel-private-group-id"), None
        )

        warnings: list[ApiWarning] = []
        if (
            subject
            and subject.subject_type is SubjectType.DEVICE
            and await self.settings.show_mab_warning()
        ):
            warnings.append(
                ApiWarning(
                    code="warn.mab_not_authentication",
                    message=translate("warn.mab_not_authentication", language),
                )
            )
        if any(r.attribute == "Cleartext-Password" for r in checks):
            warnings.append(
                ApiWarning(
                    code="warn.cleartext_stored",
                    message=translate("warn.cleartext_stored", language),
                    attribute="Cleartext-Password",
                )
            )

        return UserDetail(
            username=username,
            subject_type=subject.subject_type if subject else SubjectType.USER,
            display_name=subject.display_name if subject else None,
            owner=subject.owner if subject else None,
            note=subject.note if subject else None,
            location=subject.location if subject else None,
            device_type=subject.device_type if subject else None,
            inventory_no=subject.inventory_no if subject else None,
            groups=[m.groupname for m in memberships],
            status=self._status(checks),
            expires_at=self._expiry(checks, subject),
            credential_type=subject.credential_type if subject else None,
            has_metadata=subject is not None,
            check_attributes=mask_attributes(checks),
            reply_attributes=mask_attributes(replies),
            memberships=[
                MembershipOut(groupname=m.groupname, priority=m.priority) for m in memberships
            ],
            vlan=vlan,
            active_sessions=len(active),
            last_auth=recent[0].authdate if recent else None,
            last_auth_reply=recent[0].reply if recent else None,
            created_at=subject.created_at if subject else None,
            updated_at=subject.updated_at if subject else None,
            warnings=warnings,
        )

    # ------------------------------------------------------------------
    # Schreiben
    # ------------------------------------------------------------------

    async def create(
        self,
        payload: UserCreate,
        *,
        actor: Principal,
        actor_ip: str | None = None,
        subject_type: SubjectType = SubjectType.USER,
        language: str = "de",
    ) -> UserDetail:
        # Geprueft wird ueber alle RADIUS-Tabellen: in einer Bestandsinstallation
        # kann ein Name auch nur Antwortattribute oder Gruppen besitzen, die
        # sonst beim Anlegen ueberschrieben wuerden.
        if await self.attrs.exists_anywhere(payload.username) or await self.subjects.get(
            payload.username
        ):
            raise ConflictError(code="error.user_exists", details={"username": payload.username})

        credential_type = payload.credential_type or await self.settings.default_credential_type()
        if payload.password:
            await self._write_credentials(payload.username, payload.password, credential_type)
        elif not payload.check_attributes:
            raise ValidationError(
                code="error.password_required", details={"username": payload.username}
            )

        warnings = await self._apply_check_attributes(
            payload.username, payload.check_attributes, language=language
        )
        warnings += await self._apply_reply_attributes(
            payload.username, payload.reply_attributes, payload.vlan, language=language
        )

        if payload.expires_at:
            await self.attrs.set_check(
                payload.username, EXPIRATION, ":=", to_expiration(payload.expires_at)
            )
        if payload.disabled:
            await self.attrs.set_check(payload.username, AUTH_TYPE, ":=", REJECT)

        await self.groups.set_memberships(
            payload.username, [(g.groupname, g.priority) for g in payload.groups]
        )

        subject = MgrSubject(
            username=payload.username,
            subject_type=subject_type,
            credential_type=credential_type,
            expires_at=payload.expires_at,
            disabled_at=utcnow() if payload.disabled else None,
            created_by=actor.username,
            **payload.meta.model_dump(),
        )
        await self.subjects.add(subject)

        await self.audit.log(
            action="user.create",
            object_type=subject_type.value,
            object_id=payload.username,
            actor=actor,
            actor_ip=actor_ip,
            after=payload.model_dump(mode="json"),
        )
        await self.session.commit()
        detail = await self.get(payload.username, language)
        detail.warnings.extend(warnings)
        return detail

    async def update(
        self,
        username: str,
        payload: UserUpdate,
        *,
        actor: Principal,
        actor_ip: str | None = None,
        language: str = "de",
    ) -> UserDetail:
        before = await self.get(username, language)
        subject = await self.subjects.ensure(username)
        warnings: list[ApiWarning] = []

        if payload.username and payload.username != username:
            await self._rename(username, payload.username)
            username = payload.username
            subject = await self.subjects.ensure(username)

        if payload.credential_type is not None:
            subject.credential_type = payload.credential_type

        if payload.clear_expiry:
            await self.attrs.delete_check(username, EXPIRATION)
            subject.expires_at = None
        elif payload.expires_at is not None:
            await self.attrs.set_check(
                username, EXPIRATION, ":=", to_expiration(payload.expires_at)
            )
            subject.expires_at = payload.expires_at

        if payload.check_attributes is not None:
            warnings += await self._apply_check_attributes(
                username, payload.check_attributes, replace=True, language=language
            )

        if payload.reply_attributes is not None or payload.vlan is not None or payload.clear_vlan:
            warnings += await self._apply_reply_attributes(
                username,
                payload.reply_attributes,
                None if payload.clear_vlan else payload.vlan,
                replace=payload.reply_attributes is not None,
                clear_vlan=payload.clear_vlan,
                language=language,
            )

        if payload.groups is not None:
            await self.groups.set_memberships(
                username, [(g.groupname, g.priority) for g in payload.groups]
            )

        if payload.meta is not None:
            for key, value in payload.meta.model_dump(exclude_unset=True).items():
                setattr(subject, key, value)

        await self.audit.log(
            action="user.update",
            object_type=subject.subject_type.value,
            object_id=username,
            actor=actor,
            actor_ip=actor_ip,
            before=before.model_dump(mode="json"),
            after=payload.model_dump(mode="json", exclude_unset=True),
        )
        await self.session.commit()
        detail = await self.get(username, language)
        detail.warnings.extend(warnings)
        return detail

    async def set_password(
        self,
        username: str,
        payload: PasswordSet,
        *,
        actor: Principal,
        actor_ip: str | None = None,
    ) -> None:
        # Auch reine radreply-/radusergroup-Eintraege gelten als vorhanden: sie
        # erscheinen in der Liste und lassen sich dort oeffnen, also muessen sie
        # auch ein Passwort erhalten koennen.
        if not await self.attrs.exists_anywhere(username) and not await self.subjects.get(username):
            raise NotFoundError(code="error.not_found", details={"username": username})
        subject = await self.subjects.ensure(username)
        credential_type = payload.credential_type or subject.credential_type
        subject.credential_type = credential_type
        await self._write_credentials(username, payload.password, credential_type)
        await self.audit.log(
            action="user.set_password",
            object_type=subject.subject_type.value,
            object_id=username,
            actor=actor,
            actor_ip=actor_ip,
            after={"credential_type": credential_type.value, "password": payload.password},
        )
        await self.session.commit()

    async def set_disabled(
        self,
        username: str,
        disabled: bool,
        *,
        actor: Principal,
        actor_ip: str | None = None,
    ) -> None:
        """Sperren/Entsperren. Der uebrige Zustand bleibt unangetastet (FR-1)."""
        if not await self.attrs.exists_anywhere(username) and not await self.subjects.get(username):
            raise NotFoundError(code="error.not_found", details={"username": username})
        subject = await self.subjects.ensure(username)
        if disabled:
            await self.attrs.set_check(username, AUTH_TYPE, ":=", REJECT)
            subject.disabled_at = utcnow()
        else:
            row = await self.attrs.find_check(username, AUTH_TYPE)
            if row is not None and row.value == REJECT:
                await self.attrs.delete_check(username, AUTH_TYPE)
            subject.disabled_at = None
        await self.audit.log(
            action="user.disable" if disabled else "user.enable",
            object_type=subject.subject_type.value,
            object_id=username,
            actor=actor,
            actor_ip=actor_ip,
            after={"disabled": disabled},
        )
        await self.session.commit()

    async def delete(self, username: str, *, actor: Principal, actor_ip: str | None = None) -> None:
        subject = await self.subjects.get(username)
        exists = await self.attrs.exists_anywhere(username)
        if subject is None and not exists:
            raise NotFoundError(code="error.not_found", details={"username": username})
        object_type = subject.subject_type.value if subject else SubjectType.USER.value
        await self.attrs.delete_user(username)
        await self.subjects.delete(username)
        await self.audit.log(
            action="user.delete",
            object_type=object_type,
            object_id=username,
            actor=actor,
            actor_ip=actor_ip,
            before={"username": username},
        )
        await self.session.commit()

    # ------------------------------------------------------------------
    # Hilfsfunktionen
    # ------------------------------------------------------------------

    async def _rename(self, old: str, new: str) -> None:
        """Umbenennung fasst beide Seiten in einer Transaktion an (Abschnitt 4.1).

        Bei MAB-Geraeten ist die MAC ueblicherweise zugleich das Passwort (FR-3).
        Bleibt der alte Wert stehen, scheitert die Anmeldung sofort, weil das NAS
        die neue MAC als Kennung *und* Passwort sendet - deshalb wird das
        Credential hier im selben Vorgang mitgezogen.
        """
        if await self.attrs.exists_anywhere(new) or await self.subjects.get(new):
            raise ConflictError(code="error.user_exists", details={"username": new})

        subject = await self.subjects.get(old)
        cleartext = await self.attrs.find_check(old, "Cleartext-Password")
        mac_is_password = (
            subject is not None
            and subject.subject_type is SubjectType.DEVICE
            and cleartext is not None
            and cleartext.value == old
        )

        await self.attrs.rename(old, new)
        await self.subjects.rename(old, new)

        if mac_is_password:
            credential_type = subject.credential_type if subject else CredentialType.CLEARTEXT
            await self._write_credentials(new, new, credential_type)

    async def _write_credentials(
        self, username: str, password: str, credential_type: CredentialType
    ) -> None:
        wanted = CREDENTIAL_ATTRIBUTES[credential_type]
        for attribute in ("Cleartext-Password", "NT-Password"):
            if attribute not in wanted:
                await self.attrs.delete_check(username, attribute)
        for attribute in wanted:
            value = password if attribute == "Cleartext-Password" else nt_hash(password)
            await self.attrs.set_check(username, attribute, ":=", value)

    async def _apply_check_attributes(
        self,
        username: str,
        attributes: list[AttributeIn] | None,
        *,
        replace: bool = False,
        language: str = "de",
    ) -> list[ApiWarning]:
        """Setzt zusaetzliche Check-Attribute. Passwort-, Auth-Type- und
        Expiration-Attribute werden hier bewusst nicht angefasst – dafuer gibt es
        eigene, protokollierte Aktionen."""
        warnings: list[ApiWarning] = []
        if attributes is None:
            return warnings
        reserved = {"cleartext-password", "nt-password", AUTH_TYPE.lower(), EXPIRATION.lower()}
        if replace:
            for row in await self.attrs.check_attributes(username):
                if row.attribute.lower() not in reserved:
                    await self.attrs.delete_check_row(row.id)
        for item in attributes:
            if item.attribute.lower() in reserved:
                raise ValidationError(
                    code="error.validation",
                    details={"attribute": item.attribute, "reason": "reserved"},
                )
            for w in validate_triple(
                item.attribute, item.op, item.value, table="radcheck", language=language
            ):
                warnings.append(ApiWarning(code=w.code, message=w.message, attribute=w.attribute))
            await self.attrs.add_check(username, item.attribute, item.op, item.value)
        return warnings

    async def _apply_reply_attributes(
        self,
        username: str,
        attributes: list[AttributeIn] | None,
        vlan: str | None,
        *,
        replace: bool = True,
        clear_vlan: bool = False,
        language: str = "de",
    ) -> list[ApiWarning]:
        warnings: list[ApiWarning] = []
        existing = list(await self.attrs.reply_attributes(username))
        rows: list[tuple[str, str, str]] = []

        if attributes is not None:
            for item in attributes:
                for w in validate_triple(
                    item.attribute, item.op, item.value, table="radreply", language=language
                ):
                    warnings.append(
                        ApiWarning(code=w.code, message=w.message, attribute=w.attribute)
                    )
                rows.append((item.attribute, item.op, item.value))
        elif replace or clear_vlan or vlan is not None:
            rows = [(r.attribute, r.op, r.value) for r in existing]

        vlan_names = {a.lower() for a in radius_dict.VLAN_ATTRIBUTES}
        if vlan is not None or clear_vlan:
            rows = [r for r in rows if r[0].lower() not in vlan_names]
        if vlan:
            rows.extend((t.attribute, t.op, t.value) for t in vlan_triples(vlan))

        if attributes is not None or vlan is not None or clear_vlan:
            await self.attrs.replace_replies(username, rows)
        return warnings

    @staticmethod
    def _status(checks: Sequence[RadCheck]) -> UserStatus:
        by_name = {row.attribute.lower(): row for row in checks}
        auth_type = by_name.get(AUTH_TYPE.lower())
        if auth_type is not None and auth_type.value == REJECT:
            return "disabled"
        expiration = by_name.get(EXPIRATION.lower())
        if expiration is not None:
            parsed = from_expiration(expiration.value)
            if parsed is not None and parsed < utcnow():
                return "expired"
        if not any(radius_dict.is_password_attribute(row.attribute) for row in checks):
            return "no_credentials"
        return "active"

    @staticmethod
    def _expiry(checks: Sequence[RadCheck], subject: MgrSubject | None) -> dt.datetime | None:
        for row in checks:
            if row.attribute.lower() == EXPIRATION.lower():
                parsed = from_expiration(row.value)
                if parsed is not None:
                    return parsed
        return subject.expires_at if subject else None

    async def last_reply(self, username: str) -> str | None:
        recent = await self.postauth.recent_for(username, limit=1)
        if not recent:
            return None
        return "accept" if recent[0].reply in ACCEPT_VALUES else "reject"

    async def apply_meta(self, username: str, meta: SubjectMeta) -> MgrSubject:
        subject = await self.subjects.ensure(username)
        for key, value in meta.model_dump(exclude_unset=True).items():
            setattr(subject, key, value)
        return subject

    async def membership_list(self, username: str) -> list[MembershipIn]:
        return [
            MembershipIn(groupname=m.groupname, priority=m.priority)
            for m in await self.groups.memberships(username)
        ]
