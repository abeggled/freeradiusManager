"""Benutzerverwaltung (FR-1) und Gruppenzuordnung.

Die Credential-Typen sind pro Benutzer waehlbar (``mgr_subject.credential_type``);
der Instanz-Default kommt aus ``mgr_setting``.

Klartextpasswoerter verlassen die Anwendung nie: Werte von Passwort-Attributen
werden in jeder API-Antwort maskiert (NFR-1).
"""

from __future__ import annotations

import datetime as dt
import json
from collections.abc import Sequence

from sqlalchemy.ext.asyncio import AsyncSession

from app.core import radius_dict
from app.core.crypto import nt_hash
from app.core.dates import from_expiration, to_expiration, utcnow
from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.core.i18n import translate
from app.core.identifiers import fold
from app.core.locking import named_lock
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
from app.services.masking import mask_attributes, stored_values, unmask
from app.services.settings_service import SettingsService

AUTH_TYPE = "Auth-Type"
EXPIRATION = "Expiration"
REJECT = "Reject"

CREDENTIAL_ATTRIBUTES = {
    CredentialType.CLEARTEXT: ("Cleartext-Password",),
    CredentialType.NT: ("NT-Password",),
    CredentialType.BOTH: ("Cleartext-Password", "NT-Password"),
}


def _lock_names(username: str, groups: list[MembershipIn]) -> list[str]:
    """Sperrnamen fuer eine Aenderung an einem Benutzer und seinen Gruppen.

    ``named_lock`` nimmt sie auf einer Verbindung und in sortierter Reihenfolge;
    geschachtelte Aufrufe brauchten je eine Verbindung und zwei Aufrufer in
    verschiedener Reihenfolge liefen in eine Verklemmung.
    """
    return [f"user:{username}", *(f"group:{g.groupname}" for g in groups)]


def _locked_groups(names: list[str]) -> set[str]:
    """Die Gruppennamen aus einer Sperrliste."""
    return {name.removeprefix("group:") for name in names if name.startswith("group:")}


RESERVED_CHECK_ATTRIBUTES = frozenset(radius_dict.PASSWORD_ATTRIBUTES) | {
    AUTH_TYPE.lower(),
    EXPIRATION.lower(),
}
"""Check-Attribute, die nur ueber ihre eigenen Endpunkte geaendert werden.

Aus dem gemeinsamen Woerterbuch: eine feste Zweierliste haette bei
Bestandsbenutzern mit Crypt-, MD5- oder SHA2-Password deren Anmeldedaten
geloescht. Die Oberflaeche blendet sie im Expertenmodus aus - sonst schickte
sie die vom Server gelieferten Zeilen unveraendert zurueck und jede Aenderung
scheiterte an dieser Pruefung."""


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

        # Ueber die Vergleichsform verbunden: Anmeldedaten koennen als "Alice"
        # und die Mitgliedschaft als "alice" gespeichert sein - die Datenbank
        # meint denselben Benutzer. Ein exakter Vergleich liesse die
        # Mitgliedschaft in Liste und Export fehlen, und ein Reimport dieser
        # Datei entfernte sie dann tatsaechlich.
        memberships = await self.groups.memberships_for(usernames)
        by_user: dict[str, list[MembershipOut]] = {}
        for m in memberships:
            by_user.setdefault(fold(m.username), []).append(
                MembershipOut(groupname=m.groupname, priority=m.priority)
            )

        checks = await self.attrs.check_attributes_for(usernames)
        checks_by_user: dict[str, list[RadCheck]] = {}
        for check in checks:
            checks_by_user.setdefault(fold(check.username), []).append(check)

        items: list[UserListItem] = []
        for row in rows:
            subject = row.subject
            key = fold(row.username)
            user_checks = checks_by_user.get(key, [])
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
                    groups=sorted(m.groupname for m in by_user.get(key, [])),
                    memberships=sorted(
                        by_user.get(key, []), key=lambda m: (m.priority, m.groupname)
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

        active_sessions = await self.acct.count_active_for_user(username)
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
            active_sessions=active_sessions,
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
        # Neben dem eigenen Namen auch die Zielgruppen: waere eine davon
        # zwischen Existenzpruefung und Schreiben geloescht worden, liesse die
        # neue radusergroup-Zeile sie als reine Mitgliedschaftsgruppe wieder
        # auferstehen.
        names = _lock_names(payload.username, payload.groups)
        async with named_lock(self.session, *names):
            return await self._create_locked(
                payload,
                actor=actor,
                actor_ip=actor_ip,
                subject_type=subject_type,
                language=language,
                locked=_locked_groups(names),
            )

    async def _create_locked(
        self,
        payload: UserCreate,
        *,
        actor: Principal,
        actor_ip: str | None,
        subject_type: SubjectType,
        language: str,
        locked: set[str],
        commit: bool = True,
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

        await self._set_memberships(payload.username, payload.groups, locked)

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
        if commit:
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
        names = _lock_names(username, payload.groups or [])
        if payload.groups is not None:
            # Auch die Gruppen, die dabei *verlassen* werden: zwei gleichzeitige
            # Aenderungen an verschiedenen Benutzern saehen sonst beide noch zwei
            # Mitglieder und loeschten anschliessend beide - die attributlose
            # Gruppe verschwaende trotz ``guard_last_membership``.
            names += [f"group:{m.groupname}" for m in await self.groups.memberships(username)]
        if payload.username and payload.username != username:
            names.append(f"user:{payload.username}")
        async with named_lock(self.session, *names):
            return await self._update_locked(
                username,
                payload,
                actor=actor,
                actor_ip=actor_ip,
                language=language,
                locked=_locked_groups(names),
            )

    async def _update_locked(
        self,
        username: str,
        payload: UserUpdate,
        *,
        actor: Principal,
        actor_ip: str | None,
        language: str,
        locked: set[str],
        commit: bool = True,
    ) -> UserDetail:
        before = await self.get(username, language)
        subject = await self._ensure_subject(username)
        warnings: list[ApiWarning] = []

        if payload.username and payload.username != username:
            await self._rename(username, payload.username)
            username = payload.username
            subject = await self.subjects.ensure(username)

        if payload.credential_type is not None:
            await self._change_credential_type(username, subject, payload.credential_type)

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
            await self._set_memberships(username, payload.groups, locked)

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
        if commit:
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
        async with named_lock(self.session, f"user:{username}"):
            await self._set_password_locked(username, payload, actor=actor, actor_ip=actor_ip)

    async def _set_password_locked(
        self,
        username: str,
        payload: PasswordSet,
        *,
        actor: Principal,
        actor_ip: str | None,
        commit: bool = True,
    ) -> None:
        # Auch reine radreply-/radusergroup-Eintraege gelten als vorhanden: sie
        # erscheinen in der Liste und lassen sich dort oeffnen, also muessen sie
        # auch ein Passwort erhalten koennen.
        if not await self.attrs.exists_anywhere(username) and not await self.subjects.get(username):
            raise NotFoundError(code="error.not_found", details={"username": username})
        subject = await self._ensure_subject(username)
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
        if commit:
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
        # Unter derselben Sperre wie Loeschen und Passwortwechsel: sonst koennte
        # ein gleichzeitiges Loeschen dazwischentreten und dieser Vorgang legte
        # den Benutzer anschliessend als reine Reject-Zeile neu an.
        async with named_lock(self.session, f"user:{username}"):
            await self._set_disabled_locked(username, disabled, actor=actor, actor_ip=actor_ip)

    async def _set_disabled_locked(
        self,
        username: str,
        disabled: bool,
        *,
        actor: Principal,
        actor_ip: str | None,
        commit: bool = True,
    ) -> None:
        if not await self.attrs.exists_anywhere(username) and not await self.subjects.get(username):
            raise NotFoundError(code="error.not_found", details={"username": username})
        subject = await self._ensure_subject(username)
        # Bestandsdaten koennen mehrere Auth-Type-Zeilen enthalten; bewertet
        # wird die Gesamtheit, wie in der Statusberechnung.
        rows = [
            row
            for row in await self.attrs.check_attributes(username)
            if row.attribute.lower() == AUTH_TYPE.lower()
        ]
        others = [row for row in rows if row.value != REJECT]
        if disabled:
            # Eine vorhandene Auth-Type-Vorgabe (etwa "PAP") wird gemerkt und
            # beim Entsperren zurueckgeschrieben; sonst waere die Sperre eine
            # dauerhafte Aenderung der Authentifizierungskonfiguration.
            if others:
                # Die vollstaendige Sammlung wird gemerkt: eine Sperre darf die
                # Authentifizierungskonfiguration nicht dauerhaft beschneiden.
                subject.disabled_state = json.dumps(
                    [{"op": row.op, "value": row.value} for row in others]
                )
            # set_check ersetzt alle Zeilen des Attributs.
            await self.attrs.set_check(username, AUTH_TYPE, ":=", REJECT)
            subject.disabled_at = utcnow()
        else:
            # Entfernt werden ausschliesslich die Reject-Zeilen; eine daneben
            # bestehende Vorgabe (etwa "PAP") bleibt erhalten. Nur wenn dadurch
            # keine Zeile uebrig bleibt, wird der gemerkte Zustand
            # zurueckgeschrieben.
            for row in rows:
                if row.value == REJECT:
                    await self.attrs.delete_check_row(row.id)
            if not others:
                for previous in self._previous_auth_types(subject.disabled_state):
                    await self.attrs.add_check(
                        username, AUTH_TYPE, previous["op"], previous["value"]
                    )
            subject.disabled_state = None
            subject.disabled_at = None
        await self.audit.log(
            action="user.disable" if disabled else "user.enable",
            object_type=subject.subject_type.value,
            object_id=username,
            actor=actor,
            actor_ip=actor_ip,
            after={"disabled": disabled},
        )
        if commit:
            await self.session.commit()

    async def apply_row(
        self,
        username: str,
        *,
        subject_type: SubjectType,
        password: PasswordSet | None,
        payload: UserUpdate,
        disabled: bool | None,
        actor: Principal,
        actor_ip: str | None = None,
        language: str = "de",
    ) -> None:
        """Eine Importzeile fuer einen bestehenden Datensatz - in einer Transaktion.

        Die Einzelaufrufe schreiben jeweils sofort fest. Scheiterte ein spaeterer
        Teilschritt, waere das Passwort bereits geaendert, obwohl der Bericht die
        Zeile als Fehler meldet (FR-8). Deshalb laufen alle Teilschritte unter
        derselben Sperre und mit einem gemeinsamen Commit.
        """
        names = _lock_names(username, payload.groups or [])
        if payload.groups is not None:
            names += [f"group:{m.groupname}" for m in await self.groups.memberships(username)]
        if payload.username and payload.username != username:
            names.append(f"user:{payload.username}")

        async with named_lock(self.session, *names):
            try:
                # Erst unter der Sperre pruefen und anlegen: ein gleichzeitiges
                # Loeschen zwischen der Einstufung der Zeile und diesem Punkt
                # liesse den Datensatz sonst als Metadatenrumpf - oder mit
                # Passwort - wieder entstehen.
                if not await self.attrs.exists_anywhere(username) and not await self.subjects.get(
                    username
                ):
                    raise NotFoundError(code="error.not_found", details={"username": username})
                await self.subjects.ensure(username, subject_type)
                # Ein neues Passwort wird vor der Typumstellung geschrieben: der
                # Wechsel zu einem Typ mit Klartext liesse sich sonst aus dem
                # alten NT-Hash nicht ableiten.
                if password is not None:
                    await self._set_password_locked(
                        username, password, actor=actor, actor_ip=actor_ip, commit=False
                    )
                await self._update_locked(
                    username,
                    payload,
                    actor=actor,
                    actor_ip=actor_ip,
                    language=language,
                    locked=_locked_groups(names),
                    commit=False,
                )
                target = payload.username or username
                if disabled is not None:
                    await self._set_disabled_locked(
                        target, disabled, actor=actor, actor_ip=actor_ip, commit=False
                    )
            except Exception:
                # Der Aufrufer faengt den Fehler zeilenweise ab; ohne dieses
                # Zuruecknehmen truege die naechste Zeile die Teilaenderungen mit.
                await self.session.rollback()
                raise
            await self.session.commit()

    async def delete(self, username: str, *, actor: Principal, actor_ip: str | None = None) -> None:
        # Unter derselben Sperre wie die schreibenden Pfade: sonst koennte ein
        # gleichzeitiger Passwortwechsel die alten Zeilen noch sehen und nach dem
        # Loeschen neue schreiben - der Benutzer waere ohne Metadaten zurueck.
        # Auch die Gruppen des Benutzers: verschwindet eine attributlose Gruppe
        # dadurch, wird das protokolliert (siehe ``_delete_locked``).
        names = [
            f"user:{username}",
            *(f"group:{m.groupname}" for m in await self.groups.memberships(username)),
        ]
        async with named_lock(self.session, *names):
            await self._delete_locked(username, actor=actor, actor_ip=actor_ip)

    async def _delete_locked(
        self, username: str, *, actor: Principal, actor_ip: str | None
    ) -> None:
        subject = await self.subjects.get(username)
        exists = await self.attrs.exists_anywhere(username)
        if subject is None and not exists:
            raise NotFoundError(code="error.not_found", details={"username": username})
        object_type = subject.subject_type.value if subject else SubjectType.USER.value
        # Der vollstaendige Zustand wird vor dem Loeschen festgehalten - danach
        # liesse er sich nicht mehr rekonstruieren (FR-9). Passwortwerte sind in
        # der Detailansicht bereits maskiert und werden zusaetzlich redigiert.
        before = (await self.get(username)).model_dump(mode="json")
        # Eine Gruppe, die nur ueber diese eine Mitgliedschaft bestand,
        # verschwindet mit dem Benutzer. Das Loeschen des Benutzers deswegen zu
        # verweigern waere eine Sackgasse - stattdessen wird der Wegfall wie ein
        # ``group.delete`` protokolliert (FR-9).
        vanishing = await self._groups_vanishing_with(username)
        await self.attrs.delete_user(username)
        await self.subjects.delete(username)
        for groupname in vanishing:
            await self.audit.log(
                action="group.delete",
                object_type="group",
                object_id=groupname,
                actor=actor,
                actor_ip=actor_ip,
                before={"groupname": groupname, "members": [username]},
                message="letzte Mitgliedschaft mit dem Benutzer entfallen",
            )
        await self.audit.log(
            action="user.delete",
            object_type=object_type,
            object_id=username,
            actor=actor,
            actor_ip=actor_ip,
            before=before,
        )
        await self.session.commit()

    async def _groups_vanishing_with(self, username: str) -> list[str]:
        """Attributlose Gruppen, deren letzte Mitgliedschaft dieser Benutzer ist."""
        vanishing: list[str] = []
        for membership in await self.groups.memberships(username):
            name = membership.groupname
            if await self.groups.check_attributes(name) or await self.groups.reply_attributes(name):
                continue
            members = await self.groups.members(name, limit=2, offset=0)
            if len(members) == 1 and fold(members[0]) == fold(username):
                vanishing.append(name)
        return vanishing

    # ------------------------------------------------------------------
    # Hilfsfunktionen
    # ------------------------------------------------------------------

    async def _ensure_subject(
        self, username: str, subject_type: SubjectType = SubjectType.USER
    ) -> MgrSubject:
        """Metadaten anlegen und dabei den vorhandenen Credential-Typ uebernehmen.

        Ein Bestandsbenutzer ohne ``mgr_subject`` waere sonst als ``both``
        eingetragen, obwohl er nur einen NT-Hash besitzt - der Export meldete
        einen Typ, den die Daten nicht hergeben.
        """
        existing = await self.subjects.get(username)
        if existing is not None:
            return existing

        checks = await self.attrs.check_attributes(username)
        attributes = {row.attribute.lower() for row in checks}
        has_cleartext = "cleartext-password" in attributes
        has_nt = "nt-password" in attributes
        if has_cleartext and has_nt:
            credential_type = CredentialType.BOTH
        elif has_nt:
            credential_type = CredentialType.NT
        elif has_cleartext:
            credential_type = CredentialType.CLEARTEXT
        else:
            credential_type = await self.settings.default_credential_type()

        subject = await self.subjects.add(
            MgrSubject(
                username=username,
                subject_type=subject_type,
                credential_type=credential_type,
            )
        )
        return subject

    async def _set_memberships(
        self, username: str, groups: list[MembershipIn], locked: set[str]
    ) -> None:
        """Setzt die Mitgliedschaften und prueft dabei die Gruppen.

        Das RADIUS-Schema kennt keine Fremdschluessel: ein Tippfehler wuerde
        sonst eine Phantomgruppe erzeugen, die anschliessend in der
        Gruppenliste auftaucht.
        """
        for membership in groups:
            if not await self.groups.exists(membership.groupname):
                raise NotFoundError(
                    code="error.not_found", details={"groupname": membership.groupname}
                )
        # Eine entfernte Zuordnung darf keine attributlose Gruppe aufloesen.
        # Ueber die Vergleichsform: eine bestehende Mitgliedschaft "staff" und
        # der angeforderte Name "Staff" bezeichnen dieselbe Gruppe. Exakt
        # verglichen galte das als Entfernung - und der Schutz der letzten
        # Mitgliedschaft wiese eine inhaltlich unveraenderte Anfrage ab.
        wanted = {fold(g.groupname) for g in groups}
        for current in await self.groups.memberships(username):
            if fold(current.groupname) in wanted:
                continue
            if current.groupname not in locked:
                # Die Mitgliedschaft ist erst nach dem Setzen der Sperren
                # entstanden. Ohne ihre Gruppensperre waere die Pruefung unten
                # wertlos - deshalb abbrechen statt ungesichert zu loeschen.
                raise ConflictError(code="error.busy", details={"groupname": current.groupname})
            await self.guard_last_membership(current.groupname, username)
        await self.groups.set_memberships(username, [(g.groupname, g.priority) for g in groups])

    async def guard_last_membership(self, groupname: str, username: str) -> None:
        """Schuetzt eine nur ueber Mitgliedschaften bestehende Gruppe.

        Die letzte Zuordnung zu entfernen waere ein Loeschen ohne Bestaetigung
        und ohne ``group.delete`` im Audit-Log.
        """
        if await self.groups.check_attributes(groupname) or await self.groups.reply_attributes(
            groupname
        ):
            return
        # Wie in ``GroupService``: der Vergleich folgt der Kollation.
        members = await self.groups.members(groupname, limit=2, offset=0)
        if len(members) == 1 and fold(members[0]) == fold(username):
            raise ValidationError(code="error.group_last_member", details={"groupname": groupname})

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
        nt = await self.attrs.find_check(old, "NT-Password")
        # Auch ein reiner NT-Hash kann aus der alten MAC abgeleitet sein; ohne
        # diese Erkennung schluege MAB nach dem Umbenennen sofort fehl.
        mac_is_password = (
            subject is not None
            and subject.subject_type is SubjectType.DEVICE
            and (
                (cleartext is not None and cleartext.value == old)
                or (cleartext is None and nt is not None and nt.value.upper() == nt_hash(old))
            )
        )

        await self.attrs.rename(old, new)
        await self.subjects.rename(old, new)

        if mac_is_password:
            credential_type = subject.credential_type if subject else CredentialType.CLEARTEXT
            await self._write_credentials(new, new, credential_type)

    async def check_credential_change(self, username: str, target: CredentialType) -> None:
        """Prueft einen Typwechsel, ohne zu schreiben - fuer die Import-Vorschau."""
        wanted = set(CREDENTIAL_ATTRIBUTES[target])
        if "Cleartext-Password" not in wanted:
            return
        if await self.attrs.find_check(username, "Cleartext-Password") is None:
            raise ValidationError(
                code="error.credential_type_needs_password",
                details={"username": username, "credential_type": target.value},
            )

    async def _change_credential_type(
        self, username: str, subject: MgrSubject, target: CredentialType
    ) -> None:
        """Passt die gespeicherten Attribute an den neuen Credential-Typ an.

        Aus dem NT-Hash laesst sich kein Klartext zurueckgewinnen; ein Wechsel,
        der Klartext verlangt, wird deshalb abgewiesen, statt einen Typ zu
        melden, den die Daten nicht hergeben.
        """
        wanted = set(CREDENTIAL_ATTRIBUTES[target])
        cleartext = await self.attrs.find_check(username, "Cleartext-Password")

        if "Cleartext-Password" in wanted and cleartext is None:
            raise ValidationError(
                code="error.credential_type_needs_password",
                details={"username": username, "credential_type": target.value},
            )
        if "NT-Password" in wanted and cleartext is not None:
            await self.attrs.set_check(username, "NT-Password", ":=", nt_hash(cleartext.value))
        for attribute in ("Cleartext-Password", "NT-Password"):
            if attribute not in wanted:
                await self.attrs.delete_check(username, attribute)
        subject.credential_type = target

    async def _write_credentials(
        self, username: str, password: str, credential_type: CredentialType
    ) -> None:
        wanted = CREDENTIAL_ATTRIBUTES[credential_type]
        wanted_lower = {a.lower() for a in wanted}
        # Alle Passwort-Attribute aus dem Woerterbuch, nicht nur die beiden
        # eigenen: ein Bestandsbenutzer mit Crypt-, MD5- oder SSHA-Password
        # behielte sonst sein altes Geheimnis, und je nach
        # Authentifizierungsmethode gaelte weiterhin das alte Passwort.
        for row in await self.attrs.check_attributes(username):
            if (
                radius_dict.is_password_attribute(row.attribute)
                and row.attribute.lower() not in wanted_lower
            ):
                await self.attrs.delete_check_row(row.id)
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
        # Aus dem gemeinsamen Woerterbuch: eine feste Zweierliste haette bei
        # Bestandsbenutzern mit Crypt-, MD5- oder SHA2-Password deren
        # Anmeldedaten geloescht.
        reserved = RESERVED_CHECK_ATTRIBUTES
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
            # Passwort-Attribute sind auch in ``radreply` moeglich und werden
            # maskiert ausgeliefert. Unveraendert zurueckgeschickt duerfen sie
            # den gespeicherten Wert nicht durch Sternchen ersetzen.
            stored = stored_values(existing)
            for item in attributes:
                kept = unmask(item.attribute, item.op, item.value, stored)
                if kept is not None:
                    rows.append((item.attribute, item.op, kept))
                    continue
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
    def _previous_auth_types(raw: str | None) -> list[dict[str, str]]:
        """Liest den gemerkten Zustand.

        Aeltere Eintraege enthalten ein einzelnes Objekt; beide Formen werden
        unterstuetzt.
        """
        if not raw:
            return []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []
        entries = data if isinstance(data, list) else [data]
        return [
            {"op": str(item["op"]), "value": str(item["value"])}
            for item in entries
            if isinstance(item, dict) and "op" in item and "value" in item
        ]

    @staticmethod
    def _status(checks: Sequence[RadCheck]) -> UserStatus:
        """Status eines Subjekts aus seinen Check-Attributen.

        Mehrfach vorhandene ``Auth-Type``- oder ``Expiration``-Zeilen kommen in
        Bestandsdaten vor. Bewertet wird deshalb - wie im SQL-Filter - ob
        *irgendeine* Zeile zutrifft; sonst zeigte die Liste "aktiv", waehrend
        eine Sammelaktion mit demselben Filter das Objekt erfasst.
        """
        if any(
            row.attribute.lower() == AUTH_TYPE.lower() and row.value == REJECT for row in checks
        ):
            return "disabled"
        now = utcnow()
        for row in checks:
            if row.attribute.lower() != EXPIRATION.lower():
                continue
            parsed = from_expiration(row.value)
            if parsed is not None and parsed < now:
                return "expired"
        if not any(radius_dict.is_password_attribute(row.attribute) for row in checks):
            return "no_credentials"
        return "active"

    @staticmethod
    def _expiry(checks: Sequence[RadCheck], subject: MgrSubject | None) -> dt.datetime | None:
        """Das wirksame, also frueheste Ablaufdatum.

        Bestandsdaten koennen mehrere ``Expiration``-Zeilen fuehren; die
        Statusberechnung wertet den Benutzer schon als abgelaufen, wenn *eine*
        davon vergangen ist. Gaebe man hier die erste zurueck, zeigte die
        Oberflaeche ein kuenftiges Datum zu einem abgelaufenen Status - und ein
        Reimport des Exports reaktivierte den Benutzer.
        """
        parsed_rows = [
            parsed
            for row in checks
            if row.attribute.lower() == EXPIRATION.lower()
            and (parsed := from_expiration(row.value)) is not None
        ]
        if parsed_rows:
            return min(parsed_rows)
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
