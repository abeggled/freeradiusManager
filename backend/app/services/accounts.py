"""Manager-Konten und Anmeldung (FR-10)."""

from __future__ import annotations

import datetime as dt

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings as app_settings
from app.core.constants import MAX_ACCOUNT_USERNAME_LENGTH, MIN_PASSWORD_LENGTH
from app.core.crypto import (
    SecretBox,
    hash_password,
    hash_password_async,
    needs_rehash,
    verify_password_async,
)
from app.core.dates import utcnow
from app.core.errors import (
    AuthenticationError,
    ConflictError,
    NotFoundError,
    PermissionDeniedError,
    ValidationError,
)
from app.core.locking import named_lock
from app.core.security import (
    TOTP_ENROLL_SCOPE,
    TOTP_SCOPE,
    Principal,
    create_totp_challenge_token,
    decode_token,
    generate_totp_secret,
    totp_provisioning_uri,
    verify_totp,
)
from app.models.mgr import AuditResult, MgrAccount, Role
from app.repositories.mgr.accounts import AccountRepository
from app.schemas.accounts import (
    AccountCreate,
    AccountOut,
    AccountUpdate,
    PasswordChange,
    TotpSetupResponse,
)
from app.services.audit import AuditService

LOCKOUT_THRESHOLD = 10
LOCKOUT_MINUTES = 15

# Vergleichswert fuer nicht existierende Konten: ohne ihn waere an der Antwortzeit
# ablesbar, welche Benutzernamen es gibt (NFR-1).
_DUMMY_HASH = hash_password("kein-konto-mit-diesem-namen")


def _box() -> SecretBox:
    return SecretBox(app_settings.coa_secret_key or app_settings.secret_key)


class AccountService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.repo = AccountRepository(session)
        self.audit = AuditService(session)

    # --- Anmeldung -------------------------------------------------------

    async def authenticate(
        self,
        username: str,
        password: str,
        *,
        actor_ip: str | None = None,
        reset_failures: bool = True,
    ) -> MgrAccount:
        """Prueft Benutzername und Passwort.

        ``reset_failures=False`` laesst den Fehlerzaehler stehen, damit ihn erst
        die vollstaendig abgeschlossene Anmeldung zuruecksetzt - sonst waere die
        Sperre auf dem kombinierten Weg (Passwort und TOTP in einem Aufruf) nie
        erreichbar.
        """
        # Zeilensperre: gleichzeitige Fehlversuche muessen den Zaehler
        # nacheinander erhoehen, sonst bliebe die Sperre wirkungslos.
        account = await self.repo.get_by_username(username, lock=True)
        if (
            account is not None
            and account.locked_until is not None
            and account.locked_until <= utcnow()
        ):
            # Abgelaufene Sperre vollstaendig aufheben. Bliebe der Zaehler auf
            # dem Schwellwert stehen, loeste der naechste Fehlversuch - auch der
            # erste am zweiten Faktor - sofort die naechste Sperre aus; das
            # Konto waere praktisch dauerhaft gesperrt.
            account.locked_until = None
            account.failed_logins = 0
        if account is None:
            # Gleicher Aufwand wie bei einem vorhandenen Konto.
            await verify_password_async(password, _DUMMY_HASH)
        if account is None or not await verify_password_async(password, account.password_hash):
            if account is not None:
                account.failed_logins += 1
                self._apply_lockout(account)
            await self.audit.log(
                action="auth.login",
                object_type="account",
                object_id=username,
                actor_ip=actor_ip,
                result=AuditResult.FAILURE,
                message="invalid credentials",
            )
            await self.session.commit()
            raise AuthenticationError(code="error.invalid_credentials")

        if not account.is_active:
            await self._log_failed_login(account, actor_ip, "account disabled")
            raise AuthenticationError(code="error.account_disabled")
        if account.locked_until is not None and account.locked_until > utcnow():
            await self._log_failed_login(account, actor_ip, "account locked")
            raise AuthenticationError(
                code="error.account_locked",
                details={"until": account.locked_until.isoformat()},
            )

        if needs_rehash(account.password_hash or ""):
            account.password_hash = await hash_password_async(password)
        if reset_failures:
            account.failed_logins = 0
            account.locked_until = None
        await self.session.commit()
        return account

    async def apply_mapped_role(
        self, account: MgrAccount, role: Role, *, actor_ip: str | None = None
    ) -> None:
        """Uebernimmt die aus den OIDC-Claims abgeleitete Rolle.

        Der letzte aktive Administrator wird dabei nicht herabgestuft - sonst
        koennte eine Aenderung im Identity-Provider die Instanz verwaisen lassen.
        """
        if account.role is role:
            return
        if (
            account.role is Role.ADMINISTRATOR
            and role is not Role.ADMINISTRATOR
            and await self.repo.count_active_administrators(exclude_id=account.id, lock=True) == 0
        ):
            raise ValidationError(code="error.last_administrator")
        previous = account.role
        account.role = role
        # Wie bei der Aenderung durch einen Administrator: bestehende Token
        # dieses Kontos werden dauerhaft ungueltig.
        account.session_epoch += 1
        # Auch eine vom Identity-Provider ausgeloeste Aenderung ist eine
        # schreibende Aktion und gehoert ins Protokoll (FR-9).
        await self.audit.log(
            action="account.role_mapped",
            object_type="account",
            object_id=account.username,
            actor_ip=actor_ip,
            before={"role": previous.value},
            after={"role": role.value, "source": "oidc"},
        )
        await self.session.commit()

    async def _log_failed_login(
        self, account: MgrAccount, actor_ip: str | None, reason: str
    ) -> None:
        """Auch ein richtiges Passwort gegen ein gesperrtes Konto gehoert ins
        Protokoll - sonst bliebe der Versuch unsichtbar (FR-9)."""
        await self.audit.log(
            action="auth.login",
            object_type="account",
            object_id=account.username,
            actor_ip=actor_ip,
            result=AuditResult.FAILURE,
            message=reason,
        )
        await self.session.commit()

    @staticmethod
    def _apply_lockout(account: MgrAccount) -> None:
        """Setzt die Sperre beim Erreichen der Schwelle.

        Eine bereits laufende Sperre wird nicht verlaengert: sonst koennte ein
        Aufrufer ein Konto allein durch weitere Fehlversuche dauerhaft
        blockieren, ohne das Passwort zu kennen.
        """
        if account.failed_logins < LOCKOUT_THRESHOLD:
            return
        now = utcnow()
        if account.locked_until is None or account.locked_until <= now:
            account.locked_until = now + dt.timedelta(minutes=LOCKOUT_MINUTES)

    async def clear_failures(self, account: MgrAccount) -> None:
        """Setzt Fehlerzaehler und Sperre zurueck - nach vollstaendigem Erfolg."""
        account.failed_logins = 0
        account.locked_until = None
        await self.session.commit()

    def requires_totp(self, account: MgrAccount) -> bool:
        return account.totp_enabled

    def requires_totp_enrollment(self, account: MgrAccount) -> bool:
        return (
            app_settings.require_totp_for_admin
            and account.role is Role.ADMINISTRATOR
            and not account.totp_enabled
        )

    def challenge_for(self, account: MgrAccount) -> str:
        """Challenge fuer den zweiten Faktor eines bereits eingerichteten Kontos."""
        return create_totp_challenge_token(
            account.id, scope=TOTP_SCOPE, epoch=account.session_epoch
        )

    def enrollment_challenge_for(self, account: MgrAccount) -> str:
        """Challenge fuer die Ersteinrichtung - nur ohne aktives TOTP."""
        return create_totp_challenge_token(
            account.id, scope=TOTP_ENROLL_SCOPE, epoch=account.session_epoch
        )

    async def account_from_challenge(
        self, challenge: str, *, scope: str = TOTP_SCOPE
    ) -> MgrAccount:
        payload = decode_token(challenge, scope=scope)
        account = await self.repo.get(int(payload["sub"]))
        if account is None or not account.is_active:
            raise AuthenticationError(code="error.unauthenticated")
        # Eine vor der Passwortaenderung ausgestellte Challenge darf den zweiten
        # Schritt nicht mehr freischalten.
        # Mit Sekundenbruchteilen; aeltere Token fuehren nur ``iat``.
        issued_at = float(payload.get("auth_at", payload.get("iat", 0)))
        if (
            account.password_changed_at is not None
            and issued_at < account.password_changed_at.replace(tzinfo=dt.UTC).timestamp()
        ):
            raise AuthenticationError(code="error.reauthentication_required")
        # Eine Deaktivierung oder Rollenaenderung entwertet auch die bereits
        # ausgestellte Challenge: sonst liesse sich eine vor der Sperrung
        # angeforderte Challenge nach einer Reaktivierung noch einloesen.
        if int(payload.get("gen", 0)) != account.session_epoch:
            raise AuthenticationError(code="error.reauthentication_required")
        # Die Sperre muss auch hier greifen: sonst liesse sich der zweite Faktor
        # mit derselben Challenge unbegrenzt weiterraten, und ein spaeter
        # richtiger Code haette die Sperre sogar wieder aufgehoben.
        if account.locked_until is not None and account.locked_until > utcnow():
            raise AuthenticationError(
                code="error.account_locked", details={"until": account.locked_until.isoformat()}
            )
        return account

    async def verify_totp_code(
        self, account: MgrAccount, code: str, *, actor_ip: str | None = None
    ) -> None:
        # Wie bei der Passwortpruefung: der Zaehler wird unter Zeilensperre
        # fortgeschrieben, damit parallele Versuche sich nicht ueberschreiben.
        locked = await self.repo.get_for_update(account.id)
        if locked is not None:
            account = locked
        if not account.totp_secret_enc:
            raise AuthenticationError(code="error.totp_required")
        secret = _box().decrypt(account.totp_secret_enc)
        counter = verify_totp(secret, code)
        # Ein bereits angenommenes Zeitfenster wird nicht erneut akzeptiert: ein
        # abgefangener Code liesse sich sonst innerhalb des Prueffensters ein
        # zweites Mal einloesen und erzeugte eine weitere Sitzung. Die Marke
        # steht unter derselben Zeilensperre wie der Fehlerzaehler.
        replayed = (
            counter is not None
            and account.totp_last_counter is not None
            and counter <= account.totp_last_counter
        )
        if counter is None or replayed:
            # Fehlversuche am zweiten Faktor zaehlen auf dieselbe Sperre ein wie
            # falsche Passwoerter - sonst waere der TOTP-Schritt frei ratbar.
            account.failed_logins += 1
            self._apply_lockout(account)
            await self.audit.log(
                action="auth.totp",
                object_type="account",
                object_id=account.username,
                actor_ip=actor_ip,
                result=AuditResult.FAILURE,
                message="replayed totp code" if replayed else "invalid totp code",
            )
            await self.session.commit()
            raise AuthenticationError(code="error.totp_invalid")
        account.totp_last_counter = counter
        account.failed_logins = 0
        account.locked_until = None
        await self.session.commit()

    async def mark_login(self, account: MgrAccount, actor_ip: str | None = None) -> None:
        account.last_login_at = utcnow()
        await self.audit.log(
            action="auth.login",
            object_type="account",
            object_id=account.username,
            actor_ip=actor_ip,
            message=f"role={account.role.value}",
        )
        await self.session.commit()

    # --- TOTP ------------------------------------------------------------

    async def start_totp_enrollment(
        self,
        account: MgrAccount,
        *,
        actor: Principal | None = None,
        actor_ip: str | None = None,
    ) -> TotpSetupResponse:
        """Legt ein neues TOTP-Geheimnis an.

        Fuer ein Konto mit bereits aktivem TOTP ist das verboten: sonst koennte
        wer nur das Passwort kennt die zweite Stufe durch eine eigene ersetzen.
        Das Zuruecksetzen erfolgt ausschliesslich durch einen Administrator.
        """
        async with named_lock(self.session, f"account-totp:{account.id}"):
            await self.session.refresh(account)
            return await self._start_totp_enrollment_locked(
                account, actor=actor, actor_ip=actor_ip
            )

    async def _start_totp_enrollment_locked(
        self, account: MgrAccount, *, actor: Principal | None, actor_ip: str | None
    ) -> TotpSetupResponse:
        if account.totp_enabled:
            raise ConflictError(code="error.totp_already_enrolled")
        # ``totp_changed_at`` wird erst bei der Bestaetigung gesetzt: waehrend
        # der Einrichtung aus dem eigenen Profil heraus wuerde die laufende
        # Sitzung sonst mitten im Vorgang beendet.
        secret = generate_totp_secret()
        account.totp_secret_enc = _box().encrypt(secret)
        account.totp_enabled = False
        # Neues Geheimnis, neue Zeitfensterrechnung (siehe ``reset_totp``).
        account.totp_last_counter = None
        # Auch der Beginn ist eine sicherheitsrelevante Aenderung: das
        # Geheimnis wird dauerhaft geschrieben und ersetzt ein evtl. bereits
        # begonnenes. Wird die Einrichtung abgebrochen, gaebe es sonst gar
        # keinen Eintrag dazu (FR-9). Das Geheimnis selbst steht nie im
        # Protokoll.
        await self.audit.log(
            action="account.totp_enrollment_started",
            object_type="account",
            object_id=account.username,
            # Im Anmeldeweg gibt es noch keine Sitzung; aus der Selbstbedienung
            # heraus ist der Handelnde bekannt und gehoert in den Eintrag.
            actor=actor,
            actor_ip=actor_ip,
        )
        await self.session.commit()
        return TotpSetupResponse(
            secret=secret, provisioning_uri=totp_provisioning_uri(secret, account.username)
        )

    async def confirm_totp(
        self,
        account: MgrAccount,
        code: str,
        *,
        actor_ip: str | None = None,
        actor: Principal | None = None,
    ) -> None:
        # Unter derselben Sperre wie das Zuruecksetzen durch einen Administrator:
        # sonst koennte dieses zwischen Pruefung und Schreiben das Geheimnis
        # loeschen und das Konto bliebe als "TOTP aktiv, ohne Geheimnis" zurueck -
        # eine Anmeldung waere danach unmoeglich.
        async with named_lock(self.session, f"account-totp:{account.id}"):
            await self.session.refresh(account)
            await self._confirm_totp_locked(account, code, actor_ip=actor_ip, actor=actor)

    async def _confirm_totp_locked(
        self,
        account: MgrAccount,
        code: str,
        *,
        actor_ip: str | None,
        actor: Principal | None,
    ) -> None:
        if not account.totp_secret_enc:
            raise ValidationError(code="error.totp_setup_required")
        if account.totp_enabled:
            # Die Einrichtung ist bereits abgeschlossen; ein erneuter Aufruf
            # koennte sonst mit demselben Code eine weitere Sitzung erzeugen.
            raise ConflictError(code="error.totp_already_enrolled")
        secret = _box().decrypt(account.totp_secret_enc)
        counter = verify_totp(secret, code)
        # Auch der Einrichtungscode gilt nur einmal: sonst liesse sich Challenge
        # und Code innerhalb des Prueffensters erneut einloesen.
        if counter is None or counter <= (account.totp_last_counter or -1):
            raise AuthenticationError(code="error.totp_invalid")
        account.totp_last_counter = counter
        account.totp_enabled = True
        account.totp_changed_at = utcnow()
        await self.audit.log(
            action="account.totp_enabled",
            object_type="account",
            object_id=account.username,
            # Bei der Selbstbedienung ist der Handelnde bekannt; im ersten
            # Anmeldeweg gibt es noch keine Sitzung.
            actor=actor,
            actor_ip=actor_ip,
        )
        await self.session.commit()

    # --- Kontenverwaltung ------------------------------------------------

    async def search(
        self, search: str | None = None, limit: int = 50, offset: int = 0
    ) -> tuple[list[AccountOut], int]:
        rows, total = await self.repo.search(search=search, limit=limit, offset=offset)
        return [AccountOut.model_validate(r) for r in rows], total

    async def get(self, account_id: int) -> MgrAccount:
        account = await self.repo.get(account_id)
        if account is None:
            raise NotFoundError(code="error.not_found", details={"id": account_id})
        return account

    async def create(
        self, payload: AccountCreate, *, actor: Principal, actor_ip: str | None = None
    ) -> AccountOut:
        if await self.repo.get_by_username(payload.username) is not None:
            raise ConflictError(code="error.conflict", details={"username": payload.username})
        account = MgrAccount(
            username=payload.username,
            email=payload.email,
            display_name=payload.display_name,
            role=payload.role,
            language=payload.language,
            password_hash=await hash_password_async(payload.password),
            password_changed_at=utcnow(),
        )
        await self.repo.add(account)
        await self.audit.log(
            action="account.create",
            object_type="account",
            object_id=payload.username,
            actor=actor,
            actor_ip=actor_ip,
            after=payload.model_dump(mode="json"),
        )
        await self.session.commit()
        return AccountOut.model_validate(account)

    async def update(
        self,
        account_id: int,
        payload: AccountUpdate,
        *,
        actor: Principal,
        actor_ip: str | None = None,
    ) -> AccountOut:
        # Dieselbe Sperre wie Einrichtung und Bestaetigung des zweiten Faktors:
        # ein Zuruecksetzen dazwischen liesse das Konto als "TOTP aktiv, ohne
        # Geheimnis" zurueck und die naechste Anmeldung waere unmoeglich.
        async with named_lock(self.session, f"account-totp:{account_id}"):
            return await self._update_locked(account_id, payload, actor=actor, actor_ip=actor_ip)

    async def _update_locked(
        self,
        account_id: int,
        payload: AccountUpdate,
        *,
        actor: Principal,
        actor_ip: str | None,
    ) -> AccountOut:
        account = await self.get(account_id)
        before = AccountOut.model_validate(account).model_dump(mode="json")

        demoting = (
            payload.role is not None
            and payload.role is not Role.ADMINISTRATOR
            and account.role is Role.ADMINISTRATOR
        ) or (payload.is_active is False and account.role is Role.ADMINISTRATOR)
        if (
            demoting
            and await self.repo.count_active_administrators(exclude_id=account.id, lock=True) == 0
        ):
            raise ValidationError(code="error.last_administrator")

        # ``model_fields_set`` trennt "nicht gesendet" von "ausdruecklich auf
        # null gesetzt"; sonst liessen sich E-Mail und Anzeigename nie leeren.
        supplied = payload.model_fields_set
        for field in ("email", "display_name"):
            if field in supplied:
                setattr(account, field, getattr(payload, field))
        for field in ("role", "is_active", "language"):
            value = getattr(payload, field)
            if value is not None:
                # Rolle und Status beenden laufende Sitzungen dauerhaft: ein
                # blosser Vergleich mit dem aktuellen Wert liesse alte Token
                # nach "weg und zurueck" wieder aufleben.
                if field in ("role", "is_active") and value != getattr(account, field):
                    account.session_epoch += 1
                setattr(account, field, value)
        if payload.reset_totp:
            account.totp_enabled = False
            account.totp_secret_enc = None
            # Die Marke gilt nur fuer das jeweilige Geheimnis. Bliebe sie
            # stehen, wiese die Bestaetigung des neuen Faktors den ersten
            # richtigen Code als Wiedereinsatz ab.
            account.totp_last_counter = None
            # Beendet auch bereits laufende Sitzungen dieses Kontos.
            account.totp_changed_at = utcnow()

        await self.audit.log(
            action="account.update",
            object_type="account",
            object_id=account.username,
            actor=actor,
            actor_ip=actor_ip,
            before=before,
            after=payload.model_dump(mode="json", exclude_unset=True),
        )
        await self.session.commit()
        return AccountOut.model_validate(account)

    async def delete(
        self, account_id: int, *, actor: Principal, actor_ip: str | None = None
    ) -> None:
        if account_id == actor.account_id:
            raise ValidationError(code="error.self_delete")
        account = await self.get(account_id)
        if (
            account.role is Role.ADMINISTRATOR
            and await self.repo.count_active_administrators(exclude_id=account.id, lock=True) == 0
        ):
            raise ValidationError(code="error.last_administrator")
        username = account.username
        # Vollstaendiger Zustand vor dem Loeschen: danach liesse sich nicht mehr
        # feststellen, welche Rechte das Konto hatte (FR-9).
        before = AccountOut.model_validate(account).model_dump(mode="json")
        before["oidc_subject"] = account.oidc_subject
        await self.repo.delete(account)
        await self.audit.log(
            action="account.delete",
            object_type="account",
            object_id=username,
            actor=actor,
            actor_ip=actor_ip,
            before=before,
        )
        await self.session.commit()

    async def set_oidc_subject(
        self,
        account_id: int,
        subject: str | None,
        *,
        actor: Principal,
        actor_ip: str | None = None,
    ) -> AccountOut:
        """Verknuepft ein Konto mit einer OIDC-Identitaet oder loest die Bindung."""
        account = await self.get(account_id)
        previous = account.oidc_subject
        if subject:
            existing = await self.repo.get_by_oidc_subject(subject)
            if existing is not None and existing.id != account.id:
                raise ConflictError(
                    code="error.oidc_subject_taken",
                    details={"oidc_subject": subject, "username": existing.username},
                )
        account.oidc_subject = subject or None
        if account.oidc_subject != previous:
            # Das Loesen der Verknuepfung soll sofort wirken; sonst blieben die
            # ueber diese Identitaet ausgestellten Sitzungen bis zum Ablauf
            # gueltig. Dasselbe gilt beim Umhaengen auf ein anderes Subject.
            account.session_epoch += 1
        await self.audit.log(
            action="account.link_oidc" if subject else "account.unlink_oidc",
            object_type="account",
            object_id=account.username,
            actor=actor,
            actor_ip=actor_ip,
            before={"oidc_subject": previous},
            after={"oidc_subject": account.oidc_subject},
        )
        await self.session.commit()
        return AccountOut.model_validate(account)

    async def change_password(
        self,
        account_id: int,
        payload: PasswordChange,
        *,
        actor: Principal,
        actor_ip: str | None = None,
    ) -> None:
        # Zeilensperre wie bei der Anmeldung: parallele Versuche wuerden sonst
        # denselben Zaehlerstand lesen und schreiben.
        locked = await self.repo.get_for_update(account_id)
        account = locked if locked is not None else await self.get(account_id)
        if account.id != actor.account_id and not actor.is_admin:
            raise PermissionDeniedError(code="error.forbidden")
        # Wie bei der Anmeldung: eine abgelaufene Sperre wird vollstaendig
        # aufgehoben. Bliebe der Zaehler auf dem Schwellwert stehen, loeste der
        # erste Tippfehler danach sofort die naechste Sperre aus.
        if account.locked_until is not None and account.locked_until <= utcnow():
            account.locked_until = None
            account.failed_logins = 0
        # Die Sperre muss auch hier greifen: sonst liesse sich mit einer noch
        # gueltigen Sitzung unbegrenzt weiterraten.
        if account.locked_until is not None and account.locked_until > utcnow():
            raise AuthenticationError(
                code="error.account_locked",
                details={"until": account.locked_until.isoformat()},
            )
        if account.id == actor.account_id and not await verify_password_async(
            payload.current_password, account.password_hash
        ):
            # Auch mit gueltiger Sitzung darf das aktuelle Passwort nicht
            # unbegrenzt geraten werden.
            account.failed_logins += 1
            self._apply_lockout(account)
            await self.audit.log(
                action="account.change_password",
                object_type="account",
                object_id=account.username,
                actor=actor,
                actor_ip=actor_ip,
                result=AuditResult.FAILURE,
                message="falsches aktuelles Passwort",
            )
            await self.session.commit()
            raise AuthenticationError(code="error.invalid_credentials")
        account.password_hash = await hash_password_async(payload.new_password)
        account.password_changed_at = utcnow()
        # Wie nach einer vollstaendigen Anmeldung: das aktuelle Passwort wurde
        # gerade bewiesen. Sonst traegt das Konto die frueheren Fehlversuche in
        # die erzwungene Neuanmeldung mit und ein einziger Tippfehler sperrt es.
        account.failed_logins = 0
        account.locked_until = None
        await self.audit.log(
            action="account.change_password",
            object_type="account",
            object_id=account.username,
            actor=actor,
            actor_ip=actor_ip,
            after={"password": payload.new_password},
        )
        await self.session.commit()

    async def ensure_bootstrap_admin(self, username: str, password: str) -> MgrAccount | None:
        """Legt beim ersten Start einen Administrator an, falls noch keiner existiert.

        Das Passwort unterliegt derselben Mindestlaenge wie ueber die
        Kontenverwaltung: ein Platzhalter aus der Umgebung waere sonst ein
        vollwertiger Administratorzugang mit ratbarem Passwort.
        """
        # Zuerst pruefen, ob ueberhaupt ein Konto entstehen soll: sonst
        # verhinderte ein inzwischen unbenutzter Platzhalter in der Umgebung den
        # Start einer laengst eingerichteten Instanz.
        if await self.repo.count_active_administrators() > 0:
            return None
        if await self.repo.get_by_username(username) is not None:
            return None
        # Dieselben Grenzen wie ueber die Kontenverwaltung: ein zu langer Wert
        # aus der Umgebung liefe sonst in einen Datenbankfehler - der Start
        # scheiterte, statt eine lesbare Meldung zu erzeugen.
        if not username.strip() or len(username) > MAX_ACCOUNT_USERNAME_LENGTH:
            raise ValidationError(
                code="error.validation",
                details={"field": "username", "maximum": MAX_ACCOUNT_USERNAME_LENGTH},
            )
        if len(password) < MIN_PASSWORD_LENGTH:
            raise ValidationError(
                code="error.password_too_short", details={"minimum": MIN_PASSWORD_LENGTH}
            )
        account = MgrAccount(
            username=username,
            role=Role.ADMINISTRATOR,
            password_hash=await hash_password_async(password),
            password_changed_at=utcnow(),
        )
        await self.repo.add(account)
        await self.audit.log(
            action="account.bootstrap",
            object_type="account",
            object_id=username,
            message="Initialer Administrator angelegt",
        )
        await self.session.commit()
        return account
