"""Manager-Konten und Anmeldung (FR-10)."""

from __future__ import annotations

import datetime as dt

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings as app_settings
from app.core.crypto import SecretBox, hash_password, needs_rehash, verify_password
from app.core.dates import utcnow
from app.core.errors import (
    AuthenticationError,
    ConflictError,
    NotFoundError,
    PermissionDeniedError,
    ValidationError,
)
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


def _box() -> SecretBox:
    return SecretBox(app_settings.coa_secret_key or app_settings.secret_key)


class AccountService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.repo = AccountRepository(session)
        self.audit = AuditService(session)

    # --- Anmeldung -------------------------------------------------------

    async def authenticate(
        self, username: str, password: str, *, actor_ip: str | None = None
    ) -> MgrAccount:
        account = await self.repo.get_by_username(username)
        if account is None or not verify_password(password, account.password_hash):
            if account is not None:
                account.failed_logins += 1
                if account.failed_logins >= LOCKOUT_THRESHOLD:
                    account.locked_until = utcnow() + dt.timedelta(minutes=LOCKOUT_MINUTES)
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
            raise AuthenticationError(code="error.account_disabled")
        if account.locked_until is not None and account.locked_until > utcnow():
            raise AuthenticationError(
                code="error.account_locked",
                details={"until": account.locked_until.isoformat()},
            )

        if needs_rehash(account.password_hash or ""):
            account.password_hash = hash_password(password)
        account.failed_logins = 0
        account.locked_until = None
        await self.session.commit()
        return account

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
        return create_totp_challenge_token(account.id, scope=TOTP_SCOPE)

    def enrollment_challenge_for(self, account: MgrAccount) -> str:
        """Challenge fuer die Ersteinrichtung - nur ohne aktives TOTP."""
        return create_totp_challenge_token(account.id, scope=TOTP_ENROLL_SCOPE)

    async def account_from_challenge(
        self, challenge: str, *, scope: str = TOTP_SCOPE
    ) -> MgrAccount:
        payload = decode_token(challenge, scope=scope)
        account = await self.repo.get(int(payload["sub"]))
        if account is None or not account.is_active:
            raise AuthenticationError(code="error.unauthenticated")
        return account

    async def verify_totp_code(
        self, account: MgrAccount, code: str, *, actor_ip: str | None = None
    ) -> None:
        if not account.totp_secret_enc:
            raise AuthenticationError(code="error.totp_required")
        secret = _box().decrypt(account.totp_secret_enc)
        if not verify_totp(secret, code):
            # Fehlversuche am zweiten Faktor zaehlen auf dieselbe Sperre ein wie
            # falsche Passwoerter - sonst waere der TOTP-Schritt frei ratbar.
            account.failed_logins += 1
            if account.failed_logins >= LOCKOUT_THRESHOLD:
                account.locked_until = utcnow() + dt.timedelta(minutes=LOCKOUT_MINUTES)
            await self.audit.log(
                action="auth.totp",
                object_type="account",
                object_id=account.username,
                actor_ip=actor_ip,
                result=AuditResult.FAILURE,
                message="invalid totp code",
            )
            await self.session.commit()
            raise AuthenticationError(code="error.totp_invalid")
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

    async def start_totp_enrollment(self, account: MgrAccount) -> TotpSetupResponse:
        """Legt ein neues TOTP-Geheimnis an.

        Fuer ein Konto mit bereits aktivem TOTP ist das verboten: sonst koennte
        wer nur das Passwort kennt die zweite Stufe durch eine eigene ersetzen.
        Das Zuruecksetzen erfolgt ausschliesslich durch einen Administrator.
        """
        if account.totp_enabled:
            raise ConflictError(code="error.totp_already_enrolled")
        secret = generate_totp_secret()
        account.totp_secret_enc = _box().encrypt(secret)
        account.totp_enabled = False
        await self.session.commit()
        return TotpSetupResponse(
            secret=secret, provisioning_uri=totp_provisioning_uri(secret, account.username)
        )

    async def confirm_totp(
        self, account: MgrAccount, code: str, *, actor_ip: str | None = None
    ) -> None:
        if not account.totp_secret_enc:
            raise ValidationError(code="error.totp_setup_required")
        secret = _box().decrypt(account.totp_secret_enc)
        if not verify_totp(secret, code):
            raise AuthenticationError(code="error.totp_invalid")
        account.totp_enabled = True
        await self.audit.log(
            action="account.totp_enabled",
            object_type="account",
            object_id=account.username,
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
            password_hash=hash_password(payload.password),
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
        account = await self.get(account_id)
        before = AccountOut.model_validate(account).model_dump(mode="json")

        demoting = (
            payload.role is not None
            and payload.role is not Role.ADMINISTRATOR
            and account.role is Role.ADMINISTRATOR
        ) or payload.is_active is False
        if demoting and await self.repo.count_active_administrators(exclude_id=account.id) == 0:
            raise ValidationError(code="error.last_administrator")

        for field in ("email", "display_name", "role", "is_active", "language"):
            value = getattr(payload, field)
            if value is not None:
                setattr(account, field, value)
        if payload.reset_totp:
            account.totp_enabled = False
            account.totp_secret_enc = None

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
            and await self.repo.count_active_administrators(exclude_id=account.id) == 0
        ):
            raise ValidationError(code="error.last_administrator")
        username = account.username
        await self.repo.delete(account)
        await self.audit.log(
            action="account.delete",
            object_type="account",
            object_id=username,
            actor=actor,
            actor_ip=actor_ip,
            before={"username": username},
        )
        await self.session.commit()

    async def change_password(
        self,
        account_id: int,
        payload: PasswordChange,
        *,
        actor: Principal,
        actor_ip: str | None = None,
    ) -> None:
        account = await self.get(account_id)
        if account.id != actor.account_id and not actor.is_admin:
            raise PermissionDeniedError(code="error.forbidden")
        if account.id == actor.account_id and not verify_password(
            payload.current_password, account.password_hash
        ):
            raise AuthenticationError(code="error.invalid_credentials")
        account.password_hash = hash_password(payload.new_password)
        account.password_changed_at = utcnow()
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
        """Legt beim ersten Start einen Administrator an, falls noch keiner existiert."""
        if await self.repo.count_active_administrators() > 0:
            return None
        if await self.repo.get_by_username(username) is not None:
            return None
        account = MgrAccount(
            username=username,
            role=Role.ADMINISTRATOR,
            password_hash=hash_password(password),
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
