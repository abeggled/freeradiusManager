"""Manager-Konten (FR-10), Einstellungen und Statistik-Snapshot (NFR-2)."""

from __future__ import annotations

import datetime as dt

import pyotp
import pytest

from app.core.config import settings as app_settings
from app.core.crypto import SecretBox
from app.core.errors import (
    AuthenticationError,
    ConflictError,
    PermissionDeniedError,
    ValidationError,
)
from app.models.mgr import Role
from app.models.radius import RadAcct, RadPostAuth
from app.schemas.accounts import AccountCreate, AccountUpdate, PasswordChange
from app.schemas.users import UserCreate
from app.services.accounts import LOCKOUT_THRESHOLD, AccountService
from app.services.settings_service import (
    KEY_DEFAULT_CREDENTIAL,
    KEY_MAC_FORMAT,
    SettingsService,
)
from app.services.stats import StatsService
from app.services.users import UserService

pytestmark = pytest.mark.asyncio


async def _admin(session, admin_principal, username: str = "admin"):
    return await AccountService(session).create(
        AccountCreate(username=username, password="ein-sicheres-passwort", role=Role.ADMINISTRATOR),
        actor=admin_principal,
    )


async def test_authenticate_success_and_failure(session, admin_principal) -> None:
    service = AccountService(session)
    await _admin(session, admin_principal)

    account = await service.authenticate("admin", "ein-sicheres-passwort")
    assert account.failed_logins == 0

    with pytest.raises(AuthenticationError) as excinfo:
        await service.authenticate("admin", "falsch")
    assert excinfo.value.code == "error.invalid_credentials"


async def test_account_is_locked_after_repeated_failures(session, admin_principal) -> None:
    service = AccountService(session)
    await _admin(session, admin_principal)
    for _ in range(LOCKOUT_THRESHOLD):
        with pytest.raises(AuthenticationError):
            await service.authenticate("admin", "falsch")

    with pytest.raises(AuthenticationError) as excinfo:
        await service.authenticate("admin", "ein-sicheres-passwort")
    assert excinfo.value.code == "error.account_locked"


async def test_duplicate_account_rejected(session, admin_principal) -> None:
    await _admin(session, admin_principal)
    with pytest.raises(ConflictError):
        await _admin(session, admin_principal)


async def test_last_administrator_cannot_be_demoted(session, admin_principal) -> None:
    service = AccountService(session)
    created = await _admin(session, admin_principal)
    with pytest.raises(ValidationError) as excinfo:
        await service.update(created.id, AccountUpdate(role=Role.AUDITOR), actor=admin_principal)
    assert excinfo.value.code == "error.last_administrator"


async def test_second_administrator_can_be_demoted(session, admin_principal) -> None:
    service = AccountService(session)
    await _admin(session, admin_principal, "admin1")
    second = await _admin(session, admin_principal, "admin2")
    updated = await service.update(
        second.id, AccountUpdate(role=Role.OPERATOR), actor=admin_principal
    )
    assert updated.role is Role.OPERATOR


async def test_cannot_delete_own_account(session, admin_principal) -> None:
    service = AccountService(session)
    created = await _admin(session, admin_principal)
    actor = admin_principal.__class__(
        account_id=created.id,
        username=created.username,
        role=Role.ADMINISTRATOR,
        language="de",
        session_id="x",
        absolute_expiry=0,
    )
    with pytest.raises(ValidationError) as excinfo:
        await service.delete(created.id, actor=actor)
    assert excinfo.value.code == "error.self_delete"


async def test_totp_enrollment_and_verification(session, admin_principal) -> None:
    service = AccountService(session)
    created = await _admin(session, admin_principal)
    account = await service.get(created.id)

    assert service.requires_totp_enrollment(account) is True
    setup = await service.start_totp_enrollment(account)
    assert setup.provisioning_uri.startswith("otpauth://totp/")

    with pytest.raises(AuthenticationError):
        await service.confirm_totp(account, "000000")

    await service.confirm_totp(account, pyotp.TOTP(setup.secret).now())
    assert account.totp_enabled is True
    assert service.requires_totp(account) is True

    stored = SecretBox(app_settings.coa_secret_key or app_settings.secret_key).decrypt(
        account.totp_secret_enc
    )
    assert stored == setup.secret


async def test_password_change_requires_current_password(session, admin_principal) -> None:
    service = AccountService(session)
    created = await _admin(session, admin_principal)
    actor = admin_principal.__class__(
        account_id=created.id,
        username=created.username,
        role=Role.ADMINISTRATOR,
        language="de",
        session_id="x",
        absolute_expiry=0,
    )
    with pytest.raises(AuthenticationError):
        await service.change_password(
            created.id,
            PasswordChange(current_password="falsch", new_password="neues-sicheres-pw"),
            actor=actor,
        )
    await service.change_password(
        created.id,
        PasswordChange(current_password="ein-sicheres-passwort", new_password="neues-sicheres-pw"),
        actor=actor,
    )
    assert await service.authenticate(created.username, "neues-sicheres-pw")


async def test_operator_cannot_change_foreign_password(
    session, admin_principal, operator_principal
) -> None:
    service = AccountService(session)
    created = await _admin(session, admin_principal)
    with pytest.raises(PermissionDeniedError):
        await service.change_password(
            created.id,
            PasswordChange(current_password="x", new_password="neues-sicheres-pw"),
            actor=operator_principal,
        )


async def test_bootstrap_admin_only_once(session) -> None:
    service = AccountService(session)
    first = await service.ensure_bootstrap_admin("admin", "ein-sicheres-passwort")
    assert first is not None and first.role is Role.ADMINISTRATOR
    assert await service.ensure_bootstrap_admin("admin2", "ein-sicheres-passwort") is None


async def test_settings_roundtrip_and_validation(session) -> None:
    service = SettingsService(session)
    defaults = await service.all()
    assert KEY_MAC_FORMAT in defaults

    await service.update({KEY_MAC_FORMAT: "hyphen_upper"}, updated_by="admin")
    await session.commit()
    assert await service.mac_format() == "hyphen_upper"

    await service.update({KEY_DEFAULT_CREDENTIAL: "nt"})
    await session.commit()
    assert (await service.default_credential_type()).value == "nt"

    with pytest.raises(ValidationError):
        await service.update({KEY_MAC_FORMAT: "gibtsnicht"})
    with pytest.raises(ValidationError):
        await service.update({"unbekannt": 1})


async def test_stats_snapshot_is_computed_and_read(session, admin_principal) -> None:
    await UserService(session).create(
        UserCreate(username="anna", password="geheim123"), actor=admin_principal
    )
    now = dt.datetime.now()
    session.add(
        RadAcct(
            acctsessionid="s1",
            acctuniqueid="u1",
            username="anna",
            nasipaddress="10.0.0.1",
            acctstarttime=now,
            acctinputoctets=100,
            acctoutputoctets=200,
        )
    )
    session.add(RadPostAuth(username="anna", pass_="", reply="Access-Accept", authdate=now))
    session.add(RadPostAuth(username="mallory", pass_="", reply="Access-Reject", authdate=now))
    await session.commit()

    service = StatsService(session)
    await service.refresh()
    stats = await service.read(max_age_seconds=3600)

    assert stats.stale is False
    assert stats.active_sessions == 1
    assert stats.sessions_started == 1
    # Als Zeichenkette ausgeliefert (BIGINT, JavaScript-Genauigkeit).
    assert stats.input_octets == "100"
    assert stats.accepts == 1
    assert stats.rejects == 1
    assert stats.users_total == 1
    assert {entry["username"] for entry in stats.top_rejected} == {"mallory"}


async def test_stats_without_snapshot_is_stale(session) -> None:
    stats = await StatsService(session).read(max_age_seconds=60)
    assert stats.stale is True
    assert stats.active_sessions == 0
