"""Anmeldung am Manager (FR-10): lokale Konten mit TOTP, optional OIDC."""

from __future__ import annotations

import secrets

from fastapi import APIRouter, Request, Response, status
from fastapi.responses import RedirectResponse

from app.api.deps import (
    ClientIp,
    CurrentUser,
    SessionDep,
    clear_session_cookie,
    login_ip_limiter,
    login_limiter,
    set_session_cookie,
)
from app.core.config import settings
from app.core.crypto import hash_password
from app.core.errors import AuthenticationError, ValidationError
from app.core.security import TOTP_ENROLL_SCOPE, create_session_token
from app.models.mgr import MgrAccount, Role
from app.schemas.accounts import (
    AccountOut,
    LoginRequest,
    LoginResponse,
    TotpActivate,
    TotpEnrollRequest,
    TotpLoginRequest,
    TotpSetupResponse,
)
from app.services.accounts import AccountService
from app.services.oidc import OidcService

router = APIRouter(prefix="/auth", tags=["auth"])

OIDC_STATE_COOKIE = "frm_oidc"


def _bounded(value: object, limit: int) -> str | None:
    """Kuerzt einen Claim auf die Spaltenbreite."""
    if not isinstance(value, str) or not value.strip():
        return None
    return value.strip()[:limit]


def _issue_session(
    response: Response, account: MgrAccount, *, mfa: bool = False, oidc: bool = False
) -> None:
    token, _ = create_session_token(
        account.id, account.username, account.role, account.language, mfa=mfa, oidc=oidc
    )
    set_session_cookie(response, token)


@router.post("/login", response_model=LoginResponse)
async def login(
    payload: LoginRequest,
    response: Response,
    session: SessionDep,
    actor_ip: ClientIp,
) -> LoginResponse:
    # Zwei Grenzen: je Konto und - unabhaengig vom genannten Namen - je Absender.
    # Sonst genuegte ein neuer Benutzername je Versuch, um das Limit zu umgehen.
    login_ip_limiter.check(str(actor_ip))
    login_limiter.check(f"{actor_ip}:{payload.username}")
    service = AccountService(session)
    mfa_completed = False
    account = await service.authenticate(
        payload.username, payload.password, actor_ip=actor_ip, reset_failures=False
    )

    if service.requires_totp(account):
        if not payload.totp_code:
            # Der Zaehler bleibt stehen: eine neue Challenge anzufordern darf die
            # bisherigen Fehlversuche am zweiten Faktor nicht loeschen, sonst
            # waere die Kontosperre durch wiederholtes Neuanfordern umgehbar.
            return LoginResponse(status="totp_required", challenge=service.challenge_for(account))
        await service.verify_totp_code(account, payload.totp_code, actor_ip=actor_ip)
        mfa_completed = True
    elif service.requires_totp_enrollment(account):
        # Eigener Scope: dieses Token darf ausschliesslich die Ersteinrichtung
        # freischalten, nie einen bereits aktiven Faktor ersetzen.
        return LoginResponse(
            status="totp_setup_required", challenge=service.enrollment_challenge_for(account)
        )

    await service.clear_failures(account)
    await service.mark_login(account, actor_ip)
    # Nur das Kontingent des eigenen Kontos wird freigegeben. Das IP-weite
    # Kontingent bleibt bestehen: sonst genuegte eine eigene gueltige Kennung,
    # um nach jedem Erfolg wieder beliebig viele fremde Namen zu probieren.
    login_limiter.reset(f"{actor_ip}:{payload.username}")
    _issue_session(response, account, mfa=mfa_completed)
    return LoginResponse(status="authenticated", account=AccountOut.model_validate(account))


@router.post("/login/totp", response_model=LoginResponse)
async def login_totp(
    payload: TotpLoginRequest,
    response: Response,
    session: SessionDep,
    actor_ip: ClientIp,
) -> LoginResponse:
    service = AccountService(session)
    account = await service.account_from_challenge(payload.challenge)
    # Je Konto begrenzen statt je IP: hinter einem NAT teilen sich sonst alle
    # Benutzer dasselbe Kontingent und sperren sich gegenseitig aus.
    login_limiter.check(f"totp:{account.id}")
    login_ip_limiter.check(str(actor_ip))
    await service.verify_totp_code(account, payload.totp_code, actor_ip=actor_ip)
    login_limiter.reset(f"totp:{account.id}")
    await service.clear_failures(account)
    await service.mark_login(account, actor_ip)
    _issue_session(response, account, mfa=True)
    return LoginResponse(status="authenticated", account=AccountOut.model_validate(account))


@router.post("/totp/enroll", response_model=TotpSetupResponse)
async def enroll_totp(payload: TotpEnrollRequest, session: SessionDep) -> TotpSetupResponse:
    """Startet die TOTP-Einrichtung im Rahmen einer Anmeldung mit Pflicht-2FA.

    Die Challenge kommt bewusst im Rumpf: als Query-Parameter stuende dieses
    kurzlebige Zugangsmerkmal in jedem Zugriffsprotokoll.
    """
    if not payload.challenge:
        raise ValidationError(code="error.validation", details={"field": "challenge"})
    service = AccountService(session)
    account = await service.account_from_challenge(payload.challenge, scope=TOTP_ENROLL_SCOPE)
    return await service.start_totp_enrollment(account)


@router.post("/totp/confirm", response_model=LoginResponse)
async def confirm_totp(
    payload: TotpLoginRequest,
    response: Response,
    session: SessionDep,
    actor_ip: ClientIp,
) -> LoginResponse:
    service = AccountService(session)
    account = await service.account_from_challenge(payload.challenge, scope=TOTP_ENROLL_SCOPE)
    await service.confirm_totp(account, payload.totp_code, actor_ip=actor_ip)
    # Auch der Einrichtungsweg ist eine vollstaendige Anmeldung: der
    # zurueckgehaltene Fehlerzaehler wird jetzt geleert.
    await service.clear_failures(account)
    await service.mark_login(account, actor_ip)
    _issue_session(response, account, mfa=True)
    return LoginResponse(status="authenticated", account=AccountOut.model_validate(account))


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(response: Response) -> None:
    clear_session_cookie(response)


@router.get("/me", response_model=AccountOut)
async def me(principal: CurrentUser, session: SessionDep) -> AccountOut:
    account = await AccountService(session).get(principal.account_id)
    return AccountOut.model_validate(account)


# --- Eigenes Konto: TOTP nachtraeglich einrichten -------------------------


@router.post("/me/totp/enroll", response_model=TotpSetupResponse)
async def enroll_own_totp(principal: CurrentUser, session: SessionDep) -> TotpSetupResponse:
    service = AccountService(session)
    account = await service.get(principal.account_id)
    return await service.start_totp_enrollment(account)


@router.post("/me/totp/confirm", status_code=status.HTTP_204_NO_CONTENT)
async def confirm_own_totp(
    payload: TotpActivate, principal: CurrentUser, session: SessionDep, actor_ip: ClientIp
) -> None:
    service = AccountService(session)
    account = await service.get(principal.account_id)
    await service.confirm_totp(account, payload.code, actor_ip=actor_ip)


# --- OIDC ----------------------------------------------------------------


@router.get("/oidc/login")
async def oidc_login() -> RedirectResponse:
    if not settings.oidc_enabled:
        raise AuthenticationError(code="error.forbidden")
    start = await OidcService().start()
    redirect = RedirectResponse(url=start.url, status_code=status.HTTP_307_TEMPORARY_REDIRECT)
    redirect.set_cookie(
        OIDC_STATE_COOKIE,
        f"{start.state}|{start.code_verifier}|{start.nonce}",
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        max_age=600,
        path="/",
    )
    return redirect


@router.get("/oidc/callback")
async def oidc_callback(
    request: Request, session: SessionDep, actor_ip: ClientIp, code: str = "", state: str = ""
) -> RedirectResponse:
    if not settings.oidc_enabled:
        raise AuthenticationError(code="error.forbidden")
    raw = request.cookies.get(OIDC_STATE_COOKIE, "")
    parts = raw.split("|")
    if len(parts) != 3 or not secrets.compare_digest(parts[0], state) or not code:
        raise AuthenticationError(code="error.unauthenticated", details={"stage": "state"})
    _, verifier, nonce = parts

    oidc = OidcService()
    claims = await oidc.exchange(code, verifier, nonce)
    mapped = oidc.map_role(claims)
    if mapped is None:
        raise AuthenticationError(code="error.forbidden", details={"stage": "role_mapping"})

    service = AccountService(session)
    raw_subject = claims.get("sub")
    if not isinstance(raw_subject, str) or not raw_subject.strip():
        # Ohne stabiles "sub" landeten alle solchen Token auf demselben Konto.
        raise AuthenticationError(code="error.unauthenticated", details={"stage": "subject"})
    subject = raw_subject.strip()
    account = await service.repo.get_by_oidc_subject(subject)
    if account is None:
        username = str(claims.get("preferred_username") or claims.get("email") or subject)
        if len(username) > 64:
            # mgr_account.username fasst 64 Zeichen; ein laengerer Wert waere
            # ein Datenbankfehler statt einer klaren Meldung.
            raise AuthenticationError(
                code="error.unauthenticated", details={"stage": "username_too_long"}
            )
        existing = await service.repo.get_by_username(username)
        if existing is not None:
            # Ein vorhandenes lokales Konto wird nicht stillschweigend an eine
            # OIDC-Identitaet gebunden: sonst koennte eine fremd verwaltete
            # Kennung namens "admin" das Bootstrap-Konto uebernehmen und dabei
            # gleich herabstufen. Die Verknuepfung erfolgt bewusst durch einen
            # Administrator.
            raise AuthenticationError(
                code="error.oidc_account_conflict", details={"username": username}
            )
        # Claims koennen laenger sein als die Spalten; gekuerzt statt mit einem
        # Datenbankfehler abgebrochen.
        account = MgrAccount(
            username=username,
            email=_bounded(claims.get("email"), 255),
            display_name=_bounded(claims.get("name"), 128),
            role=Role(mapped),
            oidc_subject=subject,
            password_hash=hash_password(secrets.token_urlsafe(32)),
        )
        await service.repo.add(account)
        # Auch die automatische Anlage ist eine schreibende Aktion (FR-9).
        await service.audit.log(
            action="account.create",
            object_type="account",
            object_id=account.username,
            actor_ip=actor_ip,
            after={
                "role": account.role.value,
                "source": "oidc",
                "oidc_subject": subject,
                "email": account.email,
            },
        )
    if not account.is_active:
        # Ein deaktiviertes Konto darf sich auch ueber OIDC nicht neu anmelden.
        raise AuthenticationError(code="error.account_disabled")
    await service.apply_mapped_role(account, Role(mapped), actor_ip=actor_ip)
    await service.mark_login(account, actor_ip)

    redirect = RedirectResponse(
        url=settings.root_path or "/", status_code=status.HTTP_303_SEE_OTHER
    )
    # Der Identity-Provider hat die Anmeldung vollstaendig durchgefuehrt; die
    # lokale TOTP-Pflicht gilt fuer diese Sitzung nicht.
    _issue_session(redirect, account, mfa=True, oidc=True)
    redirect.delete_cookie(OIDC_STATE_COOKIE, path="/")
    return redirect


@router.get("/oidc/status")
async def oidc_status() -> dict[str, object]:
    return {"enabled": settings.oidc_enabled, "issuer": settings.oidc_issuer or None}
