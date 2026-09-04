"""Anmeldung am Manager (FR-10): lokale Konten mit TOTP, optional OIDC."""

from __future__ import annotations

import datetime as dt
import secrets

from fastapi import APIRouter, Request, Response, status
from fastapi.responses import RedirectResponse

from app.api.deps import (
    ClientIp,
    CurrentUser,
    SessionDep,
    clear_session_cookie,
    cookie_path,
    login_ip_limiter,
    login_limiter,
    set_session_cookie,
)
from app.core.config import settings
from app.core.errors import AuthenticationError, ValidationError
from app.core.identifiers import fold
from app.core.security import TOTP_ENROLL_SCOPE, create_session_token, principal_from_token
from app.models.mgr import MgrAccount, Role
from app.repositories.mgr.session_revocations import SessionRevocationRepository
from app.schemas.accounts import (
    AccountOut,
    LoginRequest,
    LoginResponse,
    TotpActivate,
    TotpEnrollRequest,
    TotpEnrollSelf,
    TotpLoginRequest,
    TotpSetupResponse,
)
from app.services.accounts import AccountService
from app.services.oidc import OidcService, provider_confirmed_mfa

router = APIRouter(prefix="/auth", tags=["auth"])

OIDC_STATE_COOKIE = "frm_oidc"


def _bounded(value: object, limit: int) -> str | None:
    """Kuerzt einen Claim auf die Spaltenbreite."""
    if not isinstance(value, str) or not value.strip():
        return None
    return value.strip()[:limit]


def _issue_session(
    response: Response,
    account: MgrAccount,
    *,
    mfa: bool = False,
    oidc: bool = False,
    verified_at: float | None = None,
) -> None:
    """Stellt das Sitzungscookie aus.

    ``verified_at`` ist der Zeitpunkt *vor* der Pruefung der Anmeldedaten. Aus
    der Ausstellungszeit abgeleitet erschiene das Token neuer als eine
    Passwortaenderung, die dazwischen liegt - die Sitzung waere mit dem alten,
    inzwischen entwerteten Passwort zustande gekommen und bliebe gueltig.
    """
    token, _ = create_session_token(
        account.id,
        account.username,
        account.role,
        account.language,
        mfa=mfa,
        oidc=oidc,
        epoch=account.session_epoch,
        auth_at=verified_at,
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
    # In der Vergleichsform: die Datenbank findet ``Admin`` und ``admin`` als
    # dasselbe Konto, zwei verschiedene Schluessel liessen den Zaehler
    # auseinanderlaufen.
    login_limiter.check(f"{actor_ip}:{fold(payload.username)}")
    service = AccountService(session)
    mfa_completed = False
    # Vor der Pruefung festgehalten: eine Passwortaenderung, die waehrend der
    # Anmeldung festgeschrieben wird, muss die entstehende Sitzung verwerfen.
    verified_at = dt.datetime.now(tz=dt.UTC).timestamp()
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
    login_limiter.reset(f"{actor_ip}:{fold(payload.username)}")
    _issue_session(response, account, mfa=mfa_completed, verified_at=verified_at)
    return LoginResponse(status="authenticated", account=AccountOut.model_validate(account))


@router.post("/login/totp", response_model=LoginResponse)
async def login_totp(
    payload: TotpLoginRequest,
    response: Response,
    session: SessionDep,
    actor_ip: ClientIp,
) -> LoginResponse:
    # Vor dem Dekodieren: eine ungueltige Challenge kam sonst nie bis zur
    # Zaehlung und liesse sich unbegrenzt oft durch die Signaturpruefung
    # schicken, ohne das Kontingent zu verbrauchen.
    login_ip_limiter.check(str(actor_ip))
    verified_at = dt.datetime.now(tz=dt.UTC).timestamp()
    service = AccountService(session)
    account = await service.account_from_challenge(payload.challenge)
    # Je Konto zusaetzlich begrenzen: hinter einem NAT teilen sich sonst alle
    # Benutzer dasselbe Kontingent und sperren sich gegenseitig aus.
    login_limiter.check(f"totp:{account.id}")
    await service.verify_totp_code(account, payload.totp_code, actor_ip=actor_ip)
    login_limiter.reset(f"totp:{account.id}")
    # Auch den Treffer der Passwortstufe: sonst bliebe je vollstaendig
    # erfolgreicher Anmeldung einer stehen und die elfte korrekte Anmeldung
    # innerhalb des Fensters waere abgewiesen.
    login_limiter.reset(f"{actor_ip}:{fold(account.username)}")
    await service.clear_failures(account)
    await service.mark_login(account, actor_ip)
    _issue_session(response, account, mfa=True, verified_at=verified_at)
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
    login_ip_limiter.check(str(actor_ip))
    verified_at = dt.datetime.now(tz=dt.UTC).timestamp()
    service = AccountService(session)
    account = await service.account_from_challenge(payload.challenge, scope=TOTP_ENROLL_SCOPE)
    login_limiter.check(f"totp:{account.id}")
    await service.confirm_totp(account, payload.totp_code, actor_ip=actor_ip)
    login_limiter.reset(f"totp:{account.id}")
    # Auch der Einrichtungsweg ist eine vollstaendige Anmeldung: der
    # zurueckgehaltene Fehlerzaehler wird jetzt geleert.
    await service.clear_failures(account)
    await service.mark_login(account, actor_ip)
    # Dieser Vorgang setzt selbst ``totp_changed_at``; die eigene Sitzung darf
    # daran nicht scheitern. Eine gleichzeitige Passwortaenderung faellt
    # weiterhin auf, weil ``password_changed_at`` unberuehrt bleibt.
    if account.totp_changed_at is not None:
        verified_at = max(
            verified_at, account.totp_changed_at.replace(tzinfo=dt.UTC).timestamp()
        )
    _issue_session(response, account, mfa=True, verified_at=verified_at)
    return LoginResponse(status="authenticated", account=AccountOut.model_validate(account))


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(request: Request, response: Response, session: SessionDep) -> None:
    """Meldet ab - auch serverseitig.

    Das Loeschen des Cookies erreicht nur den Browser. Eine zuvor kopierte
    Kennung liesse sich sonst bis zur absoluten Gueltigkeit weiterverwenden und
    dabei sogar verlaengern (FR-10).
    """
    token = request.cookies.get(settings.cookie_name)
    if token:
        try:
            claims = principal_from_token(token)
        except AuthenticationError:
            claims = None
        if claims is not None:
            await SessionRevocationRepository(session).revoke(
                claims.session_id,
                claims.account_id,
                dt.datetime.fromtimestamp(claims.absolute_expiry, tz=dt.UTC).replace(
                    tzinfo=None
                ),
            )
            await session.commit()
    clear_session_cookie(response)


@router.get("/me", response_model=AccountOut)
async def me(principal: CurrentUser, session: SessionDep) -> AccountOut:
    account = await AccountService(session).get(principal.account_id)
    return AccountOut.model_validate(account)


# --- Eigenes Konto: TOTP nachtraeglich einrichten -------------------------


@router.post("/me/totp/enroll", response_model=TotpSetupResponse)
async def enroll_own_totp(
    payload: TotpEnrollSelf,
    principal: CurrentUser,
    session: SessionDep,
    actor_ip: ClientIp,
) -> TotpSetupResponse:
    """Startet die Einrichtung des zweiten Faktors im eigenen Profil.

    Das Passwort wird erneut geprueft (siehe ``TotpEnrollSelf``).
    """
    login_ip_limiter.check(str(actor_ip))
    service = AccountService(session)
    account = await service.get(principal.account_id)
    await service.verify_current_password(account, payload.current_password, actor_ip=actor_ip)
    return await service.start_totp_enrollment(account, actor=principal, actor_ip=actor_ip)


@router.post("/me/totp/confirm", status_code=status.HTTP_204_NO_CONTENT)
async def confirm_own_totp(
    payload: TotpActivate, principal: CurrentUser, session: SessionDep, actor_ip: ClientIp
) -> None:
    """Schliesst die Einrichtung im eigenen Profil ab.

    Begrenzt wie der Anmeldeweg: mit einer gestohlenen Sitzung liesse sich ein
    begonnener Faktor sonst unbegrenzt oft erraten (FR-10).
    """
    login_ip_limiter.check(str(actor_ip))
    login_limiter.check(f"totp:{principal.account_id}")
    service = AccountService(session)
    account = await service.get(principal.account_id)
    await service.confirm_totp(account, payload.code, actor_ip=actor_ip, actor=principal)
    login_limiter.reset(f"totp:{principal.account_id}")


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
        path=cookie_path(),
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
    # Der Wert bleibt unveraendert: OIDC-Subjects sind undurchsichtige,
    # fallunterscheidende Schluessel. Wuerde man sie trimmen, erhielte " alice"
    # die Sitzung von "alice".
    if raw_subject != raw_subject.strip():
        raise AuthenticationError(
            code="error.unauthenticated", details={"stage": "subject_whitespace"}
        )
    subject = raw_subject
    if len(subject) > 255:
        # mgr_account.oidc_subject fasst 255 Zeichen; gekuerzt waere die
        # Identitaet nicht mehr eindeutig, deshalb wird abgewiesen.
        raise AuthenticationError(
            code="error.unauthenticated", details={"stage": "subject_too_long"}
        )
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
            # Kein lokales Passwort: ein zufaelliger, niemandem bekannter Hash
            # sieht aus wie ein Zugang, ist aber keiner. Ohne Passwort ist der
            # Zustand sichtbar - und das Loesen der Verknuepfung wird abgewiesen,
            # solange kein Administrator eines gesetzt hat.
            password_hash=None,
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

    # Eine OIDC-Sitzung gilt als mehrstufig und ist damit von der lokalen
    # TOTP-Pflicht ausgenommen. Das darf nur gelten, wenn das Token einen
    # zweiten Faktor belegt - sonst umginge ein Provider mit reiner
    # Passwortanmeldung die Pflicht fuer Administratoren (FR-10).
    provider_mfa = provider_confirmed_mfa(claims)
    if (
        Role(mapped) is Role.ADMINISTRATOR
        and settings.require_totp_for_admin
        and not provider_mfa
    ):
        raise AuthenticationError(
            code="error.reauthentication_required", details={"stage": "mfa_required"}
        )
    await service.apply_mapped_role(account, Role(mapped), actor_ip=actor_ip)
    await service.mark_login(account, actor_ip)

    redirect = RedirectResponse(
        url=settings.root_path or "/", status_code=status.HTTP_303_SEE_OTHER
    )
    # Der Identity-Provider hat die Anmeldung vollstaendig durchgefuehrt; die
    # lokale TOTP-Pflicht gilt fuer diese Sitzung nicht.
    # ``oidc`` bleibt wahr - die Sitzung kam ueber den Provider. Ob sie als
    # mehrstufig gilt, sagt ``mfa``.
    _issue_session(redirect, account, mfa=provider_mfa, oidc=True)
    redirect.delete_cookie(OIDC_STATE_COOKIE, path=cookie_path())
    return redirect


@router.get("/oidc/status")
async def oidc_status() -> dict[str, object]:
    return {"enabled": settings.oidc_enabled, "issuer": settings.oidc_issuer or None}
