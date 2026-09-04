"""FastAPI-Dependencies: Session, Sprache, Principal und Rollenpruefung."""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
from datetime import UTC
from functools import lru_cache
from typing import Annotated

from fastapi import Depends, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.db import get_session
from app.core.errors import AuthenticationError, PermissionDeniedError
from app.core.i18n import normalise_language
from app.core.ratelimit import RateLimiter
from app.core.security import Principal, create_session_token, principal_from_token
from app.models.mgr import Role
from app.repositories.mgr.accounts import AccountRepository

login_limiter = RateLimiter(settings.login_rate_limit, settings.login_rate_window_seconds)
login_ip_limiter = RateLimiter(settings.login_ip_rate_limit, settings.login_rate_window_seconds)
coa_limiter = RateLimiter(settings.coa_rate_limit, settings.coa_rate_window_seconds)

SessionDep = Annotated[AsyncSession, Depends(get_session)]

BACKGROUND_HEADER = "x-background-refresh"
"""Vom Client gesetzt, wenn die Anfrage aus einem Hintergrundlauf stammt."""


@lru_cache
def _trusted_networks() -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    networks = []
    for entry in settings.trusted_proxies:
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            continue
    return tuple(networks)


def _is_trusted(peer: str | None) -> bool:
    if not peer or not _trusted_networks():
        return False
    try:
        address = ipaddress.ip_address(peer)
    except ValueError:
        return False
    return any(address in network for network in _trusted_networks())


def client_ip(request: Request) -> str | None:
    """Aufrufer-Adresse fuer Audit-Log und Rate-Limits.

    ``X-Forwarded-For`` wird nur ausgewertet, wenn die direkte Gegenstelle in
    ``FRM_TRUSTED_PROXIES`` steht - sonst koennte ein Aufrufer den Header
    faelschen und die Rate-Limits umgehen (NFR-1). Ohne konfigurierte Proxys
    zaehlt ausschliesslich die Peer-Adresse.
    """
    peer = request.client.host if request.client else None
    if not _is_trusted(peer):
        return peer
    forwarded = request.headers.get("x-forwarded-for")
    if not forwarded:
        return peer
    # Von rechts nach links: der erste Wert, der nicht aus einem Proxynetz
    # stammt, ist die aeusserste nicht selbst gesetzte Adresse.
    candidates = [part.strip() for part in forwarded.split(",") if part.strip()]
    for candidate in reversed(candidates):
        if not _is_trusted(candidate):
            return candidate
    return candidates[0] if candidates else peer


ClientIp = Annotated[str | None, Depends(client_ip)]


def language(request: Request) -> str:
    """Sprache aus Query, Cookie oder ``Accept-Language`` (NFR-4)."""
    explicit = request.query_params.get("lang") or request.cookies.get("frm_lang")
    if explicit:
        return normalise_language(explicit)
    principal = getattr(request.state, "principal", None)
    if principal is not None:
        return normalise_language(principal.language)
    return normalise_language(request.headers.get("accept-language"))


Language = Annotated[str, Depends(language)]


def set_session_cookie(response: Response, token: str, max_age: int | None = None) -> None:
    response.set_cookie(
        settings.cookie_name,
        token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        domain=settings.cookie_domain,
        max_age=max_age or settings.session_idle_minutes * 60,
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(settings.cookie_name, domain=settings.cookie_domain, path="/")


async def current_principal(request: Request, response: Response, session: SessionDep) -> Principal:
    """Liest das Session-Cookie und verlaengert es gleitend (Idle-Timeout).

    Rolle und Aktivstatus stammen bewusst aus der Datenbank und nicht aus dem
    Token: sonst behielte ein bereits ausgestelltes Token seine alten Rechte,
    bis die absolute Gueltigkeit ablaeuft - auch wenn das Konto zwischenzeitlich
    deaktiviert, geloescht oder herabgestuft wurde.
    """
    token = request.cookies.get(settings.cookie_name)
    if not token:
        raise AuthenticationError(code="error.unauthenticated")
    claims = principal_from_token(token)

    account = await AccountRepository(session).get(claims.account_id)
    if account is None or not account.is_active:
        raise AuthenticationError(code="error.unauthenticated")

    # Eine Rollenaenderung beendet die laufende Sitzung. Der Entzug wirkt damit
    # sofort; eine Erweiterung dagegen setzt eine neue Anmeldung voraus - sonst
    # erhielte eine nur mit Passwort begonnene Sitzung Administratorrechte
    # entgegen der 2FA-Pflicht (FR-10).
    if account.role is not claims.role:
        raise AuthenticationError(
            code="error.reauthentication_required", details={"reason": "role_changed"}
        )
    # Bei OIDC verantwortet der Identity-Provider den zweiten Faktor; die
    # lokale TOTP-Pflicht gilt fuer lokale Anmeldungen.
    if (
        account.role is Role.ADMINISTRATOR
        and settings.require_totp_for_admin
        and not claims.oidc
        and not (claims.mfa and account.totp_enabled)
    ):
        raise AuthenticationError(
            code="error.reauthentication_required", details={"reason": "mfa_required"}
        )

    # Eine Aenderung an Passwort oder zweitem Faktor verwirft aeltere Sitzungen -
    # sonst bliebe ein gestohlenes Cookie bis zur absoluten Gueltigkeit brauchbar,
    # und ein zurueckgesetztes TOTP waere nach der Neueinrichtung wieder wirkungslos.
    if claims.auth_at:
        for reason, changed in (
            ("password_changed", account.password_changed_at),
            ("totp_changed", account.totp_changed_at),
        ):
            if changed is None:
                continue
            # Beide Werte fuehren Sekundenbruchteile (``mgr_account`` als
            # DATETIME(6)): eine Aenderung in derselben Sekunde, in der die
            # Sitzung ausgestellt wurde, verwirft diese sonst nicht.
            if claims.auth_at < changed.replace(tzinfo=UTC).timestamp():
                raise AuthenticationError(
                    code="error.reauthentication_required", details={"reason": reason}
                )

    principal = Principal(
        account_id=account.id,
        username=account.username,
        role=account.role,
        language=account.language,
        session_id=claims.session_id,
        absolute_expiry=claims.absolute_expiry,
        mfa=claims.mfa,
        oidc=claims.oidc,
        auth_at=claims.auth_at,
    )
    request.state.principal = principal

    # Eine Hintergrundabfrage ist keine Benutzeraktivitaet. Wuerde sie das
    # Cookie verlaengern, liefe der Idle-Timeout nie ab, solange irgendwo ein
    # Dashboard offen steht (FR-10).
    if request.headers.get(BACKGROUND_HEADER, "").lower() not in ("1", "true"):
        refreshed, _ = create_session_token(
            principal.account_id,
            principal.username,
            principal.role,
            principal.language,
            session_id=principal.session_id,
            absolute_expiry=principal.absolute_expiry,
            mfa=principal.mfa,
            oidc=principal.oidc,
            auth_at=principal.auth_at,
        )
        set_session_cookie(response, refreshed)
    return principal


CurrentUser = Annotated[Principal, Depends(current_principal)]


def require_roles(*roles: Role) -> Callable[[Principal], Principal]:
    def dependency(principal: CurrentUser) -> Principal:
        if principal.role not in roles:
            raise PermissionDeniedError(code="error.forbidden")
        return principal

    return dependency


require_admin = require_roles(Role.ADMINISTRATOR)
require_writer = require_roles(Role.ADMINISTRATOR, Role.OPERATOR)
require_reader = require_roles(Role.ADMINISTRATOR, Role.OPERATOR, Role.AUDITOR)

AdminUser = Annotated[Principal, Depends(require_admin)]
WriterUser = Annotated[Principal, Depends(require_writer)]
ReaderUser = Annotated[Principal, Depends(require_reader)]
