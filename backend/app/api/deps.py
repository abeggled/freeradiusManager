"""FastAPI-Dependencies: Session, Sprache, Principal und Rollenpruefung."""

from __future__ import annotations

from collections.abc import Callable
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

login_limiter = RateLimiter(settings.login_rate_limit, settings.login_rate_window_seconds)
coa_limiter = RateLimiter(settings.coa_rate_limit, settings.coa_rate_window_seconds)

SessionDep = Annotated[AsyncSession, Depends(get_session)]


def client_ip(request: Request) -> str | None:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


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


async def current_principal(request: Request, response: Response) -> Principal:
    """Liest das Session-Cookie und verlaengert es gleitend (Idle-Timeout)."""
    token = request.cookies.get(settings.cookie_name)
    if not token:
        raise AuthenticationError(code="error.unauthenticated")
    principal = principal_from_token(token)
    request.state.principal = principal
    refreshed, _ = create_session_token(
        principal.account_id,
        principal.username,
        principal.role,
        principal.language,
        session_id=principal.session_id,
        absolute_expiry=principal.absolute_expiry,
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
