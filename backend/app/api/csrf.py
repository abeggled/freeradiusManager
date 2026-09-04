"""Herkunftspruefung fuer zustandsaendernde Anfragen.

``SameSite=Lax`` schuetzt nicht gegen einen anderen Host derselben
registrierbaren Domain: fuer den Browser ist der "same-site" und das
Sitzungscookie ginge mit. Deshalb wird bei schreibenden Methoden geprueft, dass
``Origin`` (ersatzweise ``Referer``) zur eigenen Adresse passt.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from urllib.parse import urlsplit

from fastapi import Request, Response
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.core.i18n import normalise_language, translate

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})


OPAQUE_ORIGIN = "null"
"""Was ein Browser aus einem Sandbox-Kontext sendet.

Es ist eine ausdrueckliche Herkunftsangabe und keine fehlende: als fehlend
behandelt liefe die Anfrage in den Zweig fuer Nicht-Browser (curl) und waere
erlaubt - obwohl das Sitzungscookie mitgeht (``SameSite=Lax``)."""


def _origin_of(request: Request) -> str | None:
    origin = request.headers.get("origin")
    if origin and origin.lower() == OPAQUE_ORIGIN:
        return OPAQUE_ORIGIN
    if origin:
        return origin.rstrip("/")
    referer = request.headers.get("referer")
    if referer:
        parts = urlsplit(referer)
        if parts.scheme and parts.netloc:
            return f"{parts.scheme}://{parts.netloc}"
    return None


def _expected(request: Request) -> set[str]:
    allowed = {origin.rstrip("/") for origin in settings.allowed_origins}
    allowed.update(origin.rstrip("/") for origin in settings.cors_origins)
    host = request.headers.get("host")
    if host:
        # Hinter einem TLS-Proxy meldet der Client https, der Request selbst http.
        forwarded = request.headers.get("x-forwarded-proto", request.url.scheme)
        allowed.add(f"{forwarded}://{host}")
        allowed.add(f"{request.url.scheme}://{host}")
    return allowed


async def add_security_headers(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    """Verhindert das Einbetten der Oberflaeche in fremde Seiten.

    Ohne diesen Kopf koennte eine Seite derselben registrierbaren Domain den
    Manager in einen Rahmen laden; das Sitzungscookie ginge mit (``SameSite=Lax``)
    und ein Klick darin stammte aus Sicht der Herkunftspruefung vom Manager
    selbst - Loeschungen liessen sich so unterschieben (Clickjacking).
    """
    response = await call_next(request)
    response.headers.setdefault("Content-Security-Policy", "frame-ancestors 'none'")
    # Fuer Browser ohne CSP-Unterstuetzung.
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    return response


async def enforce_same_origin(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    """Weist schreibende Anfragen fremder Herkunft ab."""
    if request.method in SAFE_METHODS:
        return await call_next(request)

    origin = _origin_of(request)
    # Ohne Origin/Referer stammt die Anfrage nicht aus einem Browserformular
    # (etwa curl oder ein Skript); dort schuetzt bereits das Cookie.
    if origin is not None and origin not in _expected(request):
        language = normalise_language(
            request.query_params.get("lang")
            or request.cookies.get("frm_lang")
            or request.headers.get("accept-language")
        )
        return JSONResponse(
            status_code=403,
            content={
                "code": "error.cross_origin",
                "message": translate("error.cross_origin", language),
                "details": {"origin": origin},
            },
        )
    return await call_next(request)
