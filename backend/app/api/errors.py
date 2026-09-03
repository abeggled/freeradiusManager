"""Zentrale Fehlerbehandlung: einheitliches ``{code, message, details}``."""

from __future__ import annotations

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.errors import AppError
from app.core.i18n import normalise_language, translate
from app.core.logging import get_logger

log = get_logger("api")


def _language(request: Request) -> str:
    """Wie die ``language``-Dependency: die ausdrueckliche Wahl gilt zuerst.

    Sonst kaeme die Fehlermeldung in der Kontosprache, waehrend die Oberflaeche
    ringsum in der umgeschalteten Sprache steht.
    """
    explicit = request.query_params.get("lang") or request.cookies.get("frm_lang")
    if explicit:
        return normalise_language(explicit)
    principal = getattr(request.state, "principal", None)
    if principal is not None:
        return normalise_language(principal.language)
    return normalise_language(request.headers.get("accept-language"))


def _payload(code: str, message: str, details: dict[str, object]) -> dict[str, object]:
    return {"code": code, "message": message, "details": details}


# Auch Fehler aus dem Routing (404, 405 …) folgen der Struktur aus Abschnitt 6.3.
_STATUS_CODES = {
    401: "error.unauthenticated",
    403: "error.forbidden",
    404: "error.not_found",
    409: "error.conflict",
    429: "error.rate_limited",
}


def register_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def _app_error(request: Request, exc: AppError) -> JSONResponse:
        language = _language(request)
        return JSONResponse(
            status_code=exc.status_code,
            content=_payload(exc.code, translate(exc.code, language), exc.details),
        )

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        language = _language(request)
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=_payload(
                "error.validation",
                translate("error.validation", language),
                {
                    "fields": [
                        {"loc": list(err.get("loc", [])), "msg": err.get("msg", "")}
                        for err in exc.errors()
                    ]
                },
            ),
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        language = _language(request)
        code = _STATUS_CODES.get(exc.status_code, "error.generic")
        details: dict[str, object] = {}
        if exc.status_code not in _STATUS_CODES and exc.detail:
            details["detail"] = str(exc.detail)
        return JSONResponse(
            status_code=exc.status_code,
            content=_payload(code, translate(code, language), details),
            headers=getattr(exc, "headers", None),
        )

    @app.exception_handler(IntegrityError)
    async def _integrity(request: Request, exc: IntegrityError) -> JSONResponse:
        language = _language(request)
        log.warning("integrity_error", error=str(exc.orig))
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content=_payload("error.conflict", translate("error.conflict", language), {}),
        )

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        language = _language(request)
        log.error("unhandled_error", path=request.url.path, error=str(exc), exc_info=exc)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=_payload("error.generic", translate("error.generic", language), {}),
        )
