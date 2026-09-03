"""Konsistente Fehlerstruktur ``{code, message, details}`` (Abschnitt 6.3).

``code`` ist ein stabiler, uebersetzbarer Schluessel; ``message`` die bereits in der
Sprache des Requests aufgeloeste Fassung.
"""

from __future__ import annotations

from typing import Any


class AppError(Exception):
    """Basisklasse aller fachlichen Fehler."""

    status_code: int = 400
    code: str = "error.generic"

    def __init__(
        self,
        message: str | None = None,
        *,
        code: str | None = None,
        details: dict[str, Any] | None = None,
        status_code: int | None = None,
    ) -> None:
        if code is not None:
            self.code = code
        if status_code is not None:
            self.status_code = status_code
        self.details = details or {}
        super().__init__(message or self.code)

    @property
    def message_key(self) -> str:
        return self.code


class NotFoundError(AppError):
    status_code = 404
    code = "error.not_found"


class ConflictError(AppError):
    status_code = 409
    code = "error.conflict"


class ValidationError(AppError):
    status_code = 422
    code = "error.validation"


class AuthenticationError(AppError):
    status_code = 401
    code = "error.unauthenticated"


class TotpRequiredError(AuthenticationError):
    code = "error.totp_required"


class ReauthenticationRequiredError(AuthenticationError):
    """Rollen- oder 2FA-Zustand hat sich geaendert; die Sitzung endet."""

    code = "error.reauthentication_required"


class PermissionDeniedError(AppError):
    status_code = 403
    code = "error.forbidden"


class RateLimitError(AppError):
    status_code = 429
    code = "error.rate_limited"


class SchemaError(AppError):
    status_code = 503
    code = "error.radius_schema"


class CoAError(AppError):
    status_code = 502
    code = "error.coa_failed"
