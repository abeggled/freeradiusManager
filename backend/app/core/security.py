"""JWT im HttpOnly-Cookie, TOTP und Rollenlogik (FR-10, Abschnitt 2)."""

from __future__ import annotations

import datetime as dt
import hmac
import secrets
from dataclasses import dataclass
from typing import Any

import jwt
import pyotp

from app.core.config import Settings, settings
from app.core.errors import AuthenticationError
from app.models.mgr import Role

ISSUER = "freeradiusManager"


@dataclass(frozen=True)
class Principal:
    """Der authentifizierte Manager-Benutzer eines Requests."""

    account_id: int
    username: str
    role: Role
    language: str
    session_id: str
    absolute_expiry: int
    mfa: bool = False
    """Ob diese Sitzung mit zweitem Faktor begonnen wurde."""
    oidc: bool = False
    """Ob die Anmeldung ueber den Identity-Provider lief."""
    epoch: int = 0
    """Sitzungsgeneration des Kontos zum Zeitpunkt der Anmeldung."""
    auth_at: float = 0.0
    """Zeitpunkt der Anmeldung; bleibt ueber die gleitende Verlaengerung stabil.

    Mit Sekundenbruchteilen: eine Passwortaenderung in derselben Sekunde, in der
    die Sitzung ausgestellt wurde, muss diese verwerfen koennen."""

    def has_role(self, *roles: Role) -> bool:
        return self.role in roles

    @property
    def is_admin(self) -> bool:
        return self.role is Role.ADMINISTRATOR

    @property
    def can_write(self) -> bool:
        return self.role in (Role.ADMINISTRATOR, Role.OPERATOR)


def _now() -> dt.datetime:
    return dt.datetime.now(tz=dt.UTC)


def create_session_token(
    account_id: int,
    username: str,
    role: Role,
    language: str,
    *,
    config: Settings | None = None,
    session_id: str | None = None,
    absolute_expiry: int | None = None,
    mfa: bool = False,
    oidc: bool = False,
    auth_at: float | None = None,
    epoch: int = 0,
) -> tuple[str, int]:
    """Erzeugt das Session-JWT. Rueckgabe: (Token, Ablauf als Unix-Zeit)."""
    config = config or settings
    now = _now()
    idle_exp = now + dt.timedelta(minutes=config.session_idle_minutes)
    absolute = absolute_expiry or int(
        (now + dt.timedelta(hours=config.session_absolute_hours)).timestamp()
    )
    idle_ts = min(int(idle_exp.timestamp()), absolute)
    payload: dict[str, Any] = {
        "iss": ISSUER,
        "sub": str(account_id),
        "name": username,
        "role": role.value,
        "lang": language,
        "sid": session_id or secrets.token_urlsafe(16),
        "mfa": mfa,
        "oidc": oidc,
        # Bleibt ueber alle Verlaengerungen erhalten: nur so laesst sich eine
        # Sitzung nach einer Passwortaenderung zuverlaessig verwerfen.
        "auth_at": auth_at if auth_at is not None else now.timestamp(),
        "gen": epoch,
        "abs": absolute,
        "scope": "session",
        "iat": int(now.timestamp()),
        "exp": idle_ts,
    }
    token = jwt.encode(payload, config.secret_key, algorithm=config.jwt_algorithm)
    return token, idle_ts


TOTP_SCOPE = "totp"
TOTP_ENROLL_SCOPE = "totp_enroll"


def create_totp_challenge_token(
    account_id: int,
    *,
    scope: str = TOTP_SCOPE,
    config: Settings | None = None,
    minutes: int = 5,
    epoch: int = 0,
) -> str:
    """Kurzlebiges Token zwischen Passwort- und TOTP-Schritt.

    Die Ersteinrichtung nutzt einen eigenen Scope: ein Challenge-Token aus einer
    normalen Anmeldung darf niemals eine bereits eingerichtete zweite Stufe
    ersetzen koennen (FR-10).
    """
    config = config or settings
    now = _now()
    payload = {
        "iss": ISSUER,
        "sub": str(account_id),
        "scope": scope,
        "iat": int(now.timestamp()),
        # ``iat`` muss laut JWT eine ganze Sekunde sein; fuer den Vergleich mit
        # ``password_changed_at`` (DATETIME(6)) braucht es die Bruchteile, sonst
        # gilt eine Challenge aus derselben Sekunde weiterhin als aktuell.
        "auth_at": now.timestamp(),
        # Wie beim Sitzungstoken: eine Deaktivierung soll auch die schon
        # ausgestellte Challenge entwerten, nicht nur die fertige Sitzung.
        "gen": epoch,
        "exp": int((now + dt.timedelta(minutes=minutes)).timestamp()),
    }
    return jwt.encode(payload, config.secret_key, algorithm=config.jwt_algorithm)


def decode_token(token: str, *, scope: str, config: Settings | None = None) -> dict[str, Any]:
    config = config or settings
    try:
        payload = jwt.decode(
            token, config.secret_key, algorithms=[config.jwt_algorithm], issuer=ISSUER
        )
    except jwt.PyJWTError as exc:
        raise AuthenticationError(code="error.unauthenticated") from exc
    if payload.get("scope") != scope:
        raise AuthenticationError(code="error.unauthenticated")
    return payload


def principal_from_token(token: str, *, config: Settings | None = None) -> Principal:
    payload = decode_token(token, scope="session", config=config)
    absolute = int(payload.get("abs", 0))
    if absolute and absolute < int(_now().timestamp()):
        raise AuthenticationError(code="error.unauthenticated")
    try:
        role = Role(payload["role"])
    except (KeyError, ValueError) as exc:
        raise AuthenticationError(code="error.unauthenticated") from exc
    return Principal(
        account_id=int(payload["sub"]),
        username=str(payload.get("name", "")),
        role=role,
        language=str(payload.get("lang", "de")),
        session_id=str(payload.get("sid", "")),
        absolute_expiry=absolute,
        mfa=bool(payload.get("mfa", False)),
        oidc=bool(payload.get("oidc", False)),
        # Aeltere Token fuehren hier eine ganze Sekunde.
        auth_at=float(payload.get("auth_at", 0)),
        epoch=int(payload.get("gen", 0)),
    )


# --------------------------------------------------------------------------
# TOTP
# --------------------------------------------------------------------------


def generate_totp_secret() -> str:
    return pyotp.random_base32()


def totp_provisioning_uri(secret: str, username: str, issuer: str = ISSUER) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)


def verify_totp(secret: str, code: str, *, valid_window: int = 1) -> int | None:
    """Prueft einen TOTP-Code und liefert das angenommene Zeitfenster.

    Der Zaehler wird zurueckgegeben, damit der Aufrufer ihn festhalten kann: ein
    abgefangener Code liesse sich sonst innerhalb des Prueffensters ein zweites
    Mal einloesen und erzeugte eine weitere Sitzung.
    """
    if not secret or not code:
        return None
    cleaned = code.strip().replace(" ", "")
    totp = pyotp.TOTP(secret)
    now = _now().timestamp()
    for offset in range(-valid_window, valid_window + 1):
        moment = now + offset * totp.interval
        # Zeitkonstant vergleichen: sonst liesse sich der erwartete Code aus der
        # Laufzeit ableiten.
        if hmac.compare_digest(totp.at(dt.datetime.fromtimestamp(moment, tz=dt.UTC)), cleaned):
            return int(moment // totp.interval)
    return None
