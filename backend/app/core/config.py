"""Konfiguration ausschliesslich ueber Umgebungsvariablen (12-Factor, NFR-3)."""

from __future__ import annotations

import secrets
from functools import lru_cache
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict
from sqlalchemy import URL

CredentialType = Literal["cleartext", "nt", "both"]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="FRM_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Allgemein -------------------------------------------------------
    app_name: str = "freeradiusManager"
    environment: Literal["development", "test", "production"] = "production"
    debug: bool = False
    root_path: str = ""
    cors_origins: Annotated[list[str], NoDecode] = Field(default_factory=list)

    # --- Datenbank -------------------------------------------------------
    db_host: str = "localhost"
    db_port: int = 3306
    db_name: str = "radius"
    db_user: str = "radmgr"
    db_password: str = ""
    # Mindestens zwei gleichzeitige Verbindungen: benannte Sperren laufen ueber
    # eine eigene Verbindung, waehrend die Sitzung des Aufrufers eine weitere
    # haelt (siehe app/core/locking.py).
    db_pool_size: int = Field(default=10, ge=2)
    db_pool_max_overflow: int = Field(default=10, ge=0)
    db_echo: bool = False

    # --- Sicherheit ------------------------------------------------------
    secret_key: str = Field(default_factory=lambda: secrets.token_urlsafe(48))
    """Signierschluessel der Session-Tokens.

    Ohne Vorgabe wird fuer Entwicklung und Tests ein Zufallswert erzeugt; im
    Produktivbetrieb ist ein gesetzter Wert Pflicht (siehe Validierung unten).
    """
    coa_secret_key: str = ""
    """Fernet-/AES-GCM-Schluessel (base64, 32 Byte) fuer CoA-Secrets (NFR-1)."""

    jwt_algorithm: str = "HS256"
    # Positive Laufzeiten erzwungen: bei 0 waere das Token sofort abgelaufen und
    # die Anmeldung faktisch unbrauchbar.
    session_idle_minutes: int = Field(default=30, ge=1)
    session_absolute_hours: int = Field(default=12, ge=1)
    cookie_name: str = "frm_session"
    allowed_origins: Annotated[list[str], NoDecode] = Field(default_factory=list)
    """Zusaetzlich erlaubte Herkuenfte fuer schreibende Anfragen.

    Ohne Eintrag gilt nur die eigene Adresse des Requests. Die Pruefung ergaenzt
    ``SameSite=Lax``: ein Geschwister-Host derselben registrierbaren Domain gilt
    fuer den Browser als "same-site" und duerfte das Cookie sonst mitsenden.
    """
    cookie_secure: bool = True
    cookie_domain: str | None = None
    require_totp_for_admin: bool = True

    trusted_proxies: Annotated[list[str], NoDecode] = Field(default_factory=list)
    """Netze, deren ``X-Forwarded-For`` vertraut wird (z. B. ``10.0.0.0/8``).

    Leer bedeutet: der Header wird ignoriert und die Peer-Adresse verwendet.
    Andernfalls koennte ein Aufrufer die Rate-Limits durch gefaelschte
    Adressen umgehen (NFR-1).
    """

    # Positive Werte erzwungen: bei 0 waere jede Anmeldung sofort "ueber dem
    # Limit" und der Zaehler liefe auf einen leeren Puffer.
    login_rate_limit: int = Field(default=10, ge=1)
    login_rate_window_seconds: int = Field(default=300, ge=1)
    login_ip_rate_limit: int = Field(default=30, ge=1)
    """Obergrenze je Absender-IP, unabhaengig vom genannten Benutzernamen.

    Ohne sie liesse sich das Limit umgehen, indem fuer jeden Versuch ein neuer
    Benutzername angegeben wird (Password Spraying).
    """
    coa_rate_limit: int = Field(default=30, ge=1)
    coa_rate_window_seconds: int = Field(default=60, ge=1)

    # --- OIDC (optional, FR-10) -----------------------------------------
    oidc_enabled: bool = False
    oidc_issuer: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_redirect_url: str = ""
    oidc_scopes: str = "openid profile email"
    oidc_role_claim: str = "roles"
    oidc_role_map: dict[str, str] = Field(default_factory=dict)
    oidc_mfa_amr_values: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["mfa", "otp", "hwk", "swk", "pop"]
    )
    """``amr``-Werte, die einen zweiten Faktor beim Provider belegen (RFC 8176)."""
    oidc_mfa_acr_values: Annotated[list[str], NoDecode] = Field(default_factory=list)
    """Zusaetzlich akzeptierte ``acr``-Werte; providerspezifisch."""

    # --- Fachliche Defaults ---------------------------------------------
    default_mac_format: str = "colon_lower"
    default_credential_type: CredentialType = "both"
    # Wie bei der Einstellung in der Datenbank: 0 oder negativ liesse den
    # Hintergrundjob das gesamte Audit-Log loeschen.
    audit_retention_days: int = Field(default=730, ge=1, le=36_500)
    default_language: Literal["de", "en"] = "de"

    # --- Erstinbetriebnahme ---------------------------------------------
    bootstrap_admin_username: str = "admin"
    bootstrap_admin_password: str = ""
    """Wird nur verwendet, solange noch kein aktiver Administrator existiert."""

    # --- Betrieb ---------------------------------------------------------
    schema_check_on_startup: bool = True
    # Positive Intervalle erzwungen: bei 0 liefen die Hintergrundjobs ohne
    # Pause und belasteten die Datenbank dauerhaft.
    stats_refresh_seconds: int = Field(default=300, ge=1)
    audit_purge_interval_seconds: int = Field(default=6 * 3600, ge=1)
    # Positiv erzwungen: ohne Zeitgrenze waere der Socket nicht blockierend,
    # ohne Versuch gaebe es keinen Sendevorgang.
    coa_timeout_seconds: float = Field(default=5.0, gt=0, le=60)
    coa_retries: int = Field(default=2, ge=1, le=10)

    @model_validator(mode="after")
    def _require_production_keys(self) -> Settings:
        """Im Produktivbetrieb muessen die Schluessel gesetzt und eigenstaendig sein.

        Ein zufaellig erzeugter ``secret_key`` waere bei mehreren Instanzen oder
        nach einem Neustart wertlos, ein aus dem Repository bekannter Wert
        waere schlicht kein Geheimnis (NFR-1).
        """
        if self.environment != "production":
            return self
        missing: list[str] = []
        # Ein per default_factory erzeugter Zufallswert zaehlt nicht als gesetzt:
        # er waere nach jedem Neustart ein anderer.
        if "secret_key" not in self.model_fields_set or len(self.secret_key) < 32:
            missing.append("FRM_SECRET_KEY")
        if len(self.coa_secret_key) < 32:
            missing.append("FRM_COA_SECRET_KEY")
        if missing:
            raise ValueError(
                "Im Produktivbetrieb muessen "
                + " und ".join(missing)
                + " gesetzt sein (mindestens 32 Zeichen)."
            )
        return self

    @model_validator(mode="after")
    def _require_oidc_settings(self) -> Settings:
        """Aktiviertes OIDC braucht Aussteller, Client-ID und Redirect-URL.

        Fehlen sie, scheiterte erst der erste Anmeldeversuch - nach erfolgreicher
        Authentisierung beim Provider und mit einem allgemeinen Serverfehler.
        """
        if not self.oidc_enabled:
            return self
        missing = [
            name
            for name, value in (
                ("FRM_OIDC_ISSUER", self.oidc_issuer),
                ("FRM_OIDC_CLIENT_ID", self.oidc_client_id),
                ("FRM_OIDC_REDIRECT_URL", self.oidc_redirect_url),
            )
            if not value.strip()
        ]
        if missing:
            raise ValueError("Bei aktiviertem OIDC fehlen: " + ", ".join(missing))
        return self

    @model_validator(mode="after")
    def _require_origins_with_cookie_domain(self) -> Settings:
        """Ein geteiltes Cookie verlangt konfigurierte Herkuenfte.

        Mit ``FRM_COOKIE_DOMAIN`` geht das Sitzungscookie an jeden Host der
        Domain. Die Herkunftspruefung darf sich dann nicht auf den Host-Header
        der Anfrage stuetzen (app/api/csrf.py) - ohne eingetragene Herkunft
        wiese sie jeden Schreibzugriff ab, und zwar erst im Betrieb.
        """
        if self.cookie_domain and not (self.allowed_origins or self.cors_origins):
            raise ValueError(
                "FRM_COOKIE_DOMAIN verlangt FRM_ALLOWED_ORIGINS (oder FRM_CORS_ORIGINS)"
            )
        return self

    @field_validator("oidc_role_map")
    @classmethod
    def _check_role_map(cls, value: dict[str, str]) -> dict[str, str]:
        """Nur bekannte Rollen als Ziel zulassen.

        Ein Tippfehler wuerde sonst erst beim Anmelden auffallen - und dort als
        allgemeiner Serverfehler nach erfolgreicher Authentisierung.
        """
        allowed = {"administrator", "operator", "auditor"}
        invalid = sorted(set(value.values()) - allowed)
        if invalid:
            raise ValueError(
                "FRM_OIDC_ROLE_MAP kennt nur "
                + ", ".join(sorted(allowed))
                + f"; ungueltig: {', '.join(invalid)}"
            )
        return value

    @field_validator(
        "cors_origins",
        "trusted_proxies",
        "allowed_origins",
        "oidc_mfa_amr_values",
        "oidc_mfa_acr_values",
        mode="before",
    )
    @classmethod
    def _split_origins(cls, value: object) -> object:
        """Kommagetrennte Liste aus der Umgebung.

        ``NoDecode`` ist noetig, weil pydantic-settings Listenfelder sonst als
        JSON liest und ``10.0.0.0/8,192.168.0.0/16`` den Start abbrechen wuerde.
        """
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    def _url(self, driver: str) -> str:
        """Baut die Verbindungs-URL ueber SQLAlchemy.

        Zusammengesetzte Zeichenketten scheitern, sobald Benutzername oder
        Passwort ein ``@``, ``/``, ``#`` oder ``%`` enthalten - genau das kommt
        bei generierten Datenbankpasswoertern regelmaessig vor.
        """
        return URL.create(
            drivername=driver,
            username=self.db_user,
            password=self.db_password,
            host=self.db_host,
            port=self.db_port,
            database=self.db_name,
            query={"charset": "utf8mb4"},
        ).render_as_string(hide_password=False)

    @property
    def database_url(self) -> str:
        return self._url("mysql+aiomysql")

    @property
    def sync_database_url(self) -> str:
        return self._url("mysql+pymysql")


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
