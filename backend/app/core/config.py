"""Konfiguration ausschliesslich ueber Umgebungsvariablen (12-Factor, NFR-3)."""

from __future__ import annotations

import secrets
from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

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
    cors_origins: list[str] = Field(default_factory=list)

    # --- Datenbank -------------------------------------------------------
    db_host: str = "localhost"
    db_port: int = 3306
    db_name: str = "radius"
    db_user: str = "radmgr"
    db_password: str = ""
    db_pool_size: int = 10
    db_pool_max_overflow: int = 10
    db_echo: bool = False

    # --- Sicherheit ------------------------------------------------------
    secret_key: str = Field(default_factory=lambda: secrets.token_urlsafe(48))
    coa_secret_key: str = ""
    """Fernet-/AES-GCM-Schluessel (base64, 32 Byte) fuer CoA-Secrets (NFR-1)."""

    jwt_algorithm: str = "HS256"
    session_idle_minutes: int = 30
    session_absolute_hours: int = 12
    cookie_name: str = "frm_session"
    cookie_secure: bool = True
    cookie_domain: str | None = None
    require_totp_for_admin: bool = True

    trusted_proxies: list[str] = Field(default_factory=list)
    """Netze, deren ``X-Forwarded-For`` vertraut wird (z. B. ``10.0.0.0/8``).

    Leer bedeutet: der Header wird ignoriert und die Peer-Adresse verwendet.
    Andernfalls koennte ein Aufrufer die Rate-Limits durch gefaelschte
    Adressen umgehen (NFR-1).
    """

    login_rate_limit: int = 10
    login_rate_window_seconds: int = 300
    coa_rate_limit: int = 30
    coa_rate_window_seconds: int = 60

    # --- OIDC (optional, FR-10) -----------------------------------------
    oidc_enabled: bool = False
    oidc_issuer: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_redirect_url: str = ""
    oidc_scopes: str = "openid profile email"
    oidc_role_claim: str = "roles"
    oidc_role_map: dict[str, str] = Field(default_factory=dict)

    # --- Fachliche Defaults ---------------------------------------------
    default_mac_format: str = "colon_lower"
    default_credential_type: CredentialType = "both"
    audit_retention_days: int = 730
    default_language: Literal["de", "en"] = "de"

    # --- Erstinbetriebnahme ---------------------------------------------
    bootstrap_admin_username: str = "admin"
    bootstrap_admin_password: str = ""
    """Wird nur verwendet, solange noch kein aktiver Administrator existiert."""

    # --- Betrieb ---------------------------------------------------------
    schema_check_on_startup: bool = True
    stats_refresh_seconds: int = 300
    audit_purge_interval_seconds: int = 6 * 3600
    coa_timeout_seconds: float = 5.0
    coa_retries: int = 2

    @field_validator("cors_origins", "trusted_proxies", mode="before")
    @classmethod
    def _split_origins(cls, value: object) -> object:
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @property
    def database_url(self) -> str:
        return (
            f"mysql+aiomysql://{self.db_user}:{self.db_password}"
            f"@{self.db_host}:{self.db_port}/{self.db_name}?charset=utf8mb4"
        )

    @property
    def sync_database_url(self) -> str:
        return (
            f"mysql+pymysql://{self.db_user}:{self.db_password}"
            f"@{self.db_host}:{self.db_port}/{self.db_name}?charset=utf8mb4"
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
