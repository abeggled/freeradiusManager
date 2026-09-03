"""Optionale OIDC-Anbindung (Authorization Code + PKCE, FR-10).

Das Rollen-Mapping erfolgt ueber einen konfigurierbaren Claim. Konten werden bei
der ersten Anmeldung angelegt, sofern das Mapping eine bekannte Rolle liefert.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import time
from dataclasses import dataclass
from typing import Any

import httpx
from authlib.jose import JsonWebKey, jwt

from app.core.config import Settings
from app.core.config import settings as app_settings
from app.core.errors import AuthenticationError

_metadata_cache: dict[str, dict[str, Any]] = {}
_jwks_cache: dict[str, tuple[float, Any]] = {}

JWKS_TTL_SECONDS = 3600
"""Nach dieser Zeit wird der Schluesselsatz neu geladen."""


@dataclass(frozen=True)
class AuthorizationStart:
    url: str
    state: str
    code_verifier: str
    nonce: str


def _challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


class OidcService:
    def __init__(self, config: Settings | None = None) -> None:
        self.config = config or app_settings

    async def metadata(self) -> dict[str, Any]:
        issuer = self.config.oidc_issuer.rstrip("/")
        if issuer in _metadata_cache:
            return _metadata_cache[issuer]
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(f"{issuer}/.well-known/openid-configuration")
            response.raise_for_status()
            data = response.json()
        # Ein Discovery-Dokument, das einen anderen Aussteller nennt als
        # konfiguriert, wird nicht verwendet (OpenID Connect Discovery 4.3).
        if str(data.get("issuer", "")).rstrip("/") != issuer:
            raise AuthenticationError(
                code="error.unauthenticated", details={"stage": "discovery_issuer"}
            )
        _metadata_cache[issuer] = data
        return data

    async def start(self) -> AuthorizationStart:
        if not self.config.oidc_enabled:
            raise AuthenticationError(code="error.forbidden")
        meta = await self.metadata()
        verifier = secrets.token_urlsafe(64)
        state = secrets.token_urlsafe(24)
        nonce = secrets.token_urlsafe(24)
        params = {
            "response_type": "code",
            "client_id": self.config.oidc_client_id,
            "redirect_uri": self.config.oidc_redirect_url,
            "scope": self.config.oidc_scopes,
            "state": state,
            "nonce": nonce,
            "code_challenge": _challenge(verifier),
            "code_challenge_method": "S256",
        }
        url = f"{meta['authorization_endpoint']}?{httpx.QueryParams(params)}"
        return AuthorizationStart(url=url, state=state, code_verifier=verifier, nonce=nonce)

    async def exchange(self, code: str, verifier: str, nonce: str) -> dict[str, Any]:
        meta = await self.metadata()
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.post(
                meta["token_endpoint"],
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": self.config.oidc_redirect_url,
                    "client_id": self.config.oidc_client_id,
                    "client_secret": self.config.oidc_client_secret,
                    "code_verifier": verifier,
                },
                headers={"Accept": "application/json"},
            )
        if response.status_code != 200:
            raise AuthenticationError(
                code="error.unauthenticated", details={"stage": "token_exchange"}
            )
        tokens = response.json()
        return await self._verify_id_token(tokens.get("id_token", ""), nonce, meta)

    async def _verify_id_token(
        self, id_token: str, nonce: str, meta: dict[str, Any]
    ) -> dict[str, Any]:
        if not id_token:
            raise AuthenticationError(code="error.unauthenticated")
        jwks_uri = meta["jwks_uri"]
        key_set = await self._jwks(jwks_uri)
        # Der Aussteller wird gegen die Discovery-Metadaten geprueft. Ohne diese
        # Bindung akzeptierte ein Anbieter mit gemeinsamem Token-Endpunkt oder
        # JWKS auch ein korrekt signiertes Token eines fremden Issuers.
        expected_issuer = str(meta.get("issuer") or self.config.oidc_issuer).rstrip("/")
        try:
            claims = self._decode(id_token, key_set, expected_issuer)
        except AuthenticationError:
            raise
        except Exception:  # noqa: BLE001 - unbekannter Schluessel oder Rotation
            # Der Anbieter kann seinen Signierschluessel jederzeit wechseln.
            # Ohne erneutes Laden waeren nach einer Rotation alle Anmeldungen
            # bis zum Neustart des Managers unmoeglich.
            key_set = await self._jwks(jwks_uri, force=True)
            try:
                claims = self._decode(id_token, key_set, expected_issuer)
            except AuthenticationError:
                raise
            except Exception as exc:
                raise AuthenticationError(
                    code="error.unauthenticated", details={"stage": "signature"}
                ) from exc

        if str(claims.get("iss", "")).rstrip("/") != expected_issuer:
            raise AuthenticationError(code="error.unauthenticated", details={"stage": "issuer"})
        if claims.get("nonce") != nonce:
            raise AuthenticationError(code="error.unauthenticated", details={"stage": "nonce"})
        if claims.get("aud") not in (self.config.oidc_client_id, [self.config.oidc_client_id]):
            aud = claims.get("aud")
            if not (isinstance(aud, list) and self.config.oidc_client_id in aud):
                raise AuthenticationError(
                    code="error.unauthenticated", details={"stage": "audience"}
                )
        return dict(claims)

    @staticmethod
    async def _jwks(jwks_uri: str, *, force: bool = False) -> Any:
        cached = _jwks_cache.get(jwks_uri)
        if cached is not None and not force and time.monotonic() - cached[0] < JWKS_TTL_SECONDS:
            return cached[1]
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(jwks_uri)
            response.raise_for_status()
            key_set = JsonWebKey.import_key_set(response.json())
        _jwks_cache[jwks_uri] = (time.monotonic(), key_set)
        return key_set

    def _decode(self, id_token: str, key_set: Any, expected_issuer: str) -> Any:
        claims = jwt.decode(
            id_token,
            key_set,
            claims_options={
                "iss": {"essential": True, "values": [expected_issuer]},
                "aud": {"essential": True, "values": [self.config.oidc_client_id]},
                "sub": {"essential": True},
                "exp": {"essential": True},
            },
        )
        claims.validate()
        return claims

    def map_role(self, claims: dict[str, Any]) -> str | None:
        """Bildet den konfigurierten Claim auf eine Manager-Rolle ab."""
        raw = claims.get(self.config.oidc_role_claim)
        values = raw if isinstance(raw, list) else [raw] if raw else []
        for value in values:
            mapped = self.config.oidc_role_map.get(str(value))
            if mapped:
                return mapped
        return None
