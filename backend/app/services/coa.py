"""Disconnect-Message und Change-of-Authorization nach RFC 5176 (FR-7).

Der Manager tritt hier ausnahmsweise als RADIUS-*Client* auf; er bleibt aber
weiterhin kein RADIUS-Server (Abschnitt 1.2). Voraussetzung ist ein pro NAS
hinterlegtes CoA-Secret samt Port.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from pyrad.client import Client
from pyrad.client import Timeout as PyradTimeout
from pyrad.dictionary import Dictionary
from pyrad.packet import CoAACK, CoANAK, DisconnectACK, DisconnectNAK
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings as app_settings
from app.core.errors import CoAError, NotFoundError, ValidationError
from app.core.logging import get_logger
from app.core.security import Principal
from app.models.mgr import AuditResult
from app.repositories.radius.acct import AccountingRepository
from app.schemas.nas import CoARequest, CoAResponse
from app.services.audit import AuditService
from app.services.nas import NasService

DICTIONARY_PATH = Path(__file__).resolve().parent.parent / "resources" / "dictionary"
log = get_logger("coa")

# Je Aktion die passende Antwort. Ein Disconnect, das mit CoA-ACK beantwortet
# wird, hat die angeforderte Operation nicht ausgefuehrt.
_ACK_CODES = {True: DisconnectACK, False: CoAACK}
_NAK_CODES = {True: DisconnectNAK, False: CoANAK}


def _send_blocking(
    host: str, port: int, secret: str, attributes: dict[str, Any], disconnect: bool
) -> tuple[int | None, dict[str, Any]]:
    """Blockierender pyrad-Aufruf; wird in einem Thread ausgefuehrt."""
    client = Client(
        server=host,
        coaport=port,
        secret=secret.encode("utf-8"),
        dict=Dictionary(str(DICTIONARY_PATH)),
    )
    client.timeout = app_settings.coa_timeout_seconds
    client.retries = app_settings.coa_retries
    request = client.CreateCoAPacket(code=40 if disconnect else 43)
    for key, value in attributes.items():
        request[key] = value
    reply = client.SendPacket(request)
    return reply.code, {str(k): str(v) for k, v in reply.items()}


class CoAService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.acct = AccountingRepository(session)
        self.nas = NasService(session)
        self.audit = AuditService(session)

    async def execute(
        self,
        payload: CoARequest,
        *,
        actor: Principal,
        actor_ip: str | None = None,
        language: str = "de",
    ) -> CoAResponse:
        del language  # Meldungen entstehen jetzt ausschliesslich ueber Fehlercodes
        session_row = await self._resolve_session(payload)
        target = await self.nas.coa_target(session_row.nasipaddress)
        if target is None:
            # Auch der nicht abgeschickte Versuch gehoert ins Protokoll: sonst
            # bliebe eine Reihe fehlgeleiteter Trennversuche unsichtbar (FR-9).
            await self._log(
                payload,
                session_row,
                actor,
                actor_ip,
                AuditResult.FAILURE,
                "kein CoA konfiguriert",
            )
            raise CoAError(
                code="error.coa_not_configured",
                details={"nas": session_row.nasipaddress},
                status_code=409,
            )
        host, port, secret = target

        attributes: dict[str, Any] = {
            "User-Name": session_row.username,
            "Acct-Session-Id": session_row.acctsessionid,
            "NAS-IP-Address": session_row.nasipaddress,
        }
        if session_row.callingstationid:
            attributes["Calling-Station-Id"] = session_row.callingstationid
        if session_row.framedipaddress:
            attributes["Framed-IP-Address"] = session_row.framedipaddress

        disconnect = payload.action == "disconnect"
        if not disconnect:
            if not payload.vlan:
                raise ValidationError(code="error.validation", details={"field": "vlan"})
            attributes["Tunnel-Type"] = (0, 13)  # VLAN
            attributes["Tunnel-Medium-Type"] = (0, 6)  # IEEE-802
            attributes["Tunnel-Private-Group-Id"] = (0, str(payload.vlan))

        try:
            code, reply_attributes = await asyncio.to_thread(
                _send_blocking, host, port, secret, attributes, disconnect
            )
        # pyrad meldet Zeitueberschreitungen ueber eine eigene Klasse, die nicht
        # von TimeoutError erbt - ohne sie landete jeder Timeout im Sammelzweig.
        except (PyradTimeout, TimeoutError) as exc:
            await self._log(payload, session_row, actor, actor_ip, AuditResult.FAILURE, "timeout")
            raise CoAError(code="error.coa_timeout", details={"nas": host, "port": port}) from exc
        except Exception as exc:
            log.warning("coa_failed", nas=host, error=str(exc))
            await self._log(payload, session_row, actor, actor_ip, AuditResult.FAILURE, str(exc))
            raise CoAError(code="error.coa_failed", details={"nas": host}) from exc

        ok = code == _ACK_CODES[disconnect]
        if not ok:
            # Auch eine gueltig signierte Antwort des falschen Typs bestaetigt
            # nicht die angeforderte Operation.
            is_nak = code in (_NAK_CODES[disconnect], _NAK_CODES[not disconnect])
            await self._log(
                payload,
                session_row,
                actor,
                actor_ip,
                AuditResult.FAILURE,
                "NAK" if is_nak else f"unerwartete Antwort {code}",
            )
            raise CoAError(
                code="error.coa_nak" if is_nak else "error.coa_failed",
                details={"nas": host, "code": str(code), "reply": reply_attributes},
            )

        await self._log(payload, session_row, actor, actor_ip, AuditResult.SUCCESS, f"code={code}")
        return CoAResponse(
            ok=True,
            action=payload.action,
            nas=host,
            code=str(code),
            message="ACK",
            attributes=reply_attributes,
        )

    async def _resolve_session(self, payload: CoARequest) -> Any:
        row = None
        if payload.radacctid:
            try:
                radacctid = int(payload.radacctid)
            except ValueError as exc:
                raise ValidationError(
                    code="error.validation", details={"radacctid": payload.radacctid}
                ) from exc
            row = await self.acct.get(radacctid)
        elif payload.acctuniqueid:
            row = await self.acct.get_by_unique_id(payload.acctuniqueid)
        elif payload.username:
            active = await self.acct.active_for_user(payload.username)
            if len(active) > 1:
                # Sonst traefe es stillschweigend die zuletzt begonnene Sitzung -
                # bei geteilten Kennungen die falsche.
                raise ValidationError(
                    code="error.session_ambiguous",
                    details={
                        "username": payload.username,
                        "sessions": [
                            {"radacctid": r.radacctid, "acctuniqueid": r.acctuniqueid}
                            for r in active[:20]
                        ],
                    },
                )
            row = active[0] if active else None
        if row is None:
            raise NotFoundError(code="error.session_not_found")
        if row.acctstoptime is not None:
            raise NotFoundError(code="error.session_not_found")
        return row

    async def _log(
        self,
        payload: CoARequest,
        session_row: Any,
        actor: Principal,
        actor_ip: str | None,
        result: AuditResult,
        message: str,
    ) -> None:
        await self.audit.log(
            action=f"coa.{payload.action}",
            object_type="session",
            object_id=str(session_row.acctuniqueid or session_row.radacctid),
            actor=actor,
            actor_ip=actor_ip,
            after={
                "username": session_row.username,
                "nas": session_row.nasipaddress,
                "vlan": payload.vlan,
            },
            result=result,
            message=message,
        )
        await self.session.commit()
