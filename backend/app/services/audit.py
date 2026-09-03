"""Audit-Log-Dienst (FR-9).

Jede schreibende Aktion wird protokolliert. Passwoerter und Shared Secrets
erscheinen ausschliesslich als Marker ``"<geaendert>"`` – nie im Klartext (NFR-1).
"""

from __future__ import annotations

import asyncio
import datetime as dt
import json
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core import radius_dict
from app.core.logging import get_logger
from app.core.security import Principal
from app.models.mgr import AuditResult, MgrAudit
from app.repositories.mgr.audit import AuditRepository

log = get_logger("audit")

REDACTED = "<geaendert>"

SENSITIVE_KEYS = frozenset(
    {
        "password",
        "new_password",
        "current_password",
        "cleartext_password",
        "nt_password",
        "secret",
        "shared_secret",
        "coa_secret",
        "totp_secret",
        "totp_code",
        "password_hash",
        "totp_secret_enc",
        "coa_secret_enc",
        "value",  # Attributwerte von Passwort-Attributen, siehe redact()
    }
)


def _is_password_attribute(attribute: str) -> bool:
    """Dieselbe Liste wie fuer die API-Maskierung - eine zweite, engere Liste
    wuerde frueher oder spaeter auseinanderlaufen (NFR-1)."""
    return radius_dict.is_password_attribute(attribute)


def redact(payload: Any) -> Any:
    """Ersetzt sensible Werte rekursiv durch einen Marker."""
    if isinstance(payload, dict):
        attribute = str(payload.get("attribute", ""))
        sensitive_row = bool(attribute) and _is_password_attribute(attribute)
        out: dict[str, Any] = {}
        for key, value in payload.items():
            lowered = key.lower()
            if lowered == "value":
                out[key] = REDACTED if sensitive_row else redact(value)
            elif lowered in SENSITIVE_KEYS:
                out[key] = REDACTED if value not in (None, "") else None
            else:
                out[key] = redact(value)
        return out
    if isinstance(payload, list):
        return [redact(item) for item in payload]
    return payload


def _dump(payload: Any) -> str | None:
    if payload is None:
        return None
    return json.dumps(redact(payload), ensure_ascii=False, default=str)


class AuditService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.repo = AuditRepository(session)

    async def log(
        self,
        *,
        action: str,
        object_type: str,
        object_id: str | None = None,
        actor: Principal | None = None,
        actor_ip: str | None = None,
        before: Any = None,
        after: Any = None,
        result: AuditResult = AuditResult.SUCCESS,
        message: str | None = None,
    ) -> MgrAudit:
        entry = MgrAudit(
            ts=dt.datetime.now(tz=dt.UTC).replace(tzinfo=None),
            actor_id=actor.account_id if actor else None,
            actor_name=actor.username if actor else "system",
            actor_ip=actor_ip,
            action=action,
            object_type=object_type,
            object_id=object_id,
            result=result,
            message=message[:512] if message else None,
            before_json=_dump(before),
            after_json=_dump(after),
        )
        return await self.repo.add(entry)

    async def purge(self, retention_days: int) -> int:
        cutoff = dt.datetime.now(tz=dt.UTC).replace(tzinfo=None) - dt.timedelta(days=retention_days)
        return await self.repo.purge_older_than(cutoff)


async def retention_worker(
    sessionmaker: async_sessionmaker[AsyncSession], interval_seconds: int
) -> None:
    """Setzt die konfigurierte Aufbewahrungsfrist regelmaessig durch (FR-9).

    Ohne diesen Job waere die Einstellung folgenlos und ``mgr_audit`` wuechse
    unbegrenzt.
    """
    from app.services.settings_service import KEY_AUDIT_RETENTION, SettingsService

    while True:
        try:
            async with sessionmaker() as session:
                retention = int(await SettingsService(session).get(KEY_AUDIT_RETENTION))
                removed = await AuditService(session).purge(retention)
                await session.commit()
            if removed:
                log.info("audit_purged", removed=removed, retention_days=retention)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - der Job darf den Prozess nie beenden
            log.warning("audit_purge_failed", error=str(exc))
        await asyncio.sleep(interval_seconds)
