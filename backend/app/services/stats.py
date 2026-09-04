"""Aggregationen als Hintergrundjob (NFR-2).

Die Statistiken werden periodisch berechnet und in ``mgr_stats_snapshot``
abgelegt; der Request liest nur den Snapshot.
"""

from __future__ import annotations

import asyncio
import datetime as dt

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.dates import utcnow
from app.core.logging import get_logger
from app.models.mgr import SubjectType
from app.models.radius import Nas
from app.repositories.directory import DirectoryRepository, SubjectFilter
from app.repositories.mgr.settings_repo import StatsRepository
from app.repositories.radius.acct import AccountingRepository
from app.repositories.radius.groups import GroupRepository
from app.repositories.radius.postauth import PostAuthRepository
from app.schemas.sessions import StatsResponse

SNAPSHOT_KEY = "dashboard"
log = get_logger("stats")


class StatsService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.repo = StatsRepository(session)
        self.directory = DirectoryRepository(session)
        self.acct = AccountingRepository(session)
        self.postauth = PostAuthRepository(session)
        self.groups = GroupRepository(session)

    async def compute(self, window_hours: int = 24) -> dict[str, object]:
        since = utcnow() - dt.timedelta(hours=window_hours)
        payload: dict[str, object] = await self.acct.summary(since)
        payload.update(await self.postauth.summary(since))
        payload["top_rejected"] = [
            {"username": u, "attempts": c}
            for u, c in await self.postauth.unknown_subjects(since, limit=10)
        ]
        # Beide Zahlen kommen aus derselben Menge wie die Listenansichten -
        # sonst zaehlten MAB-Geraete doppelt und Bestandsnamen ohne
        # Check-Attribute fehlten ganz.
        _, payload["users_total"] = await self.directory.search(
            SubjectFilter(subject_type=SubjectType.USER), limit=1, offset=0
        )
        _, payload["devices_total"] = await self.directory.search(
            SubjectFilter(subject_type=SubjectType.DEVICE), limit=1, offset=0
        )
        payload["groups_total"] = len(await self.groups.group_names())
        payload["nas_total"] = int(
            await self.session.scalar(select(func.count()).select_from(Nas)) or 0
        )
        payload["window_hours"] = window_hours
        return payload

    async def refresh(self) -> dict[str, object]:
        payload = await self.compute()
        await self.repo.store(SNAPSHOT_KEY, payload)
        await self.session.commit()
        return payload

    async def read(self, max_age_seconds: int) -> StatsResponse:
        snapshot = await self.repo.get(SNAPSHOT_KEY)
        if snapshot is None:
            return StatsResponse(stale=True)
        computed_at, payload = snapshot
        stale = (utcnow() - computed_at).total_seconds() > max_age_seconds
        known = set(StatsResponse.model_fields)
        filtered = {k: v for k, v in payload.items() if k in known}
        return StatsResponse(computed_at=computed_at, stale=stale, **filtered)


async def stats_worker(
    sessionmaker: async_sessionmaker[AsyncSession], interval_seconds: int
) -> None:
    """Hintergrundschleife; wird beim Anwendungsstart als Task gestartet."""
    while True:
        try:
            async with sessionmaker() as session:
                await StatsService(session).refresh()
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - Job darf nie den Prozess beenden
            log.warning("stats_refresh_failed", error=str(exc))
        await asyncio.sleep(interval_seconds)
