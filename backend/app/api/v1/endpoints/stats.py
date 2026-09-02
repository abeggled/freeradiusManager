"""Kennzahlen fuer das Dashboard. Gelesen wird nur der Hintergrund-Snapshot (NFR-2)."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.deps import AdminUser, ReaderUser, SessionDep
from app.core.config import settings
from app.schemas.sessions import StatsResponse
from app.services.stats import StatsService

router = APIRouter(prefix="/stats", tags=["stats"])


@router.get("", response_model=StatsResponse)
async def read_stats(session: SessionDep, _: ReaderUser) -> StatsResponse:
    return await StatsService(session).read(max_age_seconds=settings.stats_refresh_seconds * 2)


@router.post("/refresh", response_model=StatsResponse)
async def refresh_stats(session: SessionDep, _: AdminUser) -> StatsResponse:
    service = StatsService(session)
    await service.refresh()
    return await service.read(max_age_seconds=settings.stats_refresh_seconds * 2)
