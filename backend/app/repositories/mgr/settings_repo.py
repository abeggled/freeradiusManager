"""Instanzweite Einstellungen (``mgr_setting``) und Statistik-Snapshots."""

from __future__ import annotations

import datetime as dt
import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.mgr import MgrSetting, MgrStatsSnapshot


class SettingRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get(self, key: str) -> Any | None:
        row = await self.session.get(MgrSetting, key)
        return None if row is None else json.loads(row.value_json)

    async def all(self) -> dict[str, Any]:
        rows = (await self.session.scalars(select(MgrSetting))).all()
        return {row.key: json.loads(row.value_json) for row in rows}

    async def set(self, key: str, value: Any, updated_by: str | None = None) -> None:
        row = await self.session.get(MgrSetting, key)
        payload = json.dumps(value, ensure_ascii=False)
        if row is None:
            self.session.add(MgrSetting(key=key, value_json=payload, updated_by=updated_by))
        else:
            row.value_json = payload
            row.updated_by = updated_by
        await self.session.flush()


class StatsRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get(self, key: str) -> tuple[dt.datetime, Any] | None:
        row = await self.session.scalar(select(MgrStatsSnapshot).where(MgrStatsSnapshot.key == key))
        if row is None:
            return None
        return row.computed_at, json.loads(row.payload_json)

    async def store(self, key: str, payload: Any) -> None:
        row = await self.session.scalar(select(MgrStatsSnapshot).where(MgrStatsSnapshot.key == key))
        encoded = json.dumps(payload, ensure_ascii=False, default=str)
        now = dt.datetime.now(tz=dt.UTC).replace(tzinfo=None)
        if row is None:
            self.session.add(MgrStatsSnapshot(key=key, payload_json=encoded, computed_at=now))
        else:
            row.payload_json = encoded
            row.computed_at = now
        await self.session.flush()
