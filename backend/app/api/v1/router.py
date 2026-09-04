"""Zusammenbau der REST-API unter ``/api/v1`` (Abschnitt 6.3)."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1.endpoints import (
    accounts,
    audit,
    auth,
    authlog,
    devices,
    groups,
    imports,
    nas,
    sessions,
    settings,
    stats,
    users,
)

api_router = APIRouter(prefix="/api/v1")
for module in (
    auth,
    users,
    devices,
    groups,
    nas,
    sessions,
    authlog,
    audit,
    accounts,
    imports,
    settings,
    stats,
):
    api_router.include_router(module.router)
