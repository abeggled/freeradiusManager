"""FastAPI-Anwendung.

Startreihenfolge: Logging, Schemapruefung (Abschnitt 4.2), Bootstrap-Administrator,
Hintergrundjob fuer Aggregationen (NFR-2).
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator
from functools import lru_cache
from pathlib import Path

from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text

from app.api.errors import register_error_handlers
from app.api.v1.router import api_router
from app.core.config import settings
from app.core.db import dispose, get_engine, get_sessionmaker
from app.core.logging import configure_logging, get_logger
from app.repositories.radius.schema import inspect_schema
from app.services.accounts import AccountService
from app.services.audit import retention_worker
from app.services.stats import stats_worker

log = get_logger("main")
STATIC_DIR = Path(__file__).resolve().parent.parent / "static"


async def check_schema() -> None:
    """Verweigert den Betrieb, wenn das RADIUS-Schema abweicht (Abschnitt 4.2)."""
    async with get_engine().connect() as connection:
        report = await inspect_schema(connection, settings.db_name)
    if not report.ok:
        log.error("radius_schema_invalid", **report.as_details())
        raise RuntimeError(
            "FreeRADIUS-Schema entspricht nicht den Erwartungen: " + report.summary()
        )
    if report.missing_indexes:
        log.warning("radius_schema_missing_indexes", **report.as_details())


async def bootstrap_admin() -> None:
    if not settings.bootstrap_admin_password:
        return
    async with get_sessionmaker()() as session:
        created = await AccountService(session).ensure_bootstrap_admin(
            settings.bootstrap_admin_username, settings.bootstrap_admin_password
        )
    if created is not None:
        log.info("bootstrap_admin_created", username=created.username)


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    configure_logging()
    if settings.schema_check_on_startup:
        await check_schema()
    await bootstrap_admin()
    tasks = [
        asyncio.create_task(stats_worker(get_sessionmaker(), settings.stats_refresh_seconds)),
        # Ohne diesen Job bliebe die konfigurierte Aufbewahrungsfrist folgenlos
        # und mgr_audit wuechse unbegrenzt (FR-9).
        asyncio.create_task(
            retention_worker(get_sessionmaker(), settings.audit_purge_interval_seconds)
        ),
    ]
    log.info("started", environment=settings.environment)
    try:
        yield
    finally:
        for task in tasks:
            task.cancel()
        for task in tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await task
        await dispose()


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.app_name,
        version="0.1.0",
        description=("Verwaltung eines bestehenden FreeRADIUS-Servers ueber das rlm_sql-Schema."),
        lifespan=lifespan,
        root_path=settings.root_path,
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
    )

    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    register_error_handlers(app)
    app.include_router(api_router)

    @app.get("/healthz", tags=["health"])
    async def healthz() -> dict[str, str]:
        """Liveness – prueft bewusst keine Abhaengigkeiten (NFR-3)."""
        return {"status": "ok"}

    @app.get("/readyz", tags=["health"])
    async def readyz() -> JSONResponse:
        """Readiness inkl. DB-Pruefung (NFR-3)."""
        try:
            async with get_engine().connect() as connection:
                await connection.execute(text("SELECT 1"))
        except Exception as exc:  # noqa: BLE001 - jeder DB-Fehler bedeutet not ready
            log.warning("readyz_failed", error=str(exc))
            return JSONResponse(status_code=503, content={"status": "unavailable"})
        return JSONResponse(content={"status": "ok"})

    if STATIC_DIR.is_dir():
        app.mount("/assets", StaticFiles(directory=STATIC_DIR / "assets"), name="assets")

        @lru_cache(maxsize=1)
        def index_html() -> str:
            """index.html mit dem konfigurierten Basispfad.

            Die Oberflaeche leitet Asset- und API-Adressen aus ``<base href>`` ab;
            hinter einem Reverse-Proxy-Praefix (``FRM_ROOT_PATH``) waeren sie
            sonst am Origin verankert.
            """
            base = (settings.root_path.rstrip("/") + "/") or "/"
            return (
                (STATIC_DIR / "index.html")
                .read_text(encoding="utf-8")
                .replace('<base href="/" />', f'<base href="{base}" />')
            )

        @app.get("/{full_path:path}", include_in_schema=False)
        async def spa(full_path: str) -> Response:
            """Ausliefern der gebauten Oberflaeche; Routing uebernimmt der Browser.

            Unbekannte API-Pfade duerfen hier nicht landen – sonst bekaeme ein
            Client statt eines Fehlerobjekts stillschweigend die HTML-Seite.
            """
            if full_path.startswith("api/"):
                return JSONResponse(
                    status_code=404,
                    content={"code": "error.not_found", "message": full_path, "details": {}},
                )
            candidate = (STATIC_DIR / full_path).resolve()
            if full_path and candidate.is_file() and candidate.is_relative_to(STATIC_DIR):
                return FileResponse(candidate)
            return HTMLResponse(index_html())

    return app


app = create_app()
