"""CSV-Import mit Vorschau und Dry-Run (FR-8)."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, File, Form, Response, UploadFile

from app.api.deps import ClientIp, Language, ReaderUser, SessionDep, WriterUser
from app.api.upload_limit import MAX_BODY_BYTES
from app.core.errors import ValidationError
from app.services.importexport import ImportExportService

router = APIRouter(prefix="/imports", tags=["import-export"])

MAX_BYTES = MAX_BODY_BYTES
"""Zweite Schranke; die erste greift schon vor dem Multipart-Parser
(``app/api/upload_limit.py``)."""


@router.get("/template/{kind}")
async def template(kind: Literal["user", "device"], _: ReaderUser) -> Response:
    return Response(
        content=ImportExportService.template(kind),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="vorlage-{kind}.csv"'},
    )


@router.post("/{kind}")
async def import_csv(
    kind: Literal["user", "device"],
    session: SessionDep,
    actor: WriterUser,
    actor_ip: ClientIp,
    language: Language,
    file: UploadFile = File(...),
    dry_run: bool = Form(default=True),
) -> dict[str, object]:
    """Erst ``dry_run=true`` fuer die Vorschau, danach ``dry_run=false`` zum Schreiben."""
    raw = await file.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValidationError(code="error.import_invalid", details={"max_bytes": MAX_BYTES})
    try:
        content = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        content = raw.decode("latin-1")

    report = await ImportExportService(session).import_csv(
        content,
        kind=kind,
        dry_run=dry_run,
        actor=actor,
        actor_ip=actor_ip,
        language=language,
    )
    return {
        "dry_run": report.dry_run,
        "total": report.total,
        "to_create": report.to_create,
        "to_update": report.to_update,
        "errors": report.errors,
        # ``ImportReport`` behaelt bereits nur eine begrenzte Auswahl und
        # bevorzugt dabei Fehlerzeilen.
        "rows": [
            {
                "line": r.line,
                "action": r.action,
                "username": r.username,
                "message": r.message,
                "values": r.values,
            }
            for r in report.rows
        ],
        "rows_truncated": report.rows_truncated,
    }
