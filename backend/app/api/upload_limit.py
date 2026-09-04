"""Groessenbeschraenkung fuer Anfragekoerper.

Ohne diese Schranke haette Starlette den Multipart-Koerper bereits vollstaendig
eingelesen - grosse Dateien landen dabei in einer temporaeren Datei -, bevor der
Endpunkt ueberhaupt laeuft. Die Pruefung im Endpunkt kaeme also zu spaet, um den
Ressourcenverbrauch zu begrenzen.

Fuer den Produktivbetrieb gehoert dieselbe Schranke zusaetzlich in den
vorgelagerten Reverse-Proxy (``client_max_body_size``); hier steht sie, damit
der Manager auch ohne ihn nicht ueberfahren werden kann.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any

from fastapi import Request, Response
from fastapi.responses import JSONResponse

from app.core.i18n import normalise_language, translate

MAX_UPLOAD_BYTES = 5 * 1024 * 1024
"""Groesste zulaessige Importdatei."""

MULTIPART_OVERHEAD_BYTES = 64 * 1024
"""Zuschlag fuer Grenzmarken, Kopfzeilen und die uebrigen Formularfelder.

Ohne ihn wiese die Schranke eine Datei ab, die genau der erlaubten Groesse
entspricht: ``Content-Length`` zaehlt den ganzen Multipart-Koerper."""

MAX_BODY_BYTES = MAX_UPLOAD_BYTES + MULTIPART_OVERHEAD_BYTES


def _too_large(request: Request) -> JSONResponse:
    language = normalise_language(
        request.query_params.get("lang")
        or request.cookies.get("frm_lang")
        or request.headers.get("accept-language")
    )
    return JSONResponse(
        status_code=413,
        content={
            "code": "error.payload_too_large",
            "message": translate("error.payload_too_large", language, max_bytes=MAX_BODY_BYTES),
            "details": {"max_bytes": MAX_BODY_BYTES},
        },
    )


async def limit_body_size(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    """Weist zu grosse Anfragekoerper ab, bevor sie gelesen werden."""
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            if int(declared) > MAX_BODY_BYTES:
                return _too_large(request)
        except ValueError:
            return _too_large(request)

    # Ohne ``Content-Length`` (chunked) hilft nur Mitzaehlen beim Lesen. Der
    # Zaehler sitzt vor dem Multipart-Parser, der Koerper wird also nie
    # vollstaendig eingelesen.
    received = 0
    original = request.receive

    async def counting_receive() -> MutableMapping[str, Any]:
        nonlocal received
        message = await original()
        if message["type"] == "http.request":
            received += len(message.get("body", b""))
            if received > MAX_BODY_BYTES:
                # Verbindung abbrechen: ein sauberer Fehlerkoerper waere hier
                # nicht mehr zustellbar, der Parser laeuft bereits.
                raise _BodyTooLargeError
        return message

    request._receive = counting_receive
    try:
        return await call_next(request)
    except _BodyTooLargeError:
        return _too_large(request)


class _BodyTooLargeError(Exception):
    """Intern: signalisiert das Ueberschreiten waehrend des Lesens."""
