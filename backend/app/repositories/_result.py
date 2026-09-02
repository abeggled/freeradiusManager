"""Kleine Helfer rund um SQLAlchemy-Ergebnisse."""

from __future__ import annotations

from typing import Any, cast

from sqlalchemy import CursorResult, Result


def rowcount(result: Result[Any]) -> int:
    """Anzahl betroffener Zeilen eines DML-Statements."""
    return int(cast(CursorResult[Any], result).rowcount or 0)
