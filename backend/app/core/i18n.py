"""Zweisprachigkeit von Beginn an (NFR-4).

Uebersetzt werden Fehlercodes und serverseitig erzeugte Hinweistexte (z. B. die
Diagnose-Hinweise aus FR-6). Die Oberflaeche bringt eigene Kataloge mit.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

SUPPORTED_LANGUAGES = ("de", "en")
DEFAULT_LANGUAGE = "de"

_CATALOG_DIR = Path(__file__).resolve().parent.parent / "i18n"


@lru_cache
def _catalog(language: str) -> dict[str, str]:
    path = _CATALOG_DIR / f"{language}.json"
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def normalise_language(value: str | None) -> str:
    if not value:
        return DEFAULT_LANGUAGE
    for part in value.split(","):
        code = part.split(";")[0].strip().lower()[:2]
        if code in SUPPORTED_LANGUAGES:
            return code
    return DEFAULT_LANGUAGE


def translate(key: str, language: str = DEFAULT_LANGUAGE, **params: Any) -> str:
    """Loest einen Schluessel auf; unbekannte Schluessel werden unveraendert
    zurueckgegeben, damit nie eine leere Fehlermeldung entsteht."""
    template = _catalog(language).get(key) or _catalog(DEFAULT_LANGUAGE).get(key) or key
    if not params:
        return template
    try:
        return template.format(**params)
    except (KeyError, IndexError):
        return template
