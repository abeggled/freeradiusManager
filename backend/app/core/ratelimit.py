"""Schlanker In-Memory-Rate-Limiter fuer Login- und CoA-Endpunkte (NFR-1).

Bewusst prozesslokal: bei mehreren Instanzen begrenzt jede Instanz fuer sich.
Fuer eine geteilte Zaehlung ist ein Redis-Backend die vorgesehene Ausbaustufe.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque

from app.core.errors import RateLimitError


class RateLimiter:
    def __init__(self, limit: int, window_seconds: int) -> None:
        self.limit = limit
        self.window = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()
        self._last_sweep = time.monotonic()

    def _sweep(self, now: float) -> None:
        """Entfernt abgelaufene Eintraege.

        Die Schluessel enthalten frei waehlbare Benutzernamen: ohne Aufraeumen
        wuechse der Speicher durch unangemeldete Anfragen unbegrenzt.
        """
        if now - self._last_sweep < self.window:
            return
        self._last_sweep = now
        for key in list(self._hits):
            bucket = self._hits[key]
            while bucket and now - bucket[0] > self.window:
                bucket.popleft()
            if not bucket:
                del self._hits[key]

    def check(self, key: str) -> None:
        """Zaehlt einen Versuch und wirft bei Ueberschreitung ``RateLimitError``."""
        now = time.monotonic()
        with self._lock:
            self._sweep(now)
            bucket = self._hits[key]
            while bucket and now - bucket[0] > self.window:
                bucket.popleft()
            if len(bucket) >= self.limit:
                retry_after = int(self.window - (now - bucket[0])) + 1
                raise RateLimitError(
                    code="error.rate_limited", details={"retry_after_seconds": retry_after}
                )
            bucket.append(now)

    def tracked_keys(self) -> int:
        """Anzahl verwalteter Schluessel - fuer Tests und Diagnose."""
        with self._lock:
            return len(self._hits)

    def reset(self, key: str) -> None:
        with self._lock:
            self._hits.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._hits.clear()
