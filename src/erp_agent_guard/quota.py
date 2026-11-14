"""Per-agent rate limits: a sliding one-minute window for calls and a
rolling 24-hour window for committed writes. In-process only."""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque

from .errors import QuotaExceeded


class QuotaTracker:
    def __init__(self, clock=time.monotonic):
        self._clock = clock
        self._lock = threading.Lock()
        self._calls: dict[str, deque] = defaultdict(deque)
        self._writes: dict[str, deque] = defaultdict(deque)

    @staticmethod
    def _trim(q: deque, now: float, window: float) -> None:
        while q and now - q[0] >= window:
            q.popleft()

    def check_call(self, agent: str, per_minute: int) -> None:
        with self._lock:
            now = self._clock()
            q = self._calls[agent]
            self._trim(q, now, 60.0)
            if len(q) >= per_minute:
                retry = 60.0 - (now - q[0])
                raise QuotaExceeded(f"rate limit: {per_minute} calls/minute for agent '{agent}'; retry in {retry:.0f}s")
            q.append(now)

    def check_write(self, agent: str, per_day: int, count: int = 1) -> None:
        with self._lock:
            now = self._clock()
            q = self._writes[agent]
            self._trim(q, now, 86400.0)
            if len(q) + count > per_day:
                raise QuotaExceeded(f"write quota: {per_day} record writes/day for agent '{agent}' ({len(q)} used)")

    def record_write(self, agent: str, count: int = 1) -> None:
        with self._lock:
            now = self._clock()
            self._writes[agent].extend([now] * count)
