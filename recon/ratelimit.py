"""A small thread-safe token-bucket rate limiter.

Being a good citizen matters for authorized testing: programs frequently cap
request rates, and hammering a target is both rude and a good way to get
yourself banned (or to cause a denial of service, which is out of scope for
essentially every bug-bounty program). Active modules acquire a token before
each network request.
"""

from __future__ import annotations

import threading
import time


class RateLimiter:
    """Token bucket allowing ``rate`` events per second with burst ``capacity``.

    A ``rate`` of 0 or less disables limiting (every acquire returns at once).
    """

    def __init__(self, rate: float, capacity: float | None = None) -> None:
        self.rate = float(rate)
        self.capacity = float(capacity if capacity is not None else max(rate, 1))
        self._tokens = self.capacity
        self._updated = time.monotonic()
        self._lock = threading.Lock()

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._updated
        self._updated = now
        self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)

    def acquire(self, tokens: float = 1.0) -> float:
        """Block until ``tokens`` are available. Returns seconds waited."""

        if self.rate <= 0:
            return 0.0
        waited = 0.0
        while True:
            with self._lock:
                self._refill()
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return waited
                deficit = tokens - self._tokens
                sleep_for = deficit / self.rate
            time.sleep(sleep_for)
            waited += sleep_for
