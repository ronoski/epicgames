"""One unified per-target rate-budget ledger (``docs/safety-model.md`` §4).

Every active verb across every domain debits ONE authoritative token bucket per target.
The ledger is keyed by registrable domain / apex / bucket-name / authoritative-NS — never
by a shared IP (one CDN IP fronts many tenants). It fails closed: a debit that would drive
a per-target budget negative raises :class:`RateBudgetExceeded` and is never silently
allowed. All debits are appended to an auditable log.

This is a non-intrusive, good-citizen control: programs cap request rates and hammering a
target risks a denial of service, which is out of scope for essentially every program.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

from .scope import registrable_domain


@dataclass
class LedgerEntry:
    target: str
    verb: str
    cost: float
    at: float  # monotonic timestamp
    balance_after: float


class RateBudgetExceeded(RuntimeError):
    def __init__(self, target: str, needed: float, available: float) -> None:
        super().__init__(
            f"rate budget exceeded for {target!r}: need {needed}, have {available:.2f}"
        )
        self.target = target


class RateLedger:
    """Thread-safe unified per-target token bucket with an append-only audit log.

    ``global_qps`` is the refill rate (tokens/sec) applied per target; ``capacity`` is the
    burst ceiling. A monotonic clock is injected for deterministic tests.
    """

    def __init__(
        self,
        global_qps: float = 2.0,
        capacity: float | None = None,
        *,
        clock=None,
    ) -> None:
        import time as _time

        self.global_qps = float(global_qps)
        self.capacity = float(capacity if capacity is not None else max(global_qps, 1.0))
        self._clock = clock or _time.monotonic
        self._tokens: dict[str, float] = {}
        self._updated: dict[str, float] = {}
        self._locks: dict[str, threading.Lock] = {}
        self._master = threading.Lock()
        self.log: list[LedgerEntry] = []

    def target_key(self, value: str) -> str:
        return registrable_domain(value)

    def _lock_for(self, target: str) -> threading.Lock:
        with self._master:
            return self._locks.setdefault(target, threading.Lock())

    def _refill(self, target: str, now: float) -> None:
        last = self._updated.get(target, now)
        elapsed = max(0.0, now - last)
        self._tokens[target] = min(
            self.capacity,
            self._tokens.get(target, self.capacity) + elapsed * self.global_qps,
        )
        self._updated[target] = now

    def balance(self, value: str) -> float:
        target = self.target_key(value)
        with self._lock_for(target):
            self._refill(target, self._clock())
            return self._tokens.get(target, self.capacity)

    def debit(self, value: str, verb: str, cost: float = 1.0) -> LedgerEntry:
        """Debit the budget for ``value``'s target. Fail closed if insufficient."""

        target = self.target_key(value)
        with self._lock_for(target):
            now = self._clock()
            self._refill(target, now)
            available = self._tokens.get(target, self.capacity)
            if available < cost:
                raise RateBudgetExceeded(target, cost, available)
            self._tokens[target] = available - cost
            entry = LedgerEntry(target, verb, cost, now, self._tokens[target])
            self.log.append(entry)
            return entry
