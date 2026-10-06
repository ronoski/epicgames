"""Coverage model and the gap-queue scheduler (``docs/SPEC.md`` §4.2–4.3).

Coverage is a weighted score over per-entity signals, not a boolean. The gap queue ranks
work by ``priority = value × staleness × confidence_deficit ÷ cost`` and is the scheduler
for the autonomous loop. Human-gated gaps are flagged and never auto-dispatched.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .models import Node

# Weighted coverage signals shared across node types (domain docs add more).
COVERAGE_WEIGHTS = {
    "enumerated": 0.15,
    "fingerprinted": 0.20,
    "param_mined": 0.25,
    "flow_mapped": 0.25,
    "artifact_correlated": 0.15,
}


def coverage_score(node: Node) -> float:
    total = sum(COVERAGE_WEIGHTS.values())
    got = sum(w for k, w in COVERAGE_WEIGHTS.items() if node.coverage.get(k))
    return got / total if total else 0.0


_DUR = re.compile(
    r"P(?:(?P<d>\d+)D)?(?:T(?:(?P<h>\d+)H)?(?:(?P<m>\d+)M)?(?:(?P<s>\d+)S)?)?"
)


def parse_duration(iso: str) -> timedelta:
    m = _DUR.fullmatch(iso or "P14D")
    if not m:
        return timedelta(days=14)
    d, h, mi, s = (int(m.group(x) or 0) for x in ("d", "h", "m", "s"))
    return timedelta(days=d, hours=h, minutes=mi, seconds=s)


def staleness(node: Node, now: datetime) -> float:
    """>= 1.0; grows as the fact ages past its decay half-life."""

    try:
        last = datetime.fromisoformat(node.temporal.last_verified)
    except ValueError:
        return 1.0
    half = parse_duration(node.temporal.decay_half_life).total_seconds()
    if half <= 0:
        return 1.0
    age = max(0.0, (now - last).total_seconds())
    return 1.0 + age / half


def confidence_deficit(node: Node) -> float:
    return max(0.0, 1.0 - node.confidence.probability)


@dataclass(order=True)
class Gap:
    priority: float
    id: str = field(compare=False)
    node_id: str = field(compare=False, default="")
    verb: str = field(compare=False, default="")
    module: str = field(compare=False, default="")
    passive: bool = field(compare=False, default=False)
    value: float = field(compare=False, default=1.0)
    cost: float = field(compare=False, default=1.0)
    human_gated: bool = field(compare=False, default=False)
    note: str = field(compare=False, default="")


def gap_priority(value: float, node: Node | None, cost: float, now: datetime) -> float:
    st = staleness(node, now) if node else 1.0
    cd = confidence_deficit(node) if node else 1.0
    return value * st * max(cd, 0.05) / max(cost, 0.01)


class GapQueue:
    def __init__(self) -> None:
        self._gaps: dict[str, Gap] = {}

    def enqueue(self, gap: Gap) -> None:
        # keep the higher-priority version if re-enqueued
        existing = self._gaps.get(gap.id)
        if existing is None or gap.priority > existing.priority:
            self._gaps[gap.id] = gap

    def __len__(self) -> int:
        return len(self._gaps)

    def ranked(self) -> list[Gap]:
        return sorted(self._gaps.values(), key=lambda g: g.priority, reverse=True)

    def pop_highest(self, *, auto_only: bool = True) -> Gap | None:
        """Pop the highest-priority gap. With ``auto_only`` skip human-gated gaps."""

        for gap in self.ranked():
            if auto_only and gap.human_gated:
                continue
            return self._gaps.pop(gap.id)
        return None

    def human_gated(self) -> list[Gap]:
        return [g for g in self.ranked() if g.human_gated]
