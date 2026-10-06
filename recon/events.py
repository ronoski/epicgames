"""Append-only event log — the source of truth (``docs/SPEC.md`` §4.1).

The graph and every per-run diff are projections of this ordered, idempotent log. Events
are persisted as JSONL so a run is fully replayable and auditable. Re-applying an event
with the same ``idempotency_key`` is a no-op.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Iterator

from . import clock

EVENT_KINDS = {
    "scope_snapshot_taken", "scope_drift_detected", "scope_binding_set",
    "gate_decision_recorded", "rate_debit", "third_party_debit",
    "evidence_captured",
    "node_upserted", "edge_upserted", "contradiction_forked",
    "coverage_updated", "gap_enqueued", "gap_dispatched",
    "hypothesis_raised", "hypothesis_promoted", "hypothesis_decayed",
    "invariant_violation", "loop_halted",
}


def _next_seq(path: Path) -> int:
    """One past the highest ``seq`` already in the log file (0 for a new log)."""

    if not path.exists():
        return 0
    highest = -1
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                highest = max(highest, int(json.loads(line).get("seq", -1)))
            except (json.JSONDecodeError, TypeError, ValueError):
                continue
    except OSError:
        return 0
    return highest + 1


@dataclass
class Event:
    seq: int
    ts: str
    run_id: str
    kind: str
    payload: dict[str, Any]
    cycle: int = 0
    actor: str = "autonomous_loop"
    idempotency_key: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class EventLog:
    def __init__(self, path: str | Path | None = None, run_id: str = "run") -> None:
        self.run_id = run_id
        self.path = Path(path) if path else None
        self._events: list[Event] = []
        self._seen_keys: set[str] = set()
        # Sequence numbers must CONTINUE an existing log, not restart at 0. Restarting
        # gave every run overlapping seqs, so ordering by seq interleaved runs wrongly and
        # a replay could apply a later run's event before the earlier one that created the
        # node it refers to. The log is append-only across runs, so the counter is too.
        self._seq_offset = 0
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._seq_offset = _next_seq(self.path)

    def append(
        self,
        kind: str,
        payload: dict[str, Any],
        *,
        cycle: int = 0,
        actor: str = "autonomous_loop",
        idempotency_key: str = "",
        ts: str | None = None,
    ) -> Event | None:
        if kind not in EVENT_KINDS:
            raise ValueError(f"unknown event kind {kind!r}")
        if idempotency_key and idempotency_key in self._seen_keys:
            return None  # idempotent no-op
        evt = Event(
            seq=self._seq_offset + len(self._events),
            ts=ts or clock.iso(),
            run_id=self.run_id,
            kind=kind,
            payload=payload,
            cycle=cycle,
            actor=actor,
            idempotency_key=idempotency_key,
        )
        self._events.append(evt)
        if idempotency_key:
            self._seen_keys.add(idempotency_key)
        if self.path:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(evt.to_dict(), sort_keys=True) + "\n")
        return evt

    def all(self) -> list[Event]:
        return list(self._events)

    def by_kind(self, kind: str) -> Iterator[Event]:
        return (e for e in self._events if e.kind == kind)

    @classmethod
    def replay(cls, path: str | Path) -> list[Event]:
        events: list[Event] = []
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            if line.strip():
                events.append(Event(**json.loads(line)))
        return events
