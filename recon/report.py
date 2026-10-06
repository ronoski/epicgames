"""Per-run deltas from the event log (``docs/SPEC.md`` §4.1).

For a target worked over months the headline is not "we know about 412 hosts", it is
"since the last run: 3 new subdomains, 1 newly-open port, 2 new endpoints, and a takeover
candidate appeared". Totals go stale as a thing to read; a delta is always news.

Because the event log is the source of truth and is append-only and ordered, the delta is
a *projection* of it rather than a separate bookkeeping path that could disagree with the
graph. Nothing here recomputes state by guesswork.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from .events import Event, EventLog

#: Hypothesis kinds worth calling out by name in a delta — a takeover candidate appearing
#: is the single most actionable thing a passive sweep can surface.
NOTABLE_HYPOTHESES = {
    "dangling-cname": "subdomain-takeover candidate",
    "dns-candidate": "unconfirmed hostname candidate",
}


@dataclass
class RunDelta:
    run_id: str = ""
    first_ts: str = ""
    last_ts: str = ""
    nodes_created: dict[str, int] = field(default_factory=dict)
    nodes_merged: dict[str, int] = field(default_factory=dict)
    edges_created: dict[str, int] = field(default_factory=dict)
    forks: list[str] = field(default_factory=list)
    gaps_dispatched: int = 0
    refusals: list[dict] = field(default_factory=list)
    violations: list[dict] = field(default_factory=list)
    halted_because: str = ""
    rate_spend: dict[str, float] = field(default_factory=dict)
    third_party_spend: dict[str, float] = field(default_factory=dict)
    notable: list[dict] = field(default_factory=list)
    scope_drift: list[dict] = field(default_factory=list)

    @property
    def is_quiet(self) -> bool:
        """True when the run learned nothing new — worth saying so explicitly."""

        return not (self.nodes_created or self.edges_created or self.forks
                    or self.notable or self.scope_drift)

    def to_dict(self) -> dict:
        return {
            "headline": self.headline(),
            "run_id": self.run_id,
            "window": {"first": self.first_ts, "last": self.last_ts},
            "new": self.nodes_created,
            "merged": self.nodes_merged,
            "new_edges": self.edges_created,
            "forks": self.forks,
            "notable": self.notable,
            "scope_drift": self.scope_drift,
            "gaps_dispatched": self.gaps_dispatched,
            "refusals": self.refusals,
            "violations": self.violations,
            "halted_because": self.halted_because,
            "rate_spend": self.rate_spend,
            "third_party_spend": self.third_party_spend,
            "quiet": self.is_quiet,
        }

    def headline(self) -> str:
        """One line a human (or an AI session) can read without unpacking the JSON."""

        if self.scope_drift:
            return "SCOPE DRIFT detected — re-bind before acting"
        if self.violations:
            return f"HALTED on a safety invariant ({self.violations[0].get('code', '?')})"
        if self.is_quiet:
            return "no change since the previous run"
        bits = [f"{n} new {t}" for t, n in sorted(self.nodes_created.items())]
        if self.forks:
            bits.append(f"{len(self.forks)} contradiction(s) forked")
        for item in self.notable:
            bits.append(item["what"])
        return "; ".join(bits)


def _bump(d: dict, key: str, by: float = 1) -> None:
    d[key] = d.get(key, 0) + by


def _hypothesis_kind(node_id: str) -> str:
    parts = node_id.split(":")
    return parts[1] if node_id.startswith("hyp:") and len(parts) >= 3 else ""


def delta_for(events: list[Event]) -> RunDelta:
    """Fold a list of events into one delta."""

    d = RunDelta()
    if not events:
        return d
    ordered = sorted(events, key=lambda e: e.seq)
    d.run_id = ordered[0].run_id
    d.first_ts, d.last_ts = ordered[0].ts, ordered[-1].ts

    for evt in ordered:
        p = evt.payload
        if evt.kind == "node_upserted":
            if p.get("outcome") == "created":
                _bump(d.nodes_created, p.get("type", "?"))
                kind = _hypothesis_kind(p.get("id", ""))
                if kind in NOTABLE_HYPOTHESES:
                    d.notable.append({
                        "what": NOTABLE_HYPOTHESES[kind],
                        "id": p.get("id", ""),
                        "kind": kind,
                    })
            else:
                _bump(d.nodes_merged, p.get("type", "?"))
        elif evt.kind == "edge_upserted":
            if p.get("outcome") == "created":
                _bump(d.edges_created, p.get("type", "?"))
        elif evt.kind == "contradiction_forked":
            d.forks.append(p.get("id", ""))
        elif evt.kind == "gap_dispatched":
            d.gaps_dispatched += 1
        elif evt.kind == "gate_decision_recorded" and p.get("decision") == "REFUSE":
            d.refusals.append({"value": p.get("value", ""), "verb": p.get("verb", ""),
                               "reason": p.get("reason", "")})
        elif evt.kind == "rate_debit":
            _bump(d.rate_spend, p.get("target", "?"))
        elif evt.kind == "third_party_debit":
            _bump(d.third_party_spend, p.get("source", "?"))
        elif evt.kind == "invariant_violation":
            d.violations.append({"code": p.get("code", ""), "detail": p.get("detail", "")})
        elif evt.kind == "loop_halted":
            d.halted_because = p.get("reason", "")
        elif evt.kind == "scope_drift_detected":
            d.scope_drift.append(p)
    return d


def run_ids(events: list[Event]) -> list[str]:
    """Run ids in the order they first appear."""

    seen: list[str] = []
    for evt in sorted(events, key=lambda e: e.seq):
        if evt.run_id not in seen:
            seen.append(evt.run_id)
    return seen


def per_run(events: list[Event]) -> list[RunDelta]:
    """One delta per run, oldest first."""

    buckets: dict[str, list[Event]] = {}
    for evt in events:
        buckets.setdefault(evt.run_id, []).append(evt)
    return [delta_for(buckets[rid]) for rid in run_ids(events)]


def delta_since(
    events: list[Event],
    *,
    run_id: str | None = None,
    since_ts: str | None = None,
) -> RunDelta:
    """The delta over everything after ``run_id`` (exclusive) or after ``since_ts``.

    With neither, the most recent run's delta is returned — the common "what did the last
    run find?" question.
    """

    ordered = sorted(events, key=lambda e: e.seq)
    if run_id:
        ids = run_ids(ordered)
        if run_id in ids:
            cutoff = ids.index(run_id)
            wanted = set(ids[cutoff + 1:])
            return delta_for([e for e in ordered if e.run_id in wanted])
        return delta_for(ordered)
    if since_ts:
        return delta_for([e for e in ordered if e.ts > since_ts])
    runs = per_run(ordered)
    return runs[-1] if runs else RunDelta()


def load_events(path) -> list[Event]:
    return EventLog.replay(path)
