"""The graph projection and the write facade (``docs/SPEC.md`` §2, §3.3).

:class:`GraphStore` is an in-memory projection keyed by deterministic node/edge id (so it
is rebuildable from the event log). :class:`Graph` is the write facade: it turns an upsert
into an event, appends it, and applies it. On re-observation it **dedupes by id and merges**
(provenance union + log-odds corroboration + evidence union + temporal refresh + coverage
union). A conflicting scalar attribute is a **contradiction** that **forks** a competing
node, never an overwrite.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator

from . import clock
from .events import EventLog
from .models import (
    Confidence, Datum, Edge, Node, Provenance, ProvStep, ScopeBinding,
)

# Default independent-source corroboration bump, in log-odds.
CORROBORATION_DELTA = 0.8


def _sources(d: Datum) -> set[tuple[str, str]]:
    """The distinct (tool, rule) pairs that produced this datum.

    Independence is keyed on tool AND rule: re-running the *same* extractor over the same
    artifact is not a second opinion, so it must not raise confidence.
    """

    return {(s.tool, s.rule_id) for s in d.provenance.chain}


def _rebuild_datum(kind: str, data: dict) -> Datum:
    # Reconstruct a Node/Edge from a stored dict (used on replay). Kept lenient.
    cls = Node if kind == "node" else Edge
    prov = Provenance(chain=[ProvStep(**s) for s in data.get("provenance", {}).get("chain", [])])
    # Confidence/temporal/scope_binding are reconstructed by the models' own types.
    from .models import Confidence as C, Temporal, ScopeBinding, Penalty, EvidenceRef, Sensitivity
    conf_d = data.get("confidence", {})
    conf = C(
        log_odds=conf_d.get("log_odds", 0.0),
        independent_sources=conf_d.get("independent_sources", 1),
        penalties=[Penalty(**p) for p in conf_d.get("penalties", [])],
        forked_from=conf_d.get("forked_from"),
    )
    temporal = Temporal(**data["temporal"])
    sb = data["scope_binding"]
    scope_binding = ScopeBinding(verdict=sb["verdict"], snapshot_id=sb["snapshot_id"],
                                 observed_at=sb["observed_at"], rule_matched=sb.get("rule_matched", ""))
    common = dict(
        id=data["id"], type=data["type"], provenance=prov, confidence=conf,
        temporal=temporal, scope_binding=scope_binding, attrs=data.get("attrs", {}),
        evidence=[EvidenceRef(**e) for e in data.get("evidence", [])],
        sensitivity=Sensitivity(data.get("sensitivity", "S0")),
        coverage=data.get("coverage", {}), data_subject=data.get("data_subject", "none"),
    )
    if kind == "edge":
        return Edge(frm=data.get("frm", ""), to=data.get("to", ""), **common)
    return Node(**common)


@dataclass
class UpsertResult:
    outcome: str  # "created" | "merged" | "forked"
    id: str


class GraphStore:
    def __init__(self) -> None:
        self.nodes: dict[str, Node] = {}
        self.edges: dict[str, Edge] = {}

    # --- merge ---------------------------------------------------------
    def _merge(self, existing: Datum, incoming: Datum) -> str:
        """Return the final id; merges in place, or forks on contradiction."""

        conflict_key = self._conflicting_attr(existing.attrs, incoming.attrs)
        if conflict_key is not None:
            return self._fork(existing, incoming, conflict_key)

        # Non-conflicting: union attrs, provenance, evidence; corroborate; refresh time.
        for k, v in incoming.attrs.items():
            existing.attrs.setdefault(k, v)
        # Corroborate ONLY on a genuinely new, independent source. Re-observing the same
        # fact with the same tool+rule must not inflate confidence — otherwise a guess
        # would promote itself just by being re-run.
        new_sources = _sources(incoming) - _sources(existing)
        existing.provenance.merge(incoming.provenance)
        existing.evidence.extend(
            e for e in incoming.evidence
            if e.sha256 not in {x.sha256 for x in existing.evidence}
        )
        if new_sources:
            existing.confidence.corroborate(CORROBORATION_DELTA)
        existing.temporal.last_seen = incoming.temporal.last_seen
        existing.temporal.last_verified = incoming.temporal.last_verified
        existing.coverage.update({k: True for k, v in incoming.coverage.items() if v})
        return existing.id

    @staticmethod
    def _conflicting_attr(a: dict, b: dict) -> str | None:
        for k in set(a) & set(b):
            av, bv = a[k], b[k]
            if av in (None, "", [], {}) or bv in (None, "", [], {}):
                continue
            if isinstance(av, (dict, list)) or isinstance(bv, (dict, list)):
                continue
            if av != bv:
                return k
        return None

    def _fork(self, existing: Datum, incoming: Datum, key: str) -> str:
        n = sum(1 for i in self.nodes if i.startswith(existing.id + "#fork"))
        fork_id = f"{existing.id}#fork{n + 1}"
        incoming.id = fork_id
        incoming.confidence.forked_from = existing.id
        if isinstance(incoming, Edge):
            self.edges[fork_id] = incoming
        else:
            self.nodes[fork_id] = incoming  # type: ignore[assignment]
        return fork_id

    # --- apply ---------------------------------------------------------
    def apply_node(self, node: Node) -> UpsertResult:
        if node.id not in self.nodes:
            self.nodes[node.id] = node
            return UpsertResult("created", node.id)
        final = self._merge(self.nodes[node.id], node)
        return UpsertResult("forked" if "#fork" in final else "merged", final)

    def apply_edge(self, edge: Edge) -> UpsertResult:
        if edge.id not in self.edges:
            self.edges[edge.id] = edge
            return UpsertResult("created", edge.id)
        final = self._merge(self.edges[edge.id], edge)
        return UpsertResult("forked" if "#fork" in final else "merged", final)

    # --- queries -------------------------------------------------------
    def get(self, node_id: str) -> Node | None:
        return self.nodes.get(node_id)

    def iter_type(self, type_: str) -> Iterator[Node]:
        return (n for n in self.nodes.values() if n.type == type_)

    def out_edges(self, node_id: str, type_: str | None = None) -> list[Edge]:
        return [
            e for e in self.edges.values()
            if e.frm == node_id and (type_ is None or e.type == type_)
        ]

    def in_edges(self, node_id: str, type_: str | None = None) -> list[Edge]:
        return [
            e for e in self.edges.values()
            if e.to == node_id and (type_ is None or e.type == type_)
        ]

    def has_out_edge(self, node_id: str, type_: str) -> bool:
        return any(e.frm == node_id and e.type == type_ for e in self.edges.values())

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for n in self.nodes.values():
            out[n.type] = out.get(n.type, 0) + 1
        return out

    # --- replay --------------------------------------------------------
    @classmethod
    def from_events(cls, events) -> "GraphStore":
        """Rebuild the projection by replaying the log (``SPEC.md`` §4.1).

        Events are applied in ``seq`` order with the same merge/fork logic as a live run,
        so a replayed store is identical to the one the run produced. An event from an
        older schema that carries no datum is skipped rather than guessed at — a partial
        replay that silently invents nodes would be worse than an incomplete one.
        """

        store = cls()
        skipped = 0
        for evt in sorted(events, key=lambda e: e.seq):
            if evt.kind in ("node_upserted", "contradiction_forked") and evt.payload.get("node"):
                store.apply_node(_rebuild_datum("node", evt.payload["node"]))
            elif evt.kind in ("edge_upserted", "contradiction_forked") and evt.payload.get("edge"):
                store.apply_edge(_rebuild_datum("edge", evt.payload["edge"]))
            elif evt.kind == "scope_binding_set" and evt.payload.get("binding"):
                # A re-bind is a real state change (scope drift moved an asset), so replay
                # must apply it; otherwise the rebuilt graph asserts a superseded verdict.
                target = store.nodes.get(evt.payload.get("id", ""))
                if target is not None:
                    b = evt.payload["binding"]
                    target.scope_binding = ScopeBinding(
                        verdict=b["verdict"], snapshot_id=b["snapshot_id"],
                        observed_at=b["observed_at"], rule_matched=b.get("rule_matched", ""),
                    )
            elif evt.kind in ("node_upserted", "edge_upserted", "contradiction_forked"):
                skipped += 1
        store.replay_skipped = skipped  # type: ignore[attr-defined]
        return store


class Graph:
    """Write facade: upsert -> event -> apply. The event log stays the source of truth.

    The upsert events carry the **whole datum**, not just its id. That is what makes the
    log authoritative rather than merely a trace: :meth:`GraphStore.from_events` can
    rebuild an identical projection from it (see ``recon replay``). Logging only
    ``{id, type, outcome}`` would have left the graph unreconstructable and the
    event-sourcing claim in ``SPEC.md`` §4.1 unprovable.
    """

    def __init__(self, log: EventLog | None = None, store: GraphStore | None = None) -> None:
        self.log = log or EventLog()
        self.store = store or GraphStore()

    @staticmethod
    def _observation_key(prefix: str, datum_id: str, datum: Datum) -> str:
        """Idempotency key for ONE observation of a datum.

        It must include the observing source. Keying on ``(id, last_seen)`` alone dropped
        a second observation of the same node by a *different* module within the same
        timestamp — which is exactly the independent corroboration the confidence model
        depends on. The log then lost information the live store had used, and a replay
        diverged from the run it was supposed to reproduce.
        """

        sources = ",".join(sorted(f"{s.tool}@{s.rule_id}" for s in datum.provenance.chain))
        return f"{prefix}:{datum_id}:{datum.temporal.last_seen}:{sources}"

    def upsert_node(self, node: Node) -> UpsertResult:
        # Snapshot the datum as submitted, BEFORE the store merges it in place: replay
        # must see the same inputs in the same order, not the merged outcome.
        payload = node.to_dict()
        result = self.store.apply_node(node)
        # Key on the RESULTING id, after apply: a contradiction fork yields a new id
        # ("...#fork1"), so keying on the submitted id would have deduped the fork event
        # away and the log would have lost the record of the contradiction entirely.
        key = self._observation_key("node", result.id, node)
        kind = "contradiction_forked" if result.outcome == "forked" else "node_upserted"
        self.log.append(kind, {"id": result.id, "type": node.type,
                               "outcome": result.outcome, "node": payload},
                        idempotency_key=key)
        return result

    def upsert_edge(self, edge: Edge) -> UpsertResult:
        payload = edge.to_dict()
        result = self.store.apply_edge(edge)
        key = self._observation_key("edge", result.id, edge)
        kind = "contradiction_forked" if result.outcome == "forked" else "edge_upserted"
        self.log.append(kind, {"id": result.id, "type": edge.type,
                               "outcome": result.outcome, "edge": payload},
                        idempotency_key=key)
        return result
