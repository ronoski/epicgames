"""The gap planner — what makes the loop autonomously *deep*.

The planner reads the current graph and derives the set of things that are **not yet
known**: a domain never enumerated, a hostname never resolved, a host never port-scanned, a
web app never fingerprinted, an API never contract-mapped, a fact past its decay half-life.
Each becomes a :class:`~recon.coverage.Gap` carrying the module + verb that would close it
and a priority from ``value × staleness × confidence_deficit ÷ cost``.

This is the "negative space" of the knowledge base: the loop does not follow a fixed
script, it repeatedly closes its own highest-value unknown. Depth emerges because closing
one gap (resolve a name) creates the next (scan the host → probe HTTP → read the OpenAPI
spec → type its parameters).

Rules are declarative so the ladder is auditable and easy to extend.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Callable

from .coverage import Gap, coverage_score, gap_priority, parse_duration, staleness
from .models import Node, Verdict
from .store import GraphStore


@dataclass(frozen=True)
class Rule:
    """A declarative gap rule.

    ``applies`` decides whether the node has this gap; ``module``/``verb`` say how to close
    it. ``value`` is the intrinsic worth of closing it; ``cost`` the expected expense.

    ``cooldown`` is the minimum time before the same gap may be dispatched again. It exists
    because a rule cannot always observe its own closure: a module may legitimately find
    *nothing* (no OIDC document, no archived URLs, every resolved address out of scope), and
    without a cooldown that gap would re-fire every cycle forever, re-spending active budget
    on a question already answered. A negative result is an answer.
    """

    key: str
    node_type: str
    module: str
    verb: str
    passive: bool
    value: float
    cost: float
    applies: Callable[[Node, GraphStore], bool]
    human_gated: bool = False
    cooldown: str = "P1D"


def _not_enumerated(n: Node, _s: GraphStore) -> bool:
    return not n.coverage.get("enumerated")


def _unresolved(n: Node, s: GraphStore) -> bool:
    return not s.has_out_edge(n.id, "resolves_to")


def _is_dns_candidate(n: Node, _s: GraphStore) -> bool:
    return n.id.startswith("hyp:dns-candidate:")


def _no_service(n: Node, s: GraphStore) -> bool:
    # Services point at the host via hosted_on, so look at inbound edges.
    return not s.in_edges(n.id, "hosted_on")


def _no_webapp(n: Node, s: GraphStore) -> bool:
    host = n.id.split(":", 1)[1] if ":" in n.id else n.id
    return not any(w.id.endswith("://" + host) for w in s.iter_type("WebApp"))


def _not_fingerprinted(n: Node, _s: GraphStore) -> bool:
    return not n.coverage.get("fingerprinted")


def _no_auth(n: Node, s: GraphStore) -> bool:
    return not s.has_out_edge(n.id, "authenticates_with")


def _no_typed_ops(n: Node, s: GraphStore) -> bool:
    """WebApp has nothing downstream whose parameters were mined.

    Walks two hops, because the real shape is WebApp -> Route -> Operation: looking only at
    the WebApp's direct ``exposes`` targets misses every Operation hanging off a Route and
    the gap would never observe its own closure.
    """

    for e in s.out_edges(n.id, "exposes"):
        tgt = s.get(e.to)
        if tgt is None:
            continue
        if tgt.coverage.get("param_mined"):
            return False
        for e2 in s.out_edges(tgt.id, "exposes"):
            deep = s.get(e2.to)
            if deep is not None and deep.coverage.get("param_mined"):
                return False
    return True


# Ordered roughly passive-first, shallow-to-deep. Depth comes from the chain:
# enumerate -> resolve -> scan -> probe -> fingerprint -> auth model -> API contract.
RULES: list[Rule] = [
    # --- passive breadth -------------------------------------------------
    Rule("enumerate-ct", "Domain", "crtsh", "passive-collect", True, 5.0, 1.0, _not_enumerated),
    Rule("enumerate-ct-host", "DNSName", "crtsh", "passive-collect", True, 3.0, 1.0, _not_enumerated),
    Rule("archive-mine", "Domain", "wayback", "passive-collect", True, 2.5, 1.0,
         lambda n, s: not n.coverage.get("artifact_correlated")),
    Rule("generate-candidates", "DNSName", "permutations", "enumerate", True, 1.5, 0.5,
         lambda n, s: n.coverage.get("enumerated") and not n.attrs.get("permuted")),
    # --- active ladder ---------------------------------------------------
    Rule("confirm-candidate", "Hypothesis", "resolver", "resolve", False, 2.0, 1.0, _is_dns_candidate),
    Rule("resolve-name", "DNSName", "resolver", "resolve", False, 4.0, 1.0, _unresolved),
    Rule("scan-host", "Host", "port_scan", "port-scan", False, 2.0, 3.0, _no_service),
    Rule("probe-http", "DNSName", "http_probe", "http-HEAD", False, 4.0, 1.5, _no_webapp),
    Rule("tls-fingerprint", "WebApp", "tls_probe", "tls-handshake", False, 3.0, 1.5,
         _not_fingerprinted),
    Rule("auth-model", "WebApp", "oidc_discovery", "http-GET", False, 5.0, 1.5, _no_auth),
    Rule("api-contract", "WebApp", "openapi_discovery", "read-openapi", False, 6.0, 2.0, _no_typed_ops),
    Rule("graphql-contract", "WebApp", "graphql_introspect", "graphql-introspect", False, 6.0, 2.0,
         _no_typed_ops),
]

# Facts past their decay half-life get re-verified by the module that produced them.
REVERIFY_AFTER_HALFLIVES = 2.0


def dispatch_history(log) -> dict[str, datetime]:
    """Map gap id -> last dispatch time, read back from the event log.

    The log is the source of truth, so this survives process restarts and makes cooldowns
    work across runs rather than only within one loop.
    """

    out: dict[str, datetime] = {}
    for evt in getattr(log, "all", list)():
        if evt.kind != "gap_dispatched":
            continue
        gap_id = evt.payload.get("id")
        if not gap_id:
            continue
        try:
            ts = datetime.fromisoformat(evt.ts)
        except (ValueError, TypeError):
            continue
        prev = out.get(gap_id)
        if prev is None or ts > prev:
            out[gap_id] = ts
    return out


def plan(
    store: GraphStore,
    now: datetime,
    *,
    allow_active: bool = False,
    include_prefilter: bool = False,
    dispatched: dict[str, datetime] | None = None,
) -> list[Gap]:
    """Derive the current gap set from the graph.

    Only ``in_scope`` nodes generate gaps. ``prefilter_only`` nodes are deliberately
    excluded (owned-but-unlisted assets never drive work) unless explicitly requested for
    reporting, and even then never for an active rule. Gaps dispatched more recently than
    their rule's cooldown are suppressed (see :class:`Rule`).
    """

    dispatched = dispatched or {}
    gaps: list[Gap] = []
    for node in list(store.nodes.values()):
        actionable = node.scope_binding.verdict == Verdict.IN_SCOPE
        if not actionable and not (include_prefilter
                                   and node.scope_binding.verdict == Verdict.PREFILTER_ONLY):
            continue
        for rule in RULES:
            if rule.node_type != node.type:
                continue
            if not rule.passive and not (allow_active and actionable):
                continue  # active work needs active enabled AND an in-scope verdict
            try:
                if not rule.applies(node, store):
                    continue
            except Exception:  # a malformed node must not break planning
                continue
            gap_id = f"{rule.key}:{node.id}"
            last = dispatched.get(gap_id)
            if last is not None and (now - last) < parse_duration(rule.cooldown):
                continue  # already answered recently; a negative result is an answer
            gaps.append(Gap(
                priority=gap_priority(rule.value, node, rule.cost, now),
                id=gap_id,
                node_id=node.id,
                verb=rule.verb,
                module=rule.module,
                passive=rule.passive,
                value=rule.value,
                cost=rule.cost,
                human_gated=rule.human_gated,
                note=f"{rule.key} on {node.type}",
            ))

        # Re-verification gap for stale facts.
        if actionable and staleness(node, now) > 1.0 + REVERIFY_AFTER_HALFLIVES:
            gaps.append(Gap(
                priority=gap_priority(1.0, node, 2.0, now),
                id=f"reverify:{node.id}",
                node_id=node.id,
                verb="passive-collect",
                module="",  # resolved from provenance at dispatch
                passive=True,
                note=f"stale beyond {REVERIFY_AFTER_HALFLIVES} half-lives",
            ))
    return gaps


def seeds_for(gap: Gap, store: GraphStore) -> list:
    """The seed list handed to the module closing ``gap``."""

    node = store.get(gap.node_id)
    return [node] if node is not None else []


def coverage_report(store: GraphStore) -> dict:
    """Aggregate coverage by node type — the 'how much do we know' view."""

    out: dict[str, dict] = {}
    for node in store.nodes.values():
        bucket = out.setdefault(node.type, {"count": 0, "coverage_sum": 0.0})
        bucket["count"] += 1
        bucket["coverage_sum"] += coverage_score(node)
    for bucket in out.values():
        bucket["coverage_avg"] = round(bucket["coverage_sum"] / bucket["count"], 3)
        del bucket["coverage_sum"]
    return out
