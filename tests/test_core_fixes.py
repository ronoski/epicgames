"""Regression tests for defects the module implementations surfaced in the core."""

from datetime import datetime, timedelta, timezone

import pytest

from recon import planner, verbs
from recon.events import EventLog
from recon.factory import make_node, make_edge
from recon.models import Provenance, ProvStep, ScopeBinding, Verdict
from recon.ratelimit import RateLedger
from recon.store import Graph, GraphStore

NOW = datetime(2026, 1, 10, tzinfo=timezone.utc)


def binding(v=Verdict.IN_SCOPE, snap="snap1"):
    return ScopeBinding(verdict=v, snapshot_id=snap, observed_at="2026-01-10T00:00:00+00:00")


def node(nid, source, rule="default", ntype="DNSName", attrs=None):
    return make_node(ntype, nid, binding=binding(), source=source, rule_id=rule,
                     now=NOW, attrs=attrs or {})


# --- store: independence is actually checked ---------------------------
def test_same_tool_rerun_does_not_inflate_confidence():
    """Re-running the same extractor is not a second opinion."""

    g = Graph()
    g.upsert_node(node("dns:a.epicgames.com", "crtsh"))
    first = g.store.get("dns:a.epicgames.com").confidence.log_odds
    g.upsert_node(node("dns:a.epicgames.com", "crtsh"))  # same tool + rule
    g.upsert_node(node("dns:a.epicgames.com", "crtsh"))
    after = g.store.get("dns:a.epicgames.com")
    assert after.confidence.log_odds == first
    assert after.confidence.independent_sources == 1


def test_genuinely_new_source_still_corroborates():
    g = Graph()
    g.upsert_node(node("dns:b.epicgames.com", "crtsh"))
    before = g.store.get("dns:b.epicgames.com").confidence.log_odds
    g.upsert_node(node("dns:b.epicgames.com", "resolver"))
    after = g.store.get("dns:b.epicgames.com")
    assert after.confidence.log_odds > before
    assert after.confidence.independent_sources == 2


def test_same_tool_different_rule_counts_as_new_evidence():
    g = Graph()
    g.upsert_node(node("dns:c.epicgames.com", "crtsh", rule="ct-name"))
    before = g.store.get("dns:c.epicgames.com").confidence.log_odds
    g.upsert_node(node("dns:c.epicgames.com", "crtsh", rule="san-pivot"))
    assert g.store.get("dns:c.epicgames.com").confidence.log_odds > before


# --- verbs: the TLS handshake verb exists and is active ----------------
def test_tls_handshake_is_allowed_and_active():
    verbs.assert_schedulable("tls-handshake")
    assert verbs.is_active("tls-handshake")


def test_fingerprint_stays_non_active():
    """fingerprint can be computed from stored evidence, so it is not a traffic verb."""

    verbs.assert_schedulable("fingerprint")
    assert not verbs.is_active("fingerprint")


def test_planner_tls_rule_uses_an_active_verb():
    """The scheduled verb must be one a module can actually spend through the gate."""

    rule = next(r for r in planner.RULES if r.key == "tls-fingerprint")
    verbs.assert_schedulable(rule.verb)
    assert verbs.is_active(rule.verb), "planner would schedule a verb the gate always refuses"


def test_every_active_planner_rule_schedules_a_spendable_verb():
    for rule in planner.RULES:
        verbs.assert_schedulable(rule.verb)
        if not rule.passive:
            assert verbs.is_active(rule.verb), f"rule {rule.key} schedules a non-active verb"


# --- planner: two-hop operation detection -----------------------------
def test_api_contract_gap_closes_via_route_then_operation():
    """WebApp -> Route -> Operation: the Operation is two hops away."""

    store = GraphStore()
    web = make_node("WebApp", "web:https://api.epicgames.com", binding=binding(),
                    source="http_probe", now=NOW, coverage={"fingerprinted": True})
    store.apply_node(web)
    assert planner._no_typed_ops(web, store) is True

    route = make_node("Route", "route:web:https://api.epicgames.com/v1/items",
                      binding=binding(), source="openapi", now=NOW)
    op = make_node("Operation", "op:GET:/v1/items", binding=binding(), source="openapi",
                   now=NOW, coverage={"param_mined": True})
    store.apply_node(route)
    store.apply_node(op)
    store.apply_edge(make_edge("exposes", web.id, route.id, binding=binding(),
                               source="openapi", now=NOW))
    store.apply_edge(make_edge("exposes", route.id, op.id, binding=binding(),
                               source="openapi", now=NOW))
    assert planner._no_typed_ops(web, store) is False


# --- planner: cooldown stops infinite re-fire -------------------------
def test_cooldown_suppresses_a_recently_dispatched_gap():
    store = GraphStore()
    store.apply_node(make_node("Domain", "domain:epicgames.com", binding=binding(),
                               source="seeds", now=NOW))
    gaps = planner.plan(store, NOW, allow_active=False)
    assert any(g.id == "enumerate-ct:domain:epicgames.com" for g in gaps)

    dispatched = {"enumerate-ct:domain:epicgames.com": NOW - timedelta(hours=1)}
    gaps2 = planner.plan(store, NOW, allow_active=False, dispatched=dispatched)
    assert not any(g.id == "enumerate-ct:domain:epicgames.com" for g in gaps2)


def test_cooldown_expires_and_the_gap_returns():
    store = GraphStore()
    store.apply_node(make_node("Domain", "domain:epicgames.com", binding=binding(),
                               source="seeds", now=NOW))
    dispatched = {"enumerate-ct:domain:epicgames.com": NOW - timedelta(days=3)}
    gaps = planner.plan(store, NOW, allow_active=False, dispatched=dispatched)
    assert any(g.id == "enumerate-ct:domain:epicgames.com" for g in gaps)


def test_dispatch_history_reads_back_from_the_event_log():
    log = EventLog()
    log.append("gap_dispatched", {"id": "enumerate-ct:domain:x", "module": "crtsh"},
               ts="2026-01-09T00:00:00+00:00")
    log.append("gap_dispatched", {"id": "enumerate-ct:domain:x", "module": "crtsh"},
               ts="2026-01-10T00:00:00+00:00")
    hist = planner.dispatch_history(log)
    assert hist["enumerate-ct:domain:x"] == datetime(2026, 1, 10, tzinfo=timezone.utc)


def test_loop_does_not_redispatch_within_cooldown(tmp_path):
    """A second run must not re-spend on a gap the first run already answered."""

    import logging
    from recon.evidence import EvidenceStore
    from recon.loop import AutonomousLoop
    from recon.modules.base import ModuleContext
    from recon.scope import Scope
    from recon.snapshot import take_snapshot

    snap = take_snapshot("p", now=NOW)
    store = GraphStore()
    store.apply_node(make_node("Domain", "domain:epicgames.com",
                               binding=binding(snap=snap.snapshot_id),
                               source="seeds", now=NOW))
    log = EventLog()
    ctx = ModuleContext(
        scope=Scope(include=["*.epicgames.com"]),
        ledger=RateLedger(global_qps=10.0, capacity=100.0),
        evidence=EvidenceStore(tmp_path), graph=Graph(log=log, store=store),
        snapshot=snap, logger=logging.getLogger("t"), allow_active=False, now=NOW,
    )
    first = AutonomousLoop(ctx, dry_run=True, max_cycles=5).run(now=NOW)
    dispatched_ids = {c.gap_id for c in first.cycles}
    assert dispatched_ids

    second = AutonomousLoop(ctx, dry_run=True, max_cycles=5).run(now=NOW)
    # same event log -> cooldown suppresses everything already dispatched
    assert not ({c.gap_id for c in second.cycles} & dispatched_ids)


# --- gate: explicit ledger key for IP targets -------------------------
def test_gate_active_charges_an_explicit_ledger_key(tmp_path):
    import logging
    from recon.evidence import EvidenceStore
    from recon.modules.base import ModuleContext
    from recon.scope import Scope
    from recon.snapshot import take_snapshot

    snap = take_snapshot("p", now=NOW)
    ledger = RateLedger(global_qps=10.0, capacity=100.0)
    ctx = ModuleContext(
        scope=Scope(include=["*.epicgames.com", "203.0.113.0/24"]),
        ledger=ledger, evidence=EvidenceStore(tmp_path), graph=Graph(),
        snapshot=snap, logger=logging.getLogger("t"), allow_active=True, now=NOW,
    )
    ctx.gate_active("203.0.113.5", "port-scan", ledger_key="api.epicgames.com")
    # the spend is charged to the owning target, not to the bare IP
    assert ledger.log[-1].target == "epicgames.com"
