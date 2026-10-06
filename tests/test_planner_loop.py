from datetime import datetime, timedelta, timezone

import pytest

from recon import planner
from recon.coverage import Gap, GapQueue
from recon.factory import make_node, make_edge
from recon.loop import AutonomousLoop
from recon.models import ScopeBinding, Sensitivity, Verdict
from recon.modules.base import ModuleContext
from recon.evidence import EvidenceStore
from recon.events import EventLog
from recon.ratelimit import RateLedger
from recon.scope import Scope
from recon.snapshot import take_snapshot
from recon.store import Graph, GraphStore

import logging

NOW = datetime(2026, 1, 10, tzinfo=timezone.utc)
SNAP = take_snapshot("policy-text", now=NOW)


def binding(v=Verdict.IN_SCOPE):
    return ScopeBinding(verdict=v, snapshot_id=SNAP.snapshot_id,
                        observed_at="2026-01-10T00:00:00+00:00")


def ctx(*, allow_active=False, snapshot=SNAP, now=NOW, store=None, tmp=None):
    graph = Graph(log=EventLog(), store=store or GraphStore())
    return ModuleContext(
        scope=Scope(include=["*.epicgames.com"]),
        ledger=RateLedger(global_qps=10.0, capacity=100.0),
        evidence=EvidenceStore(tmp or "/tmp/recon-test-ev"),
        graph=graph, snapshot=snapshot, logger=logging.getLogger("t"),
        allow_active=allow_active, now=now,
    )


def dns(fqdn, *, enumerated=False, v=Verdict.IN_SCOPE, now=NOW):
    return make_node("DNSName", f"dns:{fqdn}", binding=binding(v), source="seeds",
                     now=now, coverage={"enumerated": enumerated})


# --- planner -----------------------------------------------------------
def test_planner_emits_passive_enumeration_gap_for_domain():
    store = GraphStore()
    store.apply_node(make_node("Domain", "domain:epicgames.com", binding=binding(),
                               source="seeds", now=NOW))
    gaps = planner.plan(store, NOW, allow_active=False)
    assert any(g.id.startswith("enumerate-ct:") and g.passive for g in gaps)


def test_planner_withholds_active_gaps_unless_allowed():
    store = GraphStore()
    store.apply_node(dns("api.epicgames.com", enumerated=True))
    passive_only = planner.plan(store, NOW, allow_active=False)
    assert all(g.passive for g in passive_only)
    with_active = planner.plan(store, NOW, allow_active=True)
    assert any(g.module == "resolver" and not g.passive for g in with_active)


def test_planner_ignores_out_of_scope_and_prefilter_nodes():
    store = GraphStore()
    store.apply_node(dns("x.epicgames.com", v=Verdict.OUT_OF_SCOPE))
    store.apply_node(dns("y.epicgames.com", v=Verdict.PREFILTER_ONLY))
    assert planner.plan(store, NOW, allow_active=True) == []


def test_planner_depth_ladder_resolve_then_scan_then_probe():
    """Closing one gap should surface the next, deeper one."""

    store = GraphStore()
    store.apply_node(dns("api.epicgames.com", enumerated=True))
    keys = {g.id.split(":")[0] for g in planner.plan(store, NOW, allow_active=True)}
    assert "resolve-name" in keys

    # now the name resolves -> a Host exists -> scanning becomes the next gap
    store.apply_node(make_node("Host", "host:203.0.113.5", binding=binding(),
                               source="resolver", now=NOW))
    store.apply_edge(make_edge("resolves_to", "dns:api.epicgames.com", "host:203.0.113.5",
                               binding=binding(), source="resolver", now=NOW))
    keys2 = {g.id.split(":")[0] for g in planner.plan(store, NOW, allow_active=True)}
    assert "resolve-name" not in keys2  # closed
    assert "scan-host" in keys2 and "probe-http" in keys2


def test_planner_api_contract_gap_closes_when_params_mined():
    store = GraphStore()
    store.apply_node(make_node("WebApp", "web:https://api.epicgames.com", binding=binding(),
                               source="http_probe", now=NOW,
                               coverage={"fingerprinted": True}))
    keys = {g.id.split(":")[0] for g in planner.plan(store, NOW, allow_active=True)}
    assert "api-contract" in keys

    op = make_node("Operation", "op:GET:/v1/items", binding=binding(), source="openapi",
                   now=NOW, coverage={"param_mined": True})
    store.apply_node(op)
    store.apply_edge(make_edge("exposes", "web:https://api.epicgames.com", op.id,
                               binding=binding(), source="openapi", now=NOW))
    keys2 = {g.id.split(":")[0] for g in planner.plan(store, NOW, allow_active=True)}
    assert "api-contract" not in keys2


def test_planner_reverify_gap_for_stale_fact():
    old = dns("old.epicgames.com", enumerated=True, now=datetime(2025, 1, 1, tzinfo=timezone.utc))
    store = GraphStore()
    store.apply_node(old)
    assert any(g.id.startswith("reverify:") for g in planner.plan(store, NOW, allow_active=False))


def test_coverage_report_shape():
    store = GraphStore()
    store.apply_node(dns("a.epicgames.com", enumerated=True))
    rep = planner.coverage_report(store)
    assert rep["DNSName"]["count"] == 1
    assert 0.0 <= rep["DNSName"]["coverage_avg"] <= 1.0


# --- loop --------------------------------------------------------------
def test_loop_dry_run_plans_without_acting(tmp_path):
    store = GraphStore()
    store.apply_node(make_node("Domain", "domain:epicgames.com", binding=binding(),
                               source="seeds", now=NOW))
    c = ctx(store=store, tmp=tmp_path)
    res = AutonomousLoop(c, dry_run=True, max_cycles=3).run(now=NOW)
    assert res.cycles and all(x.outcome == "planned" for x in res.cycles)
    # nothing was dispatched, so no rate budget was spent
    assert c.ledger.log == []


def test_loop_halts_without_snapshot(tmp_path):
    c = ctx(snapshot=None, tmp=tmp_path)
    res = AutonomousLoop(c, max_cycles=2).run(now=NOW)
    assert "no scope snapshot" in res.halted_because


def test_loop_halts_on_stale_snapshot(tmp_path):
    c = ctx(snapshot=SNAP, tmp=tmp_path)
    later = NOW + timedelta(days=3)  # beyond the PT24H half-life
    res = AutonomousLoop(c, max_cycles=2).run(now=later)
    assert "stale" in res.halted_because


def test_loop_halts_on_invariant_violation(tmp_path):
    store = GraphStore()
    # actively probed but out of scope -> I3 violation
    store.apply_node(make_node("Host", "host:1.2.3.4", binding=binding(Verdict.OUT_OF_SCOPE),
                               source="scan", now=NOW, attrs={"active_probed": True}))
    c = ctx(store=store, tmp=tmp_path)
    res = AutonomousLoop(c, max_cycles=2).run(now=NOW)
    assert res.violations and "invariant" in res.halted_because


def test_loop_halts_when_gap_queue_dry(tmp_path):
    c = ctx(tmp=tmp_path)  # empty graph -> no gaps
    res = AutonomousLoop(c, max_cycles=2).run(now=NOW)
    assert res.halted_because == "gap queue dry"


def test_loop_prefers_passive_first(tmp_path):
    store = GraphStore()
    store.apply_node(make_node("Domain", "domain:epicgames.com", binding=binding(),
                               source="seeds", now=NOW))
    store.apply_node(dns("api.epicgames.com", enumerated=True))
    c = ctx(allow_active=True, store=store, tmp=tmp_path)
    res = AutonomousLoop(c, dry_run=True, max_cycles=1, passive_first=True).run(now=NOW)
    assert res.cycles[0].passive is True


def test_loop_respects_active_action_budget(tmp_path):
    store = GraphStore()
    store.apply_node(dns("api.epicgames.com", enumerated=True))
    c = ctx(allow_active=True, store=store, tmp=tmp_path)
    # dry_run=False with a 0 active budget must halt before dispatching
    res = AutonomousLoop(c, dry_run=False, max_cycles=3, max_active_actions=0).run(now=NOW)
    assert "active-action budget exhausted" in res.halted_because


def test_gap_queue_skips_human_gated():
    q = GapQueue()
    q.enqueue(Gap(priority=99.0, id="g", verb="content-discovery-wordlist", human_gated=True))
    q.enqueue(Gap(priority=1.0, id="ok", verb="resolve"))
    assert q.pop_highest(auto_only=True).id == "ok"
