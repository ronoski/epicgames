from datetime import datetime, timedelta, timezone

from recon.coverage import (
    GapQueue, Gap, coverage_score, staleness, confidence_deficit, gap_priority, parse_duration,
)
from recon.factory import make_node, make_edge
from recon.models import ScopeBinding, Verdict, Sensitivity
from recon.store import GraphStore
from recon import invariants

NOW = datetime(2026, 1, 10, tzinfo=timezone.utc)


def binding(v=Verdict.IN_SCOPE):
    return ScopeBinding(verdict=v, snapshot_id="snap1", observed_at="2026-01-01T00:00:00+00:00")


def test_parse_duration():
    assert parse_duration("P7D") == timedelta(days=7)
    assert parse_duration("PT12H") == timedelta(hours=12)


def test_coverage_score_monotonic():
    n = make_node("WebApp", "web:https://a.epicgames.com", binding=binding(),
                  source="httpx", now=NOW)
    base = coverage_score(n)
    n.coverage["fingerprinted"] = True
    assert coverage_score(n) > base


def test_staleness_grows_with_age():
    old = make_node("DNSName", "dns:a.epicgames.com", binding=binding(), source="x",
                    now=datetime(2026, 1, 1, tzinfo=timezone.utc))
    assert staleness(old, NOW) > 1.0


def test_gap_queue_orders_by_priority_and_skips_human_gated():
    q = GapQueue()
    q.enqueue(Gap(priority=1.0, id="low", verb="resolve"))
    q.enqueue(Gap(priority=9.0, id="high", verb="resolve"))
    q.enqueue(Gap(priority=99.0, id="gated", verb="content-discovery-wordlist", human_gated=True))
    top = q.pop_highest(auto_only=True)
    assert top.id == "high"  # human-gated skipped despite higher priority
    assert any(g.id == "gated" for g in q.human_gated())


def test_priority_formula():
    n = make_node("DNSName", "dns:a.epicgames.com", binding=binding(), source="x",
                  now=datetime(2026, 1, 1, tzinfo=timezone.utc))
    p = gap_priority(value=2.0, node=n, cost=1.0, now=NOW)
    assert p > 0


def test_invariants_clean_graph_has_no_violations():
    store = GraphStore()
    store.apply_node(make_node("DNSName", "dns:a.epicgames.com", binding=binding(),
                               source="x", now=NOW))
    assert invariants.check(store, current_snapshot="snap1") == []


def test_invariant_I3_active_probe_out_of_scope():
    store = GraphStore()
    store.apply_node(make_node("Host", "host:1.2.3.4", binding=binding(Verdict.OUT_OF_SCOPE),
                               source="scan", now=NOW, attrs={"active_probed": True}))
    codes = [x.code for x in invariants.check(store)]
    assert "I3" in codes


def test_invariant_I6_anticheat_and_I7_trafficking():
    store = GraphStore()
    store.apply_node(make_node("Artifact", "art:deadbeef", binding=binding(), source="re",
                               now=NOW, attrs={"anti_cheat_action_mode": "runtime_circumvent",
                                               "is_circumvention_tool": True}))
    codes = [x.code for x in invariants.check(store)]
    assert "I6" in codes and "I7" in codes


def test_invariant_I8_unlabeled_credential():
    store = GraphStore()
    store.apply_node(make_node("Credential", "cred:abc", binding=binding(), source="re",
                               now=NOW, sensitivity=Sensitivity.S0))
    codes = [x.code for x in invariants.check(store)]
    assert "I8" in codes


def test_invariant_I9_other_user_pii_endpoint():
    store = GraphStore()
    store.apply_node(make_node("ObjectType", "obj:other-account", binding=binding(),
                               source="live", now=NOW, data_subject="other",
                               sensitivity=Sensitivity.S3))
    store.apply_node(make_node("Operation", "op:GET:/x", binding=binding(), source="live", now=NOW))
    store.apply_edge(make_edge("references_object", "op:GET:/x", "obj:other-account",
                               binding=binding(), source="live", now=NOW))
    codes = [x.code for x in invariants.check(store)]
    assert "I9" in codes
