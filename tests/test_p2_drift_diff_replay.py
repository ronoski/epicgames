"""P2: scope-drift detection, the per-run delta report, and event-log replay."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone

import pytest

from recon import drift, report
from recon.events import EventLog
from recon.evidence import EvidenceStore
from recon.factory import make_edge, make_node
from recon.models import ScopeBinding, Verdict
from recon.modules.base import ModuleContext
from recon.ratelimit import RateLedger
from recon.scope import Scope
from recon.snapshot import Snapshot, take_snapshot
from recon.store import Graph, GraphStore

NOW = datetime(2026, 1, 10, tzinfo=timezone.utc)


def snap(include, exclude=(), prefilter=(), text="policy v1", now=NOW):
    return take_snapshot(text, now=now, include=list(include),
                         exclude=list(exclude), prefilter=list(prefilter))


def binding(v=Verdict.IN_SCOPE, snapshot_id="s1"):
    return ScopeBinding(verdict=v, snapshot_id=snapshot_id,
                        observed_at="2026-01-10T00:00:00+00:00")


def node(nid, ntype="DNSName", source="crtsh", attrs=None, v=Verdict.IN_SCOPE,
         snapshot_id="s1", now=NOW):
    return make_node(ntype, nid, binding=binding(v, snapshot_id), source=source,
                     now=now, attrs=attrs or {})


# ============================ snapshots =================================
def test_snapshot_id_changes_when_the_rule_set_changes():
    """Identical prose with a different asset list must still re-pin."""

    a = snap(["*.example.com"])
    b = snap(["*.example.com", "*.example.net"])
    assert a.snapshot_id != b.snapshot_id
    assert a.content_sha256 == b.content_sha256  # the prose did not change


def test_snapshot_id_changes_when_the_policy_text_changes():
    a = snap(["*.example.com"], text="v1")
    b = snap(["*.example.com"], text="v2")
    assert a.snapshot_id != b.snapshot_id
    assert a.content_sha256 != b.content_sha256


def test_snapshot_round_trips_through_disk(tmp_path):
    original = snap(["*.example.com"], exclude=["secret.example.com"])
    path = original.save(tmp_path / "snapshot.json")
    loaded = Snapshot.load(path)
    assert loaded == original


def test_loading_a_missing_or_corrupt_snapshot_returns_none(tmp_path):
    assert Snapshot.load(tmp_path / "nope.json") is None
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert Snapshot.load(bad) is None


# ============================ drift detection ===========================
def test_no_previous_snapshot_is_not_drift():
    rep = drift.detect(None, snap(["*.example.com"]))
    assert rep.drifted is False
    assert rep.summary() == "no scope drift"


def test_identical_snapshots_do_not_drift():
    a = snap(["*.example.com"], exclude=["x.example.com"])
    assert drift.detect(a, a).drifted is False


def test_detects_an_added_asset():
    rep = drift.detect(snap(["*.example.com"]),
                       snap(["*.example.com", "*.example.net"]))
    assert rep.drifted
    assert rep.added == ["*.example.net"] and rep.removed == []
    assert "1 added" in rep.summary()


def test_detects_a_removed_asset():
    rep = drift.detect(snap(["*.example.com", "*.example.net"]),
                       snap(["*.example.com"]))
    assert rep.removed == ["*.example.net"] and rep.added == []


def test_detects_a_new_exclusion_and_an_un_exclusion():
    rep = drift.detect(snap(["*.example.com"], exclude=["a.example.com"]),
                       snap(["*.example.com"], exclude=["b.example.com"]))
    assert rep.newly_excluded == ["b.example.com"]
    assert rep.no_longer_excluded == ["a.example.com"]


def test_detects_a_policy_text_change_with_an_unchanged_asset_list():
    rep = drift.detect(snap(["*.example.com"], text="v1"),
                       snap(["*.example.com"], text="v2"))
    assert rep.drifted and rep.policy_text_changed
    assert rep.added == [] and rep.removed == []
    assert "policy text changed" in rep.summary()


def test_detects_a_prefilter_change():
    rep = drift.detect(snap(["*.example.com"], prefilter=[]),
                       snap(["*.example.com"], prefilter=["*.owned.com"]))
    assert rep.drifted and rep.prefilter_changed


# ============================ re-binding ================================
def test_rebind_moves_a_node_out_of_scope_without_deleting_it():
    """History is preserved: losing scope must not erase that it was collected."""

    store = GraphStore()
    store.apply_node(node("dns:a.example.com", attrs={"fqdn": "a.example.com"}))
    new_snap = snap(["*.example.com"], exclude=["a.example.com"])
    result = drift.rebind(store, Scope(include=["*.example.com"],
                                       exclude=["a.example.com"]), new_snap, now=NOW)
    assert result.lost_scope == ["dns:a.example.com"]
    kept = store.get("dns:a.example.com")
    assert kept is not None, "the node must survive losing scope"
    assert kept.scope_binding.verdict == Verdict.OUT_OF_SCOPE
    assert kept.scope_binding.snapshot_id == new_snap.snapshot_id


def test_rebind_can_bring_a_node_back_into_scope():
    store = GraphStore()
    store.apply_node(node("dns:a.example.com", v=Verdict.OUT_OF_SCOPE,
                          attrs={"fqdn": "a.example.com"}))
    new_snap = snap(["*.example.com"])
    result = drift.rebind(store, Scope(include=["*.example.com"]), new_snap, now=NOW)
    assert result.gained_scope == ["dns:a.example.com"]
    assert store.get("dns:a.example.com").scope_binding.verdict == Verdict.IN_SCOPE


def test_rebind_logs_each_change():
    store = GraphStore()
    store.apply_node(node("dns:a.example.com", attrs={"fqdn": "a.example.com"}))
    log = EventLog()
    drift.rebind(store, Scope(include=["*.other.com"]), snap(["*.other.com"]),
                 now=NOW, log=log)
    kinds = [e.kind for e in log.all()]
    assert "scope_binding_set" in kinds


def test_rebind_is_a_noop_when_nothing_changed():
    store = GraphStore()
    store.apply_node(node("dns:a.example.com", attrs={"fqdn": "a.example.com"}))
    s = snap(["*.example.com"])
    result = drift.rebind(store, Scope(include=["*.example.com"]), s, now=NOW)
    assert result.changed == [] and result.lost_scope == [] and result.rebound == 1


@pytest.mark.parametrize("nid,attrs,expected", [
    ("dns:a.example.com", {}, "a.example.com"),
    ("host:1.2.3.4", {}, "1.2.3.4"),
    ("domain:example.com", {}, "example.com"),
    ("web:https://a.example.com", {}, "a.example.com"),
    ("svc:1.2.3.4:443/tcp", {}, "1.2.3.4"),
    ("hyp:dns-candidate:dev.example.com", {}, "dev.example.com"),
    ("dns:whatever", {"fqdn": "recorded.example.com"}, "recorded.example.com"),
])
def test_binding_subject_recovers_what_the_verdict_was_about(nid, attrs, expected):
    n = node(nid, ntype="DNSName" if nid.startswith("dns:") else "Host", attrs=attrs)
    # type does not matter for subject extraction; use the raw helper
    n.id = nid
    n.attrs = attrs
    assert drift.binding_subject(n) == expected


def test_a_node_with_no_recoverable_subject_is_left_alone():
    store = GraphStore()
    store.apply_node(node("obj:SomeType", ntype="ObjectType"))
    result = drift.rebind(store, Scope(include=["*.example.com"]),
                          snap(["*.example.com"]), now=NOW)
    assert result.rebound == 0
    assert store.get("obj:SomeType").scope_binding.verdict == Verdict.IN_SCOPE


# ============================ the delta report ==========================
def graph_with(run_id="run1"):
    return Graph(log=EventLog(run_id=run_id), store=GraphStore())


def test_delta_reports_new_nodes_by_type():
    g = graph_with()
    g.upsert_node(node("dns:a.example.com"))
    g.upsert_node(node("host:1.2.3.4", ntype="Host", source="resolver"))
    d = report.delta_for(g.log.all())
    assert d.nodes_created == {"DNSName": 1, "Host": 1}
    assert d.is_quiet is False
    assert "1 new DNSName" in d.headline()


def test_delta_distinguishes_created_from_merged():
    g = graph_with()
    g.upsert_node(node("dns:a.example.com", source="crtsh"))
    g.upsert_node(node("dns:a.example.com", source="wayback"))
    d = report.delta_for(g.log.all())
    assert d.nodes_created == {"DNSName": 1}
    assert d.nodes_merged == {"DNSName": 1}


def test_delta_reports_new_edges_and_forks():
    g = graph_with()
    g.upsert_node(node("dns:a.example.com", attrs={"ip": "1.1.1.1"}))
    g.upsert_node(node("host:1.2.3.4", ntype="Host"))
    g.upsert_edge(make_edge("resolves_to", "dns:a.example.com", "host:1.2.3.4",
                            binding=binding(), source="resolver", now=NOW))
    g.upsert_node(node("dns:a.example.com", source="other", attrs={"ip": "2.2.2.2"}))
    d = report.delta_for(g.log.all())
    assert d.edges_created == {"resolves_to": 1}
    assert len(d.forks) == 1
    assert "forked" in d.headline()


def test_a_takeover_candidate_is_called_out_as_notable():
    """The single most actionable thing a passive sweep can surface."""

    g = graph_with()
    g.upsert_node(node("hyp:dangling-cname:gone.example.com", ntype="Hypothesis",
                       source="resolver"))
    d = report.delta_for(g.log.all())
    assert d.notable and d.notable[0]["kind"] == "dangling-cname"
    assert "takeover candidate" in d.headline()


def test_a_run_that_learned_nothing_says_so():
    log = EventLog(run_id="quiet")
    log.append("gap_dispatched", {"id": "g", "verb": "resolve", "module": "resolver"})
    d = report.delta_for(log.all())
    assert d.is_quiet
    assert d.headline() == "no change since the previous run"


def test_delta_surfaces_refusals_and_spend():
    log = EventLog(run_id="r")
    log.append("gate_decision_recorded", {"decision": "REFUSE", "value": "x.example.com",
                                          "verb": "resolve", "reason": "not in scope"})
    log.append("rate_debit", {"target": "example.com", "verb": "resolve",
                              "balance_after": 3.0})
    log.append("third_party_debit", {"source": "crt.sh", "balance_after": 4.0})
    d = report.delta_for(log.all())
    assert d.refusals[0]["reason"] == "not in scope"
    assert d.rate_spend == {"example.com": 1}
    assert d.third_party_spend == {"crt.sh": 1}


def test_drift_dominates_the_headline():
    log = EventLog(run_id="r")
    log.append("scope_drift_detected", {"added": ["*.new.com"], "drifted": True})
    d = report.delta_for(log.all())
    assert "SCOPE DRIFT" in d.headline()


def test_a_violation_dominates_over_new_findings():
    g = graph_with()
    g.upsert_node(node("dns:a.example.com"))
    g.log.append("invariant_violation", {"code": "I3", "detail": "boom"})
    d = report.delta_for(g.log.all())
    assert "HALTED" in d.headline() and "I3" in d.headline()


def test_per_run_splits_by_run_id():
    log = EventLog(run_id="run1")
    log.append("node_upserted", {"id": "dns:a", "type": "DNSName", "outcome": "created"})
    log2 = EventLog(run_id="run2")
    log2.append("node_upserted", {"id": "dns:b", "type": "DNSName", "outcome": "created"})
    events = log.all() + log2.all()
    runs = report.per_run(events)
    assert [r.run_id for r in runs] == ["run1", "run2"]


def test_delta_since_a_run_excludes_that_run():
    e1 = EventLog(run_id="run1")
    e1.append("node_upserted", {"id": "dns:a", "type": "DNSName", "outcome": "created"})
    e2 = EventLog(run_id="run2")
    e2.append("node_upserted", {"id": "dns:b", "type": "Host", "outcome": "created"})
    d = report.delta_since(e1.all() + e2.all(), run_id="run1")
    assert d.nodes_created == {"Host": 1}


def test_delta_of_an_empty_log_is_quiet():
    assert report.delta_for([]).is_quiet


# ============================ replay ====================================
def test_replay_reproduces_the_graph_exactly():
    """The event log is the source of truth, so a replay must reproduce the run."""

    g = graph_with()
    g.upsert_node(node("dns:a.example.com", source="crtsh"))
    g.upsert_node(node("host:1.2.3.4", ntype="Host", source="resolver"))
    g.upsert_edge(make_edge("resolves_to", "dns:a.example.com", "host:1.2.3.4",
                            binding=binding(), source="resolver", now=NOW))

    rebuilt = GraphStore.from_events(g.log.all())
    assert sorted(rebuilt.nodes) == sorted(g.store.nodes)
    assert sorted(rebuilt.edges) == sorted(g.store.edges)
    assert rebuilt.counts() == g.store.counts()


def test_replay_preserves_merged_confidence():
    """A second independent source raised confidence live; replay must agree."""

    g = graph_with()
    g.upsert_node(node("dns:a.example.com", source="crtsh"))
    g.upsert_node(node("dns:a.example.com", source="wayback"))
    live = g.store.get("dns:a.example.com")
    rebuilt = GraphStore.from_events(g.log.all()).get("dns:a.example.com")
    assert rebuilt.confidence.log_odds == live.confidence.log_odds
    assert rebuilt.confidence.independent_sources == live.confidence.independent_sources


def test_replay_preserves_a_contradiction_fork():
    g = graph_with()
    g.upsert_node(node("dns:a.example.com", source="a", attrs={"ip": "1.1.1.1"}))
    g.upsert_node(node("dns:a.example.com", source="b", attrs={"ip": "2.2.2.2"}))
    rebuilt = GraphStore.from_events(g.log.all())
    assert "dns:a.example.com#fork1" in rebuilt.nodes
    assert rebuilt.get("dns:a.example.com").attrs["ip"] == "1.1.1.1"
    assert rebuilt.get("dns:a.example.com#fork1").confidence.forked_from == \
        "dns:a.example.com"


def test_a_true_duplicate_observation_is_deduped_in_the_log():
    """Same source, same instant, same datum = a replay, not new evidence."""

    g = graph_with()
    g.upsert_node(node("dns:a.example.com", source="crtsh"))
    g.upsert_node(node("dns:a.example.com", source="crtsh"))
    upserts = [e for e in g.log.all() if e.kind == "node_upserted"]
    assert len(upserts) == 1


def test_a_second_source_at_the_same_instant_is_NOT_deduped():
    """The bug this pins: keying only on (id, timestamp) dropped real corroboration."""

    g = graph_with()
    g.upsert_node(node("dns:a.example.com", source="crtsh"))
    g.upsert_node(node("dns:a.example.com", source="wayback"))
    upserts = [e for e in g.log.all() if e.kind == "node_upserted"]
    assert len(upserts) == 2


def test_upsert_events_carry_the_whole_datum():
    """Without the datum the log is a trace, not a source of truth."""

    g = graph_with()
    g.upsert_node(node("dns:a.example.com"))
    evt = next(e for e in g.log.all() if e.kind == "node_upserted")
    assert evt.payload["node"]["id"] == "dns:a.example.com"
    assert evt.payload["node"]["scope_binding"]["verdict"] == "in_scope"
    assert evt.payload["node"]["provenance"]["chain"]


def test_replay_skips_a_legacy_event_without_inventing_data():
    log = EventLog()
    log.append("node_upserted", {"id": "dns:a", "type": "DNSName", "outcome": "created"})
    store = GraphStore.from_events(log.all())
    assert store.nodes == {}
    assert store.replay_skipped == 1


def test_replay_survives_a_round_trip_through_disk(tmp_path):
    path = tmp_path / "events.jsonl"
    g = Graph(log=EventLog(path=path, run_id="r1"), store=GraphStore())
    g.upsert_node(node("dns:a.example.com"))
    g.upsert_node(node("host:9.9.9.9", ntype="Host", source="resolver"))

    rebuilt = GraphStore.from_events(EventLog.replay(path))
    assert sorted(rebuilt.nodes) == ["dns:a.example.com", "host:9.9.9.9"]


# ============ durability bugs the end-to-end run surfaced ===============
def test_event_sequence_continues_across_runs(tmp_path):
    """A fresh EventLog restarting seq at 0 made replay interleave runs wrongly.

    Overlapping sequence numbers let a later run's event sort before the earlier event
    that created the node it refers to, so the later one silently did nothing.
    """

    path = tmp_path / "events.jsonl"
    first = EventLog(path=path, run_id="r1")
    first.append("scope_snapshot_taken", {"snapshot_id": "s1"})
    first.append("scope_snapshot_taken", {"snapshot_id": "s1b"})

    second = EventLog(path=path, run_id="r2")
    evt = second.append("scope_snapshot_taken", {"snapshot_id": "s2"})
    assert evt.seq == 2, "the second run must continue the sequence, not restart it"

    seqs = [e.seq for e in EventLog.replay(path)]
    assert seqs == sorted(set(seqs)), "sequence numbers must be unique and ordered"


def test_a_rebind_survives_replay(tmp_path):
    """The re-bind is a state change, so the rebuilt graph must reflect it."""

    path = tmp_path / "events.jsonl"
    g = Graph(log=EventLog(path=path, run_id="r1"), store=GraphStore())
    g.upsert_node(node("dns:a.example.com", attrs={"fqdn": "a.example.com"},
                       snapshot_id="old"))

    new_snap = snap(["*.example.com"], exclude=["a.example.com"], text="v2")
    rebind_log = EventLog(path=path, run_id="rebind")
    store = GraphStore.from_events(EventLog.replay(path))
    drift.rebind(store, Scope(include=["*.example.com"], exclude=["a.example.com"]),
                 new_snap, now=NOW, log=rebind_log)

    rebuilt = GraphStore.from_events(EventLog.replay(path))
    kept = rebuilt.get("dns:a.example.com")
    assert kept.scope_binding.verdict == Verdict.OUT_OF_SCOPE
    assert kept.scope_binding.snapshot_id == new_snap.snapshot_id


def test_a_rebind_is_recorded_even_when_only_the_snapshot_changed(tmp_path):
    """Invariant I1 checks the snapshot id, so an unchanged verdict still needs logging."""

    store = GraphStore()
    store.apply_node(node("dns:a.example.com", attrs={"fqdn": "a.example.com"},
                          snapshot_id="old"))
    log = EventLog()
    result = drift.rebind(store, Scope(include=["*.example.com"]),
                          snap(["*.example.com"], text="v2"), now=NOW, log=log)
    assert result.changed == [], "the verdict did not change"
    assert result.rebound == 1
    bindings = [e for e in log.all() if e.kind == "scope_binding_set"]
    assert bindings, "a re-bind under a new snapshot must still be recorded"
    assert bindings[0].payload["binding"]["snapshot_id"] != "old"
