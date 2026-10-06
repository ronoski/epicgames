"""Offline tests for the correlate (entity-resolution) module.

Fully deterministic and network-free by construction: the module only reads fingerprints
already stored in the graph.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import pytest

from recon import ontology, verbs
from recon.evidence import EvidenceStore
from recon.events import EventLog
from recon.factory import make_edge, make_node
from recon.models import ScopeBinding, Verdict
from recon.modules.base import ModuleContext
from recon.modules.passive import correlate
from recon.ratelimit import RateLedger
from recon.scope import Scope
from recon.snapshot import take_snapshot
from recon.store import Graph, GraphStore

NOW = datetime(2026, 1, 10, tzinfo=timezone.utc)
SNAP = take_snapshot("policy v1", now=NOW, include=["*.example.com"])

A = "web:https://a.example.com"
B = "web:https://b.example.com"
C = "web:https://c.example.com"
OUT = "web:https://evil.invalid"

H1 = "a" * 64
H2 = "b" * 64


def binding(v=Verdict.IN_SCOPE):
    return ScopeBinding(verdict=v, snapshot_id=SNAP.snapshot_id,
                        observed_at="2026-01-10T00:00:00+00:00")


def webapp(nid, attrs=None, v=Verdict.IN_SCOPE, coverage=None):
    return make_node("WebApp", nid, binding=binding(v), source="http_probe", now=NOW,
                     attrs=attrs or {}, coverage=coverage or {"fingerprinted": True})


def make_ctx(tmp_path, nodes=(), edges=(), snapshot=SNAP, include=("*.example.com",)):
    store = GraphStore()
    for n in nodes:
        store.apply_node(n)
    for e in edges:
        store.apply_edge(e)
    return ModuleContext(
        scope=Scope(include=list(include)),
        ledger=RateLedger(global_qps=10.0, capacity=100.0),
        evidence=EvidenceStore(tmp_path),
        graph=Graph(log=EventLog(), store=store),
        snapshot=snapshot, logger=logging.getLogger("t.correlate"),
        allow_active=False, now=NOW,
    )


def run(ctx):
    return correlate.CorrelateModule(ctx).run([])


def edges_of(ctx, etype):
    return [e for e in ctx.graph.store.edges.values() if e.type == etype]


# --- contract ----------------------------------------------------------
def test_module_is_passive_and_its_verb_is_not_active():
    assert correlate.CorrelateModule.active is False
    verbs.assert_schedulable(correlate.VERB)
    assert not verbs.is_active(correlate.VERB)


def test_the_edges_it_emits_are_declared():
    for edge in ("same_as", "co_deploy", "shared_trust_domain"):
        ontology.assert_edge_type(edge)


def test_it_never_touches_the_network_or_the_ledger(tmp_path, monkeypatch):
    import socket
    monkeypatch.setattr(socket, "create_connection",
                        lambda *a, **k: pytest.fail("correlate opened a socket"))
    ctx = make_ctx(tmp_path, nodes=[webapp(A, {"response_hash": H1}),
                                    webapp(B, {"response_hash": H1})])
    run(ctx)
    assert ctx.ledger.log == []


# --- strong signals -> same_as -----------------------------------------
def test_identical_response_hash_links_as_same_as(tmp_path):
    ctx = make_ctx(tmp_path, nodes=[webapp(A, {"response_hash": H1}),
                                    webapp(B, {"response_hash": H1})])
    summary = run(ctx)
    assert summary["same_as"] == 2  # symmetric: one edge each way
    pairs = {(e.frm, e.to) for e in edges_of(ctx, "same_as")}
    assert pairs == {(A, B), (B, A)}


def test_certificate_reuse_is_the_strongest_signal(tmp_path):
    cert = make_node("Certificate", "cert:" + H2, binding=binding(), source="tls_probe",
                     now=NOW)
    ctx = make_ctx(
        tmp_path,
        nodes=[webapp(A), webapp(B), cert],
        edges=[make_edge("presents_certificate", A, cert.id, binding=binding(),
                         source="tls_probe", now=NOW),
               make_edge("presents_certificate", B, cert.id, binding=binding(),
                         source="tls_probe", now=NOW)],
    )
    summary = run(ctx)
    assert summary["same_as"] == 2
    edge = edges_of(ctx, "same_as")[0]
    assert edge.attrs["signal"] == "certificate_spki"
    assert edge.confidence.log_odds >= 2.4


def test_favicon_and_404_agreeing_scores_higher_than_either_alone(tmp_path):
    both = make_ctx(tmp_path, nodes=[
        webapp(A, {"favicon_hash": H1, "default_404_hash": H2}),
        webapp(B, {"favicon_hash": H1, "default_404_hash": H2}),
    ])
    run(both)
    paired_odds = max(e.confidence.log_odds for e in edges_of(both, "same_as"))

    one = make_ctx(tmp_path, nodes=[webapp(A, {"favicon_hash": H1}),
                                    webapp(B, {"favicon_hash": H1})])
    run(one)
    single_odds = max(e.confidence.log_odds for e in edges_of(one, "same_as"))
    assert paired_odds > single_odds


def test_three_members_link_pairwise(tmp_path):
    ctx = make_ctx(tmp_path, nodes=[webapp(A, {"response_hash": H1}),
                                    webapp(B, {"response_hash": H1}),
                                    webapp(C, {"response_hash": H1})])
    summary = run(ctx)
    assert summary["same_as"] == 6  # 3 pairs, both directions


# --- weak signals must NOT mint identity --------------------------------
def test_a_shared_server_banner_is_co_deploy_not_same_as(tmp_path):
    """Half the internet shares an nginx banner; that is not one service."""

    ctx = make_ctx(tmp_path, nodes=[webapp(A, {"server": "nginx"}),
                                    webapp(B, {"server": "nginx"})])
    summary = run(ctx)
    assert summary["same_as"] == 0
    assert summary["co_deploy"] == 2
    assert edges_of(ctx, "same_as") == []


def test_a_shared_jarm_is_co_deploy_not_same_as(tmp_path):
    ctx = make_ctx(tmp_path, nodes=[webapp(A, {"jarm": "29d3fd00029d29d0"}),
                                    webapp(B, {"jarm": "29d3fd00029d29d0"})])
    summary = run(ctx)
    assert summary["same_as"] == 0 and summary["co_deploy"] == 2


def test_a_shared_jwks_kid_is_a_trust_domain_not_identity(tmp_path):
    ctx = make_ctx(tmp_path, nodes=[webapp(A, {"kids": ["kid-1"]}),
                                    webapp(B, {"kids": ["kid-1", "kid-2"]})])
    summary = run(ctx)
    assert summary["shared_trust_domain"] == 2
    assert summary["same_as"] == 0


# --- noise rejection ----------------------------------------------------
@pytest.mark.parametrize("trivial", sorted(correlate.TRIVIAL_HASHES))
def test_a_trivial_hash_never_clusters(trivial):
    """An empty-body hash would link thousands of unrelated hosts into one 'service'."""

    nodes = [webapp(A, {"response_hash": trivial}), webapp(B, {"response_hash": trivial})]
    assert correlate._fingerprint_clusters(nodes, "response_hash") == []


def test_an_oversized_cluster_is_reported_not_linked(tmp_path):
    """A huge cluster is shared infrastructure, not one logical service."""

    nodes = [webapp(f"web:https://h{i}.example.com", {"response_hash": H1})
             for i in range(correlate.MAX_CLUSTER + 2)]
    ctx = make_ctx(tmp_path, nodes=nodes)
    summary = run(ctx)
    assert summary["same_as"] == 0
    assert summary["oversized_clusters"]
    assert "shared infrastructure" in summary["oversized_clusters"][0]["reason"]


def test_differing_fingerprints_are_not_linked(tmp_path):
    ctx = make_ctx(tmp_path, nodes=[webapp(A, {"response_hash": H1}),
                                    webapp(B, {"response_hash": H2})])
    assert run(ctx)["same_as"] == 0


def test_a_node_with_no_fingerprint_is_not_linked(tmp_path):
    ctx = make_ctx(tmp_path, nodes=[webapp(A), webapp(B)])
    assert run(ctx)["same_as"] == 0


def test_a_single_node_is_a_noop(tmp_path):
    ctx = make_ctx(tmp_path, nodes=[webapp(A, {"response_hash": H1})])
    summary = run(ctx)
    assert summary["same_as"] == 0 and summary["considered"] == 1


# --- scope ---------------------------------------------------------------
def test_an_out_of_scope_node_is_never_linked(tmp_path):
    """Linking an out-of-scope identifier would extend an in-scope finding onto it."""

    ctx = make_ctx(tmp_path, nodes=[
        webapp(A, {"response_hash": H1}),
        webapp(OUT, {"response_hash": H1}, v=Verdict.OUT_OF_SCOPE),
    ])
    summary = run(ctx)
    assert summary["same_as"] == 0
    for e in ctx.graph.store.edges.values():
        assert OUT not in (e.frm, e.to)


def test_no_edges_without_a_usable_snapshot(tmp_path):
    ctx = make_ctx(tmp_path, nodes=[webapp(A, {"response_hash": H1}),
                                    webapp(B, {"response_hash": H1})],
                   snapshot=None)
    summary = run(ctx)
    assert summary["same_as"] == 0
    assert "snapshot" in summary["blocked"]
    assert ctx.graph.store.edges == {}


def test_emitted_edges_carry_a_real_binding(tmp_path):
    ctx = make_ctx(tmp_path, nodes=[webapp(A, {"response_hash": H1}),
                                    webapp(B, {"response_hash": H1})])
    run(ctx)
    for e in edges_of(ctx, "same_as"):
        assert e.scope_binding.verdict == Verdict.IN_SCOPE
        assert e.scope_binding.snapshot_id == SNAP.snapshot_id


# --- idempotence ---------------------------------------------------------
def test_rerunning_does_not_duplicate_edges(tmp_path):
    ctx = make_ctx(tmp_path, nodes=[webapp(A, {"response_hash": H1}),
                                    webapp(B, {"response_hash": H1})])
    run(ctx)
    before = len(ctx.graph.store.edges)
    run(ctx)
    assert len(ctx.graph.store.edges) == before


# --- planner integration -------------------------------------------------
def test_planner_schedules_correlate_for_a_fingerprinted_webapp():
    from recon import planner
    store = GraphStore()
    store.apply_node(webapp(A, {"response_hash": H1}))
    keys = {g.id.split(":")[0] for g in planner.plan(store, NOW, allow_active=False)}
    assert "resolve-identity" in keys


def test_planner_stops_scheduling_once_identity_is_resolved():
    from recon import planner
    store = GraphStore()
    store.apply_node(webapp(A, {"response_hash": H1}))
    store.apply_node(webapp(B, {"response_hash": H1}))
    store.apply_edge(make_edge("same_as", A, B, binding=binding(), source="correlate",
                               now=NOW))
    gaps = [g for g in planner.plan(store, NOW, allow_active=False)
            if g.id == f"resolve-identity:{A}"]
    assert gaps == []
