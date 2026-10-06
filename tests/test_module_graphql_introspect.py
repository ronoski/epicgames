"""Offline tests for the graphql_introspect module.

Fully deterministic: ``requests.post`` is monkeypatched and no socket is ever opened.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone

import pytest

from recon.evidence import EvidenceStore
from recon.events import EventLog
from recon.factory import make_node
from recon.models import ScopeBinding, Verdict
from recon.modules.active import graphql_introspect as gql
from recon.modules.base import ModuleContext
from recon.ratelimit import RateLedger
from recon.scope import Scope
from recon.snapshot import take_snapshot
from recon.store import Graph, GraphStore
from recon import verbs

NOW = datetime(2026, 1, 10, tzinfo=timezone.utc)
SNAP = take_snapshot("policy v1", now=NOW)
HOST = "api.example.com"
WEBAPP = f"web:https://{HOST}"


def binding(v=Verdict.IN_SCOPE):
    return ScopeBinding(verdict=v, snapshot_id=SNAP.snapshot_id,
                        observed_at="2026-01-10T00:00:00+00:00")


def make_ctx(tmp_path, *, allow_active=True, snapshot=SNAP, capacity=100.0,
             include=("*.example.com",)):
    store = GraphStore()
    return ModuleContext(
        scope=Scope(include=list(include)),
        ledger=RateLedger(global_qps=10.0, capacity=capacity),
        evidence=EvidenceStore(tmp_path),
        graph=Graph(log=EventLog(), store=store),
        snapshot=snapshot,
        logger=logging.getLogger("test.gql"),
        allow_active=allow_active,
        now=NOW,
    )


def webapp_node(verdict=Verdict.IN_SCOPE, node_id=WEBAPP):
    return make_node("WebApp", node_id, binding=binding(verdict), source="http_probe",
                     now=NOW, coverage={"fingerprinted": True})


# --- fake transport ----------------------------------------------------
@dataclass
class FakeResponse:
    status_code: int = 200
    _payload: object = None
    text: str = ""

    def __post_init__(self):
        if self._payload is not None and not self.text:
            self.text = json.dumps(self._payload)

    @property
    def content(self):
        return self.text.encode()

    def json(self):
        return json.loads(self.text)


SCHEMA = {
    "data": {
        "__schema": {
            "queryType": {"name": "Query"},
            "mutationType": {"name": "Mutation"},
            "types": [
                {
                    "name": "Query", "kind": "OBJECT",
                    "fields": [
                        {"name": "account", "type": {"name": "Account", "kind": "OBJECT"},
                         "args": [{"name": "id", "type": {"name": "ID", "kind": "SCALAR"}}]},
                    ],
                },
                {
                    "name": "Mutation", "kind": "OBJECT",
                    "fields": [
                        {"name": "deleteAccount", "type": {"name": "Boolean", "kind": "SCALAR"},
                         "args": [{"name": "id", "type": {"name": "ID", "kind": "SCALAR"}}]},
                    ],
                },
                {"name": "Account", "kind": "OBJECT",
                 "fields": [{"name": "email", "type": {"name": "String", "kind": "SCALAR"},
                             "args": []}]},
                {"name": "__Type", "kind": "OBJECT", "fields": []},  # introspection, skipped
            ],
        }
    }
}


def install(monkeypatch, handler):
    calls = []

    def fake_post(url, **kwargs):
        calls.append((url, kwargs))
        return handler(url, **kwargs)

    monkeypatch.setattr(gql.requests, "post", fake_post)
    return calls


def run(ctx, seeds=None):
    return gql.GraphqlIntrospectModule(ctx).run(
        seeds if seeds is not None else [webapp_node()])


# --- contract ----------------------------------------------------------
def test_verb_is_whitelisted_and_active():
    verbs.assert_schedulable(gql.VERB)
    assert verbs.is_active(gql.VERB)


def test_module_declares_itself_active():
    assert gql.GraphqlIntrospectModule.active is True


def test_candidate_paths_are_a_fixed_constant_not_a_wordlist():
    assert isinstance(gql.CANDIDATE_PATHS, tuple)
    assert 0 < len(gql.CANDIDATE_PATHS) <= 8


def test_introspection_query_is_an_anonymous_query_never_a_mutation():
    q = gql.INTROSPECTION_QUERY.strip()
    assert q.startswith("{")
    assert "mutation" not in q.split("__schema")[0].lower()
    assert "__schema" in q


# --- happy path --------------------------------------------------------
def test_emits_operations_object_types_and_parameters(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    install(monkeypatch, lambda url, **kw: FakeResponse(200, SCHEMA))
    summary = run(ctx)

    assert summary["schemas"] == 1
    ids = set(ctx.graph.store.nodes)
    # root fields become Operations, keyed by field name
    assert any(i.startswith("op:POST:") and i.endswith("#account") for i in ids)
    assert any(i.endswith("#deleteAccount") for i in ids)
    # declared types become ObjectTypes; introspection types are skipped
    assert "obj:Account" in ids
    assert not any(i.startswith("obj:__") for i in ids)
    # declared args become Parameters
    assert any(i.startswith("param:") and i.endswith("#id") for i in ids)


def test_mutation_is_mapped_but_never_executed(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    calls = install(monkeypatch, lambda url, **kw: FakeResponse(200, SCHEMA))
    run(ctx)

    mutation_ops = [n for n in ctx.graph.store.nodes.values()
                    if n.type == "Operation" and n.attrs.get("graphql_kind") == "mutation"]
    assert mutation_ops, "the mutation should be recorded as attack surface"
    # every request body is the pinned introspection document only
    for _url, kwargs in calls:
        body = kwargs.get("json") or {}
        assert set(body) == {"query"}
        assert body["query"] == gql.INTROSPECTION_QUERY
        assert "deleteAccount" not in body["query"]


def test_emitted_nodes_are_marked_active_probed_and_in_scope(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    install(monkeypatch, lambda url, **kw: FakeResponse(200, SCHEMA))
    run(ctx)
    ops = [n for n in ctx.graph.store.nodes.values() if n.type == "Operation"]
    assert ops
    for n in ops:
        assert n.attrs.get("active_probed") is True
        assert n.scope_binding.verdict == Verdict.IN_SCOPE
        assert n.scope_binding.snapshot_id == SNAP.snapshot_id


def test_operations_claim_param_mined_coverage(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    install(monkeypatch, lambda url, **kw: FakeResponse(200, SCHEMA))
    run(ctx)
    ops = [n for n in ctx.graph.store.nodes.values() if n.type == "Operation"]
    assert all(n.coverage.get("param_mined") for n in ops)
    # flow_mapped is deliberately NOT claimed from a schema read
    assert all(not n.coverage.get("flow_mapped") for n in ops)


def test_only_declared_edge_types_are_used(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    install(monkeypatch, lambda url, **kw: FakeResponse(200, SCHEMA))
    run(ctx)
    kinds = {e.type for e in ctx.graph.store.edges.values()}
    assert kinds <= {"exposes", "takes", "references_object"}


def test_stops_at_the_first_endpoint_that_answers(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    calls = install(monkeypatch, lambda url, **kw: FakeResponse(200, SCHEMA))
    run(ctx)
    # the first candidate answered, so the remaining paths are budget left unspent
    assert len(calls) == 1


# --- gating ------------------------------------------------------------
def test_every_request_is_gated(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    calls = install(monkeypatch, lambda url, **kw: FakeResponse(200, SCHEMA))
    run(ctx)
    gate_allows = [e for e in ctx.graph.log.all()
                   if e.kind == "gate_decision_recorded" and e.payload.get("decision") == "ALLOW"]
    assert len(gate_allows) == len(calls) >= 1
    assert len(ctx.ledger.log) == len(calls)


def test_no_request_when_active_disabled(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path, allow_active=False)
    calls = install(monkeypatch, lambda url, **kw: FakeResponse(200, SCHEMA))
    run(ctx)
    assert calls == []
    assert ctx.ledger.log == []


def test_no_request_without_a_snapshot(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path, snapshot=None)
    calls = install(monkeypatch, lambda url, **kw: FakeResponse(200, SCHEMA))
    run(ctx)
    assert calls == []


def test_no_request_for_an_out_of_scope_seed(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    calls = install(monkeypatch, lambda url, **kw: FakeResponse(200, SCHEMA))
    run(ctx, [webapp_node(Verdict.OUT_OF_SCOPE, "web:https://evil.invalid")])
    assert calls == []
    assert ctx.graph.store.nodes == {}


def test_exhausted_budget_refuses_rather_than_probing(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path, capacity=0.0)
    calls = install(monkeypatch, lambda url, **kw: FakeResponse(200, SCHEMA))
    summary = run(ctx)
    assert calls == []
    assert summary["refused"]


# --- negative space: disabled introspection ---------------------------
def test_disabled_introspection_emits_nothing_and_is_recorded(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    err = {"errors": [{"message": "introspection is disabled"}]}
    install(monkeypatch, lambda url, **kw: FakeResponse(200, err))
    summary = run(ctx)
    assert summary["introspection_disabled"]
    assert summary["operations"] == 0
    assert ctx.graph.store.nodes == {}


def test_never_falls_back_to_the_human_gated_field_suggestion_verb(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    err = {"errors": [{"message": "introspection is disabled"}]}
    install(monkeypatch, lambda url, **kw: FakeResponse(200, err))
    run(ctx)
    # The only verb ever spent is the read-only introspection verb: no brute-force
    # fallback when introspection is refused. That gap belongs to a human.
    spent = {e.verb for e in ctx.ledger.log}
    assert spent <= {gql.VERB}
    assert "graphql-field-suggestion" not in spent
    # and the human-gated verb is never schedulable in the first place
    with pytest.raises(verbs.HumanGatedVerb):
        verbs.assert_schedulable("graphql-field-suggestion")


def test_403_is_backed_off_not_worked_around(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    calls = install(monkeypatch, lambda url, **kw: FakeResponse(403, {"m": "no"}))
    summary = run(ctx)
    # one attempt per candidate path at most, no retry of the same shape
    assert len(calls) <= len(gql.CANDIDATE_PATHS)
    assert ctx.graph.store.nodes == {}
    assert summary["operations"] == 0


# --- robustness --------------------------------------------------------
def test_network_error_is_logged_and_does_not_crash(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)

    def boom(url, **kw):
        raise gql.requests.RequestException("connection reset")

    install(monkeypatch, boom)
    summary = run(ctx)
    assert summary["errors"]
    assert summary["operations"] == 0


def test_malformed_json_does_not_crash(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    install(monkeypatch, lambda url, **kw: FakeResponse(200, None, text="not json{"))
    summary = run(ctx)
    assert summary["operations"] == 0


def test_oversized_response_is_refused_not_parsed(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    huge = "x" * (gql.MAX_RESPONSE_CHARS + 10)
    install(monkeypatch, lambda url, **kw: FakeResponse(200, None, text=huge))
    summary = run(ctx)
    assert summary["errors"]
    assert summary["operations"] == 0


def test_empty_seed_list_is_graceful(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    install(monkeypatch, lambda url, **kw: FakeResponse(200, SCHEMA))
    summary = run(ctx, [])
    assert summary["operations"] == 0


def test_seed_cap_is_enforced_and_reported(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path, capacity=1000.0)
    install(monkeypatch, lambda url, **kw: FakeResponse(200, SCHEMA))
    seeds = [webapp_node(node_id=f"web:https://h{i}.example.com")
             for i in range(gql.MAX_SEEDS + 5)]
    summary = run(ctx, seeds)
    assert len(summary["targets"]) <= gql.MAX_SEEDS
    assert summary.get("truncated") is True
