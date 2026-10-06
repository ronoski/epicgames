"""Offline tests for associated_domains (AASA / assetlinks.json)."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone

import pytest

from recon import verbs
from recon.evidence import EvidenceStore
from recon.events import EventLog
from recon.factory import make_node
from recon.models import ScopeBinding, Verdict
from recon.modules.active import associated_domains as mod
from recon.modules.base import GateRefused, ModuleContext
from recon.ratelimit import RateLedger
from recon.scope import Scope
from recon.snapshot import take_snapshot
from recon.store import Graph, GraphStore

NOW = datetime(2026, 1, 10, tzinfo=timezone.utc)
SNAP = take_snapshot("policy v1", now=NOW, include=["*.example.com"])
HOST = "a.example.com"
WEBAPP = f"web:https://{HOST}"


def binding(v=Verdict.IN_SCOPE):
    return ScopeBinding(verdict=v, snapshot_id=SNAP.snapshot_id,
                        observed_at="2026-01-10T00:00:00+00:00")


def webapp(nid=WEBAPP, v=Verdict.IN_SCOPE):
    return make_node("WebApp", nid, binding=binding(v), source="http_probe", now=NOW,
                     coverage={"fingerprinted": True})


def make_ctx(tmp_path, *, allow_active=True, snapshot=SNAP, capacity=100.0,
             include=("*.example.com",)):
    return ModuleContext(
        scope=Scope(include=list(include)),
        ledger=RateLedger(global_qps=10.0, capacity=capacity),
        evidence=EvidenceStore(tmp_path),
        graph=Graph(log=EventLog(), store=GraphStore()),
        snapshot=snapshot, logger=logging.getLogger("t.assoc"),
        allow_active=allow_active, now=NOW,
    )


@dataclass
class FakeResponse:
    status_code: int = 200
    text: str = ""


AASA = {
    "applinks": {"details": [
        {"appID": "TEAMID.com.example.app",
         "paths": ["/account/*", "/reset/*", "NOT /admin/*"]},
    ]},
    "webcredentials": {"apps": ["TEAMID.com.example.app"]},
}

ASSETLINKS = [
    {"relation": ["delegate_permission/common.handle_all_urls"],
     "target": {"namespace": "android_app", "package_name": "com.example.app",
                "sha256_cert_fingerprints": ["AA:BB:CC"]}},
]


def install(monkeypatch, routes):
    """``routes`` maps a path suffix -> FakeResponse (or None for a 404)."""

    calls = []

    def fake_get(url, **kwargs):
        calls.append({"url": url, "kwargs": kwargs})
        for suffix, resp in routes.items():
            if url.endswith(suffix):
                return resp if resp is not None else FakeResponse(404, "")
        return FakeResponse(404, "")

    monkeypatch.setattr(mod.requests, "get", fake_get)
    return calls


def run(ctx, seeds=None):
    return mod.AssociatedDomainsModule(ctx).run(
        seeds if seeds is not None else [webapp()])


def nodes_of(ctx, ntype):
    return [n for n in ctx.graph.store.nodes.values() if n.type == ntype]


# --- contract ----------------------------------------------------------
def test_verb_is_whitelisted_and_active():
    verbs.assert_schedulable(mod.VERB)
    assert verbs.is_active(mod.VERB)
    assert mod.AssociatedDomainsModule.active is True


def test_candidate_paths_are_a_fixed_constant():
    assert isinstance(mod.CANDIDATE_PATHS, tuple)
    assert 0 < len(mod.CANDIDATE_PATHS) <= 6


# --- parsing (pure) -----------------------------------------------------
def test_parse_aasa_modern_list_form():
    parsed = mod.parse_aasa(AASA)
    assert parsed["app_ids"] == ["TEAMID.com.example.app"]
    assert "/account/*" in parsed["paths"]
    assert parsed["webcredentials"] == ["TEAMID.com.example.app"]


def test_parse_aasa_legacy_dict_form():
    legacy = {"applinks": {"details": {
        "TEAMID.com.legacy": {"paths": ["/x/*"]},
    }}}
    parsed = mod.parse_aasa(legacy)
    assert parsed["app_ids"] == ["TEAMID.com.legacy"]
    assert parsed["paths"] == ["/x/*"]


def test_parse_aasa_components_form():
    doc = {"applinks": {"details": [
        {"appIDs": ["T.a", "T.b"], "components": [{"/": "/c/*"}]},
    ]}}
    parsed = mod.parse_aasa(doc)
    assert parsed["app_ids"] == ["T.a", "T.b"]
    assert parsed["paths"] == ["/c/*"]


def test_parse_aasa_tolerates_garbage():
    for junk in ({}, {"applinks": None}, {"applinks": {"details": "nope"}},
                 {"applinks": {"details": [None, 7]}}):
        parsed = mod.parse_aasa(junk)
        assert parsed["app_ids"] == [] and parsed["paths"] == []


def test_parse_assetlinks():
    parsed = mod.parse_assetlinks(ASSETLINKS)
    assert parsed["packages"] == ["com.example.app"]
    assert parsed["fingerprints"] == ["AA:BB:CC"]
    assert parsed["relations"] == ["delegate_permission/common.handle_all_urls"]


def test_parse_assetlinks_tolerates_garbage():
    for junk in ({}, None, [None], [{"target": "x"}], [{"target": {"namespace": "web"}}]):
        parsed = mod.parse_assetlinks(junk)
        assert parsed["packages"] == []


def test_parsers_cap_their_output():
    doc = {"applinks": {"details": [
        {"appID": "T.a", "paths": [f"/p{i}/*" for i in range(mod.MAX_PATHS_PER_HOST + 10)]},
    ]}}
    assert len(mod.parse_aasa(doc)["paths"]) == mod.MAX_PATHS_PER_HOST


# --- emission -----------------------------------------------------------
def test_aasa_emits_an_authscheme_and_the_declared_routes(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    install(monkeypatch, {"apple-app-site-association": FakeResponse(200, json.dumps(AASA))})
    summary = run(ctx)

    assert summary["auth_schemes"] == 1
    scheme = nodes_of(ctx, "AuthScheme")[0]
    assert scheme.id == f"auth:{HOST}:applinks"
    assert scheme.attrs["app_ids"] == ["TEAMID.com.example.app"]
    assert scheme.attrs["active_probed"] is True

    routes = {n.attrs["pattern"] for n in nodes_of(ctx, "Route")}
    assert "/account/*" in routes and "/reset/*" in routes
    # the declared pattern survives verbatim: it is a declaration, not an observed path
    assert "/account/*" in {n.id.rsplit("/", 2)[-2] + "/*" for n in nodes_of(ctx, "Route")} \
        or any(n.attrs["pattern"] == "/account/*" for n in nodes_of(ctx, "Route"))
    assert any(e.type == "authenticates_with" for e in ctx.graph.store.edges.values())
    assert any(e.type == "exposes" for e in ctx.graph.store.edges.values())


def test_a_not_exclusion_is_recorded_as_excluded(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    install(monkeypatch, {"apple-app-site-association": FakeResponse(200, json.dumps(AASA))})
    run(ctx)
    excluded = [n for n in nodes_of(ctx, "Route") if n.attrs.get("excluded")]
    assert excluded and excluded[0].attrs["pattern"] == "/admin/*"


def test_webcredentials_is_called_out(tmp_path, monkeypatch):
    """It is the surface a credential autofill can be aimed at."""

    ctx = make_ctx(tmp_path)
    install(monkeypatch, {"apple-app-site-association": FakeResponse(200, json.dumps(AASA))})
    summary = run(ctx)
    assert summary["webcredentials_hosts"] == [HOST]
    scheme = nodes_of(ctx, "AuthScheme")[0]
    assert scheme.attrs["has_webcredentials"] is True


def test_assetlinks_emits_the_android_association(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    install(monkeypatch, {"assetlinks.json": FakeResponse(200, json.dumps(ASSETLINKS))})
    run(ctx)
    scheme = nodes_of(ctx, "AuthScheme")[0]
    assert scheme.id == f"auth:{HOST}:assetlinks"
    assert scheme.attrs["packages"] == ["com.example.app"]
    assert scheme.attrs["sha256_cert_fingerprints"] == ["AA:BB:CC"]


def test_public_fingerprints_are_not_minted_as_credentials(tmp_path, monkeypatch):
    """They are public identifiers, not secrets."""

    ctx = make_ctx(tmp_path)
    install(monkeypatch, {"assetlinks.json": FakeResponse(200, json.dumps(ASSETLINKS))})
    run(ctx)
    assert nodes_of(ctx, "Credential") == []
    assert nodes_of(ctx, "Token") == []


# --- hypotheses (leads, not findings) -----------------------------------
def test_an_assetlinks_without_a_fingerprint_raises_a_hypothesis(tmp_path, monkeypatch):
    """Any app claiming that package name would match."""

    weak = [{"relation": ["delegate_permission/common.handle_all_urls"],
             "target": {"namespace": "android_app", "package_name": "com.example.app"}}]
    ctx = make_ctx(tmp_path)
    install(monkeypatch, {"assetlinks.json": FakeResponse(200, json.dumps(weak))})
    summary = run(ctx)
    assert summary["hypotheses"] == 1
    hyp = nodes_of(ctx, "Hypothesis")[0]
    assert hyp.id.startswith("hyp:assetlinks-without-fingerprint:")
    assert hyp.confidence.log_odds <= 0.0, "a lead must not look like a finding"


def test_an_aasa_with_no_app_raises_a_hypothesis(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    install(monkeypatch, {"apple-app-site-association":
                          FakeResponse(200, json.dumps({"applinks": {"details": []}}))})
    summary = run(ctx)
    assert summary["hypotheses"] == 1
    assert any(e.kind == "hypothesis_raised" for e in ctx.graph.log.all())


# --- gating -------------------------------------------------------------
def test_every_request_is_gated(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    calls = install(monkeypatch, {"apple-app-site-association":
                                  FakeResponse(200, json.dumps(AASA))})
    run(ctx)
    allows = [e for e in ctx.graph.log.all()
              if e.kind == "gate_decision_recorded" and e.payload.get("decision") == "ALLOW"]
    assert len(allows) == len(calls) >= 1
    assert len(ctx.ledger.log) == len(calls)


def test_nothing_is_requested_when_active_is_disabled(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path, allow_active=False)
    calls = install(monkeypatch, {"apple-app-site-association":
                                  FakeResponse(200, json.dumps(AASA))})
    run(ctx)
    assert calls == [] and ctx.graph.store.nodes == {}


def test_nothing_is_requested_without_a_snapshot(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path, snapshot=None)
    calls = install(monkeypatch, {"apple-app-site-association":
                                  FakeResponse(200, json.dumps(AASA))})
    run(ctx)
    assert calls == []


def test_an_out_of_scope_seed_is_not_probed(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    calls = install(monkeypatch, {"apple-app-site-association":
                                  FakeResponse(200, json.dumps(AASA))})
    run(ctx, [webapp("web:https://evil.invalid", v=Verdict.OUT_OF_SCOPE)])
    assert calls == [] and ctx.graph.store.nodes == {}


def test_an_exhausted_budget_refuses_rather_than_probing(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path, capacity=0.0)
    calls = install(monkeypatch, {"apple-app-site-association":
                                  FakeResponse(200, json.dumps(AASA))})
    summary = run(ctx)
    assert calls == [] and summary["refused"]


def test_a_refusal_does_not_abort_the_remaining_targets(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    install(monkeypatch, {"apple-app-site-association": FakeResponse(200, json.dumps(AASA))})
    original = ctx.gate_active
    seen = {"n": 0}

    def flaky(value, verb, **kwargs):
        seen["n"] += 1
        if seen["n"] == 1:
            raise GateRefused("synthetic")
        return original(value, verb, **kwargs)

    ctx.gate_active = flaky
    summary = run(ctx)
    assert summary["refused"] and summary["requests"] >= 1


# --- robustness ---------------------------------------------------------
def test_one_declaration_per_kind_stops_probing_the_legacy_path(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    calls = install(monkeypatch, {"/.well-known/apple-app-site-association":
                                  FakeResponse(200, json.dumps(AASA))})
    run(ctx)
    hit = [c["url"] for c in calls]
    assert not any(u.endswith("/apple-app-site-association") and ".well-known" not in u
                   for u in hit), "the legacy path is unspent budget once .well-known answers"


def test_a_404_emits_nothing_and_is_counted(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    install(monkeypatch, {})
    summary = run(ctx)
    assert summary["not_found"] >= 1
    assert ctx.graph.store.nodes == {}


def test_malformed_json_is_an_error_not_a_crash(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    install(monkeypatch, {"apple-app-site-association": FakeResponse(200, "not json{")})
    summary = run(ctx)
    assert summary["errors"] and ctx.graph.store.nodes == {}


def test_a_network_error_is_logged_not_raised(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)

    def boom(url, **kwargs):
        raise mod.requests.RequestException("reset")

    monkeypatch.setattr(mod.requests, "get", boom)
    summary = run(ctx)
    assert summary["errors"]


def test_an_oversized_response_is_refused(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    install(monkeypatch, {"apple-app-site-association":
                          FakeResponse(200, "x" * (mod.MAX_RESPONSE_CHARS + 5))})
    summary = run(ctx)
    assert summary["errors"] and ctx.graph.store.nodes == {}


def test_a_403_is_backed_off_from(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    install(monkeypatch, {"apple-app-site-association": FakeResponse(403, "no")})
    summary = run(ctx)
    assert summary["errors"] and ctx.graph.store.nodes == {}


def test_no_redirect_is_followed(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    calls = install(monkeypatch, {"apple-app-site-association":
                                  FakeResponse(200, json.dumps(AASA))})
    run(ctx)
    assert all(c["kwargs"].get("allow_redirects") is False for c in calls)


def test_an_empty_seed_list_is_graceful(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    install(monkeypatch, {})
    assert run(ctx, [])["requests"] == 0


def test_a_non_webapp_seed_is_ignored(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    install(monkeypatch, {})
    seed = make_node("DNSName", "dns:a.example.com", binding=binding(), source="seeds",
                     now=NOW)
    assert run(ctx, [seed])["requests"] == 0


def test_the_seed_cap_is_enforced(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path, capacity=1000.0)
    install(monkeypatch, {})
    seeds = [webapp(f"web:https://h{i}.example.com") for i in range(mod.MAX_SEEDS + 3)]
    summary = run(ctx, seeds)
    assert len(summary["targets"]) == mod.MAX_SEEDS
    assert summary["truncated"] is True


def test_the_raw_document_is_stored_as_evidence(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    body = json.dumps(AASA)
    install(monkeypatch, {"apple-app-site-association": FakeResponse(200, body)})
    run(ctx)
    scheme = nodes_of(ctx, "AuthScheme")[0]
    assert scheme.evidence
    assert ctx.evidence.get(scheme.evidence[0].sha256).decode() == body


def test_graph_satisfies_the_safety_invariants(tmp_path, monkeypatch):
    from recon import invariants
    ctx = make_ctx(tmp_path)
    install(monkeypatch, {"apple-app-site-association": FakeResponse(200, json.dumps(AASA)),
                          "assetlinks.json": FakeResponse(200, json.dumps(ASSETLINKS))})
    run(ctx)
    assert invariants.check(ctx.graph.store, ledger=ctx.ledger,
                            current_snapshot=SNAP.snapshot_id, log=ctx.graph.log,
                            snapshot=SNAP, now=NOW) == []
