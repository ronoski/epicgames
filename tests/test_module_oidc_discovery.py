"""Offline, deterministic tests for the active oidc_discovery module.

Nothing here touches the network: ``requests.get`` is monkeypatched per test, every other
sender on ``requests`` is replaced with a landmine (so a regression that tried to POST a
token request fails loudly instead of reaching an Epic host), and an autouse fixture makes
``socket``/``ssl`` raise. Time is injected via ``ModuleContext.now`` and the rate ledger gets
a frozen monotonic clock, so timestamps *and* budgets are fixed.
"""

from __future__ import annotations

import json
import logging
import socket
import ssl
from datetime import datetime, timezone

import pytest
import requests

from recon import invariants
from recon.evidence import EvidenceStore, redact, sha256_bytes
from recon.events import EventLog
from recon.models import Sensitivity, Verdict
from recon.modules.base import GateRefused, ModuleContext, get_module
from recon.modules.active import oidc_discovery
from recon.ratelimit import RateLedger
from recon.scope import Scope
from recon.snapshot import take_snapshot
from recon.store import Graph

NOW = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)

HOST = "api.epicgames.dev"
APP = f"web:https://{HOST}"
AUTH = f"auth:{HOST}:oidc"

OIDC_URL = f"https://{HOST}{oidc_discovery.OIDC_PATH}"
AS_URL = f"https://{HOST}{oidc_discovery.OAUTH_AS_PATH}"
JWKS_URL = f"https://{HOST}/epic/oauth/v2/.well-known/jwks.json"

TOKEN_ENDPOINT = f"https://{HOST}/epic/oauth/v2/token"
TOKEN_OP = f"op:POST:route:{APP}/epic/oauth/v2/token"

#: Epic serves its authorize endpoint from a different host than its discovery document
#: (``domains/non-binary.md`` §3.5) — the in-scope cross-host case.
AUTHORIZE_HOST = "www.epicgames.com"
AUTHORIZE_APP = f"web:https://{AUTHORIZE_HOST}"
AUTHORIZE_ENDPOINT = f"https://{AUTHORIZE_HOST}/id/authorize"
AUTHORIZE_OP = f"op:GET:route:{AUTHORIZE_APP}/id/authorize"

#: Every sender the module must never reach for. A token request is a blocked verb.
FORBIDDEN_SENDERS = ("post", "put", "patch", "delete", "options", "head", "request")

DOC = {
    "issuer": f"https://{HOST}",
    "authorization_endpoint": AUTHORIZE_ENDPOINT,
    "token_endpoint": TOKEN_ENDPOINT,
    "jwks_uri": JWKS_URL,
    "grant_types_supported": ["authorization_code", "client_credentials", "refresh_token"],
    "scopes_supported": ["openid", "friends_list", "basic_profile"],
    "response_types_supported": ["code"],
    # Fields this rung does not model. The allowlist must drop both — especially the second.
    "token_endpoint_auth_methods_supported": ["client_secret_basic"],
    "client_secret": "NEVER-STORE-THIS-VALUE",
}

JWKS = {
    "keys": [
        {"kty": "RSA", "kid": "epic-2026-02", "alg": "RS256", "use": "sig",
         "n": "0vx7agoebGcQSuu", "e": "AQAB"},
        {"kty": "RSA", "kid": "epic-2026-01", "alg": "RS256", "use": "sig",
         "n": "mnopqrstuvwxyz", "e": "AQAB"},
    ]
}

KIDS = ["epic-2026-01", "epic-2026-02"]
TOKEN_NODE = f"tok:{oidc_discovery.kid_set_digest(KIDS)}"


# --- harness -------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _no_real_network(monkeypatch):
    """Hard offline guard: any genuine socket/TLS use is a test failure."""

    def _boom(*args, **kwargs):
        raise AssertionError("test attempted a real network connection")

    monkeypatch.setattr(socket, "socket", _boom)
    monkeypatch.setattr(socket, "create_connection", _boom)
    monkeypatch.setattr(ssl, "create_default_context", _boom)


class FakeResponse:
    def __init__(self, status_code: int = 200, text: str = "", headers: dict | None = None):
        self.status_code = status_code
        self.text = text
        self.headers = dict(headers or {})


def json_response(payload, status: int = 200) -> FakeResponse:
    return FakeResponse(status, json.dumps(payload))


def full_responses(doc=None, jwks=None) -> dict:
    """The happy path: a discovery document and the key set it points at."""

    return {
        OIDC_URL: json_response(DOC if doc is None else doc),
        JWKS_URL: json_response(JWKS if jwks is None else jwks),
    }


def _resolve(table, url: str) -> FakeResponse:
    if table is None:
        return FakeResponse(404)
    if isinstance(table, dict):
        return table.get(url, FakeResponse(404))
    if callable(table):
        return table(url)
    return table


def install_fake_http(monkeypatch, responses=None, *, raises=None, log=None) -> list:
    """Patch ``requests.get`` inside the module and landmine every other sender."""

    calls = log if log is not None else []

    def send(url, timeout=None, headers=None, allow_redirects=None, **kwargs):
        calls.append({"kind": "request", "method": "GET", "url": url, "timeout": timeout,
                      "headers": dict(headers or {}), "allow_redirects": allow_redirects,
                      "extra": dict(kwargs)})
        if raises is not None:
            raise raises
        return _resolve(responses, url)

    def landmine(*args, **kwargs):
        raise AssertionError("oidc_discovery sent something other than a GET")

    monkeypatch.setattr(oidc_discovery.requests, "get", send)
    for name in FORBIDDEN_SENDERS:
        monkeypatch.setattr(oidc_discovery.requests, name, landmine, raising=False)
    return calls


def spy_on_gate(monkeypatch, ctx: ModuleContext, calls: list) -> None:
    """Record every ``gate_active`` call into ``calls`` without changing its behavior."""

    real = ctx.gate_active

    def spy(value, verb):
        calls.append({"kind": "gate", "value": value, "verb": verb})
        return real(value, verb)

    monkeypatch.setattr(ctx, "gate_active", spy)


def make_ctx(tmp_path, **overrides) -> ModuleContext:
    scope = Scope(
        include=["*.epicgames.dev", "*.epicgames.com", "203.0.113.0/24"],
        exclude=["secure.epicgames.com"],
        prefilter=["*.fortnite.com"],
    )
    kwargs = dict(
        scope=scope,
        # Frozen monotonic clock: the token bucket never refills mid-test.
        ledger=RateLedger(global_qps=2.0, capacity=20.0, clock=lambda: 0.0),
        evidence=EvidenceStore(tmp_path / "evidence"),
        graph=Graph(EventLog()),
        snapshot=take_snapshot("pinned policy text", now=NOW),
        logger=logging.getLogger("test.oidc_discovery"),
        allow_active=True,
        now=NOW,
    )
    kwargs.update(overrides)
    return ModuleContext(**kwargs)


class FakeNode:
    """Minimal stand-in for a graph Node seed (only ``id``/``type`` are read)."""

    def __init__(self, id: str, type: str) -> None:
        self.id = id
        self.type = type


def webapp(host: str = HOST, scheme: str = "https") -> FakeNode:
    return FakeNode(f"web:{scheme}://{host}", "WebApp")


def run(tmp_path, monkeypatch, seeds, responses=None, **kw):
    ctx = make_ctx(tmp_path, **kw.pop("ctx", {}))
    calls = install_fake_http(monkeypatch, responses, **kw)
    summary = oidc_discovery.OidcDiscoveryModule(ctx).run(seeds)
    return ctx, summary, calls


def requests_made(calls: list) -> list[dict]:
    return [c for c in calls if c["kind"] == "request"]


def urls(calls: list) -> list[str]:
    return [c["url"] for c in requests_made(calls)]


def gates(calls: list) -> list[dict]:
    return [c for c in calls if c["kind"] == "gate"]


def allow_records(ctx: ModuleContext) -> list[dict]:
    return [e.payload for e in ctx.graph.log.by_kind("gate_decision_recorded")
            if e.payload["decision"] == "ALLOW"]


def refuse_records(ctx: ModuleContext) -> list[dict]:
    return [e.payload for e in ctx.graph.log.by_kind("gate_decision_recorded")
            if e.payload["decision"] == "REFUSE"]


def blobs(ctx: ModuleContext) -> str:
    """Every evidence blob this run wrote, concatenated — for 'nothing leaked' assertions."""

    out = []
    for node in ctx.graph.store.nodes.values():
        for ref in node.evidence:
            out.append(ctx.evidence.get(ref.sha256).decode("utf-8"))
    return "\n".join(out)


# --- registration & contract ---------------------------------------------------


def test_registered_under_its_filename_and_is_active():
    assert get_module("oidc_discovery") is oidc_discovery.OidcDiscoveryModule
    assert oidc_discovery.OidcDiscoveryModule.name == "oidc_discovery"
    assert oidc_discovery.OidcDiscoveryModule.active is True
    assert oidc_discovery.OidcDiscoveryModule.produces == (
        "AuthScheme", "Operation", "Token",
    )


def test_verb_is_a_whitelisted_active_verb():
    from recon import verbs

    assert oidc_discovery.VERB == "http-GET"
    assert oidc_discovery.VERB in verbs.ALLOWED
    assert oidc_discovery.VERB in verbs.ACTIVE
    assert oidc_discovery.VERB not in verbs.BLOCKED
    assert oidc_discovery.VERB not in verbs.HUMAN_GATED


def test_only_declared_ontology_types_are_emitted(tmp_path, monkeypatch):
    ctx, _, _ = run(tmp_path, monkeypatch, [webapp()], full_responses())

    assert {n.type for n in ctx.graph.store.nodes.values()} == {
        "AuthScheme", "Operation", "Token",
    }
    assert {e.type for e in ctx.graph.store.edges.values()} == {
        "authenticates_with", "exposes", "issued_by",
    }


# --- request shape -------------------------------------------------------------


def test_one_gated_get_per_touch_with_pinned_request_shape(tmp_path, monkeypatch):
    ctx, summary, calls = run(tmp_path, monkeypatch, [webapp()], full_responses())

    assert urls(calls) == [OIDC_URL, JWKS_URL]
    for call in requests_made(calls):
        assert call["method"] == "GET"
        assert call["headers"] == {"User-Agent": ctx.user_agent,
                                  "Accept": "application/json"}
        assert call["timeout"] == ctx.timeout
        assert call["allow_redirects"] is False
        assert call["extra"] == {}  # no body, no data=, no json=, no cookies=, no auth=
    assert summary["requests"] == 2 and summary["fallbacks"] == 0


def test_no_token_request_is_ever_sent(tmp_path, monkeypatch):
    """The token endpoint is modeled as a contract fact; nothing POSTs to it."""

    ctx, summary, calls = run(tmp_path, monkeypatch, [webapp()], full_responses())

    assert {c["method"] for c in requests_made(calls)} == {"GET"}
    assert TOKEN_ENDPOINT not in urls(calls)
    assert ctx.graph.store.get(TOKEN_OP) is not None  # declared, not touched
    assert [e.verb for e in ctx.ledger.log] == ["http-GET", "http-GET"]
    assert summary["operations"] == 2


def test_duplicate_and_equivalent_seeds_are_queried_once(tmp_path, monkeypatch):
    seeds = [webapp(), webapp(), FakeNode(f"web:https://{HOST.upper()}", "WebApp"), HOST]
    _, summary, calls = run(tmp_path, monkeypatch, seeds, full_responses())

    assert summary["webapps"] == [APP]
    assert summary["seeds_in"] == 4 and summary["seeds_deduped"] == 3
    assert urls(calls) == [OIDC_URL, JWKS_URL]


def test_seed_cap_truncates_instead_of_running_away(tmp_path, monkeypatch):
    monkeypatch.setattr(oidc_discovery, "MAX_SEED_NODES", 2)
    seeds = [webapp(f"h{i}.epicgames.dev") for i in range(5)]
    _, summary, calls = run(tmp_path, monkeypatch, seeds)

    assert summary["webapps"] == ["web:https://h0.epicgames.dev",
                                  "web:https://h1.epicgames.dev"]
    assert summary["seeds_truncated"] is True
    # two targets × (404 on the OIDC path, 404 on the fallback); no third target at all
    assert len(urls(calls)) == 4
    assert not any("h2.epicgames.dev" in u for u in urls(calls))


# --- the gate is the chokepoint ------------------------------------------------


def test_every_request_is_immediately_preceded_by_its_own_gate(tmp_path, monkeypatch):
    calls: list = []
    ctx = make_ctx(tmp_path)
    spy_on_gate(monkeypatch, ctx, calls)
    install_fake_http(monkeypatch, full_responses(), log=calls)

    oidc_discovery.OidcDiscoveryModule(ctx).run([webapp()])

    # Strict alternation: gate, request, gate, request … one gate per network touch.
    assert [c["kind"] for c in calls] == ["gate", "request"] * 2
    assert [c["verb"] for c in gates(calls)] == ["http-GET", "http-GET"]
    assert [c["value"] for c in gates(calls)] == [HOST, HOST]
    assert len(allow_records(ctx)) == 2


def test_the_fallback_path_is_separately_gated(tmp_path, monkeypatch):
    calls: list = []
    ctx = make_ctx(tmp_path)
    spy_on_gate(monkeypatch, ctx, calls)
    install_fake_http(monkeypatch, {
        OIDC_URL: FakeResponse(404),
        AS_URL: json_response({"issuer": f"https://{HOST}",
                               "token_endpoint": TOKEN_ENDPOINT,
                               "grant_types_supported": ["client_credentials"]}),
    }, log=calls)

    summary = oidc_discovery.OidcDiscoveryModule(ctx).run([webapp()])

    assert [c["kind"] for c in calls] == ["gate", "request", "gate", "request"]
    assert [c.get("url") for c in requests_made(calls)] == [OIDC_URL, AS_URL]
    assert summary["fallbacks"] == 1 and summary["documents"] == 1
    assert len(allow_records(ctx)) == 2
    assert ctx.graph.store.get(AUTH) is not None
    assert ctx.graph.store.get(TOKEN_OP) is not None


def test_each_touch_debits_the_unified_ledger_once(tmp_path, monkeypatch):
    ctx, summary, calls = run(tmp_path, monkeypatch, [webapp()], full_responses())

    assert len(ctx.ledger.log) == len(requests_made(calls)) == 2
    assert {e.target for e in ctx.ledger.log} == {"epicgames.dev"}  # keyed by registrable
    assert ctx.ledger.balance(HOST) == pytest.approx(18.0)
    assert all(e.balance_after >= 0 for e in ctx.ledger.log)
    assert summary["refused"] == 0 and summary["refused_by_reason"] == {}


@pytest.mark.parametrize("override, fragment", [
    ({"allow_active": False}, "allow_active=false"),
    ({"snapshot": None}, "no scope snapshot"),
    ({"snapshot": take_snapshot("old", now=datetime(2026, 1, 1, tzinfo=timezone.utc))},
     "stale"),
])
def test_gate_refusal_skips_without_sending_anything(tmp_path, monkeypatch, override,
                                                     fragment):
    ctx, summary, calls = run(tmp_path, monkeypatch, [webapp()], full_responses(),
                              ctx=override)

    assert requests_made(calls) == []  # refused means no packet, not a quieter packet
    assert ctx.graph.store.nodes == {} and ctx.graph.store.edges == {}
    assert ctx.ledger.log == []
    assert summary["requests"] == 0 and summary["refused"] == 1
    assert all(fragment in reason for reason in summary["refused_by_reason"])
    assert len(refuse_records(ctx)) == 1


@pytest.mark.parametrize("host", [
    "secure.epicgames.com",    # excluded -> out_of_scope
    "www.fortnite.com",        # owned-but-unlisted -> prefilter_only
    "fhir.epic.com",           # default deny
    "203.0.114.9",             # outside the in-scope netblock
])
def test_out_of_scope_targets_are_never_touched(tmp_path, monkeypatch, host):
    ctx, summary, calls = run(tmp_path, monkeypatch, [webapp(host)], full_responses())

    assert requests_made(calls) == []
    assert ctx.graph.store.nodes == {}
    assert summary["requests"] == 0 and summary["refused"] == 1
    assert all("not in scope" in reason for reason in summary["refused_by_reason"])


def test_a_refused_discovery_path_never_tries_the_fallback(tmp_path, monkeypatch):
    ctx, summary, calls = run(tmp_path, monkeypatch, [webapp()], full_responses(),
                              ctx={"allow_active": False})

    assert calls == [] and summary["gated"] == 1 and summary["fallbacks"] == 0


def test_exhausted_budget_refuses_the_jwks_and_keeps_the_document(tmp_path, monkeypatch):
    ctx, summary, calls = run(
        tmp_path, monkeypatch, [webapp()], full_responses(),
        ctx={"ledger": RateLedger(global_qps=1.0, capacity=1.0, clock=lambda: 0.0)},
    )

    assert urls(calls) == [OIDC_URL]  # the jwks touch is refused, not borrowed
    assert summary["refused"] == 1
    assert all("rate budget exceeded" in r for r in summary["refused_by_reason"])
    assert ctx.graph.store.get(AUTH) is not None
    assert not list(ctx.graph.store.iter_type("Token"))
    assert all(e.balance_after >= 0 for e in ctx.ledger.log)
    assert invariants.check(ctx.graph.store, ledger=ctx.ledger,
                            current_snapshot=ctx.snapshot.snapshot_id) == []


def test_module_cannot_request_by_swallowing_a_refusal(tmp_path, monkeypatch):
    """A refusing gate must stop the request, however the refusal arrives."""

    ctx = make_ctx(tmp_path)
    calls = install_fake_http(monkeypatch, full_responses())
    monkeypatch.setattr(
        ctx, "gate_active",
        lambda value, verb: (_ for _ in ()).throw(GateRefused("synthetic refusal")),
    )

    summary = oidc_discovery.OidcDiscoveryModule(ctx).run([webapp()])

    assert requests_made(calls) == []
    assert ctx.graph.store.nodes == {}
    assert summary["refused_by_reason"] == {"synthetic refusal": 1}


# --- the AuthScheme node -------------------------------------------------------


def test_auth_scheme_envelope_and_attrs(tmp_path, monkeypatch):
    ctx, summary, _ = run(tmp_path, monkeypatch, [webapp()], full_responses())

    node = ctx.graph.store.get(AUTH)
    assert node is not None and node.type == "AuthScheme"
    assert node.attrs == {
        "active_probed": True,
        "issuer": f"https://{HOST}",
        "authorization_endpoint": AUTHORIZE_ENDPOINT,
        "token_endpoint": TOKEN_ENDPOINT,
        "jwks_uri": JWKS_URL,
        # sorted + deduplicated, so the attr does not depend on the server's order
        "grant_types_supported": ["authorization_code", "client_credentials",
                                  "refresh_token"],
        "scopes_supported": ["basic_profile", "friends_list", "openid"],
        "response_types_supported": ["code"],
    }
    assert node.coverage == {"fingerprinted": True, "flow_mapped": True}
    assert node.confidence.log_odds == pytest.approx(oidc_discovery.METADATA_LOG_ODDS)
    assert node.confidence.state.value == "observed"  # one source never self-promotes
    assert node.sensitivity == Sensitivity.S0
    assert node.data_subject == "none"
    assert node.provenance.chain[0].tool == "oidc_discovery"
    assert node.provenance.chain[0].rule_id == oidc_discovery.RULE_ID
    assert node.temporal.first_seen == NOW.isoformat()
    assert summary["auth_schemes"] == 1


def test_unmodeled_and_secret_shaped_fields_never_reach_an_attr(tmp_path, monkeypatch):
    ctx, _, _ = run(tmp_path, monkeypatch, [webapp()], full_responses())

    node = ctx.graph.store.get(AUTH)
    assert "client_secret" not in node.attrs
    assert "token_endpoint_auth_methods_supported" not in node.attrs
    assert "NEVER-STORE-THIS-VALUE" not in repr(node.to_dict())


def test_authenticates_with_edge_joins_the_seed_webapp(tmp_path, monkeypatch):
    ctx, summary, _ = run(tmp_path, monkeypatch, [webapp()], full_responses())

    edges = ctx.graph.store.out_edges(APP, "authenticates_with")
    assert [(e.frm, e.to) for e in edges] == [(APP, AUTH)]
    assert edges[0].attrs == {"active_probed": True}
    assert edges[0].scope_binding.verdict == Verdict.IN_SCOPE
    assert summary["edges"] == 4  # authenticates_with + 2 exposes + issued_by


def test_binding_comes_from_the_gate_and_pins_the_snapshot(tmp_path, monkeypatch):
    ctx, _, _ = run(tmp_path, monkeypatch, [webapp()], full_responses())

    assert ctx.graph.store.nodes
    for datum in (list(ctx.graph.store.nodes.values())
                  + list(ctx.graph.store.edges.values())):
        assert datum.scope_binding.verdict == Verdict.IN_SCOPE
        assert datum.scope_binding.snapshot_id == ctx.snapshot.snapshot_id
        assert datum.scope_binding.observed_at == NOW.isoformat()


def test_flow_mapped_is_only_claimed_when_a_flow_vocabulary_is_declared(tmp_path,
                                                                        monkeypatch):
    bare = {"issuer": f"https://{HOST}", "token_endpoint": TOKEN_ENDPOINT,
            "scopes_supported": ["openid"]}
    ctx, _, _ = run(tmp_path, monkeypatch, [webapp()], {OIDC_URL: json_response(bare)})

    assert ctx.graph.store.get(AUTH).coverage == {"fingerprinted": True}


def test_a_document_with_no_recognized_field_emits_nothing(tmp_path, monkeypatch):
    ctx, summary, _ = run(tmp_path, monkeypatch, [webapp()],
                          {OIDC_URL: json_response({"hello": "world"})})

    assert ctx.graph.store.nodes == {}
    assert summary["errors_by_kind"] == {"no_recognized_metadata": 1}
    assert summary["documents"] == 0


def test_a_ported_authority_keeps_canonical_ids(tmp_path, monkeypatch):
    host = "203.0.113.7"
    doc = {"issuer": f"https://{host}:8443", "token_endpoint": f"https://{host}:8443/t"}
    ctx, _, calls = run(tmp_path, monkeypatch, [webapp(f"{host}:8443")],
                        {f"https://{host}:8443{oidc_discovery.OIDC_PATH}":
                         json_response(doc)})

    assert urls(calls) == [f"https://{host}:8443{oidc_discovery.OIDC_PATH}"]
    assert ctx.graph.store.get(f"auth:{host}:8443:oidc") is not None
    assert ctx.graph.store.get(f"op:POST:route:web:https://{host}:8443/t") is not None


# --- Operation nodes + exposes edges -------------------------------------------


def test_operations_are_keyed_under_the_host_that_serves_them(tmp_path, monkeypatch):
    ctx, summary, _ = run(tmp_path, monkeypatch, [webapp()], full_responses())

    token_op = ctx.graph.store.get(TOKEN_OP)
    assert token_op is not None and token_op.type == "Operation"
    assert token_op.attrs == {
        "active_probed": True, "method": "POST", "path_template": "/epic/oauth/v2/token",
        "endpoint_role": "token", "webapp": APP,
    }
    assert token_op.coverage == {"enumerated": True}  # declared; no parameter mined
    assert token_op.sensitivity == Sensitivity.S0 and token_op.data_subject == "none"
    assert token_op.confidence.log_odds == pytest.approx(
        oidc_discovery.DECLARED_ENDPOINT_LOG_ODDS
    )

    authorize_op = ctx.graph.store.get(AUTHORIZE_OP)
    assert authorize_op is not None
    assert authorize_op.attrs["method"] == "GET"
    assert authorize_op.attrs["webapp"] == AUTHORIZE_APP  # a different, in-scope host

    assert {(e.frm, e.to) for e in ctx.graph.store.edges.values() if e.type == "exposes"} == {
        (APP, TOKEN_OP), (AUTHORIZE_APP, AUTHORIZE_OP),
    }
    assert summary["operations"] == 2


def test_an_out_of_scope_endpoint_host_gets_no_node_and_no_edge(tmp_path, monkeypatch):
    doc = dict(DOC, authorization_endpoint="https://login.thirdparty.example/authorize")
    ctx, summary, _ = run(tmp_path, monkeypatch, [webapp()], full_responses(doc))

    assert [n.id for n in ctx.graph.store.iter_type("Operation")] == [TOKEN_OP]
    assert summary["endpoints_dropped_by_verdict"] == {"out_of_scope": 1}
    assert not any("thirdparty.example" in e.id for e in ctx.graph.store.edges.values())
    # the url itself stays recorded as data ABOUT the in-scope AuthScheme
    assert ctx.graph.store.get(AUTH).attrs["authorization_endpoint"] == (
        "https://login.thirdparty.example/authorize"
    )


def test_a_prefilter_only_endpoint_host_is_not_retained(tmp_path, monkeypatch):
    doc = dict(DOC, authorization_endpoint="https://account.fortnite.com/authorize")
    ctx, summary, _ = run(tmp_path, monkeypatch, [webapp()], full_responses(doc))

    assert [n.id for n in ctx.graph.store.iter_type("Operation")] == [TOKEN_OP]
    assert summary["endpoints_dropped_by_verdict"] == {"prefilter_only": 1}


def test_a_userinfo_bearing_endpoint_url_is_dropped_entirely(tmp_path, monkeypatch):
    secret = "s3cr3t-client-password"
    doc = dict(DOC, token_endpoint=f"https://client:{secret}@{HOST}/epic/oauth/v2/token")
    ctx, summary, _ = run(tmp_path, monkeypatch, [webapp()], full_responses(doc))

    node = ctx.graph.store.get(AUTH)
    assert "token_endpoint" not in node.attrs
    assert secret not in repr(node.to_dict())
    assert ctx.graph.store.get(TOKEN_OP) is None
    assert [n.id for n in ctx.graph.store.iter_type("Operation")] == [AUTHORIZE_OP]
    assert summary["operations"] == 1


def test_an_endpoint_query_is_kept_but_never_becomes_the_route(tmp_path, monkeypatch):
    doc = dict(DOC, token_endpoint=f"{TOKEN_ENDPOINT}?v=2")
    ctx, _, _ = run(tmp_path, monkeypatch, [webapp()], full_responses(doc))

    assert ctx.graph.store.get(AUTH).attrs["token_endpoint"] == f"{TOKEN_ENDPOINT}?v=2"
    assert ctx.graph.store.get(TOKEN_OP).attrs["path_template"] == "/epic/oauth/v2/token"


# --- the JWKS / Token node -----------------------------------------------------


def test_token_node_from_the_key_set(tmp_path, monkeypatch):
    ctx, summary, calls = run(tmp_path, monkeypatch, [webapp()], full_responses())

    assert urls(calls)[-1] == JWKS_URL
    node = ctx.graph.store.get(TOKEN_NODE)
    assert node is not None and node.type == "Token"
    assert node.attrs == {"active_probed": True, "kids": KIDS, "algs": ["RS256"]}
    # I8: a Token node is never S0, even though JWKS material is public.
    assert node.sensitivity == Sensitivity.S1
    assert node.coverage == {"fingerprinted": True}
    assert node.data_subject == "none"
    assert node.confidence.log_odds == pytest.approx(oidc_discovery.METADATA_LOG_ODDS)

    edges = ctx.graph.store.out_edges(TOKEN_NODE, "issued_by")
    assert [(e.frm, e.to) for e in edges] == [(TOKEN_NODE, AUTH)]
    assert edges[0].scope_binding.verdict == Verdict.IN_SCOPE
    assert summary["jwks_fetched"] == 1 and summary["tokens"] == 1


def test_no_key_material_reaches_an_attribute(tmp_path, monkeypatch):
    ctx, _, _ = run(tmp_path, monkeypatch, [webapp()], full_responses())

    node = ctx.graph.store.get(TOKEN_NODE)
    assert set(node.attrs) == {"active_probed", "kids", "algs"}
    assert "0vx7agoebGcQSuu" not in repr(node.to_dict())


def test_a_rotated_key_set_mints_a_new_token_rather_than_forking(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    install_fake_http(monkeypatch, full_responses())
    oidc_discovery.OidcDiscoveryModule(ctx).run([webapp()])
    monkeypatch.undo()
    rotated = {"keys": [{"kty": "RSA", "kid": "epic-2026-03", "alg": "RS256",
                         "n": "z", "e": "AQAB"}]}
    install_fake_http(monkeypatch, full_responses(jwks=rotated))
    oidc_discovery.OidcDiscoveryModule(ctx).run([webapp()])

    rotated_id = f"tok:{oidc_discovery.kid_set_digest(['epic-2026-03'])}"
    assert sorted(n.id for n in ctx.graph.store.iter_type("Token")) == sorted(
        [TOKEN_NODE, rotated_id]
    )
    assert not any("#fork" in n.id for n in ctx.graph.store.nodes.values())


def test_a_private_jwk_member_is_redacted_before_it_can_be_stored(tmp_path, monkeypatch):
    private = "VERY-PRIVATE-EXPONENT"
    leaky = {"keys": [dict(JWKS["keys"][0], d=private)]}
    ctx, summary, _ = run(tmp_path, monkeypatch, [webapp()], full_responses(jwks=leaky))

    assert summary["private_jwk_members_redacted"] == 1
    token = next(iter(ctx.graph.store.iter_type("Token")))
    assert "d" not in token.attrs and private not in repr(token.to_dict())
    blob = blobs(ctx)
    assert private not in blob
    assert redact(private) in blob  # the omission stays explicit and replayable


def test_a_jwks_without_a_kid_mints_no_token(tmp_path, monkeypatch):
    ctx, summary, _ = run(tmp_path, monkeypatch, [webapp()],
                          full_responses(jwks={"keys": [{"kty": "RSA", "n": "x"}]}))

    assert not list(ctx.graph.store.iter_type("Token"))
    assert summary["jwks_fetched"] == 1 and summary["jwks_without_kid"] == 1
    assert ctx.graph.store.get(AUTH) is not None  # the document still stands


def test_an_out_of_scope_jwks_host_is_never_fetched(tmp_path, monkeypatch):
    foreign = "https://keys.thirdparty.example/jwks.json"
    ctx, summary, calls = run(tmp_path, monkeypatch, [webapp()],
                              full_responses(dict(DOC, jwks_uri=foreign)))

    assert urls(calls) == [OIDC_URL]  # no packet at a host the policy does not list
    assert summary["jwks_skipped_out_of_scope"] == 1 and summary["tokens"] == 0
    assert ctx.graph.store.get(AUTH).attrs["jwks_uri"] == foreign
    assert refuse_records(ctx) == []  # not even a wasted REFUSE record


@pytest.mark.parametrize("response, kind", [
    (FakeResponse(500), None),
    (FakeResponse(200, "<html>not json</html>"), "not_valid_json"),
    (FakeResponse(200, "[]"), "json_was_not_an_object"),
])
def test_an_unusable_jwks_response_keeps_the_document(tmp_path, monkeypatch, response,
                                                      kind):
    ctx, summary, _ = run(tmp_path, monkeypatch, [webapp()],
                          {OIDC_URL: json_response(DOC), JWKS_URL: response})

    assert ctx.graph.store.get(AUTH) is not None
    assert not list(ctx.graph.store.iter_type("Token"))
    if kind:
        assert summary["errors_by_kind"] == {kind: 1}


# --- status handling -----------------------------------------------------------


@pytest.mark.parametrize("status", [301, 302, 401, 403, 429, 500, 503])
def test_a_non_404_status_ends_the_target_without_a_fallback(tmp_path, monkeypatch,
                                                             status):
    ctx, summary, calls = run(tmp_path, monkeypatch, [webapp()],
                              {OIDC_URL: FakeResponse(status)})

    assert urls(calls) == [OIDC_URL]  # back off; never try the other door
    assert ctx.graph.store.nodes == {}
    assert summary["fallbacks"] == 0 and summary["documents"] == 0


def test_both_paths_404_emits_nothing(tmp_path, monkeypatch):
    ctx, summary, calls = run(tmp_path, monkeypatch, [webapp()], {})

    assert urls(calls) == [OIDC_URL, AS_URL]
    assert ctx.graph.store.nodes == {}
    assert summary["fallbacks"] == 1 and summary["documents"] == 0
    assert summary["errors"] == 0  # a 404 is an answer, not an error


@pytest.mark.parametrize("status", [None, "200", 99, 600, True])
def test_an_unusable_status_is_logged_and_skipped(tmp_path, monkeypatch, status):
    ctx, summary, _ = run(tmp_path, monkeypatch, [webapp()],
                          {OIDC_URL: FakeResponse(status, json.dumps(DOC))})

    assert ctx.graph.store.nodes == {}
    assert summary["errors_by_kind"] == {"no_usable_status_code": 1}


# --- evidence ------------------------------------------------------------------


def test_the_document_is_stored_as_content_addressed_evidence(tmp_path, monkeypatch):
    ctx, _, _ = run(tmp_path, monkeypatch, [webapp()], full_responses())

    expected = "\n".join([
        f"oidc_discovery/{oidc_discovery.RULE_VERSION} verb=http-GET",
        f"url={OIDC_URL}",
        "status=200",
        "document=" + oidc_discovery.canonical_json(DOC),
    ])
    sha = sha256_bytes(expected.encode("utf-8"))
    node = ctx.graph.store.get(AUTH)
    assert [e.sha256 for e in node.evidence] == [sha]
    assert node.evidence[0].region == f"oidc_discovery:GET {OIDC_URL}"
    assert node.evidence[0].encrypted_at_rest is True
    assert node.provenance.chain[0].evidence_id == sha
    assert ctx.evidence.get(sha).decode("utf-8") == expected
    # every node derived from the document points at the same proof
    assert [e.sha256 for e in ctx.graph.store.get(TOKEN_OP).evidence] == [sha]


def test_document_key_order_does_not_change_the_evidence_hash(tmp_path, monkeypatch):
    forward = dict(DOC)
    reversed_doc = dict(reversed(list(DOC.items())))
    ctx_a, _, _ = run(tmp_path, monkeypatch, [webapp()], full_responses(forward))
    ctx_b, _, _ = run(tmp_path, monkeypatch, [webapp()], full_responses(reversed_doc))

    assert ([e.sha256 for e in ctx_a.graph.store.get(AUTH).evidence]
            == [e.sha256 for e in ctx_b.graph.store.get(AUTH).evidence])


def test_an_unwritable_evidence_store_does_not_fail_the_read(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    install_fake_http(monkeypatch, full_responses())

    def boom(*args, **kwargs):
        raise OSError("read-only filesystem")

    monkeypatch.setattr(ctx.evidence, "put_text", boom)
    summary = oidc_discovery.OidcDiscoveryModule(ctx).run([webapp()])

    assert summary["auth_schemes"] == 1 and summary["tokens"] == 1
    assert ctx.graph.store.get(AUTH).evidence == []


# --- failure handling ----------------------------------------------------------


@pytest.mark.parametrize("exc", [
    requests.ConnectionError("down"),
    requests.Timeout("slow"),
    requests.TooManyRedirects("loop"),
    requests.RequestException("boom"),
    RuntimeError("unknown transport"),
])
def test_network_errors_do_not_crash_the_run(tmp_path, monkeypatch, exc):
    ctx, summary, calls = run(tmp_path, monkeypatch, [webapp()], raises=exc)

    assert len(requests_made(calls)) == 1  # one attempt, no retry, no fallback
    assert ctx.graph.store.nodes == {} and ctx.graph.store.edges == {}
    assert summary["errors"] == 1 and summary["documents"] == 0
    assert summary["requests"] == 1  # the budget was spent, and is recorded as spent
    assert len(ctx.ledger.log) == 1


def test_one_bad_target_does_not_stop_the_others(tmp_path, monkeypatch):
    other = "auth.epicgames.com"
    other_doc = {"issuer": f"https://{other}", "grant_types_supported": ["refresh_token"]}

    def responses(url):
        if HOST in url:
            raise requests.ConnectionError("down")
        if url == f"https://{other}{oidc_discovery.OIDC_PATH}":
            return json_response(other_doc)
        return FakeResponse(404)

    ctx, summary, _ = run(tmp_path, monkeypatch, [webapp(), webapp(other)], responses)

    assert [n.id for n in ctx.graph.store.iter_type("AuthScheme")] == [f"auth:{other}:oidc"]
    assert summary["errors"] == 1 and summary["auth_schemes"] == 1


def test_an_undecodable_body_is_an_error_not_a_crash(tmp_path, monkeypatch):
    class Hostile:
        status_code = 200
        headers: dict = {}

        @property
        def text(self):
            raise RuntimeError("undecodable")

    ctx, summary, _ = run(tmp_path, monkeypatch, [webapp()], {OIDC_URL: Hostile()})

    assert ctx.graph.store.nodes == {}
    assert summary["errors_by_kind"] == {"not_valid_json": 1}


# --- seeds ---------------------------------------------------------------------


def test_empty_and_junk_seeds_are_graceful(tmp_path, monkeypatch):
    for seeds in ([], None, ["", "   ", None, 42, "not a host", "web:ftp://x.epicgames.dev"]):
        ctx, summary, calls = run(tmp_path, monkeypatch, seeds, full_responses())
        assert requests_made(calls) == []
        assert summary["webapps"] == [] and summary["auth_schemes"] == 0
        assert ctx.ledger.log == []


def test_foreign_seed_node_types_are_ignored(tmp_path, monkeypatch):
    seeds = [
        FakeNode(f"dns:{HOST}", "DNSName"),
        FakeNode(f"domain:{HOST}", "Domain"),
        FakeNode("host:203.0.113.5", "Host"),
        FakeNode("svc:203.0.113.5:443/tcp", "Service"),
        FakeNode(f"auth:{HOST}:oidc", "AuthScheme"),
        FakeNode("hyp:dns-candidate:x.epicgames.dev", "Hypothesis"),
        webapp(),
    ]
    _, summary, calls = run(tmp_path, monkeypatch, seeds, full_responses())

    assert summary["webapps"] == [APP]
    assert summary["seeds_skipped"] == 6
    assert urls(calls) == [OIDC_URL, JWKS_URL]


def test_a_plaintext_webapp_seed_is_queried_over_its_own_scheme(tmp_path, monkeypatch):
    url = f"http://{HOST}{oidc_discovery.OIDC_PATH}"
    ctx, _, calls = run(tmp_path, monkeypatch, [webapp(scheme="http")],
                        {url: json_response({"issuer": f"http://{HOST}"})})

    assert urls(calls) == [url]
    # the AuthScheme is keyed on the authority, so both schemes fold onto one auth model
    assert ctx.graph.store.get(AUTH) is not None
    assert ctx.graph.store.out_edges(f"web:http://{HOST}", "authenticates_with")


# --- idempotence, forking, invariants ------------------------------------------


def test_rerun_with_the_same_document_merges_without_forking(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    install_fake_http(monkeypatch, full_responses())
    module = oidc_discovery.OidcDiscoveryModule(ctx)
    module.run([webapp()])
    module.run([webapp()])

    assert [n.id for n in ctx.graph.store.iter_type("AuthScheme")] == [AUTH]
    node = ctx.graph.store.get(AUTH)
    assert "#fork" not in node.id
    assert node.coverage == {"fingerprinted": True, "flow_mapped": True}
    assert node.attrs["issuer"] == f"https://{HOST}"
    assert not any("#fork" in i for i in ctx.graph.store.nodes)


def test_a_changed_issuer_forks_instead_of_overwriting(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    install_fake_http(monkeypatch, full_responses())
    oidc_discovery.OidcDiscoveryModule(ctx).run([webapp()])
    monkeypatch.undo()
    install_fake_http(monkeypatch,
                      full_responses(dict(DOC, issuer="https://id.epicgames.com")))
    oidc_discovery.OidcDiscoveryModule(ctx).run([webapp()])

    assert ctx.graph.store.get(AUTH).attrs["issuer"] == f"https://{HOST}"  # never rewritten
    fork = ctx.graph.store.get(f"{AUTH}#fork1")
    assert fork is not None and fork.attrs["issuer"] == "https://id.epicgames.com"
    assert fork.confidence.forked_from == AUTH
    assert any(e.kind == "contradiction_forked" for e in ctx.graph.log.all())


def test_graph_satisfies_the_safety_invariants(tmp_path, monkeypatch):
    seeds = [
        webapp(),
        webapp("auth.epicgames.com"),
        webapp("secure.epicgames.com"),    # excluded
        webapp("www.fortnite.com"),        # prefilter only
        FakeNode(f"dns:{HOST}", "DNSName"),
    ]

    def responses(url):
        if url.startswith(f"https://{HOST}{oidc_discovery.OIDC_PATH}"):
            return json_response(DOC)
        if url == JWKS_URL:
            return json_response(JWKS)
        if url == f"https://auth.epicgames.com{oidc_discovery.OIDC_PATH}":
            return json_response({"issuer": "https://auth.epicgames.com",
                                  "token_endpoint": "https://auth.epicgames.com/oauth/token",
                                  "grant_types_supported": ["authorization_code"]})
        return FakeResponse(404)

    ctx, summary, _ = run(tmp_path, monkeypatch, seeds, responses)

    assert summary["auth_schemes"] == 2 and summary["tokens"] == 1
    assert summary["refused"] == 2
    assert invariants.check(ctx.graph.store, ledger=ctx.ledger,
                            current_snapshot=ctx.snapshot.snapshot_id) == []
    for node in ctx.graph.store.nodes.values():
        assert node.attrs["active_probed"] is True
        assert node.scope_binding.verdict == Verdict.IN_SCOPE


# --- pure helpers --------------------------------------------------------------


@pytest.mark.parametrize("value, expected", [
    (f"https://{HOST}/epic/oauth/v2/token", f"https://{HOST}/epic/oauth/v2/token"),
    ("HTTPS://API.EPICGAMES.DEV/Path", f"https://{HOST}/Path"),
    (f"http://{HOST}/t", f"http://{HOST}/t"),            # plaintext is recorded, not endorsed
    (f"https://{HOST}/t?v=2", f"https://{HOST}/t?v=2"),  # query kept: the issuer's statement
    (f"https://{HOST}/cb#access_token=SECRET", f"https://{HOST}/cb"),  # fragment dropped
    (f"https://u:p@{HOST}/t", ""),                       # userinfo: dropped, not cleaned
    (f"https://{HOST}:8443/t", f"https://{HOST}:8443/t"),
    (f"https://{HOST}:notaport/t", ""),
    ("https://[2001:db8::1]/t", "https://[2001:db8::1]/t"),
    ("com.epicgames.launcher://store", ""),              # a deeplink is not an endpoint
    ("urn:ietf:params:oauth:grant-type:device_code", ""),
    (f"https://{HOST}/\x00evil", ""),
    (f"https://{HOST}/a b", ""),
    ("", ""),
    ("   ", ""),
    (None, ""),
    (12345, ""),
    (["https://x.epicgames.dev/"], ""),
])
def test_safe_url_canonicalization(value, expected):
    assert oidc_discovery.safe_url(value) == expected


def test_safe_url_caps_a_runaway_value():
    assert oidc_discovery.safe_url(f"https://{HOST}/" + "x" * 1000) == ""


@pytest.mark.parametrize("value, expected", [
    (["b", "a", "a"], ["a", "b"]),
    (("refresh_token", "authorization_code"), ["authorization_code", "refresh_token"]),
    ("not a list", []),
    ([{"x": 1}, "ok", None, 5, ["y"]], ["5", "ok"]),
    ([], []),
    (None, []),
])
def test_short_tokens_is_sorted_deduplicated_and_scalar_only(value, expected):
    assert oidc_discovery.short_tokens(value) == expected


def test_short_tokens_respects_its_cap():
    assert oidc_discovery.short_tokens([f"s{i:02d}" for i in range(50)], limit=3) == [
        "s00", "s01", "s02",
    ]


def test_metadata_attrs_is_an_allowlist():
    assert oidc_discovery.metadata_attrs({
        "issuer": f"https://{HOST}",
        "jwks_uri": "",
        "scopes_supported": [],
        "client_secret": "nope",
        "registration_endpoint": f"https://{HOST}/register",
    }) == {"issuer": f"https://{HOST}"}
    assert oidc_discovery.metadata_attrs({}) == {}


def test_kid_set_digest_is_order_independent_and_stable():
    assert oidc_discovery.kid_set_digest(["b", "a"]) == oidc_discovery.kid_set_digest(
        ["a", "b"]
    )
    assert oidc_discovery.kid_set_digest(["a"]) != oidc_discovery.kid_set_digest(["b"])
    assert len(oidc_discovery.kid_set_digest(["a"])) == 16


def test_sanitized_jwks_redacts_private_members_and_sorts_keys():
    jwks = oidc_discovery.sanitized_jwks({
        "keys": [
            {"kid": "b", "alg": "RS256", "kty": "RSA", "d": "PRIVATE"},
            {"kid": "a", "alg": "ES256", "kty": "EC"},
            "not-a-key",
            {"kid": "a", "alg": "ES256"},  # duplicate kid/alg collapse in the sets
        ],
        "extra": "kept",
    })

    assert jwks.kids == ("a", "b") and jwks.algs == ("ES256", "RS256")
    assert jwks.private_members_redacted == 1
    assert [k["kid"] for k in jwks.document["keys"]] == ["a", "a", "b"]
    assert jwks.document["keys"][-1]["d"] == redact("PRIVATE")
    assert jwks.document["extra"] == "kept"


def test_sanitized_jwks_tolerates_a_malformed_document():
    for data in ({}, {"keys": "nope"}, {"keys": [None, 5]}):
        jwks = oidc_discovery.sanitized_jwks(data)
        assert jwks.kids == () and jwks.algs == ()
        assert jwks.document["keys"] == []


def test_sanitized_jwks_caps_the_key_count(monkeypatch):
    monkeypatch.setattr(oidc_discovery, "MAX_JWKS_KEYS", 2)
    jwks = oidc_discovery.sanitized_jwks(
        {"keys": [{"kid": f"k{i}"} for i in range(10)]}
    )
    assert jwks.kids == ("k0", "k1")


@pytest.mark.parametrize("value, expected", [
    ("api.epicgames.dev", True),
    ("203.0.113.5", True),
    ("2001:db8::1", True),
    ("", False),
    ("not a host", False),
    ("*.epicgames.dev", False),
    ("x" * 254, False),
    ("a" * 64 + ".epicgames.dev", False),
])
def test_valid_target(value, expected):
    assert oidc_discovery.valid_target(value) is expected


def test_parse_json_object_classifies_its_failures():
    assert oidc_discovery.parse_json_object('{"a": 1}') == ({"a": 1}, "")
    assert oidc_discovery.parse_json_object("[1]") == ({}, "json_was_not_an_object")
    assert oidc_discovery.parse_json_object("<html>") == ({}, "not_valid_json")
    assert oidc_discovery.parse_json_object(None) == ({}, "not_valid_json")


def test_canonical_json_is_deterministic_and_capped():
    assert oidc_discovery.canonical_json({"b": 1, "a": 2}) == '{"a": 2, "b": 1}'
    assert len(oidc_discovery.canonical_json({"a": "x" * 100}, limit=10)) == 10
    assert oidc_discovery.canonical_json({"a": {1, 2}})  # unserializable: repr fallback
