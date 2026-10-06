"""Offline, deterministic tests for the active openapi_discovery module.

Nothing here touches the network: ``requests.get`` is monkeypatched per test, every other
sender on ``requests`` is replaced with a landmine (a module that *called* a described
operation would trip it), and an autouse fixture makes ``socket``/``ssl`` raise — so a
regression that reaches for a real connection fails loudly instead of contacting any Epic
host. Time is injected via ``ModuleContext.now`` and the rate ledger gets a frozen monotonic
clock, so timestamps *and* budgets are fixed.
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
from recon.modules.active import openapi_discovery as mod
from recon.ratelimit import RateLedger
from recon.scope import Scope
from recon.snapshot import take_snapshot
from recon.store import Graph


def param_name(param_id: str) -> str:
    """The bare parameter name from a location-qualified id."""

    return param_id.rsplit(":", 1)[1]


def find_param(ctx, op_id: str, name: str):
    """The Parameter node for ``name`` on ``op_id``, whatever location it was declared in.

    Parameter ids are location-qualified now (``param:<op>#<location>:<name>``), so tests
    look the node up by what they actually care about instead of hard-coding the spelling.
    """

    prefix = f"param:{op_id}#"
    for node in ctx.graph.store.iter_type("Parameter"):
        if node.id.startswith(prefix) and node.id.rsplit(":", 1)[-1] == name:
            return node
    return None

NOW = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)

HOST = "api.epicgames.com"
WEBAPP = f"web:https://{HOST}"
SPEC_URL = f"https://{HOST}/openapi.json"
ALL_SPEC_URLS = [f"https://{HOST}{p}" for p in mod.SPEC_PATHS]

ACCOUNT_PATH = "/account/api/public/account/{accountId}"
TOKEN_PATH = "/account/api/oauth/token"
ACCOUNT_ROUTE = f"route:{WEBAPP}{ACCOUNT_PATH}"
TOKEN_ROUTE = f"route:{WEBAPP}{TOKEN_PATH}"
ACCOUNT_GET = f"op:GET:{ACCOUNT_ROUTE}"
ACCOUNT_POST = f"op:POST:{ACCOUNT_ROUTE}"
TOKEN_POST = f"op:POST:{TOKEN_ROUTE}"

#: Everything the module must never reach for. Patched to a landmine in every test.
FORBIDDEN_SENDERS = ("head", "post", "put", "patch", "delete", "options", "request")


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
    def __init__(self, status_code: int = 404, headers: dict | None = None,
                 text: str = "") -> None:
        self.status_code = status_code
        self.headers = dict(headers or {})
        self.text = text


def _resolve(table, url: str) -> FakeResponse:
    if table is None:
        return FakeResponse(404)
    if isinstance(table, dict):
        return table.get(url, FakeResponse(404))
    if callable(table):
        return table(url)
    return table


def install_fake_http(monkeypatch, get=None, *, raises=None, log=None) -> list:
    """Patch ``requests.get`` inside the module. Returns the call list.

    ``get`` may be a :class:`FakeResponse`, a ``{url: FakeResponse}`` mapping (an unknown
    url answers 404) or a callable.
    """

    calls = log if log is not None else []

    def send(url, timeout=None, headers=None, allow_redirects=None, **kwargs):
        calls.append({"kind": "request", "method": "GET", "url": url, "timeout": timeout,
                      "headers": dict(headers or {}), "allow_redirects": allow_redirects,
                      "extra": dict(kwargs)})
        if raises is not None:
            raise raises
        return _resolve(get, url)

    def landmine(*args, **kwargs):
        raise AssertionError("openapi_discovery sent something other than a GET")

    monkeypatch.setattr(mod.requests, "get", send)
    for name in FORBIDDEN_SENDERS:
        monkeypatch.setattr(mod.requests, name, landmine, raising=False)
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
        include=["*.epicgames.com", "*.fortnite.com", "203.0.113.0/24", "2001:db8::/32"],
        exclude=["secure.epicgames.com"],
        prefilter=["*.epicgames.dev"],
    )
    kwargs = dict(
        scope=scope,
        # Frozen monotonic clock: the token bucket never refills mid-test.
        ledger=RateLedger(global_qps=2.0, capacity=20.0, clock=lambda: 0.0),
        evidence=EvidenceStore(tmp_path / "evidence"),
        graph=Graph(EventLog()),
        snapshot=take_snapshot("pinned policy text", now=NOW),
        logger=logging.getLogger("test.openapi_discovery"),
        allow_active=True,
        now=NOW,
    )
    kwargs.update(overrides)
    return ModuleContext(**kwargs)


class FakeNode:
    """Minimal stand-in for a graph Node seed (only ``id``/``type`` are read)."""

    def __init__(self, id: str, type: str = "WebApp") -> None:
        self.id = id
        self.type = type


def webapp(host: str = HOST, scheme: str = "https") -> FakeNode:
    return FakeNode(f"web:{scheme}://{host}", "WebApp")


def spec(paths: dict, *, version: str = "3.0.3", key: str = "openapi", **extra) -> dict:
    doc = {key: version, "paths": paths}
    doc.update(extra)
    return doc


def body(doc) -> FakeResponse:
    raw = doc if isinstance(doc, str) else json.dumps(doc)
    return FakeResponse(200, {"Content-Type": "application/json"}, raw)


def served(doc, path: str = "/openapi.json") -> dict:
    """A table that answers ``path`` with ``doc`` and 404s every other spec path."""

    return {f"https://{HOST}{path}": body(doc)}


def run(tmp_path, monkeypatch, seeds, get=None, **kw):
    ctx = make_ctx(tmp_path, **kw.pop("ctx", {}))
    calls = install_fake_http(monkeypatch, get, **kw)
    summary = mod.OpenApiDiscoveryModule(ctx).run(seeds)
    return ctx, summary, calls


def requests_made(calls: list) -> list[dict]:
    return [c for c in calls if c["kind"] == "request"]


def gates(calls: list) -> list[dict]:
    return [c for c in calls if c["kind"] == "gate"]


def allow_records(ctx: ModuleContext) -> list[dict]:
    return [e.payload for e in ctx.graph.log.by_kind("gate_decision_recorded")
            if e.payload["decision"] == "ALLOW"]


def refuse_records(ctx: ModuleContext) -> list[dict]:
    return [e.payload for e in ctx.graph.log.by_kind("gate_decision_recorded")
            if e.payload["decision"] == "REFUSE"]


# --- the fixture document ------------------------------------------------------


OPENAPI3 = spec(
    {
        ACCOUNT_PATH: {
            "parameters": [
                {"name": "accountId", "in": "path", "required": True,
                 "schema": {"type": "string"}},
            ],
            "get": {
                "operationId": "getAccountById",
                "summary": "Fetch  an\n  account by id",
                "parameters": [
                    {"name": "includeExternalAuths", "in": "query",
                     "schema": {"type": "boolean"}},
                    {"$ref": "#/components/parameters/Correlation"},
                ],
            },
            "post": {
                "operationId": "updateAccount",
                "requestBody": {"content": {
                    "application/json": {
                        "schema": {"$ref": "#/components/schemas/AccountPatch"},
                    },
                    "application/xml": {"schema": {"type": "string"}},
                }},
            },
        },
        TOKEN_PATH: {
            "post": {
                "summary": "Token exchange",
                "parameters": [
                    {"name": "grant_type", "in": "query", "required": True,
                     "schema": {"type": "string",
                                "enum": ["client_credentials", "device_code"]}},
                ],
            },
        },
    },
    # Never a target: a url from spec content is data, not a destination.
    servers=[{"url": "https://internal.not-a-target.invalid/v1"}],
    components={
        "parameters": {
            "Correlation": {"name": "X-Epic-Correlation-ID", "in": "header",
                            "required": False, "schema": {"type": "string"}},
        },
        "schemas": {
            "AccountPatch": {
                "type": "object",
                "required": ["displayName"],
                "properties": {
                    "displayName": {"type": "string"},
                    "preferredLanguage": {"type": "string", "enum": ["en", "fr"]},
                },
            },
        },
    },
)


# --- registration & contract ---------------------------------------------------


def test_registered_under_its_filename_and_is_active():
    assert get_module("openapi_discovery") is mod.OpenApiDiscoveryModule
    assert mod.OpenApiDiscoveryModule.name == "openapi_discovery"
    assert mod.OpenApiDiscoveryModule.active is True
    assert mod.OpenApiDiscoveryModule.produces == ("Route", "Operation", "Parameter")


def test_the_only_verb_is_a_whitelisted_active_verb():
    from recon import verbs

    assert mod.VERB == "read-openapi"
    assert mod.VERB in verbs.ALLOWED and mod.VERB in verbs.ACTIVE
    assert mod.VERB not in verbs.BLOCKED and mod.VERB not in verbs.HUMAN_GATED


def test_spec_paths_are_a_short_fixed_constant_list():
    assert mod.SPEC_PATHS == (
        "/openapi.json", "/swagger.json", "/v3/api-docs", "/api/openapi.json",
        "/.well-known/openapi.json",
    )
    assert all(p.startswith("/") for p in mod.SPEC_PATHS)


def test_only_declared_ontology_types_are_emitted(tmp_path, monkeypatch):
    ctx, _, _ = run(tmp_path, monkeypatch, [webapp()], served(OPENAPI3))

    assert {n.type for n in ctx.graph.store.nodes.values()} == {
        "Route", "Operation", "Parameter",
    }
    assert {e.type for e in ctx.graph.store.edges.values()} == {"exposes", "takes"}


# --- request shape -------------------------------------------------------------


def test_one_get_per_spec_path_with_a_pinned_request_shape(tmp_path, monkeypatch):
    ctx, summary, calls = run(tmp_path, monkeypatch, [webapp()])
    made = requests_made(calls)

    assert [c["url"] for c in made] == ALL_SPEC_URLS  # fixed list, fixed order
    for call in made:
        assert call["method"] == "GET"
        assert call["headers"] == {"User-Agent": ctx.user_agent,
                                   "Accept": "application/json"}
        assert call["timeout"] == ctx.timeout
        assert call["allow_redirects"] is False  # a hop is its own scope decision
        assert call["extra"] == {}  # no body, no data=, no json=, no stream=
    assert summary["requests"] == 5 and summary["specs"] == 0
    assert ctx.graph.store.nodes == {}


def test_the_walk_stops_at_the_first_document_that_parses(tmp_path, monkeypatch):
    _, summary, calls = run(tmp_path, monkeypatch, [webapp()], served(OPENAPI3))

    assert [c["url"] for c in requests_made(calls)] == [SPEC_URL]
    assert summary["requests"] == 1 and summary["specs"] == 1


def test_a_later_path_is_tried_when_the_earlier_ones_miss(tmp_path, monkeypatch):
    _, summary, calls = run(tmp_path, monkeypatch, [webapp()],
                            served(OPENAPI3, "/v3/api-docs"))

    assert [c["url"] for c in requests_made(calls)] == ALL_SPEC_URLS[:3]
    assert summary["specs"] == 1 and summary["not_a_spec"] == 0


def test_a_described_operation_is_never_called(tmp_path, monkeypatch):
    """The contract is parsed, not exercised: POST/DELETE stay documents."""

    doc = spec({"/v1/accounts/{id}/purchase": {
        "post": {"operationId": "purchase"},
        "delete": {"operationId": "deleteAccount"},
    }})
    ctx, summary, calls = run(tmp_path, monkeypatch, [webapp()], served(doc))

    # The only urls touched are the fixed spec paths, and only ever with GET; every other
    # sender on ``requests`` is a landmine, so a dispatched POST would have raised.
    assert [(c["method"], c["url"]) for c in requests_made(calls)] == [("GET", SPEC_URL)]
    assert summary["operations"] == 2 and summary["requests"] == 1
    assert sorted(n.id for n in ctx.graph.store.iter_type("Operation")) == [
        f"op:DELETE:route:{WEBAPP}/v1/accounts/{{id}}/purchase",
        f"op:POST:route:{WEBAPP}/v1/accounts/{{id}}/purchase",
    ]


def test_spec_content_is_never_used_to_build_a_url(tmp_path, monkeypatch):
    _, _, calls = run(tmp_path, monkeypatch, [webapp()], served(OPENAPI3))

    for call in requests_made(calls):
        assert "not-a-target.invalid" not in call["url"]
        assert call["url"] in ALL_SPEC_URLS


# --- the gate is the chokepoint ------------------------------------------------


def test_every_request_is_immediately_preceded_by_its_own_gate(tmp_path, monkeypatch):
    calls: list = []
    ctx = make_ctx(tmp_path)
    spy_on_gate(monkeypatch, ctx, calls)
    install_fake_http(monkeypatch, log=calls)  # every path 404s -> all five are spent

    mod.OpenApiDiscoveryModule(ctx).run([webapp()])

    # Strict alternation: gate, request, gate, request … one gate per network touch.
    assert [c["kind"] for c in calls] == ["gate", "request"] * 5
    assert all(c["value"] == HOST and c["verb"] == "read-openapi" for c in gates(calls))
    assert len(allow_records(ctx)) == 5


def test_each_touch_debits_the_unified_ledger_once(tmp_path, monkeypatch):
    ctx, summary, calls = run(tmp_path, monkeypatch, [webapp()], served(OPENAPI3))

    assert len(ctx.ledger.log) == len(requests_made(calls)) == 1
    assert [e.verb for e in ctx.ledger.log] == ["read-openapi"]
    assert {e.target for e in ctx.ledger.log} == {"epicgames.com"}  # keyed by registrable
    assert ctx.ledger.balance(HOST) == pytest.approx(19.0)
    assert all(e.balance_after >= 0 for e in ctx.ledger.log)
    assert summary["refused"] == []


@pytest.mark.parametrize("override, fragment", [
    ({"allow_active": False}, "allow_active=false"),
    ({"snapshot": None}, "no scope snapshot"),
    ({"snapshot": take_snapshot("old", now=datetime(2026, 1, 1, tzinfo=timezone.utc))},
     "stale"),
])
def test_gate_refusal_skips_without_sending_anything(tmp_path, monkeypatch, override,
                                                     fragment):
    ctx, summary, calls = run(tmp_path, monkeypatch, [webapp()], served(OPENAPI3),
                              ctx=override)

    assert requests_made(calls) == []  # refused means no packet, not a quieter packet
    assert ctx.graph.store.nodes == {} and ctx.graph.store.edges == {}
    assert ctx.ledger.log == []
    assert summary["requests"] == 0 and summary["specs"] == 0
    assert [r["verb"] for r in summary["refused"]] == ["read-openapi"] * 5
    assert all(fragment in r["reason"] for r in summary["refused"])
    assert len(refuse_records(ctx)) == 5


@pytest.mark.parametrize("host", [
    "secure.epicgames.com",      # excluded -> out_of_scope
    "internal.epicgames.dev",    # owned-but-unlisted -> prefilter_only
    "fhir.epic.com",             # default deny
    "203.0.114.9",               # outside the in-scope netblock
])
def test_out_of_scope_webapps_are_never_touched(tmp_path, monkeypatch, host):
    ctx, summary, calls = run(tmp_path, monkeypatch, [webapp(host)], served(OPENAPI3))

    assert requests_made(calls) == []
    assert ctx.graph.store.nodes == {}
    assert summary["requests"] == 0 and len(summary["refused"]) == 5
    assert all("not in scope" in r["reason"] for r in summary["refused"])


def test_exhausted_budget_refuses_the_rest_and_never_crashes(tmp_path, monkeypatch):
    ctx, summary, calls = run(
        tmp_path, monkeypatch, [webapp()],
        ctx={"ledger": RateLedger(global_qps=2.0, capacity=3.0, clock=lambda: 0.0)},
    )

    assert len(requests_made(calls)) == 3  # the 4th touch is refused, not borrowed
    assert len(summary["refused"]) == 2
    assert all("rate budget exceeded" in r["reason"] for r in summary["refused"])
    assert all(e.balance_after >= 0 for e in ctx.ledger.log)
    assert invariants.check(ctx.graph.store, ledger=ctx.ledger,
                            current_snapshot=ctx.snapshot.snapshot_id) == []


def test_module_cannot_fetch_by_swallowing_a_refusal(tmp_path, monkeypatch):
    """A refusing gate must stop the request, however the refusal arrives."""

    ctx = make_ctx(tmp_path)
    calls = install_fake_http(monkeypatch, served(OPENAPI3))
    monkeypatch.setattr(
        ctx, "gate_active",
        lambda value, verb: (_ for _ in ()).throw(GateRefused("synthetic refusal")),
    )

    summary = mod.OpenApiDiscoveryModule(ctx).run([webapp()])

    assert requests_made(calls) == []
    assert ctx.graph.store.nodes == {}
    assert [r["reason"] for r in summary["refused"]] == ["synthetic refusal"] * 5


def test_binding_comes_from_the_gate_and_pins_the_snapshot(tmp_path, monkeypatch):
    ctx, _, _ = run(tmp_path, monkeypatch, [webapp()], served(OPENAPI3))

    assert ctx.graph.store.nodes
    for datum in list(ctx.graph.store.nodes.values()) + list(ctx.graph.store.edges.values()):
        assert datum.scope_binding.verdict == Verdict.IN_SCOPE
        assert datum.scope_binding.snapshot_id == ctx.snapshot.snapshot_id
        assert datum.scope_binding.rule_matched == "included by '*.epicgames.com'"
        assert datum.scope_binding.observed_at == NOW.isoformat()


# --- Route / Operation / Parameter ---------------------------------------------


def test_route_node_and_its_exposes_edge(tmp_path, monkeypatch):
    ctx, summary, _ = run(tmp_path, monkeypatch, [webapp()], served(OPENAPI3))

    route = ctx.graph.store.get(ACCOUNT_ROUTE)
    assert route is not None and route.type == "Route"
    assert route.attrs == {
        "active_probed": True,
        "path_template": ACCOUNT_PATH,
        "webapp": WEBAPP,
        "spec_version": "3.0.3",
    }
    assert route.coverage == {"enumerated": True, "param_mined": True}
    assert route.confidence.log_odds == pytest.approx(mod.DECLARED_LOG_ODDS)
    assert route.confidence.state.value == "observed"  # one source never self-promotes
    assert route.sensitivity == Sensitivity.S0 and route.data_subject == "none"
    assert route.provenance.chain[0].tool == "openapi_discovery"
    assert route.temporal.first_seen == NOW.isoformat()

    exposed = ctx.graph.store.out_edges(WEBAPP, "exposes")
    assert sorted(e.to for e in exposed) == sorted([ACCOUNT_ROUTE, TOKEN_ROUTE])
    assert exposed[0].attrs == {"active_probed": True}
    assert summary["routes"] == 2


def test_operation_nodes_carry_the_declared_contract(tmp_path, monkeypatch):
    ctx, summary, _ = run(tmp_path, monkeypatch, [webapp()], served(OPENAPI3))

    op = ctx.graph.store.get(ACCOUNT_GET)
    assert op is not None and op.type == "Operation"
    assert op.attrs == {
        "active_probed": True,
        "method": "GET",
        "path_template": ACCOUNT_PATH,
        "webapp": WEBAPP,
        "spec_version": "3.0.3",
        "summary": "Fetch an account by id",  # whitespace-collapsed
        "operation_id": "getAccountById",
    }
    assert op.coverage == {"enumerated": True, "param_mined": True}
    assert op.sensitivity == Sensitivity.S0 and op.data_subject == "none"

    assert [(e.frm, e.to) for e in ctx.graph.store.out_edges(ACCOUNT_ROUTE, "exposes")] \
        == [(ACCOUNT_ROUTE, ACCOUNT_GET), (ACCOUNT_ROUTE, ACCOUNT_POST)]
    assert sorted(n.id for n in ctx.graph.store.iter_type("Operation")) == sorted(
        [ACCOUNT_GET, ACCOUNT_POST, TOKEN_POST])
    assert summary["operations"] == 3


def test_an_undeclared_summary_is_recorded_as_empty_not_invented(tmp_path, monkeypatch):
    doc = spec({"/v1/ping": {"get": {}}})
    ctx, _, _ = run(tmp_path, monkeypatch, [webapp()], served(doc))

    op = ctx.graph.store.get(f"op:GET:route:{WEBAPP}/v1/ping")
    assert op.attrs["summary"] == "" and op.attrs["operation_id"] == ""


def test_path_query_and_header_parameters_are_typed(tmp_path, monkeypatch):
    ctx, summary, _ = run(tmp_path, monkeypatch, [webapp()], served(OPENAPI3))

    def param(op_id: str, name: str):
        return find_param(ctx, op_id, name)

    account_id = param(ACCOUNT_GET, "accountId")
    assert account_id is not None and account_id.type == "Parameter"
    assert account_id.attrs == {
        "active_probed": True, "name": "accountId", "in": "path",
        "type": "string", "required": True,
    }
    assert account_id.coverage == {"enumerated": True}
    assert account_id.sensitivity == Sensitivity.S0

    assert param(ACCOUNT_GET, "includeExternalAuths").attrs == {
        "active_probed": True, "name": "includeExternalAuths", "in": "query",
        "type": "boolean", "required": False,
    }
    # a local $ref is resolved; nothing external is ever fetched
    assert param(ACCOUNT_GET, "X-Epic-Correlation-ID").attrs["in"] == "header"
    assert summary["refs_unresolved"] == 0

    takes = ctx.graph.store.out_edges(ACCOUNT_GET, "takes")
    assert sorted(e.to for e in takes) == sorted(
        find_param(ctx, ACCOUNT_GET, n).id
        for n in ("accountId", "includeExternalAuths", "X-Epic-Correlation-ID"))
    assert takes[0].attrs == {"active_probed": True}


def test_path_item_parameters_are_inherited_by_every_operation(tmp_path, monkeypatch):
    ctx, _, _ = run(tmp_path, monkeypatch, [webapp()], served(OPENAPI3))

    assert find_param(ctx, ACCOUNT_POST, "accountId") is not None
    assert find_param(ctx, ACCOUNT_GET, "accountId") is not None


def test_operation_level_parameter_overrides_the_path_item_one(tmp_path, monkeypatch):
    doc = spec({"/v1/x/{id}": {
        "parameters": [{"name": "id", "in": "path", "required": True,
                        "schema": {"type": "string"}}],
        "get": {"parameters": [{"name": "id", "in": "path", "required": True,
                                "schema": {"type": "integer"}}]},
    }})
    ctx, summary, _ = run(tmp_path, monkeypatch, [webapp()], served(doc))

    op_id = f"op:GET:route:{WEBAPP}/v1/x/{{id}}"
    assert find_param(ctx, op_id, "id").attrs["type"] == "integer"
    assert summary["parameters"] == 1  # recorded once, not forked on an id collision


def test_request_body_properties_become_parameters(tmp_path, monkeypatch):
    ctx, _, _ = run(tmp_path, monkeypatch, [webapp()], served(OPENAPI3))

    display = find_param(ctx, ACCOUNT_POST, "displayName")
    assert display.attrs == {
        "active_probed": True, "name": "displayName", "in": "body",
        "type": "string", "required": True,  # from the schema's required[] list
    }
    language = find_param(ctx, ACCOUNT_POST, "preferredLanguage")
    assert language.attrs["required"] is False
    assert language.attrs["enum"] == ["en", "fr"]
    # application/xml describes the same body: one parameter set, not duplicates
    assert sorted(e.to.rsplit(":", 1)[1]
                  for e in ctx.graph.store.out_edges(ACCOUNT_POST, "takes")) == [
        "accountId", "displayName", "preferredLanguage",
    ]


def test_declared_enum_is_recorded(tmp_path, monkeypatch):
    ctx, _, _ = run(tmp_path, monkeypatch, [webapp()], served(OPENAPI3))

    grant = find_param(ctx, TOKEN_POST, "grant_type")
    assert grant.attrs["enum"] == ["client_credentials", "device_code"]
    assert grant.attrs["required"] is True


def test_required_is_what_the_document_declares(tmp_path, monkeypatch):
    """A sloppy spec that omits ``required`` on a path param is recorded as declared."""

    doc = spec({"/v1/x/{id}": {"get": {
        "parameters": [{"name": "id", "in": "path", "schema": {"type": "string"}}],
    }}})
    ctx, _, _ = run(tmp_path, monkeypatch, [webapp()], served(doc))

    op_id = f"op:GET:route:{WEBAPP}/v1/x/{{id}}"
    assert find_param(ctx, op_id, "id").attrs["required"] is False


def test_swagger2_body_parameter_is_expanded_into_properties(tmp_path, monkeypatch):
    doc = spec(
        {"/account/api/oauth/token": {
            "post": {
                "operationId": "oauthToken",
                "consumes": ["application/x-www-form-urlencoded"],
                "parameters": [
                    {"name": "payload", "in": "body", "required": True, "schema": {
                        "type": "object",
                        "required": ["grant_type"],
                        "properties": {
                            "grant_type": {"type": "string",
                                           "enum": ["client_credentials"]},
                            "deployment_id": {"type": "string"},
                        },
                    }},
                    {"name": "token_type", "in": "formData", "type": "string"},
                ],
            },
        }},
        key="swagger", version="2.0",
    )
    ctx, summary, _ = run(tmp_path, monkeypatch, [webapp()], served(doc, "/swagger.json"))

    op = ctx.graph.store.get(TOKEN_POST)
    assert op.attrs["spec_version"] == "2.0"
    names = {e.to.rsplit(":", 1)[1] for e in ctx.graph.store.out_edges(TOKEN_POST, "takes")}
    assert names == {"grant_type", "deployment_id", "token_type"}
    assert find_param(ctx, TOKEN_POST, "grant_type").attrs == {
        "active_probed": True, "name": "grant_type", "in": "body",
        "type": "string", "required": True, "enum": ["client_credentials"],
    }
    assert find_param(ctx, TOKEN_POST, "token_type").attrs["in"] == "formData"
    assert summary["parameters"] == 3


def test_swagger2_scalar_body_stays_a_single_parameter(tmp_path, monkeypatch):
    doc = spec({"/v1/raw": {"put": {"parameters": [
        {"name": "payload", "in": "body", "required": True, "schema": {"type": "string"}},
    ]}}}, key="swagger", version="2.0")
    ctx, _, _ = run(tmp_path, monkeypatch, [webapp()], served(doc))

    op_id = f"op:PUT:route:{WEBAPP}/v1/raw"
    assert find_param(ctx, op_id, "payload").attrs["type"] == "string"


# --- $ref handling -------------------------------------------------------------


def test_an_external_ref_is_never_fetched(tmp_path, monkeypatch):
    doc = spec({"/v1/x": {"get": {"parameters": [
        {"$ref": "https://evil.example.com/params.json#/Leak"},
        {"$ref": "other-file.yaml#/Param"},
        {"name": "kept", "in": "query", "schema": {"type": "string"}},
    ]}}})
    ctx, summary, calls = run(tmp_path, monkeypatch, [webapp()], served(doc))

    assert [c["url"] for c in requests_made(calls)] == [SPEC_URL]  # one GET, no ref fetch
    op_id = f"op:GET:route:{WEBAPP}/v1/x"
    assert {e.to.rsplit(":", 1)[1]
            for e in ctx.graph.store.out_edges(op_id, "takes")} == {"kept"}
    assert summary["refs_unresolved"] == 2
    assert summary["parameters"] == 1


def test_a_ref_cycle_terminates(tmp_path, monkeypatch):
    doc = spec(
        {"/v1/x": {"get": {"parameters": [{"$ref": "#/components/parameters/Loop"}]}}},
        components={"parameters": {"Loop": {"$ref": "#/components/parameters/Loop"}}},
    )
    ctx, summary, _ = run(tmp_path, monkeypatch, [webapp()], served(doc))

    assert summary["parameters"] == 0 and summary["refs_unresolved"] == 1
    assert summary["operations"] == 1  # the operation itself still lands


def test_a_dangling_local_ref_is_dropped(tmp_path, monkeypatch):
    doc = spec({"/v1/x": {"get": {"parameters": [{"$ref": "#/components/parameters/Gone"}]}}})
    _, summary, _ = run(tmp_path, monkeypatch, [webapp()], served(doc))

    assert summary["parameters"] == 0 and summary["operations"] == 1


def test_json_pointer_escapes_and_misses():
    doc = {"a": {"b/c": {"d~e": 1}}, "list": [{"x": 2}]}
    assert mod.json_pointer(doc, "a/b~1c/d~0e") == 1
    assert mod.json_pointer(doc, "list/0/x") == 2
    assert mod.json_pointer(doc, "list/9") is None
    assert mod.json_pointer(doc, "nope/deeper") is None


def test_a_path_item_ref_is_resolved(tmp_path, monkeypatch):
    doc = spec(
        {"/v1/x": {"$ref": "#/components/pathItems/Shared"}},
        components={"pathItems": {"Shared": {"get": {"operationId": "shared"}}}},
    )
    ctx, summary, _ = run(tmp_path, monkeypatch, [webapp()], served(doc))

    assert summary["operations"] == 1
    assert ctx.graph.store.get(f"op:GET:route:{WEBAPP}/v1/x").attrs["operation_id"] == "shared"


# --- secret hygiene ------------------------------------------------------------


@pytest.mark.parametrize("value", [
    "eyJhbGciOiJIUzI1NiJ9.cGF5bG9hZA.c2lnbmF0dXJl",   # a JWT
    "a" * 40,                                          # a long hex-ish digest
    "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVoxMjM0NTY=",    # a long base64 blob
])
def test_a_secret_shaped_enum_label_is_redacted_before_storage(tmp_path, monkeypatch,
                                                                value):
    doc = spec({"/v1/x": {"get": {"parameters": [
        {"name": "token", "in": "query", "schema": {"type": "string", "enum": [value]}},
    ]}}})
    ctx, _, _ = run(tmp_path, monkeypatch, [webapp()], served(doc))

    node = find_param(ctx, f"op:GET:route:{WEBAPP}/v1/x", "token")
    assert node.attrs["enum"] == [redact(value)]
    assert value not in repr(node.to_dict())


def test_an_ordinary_enum_label_is_kept_verbatim(tmp_path, monkeypatch):
    doc = spec({"/v1/x": {"get": {"parameters": [
        {"name": "locale", "in": "query", "schema": {"enum": ["en-US", "fr", 7, True, None]}},
    ]}}})
    ctx, _, _ = run(tmp_path, monkeypatch, [webapp()], served(doc))

    node = find_param(ctx, f"op:GET:route:{WEBAPP}/v1/x", "locale")
    assert node.attrs["enum"] == ["en-US", "fr", "7", "True", "null"]


def test_no_credential_or_token_node_is_ever_minted(tmp_path, monkeypatch):
    doc = spec({"/v1/x": {"get": {
        "security": [{"bearerAuth": []}],
        "parameters": [{"name": "client_id", "in": "query", "schema": {"type": "string"},
                        "example": "xyza7891LIVE-CLIENT-SECRET"}],
    }}}, components={"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}})
    ctx, _, _ = run(tmp_path, monkeypatch, [webapp()], served(doc))

    assert not list(ctx.graph.store.iter_type("Credential"))
    assert not list(ctx.graph.store.iter_type("Token"))
    assert all(n.data_subject == "none" for n in ctx.graph.store.nodes.values())
    # an ``example`` value is never read into an attr; the raw document is the proof
    assert all("LIVE-CLIENT-SECRET" not in repr(n.to_dict())
               for n in ctx.graph.store.nodes.values())


def test_enum_values_are_capped(tmp_path, monkeypatch):
    monkeypatch.setattr(mod, "MAX_ENUM_VALUES", 3)
    doc = spec({"/v1/x": {"get": {"parameters": [
        {"name": "n", "in": "query", "schema": {"enum": [str(i) for i in range(50)]}},
    ]}}})
    ctx, _, _ = run(tmp_path, monkeypatch, [webapp()], served(doc))

    assert find_param(ctx, f"op:GET:route:{WEBAPP}/v1/x", "n").attrs["enum"] == [
        "0", "1", "2",
    ]


# --- evidence ------------------------------------------------------------------


def test_the_raw_spec_is_stored_as_content_addressed_evidence(tmp_path, monkeypatch):
    raw = json.dumps(OPENAPI3)
    ctx, _, _ = run(tmp_path, monkeypatch, [webapp()], served(OPENAPI3))

    sha = sha256_bytes(raw.encode("utf-8"))
    for node in ctx.graph.store.nodes.values():
        assert [e.sha256 for e in node.evidence] == [sha]
        assert node.evidence[0].region == f"openapi_discovery:GET {SPEC_URL}"
        assert node.evidence[0].encrypted_at_rest is True
        assert node.provenance.chain[0].evidence_id == sha
    assert json.loads(ctx.evidence.get(sha).decode("utf-8")) == OPENAPI3


def test_unwritable_evidence_store_does_not_fail_the_read(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    install_fake_http(monkeypatch, served(OPENAPI3))

    def boom(*args, **kwargs):
        raise OSError("read-only filesystem")

    monkeypatch.setattr(ctx.evidence, "put_text", boom)
    summary = mod.OpenApiDiscoveryModule(ctx).run([webapp()])

    assert summary["operations"] == 3
    assert ctx.graph.store.get(ACCOUNT_GET).evidence == []


# --- bodies that are not a spec ------------------------------------------------


@pytest.mark.parametrize("text", [
    "<!doctype html><html><title>404</title></html>",   # an HTML error page
    "openapi: 3.0.0\npaths: {}\n",                       # YAML is not probed for
    "{not json",
    "[]",
    "{}",
    '{"paths": {"/x": {"get": {}}}}',                    # no version key
    '{"openapi": "3.0.0"}',                              # no paths
    '{"openapi": "", "paths": {}}',
    "   ",
])
def test_a_body_that_is_not_a_spec_is_left_alone(tmp_path, monkeypatch, text):
    table = {SPEC_URL: FakeResponse(200, {}, text)}
    ctx, summary, calls = run(tmp_path, monkeypatch, [webapp()], table)

    assert ctx.graph.store.nodes == {}
    assert summary["specs"] == 0 and summary["operations"] == 0
    assert len(requests_made(calls)) == 5  # the walk keeps going


def test_an_oversized_body_is_not_parsed(tmp_path, monkeypatch):
    monkeypatch.setattr(mod, "MAX_SPEC_CHARS", 64)
    ctx, summary, _ = run(tmp_path, monkeypatch, [webapp()], served(OPENAPI3))

    assert ctx.graph.store.nodes == {}
    assert summary["errors"] == [{"url": SPEC_URL, "error": "spec exceeds size cap"}]


def test_a_nesting_bomb_is_a_non_event(tmp_path, monkeypatch):
    bomb = "{" + '"a":{' * 2000
    ctx, summary, _ = run(tmp_path, monkeypatch, [webapp()],
                          {SPEC_URL: FakeResponse(200, {}, bomb)})

    assert ctx.graph.store.nodes == {} and summary["not_a_spec"] == 1


@pytest.mark.parametrize("status", [204, 301, 302, 401, 403, 404, 500, None, "200", True])
def test_only_a_200_body_is_parsed(tmp_path, monkeypatch, status):
    table = {SPEC_URL: FakeResponse(status, {}, json.dumps(OPENAPI3))}
    ctx, summary, _ = run(tmp_path, monkeypatch, [webapp()], table)

    assert ctx.graph.store.nodes == {}
    assert summary["specs"] == 0 and summary["requests"] == 5


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

    assert len(requests_made(calls)) == 5  # one attempt per path; no retry
    assert ctx.graph.store.nodes == {} and ctx.graph.store.edges == {}
    assert summary["specs"] == 0 and len(summary["errors"]) == 5
    assert summary["requests"] == 5  # the budget was spent, and is recorded as spent
    assert len(ctx.ledger.log) == 5


def test_one_bad_webapp_does_not_stop_the_others(tmp_path, monkeypatch):
    other = "www.fortnite.com"

    def get(url):
        if HOST in url:
            raise requests.ConnectionError("down")
        return body(OPENAPI3) if url.endswith("/openapi.json") else FakeResponse(404)

    ctx, summary, _ = run(tmp_path, monkeypatch, [webapp(), webapp(other)], get)

    assert summary["specs"] == 1 and len(summary["errors"]) == 5
    operations = list(ctx.graph.store.iter_type("Operation"))
    assert operations and all(f"web:https://{other}" in n.id and HOST not in n.id
                              for n in operations)


def test_an_undecodable_body_is_skipped(tmp_path, monkeypatch):
    class Hostile:
        status_code = 200
        headers: dict = {}

        @property
        def text(self):
            raise UnicodeDecodeError("utf-8", b"", 0, 1, "nope")

    ctx, summary, _ = run(tmp_path, monkeypatch, [webapp()], {SPEC_URL: Hostile()})

    assert ctx.graph.store.nodes == {} and summary["specs"] == 0


def test_a_malformed_document_does_not_crash_the_parse(tmp_path, monkeypatch):
    doc = {
        "openapi": "3.0.0",
        "paths": {
            "/ok": {"get": {"parameters": "not-a-list", "summary": 42}},
            "/bad": "not-a-path-item",
            "https://elsewhere.invalid/x": {"get": {}},   # a url used as a path key
            "no-leading-slash": {"get": {}},
            "/q?a=1": {"get": {}},                        # a query is not a template
            "/ctl\x01": {"get": {}},                      # a control character
            7: {"get": {}},
            "/params": {"parameters": [None, "junk", {"in": "query"}, {"name": "  "}],
                        "get": {"requestBody": "junk"}},
        },
    }
    ctx, summary, _ = run(tmp_path, monkeypatch, [webapp()], served(doc))

    assert sorted(n.id for n in ctx.graph.store.iter_type("Route")) == [
        f"route:{WEBAPP}/ok", f"route:{WEBAPP}/params",
    ]
    assert summary["operations"] == 2 and summary["parameters"] == 0
    assert ctx.graph.store.get(f"op:GET:route:{WEBAPP}/ok").attrs["summary"] == ""


# --- caps ----------------------------------------------------------------------


def test_the_operation_cap_truncates_instead_of_running_away(tmp_path, monkeypatch):
    monkeypatch.setattr(mod, "MAX_OPERATIONS", 2)
    ctx, summary, _ = run(tmp_path, monkeypatch, [webapp()], served(OPENAPI3))

    assert summary["operations"] == 2 and summary["truncated"] is True
    assert sorted(n.id for n in ctx.graph.store.iter_type("Operation")) == sorted(
        [ACCOUNT_GET, ACCOUNT_POST])
    assert ctx.graph.store.get(TOKEN_ROUTE) is None


def test_truncation_stops_spending_budget_on_later_webapps(tmp_path, monkeypatch):
    monkeypatch.setattr(mod, "MAX_OPERATIONS", 1)
    ctx, summary, calls = run(tmp_path, monkeypatch,
                              [webapp(), webapp("www.fortnite.com")], served(OPENAPI3))

    assert [c["url"] for c in requests_made(calls)] == [SPEC_URL]
    assert summary["truncated"] is True and len(ctx.ledger.log) == 1


def test_the_path_cap_truncates(tmp_path, monkeypatch):
    monkeypatch.setattr(mod, "MAX_PATHS", 1)
    _, summary, _ = run(tmp_path, monkeypatch, [webapp()], served(OPENAPI3))

    assert summary["routes"] == 1 and summary["truncated"] is True


def test_the_seed_cap_defers_later_seeds_but_still_reads_the_kept_ones(tmp_path,
                                                                       monkeypatch):
    monkeypatch.setattr(mod, "MAX_SEEDS", 2)
    seeds = [webapp(f"h{i}.epicgames.com") for i in range(5)]
    ctx, summary, calls = run(
        tmp_path, monkeypatch, seeds,
        lambda url: body(spec({"/v1/x": {"get": {}}})) if url.endswith("/openapi.json")
        else FakeResponse(404),
    )

    assert summary["targets"] == ["web:https://h0.epicgames.com",
                                  "web:https://h1.epicgames.com"]
    assert summary["truncated"] is True
    # deferring seed 3..5 must not cancel seeds 1..2
    assert [c["url"] for c in requests_made(calls)] == [
        "https://h0.epicgames.com/openapi.json",
        "https://h1.epicgames.com/openapi.json",
    ]
    assert summary["specs"] == 2 and len(ctx.ledger.log) == 2


def test_the_per_operation_parameter_cap_truncates(tmp_path, monkeypatch):
    monkeypatch.setattr(mod, "MAX_PARAMS_PER_OPERATION", 2)
    doc = spec({"/v1/x": {"get": {"parameters": [
        {"name": f"p{i}", "in": "query", "schema": {"type": "string"}} for i in range(10)
    ]}}})
    _, summary, _ = run(tmp_path, monkeypatch, [webapp()], served(doc))

    assert summary["parameters"] == 2


# --- seeds ---------------------------------------------------------------------


def test_empty_and_junk_seeds_are_graceful(tmp_path, monkeypatch):
    for seeds in ([], None, ["", "   ", None, 42, "not a webapp", "web:", "web:gopher://x",
                   "web:https://", "web:https://host/with/path", "web:https://a@b",
                   "web:https://not a host", "web:https://x" + "y" * 300]):
        ctx, summary, calls = run(tmp_path, monkeypatch, seeds)
        assert requests_made(calls) == []
        assert summary["targets"] == [] and summary["operations"] == 0
        assert ctx.ledger.log == []


def test_foreign_seed_node_types_are_ignored(tmp_path, monkeypatch):
    seeds = [
        FakeNode(f"dns:{HOST}", "DNSName"),
        FakeNode(f"domain:{HOST}", "Domain"),
        FakeNode("svc:203.0.113.5:443/tcp", "Service"),
        FakeNode(f"route:{WEBAPP}/x", "Route"),
        webapp(),
    ]
    _, summary, calls = run(tmp_path, monkeypatch, seeds, served(OPENAPI3))

    assert summary["targets"] == [WEBAPP]
    assert [c["url"] for c in requests_made(calls)] == [SPEC_URL]


def test_duplicate_and_denormalized_seeds_are_read_once(tmp_path, monkeypatch):
    seeds = [webapp(), webapp(HOST.upper()), FakeNode(f"web:https://{HOST}."),
             f"https://{HOST}", f"web:HTTPS://{HOST}/"]
    _, summary, calls = run(tmp_path, monkeypatch, seeds, served(OPENAPI3))

    assert summary["targets"] == [WEBAPP]
    assert len(requests_made(calls)) == 1


def test_http_and_https_are_separate_targets(tmp_path, monkeypatch):
    _, summary, calls = run(tmp_path, monkeypatch, [webapp(), webapp(HOST, "http")])

    assert summary["targets"] == [WEBAPP, f"web:http://{HOST}"]
    assert [c["url"] for c in requests_made(calls)][:1] == [SPEC_URL]
    assert f"http://{HOST}/openapi.json" in [c["url"] for c in requests_made(calls)]


def test_a_seed_carrying_an_explicit_port_is_skipped_not_rewritten(tmp_path, monkeypatch):
    """The pinned ``web:<scheme>://<vhost>`` id has no slot for a port."""

    _, summary, calls = run(tmp_path, monkeypatch, [FakeNode(f"web:https://{HOST}:8443")])

    assert summary["targets"] == [] and requests_made(calls) == []


def test_an_ipv6_webapp_seed_is_bracketed_in_the_url_and_the_id(tmp_path, monkeypatch):
    doc = spec({"/v1/x": {"get": {}}})
    table = {"https://[2001:db8::1]/openapi.json": body(doc)}
    ctx, summary, calls = run(tmp_path, monkeypatch,
                              [FakeNode("web:https://[2001:db8::1]")], table)

    assert [c["url"] for c in requests_made(calls)] == [
        "https://[2001:db8::1]/openapi.json",
    ]
    assert summary["targets"] == ["web:https://[2001:db8::1]"]
    assert ctx.graph.store.get("route:web:https://[2001:db8::1]/v1/x") is not None
    assert summary["refused"] == []


def test_an_ip_webapp_seed_is_read_only_under_a_netblock_rule(tmp_path, monkeypatch):
    doc = spec({"/v1/x": {"get": {}}})
    ctx, summary, calls = run(tmp_path, monkeypatch, [FakeNode("web:https://203.0.113.5")],
                              {"https://203.0.113.5/openapi.json": body(doc)})

    assert [c["url"] for c in requests_made(calls)] == ["https://203.0.113.5/openapi.json"]
    assert summary["specs"] == 1 and summary["refused"] == []

    _, summary2, calls2 = run(tmp_path, monkeypatch, [FakeNode("web:https://198.51.100.7")])
    assert requests_made(calls2) == [] and len(summary2["refused"]) == 5


# --- idempotence, forking, invariants -----------------------------------------


def test_rerun_with_the_same_spec_merges_without_forking(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    install_fake_http(monkeypatch, served(OPENAPI3))
    module = mod.OpenApiDiscoveryModule(ctx)
    module.run([webapp()])
    module.run([webapp()])

    assert sorted(n.id for n in ctx.graph.store.iter_type("Operation")) == sorted(
        [ACCOUNT_GET, ACCOUNT_POST, TOKEN_POST])
    assert not any("#fork" in i for i in ctx.graph.store.nodes)
    node = ctx.graph.store.get(ACCOUNT_GET)
    assert node.coverage == {"enumerated": True, "param_mined": True}
    assert node.attrs["operation_id"] == "getAccountById"


def test_spec_drift_forks_instead_of_overwriting(tmp_path, monkeypatch):
    first = spec({"/v1/x": {"get": {"operationId": "readThing"}}})
    second = spec({"/v1/x": {"get": {"operationId": "renamedThing"}}})
    ctx = make_ctx(tmp_path)
    install_fake_http(monkeypatch, served(first))
    mod.OpenApiDiscoveryModule(ctx).run([webapp()])
    monkeypatch.undo()
    install_fake_http(monkeypatch, served(second))
    mod.OpenApiDiscoveryModule(ctx).run([webapp()])

    op_id = f"op:GET:route:{WEBAPP}/v1/x"
    assert ctx.graph.store.get(op_id).attrs["operation_id"] == "readThing"
    fork = ctx.graph.store.get(f"{op_id}#fork1")
    assert fork is not None and fork.attrs["operation_id"] == "renamedThing"
    assert fork.confidence.forked_from == op_id
    assert any(e.kind == "contradiction_forked" for e in ctx.graph.log.all())


def test_graph_satisfies_the_safety_invariants(tmp_path, monkeypatch):
    seeds = [webapp(), webapp("www.fortnite.com"), FakeNode("web:https://203.0.113.5"),
             FakeNode("web:https://secure.epicgames.com"),
             FakeNode("web:https://internal.epicgames.dev")]
    ctx, summary, _ = run(tmp_path, monkeypatch, seeds,
                          lambda url: body(OPENAPI3) if url.endswith("/openapi.json")
                          else FakeResponse(404))

    assert ctx.graph.store.nodes and summary["specs"] == 3
    assert invariants.check(ctx.graph.store, ledger=ctx.ledger,
                            current_snapshot=ctx.snapshot.snapshot_id) == []
    # every node carries the active-probe marker and an in_scope verdict (I2/I3)
    for node in ctx.graph.store.nodes.values():
        assert node.attrs["active_probed"] is True
        assert node.scope_binding.verdict == Verdict.IN_SCOPE


def test_the_api_contract_gap_closes_after_a_successful_read(tmp_path, monkeypatch):
    """The planner's api-contract rule must be able to observe its own closure."""

    from recon.planner import _no_typed_ops

    ctx, _, _ = run(tmp_path, monkeypatch, [webapp()], served(OPENAPI3))

    class _Seed:
        id = WEBAPP

    assert _no_typed_ops(_Seed(), ctx.graph.store) is False


# --- pure helpers --------------------------------------------------------------


@pytest.mark.parametrize("raw, expected", [
    (f"web:https://{HOST}", (f"web:https://{HOST}", "https", HOST, HOST)),
    (f"web:http://{HOST}.", (f"web:http://{HOST}", "http", HOST, HOST)),
    ("web:https://[2001:db8::1]",
     ("web:https://[2001:db8::1]", "https", "[2001:db8::1]", "2001:db8::1")),
])
def test_parse_webapp_canonicalizes(raw, expected):
    target = mod.parse_webapp(raw)
    assert (target.webapp_id, target.scheme, target.authority, target.host) == expected


@pytest.mark.parametrize("raw", [
    "", "   ", "web:", "web:https://", f"web:ftp://{HOST}", f"web:https://{HOST}:8443",
    f"web:https://user@{HOST}", f"web:https://{HOST}/openapi.json", "web:https://[2001:db8::1",
    "web:https://[2001:db8::1]:443", "web:https://-bad-", "web:https://a b",
])
def test_parse_webapp_rejects_unusable_ids(raw):
    assert mod.parse_webapp(raw) is None


@pytest.mark.parametrize("raw, expected", [
    ("/v1/x", "/v1/x"), ("  /v1/x  ", "/v1/x"), ("/v1/{id}", "/v1/{id}"),
    ("v1/x", ""), ("", ""), ("/a b", ""), ("/a?b=1", ""), ("/a#b", ""),
    ("https://x/y", ""), (None, ""), (7, ""),
])
def test_path_template_normalization(raw, expected):
    assert mod.declared_path_template(raw) == expected


@pytest.mark.parametrize("raw, expected", [
    ("accountId", "accountId"), ("X-Epic-Correlation-ID", "X-Epic-Correlation-ID"),
    ("  name  ", "name"), ("a#b", ""), ("a b", ""), ("", ""), (None, ""), (7, ""),
])
def test_clean_name_protects_the_pinned_id_form(raw, expected):
    assert mod.clean_name(raw) == expected


def test_clean_name_and_text_are_capped():
    assert len(mod.clean_name("x" * 500)) == mod.MAX_NAME_CHARS
    assert len(mod.clean_text("y" * 500)) == mod.MAX_TEXT_CHARS


@pytest.mark.parametrize("doc, expected", [
    ({"openapi": "3.1.0"}, "3.1.0"),
    ({"swagger": "2.0"}, "2.0"),
    ({"swagger": 2.0}, "2.0"),
    ({"openapi": "", "swagger": "2.0"}, "2.0"),
    ({"openapi": True}, ""),
    ({}, ""),
])
def test_spec_version_reads_either_key(doc, expected):
    assert mod.spec_version(doc) == expected


@pytest.mark.parametrize("doc, expected", [
    ({"openapi": "3.0.0", "paths": {}}, True),
    ({"swagger": "2.0", "paths": {"/x": {}}}, True),
    ({"openapi": "3.0.0"}, False),
    ({"paths": {}}, False),
    ({"openapi": "3.0.0", "paths": []}, False),
    ([], False),
    (None, False),
])
def test_looks_like_spec(doc, expected):
    assert mod.looks_like_spec(doc) is expected


@pytest.mark.parametrize("raw, expected", [
    ("string", "string"), (["string", "null"], "string"), ([], ""), (7, "7"),
    (True, ""), (None, ""), ({"a": 1}, ""),
])
def test_clean_token(raw, expected):
    assert mod.clean_token(raw) == expected


def test_clean_token_prefers_the_first_string_member():
    assert mod.clean_token([None, 7, "integer"]) == "integer"
