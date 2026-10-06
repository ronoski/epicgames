"""Offline, deterministic tests for the active http_probe module.

Nothing here touches the network: ``requests.head``/``requests.get`` are monkeypatched per
test, every other HTTP verb on ``requests`` is replaced with a landmine, and an autouse
fixture makes ``socket``/``ssl`` raise — so a regression that reaches for a real connection
fails loudly instead of contacting any Epic host. Time is injected via ``ModuleContext.now``
and the rate ledger gets a frozen monotonic clock, so timestamps *and* budgets are fixed.
"""

from __future__ import annotations

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
from recon.modules.active import http_probe
from recon.ratelimit import RateLedger
from recon.scope import Scope
from recon.snapshot import take_snapshot
from recon.store import Graph

NOW = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)

HOST = "api.epicgames.com"
HTTPS_URL = f"https://{HOST}/"
HTTP_URL = f"http://{HOST}/"
APP = f"web:https://{HOST}"
ROUTE = f"route:{APP}/"
HEAD_OP = f"op:HEAD:{ROUTE}"
GET_OP = f"op:GET:{ROUTE}"

#: Everything the module must never reach for. Patched to a landmine in every test.
FORBIDDEN_SENDERS = ("post", "put", "patch", "delete", "options", "request")


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
    def __init__(self, status_code: int = 200, headers: dict | None = None,
                 text: str = "") -> None:
        self.status_code = status_code
        self.headers = dict(headers or {})
        self.text = text


def _resolve(table, url: str) -> FakeResponse:
    if table is None:
        return FakeResponse()
    if isinstance(table, dict):
        return table.get(url, FakeResponse(404))
    if callable(table):
        return table(url)
    return table


def install_fake_http(monkeypatch, head=None, get=None, *, raises=None, log=None) -> list:
    """Patch ``requests.head``/``get`` inside the module. Returns the call list.

    ``head``/``get`` may each be a :class:`FakeResponse`, a ``{url: FakeResponse}`` mapping
    (an unknown url answers 404) or a callable. ``get`` defaults to ``head``.
    """

    calls = log if log is not None else []

    def sender(method, table):
        def send(url, timeout=None, headers=None, allow_redirects=None, **kwargs):
            calls.append({"kind": "request", "method": method, "url": url,
                          "timeout": timeout, "headers": dict(headers or {}),
                          "allow_redirects": allow_redirects, "extra": dict(kwargs)})
            if raises is not None:
                raise raises
            return _resolve(table, url)
        return send

    def landmine(*args, **kwargs):
        raise AssertionError("http_probe sent a method other than HEAD/GET")

    monkeypatch.setattr(http_probe.requests, "head", sender("HEAD", head))
    monkeypatch.setattr(http_probe.requests, "get",
                        sender("GET", head if get is None else get))
    for name in FORBIDDEN_SENDERS:
        monkeypatch.setattr(http_probe.requests, name, landmine, raising=False)
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
        logger=logging.getLogger("test.http_probe"),
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


def dns(host: str = HOST) -> FakeNode:
    return FakeNode(f"dns:{host}", "DNSName")


@pytest.fixture
def only_https(monkeypatch):
    """Probe one scheme so per-attr assertions stay about one response."""

    monkeypatch.setattr(http_probe, "SCHEMES", ("https",))


def run(tmp_path, monkeypatch, seeds, head=None, get=None, **kw):
    ctx = make_ctx(tmp_path, **kw.pop("ctx", {}))
    calls = install_fake_http(monkeypatch, head, get, **kw)
    summary = http_probe.HttpProbeModule(ctx).run(seeds)
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


# --- registration & contract ---------------------------------------------------


def test_registered_under_its_filename_and_is_active():
    assert get_module("http_probe") is http_probe.HttpProbeModule
    assert http_probe.HttpProbeModule.name == "http_probe"
    assert http_probe.HttpProbeModule.active is True
    assert http_probe.HttpProbeModule.produces == ("WebApp", "Operation")


def test_both_verbs_are_whitelisted_active_verbs():
    from recon import verbs

    for verb in (http_probe.HEAD_VERB, http_probe.GET_VERB):
        assert verb in verbs.ALLOWED
        assert verb in verbs.ACTIVE
        assert verb not in verbs.BLOCKED and verb not in verbs.HUMAN_GATED
    assert (http_probe.HEAD_VERB, http_probe.GET_VERB) == ("http-HEAD", "http-GET")


def test_only_declared_ontology_types_are_emitted(tmp_path, monkeypatch):
    ctx, _, _ = run(tmp_path, monkeypatch, [dns()])

    assert {n.type for n in ctx.graph.store.nodes.values()} <= {"WebApp", "Operation"}
    assert {e.type for e in ctx.graph.store.edges.values()} == {"exposes"}


# --- request shape -------------------------------------------------------------


def test_one_head_per_host_and_scheme_with_pinned_request_shape(tmp_path, monkeypatch):
    ctx, summary, calls = run(tmp_path, monkeypatch, [dns()])
    made = requests_made(calls)

    assert [(c["method"], c["url"]) for c in made] == [
        ("HEAD", HTTPS_URL), ("HEAD", HTTP_URL),
    ]
    for call in made:
        assert call["headers"] == {"User-Agent": ctx.user_agent}
        assert call["timeout"] == ctx.timeout
        assert call["allow_redirects"] is False
        assert call["extra"] == {}  # no body, no data=, no json=, no stream=
    assert summary["requests"] == 2 and summary["get_fallbacks"] == 0


def test_duplicate_seeds_are_probed_once(tmp_path, monkeypatch):
    seeds = [dns(), dns(), FakeNode(f"dns:{HOST}.", "DNSName"), HOST.upper()]
    _, summary, calls = run(tmp_path, monkeypatch, seeds)

    assert summary["targets"] == [HOST]
    assert len(requests_made(calls)) == 2


def test_target_cap_truncates_instead_of_running_away(tmp_path, monkeypatch):
    monkeypatch.setattr(http_probe, "MAX_TARGETS", 2)
    seeds = [dns(f"h{i}.epicgames.com") for i in range(5)]
    _, summary, calls = run(tmp_path, monkeypatch, seeds)

    assert summary["targets"] == ["h0.epicgames.com", "h1.epicgames.com"]
    assert summary["truncated"] is True
    assert len(requests_made(calls)) == 4


# --- the gate is the chokepoint ------------------------------------------------


def test_every_request_is_immediately_preceded_by_its_own_gate(tmp_path, monkeypatch):
    calls: list = []
    ctx = make_ctx(tmp_path)
    spy_on_gate(monkeypatch, ctx, calls)
    install_fake_http(monkeypatch, FakeResponse(405), FakeResponse(200), log=calls)

    http_probe.HttpProbeModule(ctx).run([dns()])

    # Strict alternation: gate, request, gate, request … one gate per network touch.
    assert [c["kind"] for c in calls] == ["gate", "request"] * 4
    assert [(c.get("verb"), c.get("method")) for c in calls] == [
        ("http-HEAD", None), (None, "HEAD"),   # https HEAD -> 405
        ("http-GET", None), (None, "GET"),     # https GET fallback, separately gated
        ("http-HEAD", None), (None, "HEAD"),   # http HEAD -> 405
        ("http-GET", None), (None, "GET"),
    ]
    assert all(c["value"] == HOST for c in gates(calls))
    assert len(allow_records(ctx)) == 4


def test_each_touch_debits_the_unified_ledger_once(tmp_path, monkeypatch):
    ctx, summary, calls = run(tmp_path, monkeypatch, [dns()])

    assert len(ctx.ledger.log) == len(requests_made(calls)) == 2
    assert [e.verb for e in ctx.ledger.log] == ["http-HEAD", "http-HEAD"]
    assert {e.target for e in ctx.ledger.log} == {"epicgames.com"}  # keyed by registrable
    assert ctx.ledger.balance(HOST) == pytest.approx(18.0)
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
    ctx, summary, calls = run(tmp_path, monkeypatch, [dns()], ctx=override)

    assert requests_made(calls) == []  # refused means no packet, not a quieter packet
    assert ctx.graph.store.nodes == {} and ctx.graph.store.edges == {}
    assert ctx.ledger.log == []
    assert summary["requests"] == 0
    assert [r["verb"] for r in summary["refused"]] == ["http-HEAD", "http-HEAD"]
    assert all(fragment in r["reason"] for r in summary["refused"])
    assert len(refuse_records(ctx)) == 2


@pytest.mark.parametrize("host", [
    "secure.epicgames.com",      # excluded -> out_of_scope
    "internal.epicgames.dev",    # owned-but-unlisted -> prefilter_only
    "fhir.epic.com",             # default deny
    "203.0.114.9",               # outside the in-scope netblock
])
def test_out_of_scope_targets_are_never_touched(tmp_path, monkeypatch, host):
    seed = FakeNode(f"dns:{host}", "DNSName")
    ctx, summary, calls = run(tmp_path, monkeypatch, [seed])

    assert requests_made(calls) == []
    assert ctx.graph.store.nodes == {}
    assert summary["requests"] == 0 and len(summary["refused"]) == 2
    assert all("not in scope" in r["reason"] for r in summary["refused"])


def test_exhausted_budget_refuses_the_rest_and_never_crashes(tmp_path, monkeypatch):
    seeds = [dns(), dns("www.epicgames.com")]
    ctx, summary, calls = run(
        tmp_path, monkeypatch, seeds,
        ctx={"ledger": RateLedger(global_qps=2.0, capacity=3.0, clock=lambda: 0.0)},
    )

    assert len(requests_made(calls)) == 3  # the 4th touch is refused, not borrowed
    assert len(summary["refused"]) == 1
    assert "rate budget exceeded" in summary["refused"][0]["reason"]
    assert all(e.balance_after >= 0 for e in ctx.ledger.log)
    assert invariants.check(ctx.graph.store, ledger=ctx.ledger,
                            current_snapshot=ctx.snapshot.snapshot_id) == []


def test_module_cannot_probe_by_swallowing_a_refusal(tmp_path, monkeypatch):
    """A refusing gate must stop the request, however the refusal arrives."""

    ctx = make_ctx(tmp_path)
    calls = install_fake_http(monkeypatch)
    monkeypatch.setattr(
        ctx, "gate_active",
        lambda value, verb: (_ for _ in ()).throw(GateRefused("synthetic refusal")),
    )

    summary = http_probe.HttpProbeModule(ctx).run([dns()])

    assert requests_made(calls) == []
    assert ctx.graph.store.nodes == {}
    assert [r["reason"] for r in summary["refused"]] == ["synthetic refusal"] * 2


# --- the WebApp node -----------------------------------------------------------


HEADERS_FULL = {
    "Server": "nginx",
    "Strict-Transport-Security": "max-age=63072000",
    "Content-Security-Policy": "default-src 'self'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Access-Control-Allow-Origin": "https://www.epicgames.com",
    "CF-RAY": "7d3f-LHR",
}


def test_webapp_envelope_and_attrs(tmp_path, monkeypatch, only_https):
    ctx, summary, _ = run(tmp_path, monkeypatch, [dns()],
                          FakeResponse(200, HEADERS_FULL))

    node = ctx.graph.store.get(APP)
    assert node is not None and node.type == "WebApp"
    assert node.attrs == {
        "active_probed": True,
        "vhost": HOST,
        "scheme": "https",
        "status": 200,
        "hsts": True,
        "csp": True,
        "x_frame_options": True,
        "x_content_type_options": True,
        "server": "nginx",
        "cors_allow_origin": "https://www.epicgames.com",
        "cdn_or_waf": "cloudflare",
    }
    assert "title" not in node.attrs  # no GET was made, so there is no body to read
    assert "redirect_to" not in node.attrs
    assert node.coverage == {"fingerprinted": True}
    assert node.confidence.log_odds == pytest.approx(http_probe.LIVE_LOG_ODDS)
    assert node.confidence.state.value == "observed"  # one source never self-promotes
    assert node.sensitivity == Sensitivity.S0
    assert node.data_subject == "none"
    assert node.provenance.chain[0].tool == "http_probe"
    assert node.temporal.first_seen == NOW.isoformat()
    assert summary["webapps"] == 1


def test_binding_comes_from_the_gate_and_pins_the_snapshot(tmp_path, monkeypatch):
    ctx, _, _ = run(tmp_path, monkeypatch, [dns()])

    assert ctx.graph.store.nodes
    for datum in list(ctx.graph.store.nodes.values()) + list(ctx.graph.store.edges.values()):
        assert datum.scope_binding.verdict == Verdict.IN_SCOPE
        assert datum.scope_binding.snapshot_id == ctx.snapshot.snapshot_id
        assert datum.scope_binding.rule_matched == "included by '*.epicgames.com'"
        assert datum.scope_binding.observed_at == NOW.isoformat()


def test_missing_security_headers_are_recorded_as_false_not_acted_on(tmp_path,
                                                                     monkeypatch,
                                                                     only_https):
    ctx, _, _ = run(tmp_path, monkeypatch, [dns()], FakeResponse(200, {}))

    node = ctx.graph.store.get(APP)
    assert node.attrs == {
        "active_probed": True, "vhost": HOST, "scheme": "https", "status": 200,
        "hsts": False, "csp": False, "x_frame_options": False,
        "x_content_type_options": False,
    }


def test_both_schemes_become_separate_webapps(tmp_path, monkeypatch):
    ctx, summary, _ = run(tmp_path, monkeypatch, [dns()], {
        HTTPS_URL: FakeResponse(200, {"Server": "nginx"}),
        HTTP_URL: FakeResponse(301, {"Location": f"https://{HOST}/"}),
    })

    assert sorted(n.id for n in ctx.graph.store.iter_type("WebApp")) == [
        f"web:http://{HOST}", APP,
    ]
    assert ctx.graph.store.get(f"web:http://{HOST}").attrs["status"] == 301
    assert summary["webapps"] == 2


@pytest.mark.parametrize("headers, label", [
    ({"CF-RAY": "x"}, "cloudflare"),
    ({"Server": "cloudflare"}, "cloudflare"),
    ({"X-Amz-Cf-Id": "x"}, "cloudfront"),
    ({"X-Akamai-Request-ID": "x"}, "akamai"),
    ({"Server": "AkamaiGHost"}, "akamai"),
    ({"Fastly-Debug-Digest": "x"}, "fastly"),
    ({"X-Served-By": "cache-lhr-egll"}, "fastly"),
    ({"X-Azure-Ref": "x"}, "azure-front-door"),
    ({"Server": "Google Frontend"}, "google-frontend"),
    ({"X-Varnish": "1"}, "varnish"),
    ({"X-Sucuri-ID": "x"}, "sucuri"),
    ({"X-Iinfo": "x"}, "imperva"),
    ({"X-Amzn-Trace-Id": "x"}, "aws-alb-or-apigw"),
])
def test_cdn_or_waf_is_best_effort_and_deterministic(tmp_path, monkeypatch, only_https,
                                                     headers, label):
    ctx, _, _ = run(tmp_path, monkeypatch, [dns()], FakeResponse(200, headers))
    assert ctx.graph.store.get(APP).attrs["cdn_or_waf"] == label


def test_unknown_front_leaves_no_cdn_claim(tmp_path, monkeypatch, only_https):
    ctx, _, _ = run(tmp_path, monkeypatch, [dns()],
                    FakeResponse(200, {"Server": "nginx", "X-Powered-By": "PHP"}))
    assert "cdn_or_waf" not in ctx.graph.store.get(APP).attrs


# --- redirects: observed, normalized, never followed ---------------------------


def test_redirect_is_recorded_without_following_it(tmp_path, monkeypatch, only_https):
    ctx, _, calls = run(tmp_path, monkeypatch, [dns()],
                        FakeResponse(302, {"Location": "https://store.epicgames.com/en-US/"}))

    assert len(requests_made(calls)) == 1  # one hit; a hop is its own scope decision
    node = ctx.graph.store.get(APP)
    assert node.attrs["status"] == 302
    assert node.attrs["redirect_to"] == "https://store.epicgames.com/en-US/"
    assert not list(ctx.graph.store.iter_type("DNSName"))  # the hop target is not minted


@pytest.mark.parametrize("location, expected", [
    # the query and fragment are dropped, never parsed or stored
    ("https://id.epicgames.com/login?client_id=abc&access_token=SECRET",
     "https://id.epicgames.com/login"),
    ("https://id.epicgames.com/login#access_token=SECRET", "https://id.epicgames.com/login"),
    ("/account/personal", "/account/personal"),
    ("//cdn.epicgames.com/assets", "//cdn.epicgames.com/assets"),
    ("https://EPICGAMES.com/Path", "https://epicgames.com/Path"),  # host folded, path kept
    ("https://user:pw@id.epicgames.com/", ""),          # userinfo: dropped, not cleaned
    ("https://id.epicgames.com/u/someone@example.com", ""),
    ("com.epicgames.launcher://store", ""),             # deeplink is not a web target
    ("", ""),
    ("   ", ""),
    ("http://host/\x00evil", ""),
])
def test_redirect_target_normalization(location, expected):
    assert http_probe.redirect_target(location) == expected


def test_secret_bearing_redirect_never_reaches_an_attr(tmp_path, monkeypatch, only_https):
    secret = "eyJhbGciOiJIUzI1NiJ9.payload.sig"
    ctx, _, _ = run(tmp_path, monkeypatch, [dns()], FakeResponse(
        301, {"Location": f"https://id.epicgames.com/cb?code={secret}"}))

    node = ctx.graph.store.get(APP)
    assert node.attrs["redirect_to"] == "https://id.epicgames.com/cb"
    assert secret not in repr(node.to_dict())


def test_redirect_to_is_absent_for_a_non_redirect_status(tmp_path, monkeypatch, only_https):
    ctx, _, _ = run(tmp_path, monkeypatch, [dns()],
                    FakeResponse(200, {"Location": "https://elsewhere.epicgames.com/"}))
    assert "redirect_to" not in ctx.graph.store.get(APP).attrs


# --- the GET fallback ----------------------------------------------------------


@pytest.mark.parametrize("status", sorted(http_probe.HEAD_REJECTED_STATUSES))
def test_head_rejection_falls_back_to_one_separately_gated_get(tmp_path, monkeypatch,
                                                               only_https, status):
    page = "<html><head>\n  <title>Epic\tGames  Store </title></head></html>"
    ctx, summary, calls = run(
        tmp_path, monkeypatch, [dns()],
        head=FakeResponse(status, {"Allow": "GET, HEAD"}),
        get=FakeResponse(200, {"Server": "nginx"}, text=page),
    )

    assert [(c["method"], c["url"]) for c in requests_made(calls)] == [
        ("HEAD", HTTPS_URL), ("GET", HTTPS_URL),
    ]
    assert [r["verb"] for r in allow_records(ctx)] == ["http-HEAD", "http-GET"]
    assert summary["get_fallbacks"] == 1 and summary["requests"] == 2

    node = ctx.graph.store.get(APP)
    assert node.attrs["status"] == 200           # the GET characterizes the app
    assert node.attrs["title"] == "Epic Games Store"
    assert ctx.graph.store.get(HEAD_OP).attrs["status"] == status
    assert ctx.graph.store.get(GET_OP).attrs["status"] == 200


def test_a_usable_head_never_spends_a_get(tmp_path, monkeypatch, only_https):
    ctx, summary, calls = run(tmp_path, monkeypatch, [dns()],
                              head=FakeResponse(403, {"Server": "nginx"}),
                              get=FakeResponse(200, text="<title>nope</title>"))

    assert [c["method"] for c in requests_made(calls)] == ["HEAD"]
    assert summary["get_fallbacks"] == 0
    assert ctx.graph.store.get(GET_OP) is None
    assert "title" not in ctx.graph.store.get(APP).attrs


def test_refused_get_fallback_still_keeps_the_head_observation(tmp_path, monkeypatch,
                                                               only_https):
    ctx, summary, calls = run(
        tmp_path, monkeypatch, [dns()], FakeResponse(405),
        ctx={"ledger": RateLedger(global_qps=1.0, capacity=1.0, clock=lambda: 0.0)},
    )

    assert [c["method"] for c in requests_made(calls)] == ["HEAD"]
    assert [r["verb"] for r in summary["refused"]] == ["http-GET"]
    node = ctx.graph.store.get(APP)
    assert node.attrs["status"] == 405 and "title" not in node.attrs
    assert ctx.graph.store.get(GET_OP) is None


def test_title_is_capped_and_absent_when_the_body_has_none(tmp_path, monkeypatch,
                                                           only_https):
    monkeypatch.setattr(http_probe, "MAX_TITLE_CHARS", 10)
    ctx, _, _ = run(tmp_path, monkeypatch, [dns()], FakeResponse(405),
                    get=FakeResponse(200, text="<title>" + "x" * 50 + "</title>"))
    assert ctx.graph.store.get(APP).attrs["title"] == "x" * 10

    ctx2, _, _ = run(tmp_path, monkeypatch, [dns()], FakeResponse(405),
                     get=FakeResponse(200, text="<html>no title here</html>"))
    assert "title" not in ctx2.graph.store.get(APP).attrs


# --- Operation nodes + exposes edges ------------------------------------------


def test_operation_and_exposes_edge(tmp_path, monkeypatch, only_https):
    ctx, summary, _ = run(tmp_path, monkeypatch, [dns()], FakeResponse(204, {"Server": "x"}))

    op = ctx.graph.store.get(HEAD_OP)
    assert op is not None and op.type == "Operation"
    assert op.attrs == {
        "active_probed": True, "method": "HEAD", "path_template": "/",
        "status": 204, "webapp": APP,
    }
    assert op.coverage == {"enumerated": True}  # existence observed; no parameter mined
    assert op.sensitivity == Sensitivity.S0 and op.data_subject == "none"

    edges = ctx.graph.store.out_edges(APP, "exposes")
    assert [(e.frm, e.to) for e in edges] == [(APP, HEAD_OP)]
    assert edges[0].attrs == {"active_probed": True}
    assert edges[0].scope_binding.verdict == Verdict.IN_SCOPE
    assert summary["operations"] == 1 and summary["edges"] == 1


def test_one_operation_per_request_actually_made(tmp_path, monkeypatch, only_https):
    ctx, summary, _ = run(tmp_path, monkeypatch, [dns()], FakeResponse(501),
                          get=FakeResponse(200))

    assert sorted(n.id for n in ctx.graph.store.iter_type("Operation")) == [GET_OP, HEAD_OP]
    assert {(e.frm, e.to) for e in ctx.graph.store.edges.values()} == {
        (APP, HEAD_OP), (APP, GET_OP),
    }
    assert summary["operations"] == 2 and summary["edges"] == 2


# --- evidence & secret hygiene -------------------------------------------------


def test_headers_are_stored_as_sorted_content_addressed_evidence(tmp_path, monkeypatch,
                                                                 only_https):
    # deliberately unsorted + mixed case: the blob must not depend on server order
    ctx, _, _ = run(tmp_path, monkeypatch, [dns()],
                    FakeResponse(200, {"Server": "nginx", "Content-Type": "text/html"}))

    expected = f"HEAD {HTTPS_URL}\nHTTP 200\ncontent-type: text/html\nserver: nginx"
    sha = sha256_bytes(expected.encode("utf-8"))
    node = ctx.graph.store.get(APP)
    assert [e.sha256 for e in node.evidence] == [sha]
    assert node.evidence[0].region == f"http_probe:HEAD {HTTPS_URL}"
    assert node.evidence[0].encrypted_at_rest is True
    assert node.provenance.chain[0].evidence_id == sha
    assert ctx.evidence.get(sha).decode("utf-8") == expected
    assert [e.sha256 for e in ctx.graph.store.get(HEAD_OP).evidence] == [sha]


def test_header_order_does_not_change_the_evidence_hash(tmp_path, monkeypatch, only_https):
    forward = {"A-Header": "1", "B-Header": "2", "Server": "nginx"}
    ctx_a, _, _ = run(tmp_path, monkeypatch, [dns()], FakeResponse(200, forward))
    ctx_b, _, _ = run(tmp_path, monkeypatch, [dns()],
                      FakeResponse(200, dict(reversed(list(forward.items())))))

    assert ([e.sha256 for e in ctx_a.graph.store.get(APP).evidence]
            == [e.sha256 for e in ctx_b.graph.store.get(APP).evidence])


def test_cookie_and_auth_values_are_redacted_before_storage(tmp_path, monkeypatch,
                                                            only_https):
    secret = "s%3Aab12cd34ef56.LIVE-SESSION-VALUE"
    ctx, _, _ = run(tmp_path, monkeypatch, [dns()], FakeResponse(200, {
        "Set-Cookie": f"EPIC_SESSION={secret}; Path=/; Secure; HttpOnly",
        "Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig",
        "Server": "nginx",
    }))

    node = ctx.graph.store.get(APP)
    blob = ctx.evidence.get(node.evidence[0].sha256).decode("utf-8")
    assert secret not in blob and "LIVE-SESSION-VALUE" not in blob
    assert "payload.sig" not in blob
    assert f"set-cookie: EPIC_SESSION={redact(secret + '; Path=/; Secure; HttpOnly')}" in blob
    assert "EPIC_SESSION" in blob  # the cookie NAME is a legitimate auth signal
    # and nothing secret-shaped reached an attribute at all
    assert set(node.attrs) & {"set_cookie", "cookies", "authorization"} == set()
    assert secret not in repr(node.to_dict())


def test_response_body_is_never_written_to_the_evidence_store(tmp_path, monkeypatch,
                                                              only_https):
    body = "<title>Store</title><script>const token='LEAKED-FROM-BODY';</script>"
    ctx, _, _ = run(tmp_path, monkeypatch, [dns()], FakeResponse(405),
                    get=FakeResponse(200, {"Server": "nginx"}, text=body))

    node = ctx.graph.store.get(APP)
    assert node.attrs["title"] == "Store"
    for ref in node.evidence:
        assert "LEAKED-FROM-BODY" not in ctx.evidence.get(ref.sha256).decode("utf-8")


def test_no_credential_or_token_node_is_ever_minted(tmp_path, monkeypatch):
    ctx, _, _ = run(tmp_path, monkeypatch, [dns()], FakeResponse(200, {
        "Set-Cookie": "EPIC_SESSION=abc", "WWW-Authenticate": 'Bearer realm="epic"',
    }))

    assert not list(ctx.graph.store.iter_type("Credential"))
    assert not list(ctx.graph.store.iter_type("Token"))
    assert all(n.data_subject == "none" for n in ctx.graph.store.nodes.values())


def test_unwritable_evidence_store_does_not_fail_the_probe(tmp_path, monkeypatch,
                                                           only_https):
    ctx = make_ctx(tmp_path)
    install_fake_http(monkeypatch, FakeResponse(200, {"Server": "nginx"}))

    def boom(*args, **kwargs):
        raise OSError("read-only filesystem")

    monkeypatch.setattr(ctx.evidence, "put_text", boom)
    summary = http_probe.HttpProbeModule(ctx).run([dns()])

    assert summary["webapps"] == 1
    assert ctx.graph.store.get(APP).evidence == []


# --- failure handling ----------------------------------------------------------


@pytest.mark.parametrize("exc", [
    requests.ConnectionError("down"),
    requests.Timeout("slow"),
    requests.TooManyRedirects("loop"),
    requests.RequestException("boom"),
    RuntimeError("unknown transport"),
])
def test_network_errors_do_not_crash_the_run(tmp_path, monkeypatch, exc):
    ctx, summary, calls = run(tmp_path, monkeypatch, [dns()], raises=exc)

    assert len(requests_made(calls)) == 2  # one attempt per (host, scheme); no retry
    assert ctx.graph.store.nodes == {} and ctx.graph.store.edges == {}
    assert summary["webapps"] == 0 and len(summary["errors"]) == 2
    assert summary["requests"] == 2  # the budget was spent, and is recorded as spent
    assert len(ctx.ledger.log) == 2


def test_one_bad_target_does_not_stop_the_others(tmp_path, monkeypatch):
    other = "www.fortnite.com"

    def head(url):
        if HOST in url:
            raise requests.ConnectionError("down")
        return FakeResponse(200, {"Server": "nginx"})

    ctx, summary, _ = run(tmp_path, monkeypatch, [dns(), dns(other)], head)

    assert sorted(n.id for n in ctx.graph.store.iter_type("WebApp")) == [
        f"web:http://{other}", f"web:https://{other}",
    ]
    assert len(summary["errors"]) == 2 and summary["webapps"] == 2


@pytest.mark.parametrize("status", [None, "200", 99, 600, True])
def test_unusable_status_is_logged_and_skipped(tmp_path, monkeypatch, only_https, status):
    ctx, summary, _ = run(tmp_path, monkeypatch, [dns()],
                          FakeResponse(status, {"Server": "nginx"}))

    assert ctx.graph.store.nodes == {}
    assert summary["errors"] == [{"url": HTTPS_URL, "method": "HEAD",
                                 "error": "no usable status code"}]


def test_undictable_headers_do_not_crash_the_probe(tmp_path, monkeypatch, only_https):
    class Hostile:
        def items(self):
            raise RuntimeError("not dict-like")

    resp = FakeResponse(200)
    resp.headers = Hostile()
    ctx, summary, _ = run(tmp_path, monkeypatch, [dns()], resp)

    node = ctx.graph.store.get(APP)
    assert node.attrs["status"] == 200 and node.attrs["hsts"] is False
    assert summary["webapps"] == 1


# --- seeds ---------------------------------------------------------------------


def test_empty_and_junk_seeds_are_graceful(tmp_path, monkeypatch):
    for seeds in ([], None, ["", "   ", None, 42, "not a host"]):
        ctx, summary, calls = run(tmp_path, monkeypatch, seeds)
        assert requests_made(calls) == []
        assert summary["targets"] == [] and summary["webapps"] == 0
        assert ctx.ledger.log == []


def test_foreign_seed_node_types_are_ignored(tmp_path, monkeypatch):
    seeds = [
        FakeNode(f"domain:{HOST}", "Domain"),
        FakeNode(APP, "WebApp"),
        FakeNode("svc:203.0.113.5:443/tcp", "Service"),
        FakeNode("hyp:dns-candidate:api.epicgames.com", "Hypothesis"),
        FakeNode(f"dns:{HOST}", "Host"),  # a mislabeled but still host-shaped seed
    ]
    _, summary, calls = run(tmp_path, monkeypatch, seeds)

    assert summary["targets"] == [HOST]
    assert len(requests_made(calls)) == 2


def test_host_seed_is_probed_only_under_a_netblock_rule(tmp_path, monkeypatch):
    ctx, summary, calls = run(tmp_path, monkeypatch, [FakeNode("host:203.0.113.5", "Host")])

    assert [c["url"] for c in requests_made(calls)] == [
        "https://203.0.113.5/", "http://203.0.113.5/",
    ]
    assert ctx.graph.store.get("web:https://203.0.113.5") is not None
    assert summary["refused"] == []

    ctx2, summary2, calls2 = run(tmp_path, monkeypatch,
                                 [FakeNode("host:198.51.100.7", "Host")])
    assert requests_made(calls2) == [] and len(summary2["refused"]) == 2


def test_ipv6_host_seed_is_bracketed_in_the_url_and_the_id(tmp_path, monkeypatch):
    for seed in (FakeNode("host:2001:db8::1", "Host"), "[2001:db8::1]"):
        ctx, summary, calls = run(tmp_path, monkeypatch, [seed])
        assert [c["url"] for c in requests_made(calls)] == [
            "https://[2001:db8::1]/", "http://[2001:db8::1]/",
        ]
        assert ctx.graph.store.get("web:https://[2001:db8::1]") is not None
        assert summary["refused"] == []


# --- idempotence, forking, invariants -----------------------------------------


def test_rerun_with_the_same_observation_merges_without_forking(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    install_fake_http(monkeypatch, FakeResponse(200, {"Server": "nginx"}))
    module = http_probe.HttpProbeModule(ctx)
    module.run([dns()])
    module.run([dns()])

    assert sorted(n.id for n in ctx.graph.store.iter_type("WebApp")) == [
        f"web:http://{HOST}", APP,
    ]
    node = ctx.graph.store.get(APP)
    assert "#fork" not in node.id
    assert node.coverage == {"fingerprinted": True}
    assert node.attrs["status"] == 200


def test_a_changed_status_forks_instead_of_overwriting(tmp_path, monkeypatch, only_https):
    ctx = make_ctx(tmp_path)
    install_fake_http(monkeypatch, FakeResponse(200, {"Server": "nginx"}))
    http_probe.HttpProbeModule(ctx).run([dns()])
    monkeypatch.undo()
    install_fake_http(monkeypatch, FakeResponse(403, {"Server": "nginx"}))
    monkeypatch.setattr(http_probe, "SCHEMES", ("https",))
    http_probe.HttpProbeModule(ctx).run([dns()])

    assert ctx.graph.store.get(APP).attrs["status"] == 200  # history is never overwritten
    fork = ctx.graph.store.get(f"{APP}#fork1")
    assert fork is not None and fork.attrs["status"] == 403
    assert fork.confidence.forked_from == APP
    assert any(e.kind == "contradiction_forked" for e in ctx.graph.log.all())


def test_graph_satisfies_the_safety_invariants(tmp_path, monkeypatch):
    seeds = [dns(), dns("www.fortnite.com"), FakeNode("host:203.0.113.5", "Host"),
             FakeNode("dns:secure.epicgames.com", "DNSName"),
             FakeNode("dns:internal.epicgames.dev", "DNSName")]
    ctx, summary, _ = run(tmp_path, monkeypatch, seeds, FakeResponse(405),
                          get=FakeResponse(200, HEADERS_FULL, text="<title>t</title>"))

    assert ctx.graph.store.nodes and summary["webapps"] == 6
    assert invariants.check(ctx.graph.store, ledger=ctx.ledger,
                            current_snapshot=ctx.snapshot.snapshot_id) == []
    # every probed node carries the active-probe marker and an in_scope verdict (I2/I3)
    for node in ctx.graph.store.nodes.values():
        assert node.attrs["active_probed"] is True
        assert node.scope_binding.verdict == Verdict.IN_SCOPE
