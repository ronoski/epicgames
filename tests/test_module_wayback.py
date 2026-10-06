"""Offline, deterministic tests for the passive wayback module.

Nothing here touches the network: ``requests.get`` is monkeypatched per test and an autouse
fixture makes ``socket``/``ssl`` raise, so a regression that reaches for a real connection
fails loudly instead of contacting web.archive.org (or any Epic host). Time is injected via
``ModuleContext.now`` so every envelope timestamp is fixed.
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
from recon.evidence import EvidenceStore, sha256_bytes
from recon.events import EventLog
from recon.models import Sensitivity, Verdict
from recon.modules.base import ModuleContext, get_module
from recon.modules.passive import wayback
from recon.ratelimit import RateLedger
from recon.scope import Scope
from recon.snapshot import take_snapshot
from recon.store import Graph

NOW = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)

APP = "web:https://api.epicgames.com"


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
    def __init__(self, text: str = "", status_code: int = 200) -> None:
        self.text = text
        self.status_code = status_code


def install_fake_get(monkeypatch, bodies, *, status_code: int = 200, raises=None):
    """Patch ``requests.get`` inside the module. Returns the captured-call list.

    ``bodies`` is either a single response string or a ``{host: string}`` mapping.
    """

    calls: list[dict] = []

    def fake_get(url, headers=None, timeout=None, **kwargs):
        calls.append({"url": url, "headers": dict(headers or {}), "timeout": timeout})
        if raises is not None:
            raise raises
        if isinstance(bodies, dict):
            host = url.split("url=", 1)[1].split("/*", 1)[0]
            return FakeResponse(bodies.get(host, "[]"), status_code)
        return FakeResponse(bodies, status_code)

    monkeypatch.setattr(wayback.requests, "get", fake_get)
    return calls


def make_ctx(tmp_path, **overrides) -> ModuleContext:
    scope = Scope(
        include=["*.epicgames.com", "*.fortnite.com"],
        exclude=["secure.epicgames.com"],
        prefilter=["*.epicgames.dev"],
    )
    kwargs = dict(
        scope=scope,
        ledger=RateLedger(global_qps=2.0, capacity=4.0),
        evidence=EvidenceStore(tmp_path / "evidence"),
        graph=Graph(EventLog()),
        snapshot=take_snapshot("pinned policy text", now=NOW),
        logger=logging.getLogger("test.wayback"),
        allow_active=False,
        now=NOW,
    )
    kwargs.update(overrides)
    return ModuleContext(**kwargs)


class FakeNode:
    """Minimal stand-in for a graph Node seed (only ``id``/``type`` are read)."""

    def __init__(self, id: str, type: str) -> None:
        self.id = id
        self.type = type


def cdx(*rows, header: bool = True) -> str:
    """Build a CDX ``output=json`` body. ``rows`` are ``(original, timestamp)`` pairs."""

    out = [["original", "timestamp"]] if header else []
    out.extend([original, timestamp] for original, timestamp in rows)
    return json.dumps(out)


def seed(host: str = "epicgames.com") -> list:
    return [FakeNode(f"domain:{host}", "Domain")]


def run(tmp_path, monkeypatch, seeds, bodies, **kw):
    ctx = make_ctx(tmp_path)
    calls = install_fake_get(monkeypatch, bodies, **kw)
    return ctx, wayback.WaybackModule(ctx).run(seeds), calls


# --- registration & contract ---------------------------------------------------


def test_registered_under_its_filename_and_is_passive():
    assert get_module("wayback") is wayback.WaybackModule
    assert wayback.WaybackModule.name == "wayback"
    assert wayback.WaybackModule.active is False
    assert wayback.WaybackModule.produces == ("WebApp", "Route")


def test_verb_is_whitelisted_and_not_active():
    from recon import verbs

    assert wayback.VERB in verbs.ALLOWED
    assert wayback.VERB not in verbs.ACTIVE
    assert wayback.VERB not in verbs.BLOCKED and wayback.VERB not in verbs.HUMAN_GATED


def test_only_declared_ontology_types_are_used():
    from recon import ontology

    assert set(wayback.WaybackModule.produces) <= ontology.node_types()
    assert "exposes" in ontology.edge_types()


# --- request shape -------------------------------------------------------------


def test_query_url_headers_and_timeout(tmp_path, monkeypatch):
    ctx, summary, calls = run(tmp_path, monkeypatch, seed(),
                              cdx(("https://api.epicgames.com/", "20200101000000")))

    assert len(calls) == 1
    assert calls[0]["url"] == (
        "https://web.archive.org/cdx/search/cdx?url=epicgames.com/*&output=json"
        "&fl=original,timestamp&collapse=urlkey&limit=500"
    )
    assert calls[0]["headers"]["User-Agent"] == ctx.user_agent
    assert calls[0]["timeout"] == ctx.timeout
    assert summary["queried"] == 1


def test_hosts_come_from_domain_and_dnsname_seeds_and_are_deduped(tmp_path, monkeypatch):
    seeds = [
        FakeNode("dns:www.epicgames.com", "DNSName"),
        FakeNode("domain:epicgames.com", "Domain"),
        FakeNode("dns:www.epicgames.com", "DNSName"),  # repeat -> one query
        "*.fortnite.com",                               # plain strings are tolerated
    ]
    _, summary, calls = run(tmp_path, monkeypatch, seeds, {})

    assert summary["hosts"] == ["www.epicgames.com", "epicgames.com", "fortnite.com"]
    assert len(calls) == 3


def test_non_domain_seeds_ips_and_junk_are_ignored(tmp_path, monkeypatch):
    seeds = [
        FakeNode("host:203.0.113.5", "Host"),
        FakeNode("web:https://a.epicgames.com", "WebApp"),
        FakeNode("domain:203.0.113.0/24", "Domain"),
        FakeNode("domain:not a host", "Domain"),
        "fortnite.com",
    ]
    _, summary, calls = run(tmp_path, monkeypatch, seeds, {})

    assert summary["hosts"] == ["fortnite.com"]
    assert len(calls) == 1


def test_empty_and_junk_seeds_are_graceful(tmp_path, monkeypatch):
    for seeds in ([], None, ["", "   ", None, 42]):
        _, summary, calls = run(tmp_path, monkeypatch, seeds, "[]")
        assert calls == []
        assert summary["hosts"] == [] and summary["emitted"] == 0
        assert summary["queried"] == 0


# --- template normalization (pure) ---------------------------------------------


@pytest.mark.parametrize("path,expected", [
    ("/", "/"),
    ("", "/"),
    ("/account", "/account"),
    ("/account/", "/account"),
    ("//account//settings//", "/account/settings"),
    ("/v2/account/12345", "/v2/account/{id}"),
    ("/users/550e8400-e29b-41d4-a716-446655440000/profile", "/users/{id}/profile"),
    ("/x/d41d8cd98f00b204e9800998ecf8427e", "/x/{id}"),
    ("/b/eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1g", "/b/{id}"),
    ("/s/" + "A" * 44, "/s/{id}"),
    ("/catalog/v1/offers/2", "/catalog/v1/offers/{id}"),
    ("/bundle.a1b2c3.js", "/bundle.a1b2c3.js"),
    ("/t/SUPERSECRETVALUE1234567890", "/t/{id}"),       # unbroken alnum run + digit = id
    ("/account/forgot-password-confirmation", "/account/forgot-password-confirmation"),
    ("/ForgotPasswordConfirmation", "/ForgotPasswordConfirmation"),
    ("/users/nobody@example.com", ""),      # an email in a path is never collected
    ("/with space", ""),                     # mangled index row
    ("/" + "/".join(str(i) for i in range(20)), ""),  # pathological depth
    ("/" + "/".join(["aaaa.bbbb.cccc.dd"] * 12), ""),  # pathological length
])
def test_path_template(path, expected):
    assert wayback.path_template(path) == expected


@pytest.mark.parametrize("url", [
    "ftp://api.epicgames.com/x",
    "mailto:someone@epicgames.com",
    "http://user:pass@api.epicgames.com/x",   # userinfo may be a credential
    "http://203.0.113.5/x",                   # raw IP is not a vhost
    "http://[bad::ipv6/x",
    "not a url",
    "",
    None,
])
def test_unusable_archived_urls_are_rejected(url):
    assert wayback.parse_archived_url(url) is None


def test_query_string_and_fragment_are_dropped_at_parse():
    assert wayback.parse_archived_url(
        "https://API.epicgames.com/account?access_token=SUPERSECRETVALUE#frag"
    ) == ("https", "api.epicgames.com", "/account")


# --- emission ------------------------------------------------------------------


def test_emits_webapp_route_and_exposes_edge(tmp_path, monkeypatch):
    body = cdx(
        ("https://api.epicgames.com/account/12345/profile", "20200101000000"),
        ("https://api.epicgames.com/", "20190101000000"),
    )
    ctx, summary, _ = run(tmp_path, monkeypatch, seed(), body)

    assert sorted(ctx.graph.store.nodes) == sorted([
        APP,
        f"route:{APP}/",
        f"route:{APP}/account/{{id}}/profile",
    ])
    assert sorted(ctx.graph.store.edges) == sorted([
        f"exposes:{APP}->route:{APP}/",
        f"exposes:{APP}->route:{APP}/account/{{id}}/profile",
    ])
    for edge in ctx.graph.store.edges.values():
        assert edge.type == "exposes"
        assert edge.frm == APP and edge.to.startswith(f"route:{APP}")
    assert summary["webapps"] == 1 and summary["routes"] == 2 and summary["edges"] == 2
    assert summary["emitted"] == 3 and summary["urls_parsed"] == 2


def test_http_and_https_are_distinct_webapps(tmp_path, monkeypatch):
    body = cdx(
        ("http://api.epicgames.com/x", "20100101000000"),
        ("https://api.epicgames.com/x", "20200101000000"),
    )
    ctx, summary, _ = run(tmp_path, monkeypatch, seed(), body)

    assert summary["webapps"] == 2 and summary["routes"] == 2
    assert "web:http://api.epicgames.com" in ctx.graph.store.nodes
    assert APP in ctx.graph.store.nodes


def test_templates_are_deduped_in_memory_before_emitting(tmp_path, monkeypatch):
    body = cdx(*[
        (f"https://api.epicgames.com/account/{i}/profile", f"20{i:02d}0101000000")
        for i in range(10, 20)
    ])
    ctx, summary, _ = run(tmp_path, monkeypatch, seed(), body)

    route_id = f"route:{APP}/account/{{id}}/profile"
    assert sorted(ctx.graph.store.nodes) == sorted([APP, route_id])
    assert summary["routes"] == 1 and summary["urls_parsed"] == 10
    node = ctx.graph.store.get(route_id)
    # one upsert per distinct template: no self-corroboration from 10 captures
    assert node.confidence.log_odds == pytest.approx(0.0)
    assert node.confidence.independent_sources == 1


def test_historical_envelope_is_not_a_live_claim(tmp_path, monkeypatch):
    body = cdx(("https://api.epicgames.com/account/1", "20200101000000"))
    ctx, _, _ = run(tmp_path, monkeypatch, seed(), body)

    for node in ctx.graph.store.nodes.values():
        assert node.attrs["historical"] is True
        assert node.attrs["archived_timestamp"] == "20200101000000"
        assert "active_probed" not in node.attrs       # passive: nothing was probed
        assert node.confidence.log_odds == pytest.approx(0.0)
        assert node.confidence.probability == pytest.approx(0.5)
        assert node.sensitivity == Sensitivity.S0
        assert node.data_subject == "none"
        assert node.coverage == {"enumerated": True}
        assert node.provenance.chain[0].tool == "wayback"
        assert node.temporal.first_seen == NOW.isoformat()
    for edge in ctx.graph.store.edges.values():
        assert edge.attrs == {"historical": True}
        assert edge.confidence.log_odds == pytest.approx(0.0)


def test_node_attrs_describe_the_id_and_nothing_else(tmp_path, monkeypatch):
    body = cdx(("https://api.epicgames.com/account/1", "20200101000000"))
    ctx, _, _ = run(tmp_path, monkeypatch, seed(), body)

    assert ctx.graph.store.get(APP).attrs == {
        "historical": True, "vhost": "api.epicgames.com", "scheme": "https",
        "archived_timestamp": "20200101000000",
    }
    assert ctx.graph.store.get(f"route:{APP}/account/{{id}}").attrs == {
        "historical": True, "path_template": "/account/{id}",
        "archived_timestamp": "20200101000000",
    }


def test_earliest_capture_timestamp_wins(tmp_path, monkeypatch):
    body = cdx(
        ("https://api.epicgames.com/account/1", "20220101000000"),
        ("https://api.epicgames.com/account/2", "20180101000000"),
        ("https://api.epicgames.com/account/3", "20200101000000"),
    )
    ctx, _, _ = run(tmp_path, monkeypatch, seed(), body)

    for node in ctx.graph.store.nodes.values():
        assert node.attrs["archived_timestamp"] == "20180101000000"


def test_malformed_timestamp_is_dropped_not_stored(tmp_path, monkeypatch):
    body = cdx(("https://api.epicgames.com/account/1", "whenever"))
    ctx, _, _ = run(tmp_path, monkeypatch, seed(), body)

    for node in ctx.graph.store.nodes.values():
        assert "archived_timestamp" not in node.attrs
        assert node.attrs["historical"] is True


def test_raw_cdx_response_is_stored_as_the_evidence_ref(tmp_path, monkeypatch):
    body = cdx(("https://api.epicgames.com/x", "20200101000000"))
    ctx, _, _ = run(tmp_path, monkeypatch, seed(), body)

    expected = sha256_bytes(body.encode("utf-8"))
    assert ctx.graph.store.nodes
    for node in ctx.graph.store.nodes.values():
        assert [e.sha256 for e in node.evidence] == [expected]
        assert node.evidence[0].region == "wayback:cdx:epicgames.com/*"
        assert node.provenance.chain[0].evidence_id == expected
    assert ctx.evidence.get(expected) == body.encode("utf-8")


def test_cdx_header_row_is_not_mistaken_for_a_url(tmp_path, monkeypatch):
    ctx, summary, _ = run(tmp_path, monkeypatch, seed(),
                          cdx(("https://api.epicgames.com/x", "20200101000000")))

    assert summary["rows_seen"] == 1 and summary["urls_skipped"] == 0
    assert len(ctx.graph.store.nodes) == 2


# --- scope enforcement ---------------------------------------------------------


def test_only_in_scope_archived_hosts_are_emitted(tmp_path, monkeypatch):
    body = cdx(
        ("https://api.epicgames.com/a", "20200101000000"),      # in scope
        ("https://secure.epicgames.com/a", "20200101000000"),    # excluded
        ("https://internal.epicgames.dev/a", "20200101000000"),  # prefilter_only
        ("https://fhir.epic.com/a", "20200101000000"),           # default deny
        ("https://cdn.example.net/a", "20200101000000"),         # default deny
    )
    ctx, summary, _ = run(tmp_path, monkeypatch, seed(), body)

    assert sorted(ctx.graph.store.nodes) == sorted([APP, f"route:{APP}/a"])
    assert summary["dropped_out_of_scope"] == 4
    assert summary["dropped_by_verdict"] == {"out_of_scope": 3, "prefilter_only": 1}
    assert summary["webapps"] == 1 and summary["routes"] == 1 and summary["edges"] == 1


def test_a_dropped_host_never_leaves_an_orphan_route_or_edge(tmp_path, monkeypatch):
    body = cdx(("https://secure.epicgames.com/a/b/c", "20200101000000"))
    ctx, summary, _ = run(tmp_path, monkeypatch, seed(), body)

    assert ctx.graph.store.nodes == {} and ctx.graph.store.edges == {}
    assert summary["emitted"] == 0 and summary["routes"] == 0


def test_every_emitted_datum_is_in_scope_bound_to_the_snapshot(tmp_path, monkeypatch):
    body = cdx(
        ("https://api.epicgames.com/a", "20200101000000"),
        ("https://www.fortnite.com/b", "20200101000000"),
        ("https://internal.epicgames.dev/c", "20200101000000"),
    )
    ctx, _, _ = run(tmp_path, monkeypatch, seed(), body)

    data = list(ctx.graph.store.nodes.values()) + list(ctx.graph.store.edges.values())
    assert len(data) == 6  # 2 WebApps + 2 Routes + 2 edges
    for datum in data:
        assert datum.scope_binding.verdict == Verdict.IN_SCOPE
        assert datum.scope_binding.snapshot_id == ctx.snapshot.snapshot_id
        assert datum.scope_binding.rule_matched  # never a fabricated binding
        assert datum.scope_binding.observed_at == NOW.isoformat()


def test_cross_host_duplicate_is_emitted_once(tmp_path, monkeypatch):
    shared = cdx(("https://api.epicgames.com/a", "20200101000000"))
    seeds = [FakeNode("domain:epicgames.com", "Domain"),
             FakeNode("dns:api.epicgames.com", "DNSName")]
    ctx, summary, calls = run(tmp_path, monkeypatch, seeds,
                              {"epicgames.com": shared, "api.epicgames.com": shared})

    assert len(calls) == 2
    assert summary["webapps"] == 1 and summary["routes"] == 1 and summary["edges"] == 1
    assert ctx.graph.store.get(APP).confidence.log_odds == pytest.approx(0.0)


# --- secrets & other-person data -----------------------------------------------


def test_no_token_value_from_a_query_string_ever_reaches_the_graph(tmp_path, monkeypatch):
    secret = "SUPERSECRETVALUE1234567890"
    body = cdx(
        (f"https://api.epicgames.com/oauth/token?access_token={secret}", "20200101000000"),
        (f"https://api.epicgames.com/cb#id_token={secret}", "20200101000000"),
        (f"https://api.epicgames.com/legacy/{secret}", "20200101000000"),
    )
    ctx, summary, _ = run(tmp_path, monkeypatch, seed(), body)

    dumped = json.dumps(
        [n.to_dict() for n in ctx.graph.store.nodes.values()]
        + [e.to_dict() for e in ctx.graph.store.edges.values()]
    )
    assert secret not in dumped
    assert sorted(ctx.graph.store.nodes) == sorted([
        APP, f"route:{APP}/cb", f"route:{APP}/legacy/{{id}}", f"route:{APP}/oauth/token",
    ])
    # nothing here is a Credential/Token node, so no S0-labelled secret can exist
    assert {n.type for n in ctx.graph.store.nodes.values()} == {"WebApp", "Route"}
    assert summary["urls_skipped"] == 0


def test_other_person_data_is_skipped_not_redacted(tmp_path, monkeypatch):
    body = cdx(
        ("https://api.epicgames.com/users/someone.else@example.com", "20200101000000"),
        ("https://user:pw@api.epicgames.com/admin", "20200101000000"),
        ("https://api.epicgames.com/ok", "20200101000000"),
    )
    ctx, summary, _ = run(tmp_path, monkeypatch, seed(), body)

    assert sorted(ctx.graph.store.nodes) == sorted([APP, f"route:{APP}/ok"])
    assert summary["urls_skipped"] == 2
    assert all(n.data_subject == "none" for n in ctx.graph.store.nodes.values())


# --- failure handling ----------------------------------------------------------


def test_non_200_is_logged_and_skipped(tmp_path, monkeypatch):
    ctx, summary, calls = run(tmp_path, monkeypatch, seed(),
                              cdx(("https://api.epicgames.com/x", "20200101000000")),
                              status_code=429)

    assert len(calls) == 1  # no retry-hammering
    assert ctx.graph.store.nodes == {}
    assert summary["emitted"] == 0
    assert summary["errors"] == [{"host": "epicgames.com", "error": "HTTP 429"}]


@pytest.mark.parametrize("exc", [
    requests.ConnectionError("down"),
    requests.Timeout("slow"),
    requests.RequestException("boom"),
    RuntimeError("unknown transport"),
])
def test_network_errors_do_not_crash_the_run(tmp_path, monkeypatch, exc):
    ctx, summary, _ = run(tmp_path, monkeypatch, seed(), "[]", raises=exc)

    assert ctx.graph.store.nodes == {}
    assert summary["emitted"] == 0 and len(summary["errors"]) == 1


@pytest.mark.parametrize("body", ["not json", '{"rows": 1}', "null", "[", "42"])
def test_bad_json_is_logged_and_skipped(tmp_path, monkeypatch, body):
    ctx, summary, _ = run(tmp_path, monkeypatch, seed(), body)

    assert ctx.graph.store.nodes == {}
    assert len(summary["errors"]) == 1
    assert "JSON" in summary["errors"][0]["error"]


@pytest.mark.parametrize("body", ["", "   ", "[]", json.dumps([["original", "timestamp"]])])
def test_no_captures_is_not_an_error(tmp_path, monkeypatch, body):
    ctx, summary, _ = run(tmp_path, monkeypatch, seed(), body)

    assert ctx.graph.store.nodes == {}
    assert summary["errors"] == [] and summary["emitted"] == 0


def test_malformed_rows_are_skipped(tmp_path, monkeypatch):
    body = json.dumps([
        ["original", "timestamp"],
        "not-a-list",
        ["https://api.epicgames.com/short"],              # missing timestamp
        [None, "20200101000000"],
        [42, 42],
        ["https://api.epicgames.com/ok", "20200101000000"],
    ])
    ctx, summary, _ = run(tmp_path, monkeypatch, seed(), body)

    assert sorted(ctx.graph.store.nodes) == sorted([APP, f"route:{APP}/ok"])
    assert summary["rows_seen"] == 1


def test_one_bad_host_does_not_stop_the_others(tmp_path, monkeypatch):
    seeds = [FakeNode("domain:epicgames.com", "Domain"),
             FakeNode("domain:fortnite.com", "Domain")]
    ctx, summary, _ = run(tmp_path, monkeypatch, seeds, {
        "epicgames.com": "truncated-garbage",
        "fortnite.com": cdx(("https://www.fortnite.com/news", "20200101000000")),
    })

    assert sorted(ctx.graph.store.nodes) == sorted([
        "web:https://www.fortnite.com", "route:web:https://www.fortnite.com/news",
    ])
    assert summary["queried"] == 2 and summary["emitted"] == 2
    assert [e["host"] for e in summary["errors"]] == ["epicgames.com"]


def test_unwritable_evidence_store_is_not_fatal(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    install_fake_get(monkeypatch, cdx(("https://api.epicgames.com/x", "20200101000000")))

    def boom(*args, **kwargs):
        raise OSError("read-only filesystem")

    monkeypatch.setattr(ctx.evidence, "put_text", boom)
    summary = wayback.WaybackModule(ctx).run(seed())

    assert summary["emitted"] == 2
    assert all(n.evidence == [] for n in ctx.graph.store.nodes.values())


def test_oversized_response_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(wayback, "MAX_RESPONSE_BYTES", 16)
    ctx, summary, _ = run(tmp_path, monkeypatch, seed(),
                          cdx(("https://api.epicgames.com/x", "20200101000000")))

    assert ctx.graph.store.nodes == {}
    assert "cap" in summary["errors"][0]["error"]


# --- caps ----------------------------------------------------------------------


def test_row_cap_is_enforced_client_side_too(tmp_path, monkeypatch):
    monkeypatch.setattr(wayback, "MAX_ROWS", 2)
    body = cdx(*[(f"https://api.epicgames.com/p{i}", "20200101000000") for i in range(10)])
    ctx, summary, calls = run(tmp_path, monkeypatch, seed(), body)

    assert "limit=2" in calls[0]["url"]
    assert summary["rows_seen"] == 2
    assert summary["routes"] == 2


def test_template_cap_truncates_instead_of_running_away(tmp_path, monkeypatch):
    monkeypatch.setattr(wayback, "MAX_TEMPLATES_PER_HOST", 2)
    body = cdx(*[(f"https://api.epicgames.com/p{i}", "20200101000000") for i in range(10)])
    ctx, summary, _ = run(tmp_path, monkeypatch, seed(), body)

    assert summary["routes"] == 2 and summary["truncated"] is True
    assert len(ctx.graph.store.nodes) == 3  # 1 WebApp + 2 Routes


def test_host_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(wayback, "MAX_HOSTS", 2)
    seeds = [FakeNode("domain:epicgames.com", "Domain"),
             FakeNode("domain:fortnite.com", "Domain"),
             FakeNode("domain:unrealengine.com", "Domain")]
    _, summary, calls = run(tmp_path, monkeypatch, seeds, {})

    assert summary["hosts"] == ["epicgames.com", "fortnite.com"]
    assert len(calls) == 2


# --- passivity: no gate, no ledger debit ---------------------------------------


def test_never_gates_and_never_debits_the_ledger(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)

    def forbidden(*args, **kwargs):
        raise AssertionError("a passive module must not gate or debit")

    monkeypatch.setattr(ctx, "gate_active", forbidden)
    monkeypatch.setattr(ctx.ledger, "debit", forbidden)
    install_fake_get(monkeypatch, cdx(
        ("https://api.epicgames.com/a", "20200101000000"),
        ("https://secure.epicgames.com/a", "20200101000000"),
    ))

    summary = wayback.WaybackModule(ctx).run(seed())

    assert summary["emitted"] == 2
    assert ctx.ledger.log == []
    assert ctx.ledger.balance("epicgames.com") == pytest.approx(4.0)
    kinds = {e.kind for e in ctx.graph.log.all()}
    assert "gate_decision_recorded" not in kinds and "rate_debit" not in kinds
    assert kinds == {"node_upserted", "edge_upserted"}


def test_runs_with_active_disabled(tmp_path, monkeypatch):
    """allow_active=False must not stop a passive module; it never gates in the first place."""

    ctx = make_ctx(tmp_path, allow_active=False)
    install_fake_get(monkeypatch, cdx(("https://api.epicgames.com/a", "20200101000000")))

    assert wayback.WaybackModule(ctx).run(seed())["emitted"] == 2


def test_stale_snapshot_blocks_retention_and_the_query(tmp_path, monkeypatch):
    stale = take_snapshot("old policy", now=datetime(2026, 1, 1, tzinfo=timezone.utc))
    assert stale.is_stale(NOW)
    ctx = make_ctx(tmp_path, snapshot=stale)
    calls = install_fake_get(monkeypatch, cdx(("https://api.epicgames.com/a", "20200101000000")))

    summary = wayback.WaybackModule(ctx).run(seed())

    assert calls == []  # I12: a stale snapshot blocks downstream action
    assert ctx.graph.store.nodes == {} and summary["emitted"] == 0
    assert "stale" in summary["blocked"]


def test_missing_snapshot_blocks_retention_and_the_query(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path, snapshot=None)
    calls = install_fake_get(monkeypatch, cdx(("https://api.epicgames.com/a", "20200101000000")))

    summary = wayback.WaybackModule(ctx).run(seed())

    assert calls == []
    assert ctx.graph.store.nodes == {} and summary["emitted"] == 0
    assert "no scope snapshot" in summary["blocked"]


# --- invariants & idempotence --------------------------------------------------


def test_graph_satisfies_the_safety_invariants(tmp_path, monkeypatch):
    body = cdx(
        ("https://api.epicgames.com/account/1", "20200101000000"),
        ("http://api.epicgames.com/oauth/token?code=abc", "20190101000000"),
        ("https://secure.epicgames.com/a", "20200101000000"),
        ("https://internal.epicgames.dev/a", "20200101000000"),
        ("https://api.epicgames.com/u/nobody@example.com", "20200101000000"),
    )
    seeds = [FakeNode("domain:epicgames.com", "Domain"),
             FakeNode("domain:fortnite.com", "Domain")]
    ctx, _, _ = run(tmp_path, monkeypatch, seeds, {
        "epicgames.com": body,
        "fortnite.com": cdx(("https://www.fortnite.com/", "20210101000000")),
    })

    assert ctx.graph.store.nodes and ctx.graph.store.edges
    assert invariants.check(
        ctx.graph.store, ledger=ctx.ledger, current_snapshot=ctx.snapshot.snapshot_id,
    ) == []


def test_rerun_is_idempotent_and_never_forks(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    install_fake_get(monkeypatch, cdx(
        ("https://api.epicgames.com/account/1", "20200101000000"),
        ("https://api.epicgames.com/account/2", "20210101000000"),
    ))
    module = wayback.WaybackModule(ctx)
    module.run(seed())
    module.run(seed())

    assert sorted(ctx.graph.store.nodes) == sorted([APP, f"route:{APP}/account/{{id}}"])
    assert list(ctx.graph.store.edges) == [f"exposes:{APP}->route:{APP}/account/{{id}}"]
    for datum in list(ctx.graph.store.nodes.values()) + list(ctx.graph.store.edges.values()):
        assert "#fork" not in datum.id
        assert datum.confidence.forked_from is None
    assert ctx.graph.store.get(APP).coverage == {"enumerated": True}
    assert "contradiction_forked" not in {e.kind for e in ctx.graph.log.all()}
