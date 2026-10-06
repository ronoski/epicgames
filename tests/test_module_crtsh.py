"""Offline, deterministic tests for the passive crtsh module.

Nothing here touches the network: ``requests.get`` is monkeypatched per test and an autouse
fixture makes ``socket``/``ssl`` raise, so a regression that reaches for a real connection
fails loudly instead of contacting crt.sh (or any Epic host). Time is injected via
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
from recon.modules.passive import crtsh
from recon.ratelimit import RateLedger
from recon.scope import Scope
from recon.snapshot import take_snapshot
from recon.store import Graph

NOW = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)


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

    ``bodies`` is either a single response string or an ``{apex: string}`` mapping.
    """

    calls: list[dict] = []

    def fake_get(url, headers=None, timeout=None, **kwargs):
        calls.append({"url": url, "headers": dict(headers or {}), "timeout": timeout})
        if raises is not None:
            raise raises
        if isinstance(bodies, dict):
            apex = url.split("q=%25.", 1)[1].split("&", 1)[0]
            return FakeResponse(bodies.get(apex, "[]"), status_code)
        return FakeResponse(bodies, status_code)

    monkeypatch.setattr(crtsh.requests, "get", fake_get)
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
        logger=logging.getLogger("test.crtsh"),
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


def crtsh_json(*name_values: str) -> str:
    return json.dumps([
        {"issuer_name": "C=US, O=Test CA", "name_value": nv, "id": i}
        for i, nv in enumerate(name_values)
    ])


def run(tmp_path, monkeypatch, seeds, bodies, **kw):
    ctx = make_ctx(tmp_path)
    calls = install_fake_get(monkeypatch, bodies, **kw)
    module = crtsh.CrtShModule(ctx)
    return ctx, module.run(seeds), calls


# --- registration & contract ---------------------------------------------------


def test_registered_under_its_filename_and_is_passive():
    assert get_module("crtsh") is crtsh.CrtShModule
    assert crtsh.CrtShModule.name == "crtsh"
    assert crtsh.CrtShModule.active is False
    assert crtsh.CrtShModule.produces == ("DNSName",)


def test_verb_is_whitelisted_and_not_active():
    from recon import verbs

    assert crtsh.VERB in verbs.ALLOWED
    assert crtsh.VERB not in verbs.ACTIVE
    assert crtsh.VERB not in verbs.BLOCKED and crtsh.VERB not in verbs.HUMAN_GATED


# --- request shape -------------------------------------------------------------


def test_query_url_headers_and_timeout(tmp_path, monkeypatch):
    seeds = [FakeNode("domain:epicgames.com", "Domain")]
    ctx, summary, calls = run(tmp_path, monkeypatch, seeds, crtsh_json("api.epicgames.com"))

    assert len(calls) == 1
    assert calls[0]["url"] == "https://crt.sh/?q=%25.epicgames.com&output=json"
    assert calls[0]["headers"]["User-Agent"] == ctx.user_agent
    assert calls[0]["timeout"] == ctx.timeout
    assert summary["queried"] == 1


def test_apex_derived_from_dnsname_seed_and_deduped(tmp_path, monkeypatch):
    seeds = [
        FakeNode("dns:a.b.epicgames.com", "DNSName"),
        FakeNode("domain:epicgames.com", "Domain"),  # same apex -> one query
        FakeNode("dns:www.fortnite.com", "DNSName"),
    ]
    _, summary, calls = run(tmp_path, monkeypatch, seeds, {})

    assert summary["apexes"] == ["epicgames.com", "fortnite.com"]
    assert [c["url"] for c in calls] == [
        "https://crt.sh/?q=%25.epicgames.com&output=json",
        "https://crt.sh/?q=%25.fortnite.com&output=json",
    ]


def test_non_domain_seeds_and_ips_are_ignored(tmp_path, monkeypatch):
    seeds = [
        FakeNode("host:203.0.113.5", "Host"),
        FakeNode("web:https://a.epicgames.com", "WebApp"),
        FakeNode("domain:203.0.113.0/24", "Domain"),
        "*.fortnite.com",  # plain-string seeds are tolerated
    ]
    _, summary, calls = run(tmp_path, monkeypatch, seeds, {})

    assert summary["apexes"] == ["fortnite.com"]
    assert len(calls) == 1


def test_empty_and_junk_seeds_are_graceful(tmp_path, monkeypatch):
    for seeds in ([], None, ["", "   ", None, 42]):
        _, summary, calls = run(tmp_path, monkeypatch, seeds, "[]")
        assert calls == []
        assert summary["apexes"] == [] and summary["emitted"] == 0
        assert summary["queried"] == 0


# --- parsing & scope enforcement -----------------------------------------------


def test_emits_only_in_scope_names(tmp_path, monkeypatch):
    body = crtsh_json(
        "api.epicgames.com\n*.cdn.epicgames.com",       # in scope (wildcard stripped)
        "LAUNCHER.Epicgames.com\napi.epicgames.com",    # lowercased + deduped
        "secure.epicgames.com",                          # excluded -> out_of_scope
        "internal.epicgames.dev",                        # owned-but-unlisted -> prefilter_only
        "fhir.epic.com\nbandcamp.com",                   # default-deny -> out_of_scope
    )
    ctx, summary, _ = run(tmp_path, monkeypatch, [FakeNode("domain:epicgames.com", "Domain")], body)

    assert sorted(ctx.graph.store.nodes) == [
        "dns:api.epicgames.com",
        "dns:cdn.epicgames.com",
        "dns:launcher.epicgames.com",
    ]
    assert summary["emitted"] == 3
    assert summary["names_seen"] == 7
    assert summary["dropped_out_of_scope"] == 4
    assert summary["dropped_by_verdict"] == {"out_of_scope": 3, "prefilter_only": 1}


def test_every_emitted_node_is_in_scope_bound_to_the_snapshot(tmp_path, monkeypatch):
    ctx, _, _ = run(
        tmp_path, monkeypatch,
        [FakeNode("domain:epicgames.com", "Domain")],
        crtsh_json("api.epicgames.com\nsecure.epicgames.com\ninternal.epicgames.dev"),
    )
    assert ctx.graph.store.nodes
    for node in ctx.graph.store.nodes.values():
        assert node.scope_binding.verdict == Verdict.IN_SCOPE
        assert node.scope_binding.snapshot_id == ctx.snapshot.snapshot_id
        assert node.scope_binding.rule_matched  # never a fabricated binding
        assert node.scope_binding.observed_at == NOW.isoformat()


def test_node_envelope(tmp_path, monkeypatch):
    body = crtsh_json("api.epicgames.com")
    ctx, _, _ = run(tmp_path, monkeypatch, [FakeNode("domain:epicgames.com", "Domain")], body)

    node = ctx.graph.store.get("dns:api.epicgames.com")
    assert node.type == "DNSName"
    assert node.coverage == {"enumerated": True}
    assert node.confidence.log_odds == pytest.approx(1.0)
    assert 0.5 < node.confidence.probability < 0.95
    assert node.sensitivity == Sensitivity.S0
    assert node.data_subject == "none"
    assert node.provenance.chain[0].tool == "crtsh"
    assert node.temporal.first_seen == NOW.isoformat()
    # passive: nothing here was probed, so the active-probe marker must be absent
    assert "active_probed" not in node.attrs
    assert node.attrs == {"ct_logged": True}


def test_raw_json_is_stored_as_the_evidence_ref(tmp_path, monkeypatch):
    body = crtsh_json("api.epicgames.com\nstore.epicgames.com")
    ctx, _, _ = run(tmp_path, monkeypatch, [FakeNode("domain:epicgames.com", "Domain")], body)

    expected = sha256_bytes(body.encode("utf-8"))
    for node in ctx.graph.store.nodes.values():
        assert [e.sha256 for e in node.evidence] == [expected]
        assert node.evidence[0].region == "crtsh:q=%25.epicgames.com"
        assert node.provenance.chain[0].evidence_id == expected
    assert ctx.evidence.get(expected) == body.encode("utf-8")


def test_email_and_ip_sans_are_never_collected(tmp_path, monkeypatch):
    body = crtsh_json(
        "admin@epicgames.com\nsomebody.else@fortnite.com\n203.0.113.5\n"
        "2001:db8::1\n*\n \napi.epicgames.com"
    )
    ctx, summary, _ = run(tmp_path, monkeypatch, [FakeNode("domain:epicgames.com", "Domain")], body)

    assert list(ctx.graph.store.nodes) == ["dns:api.epicgames.com"]
    assert summary["names_seen"] == 1  # the rest never even reached a scope binding
    assert all(n.data_subject == "none" for n in ctx.graph.store.nodes.values())


def test_malformed_rows_are_skipped(tmp_path, monkeypatch):
    body = json.dumps([
        "not-a-dict",
        {"name_value": None},
        {},
        {"name_value": "under_score.epicgames.com\nxn--tst-6la.epicgames.com"},
        {"name_value": "trailing.epicgames.com.\n  spaced.epicgames.com  "},
    ])
    ctx, _, _ = run(tmp_path, monkeypatch, [FakeNode("domain:epicgames.com", "Domain")], body)

    assert sorted(ctx.graph.store.nodes) == [
        "dns:spaced.epicgames.com",
        "dns:trailing.epicgames.com",
        "dns:under_score.epicgames.com",
        "dns:xn--tst-6la.epicgames.com",
    ]


def test_repeated_name_is_emitted_once_without_self_corroboration(tmp_path, monkeypatch):
    body = crtsh_json(*["api.epicgames.com"] * 5)
    ctx, summary, _ = run(tmp_path, monkeypatch, [FakeNode("domain:epicgames.com", "Domain")], body)

    assert summary["emitted"] == 1
    node = ctx.graph.store.get("dns:api.epicgames.com")
    assert node.confidence.log_odds == pytest.approx(1.0)
    assert node.confidence.independent_sources == 1


def test_cross_apex_name_is_not_double_counted(tmp_path, monkeypatch):
    shared = crtsh_json("shared.epicgames.com")
    seeds = [FakeNode("domain:epicgames.com", "Domain"), FakeNode("domain:fortnite.com", "Domain")]
    ctx, summary, calls = run(
        tmp_path, monkeypatch, seeds,
        {"epicgames.com": shared, "fortnite.com": shared},
    )

    assert len(calls) == 2
    assert summary["emitted"] == 1
    assert ctx.graph.store.get("dns:shared.epicgames.com").confidence.log_odds == pytest.approx(1.0)


# --- failure handling ----------------------------------------------------------


def test_non_200_is_logged_and_skipped(tmp_path, monkeypatch):
    ctx, summary, calls = run(
        tmp_path, monkeypatch, [FakeNode("domain:epicgames.com", "Domain")],
        crtsh_json("api.epicgames.com"), status_code=429,
    )

    assert len(calls) == 1  # no retry-hammering
    assert ctx.graph.store.nodes == {}
    assert summary["emitted"] == 0
    assert summary["errors"] == [{"apex": "epicgames.com", "error": "HTTP 429"}]


@pytest.mark.parametrize("exc", [
    requests.ConnectionError("down"),
    requests.Timeout("slow"),
    requests.RequestException("boom"),
    RuntimeError("unknown transport"),
])
def test_network_errors_do_not_crash_the_run(tmp_path, monkeypatch, exc):
    ctx, summary, _ = run(
        tmp_path, monkeypatch, [FakeNode("domain:epicgames.com", "Domain")],
        "[]", raises=exc,
    )
    assert ctx.graph.store.nodes == {}
    assert summary["emitted"] == 0 and len(summary["errors"]) == 1


@pytest.mark.parametrize("body", ["", "not json", "{\"rows\": 1}", "null", "[", "42"])
def test_bad_json_is_logged_and_skipped(tmp_path, monkeypatch, body):
    ctx, summary, _ = run(tmp_path, monkeypatch, [FakeNode("domain:epicgames.com", "Domain")], body)

    assert ctx.graph.store.nodes == {}
    assert len(summary["errors"]) == 1
    assert "JSON" in summary["errors"][0]["error"]


def test_one_bad_apex_does_not_stop_the_others(tmp_path, monkeypatch):
    seeds = [FakeNode("domain:epicgames.com", "Domain"), FakeNode("domain:fortnite.com", "Domain")]
    ctx, summary, _ = run(
        tmp_path, monkeypatch, seeds,
        {"epicgames.com": "truncated-garbage", "fortnite.com": crtsh_json("www.fortnite.com")},
    )

    assert list(ctx.graph.store.nodes) == ["dns:www.fortnite.com"]
    assert summary["queried"] == 2 and summary["emitted"] == 1
    assert [e["apex"] for e in summary["errors"]] == ["epicgames.com"]


def test_oversized_response_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(crtsh, "MAX_RESPONSE_BYTES", 16)
    ctx, summary, _ = run(
        tmp_path, monkeypatch, [FakeNode("domain:epicgames.com", "Domain")],
        crtsh_json("api.epicgames.com"),
    )
    assert ctx.graph.store.nodes == {}
    assert "cap" in summary["errors"][0]["error"]


def test_per_apex_name_cap_truncates_instead_of_running_away(tmp_path, monkeypatch):
    monkeypatch.setattr(crtsh, "MAX_NAMES_PER_APEX", 2)
    body = crtsh_json("\n".join(f"h{i}.epicgames.com" for i in range(10)))
    ctx, summary, _ = run(tmp_path, monkeypatch, [FakeNode("domain:epicgames.com", "Domain")], body)

    assert summary["emitted"] == 2 and summary["truncated"] is True
    assert len(ctx.graph.store.nodes) == 2


def test_apex_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(crtsh, "MAX_APEXES", 2)
    seeds = [FakeNode(f"domain:d{i}.epicgames.com", "Domain") for i in range(5)]
    seeds = [FakeNode("domain:epicgames.com", "Domain"),
             FakeNode("domain:fortnite.com", "Domain"),
             FakeNode("domain:unrealengine.com", "Domain")]
    _, summary, calls = run(tmp_path, monkeypatch, seeds, {})
    assert summary["apexes"] == ["epicgames.com", "fortnite.com"]
    assert len(calls) == 2


# --- passivity: no gate, no ledger debit ---------------------------------------


def test_never_gates_and_never_debits_the_ledger(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)

    def forbidden(*args, **kwargs):
        raise AssertionError("a passive module must not gate or debit")

    monkeypatch.setattr(ctx, "gate_active", forbidden)
    monkeypatch.setattr(ctx.ledger, "debit", forbidden)
    install_fake_get(monkeypatch, crtsh_json("api.epicgames.com\nsecure.epicgames.com"))

    summary = crtsh.CrtShModule(ctx).run([FakeNode("domain:epicgames.com", "Domain")])

    assert summary["emitted"] == 1
    assert ctx.ledger.log == []
    assert ctx.ledger.balance("epicgames.com") == pytest.approx(4.0)
    kinds = {e.kind for e in ctx.graph.log.all()}
    assert "gate_decision_recorded" not in kinds and "rate_debit" not in kinds
    assert kinds == {"node_upserted"}


def test_runs_with_active_disabled_and_a_stale_snapshot(tmp_path, monkeypatch):
    """A passive source needs no non-stale snapshot to *query*, only to bind retention."""

    stale = take_snapshot("old policy", now=datetime(2026, 1, 1, tzinfo=timezone.utc))
    ctx = make_ctx(tmp_path, snapshot=stale, allow_active=False)
    assert stale.is_stale(NOW)
    install_fake_get(monkeypatch, crtsh_json("api.epicgames.com"))

    summary = crtsh.CrtShModule(ctx).run([FakeNode("domain:epicgames.com", "Domain")])

    assert summary["emitted"] == 1
    node = ctx.graph.store.get("dns:api.epicgames.com")
    # bound to the snapshot it actually observed under, so I1/I12 can catch it downstream
    assert node.scope_binding.snapshot_id == stale.snapshot_id


def test_no_edges_emitted(tmp_path, monkeypatch):
    ctx, _, _ = run(
        tmp_path, monkeypatch, [FakeNode("domain:epicgames.com", "Domain")],
        crtsh_json("api.epicgames.com"),
    )
    assert ctx.graph.store.edges == {}


# --- invariants ----------------------------------------------------------------


def test_graph_satisfies_the_safety_invariants(tmp_path, monkeypatch):
    body = crtsh_json(
        "api.epicgames.com\nsecure.epicgames.com\ninternal.epicgames.dev\n"
        "admin@epicgames.com\nwww.fortnite.com"
    )
    ctx, _, _ = run(
        tmp_path, monkeypatch,
        [FakeNode("domain:epicgames.com", "Domain"), FakeNode("domain:fortnite.com", "Domain")],
        {"epicgames.com": body, "fortnite.com": crtsh_json("www.fortnite.com")},
    )

    assert ctx.graph.store.nodes
    assert invariants.check(
        ctx.graph.store, ledger=ctx.ledger, current_snapshot=ctx.snapshot.snapshot_id,
    ) == []


def test_rerun_is_idempotent_on_node_ids(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    install_fake_get(monkeypatch, crtsh_json("api.epicgames.com"))
    module = crtsh.CrtShModule(ctx)
    module.run([FakeNode("domain:epicgames.com", "Domain")])
    module.run([FakeNode("domain:epicgames.com", "Domain")])

    assert list(ctx.graph.store.nodes) == ["dns:api.epicgames.com"]
    node = ctx.graph.store.get("dns:api.epicgames.com")
    assert "#fork" not in node.id  # stable attrs must never fork on re-observation
    assert node.coverage == {"enumerated": True}
