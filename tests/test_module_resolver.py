"""Offline, deterministic tests for the ACTIVE ``resolver`` module.

This module is the first rung of the active ladder, so the tests are built around the two
properties a reviewer cares about most: **nothing is ever probed without a gate ALLOW for
that exact value**, and **nothing is ever retained without its own ``in_scope`` verdict**.

Everything is offline by construction: an autouse fixture makes every real socket/TLS/HTTP
primitive raise, ``socket.gethostbyname_ex`` is replaced by an in-memory answer table that
records what was asked, time is injected via ``ModuleContext.now``, and the rate ledger uses
a frozen monotonic clock. No test may contact any host — least of all an Epic one.
"""

from __future__ import annotations

import logging
import socket
import ssl
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from recon import invariants, ontology, verbs
from recon.evidence import EvidenceStore, sha256_bytes
from recon.events import EventLog
from recon.factory import make_edge, make_node
from recon.models import Sensitivity, Verdict
from recon.modules.active import resolver
from recon.modules.base import ModuleContext, get_module
from recon.ratelimit import RateLedger
from recon.scope import Scope
from recon.snapshot import take_snapshot
from recon.store import Graph

NOW = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)

INCLUDE = ["*.epicgames.com", "203.0.113.0/24"]      # TEST-NET-3 stands in for Epic's range
EXCLUDE = ["admin.epicgames.com"]
PREFILTER = ["*.epicgames.dev", "198.51.100.0/24"]   # owned-but-unlisted

IN_SCOPE_IP = "203.0.113.5"
OTHER_IN_SCOPE_IP = "203.0.113.6"
OUT_OF_SCOPE_IP = "192.0.2.5"                        # TEST-NET-1: matched by no rule
PREFILTER_IP = "198.51.100.7"                        # TEST-NET-2: owned, unlisted


# --- harness -------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _no_real_network(monkeypatch):
    """Hard offline guard: any genuine socket/TLS/HTTP use is a test failure."""

    def boom(*args, **kwargs):  # pragma: no cover - only runs on a violation
        raise AssertionError("test attempted a real network connection")

    monkeypatch.setattr(socket, "socket", boom)
    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    monkeypatch.setattr(socket, "gethostbyname", boom, raising=False)
    monkeypatch.setattr(socket, "gethostbyname_ex", boom, raising=False)
    monkeypatch.setattr(ssl, "create_default_context", boom)
    requests = pytest.importorskip("requests")
    monkeypatch.setattr(requests, "get", boom, raising=False)
    monkeypatch.setattr(requests, "request", boom, raising=False)
    monkeypatch.setattr(requests.Session, "request", boom, raising=False)


class FakeNode:
    """Minimal stand-in for a graph Node seed (only id/type/attrs are read)."""

    def __init__(self, id: str, type: str = "DNSName", attrs: dict | None = None) -> None:
        self.id = id
        self.type = type
        self.attrs = attrs if attrs is not None else {}


def nx() -> socket.gaierror:
    """A genuine 'no such name' resolver error."""

    return socket.gaierror(socket.EAI_NONAME, "Name or service not known")


def no_data() -> socket.gaierror:
    """'The name exists but has no address of the requested family' (AAAA-only host)."""

    code = getattr(socket, "EAI_NODATA", None) or getattr(socket, "EAI_ADDRFAMILY", None)
    return socket.gaierror(code, "No address associated with hostname")


def again() -> socket.gaierror:
    """A temporary resolver failure (SERVFAIL) — NOT evidence a name is gone."""

    return socket.gaierror(socket.EAI_AGAIN, "Temporary failure in name resolution")


def make_ctx(tmp_path, *, include=None, exclude=None, prefilter=None, snapshot="fresh",
             now=NOW, allow_active=True, capacity=10.0) -> ModuleContext:
    scope = Scope(
        include=list(include if include is not None else INCLUDE),
        exclude=list(exclude if exclude is not None else EXCLUDE),
        prefilter=list(prefilter if prefilter is not None else PREFILTER),
    )
    if snapshot == "fresh":
        snap = take_snapshot("PINNED POLICY TEXT", now=now, half_life="PT24H")
    elif snapshot == "stale":
        snap = take_snapshot("PINNED POLICY TEXT", now=now - timedelta(days=3),
                             half_life="PT24H")
    else:
        snap = snapshot
    return ModuleContext(
        scope=scope,
        ledger=RateLedger(global_qps=2.0, capacity=capacity, clock=lambda: 0.0),
        evidence=EvidenceStore(tmp_path / "evidence"),
        graph=Graph(log=EventLog()),
        snapshot=snap,
        logger=logging.getLogger("recon.test.resolver"),
        allow_active=allow_active,
        now=now,
    )


def install(monkeypatch, answers: dict, trace: list | None = None) -> list[str]:
    """Replace the resolver with an in-memory answer table. Returns the call list.

    A name absent from ``answers`` is NXDOMAIN; a value that is an exception is raised.
    """

    calls: list[str] = []

    def fake_gethostbyname_ex(fqdn):
        calls.append(fqdn)
        if trace is not None:
            trace.append(("probe", fqdn))
        answer = answers.get(fqdn, nx())
        if isinstance(answer, BaseException):
            raise answer
        return answer

    monkeypatch.setattr(socket, "gethostbyname_ex", fake_gethostbyname_ex)
    return calls


def spy_gate(ctx, trace: list):
    """Record every gate decision so gate-before-probe ordering is checkable."""

    original = ctx.gate_active

    def gate_active(value, verb):
        try:
            binding = original(value, verb)
        except Exception:
            trace.append(("refused", value))
            raise
        trace.append(("allowed", value))
        return binding

    ctx.gate_active = gate_active


def run(tmp_path, monkeypatch, seeds, answers=None, **kw):
    ctx = make_ctx(tmp_path, **kw)
    calls = install(monkeypatch, answers or {})
    summary = resolver.ResolverModule(ctx).run(seeds)
    return ctx, summary, calls


def node_types(ctx) -> dict:
    return {n.id: n.type for n in ctx.graph.store.nodes.values()}


# --- registration & contract ---------------------------------------------------


def test_registered_under_its_filename_and_is_active():
    assert get_module("resolver") is resolver.ResolverModule
    assert resolver.ResolverModule.name == "resolver"
    assert Path(resolver.__file__).name == "resolver.py"
    assert resolver.ResolverModule.active is True
    assert set(resolver.ResolverModule.produces) <= ontology.node_types()
    assert set(resolver.ResolverModule.produces) == {"DNSName", "Host", "Hypothesis"}


def test_verb_is_whitelisted_and_active():
    assert resolver.VERB == "resolve"
    assert resolver.VERB in verbs.ALLOWED
    assert resolver.VERB in verbs.ACTIVE
    assert resolver.VERB not in verbs.BLOCKED
    assert resolver.VERB not in verbs.HUMAN_GATED
    verbs.assert_schedulable(resolver.VERB)


def test_takeover_claiming_is_not_schedulable_at_all():
    """The dangling-CNAME path is detection only; claiming is a blocked verb."""

    assert "takeover-claim" in verbs.BLOCKED
    with pytest.raises(verbs.BlockedVerb):
        verbs.assert_schedulable("takeover-claim")


def test_one_network_primitive_and_no_http_machinery():
    """The module's only touch is a single gethostbyname_ex call site."""

    src = Path(resolver.__file__).read_text(encoding="utf-8")
    assert src.count("gethostbyname_ex(") == 1
    for token in ("import requests", "requests.", "import urllib", "import subprocess",
                  "import http", "create_connection", "getaddrinfo", "socket.socket",
                  "while True", "time.sleep"):
        assert token not in src, f"active resolver must not reference {token!r}"


def test_hypothesis_confidence_is_never_positive():
    assert resolver.DANGLING_LOG_ODDS <= 0
    assert resolver.RESOLVED_LOG_ODDS > 0  # a confirmed name is asserted, not guessed


# --- the gate: one ALLOW per lookup, always before the lookup -------------------


def test_every_probe_is_preceded_by_its_own_gate_allow(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    trace: list = []
    spy_gate(ctx, trace)
    install(monkeypatch, {
        "api.epicgames.com": ("api.epicgames.com", [], [IN_SCOPE_IP]),
        "www.epicgames.com": ("www.epicgames.com", [], [IN_SCOPE_IP]),
    }, trace=trace)

    resolver.ResolverModule(ctx).run([FakeNode("dns:api.epicgames.com"),
                                      FakeNode("dns:www.epicgames.com")])

    assert trace == [
        ("allowed", "api.epicgames.com"), ("probe", "api.epicgames.com"),
        ("allowed", "www.epicgames.com"), ("probe", "www.epicgames.com"),
    ]


def test_gate_allow_and_rate_debit_are_recorded_per_lookup(tmp_path, monkeypatch):
    ctx, summary, calls = run(
        tmp_path, monkeypatch, [FakeNode("dns:api.epicgames.com")],
        {"api.epicgames.com": ("api.epicgames.com", [], [IN_SCOPE_IP])},
    )

    allows = [e.payload for e in ctx.graph.log.by_kind("gate_decision_recorded")]
    assert [a["decision"] for a in allows] == ["ALLOW"]
    assert allows[0] == {"decision": "ALLOW", "value": "api.epicgames.com",
                         "verb": "resolve", "rule": "included by '*.epicgames.com'"}
    debits = [e.payload for e in ctx.graph.log.by_kind("rate_debit")]
    assert len(debits) == 1 and debits[0]["target"] == "epicgames.com"
    assert [e.verb for e in ctx.ledger.log] == ["resolve"]
    assert ctx.ledger.balance("epicgames.com") == pytest.approx(ctx.ledger.capacity - 1)
    assert summary["gated"] == 1 and summary["probed"] == 1 and summary["refused"] == 0


def test_active_disabled_refuses_every_seed_and_probes_nothing(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path, allow_active=False)

    def boom(fqdn):  # pragma: no cover - only runs on a violation
        raise AssertionError("probed a value the gate refused")

    monkeypatch.setattr(socket, "gethostbyname_ex", boom)
    summary = resolver.ResolverModule(ctx).run([FakeNode("dns:api.epicgames.com")])

    assert summary["refused"] == 1 and summary["probed"] == 0
    assert "allow_active=false" in next(iter(summary["refused_by_reason"]))
    assert ctx.graph.store.nodes == {} and ctx.graph.store.edges == {}
    assert ctx.ledger.log == []
    refusals = [e.payload for e in ctx.graph.log.by_kind("gate_decision_recorded")]
    assert [r["decision"] for r in refusals] == ["REFUSE"]


@pytest.mark.parametrize("snapshot,expected", [
    (None, "no scope snapshot"),
    ("stale", "stale"),
])
def test_missing_or_stale_snapshot_refuses_and_probes_nothing(tmp_path, monkeypatch,
                                                              snapshot, expected):
    ctx = make_ctx(tmp_path, snapshot=snapshot)

    def boom(fqdn):  # pragma: no cover - only runs on a violation
        raise AssertionError("probed against a missing/stale policy snapshot")

    monkeypatch.setattr(socket, "gethostbyname_ex", boom)
    summary = resolver.ResolverModule(ctx).run([FakeNode("dns:api.epicgames.com")])

    assert summary["probed"] == 0 and summary["refused"] == 1
    assert expected in next(iter(summary["refused_by_reason"]))
    assert ctx.graph.store.nodes == {}


@pytest.mark.parametrize("fqdn,verdict", [
    ("admin.epicgames.com", "out_of_scope"),      # exclude wins
    ("internal.epicgames.dev", "prefilter_only"),  # owned but unlisted
    ("www.sketchfab.com", "out_of_scope"),         # default deny
])
def test_out_of_scope_seeds_are_refused_not_probed(tmp_path, monkeypatch, fqdn, verdict):
    ctx = make_ctx(tmp_path)

    def boom(name):  # pragma: no cover - only runs on a violation
        raise AssertionError(f"probed out-of-scope value {name}")

    monkeypatch.setattr(socket, "gethostbyname_ex", boom)
    summary = resolver.ResolverModule(ctx).run([FakeNode(f"dns:{fqdn}")])

    assert summary["refused"] == 1 and summary["probed"] == 0
    assert verdict in next(iter(summary["refused_by_reason"]))
    assert ctx.graph.store.nodes == {}
    assert ctx.ledger.log == []  # a refused gate never debits


def test_exhausted_rate_budget_refuses_the_rest_of_the_seeds(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path, capacity=1.0)  # exactly one lookup available
    calls = install(monkeypatch, {
        "api.epicgames.com": ("api.epicgames.com", [], [IN_SCOPE_IP]),
        "www.epicgames.com": ("www.epicgames.com", [], [OTHER_IN_SCOPE_IP]),
    })

    summary = resolver.ResolverModule(ctx).run([FakeNode("dns:api.epicgames.com"),
                                                FakeNode("dns:www.epicgames.com")])

    assert calls == ["api.epicgames.com"]  # the second name was never touched
    assert summary["probed"] == 1 and summary["refused"] == 1
    assert "rate budget exceeded" in next(iter(summary["refused_by_reason"]))
    assert ctx.graph.store.get("host:" + OTHER_IN_SCOPE_IP) is None
    assert all(e.balance_after >= 0 for e in ctx.ledger.log)


def test_a_refusal_does_not_stop_the_other_seeds(tmp_path, monkeypatch):
    ctx, summary, calls = run(
        tmp_path, monkeypatch,
        [FakeNode("dns:admin.epicgames.com"), FakeNode("dns:api.epicgames.com")],
        {"api.epicgames.com": ("api.epicgames.com", [], [IN_SCOPE_IP])},
    )

    assert calls == ["api.epicgames.com"]
    assert summary["refused"] == 1 and summary["resolved"] == 1


# --- a live answer -------------------------------------------------------------


def test_known_name_resolves_to_host_and_edge(tmp_path, monkeypatch):
    ctx, summary, _ = run(
        tmp_path, monkeypatch, [FakeNode("dns:api.epicgames.com")],
        {"api.epicgames.com": ("api.epicgames.com", [], [IN_SCOPE_IP, OTHER_IN_SCOPE_IP])},
    )

    assert node_types(ctx) == {
        "dns:api.epicgames.com": "DNSName",
        f"host:{IN_SCOPE_IP}": "Host",
        f"host:{OTHER_IN_SCOPE_IP}": "Host",
    }
    assert set(ctx.graph.store.edges) == {
        f"resolves_to:dns:api.epicgames.com->host:{IN_SCOPE_IP}",
        f"resolves_to:dns:api.epicgames.com->host:{OTHER_IN_SCOPE_IP}",
    }
    assert summary["resolved"] == 1 and summary["hosts_emitted"] == 2
    assert summary["resolves_to_edges"] == 2 and summary["dns_emitted"] == 1
    assert summary["dropped_by_verdict"] == {}


def test_node_envelopes_from_an_active_probe(tmp_path, monkeypatch):
    ctx, _, _ = run(
        tmp_path, monkeypatch, [FakeNode("dns:api.epicgames.com")],
        {"api.epicgames.com": ("api.epicgames.com", [], [IN_SCOPE_IP])},
    )

    dns = ctx.graph.store.get("dns:api.epicgames.com")
    assert dns.type == "DNSName"
    assert dns.attrs == {"active_probed": True}  # rule: active probes are labeled
    assert dns.coverage == {"enumerated": True}  # its address records are now known
    assert dns.confidence.log_odds == pytest.approx(resolver.RESOLVED_LOG_ODDS)
    assert dns.sensitivity == Sensitivity.S0 and dns.data_subject == "none"
    assert dns.provenance.chain[0].tool == "resolver"
    assert dns.provenance.chain[0].rule_id == resolver.RULE_ID
    assert dns.provenance.chain[0].rule_version == resolver.RULE_VERSION
    assert dns.temporal.first_seen == NOW.isoformat()
    assert dns.temporal.last_verified == NOW.isoformat()

    host = ctx.graph.store.get(f"host:{IN_SCOPE_IP}")
    assert host.type == "Host" and host.attrs == {"active_probed": True}
    assert host.coverage == {"enumerated": False}  # services are the port-scan's job
    assert host.sensitivity == Sensitivity.S0

    edge = ctx.graph.store.edges[f"resolves_to:dns:api.epicgames.com->host:{IN_SCOPE_IP}"]
    assert edge.type == "resolves_to"
    assert edge.frm == "dns:api.epicgames.com" and edge.to == f"host:{IN_SCOPE_IP}"


def test_every_emitted_datum_is_in_scope_bound_to_the_current_snapshot(tmp_path, monkeypatch):
    ctx, _, _ = run(
        tmp_path, monkeypatch,
        [FakeNode("dns:api.epicgames.com"), FakeNode("dns:www.epicgames.com")],
        {
            "api.epicgames.com": ("api.epicgames.com", [], [IN_SCOPE_IP]),
            "www.epicgames.com": ("cdn.epicgames.com", ["www.epicgames.com"],
                                  [OTHER_IN_SCOPE_IP]),
        },
    )

    data = list(ctx.graph.store.nodes.values()) + list(ctx.graph.store.edges.values())
    assert data
    for datum in data:
        assert datum.scope_binding.verdict == Verdict.IN_SCOPE
        assert datum.scope_binding.snapshot_id == ctx.snapshot.snapshot_id
        assert datum.scope_binding.rule_matched  # never a fabricated binding
        assert datum.scope_binding.observed_at == NOW.isoformat()


def test_address_earns_its_own_verdict_and_is_dropped_when_not_in_scope(tmp_path, monkeypatch):
    """A hostname rule may never authorize a raw IP (scope.py refuses it)."""

    ctx, summary, _ = run(
        tmp_path, monkeypatch, [FakeNode("dns:api.epicgames.com")],
        {"api.epicgames.com": ("api.epicgames.com", [],
                               [IN_SCOPE_IP, OUT_OF_SCOPE_IP, PREFILTER_IP])},
    )

    assert ctx.graph.store.get(f"host:{IN_SCOPE_IP}") is not None
    assert ctx.graph.store.get(f"host:{OUT_OF_SCOPE_IP}") is None
    assert ctx.graph.store.get(f"host:{PREFILTER_IP}") is None  # not even capped
    assert summary["addresses_seen"] == 3 and summary["addresses_dropped"] == 2
    assert summary["dropped_by_verdict"] == {"out_of_scope": 1, "prefilter_only": 1}
    assert summary["resolves_to_edges"] == 1
    # the name itself still resolved and is still recorded
    assert ctx.graph.store.get("dns:api.epicgames.com") is not None


def test_name_with_no_in_scope_address_emits_the_name_only(tmp_path, monkeypatch):
    ctx, summary, _ = run(
        tmp_path, monkeypatch, [FakeNode("dns:api.epicgames.com")],
        {"api.epicgames.com": ("api.epicgames.com", [], [OUT_OF_SCOPE_IP])},
    )

    assert list(node_types(ctx)) == ["dns:api.epicgames.com"]
    assert ctx.graph.store.edges == {}
    assert summary["hosts_emitted"] == 0 and summary["resolved"] == 1


def test_malformed_addresses_are_dropped_not_minted(tmp_path, monkeypatch):
    ctx, summary, _ = run(
        tmp_path, monkeypatch, [FakeNode("dns:api.epicgames.com")],
        {"api.epicgames.com": ("api.epicgames.com", [],
                               ["not-an-ip", "", None, IN_SCOPE_IP, IN_SCOPE_IP])},
    )

    assert summary["addresses_seen"] == 1  # deduped, junk discarded
    assert list(ctx.graph.store.iter_type("Host"))[0].id == f"host:{IN_SCOPE_IP}"


# --- aliases / CNAME chain ------------------------------------------------------


def test_in_scope_alias_becomes_a_cname_edge(tmp_path, monkeypatch):
    ctx, summary, _ = run(
        tmp_path, monkeypatch, [FakeNode("dns:www.epicgames.com")],
        {"www.epicgames.com": ("cdn.epicgames.com", ["www.epicgames.com"], [IN_SCOPE_IP])},
    )

    assert "cname_to:dns:www.epicgames.com->dns:cdn.epicgames.com" in ctx.graph.store.edges
    alias = ctx.graph.store.get("dns:cdn.epicgames.com")
    assert alias.type == "DNSName"
    assert alias.confidence.log_odds == pytest.approx(resolver.ALIAS_LOG_ODDS)
    assert alias.coverage == {"enumerated": False}  # not itself resolved yet
    assert alias.attrs == {"active_probed": True}
    # the queried name is never its own alias
    assert "cname_to:dns:www.epicgames.com->dns:www.epicgames.com" not in ctx.graph.store.edges
    assert summary["cname_edges"] == 1 and summary["aliases_seen"] == 1
    assert summary["alias_names_emitted"] == 1 and summary["aliases_dropped"] == 0
    assert ctx.graph.store.get("dns:www.epicgames.com").attrs["cname_targets"] == \
        ["cdn.epicgames.com"]


def test_out_of_scope_alias_is_recorded_but_never_an_edge_or_a_node(tmp_path, monkeypatch):
    ctx, summary, _ = run(
        tmp_path, monkeypatch, [FakeNode("dns:store.epicgames.com")],
        {"store.epicgames.com": ("edge.thirdparty.net", [], [IN_SCOPE_IP])},
    )

    assert ctx.graph.store.get("dns:edge.thirdparty.net") is None
    assert not [e for e in ctx.graph.store.edges.values() if e.type == "cname_to"]
    assert summary["aliases_dropped"] == 1 and summary["cname_edges"] == 0
    assert summary["dropped_by_verdict"] == {"out_of_scope": 1}
    # kept as data about the in-scope name, so the takeover path can see it later
    assert ctx.graph.store.get("dns:store.epicgames.com").attrs["cname_targets"] == \
        ["edge.thirdparty.net"]


def test_alias_list_is_capped_and_canonical():
    assert resolver.alias_names(
        "www.epicgames.com", "CDN.EpicGames.com.",
        ["www.epicgames.com", "bad host", "*.epicgames.com", "a.epicgames.com"],
    ) == ["a.epicgames.com", "cdn.epicgames.com"]
    assert resolver.alias_names("a.epicgames.com", "a.epicgames.com", []) == []
    assert len(resolver.alias_names(
        "a.epicgames.com", "", [f"h{i}.epicgames.com" for i in range(50)],
    )) == resolver.MAX_ALIASES_PER_NAME


# --- hypothesis promotion -------------------------------------------------------


def seed_candidate(ctx, fqdn: str):
    """Put a passive dns-candidate Hypothesis in the graph and return the stored node."""

    node_id = f"{resolver.CANDIDATE_ID_PREFIX}{fqdn}"
    ctx.graph.upsert_node(make_node(
        "Hypothesis", node_id, binding=ctx.bind(fqdn), source="permutations", now=NOW,
        attrs={"candidate_fqdn": fqdn, "generator": "prefix"},
        log_odds=-1.0, coverage={"enumerated": False},
    ))
    return ctx.graph.store.get(node_id)


def test_resolving_candidate_promotes_it_and_corroborates_the_guess(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    candidate = seed_candidate(ctx, "dev.epicgames.com")
    install(monkeypatch, {"dev.epicgames.com": ("dev.epicgames.com", [], [IN_SCOPE_IP])})

    summary = resolver.ResolverModule(ctx).run([candidate])

    promoted = ctx.graph.store.get("dns:dev.epicgames.com")
    assert promoted is not None and promoted.type == "DNSName"
    assert promoted.confidence.log_odds == pytest.approx(2.0)
    assert promoted.attrs["active_probed"] is True
    assert promoted.coverage == {"enumerated": True}

    edge_id = f"corroborates:{candidate.id}->dns:dev.epicgames.com"
    edge = ctx.graph.store.edges[edge_id]
    assert edge.type == "corroborates" and edge.frm == candidate.id
    assert edge.scope_binding.verdict == Verdict.IN_SCOPE
    assert summary["promoted"] == 1 and summary["dns_emitted"] == 1

    # the guess itself is never rewritten: history forks, it does not mutate
    guess = ctx.graph.store.get(candidate.id)
    assert guess.confidence.log_odds == pytest.approx(-1.0)
    assert guess.type == "Hypothesis" and "active_probed" not in guess.attrs


def test_candidate_that_does_not_resolve_is_left_to_decay(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    candidate = seed_candidate(ctx, "qa.epicgames.com")
    before = dict(ctx.graph.store.nodes)
    install(monkeypatch, {})  # every lookup is NXDOMAIN

    summary = resolver.ResolverModule(ctx).run([candidate])

    assert list(ctx.graph.store.nodes) == list(before)  # nothing added
    assert ctx.graph.store.edges == {}
    assert ctx.graph.store.get(candidate.id).temporal.last_verified == NOW.isoformat()
    assert summary["nxdomain"] == 1 and summary["candidates_unconfirmed"] == 1
    assert summary["dangling_candidates"] == 0  # a guess never becomes a takeover lead


def test_candidate_not_in_the_graph_is_promoted_without_a_dangling_edge(tmp_path, monkeypatch):
    ctx, summary, _ = run(
        tmp_path, monkeypatch,
        [FakeNode(f"{resolver.CANDIDATE_ID_PREFIX}dev.epicgames.com", "Hypothesis",
                  {"candidate_fqdn": "dev.epicgames.com"})],
        {"dev.epicgames.com": ("dev.epicgames.com", [], [IN_SCOPE_IP])},
    )

    assert ctx.graph.store.get("dns:dev.epicgames.com") is not None
    assert not [e for e in ctx.graph.store.edges.values() if e.type == "corroborates"]
    assert summary["promoted"] == 0 and summary["resolved"] == 1


# --- dangling CNAME (subdomain-takeover candidate, detection only) --------------


def test_nxdomain_with_a_known_cname_edge_raises_a_takeover_candidate(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    binding = ctx.bind("legacy.epicgames.com")
    ctx.graph.upsert_node(make_node("DNSName", "dns:legacy.epicgames.com", binding=binding,
                                    source="crtsh", now=NOW, coverage={"enumerated": True}))
    ctx.graph.upsert_node(make_node("DNSName", "dns:cdn.epicgames.com",
                                    binding=ctx.bind("cdn.epicgames.com"),
                                    source="crtsh", now=NOW))
    ctx.graph.upsert_edge(make_edge("cname_to", "dns:legacy.epicgames.com",
                                    "dns:cdn.epicgames.com", binding=binding,
                                    source="resolver", now=NOW))
    install(monkeypatch, {})  # NXDOMAIN

    seed = ctx.graph.store.get("dns:legacy.epicgames.com")
    summary = resolver.ResolverModule(ctx).run([seed])

    hyp = ctx.graph.store.get("hyp:dangling-cname:legacy.epicgames.com")
    assert hyp is not None and hyp.type == "Hypothesis"
    assert hyp.attrs == {
        "dangling_fqdn": "legacy.epicgames.com",
        "cname_targets": ["cdn.epicgames.com"],
        "candidate_class": "subdomain-takeover",
        "detection_only": True,
        "active_probed": True,
    }
    assert hyp.confidence.log_odds == pytest.approx(resolver.DANGLING_LOG_ODDS)
    assert hyp.confidence.log_odds <= 0 and hyp.confidence.probability < 0.5
    assert hyp.coverage == {"enumerated": False}
    assert hyp.sensitivity == Sensitivity.S0 and hyp.data_subject == "none"
    assert hyp.scope_binding.verdict == Verdict.IN_SCOPE
    assert summary["dangling_candidates"] == 1 and summary["nxdomain"] == 1

    raised = [e.payload for e in ctx.graph.log.by_kind("hypothesis_raised")]
    assert len(raised) == 1
    assert raised[0]["id"] == hyp.id and raised[0]["detection_only"] is True
    assert raised[0]["module"] == "resolver"
    # detection only: no edge toward the (possibly third-party) target, nothing claimed
    assert not [e for e in ctx.graph.store.edges.values() if e.frm == hyp.id or e.to == hyp.id]
    assert ctx.graph.store.get("dns:legacy.epicgames.com").attrs.get("nxdomain") is None


def test_takeover_candidate_is_logged_as_detection_only(tmp_path, monkeypatch, caplog):
    caplog.set_level(logging.WARNING, logger="recon.test.resolver")
    ctx, summary, _ = run(
        tmp_path, monkeypatch,
        [FakeNode("dns:legacy.epicgames.com", attrs={"cname_target": "bucket.thirdparty.net"})],
        {},
    )

    assert summary["dangling_candidates"] == 1
    text = caplog.text
    assert "CANDIDATE" in text and "not claimed" in text
    assert "bucket.thirdparty.net" in text


def test_dangling_candidate_takes_its_alias_from_the_seed_attrs(tmp_path, monkeypatch):
    """The out-of-scope CNAME target recorded earlier is still enough to detect this."""

    ctx, summary, _ = run(
        tmp_path, monkeypatch,
        [FakeNode("dns:store.epicgames.com",
                  attrs={"cname_targets": ["edge.thirdparty.net", "bad host"]})],
        {},
    )

    hyp = ctx.graph.store.get("hyp:dangling-cname:store.epicgames.com")
    assert hyp.attrs["cname_targets"] == ["edge.thirdparty.net"]  # junk filtered out
    assert summary["dangling_candidates"] == 1


def test_nxdomain_without_any_known_cname_writes_nothing(tmp_path, monkeypatch):
    ctx, summary, _ = run(tmp_path, monkeypatch, [FakeNode("dns:gone.epicgames.com")], {})

    assert ctx.graph.store.nodes == {} and ctx.graph.store.edges == {}
    assert summary["nxdomain"] == 1 and summary["nxdomain_without_cname"] == 1
    assert summary["dangling_candidates"] == 0


def test_a_live_name_never_raises_a_takeover_candidate(tmp_path, monkeypatch):
    ctx, summary, _ = run(
        tmp_path, monkeypatch,
        [FakeNode("dns:legacy.epicgames.com", attrs={"cname_target": "cdn.epicgames.com"})],
        {"legacy.epicgames.com": ("cdn.epicgames.com", [], [IN_SCOPE_IP])},
    )

    assert ctx.graph.store.get("hyp:dangling-cname:legacy.epicgames.com") is None
    assert summary["dangling_candidates"] == 0 and summary["resolved"] == 1


# --- failure classification -----------------------------------------------------


def test_no_address_is_not_treated_as_a_vanished_name(tmp_path, monkeypatch):
    """An AAAA-only host must not mint a takeover candidate (this lookup is IPv4-only)."""

    ctx, summary, _ = run(
        tmp_path, monkeypatch,
        [FakeNode("dns:v6.epicgames.com", attrs={"cname_target": "cdn.epicgames.com"})],
        {"v6.epicgames.com": no_data()},
    )

    assert summary["no_address"] == 1 and summary["nxdomain"] == 0
    assert summary["dangling_candidates"] == 0
    assert ctx.graph.store.nodes == {}


def test_temporary_resolver_failure_is_an_error_not_an_nxdomain(tmp_path, monkeypatch):
    ctx, summary, _ = run(
        tmp_path, monkeypatch,
        [FakeNode("dns:legacy.epicgames.com", attrs={"cname_target": "cdn.epicgames.com"})],
        {"legacy.epicgames.com": again()},
    )

    assert summary["errors"] == 1 and summary["nxdomain"] == 0
    assert summary["dangling_candidates"] == 0
    assert list(summary["errors_by_kind"])[0].startswith("error:gaierror:")
    assert ctx.graph.store.nodes == {}


@pytest.mark.parametrize("exc", [
    OSError("resolver socket closed"),
    TimeoutError("resolver timed out"),
    UnicodeError("bad label"),
    RuntimeError("exotic resolver stack"),
])
def test_network_errors_log_and_continue_without_crashing(tmp_path, monkeypatch, exc):
    ctx, summary, calls = run(
        tmp_path, monkeypatch,
        [FakeNode("dns:broken.epicgames.com"), FakeNode("dns:api.epicgames.com")],
        {"broken.epicgames.com": exc,
         "api.epicgames.com": ("api.epicgames.com", [], [IN_SCOPE_IP])},
    )

    assert calls == ["broken.epicgames.com", "api.epicgames.com"]
    assert summary["errors"] == 1 and summary["resolved"] == 1
    assert ctx.graph.store.get(f"host:{IN_SCOPE_IP}") is not None


def test_gaierror_outcome_classification():
    assert resolver.gaierror_outcome(nx()) == "nxdomain"
    assert resolver.gaierror_outcome(no_data()) == "no_address"
    assert resolver.gaierror_outcome(again()).startswith("error:gaierror:")
    assert resolver.gaierror_outcome(socket.gaierror("no errno at all")).startswith("error:")


def test_unwritable_evidence_store_does_not_crash_the_run(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    install(monkeypatch, {"api.epicgames.com": ("api.epicgames.com", [], [IN_SCOPE_IP])})

    def boom(*args, **kwargs):
        raise OSError("read-only evidence store")

    monkeypatch.setattr(ctx.evidence, "put_text", boom)
    summary = resolver.ResolverModule(ctx).run([FakeNode("dns:api.epicgames.com")])

    assert summary["resolved"] == 1 and summary["hosts_emitted"] == 1
    assert all(n.evidence == [] for n in ctx.graph.store.nodes.values())


# --- evidence ------------------------------------------------------------------


def test_answer_is_content_addressed_and_replayable(tmp_path, monkeypatch):
    ctx, _, _ = run(
        tmp_path, monkeypatch, [FakeNode("dns:www.epicgames.com")],
        {"www.epicgames.com": ("cdn.epicgames.com", ["www.epicgames.com"],
                               [OTHER_IN_SCOPE_IP, IN_SCOPE_IP])},
    )

    dns = ctx.graph.store.get("dns:www.epicgames.com")
    ref = dns.evidence[0]
    assert ref.region == "resolver:www.epicgames.com"
    assert ref.encrypted_at_rest
    assert dns.provenance.chain[0].evidence_id == ref.sha256

    record = ctx.evidence.get(ref.sha256).decode("utf-8")
    assert record.splitlines() == [
        f"resolver/{resolver.RULE_VERSION} verb=resolve",
        "query=www.epicgames.com",
        "result=OK",
        "canonical=cdn.epicgames.com",
        "aliases=cdn.epicgames.com",
        f"addresses={IN_SCOPE_IP},{OTHER_IN_SCOPE_IP}",  # canonical order, not answer order
    ]
    assert sha256_bytes(record.encode("utf-8")) == ref.sha256
    # every datum derived from one answer points at that one blob
    assert {n.evidence[0].sha256 for n in ctx.graph.store.nodes.values()} == {ref.sha256}


def test_nxdomain_evidence_records_the_negative_answer(tmp_path, monkeypatch):
    ctx, _, _ = run(
        tmp_path, monkeypatch,
        [FakeNode("dns:legacy.epicgames.com", attrs={"cname_target": "cdn.epicgames.com"})],
        {},
    )

    hyp = ctx.graph.store.get("hyp:dangling-cname:legacy.epicgames.com")
    record = ctx.evidence.get(hyp.evidence[0].sha256).decode("utf-8")
    assert "result=NXDOMAIN" in record
    assert "known_cname_targets=cdn.epicgames.com" in record


def test_identical_answers_in_different_order_are_byte_identical(tmp_path, monkeypatch):
    seeds = [FakeNode("dns:api.epicgames.com")]
    ctx_a, summary_a, _ = run(
        tmp_path / "a", monkeypatch, seeds,
        {"api.epicgames.com": ("api.epicgames.com", [], [IN_SCOPE_IP, OTHER_IN_SCOPE_IP])},
    )
    ctx_b, summary_b, _ = run(
        tmp_path / "b", monkeypatch, seeds,
        {"api.epicgames.com": ("api.epicgames.com", [], [OTHER_IN_SCOPE_IP, IN_SCOPE_IP])},
    )

    assert list(ctx_a.graph.store.nodes) == list(ctx_b.graph.store.nodes)
    assert list(ctx_a.graph.store.edges) == list(ctx_b.graph.store.edges)
    assert summary_a == summary_b
    sha_a = ctx_a.graph.store.get("dns:api.epicgames.com").evidence[0].sha256
    sha_b = ctx_b.graph.store.get("dns:api.epicgames.com").evidence[0].sha256
    assert sha_a == sha_b


# --- ontology / invariants ------------------------------------------------------


def test_only_declared_ontology_types_are_emitted(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    candidate = seed_candidate(ctx, "dev.epicgames.com")
    install(monkeypatch, {
        "dev.epicgames.com": ("cdn.epicgames.com", [], [IN_SCOPE_IP]),
        "legacy.epicgames.com": nx(),
    })

    resolver.ResolverModule(ctx).run([
        candidate,
        FakeNode("dns:legacy.epicgames.com", attrs={"cname_target": "old.thirdparty.net"}),
    ])

    assert ctx.graph.store.nodes and ctx.graph.store.edges
    for node in ctx.graph.store.nodes.values():
        assert node.type in ontology.node_types()
    for edge in ctx.graph.store.edges.values():
        assert edge.type in ontology.edge_types()
        assert edge.type not in ontology.proposed_edges()
    assert {e.type for e in ctx.graph.store.edges.values()} <= {
        "resolves_to", "cname_to", "corroborates",
    }


def test_no_edge_endpoint_is_missing_or_out_of_scope(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    candidate = seed_candidate(ctx, "dev.epicgames.com")
    install(monkeypatch, {"dev.epicgames.com": ("cdn.epicgames.com", [],
                                                [IN_SCOPE_IP, OUT_OF_SCOPE_IP])})

    resolver.ResolverModule(ctx).run([candidate])

    assert ctx.graph.store.edges
    for edge in ctx.graph.store.edges.values():
        for endpoint in (edge.frm, edge.to):
            node = ctx.graph.store.get(endpoint)
            assert node is not None, f"edge {edge.id} points at a missing node"
            assert node.scope_binding.verdict == Verdict.IN_SCOPE
            assert node.data_subject != "other"


def test_graph_satisfies_the_safety_invariants(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    candidate = seed_candidate(ctx, "dev.epicgames.com")
    install(monkeypatch, {
        "dev.epicgames.com": ("cdn.epicgames.com", [], [IN_SCOPE_IP, OUT_OF_SCOPE_IP]),
        "api.epicgames.com": ("api.epicgames.com", [], [OTHER_IN_SCOPE_IP]),
    })

    resolver.ResolverModule(ctx).run([
        candidate,
        FakeNode("dns:api.epicgames.com"),
        FakeNode("dns:admin.epicgames.com"),  # refused
        FakeNode("dns:legacy.epicgames.com", attrs={"cname_target": "old.thirdparty.net"}),
    ])

    assert ctx.graph.store.nodes
    assert invariants.check(ctx.graph.store, ledger=ctx.ledger,
                            current_snapshot=ctx.snapshot.snapshot_id) == []
    assert not any(n.sensitivity != Sensitivity.S0 for n in ctx.graph.store.nodes.values())
    assert not any(n.type in ("Credential", "Token") for n in ctx.graph.store.nodes.values())


def test_rerun_merges_without_forking(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    answers = {"api.epicgames.com": ("api.epicgames.com", [], [IN_SCOPE_IP])}
    install(monkeypatch, answers)
    module = resolver.ResolverModule(ctx)

    first = module.run([FakeNode("dns:api.epicgames.com")])
    ids_after_first = set(ctx.graph.store.nodes)
    second = module.run([FakeNode("dns:api.epicgames.com")])

    assert first["resolved"] == second["resolved"] == 1
    assert set(ctx.graph.store.nodes) == ids_after_first
    assert not any("#fork" in node_id for node_id in ctx.graph.store.nodes)
    assert not any("#fork" in edge_id for edge_id in ctx.graph.store.edges)
    assert len(ctx.ledger.log) == 2  # each run pays for its own lookup


# --- defensiveness --------------------------------------------------------------


@pytest.mark.parametrize("seeds", [[], None, ["", "   ", None, 42, object()]])
def test_empty_and_junk_seeds_are_graceful(tmp_path, monkeypatch, seeds):
    ctx, summary, calls = run(tmp_path, monkeypatch, seeds, {})

    assert calls == [] and ctx.ledger.log == []
    assert ctx.graph.store.nodes == {}
    assert summary["seeds_used"] == 0 and summary["gated"] == 0


def test_unsupported_seed_kinds_are_ignored(tmp_path, monkeypatch):
    seeds = [
        FakeNode("domain:epicgames.com", "Domain"),
        FakeNode("host:203.0.113.5", "Host"),
        FakeNode("web:https://api.epicgames.com", "WebApp"),
        FakeNode("hyp:dangling-cname:legacy.epicgames.com", "Hypothesis"),
        FakeNode("dns:203.0.113.5"),       # an IP is not a resolvable name
        FakeNode("dns:epicgames"),         # not a dotted fqdn
        FakeNode("dns:*.epicgames.com"),   # a wildcard root normalizes to its apex
    ]
    ctx, summary, calls = run(
        tmp_path, monkeypatch, seeds,
        {"epicgames.com": ("epicgames.com", [], [IN_SCOPE_IP])},
    )

    assert calls == ["epicgames.com"]  # only the wildcard root's apex survives
    assert summary["seeds_in"] == 7 and summary["seeds_used"] == 1
    assert summary["seeds_skipped"] == 6


def test_duplicate_names_are_resolved_once(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    candidate = seed_candidate(ctx, "api.epicgames.com")
    calls = install(monkeypatch, {"api.epicgames.com": ("api.epicgames.com", [],
                                                        [IN_SCOPE_IP])})

    summary = resolver.ResolverModule(ctx).run([
        FakeNode("dns:api.epicgames.com"), candidate, "api.epicgames.com",
        FakeNode("dns:API.EpicGames.com."),
    ])

    assert calls == ["api.epicgames.com"]  # one gate, one debit, one lookup
    assert summary["seeds_deduped"] == 3 and len(ctx.ledger.log) == 1


def test_seed_list_is_capped_to_bound_active_spend(tmp_path, monkeypatch):
    monkeypatch.setattr(resolver, "MAX_SEED_NODES", 2)
    ctx, summary, calls = run(
        tmp_path, monkeypatch,
        [FakeNode(f"dns:h{i}.epicgames.com") for i in range(6)],
        {f"h{i}.epicgames.com": (f"h{i}.epicgames.com", [], [IN_SCOPE_IP]) for i in range(6)},
    )

    assert calls == ["h0.epicgames.com", "h1.epicgames.com"]
    assert summary["seeds_used"] == 2 and summary["seeds_truncated"] is True
    assert len(ctx.ledger.log) == 2


def test_plain_string_seed_is_tolerated(tmp_path, monkeypatch):
    ctx, summary, calls = run(
        tmp_path, monkeypatch, ["api.epicgames.com"],
        {"api.epicgames.com": ("api.epicgames.com", [], [IN_SCOPE_IP])},
    )

    assert calls == ["api.epicgames.com"] and summary["resolved"] == 1
    assert summary["promoted"] == 0


def test_valid_fqdn_and_address_helpers_reject_junk():
    assert resolver.valid_fqdn("api.epicgames.com")
    assert resolver.valid_fqdn("xn--tst-6la.epicgames.com")
    assert not resolver.valid_fqdn("")
    assert not resolver.valid_fqdn("epicgames")
    assert not resolver.valid_fqdn("*.epicgames.com")
    assert not resolver.valid_fqdn("a b.epicgames.com")
    assert not resolver.valid_fqdn(IN_SCOPE_IP)
    assert not resolver.valid_fqdn("x" * 64 + ".epicgames.com")

    assert resolver.canonical_addresses(["203.0.113.9", "203.0.113.9", "203.0.113.1"]) == \
        ["203.0.113.1", "203.0.113.9"]
    assert resolver.canonical_addresses(None) == []
    assert resolver.canonical_addresses(["nope", {}, "::1"]) == ["::1"]
    assert len(resolver.canonical_addresses([f"203.0.113.{i}" for i in range(1, 60)])) == \
        resolver.MAX_ADDRESSES_PER_NAME


def test_planner_schedules_this_module_for_the_gaps_it_closes(tmp_path, monkeypatch):
    """The resolver is what the planner's active rungs name, and it closes them."""

    from recon import planner

    ctx = make_ctx(tmp_path)
    candidate = seed_candidate(ctx, "dev.epicgames.com")
    ctx.graph.upsert_node(make_node("DNSName", "dns:api.epicgames.com",
                                    binding=ctx.bind("api.epicgames.com"),
                                    source="crtsh", now=NOW, coverage={"enumerated": True}))

    gaps = planner.plan(ctx.graph.store, NOW, allow_active=True)
    resolve_gaps = [g for g in gaps if g.module == "resolver"]
    assert {g.verb for g in resolve_gaps} == {"resolve"}
    assert {g.node_id for g in resolve_gaps} == {candidate.id, "dns:api.epicgames.com"}
    assert all(not g.passive and not g.human_gated for g in resolve_gaps)

    install(monkeypatch, {
        "dev.epicgames.com": ("dev.epicgames.com", [], [IN_SCOPE_IP]),
        "api.epicgames.com": ("api.epicgames.com", [], [OTHER_IN_SCOPE_IP]),
    })
    seeds = [s for g in resolve_gaps for s in planner.seeds_for(g, ctx.graph.store)]
    summary = resolver.ResolverModule(ctx).run(seeds)

    assert summary["resolved"] == 2 and summary["promoted"] == 1
    # the resolve-name gap is closed: the name now has a resolves_to edge
    assert ctx.graph.store.has_out_edge("dns:api.epicgames.com", "resolves_to")
    assert not [g for g in planner.plan(ctx.graph.store, NOW, allow_active=True)
                if g.id.startswith("resolve-name:dns:api.epicgames.com")]
