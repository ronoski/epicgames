"""Offline tests for the ``seeds`` entry module.

Every test is deterministic (a fixed ``now``) and 100% offline: the ``no_network`` autouse
fixture makes any socket/ssl/requests use raise, so a regression that adds a network touch
to this passive module fails here instead of reaching a live Epic host.
"""

import ipaddress
import logging
import socket
import ssl
from datetime import datetime, timedelta, timezone

import pytest

from recon import invariants, ontology
from recon.events import EventLog
from recon.evidence import EvidenceStore
from recon.models import Sensitivity, Verdict
from recon.modules import base
from recon.modules.base import ModuleContext
from recon.modules.passive.seeds import MAX_SEEDS, SeedsModule, parse_seed
from recon.ratelimit import RateLedger
from recon.scope import Scope
from recon.snapshot import take_snapshot
from recon.store import Graph

NOW = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)
INCLUDE = ["*.epicgames.com", "*.fortnite.com", "203.0.113.0/24"]


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Fail loudly on any network attempt — this module must stay network-free."""

    def boom(*args, **kwargs):  # pragma: no cover - only runs on a violation
        raise AssertionError("network access attempted in an offline test")

    monkeypatch.setattr(socket, "socket", boom)
    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    monkeypatch.setattr(socket, "gethostbyname", boom, raising=False)
    monkeypatch.setattr(ssl, "create_default_context", boom)
    requests = pytest.importorskip("requests")
    monkeypatch.setattr(requests, "request", boom, raising=False)
    monkeypatch.setattr(requests, "get", boom, raising=False)
    monkeypatch.setattr(requests.Session, "request", boom, raising=False)


def make_ctx(tmp_path, *, include=None, exclude=None, prefilter=None,
             snapshot="fresh", now=NOW, allow_active=False):
    scope = Scope(
        include=list(include if include is not None else INCLUDE),
        exclude=list(exclude or []),
        prefilter=list(prefilter or []),
    )
    if snapshot == "fresh":
        snap = take_snapshot("POLICY TEXT", now=now, half_life="PT24H")
    elif snapshot == "stale":
        snap = take_snapshot("POLICY TEXT", now=now - timedelta(days=3), half_life="PT24H")
    else:
        snap = snapshot
    return ModuleContext(
        scope=scope,
        ledger=RateLedger(global_qps=2.0, capacity=4.0, clock=lambda: 0.0),
        evidence=EvidenceStore(tmp_path / "evidence"),
        graph=Graph(log=EventLog()),
        snapshot=snap,
        logger=logging.getLogger("recon.test"),
        allow_active=allow_active,
        now=now,
    )


def run_seeds(tmp_path, seeds, **kw):
    ctx = make_ctx(tmp_path, **kw)
    return ctx, SeedsModule(ctx).run(seeds)


# --- registration / shape -------------------------------------------------

def test_module_is_registered_and_passive():
    assert base.get_module("seeds") is SeedsModule
    assert SeedsModule.name == "seeds"
    assert SeedsModule.active is False
    assert set(SeedsModule.produces) <= ontology.node_types()


def test_summary_reports_every_verdict(tmp_path):
    _, summary = run_seeds(tmp_path, ["api.epicgames.com"])
    assert set(summary["verdicts"]) == {v.value for v in Verdict}
    assert summary["verdicts"]["in_scope"] == 1
    assert summary["seeds_in"] == 1 and summary["unique_seeds"] == 1


# --- hostname seeds -------------------------------------------------------

def test_hostname_seed_emits_domain_and_dnsname(tmp_path):
    ctx, summary = run_seeds(tmp_path, ["api.epicgames.com"])
    nodes = ctx.graph.store.nodes
    assert set(nodes) == {"dns:api.epicgames.com", "domain:epicgames.com"}
    dns = nodes["dns:api.epicgames.com"]
    assert dns.type == "DNSName"
    assert dns.attrs["fqdn"] == "api.epicgames.com"
    assert dns.attrs["registrable"] == "epicgames.com"
    assert dns.scope_binding.verdict == Verdict.IN_SCOPE
    assert dns.scope_binding.snapshot_id == ctx.snapshot.snapshot_id
    assert dns.sensitivity == Sensitivity.S0 and dns.data_subject == "none"
    assert summary["nodes"] == {"Domain": 1, "DNSName": 1, "Host": 0, "NetBlock": 0}


def test_fresh_seed_is_known_but_not_enumerated(tmp_path):
    ctx, _ = run_seeds(tmp_path, ["api.epicgames.com"])
    for node in ctx.graph.store.nodes.values():
        assert node.coverage == {"enumerated": False}
        assert node.confidence.log_odds <= 0.0  # declared, not resolution-verified


def test_no_node_claims_an_active_probe(tmp_path):
    ctx, _ = run_seeds(tmp_path, ["api.epicgames.com", "203.0.113.5"])
    assert all("active_probed" not in n.attrs for n in ctx.graph.store.nodes.values())


def test_wildcard_seed_takes_the_apex_only(tmp_path):
    ctx, summary = run_seeds(tmp_path, ["*.epicgames.com"])
    assert set(ctx.graph.store.nodes) == {"dns:epicgames.com", "domain:epicgames.com"}
    assert all("*" not in node_id for node_id in ctx.graph.store.nodes)
    assert ctx.graph.store.nodes["dns:epicgames.com"].attrs["wildcard_seed"] is True
    assert summary["verdicts"]["in_scope"] == 1


def test_seed_spellings_are_canonicalized_and_deduped(tmp_path):
    ctx, summary = run_seeds(tmp_path, [
        "*.epicgames.com", "epicgames.com", "EPICGAMES.COM.",
        "https://epicgames.com/launcher", "epicgames.com:443",
    ])
    assert summary["unique_seeds"] == 1
    assert set(ctx.graph.store.nodes) == {"dns:epicgames.com", "domain:epicgames.com"}
    # One source, one run: no self-corroboration and no spurious contradiction fork.
    dns = ctx.graph.store.nodes["dns:epicgames.com"]
    assert dns.confidence.independent_sources == 1
    assert dns.confidence.log_odds == 0.0
    assert not any("#fork" in node_id for node_id in ctx.graph.store.nodes)


def test_shared_apex_is_emitted_once(tmp_path):
    ctx, summary = run_seeds(tmp_path, ["api.epicgames.com", "store.epicgames.com"])
    assert summary["nodes"]["Domain"] == 1
    assert summary["deduped"] == 1
    assert ctx.graph.store.nodes["domain:epicgames.com"].confidence.independent_sources == 1


def test_apex_earns_its_own_verdict(tmp_path):
    """An exact-host include does not authorize the registrable domain (default deny)."""

    ctx, summary = run_seeds(tmp_path, ["api.epicgames.com"],
                             include=["api.epicgames.com"])
    assert set(ctx.graph.store.nodes) == {"dns:api.epicgames.com"}
    assert summary["domains_skipped"] == 1


# --- ip / cidr seeds ------------------------------------------------------

def test_ip_seed_emits_host(tmp_path):
    ctx, summary = run_seeds(tmp_path, ["203.0.113.5"])
    node = ctx.graph.store.nodes["host:203.0.113.5"]
    assert node.type == "Host"
    assert node.attrs == {"seed_origin": "config.targets", "ip": "203.0.113.5",
                          "ip_version": 4}
    assert summary["nodes"]["Host"] == 1 and summary["nodes"]["Domain"] == 0


def test_cidr_seed_emits_netblock(tmp_path):
    ctx, summary = run_seeds(tmp_path, ["203.0.113.0/24"])
    node = ctx.graph.store.nodes["net:203.0.113.0/24"]
    assert node.type == "NetBlock"
    assert node.attrs["cidr"] == "203.0.113.0/24" and node.attrs["prefixlen"] == 24
    assert summary["nodes"]["NetBlock"] == 1


def test_ip_seed_outside_cidr_include_is_dropped(tmp_path):
    ctx, summary = run_seeds(tmp_path, ["198.51.100.7"])
    assert ctx.graph.store.nodes == {}
    assert summary["verdicts"]["out_of_scope"] == 1


# --- verdict handling -----------------------------------------------------

def test_out_of_scope_seed_is_skipped_with_a_log_line(tmp_path, caplog):
    caplog.set_level(logging.INFO, logger="recon.test")
    ctx, summary = run_seeds(tmp_path, ["bandcamp.com", "fhir.epic.com",
                                        "secure.epicgames.com"],
                             exclude=["secure.epicgames.com"])
    assert ctx.graph.store.nodes == {}
    assert summary["verdicts"]["out_of_scope"] == 3
    assert summary["emitted"] == 0
    text = caplog.text
    for value in ("bandcamp.com", "fhir.epic.com", "secure.epicgames.com"):
        assert value in text


def test_adjudication_pending_seed_is_skipped(tmp_path, caplog):
    caplog.set_level(logging.INFO, logger="recon.test")
    ctx, summary = run_seeds(tmp_path, ["dev.epicgames.com"],
                             include=["dev.epicgames.com"],
                             exclude=["dev.epicgames.com"])
    assert ctx.graph.store.nodes == {}
    assert summary["verdicts"]["adjudication_pending"] == 1
    assert "adjudication_pending" in caplog.text


def test_prefilter_only_seed_is_capped_at_enumerated(tmp_path):
    ctx, summary = run_seeds(tmp_path, ["internal.epicgames.com"],
                             include=["*.fortnite.com"],
                             prefilter=["*.epicgames.com"])
    assert summary["verdicts"]["prefilter_only"] == 1
    assert set(ctx.graph.store.nodes) == {"dns:internal.epicgames.com",
                                          "domain:epicgames.com"}
    for node in ctx.graph.store.nodes.values():
        assert node.scope_binding.verdict == Verdict.PREFILTER_ONLY
        assert node.coverage == {"enumerated": True}  # capped, nothing else
        assert "active_probed" not in node.attrs


def test_every_binding_is_recorded_as_an_event(tmp_path):
    ctx, _ = run_seeds(tmp_path, ["api.epicgames.com", "example.org"])
    bound = [e.payload for e in ctx.graph.log.by_kind("scope_binding_set")]
    assert {b["value"]: b["verdict"] for b in bound} == {
        "api.epicgames.com": "in_scope", "example.org": "out_of_scope",
    }
    assert all(b["snapshot_id"] == ctx.snapshot.snapshot_id for b in bound)


# --- snapshot gating (I1 / I12) ------------------------------------------

def test_missing_snapshot_blocks_all_retention(tmp_path):
    ctx, summary = run_seeds(tmp_path, ["api.epicgames.com"], snapshot=None)
    assert ctx.graph.store.nodes == {}
    assert "no scope snapshot" in summary["blocked"]
    assert summary["emitted"] == 0


def test_stale_snapshot_blocks_all_retention(tmp_path):
    ctx, summary = run_seeds(tmp_path, ["api.epicgames.com"], snapshot="stale")
    assert ctx.graph.store.nodes == {}
    assert "stale" in summary["blocked"]


# --- passivity ------------------------------------------------------------

def test_module_never_gates_or_debits(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path, allow_active=True)

    def boom(*args, **kwargs):  # pragma: no cover - only runs on a violation
        raise AssertionError("a passive module must not call gate_active")

    monkeypatch.setattr(ctx, "gate_active", boom)
    monkeypatch.setattr(ctx.ledger, "debit", boom)
    SeedsModule(ctx).run(["api.epicgames.com", "203.0.113.5", "203.0.113.0/24"])
    assert ctx.ledger.log == []
    assert ctx.ledger.balance("epicgames.com") == ctx.ledger.capacity
    assert list(ctx.graph.log.by_kind("gate_decision_recorded")) == []
    assert list(ctx.graph.log.by_kind("rate_debit")) == []


# --- defensiveness --------------------------------------------------------

def test_empty_seed_list_is_tolerated(tmp_path):
    ctx, summary = run_seeds(tmp_path, [])
    assert ctx.graph.store.nodes == {}
    assert summary["seeds_in"] == 0 and summary["unique_seeds"] == 0
    assert summary["verdicts"]["in_scope"] == 0
    ctx2, summary2 = run_seeds(tmp_path, None)
    assert summary2["seeds_in"] == 0 and ctx2.graph.store.nodes == {}


@pytest.mark.parametrize("raw", [
    "", "   ", "#  commented-out.epicgames.com", "not a hostname", "localhost",
    "1.2.3", "*.", "*", "http://", "..epicgames.com", "999.999.999.999/24",
])
def test_unparsable_seeds_are_ignored(tmp_path, raw):
    ctx, summary = run_seeds(tmp_path, [raw])
    assert ctx.graph.store.nodes == {}
    assert summary["unparsable"] == 1
    assert summary["unique_seeds"] == 0


def test_non_string_seeds_are_tolerated(tmp_path):
    class FakeNode:
        id = "dns:api.epicgames.com"
        attrs = {"fqdn": "api.epicgames.com"}

    ctx, summary = run_seeds(tmp_path, [FakeNode(), 7, None])
    assert "dns:api.epicgames.com" in ctx.graph.store.nodes
    assert summary["unparsable"] == 2


def test_seed_list_is_truncated_at_the_cap(tmp_path):
    seeds = [f"h{i}.epicgames.com" for i in range(MAX_SEEDS + 5)]
    ctx, summary = run_seeds(tmp_path, seeds)
    assert summary["truncated"] is True
    assert summary["unique_seeds"] == MAX_SEEDS
    assert len(list(ctx.graph.store.iter_type("DNSName"))) == MAX_SEEDS


def test_unwritable_evidence_store_does_not_crash_the_run(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)

    def boom(*args, **kwargs):
        raise OSError("read-only evidence store")

    monkeypatch.setattr(ctx.evidence, "put_text", boom)
    summary = SeedsModule(ctx).run(["api.epicgames.com"])
    assert summary["emitted"] == 2
    assert ctx.graph.store.nodes["dns:api.epicgames.com"].evidence == []


def test_idn_seed_is_punycoded(tmp_path):
    ctx, _ = run_seeds(tmp_path, ["tést.epicgames.com"])
    assert "dns:xn--tst-bma.epicgames.com" in ctx.graph.store.nodes


def test_parse_seed_is_pure_and_deterministic():
    assert parse_seed("*.EpicGames.com ").value == "epicgames.com"
    assert parse_seed("*.EpicGames.com ").wildcard is True
    assert parse_seed("203.0.113.0/24").kind == "net"
    assert parse_seed("203.0.113.5").kind == "ip"
    assert parse_seed("api.epicgames.com").kind == "host"
    assert parse_seed("garbage value") is None


# --- graph / ontology / invariants ---------------------------------------

def test_emits_declared_node_types_and_no_edges(tmp_path):
    ctx, _ = run_seeds(tmp_path, ["*.epicgames.com", "api.fortnite.com",
                                  "203.0.113.5", "203.0.113.0/24"])
    assert ctx.graph.store.edges == {}
    for node in ctx.graph.store.nodes.values():
        assert node.type in ontology.node_types()
        assert node.type in SeedsModule.produces


def test_graph_passes_the_safety_invariants(tmp_path):
    ctx, _ = run_seeds(tmp_path, ["*.epicgames.com", "internal.epicgames.com",
                                  "203.0.113.5", "example.org"],
                       prefilter=["*.epicgames.com"])
    violations = invariants.check(ctx.graph.store, ledger=ctx.ledger,
                                  current_snapshot=ctx.snapshot.snapshot_id)
    assert violations == []


def test_evidence_is_content_addressed_and_replayable(tmp_path):
    ctx, _ = run_seeds(tmp_path, ["*.epicgames.com"])
    node = ctx.graph.store.nodes["dns:epicgames.com"]
    assert len(node.evidence) == 1
    ref = node.evidence[0]
    assert ref.region == "config.targets" and ref.encrypted_at_rest
    assert ctx.evidence.get(ref.sha256) == b"*.epicgames.com"


def test_rerun_merges_without_forking(tmp_path):
    """A second run over the same config must dedupe, not fork (contradiction-free)."""

    ctx = make_ctx(tmp_path)
    SeedsModule(ctx).run(["*.epicgames.com"])
    later = NOW + timedelta(hours=1)
    ctx.now = later
    ctx.snapshot = take_snapshot("POLICY TEXT", now=later, half_life="PT24H")
    SeedsModule(ctx).run(["epicgames.com"])  # bare apex this time, no wildcard spelling
    assert set(ctx.graph.store.nodes) == {"dns:epicgames.com", "domain:epicgames.com"}
    node = ctx.graph.store.nodes["dns:epicgames.com"]
    assert node.attrs["wildcard_seed"] is True  # history preserved
    assert node.temporal.last_verified == later.isoformat()
    assert node.coverage == {"enumerated": False}  # still not enumerated


def test_node_ids_follow_the_conventions(tmp_path):
    ctx, _ = run_seeds(tmp_path, ["api.epicgames.com", "203.0.113.5", "203.0.113.0/24"])
    ids = set(ctx.graph.store.nodes)
    assert ids == {
        "dns:api.epicgames.com", "domain:epicgames.com",
        "host:203.0.113.5", "net:203.0.113.0/24",
    }
    net = ipaddress.ip_network("203.0.113.0/24")
    assert ctx.graph.store.nodes[f"net:{net}"].attrs["ip_version"] == 4
