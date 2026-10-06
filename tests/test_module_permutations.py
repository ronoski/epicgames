"""Offline, deterministic tests for the passive ``permutations`` module.

This module must never touch a network, so the guard here is doubled: an autouse fixture
makes ``socket``/``ssl``/``requests`` raise on any use, and the module's own source is
checked for network imports. Time is injected via ``ModuleContext.now`` so every envelope
timestamp is fixed, and candidate generation is asserted to be byte-identical across runs.
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
from recon.models import Sensitivity, Verdict
from recon.modules.base import ModuleContext, get_module
from recon.modules.passive import permutations
from recon.ratelimit import RateLedger
from recon.scope import Scope
from recon.snapshot import take_snapshot
from recon.store import Graph

NOW = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)

INCLUDE = ["*.epicgames.com", "*.fortnite.com"]
EXCLUDE = ["admin.epicgames.com", "secure.epicgames.com"]
PREFILTER = ["*.epicgames.dev"]

WORDS = permutations.PREFIX_WORDS


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
    monkeypatch.setattr(ssl, "create_default_context", boom)
    requests = pytest.importorskip("requests")
    monkeypatch.setattr(requests, "get", boom, raising=False)
    monkeypatch.setattr(requests, "request", boom, raising=False)
    monkeypatch.setattr(requests.Session, "request", boom, raising=False)


class FakeNode:
    """Minimal stand-in for a graph Node seed (only ``id``/``type`` are read)."""

    def __init__(self, id: str, type: str = "DNSName") -> None:
        self.id = id
        self.type = type


def make_ctx(tmp_path, *, include=None, exclude=None, prefilter=None,
             snapshot="fresh", now=NOW, allow_active=False) -> ModuleContext:
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
        ledger=RateLedger(global_qps=2.0, capacity=4.0, clock=lambda: 0.0),
        evidence=EvidenceStore(tmp_path / "evidence"),
        graph=Graph(log=EventLog()),
        snapshot=snap,
        logger=logging.getLogger("recon.test.permutations"),
        allow_active=allow_active,
        now=now,
    )


def run(tmp_path, seeds, **kw):
    ctx = make_ctx(tmp_path, **kw)
    return ctx, permutations.PermutationsModule(ctx).run(seeds)


def candidate_ids(ctx) -> list[str]:
    return list(ctx.graph.store.nodes)


def fqdns(ctx) -> set[str]:
    return {n.attrs["candidate_fqdn"] for n in ctx.graph.store.nodes.values()}


# --- registration & contract ---------------------------------------------------


def test_registered_under_its_filename_and_is_passive():
    assert get_module("permutations") is permutations.PermutationsModule
    assert permutations.PermutationsModule.name == "permutations"
    assert permutations.PermutationsModule.active is False
    assert permutations.PermutationsModule.produces == ("Hypothesis",)
    assert set(permutations.PermutationsModule.produces) <= ontology.node_types()


def test_verb_is_whitelisted_and_not_active():
    assert permutations.VERB in verbs.ALLOWED
    assert permutations.VERB not in verbs.ACTIVE
    assert permutations.VERB not in verbs.BLOCKED
    assert permutations.VERB not in verbs.HUMAN_GATED


def test_module_source_contains_no_network_machinery():
    """This generator is offline by construction, not merely by habit."""

    src = Path(permutations.__file__).read_text(encoding="utf-8")
    for token in ("import requests", "import socket", "import ssl", "import urllib",
                  "import http", "import subprocess", "requests.", "socket."):
        assert token not in src, f"offline module must not reference {token!r}"
    assert not hasattr(permutations, "requests")


def test_candidate_log_odds_is_never_positive():
    assert permutations.CANDIDATE_LOG_ODDS <= 0


# --- prefix generation ---------------------------------------------------------


def test_prefix_wordlist_is_laid_onto_the_apex(tmp_path):
    ctx, summary = run(tmp_path, [FakeNode("dns:api.epicgames.com")])

    expected = {f"{w}.epicgames.com" for w in WORDS} - {
        "api.epicgames.com",      # the seed is never proposed back to itself
        "admin.epicgames.com",    # excluded -> out_of_scope
    }
    assert fqdns(ctx) == expected
    assert summary["apexes"] == ["epicgames.com"]
    assert summary["generated"] == len(WORDS) - 1  # "api" == the seed
    assert summary["generated_by_generator"] == {"prefix": len(WORDS) - 1, "numeric": 0}
    assert summary["emitted"] == len(expected)
    assert summary["emitted_by_generator"] == {"prefix": len(expected), "numeric": 0}
    assert summary["dropped_out_of_scope"] == 1
    assert summary["dropped_by_verdict"] == {"out_of_scope": 1}
    assert summary["capped"] is False and summary["dropped_by_cap"] == 0


def test_subdomain_seed_prefixes_the_registrable_apex_not_the_seed(tmp_path):
    ctx, summary = run(tmp_path, [FakeNode("dns:a.b.epicgames.com")])

    assert "dev.epicgames.com" in fqdns(ctx)
    assert not any(f.endswith(".b.epicgames.com") for f in fqdns(ctx))
    assert summary["apexes"] == ["epicgames.com"]


def test_apexes_are_deduplicated_across_seeds(tmp_path):
    seeds = [
        FakeNode("dns:api.epicgames.com"),
        FakeNode("dns:store.epicgames.com"),
        FakeNode("dns:www.fortnite.com"),
    ]
    ctx, summary = run(tmp_path, seeds)

    assert summary["apexes"] == ["epicgames.com", "fortnite.com"]
    assert summary["seeds_used"] == 3
    # one prefix sweep per apex, not per seed
    assert summary["generated_by_generator"]["prefix"] == (len(WORDS) - 1) + len(WORDS)


# --- numeric generation --------------------------------------------------------


def test_numeric_mutations_are_pure_padded_and_nearest_first():
    assert permutations.numeric_mutations("api1.epicgames.com") == [
        "api2.epicgames.com", "api0.epicgames.com", "api3.epicgames.com",
    ]
    assert permutations.numeric_mutations("prod06.ol.epicgames.com") == [
        "prod07.ol.epicgames.com", "prod05.ol.epicgames.com",
        "prod08.ol.epicgames.com", "prod04.ol.epicgames.com",
    ]
    # the last digit run is the one mutated, surrounding text is preserved
    assert permutations.numeric_mutations("shard-3-west.epicgames.com")[0] == \
        "shard-4-west.epicgames.com"
    # deterministic: same input, same output, every time
    assert permutations.numeric_mutations("api1.epicgames.com") == \
        permutations.numeric_mutations("api1.epicgames.com")


def test_numeric_offsets_order_and_bounds():
    assert permutations.numeric_offsets(2) == (1, -1, 2, -2)
    assert permutations.numeric_offsets(1) == (1, -1)
    assert permutations.numeric_offsets(0) == ()


def test_numeric_mutations_skip_negative_numbers():
    assert permutations.numeric_mutations("api0.epicgames.com") == [
        "api1.epicgames.com", "api2.epicgames.com",
    ]


def test_numeric_never_mutates_the_apex_or_a_label_free_name():
    # a bare apex has no sub-apex label to mutate
    assert permutations.numeric_mutations("epicgames.com") == []
    # digits inside the registrable domain are off limits: a sibling *domain* is not a
    # sibling *host*, and inventing one would be scope expansion by arithmetic
    assert permutations.numeric_mutations("api.epic2.com") == []
    assert permutations.numeric_mutations("www.epicgames.com") == []


def test_numeric_candidates_are_emitted_for_a_numbered_seed(tmp_path):
    ctx, summary = run(tmp_path, [FakeNode("dns:prod06.ol.epicgames.com")])

    assert {
        "prod04.ol.epicgames.com", "prod05.ol.epicgames.com",
        "prod07.ol.epicgames.com", "prod08.ol.epicgames.com",
    } <= fqdns(ctx)
    assert summary["generated_by_generator"]["numeric"] == 4
    assert summary["emitted_by_generator"]["numeric"] == 4
    numeric = [n for n in ctx.graph.store.nodes.values() if n.attrs["generator"] == "numeric"]
    assert len(numeric) == 4


# --- node shape ----------------------------------------------------------------


def test_node_ids_follow_the_candidate_convention(tmp_path):
    ctx, _ = run(tmp_path, [FakeNode("dns:api1.epicgames.com")])

    assert candidate_ids(ctx)
    for node_id, node in ctx.graph.store.nodes.items():
        assert node_id == f"hyp:dns-candidate:{node.attrs['candidate_fqdn']}"
        assert node_id.startswith("hyp:dns-candidate:")


def test_node_envelope(tmp_path):
    ctx, _ = run(tmp_path, [FakeNode("dns:api1.epicgames.com")])

    node = ctx.graph.store.get("hyp:dns-candidate:api2.epicgames.com")
    assert node is not None
    assert node.type == "Hypothesis"
    assert node.attrs == {"candidate_fqdn": "api2.epicgames.com", "generator": "numeric"}
    assert node.confidence.log_odds == pytest.approx(permutations.CANDIDATE_LOG_ODDS)
    assert node.confidence.log_odds <= 0  # an unverified guess is never asserted
    assert node.confidence.probability < 0.5
    assert node.coverage == {"enumerated": False}  # explicit negative space
    assert node.sensitivity == Sensitivity.S0
    assert node.data_subject == "none"
    assert "active_probed" not in node.attrs  # nothing was probed
    assert node.provenance.chain[0].tool == "permutations"
    assert node.provenance.chain[0].rule_id == "dns-permutation"
    assert node.provenance.chain[0].rule_version == permutations.RULE_VERSION
    assert node.temporal.first_seen == NOW.isoformat()
    assert node.temporal.last_verified == NOW.isoformat()


def test_only_hypothesis_nodes_and_no_edges_are_emitted(tmp_path):
    ctx, _ = run(tmp_path, [FakeNode("dns:api1.epicgames.com"),
                            FakeNode("dns:www.fortnite.com")])

    assert ctx.graph.store.nodes
    assert {n.type for n in ctx.graph.store.nodes.values()} == {"Hypothesis"}
    assert list(ctx.graph.store.iter_type("DNSName")) == []  # never asserts a DNSName
    assert ctx.graph.store.edges == {}


def test_every_emitted_node_is_in_scope_bound_to_the_snapshot(tmp_path):
    ctx, _ = run(tmp_path, [FakeNode("dns:api1.epicgames.com")])

    assert ctx.graph.store.nodes
    for node in ctx.graph.store.nodes.values():
        assert node.scope_binding.verdict == Verdict.IN_SCOPE
        assert node.scope_binding.snapshot_id == ctx.snapshot.snapshot_id
        assert node.scope_binding.rule_matched  # never a fabricated binding
        assert node.scope_binding.observed_at == NOW.isoformat()


def test_each_candidate_raises_a_hypothesis_event(tmp_path):
    ctx, summary = run(tmp_path, [FakeNode("dns:api.epicgames.com")])

    raised = [e.payload for e in ctx.graph.log.by_kind("hypothesis_raised")]
    assert len(raised) == summary["emitted"]
    assert {r["id"] for r in raised} == set(candidate_ids(ctx))
    assert all(r["module"] == "permutations" for r in raised)
    assert all(r["generator"] in ("prefix", "numeric") for r in raised)


# --- scope enforcement ---------------------------------------------------------


def test_out_of_scope_candidates_are_dropped_and_counted(tmp_path):
    ctx, summary = run(tmp_path, [FakeNode("dns:api1.epicgames.com")])

    assert "admin.epicgames.com" not in fqdns(ctx)
    assert "hyp:dns-candidate:admin.epicgames.com" not in ctx.graph.store.nodes
    assert summary["dropped_by_verdict"] == {"out_of_scope": 1}
    assert summary["dropped_out_of_scope"] == 1


def test_prefilter_only_candidates_are_dropped_not_retained(tmp_path):
    """An owned-but-unlisted candidate may never be actively confirmed, so it is not kept."""

    ctx, summary = run(
        tmp_path,
        [FakeNode("dns:api.epicgames.com")],
        include=["api.epicgames.com", "dev.epicgames.com"],  # exact hosts only
        exclude=[],
        prefilter=["*.epicgames.com"],
    )

    assert fqdns(ctx) == {"dev.epicgames.com"}
    assert summary["emitted"] == 1
    assert summary["dropped_by_verdict"] == {"prefilter_only": len(WORDS) - 2}
    assert all(n.scope_binding.verdict == Verdict.IN_SCOPE
               for n in ctx.graph.store.nodes.values())


def test_adjudication_pending_candidate_is_dropped(tmp_path):
    ctx, summary = run(
        tmp_path,
        [FakeNode("dns:api1.epicgames.com")],
        include=["*.epicgames.com", "test.epicgames.com"],
        exclude=["test.epicgames.com"],  # equal specificity -> ambiguous
    )

    assert "test.epicgames.com" not in fqdns(ctx)
    assert summary["dropped_by_verdict"] == {"adjudication_pending": 1}


def test_seed_is_re_bound_and_an_out_of_scope_seed_is_not_permuted(tmp_path):
    """A seed's stored verdict is not trusted; it is re-bound against today's snapshot."""

    ctx, summary = run(tmp_path, [FakeNode("dns:secure.epicgames.com")])

    assert ctx.graph.store.nodes == {}
    assert summary["seeds_used"] == 0
    assert summary["seeds_skipped_by_verdict"] == {"out_of_scope": 1}
    assert summary["emitted"] == 0


def test_prefilter_only_seed_is_not_permuted(tmp_path):
    ctx, summary = run(tmp_path, [FakeNode("dns:internal.epicgames.dev")])

    assert ctx.graph.store.nodes == {}
    assert summary["seeds_skipped_by_verdict"] == {"prefilter_only": 1}


# --- the hard cap --------------------------------------------------------------


def test_hard_cap_truncates_loudly_and_reports_what_was_dropped(tmp_path, monkeypatch, caplog):
    caplog.set_level(logging.WARNING, logger="recon.test.permutations")
    monkeypatch.setattr(permutations, "MAX_CANDIDATES", 5)

    ctx, summary = run(tmp_path, [FakeNode("dns:api1.epicgames.com")])

    total = len(WORDS) + 3  # 15 prefix words + api0/api2/api3
    assert summary["generated"] == total
    assert summary["considered"] == 5
    assert summary["capped"] is True
    assert summary["dropped_by_cap"] == total - 5
    assert summary["dropped_sample"]  # nothing is dropped silently
    assert len(ctx.graph.store.nodes) <= 5
    text = caplog.text
    assert "cap" in text and str(total - 5) in text
    for name in summary["dropped_sample"]:
        assert name in text


def test_cap_keeps_the_first_deterministic_slice(tmp_path, monkeypatch):
    monkeypatch.setattr(permutations, "MAX_CANDIDATES", 3)
    ctx, summary = run(tmp_path, [FakeNode("dns:api1.epicgames.com")])

    assert fqdns(ctx) == {f"{w}.epicgames.com" for w in WORDS[:3]}
    assert summary["emitted"] == 3


def test_dropped_sample_is_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr(permutations, "MAX_CANDIDATES", 1)
    monkeypatch.setattr(permutations, "MAX_DROPPED_SAMPLE", 2)
    _, summary = run(tmp_path, [FakeNode("dns:api1.epicgames.com")])

    assert len(summary["dropped_sample"]) == 2
    assert summary["dropped_by_cap"] == len(WORDS) + 3 - 1


def test_seed_list_is_capped(tmp_path, monkeypatch, caplog):
    caplog.set_level(logging.WARNING, logger="recon.test.permutations")
    monkeypatch.setattr(permutations, "MAX_SEED_NODES", 2)
    seeds = [FakeNode(f"dns:h{i}.epicgames.com") for i in range(5)]

    _, summary = run(tmp_path, seeds)

    assert summary["seeds_used"] == 2
    assert summary["seeds_truncated"] is True
    assert "MAX_SEED_NODES" in caplog.text


def test_default_cap_bounds_a_wide_seed_set(tmp_path):
    seeds = [FakeNode(f"dns:api{i}.shard{i}.edge{i}.epicgames.com") for i in range(40)]
    ctx, summary = run(tmp_path, seeds)

    assert summary["generated"] > permutations.MAX_CANDIDATES
    assert summary["considered"] == permutations.MAX_CANDIDATES
    assert len(ctx.graph.store.nodes) <= permutations.MAX_CANDIDATES
    assert summary["capped"] is True


# --- already-known names -------------------------------------------------------


def test_candidate_already_in_the_graph_is_skipped(tmp_path):
    ctx = make_ctx(tmp_path)
    from recon.factory import make_node

    binding = ctx.bind("dev.epicgames.com")
    ctx.graph.upsert_node(make_node("DNSName", "dns:dev.epicgames.com",
                                    binding=binding, source="crtsh", now=NOW,
                                    coverage={"enumerated": True}))

    summary = permutations.PermutationsModule(ctx).run([FakeNode("dns:api.epicgames.com")])

    assert "hyp:dns-candidate:dev.epicgames.com" not in ctx.graph.store.nodes
    assert summary["already_known"] == 1
    # the confirmed DNSName is untouched: still one node, still a DNSName
    node = ctx.graph.store.get("dns:dev.epicgames.com")
    assert node.type == "DNSName" and node.confidence.log_odds == pytest.approx(0.0)


def test_rerun_does_not_self_corroborate_or_fork(tmp_path):
    """Regenerating the same guess is not independent corroboration."""

    ctx = make_ctx(tmp_path)
    module = permutations.PermutationsModule(ctx)
    first = module.run([FakeNode("dns:api1.epicgames.com")])

    later = NOW + timedelta(hours=1)
    ctx.now = later
    ctx.snapshot = take_snapshot("PINNED POLICY TEXT", now=later, half_life="PT24H")
    second = module.run([FakeNode("dns:api1.epicgames.com")])

    assert second["emitted"] == 0
    assert second["already_known"] == first["emitted"]
    assert not any("#fork" in node_id for node_id in ctx.graph.store.nodes)
    for node in ctx.graph.store.nodes.values():
        assert node.confidence.log_odds == pytest.approx(permutations.CANDIDATE_LOG_ODDS)
        assert node.confidence.independent_sources == 1
        # left to decay on its own clock rather than refreshed by its own generator
        assert node.temporal.last_verified == NOW.isoformat()


def test_two_fresh_runs_are_byte_identical(tmp_path):
    seeds = [FakeNode("dns:prod06.ol.epicgames.com"), FakeNode("dns:www.fortnite.com")]
    ctx_a, summary_a = run(tmp_path / "a", seeds)
    ctx_b, summary_b = run(tmp_path / "b", seeds)

    assert candidate_ids(ctx_a) == candidate_ids(ctx_b)
    assert summary_a == summary_b


# --- evidence ------------------------------------------------------------------


def test_derivation_record_is_content_addressed_and_replayable(tmp_path):
    ctx, _ = run(tmp_path, [FakeNode("dns:api1.epicgames.com")])

    node = ctx.graph.store.get("hyp:dns-candidate:dev.epicgames.com")
    assert len(node.evidence) == 1
    ref = node.evidence[0]
    assert ref.region == "permutations:dev.epicgames.com"
    assert ref.encrypted_at_rest
    assert node.provenance.chain[0].evidence_id == ref.sha256

    record = ctx.evidence.get(ref.sha256).decode("utf-8")
    assert record.startswith(f"permutations/{permutations.RULE_VERSION} generator=prefix")
    assert "apex=epicgames.com" in record
    assert ",".join(WORDS) in record
    assert sha256_bytes(record.encode("utf-8")) == ref.sha256

    numeric = ctx.graph.store.get("hyp:dns-candidate:api2.epicgames.com")
    numeric_record = ctx.evidence.get(numeric.evidence[0].sha256).decode("utf-8")
    assert "generator=numeric" in numeric_record
    assert "seed=api1.epicgames.com" in numeric_record


def test_candidates_from_one_apex_share_one_evidence_blob(tmp_path):
    ctx, summary = run(tmp_path, [FakeNode("dns:api.epicgames.com")])

    prefix_nodes = [n for n in ctx.graph.store.nodes.values()
                    if n.attrs["generator"] == "prefix"]
    assert len({n.evidence[0].sha256 for n in prefix_nodes}) == 1
    assert len({n.evidence[0].region for n in prefix_nodes}) == len(prefix_nodes)


def test_unwritable_evidence_store_does_not_crash_the_run(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)

    def boom(*args, **kwargs):
        raise OSError("read-only evidence store")

    monkeypatch.setattr(ctx.evidence, "put_text", boom)
    summary = permutations.PermutationsModule(ctx).run([FakeNode("dns:api.epicgames.com")])

    assert summary["emitted"] > 0
    assert all(n.evidence == [] for n in ctx.graph.store.nodes.values())


# --- passivity: no gate, no ledger debit, no network ---------------------------


def test_never_gates_and_never_debits_the_ledger(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path, allow_active=True)

    def forbidden(*args, **kwargs):  # pragma: no cover - only runs on a violation
        raise AssertionError("a passive module must not gate or debit")

    monkeypatch.setattr(ctx, "gate_active", forbidden)
    monkeypatch.setattr(ctx.ledger, "debit", forbidden)

    summary = permutations.PermutationsModule(ctx).run([FakeNode("dns:api1.epicgames.com")])

    assert summary["emitted"] > 0
    assert ctx.ledger.log == []
    assert ctx.ledger.balance("epicgames.com") == pytest.approx(ctx.ledger.capacity)
    kinds = {e.kind for e in ctx.graph.log.all()}
    assert "gate_decision_recorded" not in kinds and "rate_debit" not in kinds
    assert kinds == {"node_upserted", "hypothesis_raised"}


def test_runs_with_active_disabled(tmp_path):
    ctx, summary = run(tmp_path, [FakeNode("dns:api.epicgames.com")], allow_active=False)
    assert summary["emitted"] > 0


# --- snapshot gating (I1 / I12) ------------------------------------------------


def test_missing_snapshot_blocks_generation(tmp_path):
    ctx, summary = run(tmp_path, [FakeNode("dns:api.epicgames.com")], snapshot=None)

    assert ctx.graph.store.nodes == {}
    assert summary["emitted"] == 0 and summary["generated"] == 0
    assert "no scope snapshot" in summary["blocked"]


def test_stale_snapshot_blocks_generation(tmp_path):
    ctx, summary = run(tmp_path, [FakeNode("dns:api.epicgames.com")], snapshot="stale")

    assert ctx.graph.store.nodes == {}
    assert summary["emitted"] == 0
    assert "stale" in summary["blocked"]


# --- defensiveness -------------------------------------------------------------


@pytest.mark.parametrize("seeds", [[], None, ["", "   ", None, 42, object()]])
def test_empty_and_junk_seeds_are_graceful(tmp_path, seeds):
    ctx, summary = run(tmp_path, seeds)

    assert ctx.graph.store.nodes == {}
    assert summary["seeds_used"] == 0
    assert summary["generated"] == 0 and summary["emitted"] == 0
    assert "blocked" not in summary


def test_non_dnsname_seeds_are_ignored(tmp_path):
    seeds = [
        FakeNode("domain:epicgames.com", "Domain"),
        FakeNode("host:203.0.113.5", "Host"),
        FakeNode("web:https://api.epicgames.com", "WebApp"),
        FakeNode("hyp:dns-candidate:api.epicgames.com", "Hypothesis"),
        FakeNode("dns:203.0.113.5"),          # an IP is not a permutable hostname
        FakeNode("dns:*.epicgames.com"),      # a wildcard root normalizes to its apex
    ]
    ctx, summary = run(tmp_path, seeds)

    assert summary["seeds_used"] == 1  # only the wildcard root's apex survives
    assert summary["apexes"] == ["epicgames.com"]
    assert fqdns(ctx) == {f"{w}.epicgames.com" for w in WORDS} - {"admin.epicgames.com"}


def test_plain_string_seeds_are_tolerated(tmp_path):
    ctx, summary = run(tmp_path, ["api1.epicgames.com", "api1.epicgames.com"])

    assert summary["seeds_in"] == 2 and summary["seeds_used"] == 1
    assert "api2.epicgames.com" in fqdns(ctx)


def test_valid_fqdn_rejects_junk():
    assert permutations.valid_fqdn("api.epicgames.com")
    assert permutations.valid_fqdn("xn--tst-6la.epicgames.com")
    assert not permutations.valid_fqdn("")
    assert not permutations.valid_fqdn("epicgames")
    assert not permutations.valid_fqdn("*.epicgames.com")
    assert not permutations.valid_fqdn("a b.epicgames.com")
    assert not permutations.valid_fqdn("203.0.113.5")
    assert not permutations.valid_fqdn("x" * 64 + ".epicgames.com")
    assert not permutations.valid_fqdn(("a" * 60 + ".") * 5 + "epicgames.com")


def test_candidate_fqdn_never_contains_a_wildcard_or_uppercase(tmp_path):
    ctx, _ = run(tmp_path, [FakeNode("dns:API1.EpicGames.com")])

    assert ctx.graph.store.nodes
    for node in ctx.graph.store.nodes.values():
        fqdn = node.attrs["candidate_fqdn"]
        assert fqdn == fqdn.lower() and "*" not in fqdn and " " not in fqdn
    assert "api2.epicgames.com" in fqdns(ctx)


# --- invariants ----------------------------------------------------------------


def test_graph_satisfies_the_safety_invariants(tmp_path):
    ctx, _ = run(tmp_path, [FakeNode("dns:api1.epicgames.com"),
                            FakeNode("dns:prod06.ol.epicgames.com"),
                            FakeNode("dns:www.fortnite.com"),
                            FakeNode("dns:secure.epicgames.com")])

    assert ctx.graph.store.nodes
    assert invariants.check(ctx.graph.store, ledger=ctx.ledger,
                            current_snapshot=ctx.snapshot.snapshot_id) == []


def test_planner_recognizes_the_emitted_candidates(tmp_path):
    """The candidates must be exactly what the resolver gap rule looks for."""

    from recon import planner

    ctx, _ = run(tmp_path, [FakeNode("dns:api1.epicgames.com")])
    ctx.allow_active = True
    gaps = planner.plan(ctx.graph.store, NOW, allow_active=True)

    confirm = [g for g in gaps if g.id.startswith("confirm-candidate:")]
    assert len(confirm) == len(ctx.graph.store.nodes)
    assert {g.verb for g in confirm} == {"resolve"}
    assert {g.module for g in confirm} == {"resolver"}
    assert all(not g.human_gated for g in confirm)
