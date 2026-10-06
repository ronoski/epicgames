"""Offline tests for email_posture. The resolver is always faked — never a real query."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import pytest

from recon import verbs
from recon.evidence import EvidenceStore
from recon.events import EventLog
from recon.factory import make_node
from recon.models import ScopeBinding, Verdict
from recon.modules.active import email_posture as mod
from recon.modules.base import GateRefused, ModuleContext
from recon.ratelimit import RateLedger
from recon.scope import Scope
from recon.snapshot import take_snapshot
from recon.store import Graph, GraphStore

NOW = datetime(2026, 1, 10, tzinfo=timezone.utc)
SNAP = take_snapshot("policy v1", now=NOW, include=["*.example.com"])
DOMAIN = "example.com"

pytestmark = pytest.mark.skipif(not mod.HAVE_DNS, reason="dnspython not installed")


def binding(v=Verdict.IN_SCOPE):
    return ScopeBinding(verdict=v, snapshot_id=SNAP.snapshot_id,
                        observed_at="2026-01-10T00:00:00+00:00")


def domain_node(value=DOMAIN, v=Verdict.IN_SCOPE):
    return make_node("Domain", f"domain:{value}", binding=binding(v), source="seeds",
                     now=NOW, attrs={"registrable": value})


def make_ctx(tmp_path, *, allow_active=True, snapshot=SNAP, capacity=100.0,
             include=("*.example.com",)):
    return ModuleContext(
        scope=Scope(include=list(include)),
        ledger=RateLedger(global_qps=10.0, capacity=capacity),
        evidence=EvidenceStore(tmp_path),
        graph=Graph(log=EventLog(), store=GraphStore()),
        snapshot=snapshot, logger=logging.getLogger("t.email"),
        allow_active=allow_active, now=NOW,
    )


class FakeTxt:
    def __init__(self, text):
        self.strings = [text.encode()]


class FakeMx:
    def __init__(self, exchange):
        self.exchange = exchange


def install(monkeypatch, zone):
    """``zone`` maps (name, rrtype) -> list of rdata, or raises NXDOMAIN if absent."""

    import dns.resolver

    queries = []

    class FakeResolver:
        timeout = 5.0
        lifetime = 5.0

        def resolve(self, name, rrtype):
            queries.append((name, rrtype))
            key = (name.rstrip("."), rrtype)
            if key in zone:
                return zone[key]
            raise dns.resolver.NXDOMAIN(qnames=[name])

    monkeypatch.setattr(mod.dns.resolver, "Resolver", lambda: FakeResolver())
    return queries


def run(ctx, seeds=None):
    return mod.EmailPostureModule(ctx).run(
        seeds if seeds is not None else [domain_node()])


def nodes_of(ctx, ntype):
    return [n for n in ctx.graph.store.nodes.values() if n.type == ntype]


def hyp_kinds(ctx):
    return {n.attrs.get("kind") for n in nodes_of(ctx, "Hypothesis")}


# --- contract -----------------------------------------------------------
def test_verb_is_whitelisted_and_active():
    """A DNS query reaches the target's authoritative NS, so it must be budgeted."""

    verbs.assert_schedulable(mod.VERB)
    assert verbs.is_active(mod.VERB)
    assert mod.EmailPostureModule.active is True


# --- parsing (pure) -----------------------------------------------------
@pytest.mark.parametrize("record,qualifier,enforcing", [
    ("v=spf1 include:_spf.google.com -all", "-", True),
    ("v=spf1 include:_spf.google.com ~all", "~", False),
    ("v=spf1 include:a.com", "", False),
    ("", "", False),
])
def test_parse_spf_qualifier(record, qualifier, enforcing):
    parsed = mod.parse_spf(record)
    assert parsed["all_qualifier"] == qualifier
    assert parsed["enforcing"] is enforcing


def test_parse_spf_extracts_includes_and_redirects():
    parsed = mod.parse_spf("v=spf1 include:a.com include:b.com redirect=c.com -all")
    assert parsed["includes"] == ["a.com", "b.com", "c.com"]


def test_parse_spf_dedupes_and_caps_includes():
    many = " ".join(f"include:h{i}.com" for i in range(mod.MAX_INCLUDES + 10))
    parsed = mod.parse_spf(f"v=spf1 {many} include:h0.com -all")
    assert len(parsed["includes"]) == mod.MAX_INCLUDES
    assert len(set(parsed["includes"])) == len(parsed["includes"])


@pytest.mark.parametrize("record,policy,enforcing", [
    ("v=DMARC1; p=reject; rua=mailto:x@y.com", "reject", True),
    ("v=DMARC1; p=quarantine", "quarantine", True),
    ("v=DMARC1; p=none", "none", False),
    ("", "", False),
])
def test_parse_dmarc_policy(record, policy, enforcing):
    parsed = mod.parse_dmarc(record)
    assert parsed["policy"] == policy
    assert parsed["enforcing"] is enforcing


def test_parse_dmarc_records_reporting_presence_not_the_address():
    """rua/ruf are other people's mailboxes: presence only."""

    parsed = mod.parse_dmarc("v=DMARC1; p=reject; rua=mailto:dmarc@thirdparty.example")
    assert parsed["has_reporting"] is True
    assert "dmarc@thirdparty.example" not in str(parsed.get("has_reporting"))


# --- emission -----------------------------------------------------------
def test_a_healthy_domain_emits_a_scheme_and_no_leads(tmp_path, monkeypatch):
    install(monkeypatch, {
        (DOMAIN, "TXT"): [FakeTxt("v=spf1 include:ok.example -all")],
        (f"_dmarc.{DOMAIN}", "TXT"): [FakeTxt("v=DMARC1; p=reject; rua=mailto:a@b.c")],
        (DOMAIN, "MX"): [FakeMx("mail.ok.example.")],
        ("ok.example", "A"): [object()],
        ("mail.ok.example", "A"): [object()],
    })
    ctx = make_ctx(tmp_path)
    summary = run(ctx)

    assert summary["schemes"] == 1
    scheme = nodes_of(ctx, "AuthScheme")[0]
    assert scheme.id == f"auth:{DOMAIN}:email"
    assert scheme.attrs["dmarc_enforcing"] is True
    assert scheme.attrs["spf_enforcing"] is True
    assert scheme.attrs["mx_hosts"] == ["mail.ok.example"]
    assert summary["hypotheses"] == 0
    assert summary["spoofable"] == []


def test_a_missing_dmarc_is_flagged_spoofable(tmp_path, monkeypatch):
    install(monkeypatch, {(DOMAIN, "TXT"): [FakeTxt("v=spf1 -all")]})
    ctx = make_ctx(tmp_path)
    summary = run(ctx)
    assert summary["spoofable"] == [DOMAIN]
    assert "email-spoofable" in hyp_kinds(ctx)


def test_p_none_is_still_spoofable(tmp_path, monkeypatch):
    """p=none publishes a policy that rejects nothing."""

    install(monkeypatch, {
        (DOMAIN, "TXT"): [FakeTxt("v=spf1 -all")],
        (f"_dmarc.{DOMAIN}", "TXT"): [FakeTxt("v=DMARC1; p=none")],
    })
    ctx = make_ctx(tmp_path)
    assert run(ctx)["spoofable"] == [DOMAIN]


def test_a_dangling_spf_include_is_detected(tmp_path, monkeypatch):
    """Whoever registers the provider name inherits authority to send as the domain."""

    install(monkeypatch, {
        (DOMAIN, "TXT"): [FakeTxt("v=spf1 include:gone.example -all")],
        (f"_dmarc.{DOMAIN}", "TXT"): [FakeTxt("v=DMARC1; p=reject")],
        # gone.example resolves for nothing -> dangling
    })
    ctx = make_ctx(tmp_path)
    summary = run(ctx)
    assert summary["dangling_includes"] == [{"domain": DOMAIN, "include": "gone.example"}]
    assert "spf-dangling-include" in hyp_kinds(ctx)


def test_a_resolving_include_is_not_flagged(tmp_path, monkeypatch):
    install(monkeypatch, {
        (DOMAIN, "TXT"): [FakeTxt("v=spf1 include:live.example -all")],
        (f"_dmarc.{DOMAIN}", "TXT"): [FakeTxt("v=DMARC1; p=reject")],
        ("live.example", "A"): [object()],
    })
    ctx = make_ctx(tmp_path)
    assert run(ctx)["dangling_includes"] == []


def test_a_dangling_mx_is_detected(tmp_path, monkeypatch):
    install(monkeypatch, {
        (DOMAIN, "TXT"): [FakeTxt("v=spf1 -all")],
        (f"_dmarc.{DOMAIN}", "TXT"): [FakeTxt("v=DMARC1; p=reject")],
        (DOMAIN, "MX"): [FakeMx("gone-mail.example.")],
    })
    ctx = make_ctx(tmp_path)
    run(ctx)
    assert "mx-dangling" in hyp_kinds(ctx)


def test_mta_sts_presence_is_recorded(tmp_path, monkeypatch):
    install(monkeypatch, {
        (DOMAIN, "TXT"): [FakeTxt("v=spf1 -all")],
        (f"_dmarc.{DOMAIN}", "TXT"): [FakeTxt("v=DMARC1; p=reject")],
        (f"_mta-sts.{DOMAIN}", "TXT"): [FakeTxt("v=STSv1; id=20260101")],
    })
    ctx = make_ctx(tmp_path)
    run(ctx)
    assert nodes_of(ctx, "AuthScheme")[0].attrs["mta_sts_present"] is True


def test_leads_are_emitted_as_hypotheses_not_findings(tmp_path, monkeypatch):
    install(monkeypatch, {(DOMAIN, "TXT"): [FakeTxt("v=spf1 include:gone.example ~all")]})
    ctx = make_ctx(tmp_path)
    run(ctx)
    for hyp in nodes_of(ctx, "Hypothesis"):
        assert hyp.confidence.log_odds <= 0.0
        assert "detection only" in hyp.attrs["note"] or "spoofing" in hyp.attrs["note"]
    assert any(e.kind == "hypothesis_raised" for e in ctx.graph.log.all())


def test_it_links_to_an_existing_dnsname(tmp_path, monkeypatch):
    install(monkeypatch, {(DOMAIN, "TXT"): [FakeTxt("v=spf1 -all")]})
    ctx = make_ctx(tmp_path)
    ctx.graph.upsert_node(make_node("DNSName", f"dns:{DOMAIN}", binding=binding(),
                                    source="seeds", now=NOW))
    run(ctx)
    assert any(e.type == "authenticates_with" for e in ctx.graph.store.edges.values())


# --- gating -------------------------------------------------------------
def test_the_domain_query_set_is_gated_once(tmp_path, monkeypatch):
    install(monkeypatch, {(DOMAIN, "TXT"): [FakeTxt("v=spf1 -all")]})
    ctx = make_ctx(tmp_path)
    run(ctx)
    allows = [e for e in ctx.graph.log.all()
              if e.kind == "gate_decision_recorded" and e.payload.get("decision") == "ALLOW"]
    assert len(allows) == 1
    assert len(ctx.ledger.log) == 1


def test_nothing_queried_when_active_disabled(tmp_path, monkeypatch):
    queries = install(monkeypatch, {(DOMAIN, "TXT"): [FakeTxt("v=spf1 -all")]})
    ctx = make_ctx(tmp_path, allow_active=False)
    run(ctx)
    assert queries == [] and ctx.graph.store.nodes == {}


def test_nothing_queried_without_a_snapshot(tmp_path, monkeypatch):
    queries = install(monkeypatch, {(DOMAIN, "TXT"): [FakeTxt("v=spf1 -all")]})
    ctx = make_ctx(tmp_path, snapshot=None)
    run(ctx)
    assert queries == []


def test_an_out_of_scope_domain_is_not_queried(tmp_path, monkeypatch):
    queries = install(monkeypatch, {})
    ctx = make_ctx(tmp_path)
    run(ctx, [domain_node("evil.invalid", v=Verdict.OUT_OF_SCOPE)])
    assert queries == []


def test_an_exhausted_budget_refuses(tmp_path, monkeypatch):
    queries = install(monkeypatch, {(DOMAIN, "TXT"): [FakeTxt("v=spf1 -all")]})
    ctx = make_ctx(tmp_path, capacity=0.0)
    summary = run(ctx)
    assert queries == [] and summary["refused"]


# --- robustness ---------------------------------------------------------
def test_an_nxdomain_everywhere_still_emits_a_posture(tmp_path, monkeypatch):
    """Absence of every record IS the posture, and the weakest one."""

    install(monkeypatch, {})
    ctx = make_ctx(tmp_path)
    summary = run(ctx)
    scheme = nodes_of(ctx, "AuthScheme")[0]
    assert scheme.attrs["spf_present"] is False
    assert scheme.attrs["dmarc_present"] is False
    assert summary["spoofable"] == [DOMAIN]


def test_a_resolver_error_is_recorded_not_raised(tmp_path, monkeypatch):
    import dns.exception

    class Boom:
        timeout = lifetime = 5.0

        def resolve(self, name, rrtype):
            raise dns.exception.Timeout()

    monkeypatch.setattr(mod.dns.resolver, "Resolver", lambda: Boom())
    ctx = make_ctx(tmp_path)
    summary = run(ctx)
    assert summary["errors"]
    assert summary["schemes"] == 1  # it still records what it could not learn


def test_an_empty_seed_list_is_graceful(tmp_path, monkeypatch):
    install(monkeypatch, {})
    ctx = make_ctx(tmp_path)
    assert run(ctx, [])["queries"] == 0


def test_a_non_domain_seed_is_ignored(tmp_path, monkeypatch):
    install(monkeypatch, {})
    ctx = make_ctx(tmp_path)
    seed = make_node("WebApp", "web:https://a.example.com", binding=binding(),
                     source="http_probe", now=NOW)
    assert run(ctx, [seed])["queries"] == 0


def test_the_seed_cap_is_enforced(tmp_path, monkeypatch):
    install(monkeypatch, {})
    ctx = make_ctx(tmp_path, capacity=1000.0)
    seeds = [domain_node(f"h{i}.example.com") for i in range(mod.MAX_SEEDS + 3)]
    summary = run(ctx, seeds)
    assert len(summary["targets"]) == mod.MAX_SEEDS and summary["truncated"] is True


def test_graph_satisfies_the_safety_invariants(tmp_path, monkeypatch):
    from recon import invariants
    install(monkeypatch, {
        (DOMAIN, "TXT"): [FakeTxt("v=spf1 include:gone.example ~all")],
        (DOMAIN, "MX"): [FakeMx("gone-mail.example.")],
    })
    ctx = make_ctx(tmp_path)
    run(ctx)
    assert invariants.check(ctx.graph.store, ledger=ctx.ledger,
                            current_snapshot=SNAP.snapshot_id, log=ctx.graph.log,
                            snapshot=SNAP, now=NOW) == []


def test_the_module_reports_cleanly_when_dnspython_is_absent(tmp_path, monkeypatch):
    monkeypatch.setattr(mod, "HAVE_DNS", False)
    ctx = make_ctx(tmp_path)
    summary = run(ctx)
    assert "dnspython" in summary["unavailable"]
    assert ctx.graph.store.nodes == {}
    assert ctx.ledger.log == [], "it must not spend budget it cannot use"
