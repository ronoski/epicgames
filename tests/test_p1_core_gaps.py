"""Tests for the P1 core gaps the module implementations worked around.

Each test names the defect it pins so a regression is obvious.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

import pytest

from recon import invariants, urls, verbs
from recon.evidence import EvidenceStore
from recon.events import EventLog
from recon.factory import DEFAULT_HALF_LIFE, make_node
from recon.models import ScopeBinding, Verdict
from recon.modules.base import GateRefused, ModuleContext
from recon.ratelimit import RateLedger
from recon.scope import Scope
from recon.snapshot import take_snapshot
from recon.store import Graph, GraphStore
from recon import ontology

NOW = datetime(2026, 1, 10, tzinfo=timezone.utc)
SNAP = take_snapshot("p", now=NOW)


def binding(v=Verdict.IN_SCOPE):
    return ScopeBinding(verdict=v, snapshot_id=SNAP.snapshot_id, observed_at="2026-01-10T00:00:00+00:00")


def ctx(tmp_path, *, allow_active=True, snapshot=SNAP, include=("*.example.com",),
        capacity=100.0, third_party=None, now=NOW):
    return ModuleContext(
        scope=Scope(include=list(include)),
        ledger=RateLedger(global_qps=10.0, capacity=capacity),
        third_party_ledger=third_party,
        evidence=EvidenceStore(tmp_path), graph=Graph(log=EventLog(), store=GraphStore()),
        snapshot=snapshot, logger=logging.getLogger("t"), allow_active=allow_active, now=now,
    )


# === wildcard_includes_apex was dead config =============================
def test_wildcard_includes_apex_true_covers_apex():
    s = Scope(include=["*.example.com"], wildcard_includes_apex=True)
    assert s.is_in_scope("example.com")
    assert s.is_in_scope("api.example.com")


def test_wildcard_includes_apex_false_excludes_apex():
    """The flag was accepted and stored but never consulted."""

    s = Scope(include=["*.example.com"], wildcard_includes_apex=False)
    assert not s.is_in_scope("example.com"), "apex must be out when the flag is off"
    assert s.is_in_scope("api.example.com"), "subdomains stay in scope"


# === CIDR containment ===================================================
def test_network_seed_must_be_fully_contained_to_be_in_scope():
    """Seeding a /22 against an include of /24 previously bound in_scope."""

    s = Scope(include=["203.0.113.0/24"])
    assert s.is_in_scope("203.0.113.0/24")
    assert s.is_in_scope("203.0.113.128/25")           # subnet -> contained
    assert not s.is_in_scope("203.0.112.0/22")          # superset -> NOT contained
    assert s.is_in_scope("203.0.113.5")                 # single address still works


def test_exclusion_uses_overlap_not_containment():
    """Any intersection with an out-of-scope block must refuse."""

    s = Scope(include=["203.0.0.0/8"], exclude=["203.0.113.0/24"])
    assert s.verdict("203.0.113.0/25")[0] == Verdict.OUT_OF_SCOPE   # inside the exclusion
    assert s.verdict("203.0.112.0/23")[0] == Verdict.OUT_OF_SCOPE   # partially overlaps
    assert s.verdict("203.1.0.0/24")[0] == Verdict.IN_SCOPE         # no overlap


def test_mixed_ip_versions_do_not_match():
    s = Scope(include=["203.0.113.0/24"])
    assert not s.is_in_scope("2001:db8::/32")


# === shared canonicalizer ===============================================
@pytest.mark.parametrize("raw,expected", [
    ("HTTPS://API.Example.com:443/x", "api.example.com"),
    ("api.example.com.", "api.example.com"),
    ("user:pw@api.example.com:8443", "api.example.com"),
    ("[2001:db8::1]:443", "2001:db8::1"),
])
def test_canonical_host(raw, expected):
    assert urls.canonical_host(raw) == expected


def test_authority_elides_default_port_and_brackets_ipv6():
    assert urls.authority("api.example.com", 443, "https") == "api.example.com"
    assert urls.authority("api.example.com", 8443, "https") == "api.example.com:8443"
    assert urls.authority("2001:db8::1", 8443, "https") == "[2001:db8::1]:8443"


def test_canonical_url_sorts_query_and_elides_default_port():
    assert urls.canonical_url("https://A.example.com:443/p?b=2&a=1") == \
        "https://a.example.com/p?a=1&b=2"


@pytest.mark.parametrize("path,tmpl", [
    ("/v1/items/12345", "/v1/items/{id}"),
    ("/u/3f2504e0-4f89-11d3-9a0c-0305e82c3301/x", "/u/{id}/x"),
    ("/a/deadbeefdeadbeef", "/a/{id}"),
    ("/", "/"),
])
def test_path_template_collapses_identifiers(path, tmpl):
    assert urls.path_template(path) == tmpl


def test_registrable_domain_handles_multi_part_suffixes():
    assert urls.registrable_domain("a.b.example.com") == "example.com"
    assert urls.registrable_domain("x.y.example.co.uk") == "example.co.uk"
    assert urls.registrable_domain("a.b.user.github.io") == "user.github.io"
    assert urls.registrable_domain("203.0.113.5") == "203.0.113.5"


def test_valid_fqdn_rejects_ips_and_malformed():
    assert urls.valid_fqdn("api.example.com")
    assert not urls.valid_fqdn("203.0.113.5")
    assert not urls.valid_fqdn("no-dot")
    assert not urls.valid_fqdn("-bad.example.com")
    assert not urls.valid_fqdn("")


# === id grammars ========================================================
def test_webapp_id_keeps_a_non_default_port():
    """web:<scheme>://<vhost> had no port slot, making :8443 unreachable."""

    assert urls.webapp_id("https", "api.example.com") == "web:https://api.example.com"
    assert urls.webapp_id("https", "api.example.com", 443) == "web:https://api.example.com"
    assert urls.webapp_id("https", "api.example.com", 8443) == \
        "web:https://api.example.com:8443"


def test_parameter_id_distinguishes_location():
    """param:<op>#<name> collided for a query vs header param of the same name."""

    op = "op:GET:route:web:https://a.example.com/x"
    q = urls.parameter_id(op, "id", "query")
    h = urls.parameter_id(op, "id", "header")
    assert q != h, "same-named params in different locations must not share an id"
    assert q.endswith("#query:id") and h.endswith("#header:id")


def test_certificate_id_is_keyed_on_spki():
    a = urls.certificate_id(b"spki-bytes")
    assert a.startswith("cert:") and a == urls.certificate_id(b"spki-bytes")
    assert a != urls.certificate_id(b"other")


# === ontology additions =================================================
def test_certificate_node_type_is_declared():
    ontology.assert_node_type("Certificate")


def test_containment_edges_are_declared():
    ontology.assert_edge_type("subdomain_of")
    ontology.assert_edge_type("presents_certificate")


def test_still_closed_against_unknown_and_proposed():
    # same_as/co_deploy/shared_trust_domain were promoted when entity resolution landed.
    ontology.assert_edge_type("same_as")
    with pytest.raises(ontology.OntologyError):
        ontology.assert_edge_type("allows_origin")  # still only proposed
    with pytest.raises(ontology.OntologyError):
        ontology.assert_edge_type("not_a_real_edge")
    with pytest.raises(ontology.OntologyError):
        ontology.assert_node_type("Wormhole")


# === half-lives =========================================================
@pytest.mark.parametrize("ntype", ["Hypothesis", "NetBlock", "ASN", "Route", "Certificate"])
def test_missing_half_lives_are_now_declared(ntype):
    assert ntype in DEFAULT_HALF_LIFE, f"{ntype} silently inherited the P14D default"


def test_a_guess_decays_faster_than_a_netblock():
    from recon.coverage import parse_duration
    assert parse_duration(DEFAULT_HALF_LIFE["Hypothesis"]) < \
        parse_duration(DEFAULT_HALF_LIFE["NetBlock"])


# === third-party source budget ==========================================
def test_third_party_spend_does_not_touch_the_target_ledger(tmp_path):
    tp = RateLedger(global_qps=1.0, capacity=2.0)
    c = ctx(tmp_path, third_party=tp)
    assert c.spend_third_party("crt.sh") is True
    assert c.ledger.log == [], "a passive source must never debit the target's budget"
    assert len(tp.log) == 1
    kinds = {e.kind for e in c.graph.log.all()}
    assert "third_party_debit" in kinds and "rate_debit" not in kinds


def test_third_party_budget_exhausts_and_backs_off(tmp_path):
    tp = RateLedger(global_qps=0.0, capacity=1.0)
    c = ctx(tmp_path, third_party=tp)
    assert c.spend_third_party("crt.sh") is True
    assert c.spend_third_party("crt.sh") is False, "must back off, not hammer"


def test_unmetered_when_no_third_party_ledger(tmp_path):
    c = ctx(tmp_path, third_party=None)
    assert c.spend_third_party("crt.sh") is True


def test_runtime_wires_a_third_party_ledger(tmp_path):
    from recon.config import Config
    from recon.pipeline import build_runtime
    rt = build_runtime(Config.from_dict({"scope": {"include": ["*.example.com"]},
                                         "policy_text": "p"}),
                       workdir=tmp_path, persist=False)
    assert rt.ctx.third_party_ledger is not None
    assert rt.ctx.third_party_ledger is not rt.ctx.ledger


# === gate cost + non-spending pre-check =================================
def test_gate_cost_prices_an_expensive_verb(tmp_path):
    c = ctx(tmp_path, capacity=10.0)
    c.gate_active("api.example.com", "port-scan", cost=4.0)
    assert c.ledger.log[-1].cost == 4.0
    assert c.ledger.log[-1].balance_after == pytest.approx(6.0, abs=0.1)


def test_can_gate_is_non_spending_and_writes_no_refusal(tmp_path):
    c = ctx(tmp_path)
    ok, reason = c.can_gate("api.example.com", "http-GET")
    assert ok and "included by" in reason
    bad, why = c.can_gate("evil.invalid", "http-GET")
    assert not bad and "not in scope" in why
    # neither spent budget nor logged a decision
    assert c.ledger.log == []
    assert [e for e in c.graph.log.all() if e.kind == "gate_decision_recorded"] == []


def test_can_gate_agrees_with_gate_active(tmp_path):
    c = ctx(tmp_path, allow_active=False)
    ok, _ = c.can_gate("api.example.com", "http-GET")
    assert not ok
    with pytest.raises(GateRefused):
        c.gate_active("api.example.com", "http-GET")


# === invariants I10-I12 =================================================
def test_I10_flags_a_dispatched_non_whitelisted_verb():
    store = GraphStore()
    log = EventLog()
    log.append("gap_dispatched", {"id": "g", "verb": "exploit", "module": "m"})
    codes = [v.code for v in invariants.check(store, log=log)]
    assert "I10" in codes


def test_I10_clean_for_a_whitelisted_verb():
    log = EventLog()
    log.append("gap_dispatched", {"id": "g", "verb": "resolve", "module": "resolver"})
    assert [v for v in invariants.check(GraphStore(), log=log) if v.code == "I10"] == []


def test_I11_flags_a_fork_that_lost_its_lineage():
    store = GraphStore()
    log = EventLog()
    log.append("contradiction_forked", {"id": "dns:x#fork1", "outcome": "forked"})
    codes = [v.code for v in invariants.check(store, log=log)]
    assert "I11" in codes  # no such node exists


def test_I11_clean_when_a_real_fork_records_forked_from():
    store = GraphStore()
    g = Graph(log=EventLog(), store=store)
    a = make_node("DNSName", "dns:x.example.com", binding=binding(), source="a",
                  now=NOW, attrs={"ip": "1.1.1.1"})
    b = make_node("DNSName", "dns:x.example.com", binding=binding(), source="b",
                  now=NOW, attrs={"ip": "2.2.2.2"})
    g.upsert_node(a)
    res = g.upsert_node(b)
    assert res.outcome == "forked"
    assert [v for v in invariants.check(store, log=g.log) if v.code == "I11"] == []


def test_I12_flags_allows_granted_under_a_stale_snapshot(tmp_path):
    stale = take_snapshot("p", now=NOW - timedelta(days=5))
    log = EventLog()
    log.append("gate_decision_recorded", {"decision": "ALLOW", "value": "a", "verb": "resolve"})
    codes = [v.code for v in invariants.check(GraphStore(), log=log, snapshot=stale)]
    assert "I12" in codes


def test_I12_clean_with_a_fresh_snapshot():
    fresh = take_snapshot("p")
    log = EventLog()
    log.append("gate_decision_recorded", {"decision": "ALLOW", "value": "a", "verb": "resolve"})
    assert [v for v in invariants.check(GraphStore(), log=log, snapshot=fresh)
            if v.code == "I12"] == []


def test_invariants_without_a_log_skip_the_log_derived_checks():
    """Backwards compatible: no log means I1-I9 only, no crash."""

    assert invariants.check(GraphStore()) == []
