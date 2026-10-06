import pytest

from recon.scope import Scope, classify, normalize_host, registrable_domain
from recon.models import Verdict


def mk(**kw):
    return Scope(**kw)


def test_default_deny_requires_includes():
    with pytest.raises(ValueError):
        Scope(include=[])


def test_wildcard_matches_subdomains_and_apex():
    s = mk(include=["*.epicgames.com"])
    assert s.is_in_scope("api.epicgames.com")
    assert s.is_in_scope("a.b.epicgames.com")
    assert s.is_in_scope("epicgames.com")  # apex
    assert not s.is_in_scope("epicgames.com.evil.com")
    assert not s.is_in_scope("notepicgames.com")


def test_exclude_wins_over_include():
    s = mk(include=["*.epicgames.com"], exclude=["secure.epicgames.com"])
    assert s.verdict("secure.epicgames.com")[0] == Verdict.OUT_OF_SCOPE
    assert s.verdict("api.epicgames.com")[0] == Verdict.IN_SCOPE


def test_default_deny_unmatched():
    s = mk(include=["*.epicgames.com"])
    assert s.verdict("example.org")[0] == Verdict.OUT_OF_SCOPE


def test_hostname_rule_never_authorizes_ip():
    s = mk(include=["*.epicgames.com"])
    assert not s.is_in_scope("203.0.113.5")


def test_cidr_include_matches_ip_only():
    s = mk(include=["203.0.113.0/24"])
    assert s.is_in_scope("203.0.113.5")
    assert not s.is_in_scope("203.0.114.5")
    assert not s.is_in_scope("host.example.com")


def test_prefilter_only_for_owned_but_unlisted():
    s = mk(include=["*.fortnite.com"], prefilter=["*.epicgames.com"])
    v, _ = s.verdict("internal.epicgames.com")
    assert v == Verdict.PREFILTER_ONLY
    # prefilter is never actionable
    b = s.bind("internal.epicgames.com", "snap1", "2026-01-01T00:00:00Z")
    assert not b.actionable


def test_most_restrictive_exclude_beats_broad_include():
    # broad include wildcard, specific host exclude
    s = mk(include=["*.epicgames.com"], exclude=["dev.epicgames.com"])
    assert s.verdict("dev.epicgames.com")[0] == Verdict.OUT_OF_SCOPE


def test_adjudication_pending_on_equal_specificity_tie():
    s = mk(include=["dev.epicgames.com"], exclude=["dev.epicgames.com"])
    assert s.verdict("dev.epicgames.com")[0] == Verdict.ADJUDICATION_PENDING


def test_bind_records_snapshot_and_rule():
    s = mk(include=["*.epicgames.com"])
    b = s.bind("api.epicgames.com", "snap-abc", "2026-01-01T00:00:00Z")
    assert b.verdict == Verdict.IN_SCOPE
    assert b.snapshot_id == "snap-abc"
    assert "included by" in b.rule_matched
    assert b.actionable


def test_scope_traps_bandcamp_and_epic_systems():
    s = mk(include=["*.epicgames.com"], exclude=["bandcamp.com", "*.epic.com"])
    assert s.verdict("bandcamp.com")[0] == Verdict.OUT_OF_SCOPE
    assert s.verdict("fhir.epic.com")[0] == Verdict.OUT_OF_SCOPE


def test_classify_and_normalize():
    assert classify("1.2.3.4") == "ip"
    assert classify("10.0.0.0/8") == "ip"
    assert classify("host.example.com") == "host"
    assert normalize_host("HTTPS://API.Epicgames.com:443/x") == "api.epicgames.com"


def test_registrable_domain():
    assert registrable_domain("a.b.epicgames.com") == "epicgames.com"
    assert registrable_domain("epicgames.com") == "epicgames.com"
    assert registrable_domain("x.y.example.co.uk") == "example.co.uk"
    assert registrable_domain("203.0.113.5") == "203.0.113.5"
