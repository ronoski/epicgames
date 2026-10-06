"""Offline, deterministic tests for the active tls_probe module.

Nothing here touches the network. An autouse fixture replaces ``socket.socket``,
``socket.create_connection``, ``socket.gethostbyname_ex`` and ``ssl.create_default_context``
with landmines, so a regression that reaches for a real connection fails loudly instead of
contacting any Epic host; each test then installs a fake TLS stack that records every call.
The fake sockets also landmine ``send``/``sendall``/``recv``, so a module that tried to write
an HTTP request onto the connection would fail. Time is injected via ``ModuleContext.now``
and the rate ledger gets a frozen monotonic clock, so timestamps *and* budgets are fixed.
"""

from __future__ import annotations

import json
import logging
import socket
import ssl
from datetime import datetime, timezone

import pytest

from recon import invariants, verbs
from recon.evidence import EvidenceStore, sha256_bytes
from recon.events import EventLog
from recon.models import Sensitivity, Verdict
from recon.modules.base import GateRefused, ModuleContext, get_module
from recon.modules.active import tls_probe
from recon.ratelimit import RateLedger
from recon.scope import Scope
from recon.snapshot import take_snapshot
from recon.store import Graph

NOW = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)

HOST = "api.epicgames.com"
APP = f"web:https://{HOST}"
ISSUER = "DigiCert TLS RSA SHA256 2020 CA1"

#: A realistic SAN mix: the host itself, an in-scope sibling, a wildcard, an excluded name,
#: an owned-but-unlisted name and a third-party CDN name.
SANS = (
    HOST, "www.epicgames.com", "*.fortnite.com", "secure.epicgames.com",
    "internal.epicgames.dev", "cdn.akamai.net",
)


# --- certificate fixtures ------------------------------------------------------


def cert(
    *,
    subject_cn: str = HOST,
    issuer_cn: str = ISSUER,
    serial: str = "0A1B2C3D4E5F",
    not_before: str = "Jan 13 00:00:00 2026 GMT",
    not_after: str = "Feb 11 23:59:59 2027 GMT",
    sans=SANS,
    extra_sans=(),
    subject_extra=(),
) -> dict:
    """A ``getpeercert()``-shaped dict (nested RDN tuples, ``(type, value)`` SANs)."""

    return {
        "subject": ((("commonName", subject_cn),),) + tuple(subject_extra),
        "issuer": (
            (("countryName", "US"),),
            (("organizationName", "DigiCert Inc"),),
            (("commonName", issuer_cn),),
        ),
        "version": 3,
        "serialNumber": serial,
        "notBefore": not_before,
        "notAfter": not_after,
        "subjectAltName": tuple(("DNS", name) for name in sans) + tuple(extra_sans),
    }


# --- harness -------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _no_real_network(monkeypatch):
    """Hard offline guard: any genuine socket/TLS/DNS use is a test failure."""

    def _boom(*args, **kwargs):
        raise AssertionError("test attempted a real network connection")

    monkeypatch.setattr(socket, "socket", _boom)
    monkeypatch.setattr(socket, "create_connection", _boom)
    monkeypatch.setattr(socket, "gethostbyname_ex", _boom)
    monkeypatch.setattr(ssl, "create_default_context", _boom)


class FakeRawSocket:
    """A connected TCP socket. Reads/writes are landmines: nothing is sent on it."""

    def __init__(self, address, timeout, calls: list) -> None:
        self.address = address
        self.timeout = timeout
        self.timeouts: list = []
        self.closed = False
        self._calls = calls

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.closed = True
        return False

    def settimeout(self, value):
        self.timeouts.append(value)

    def _no_io(self, *args, **kwargs):
        raise AssertionError("tls_probe performed I/O on the socket")

    sendall = send = recv = _no_io


class FakeTLSSocket:
    """A completed handshake: serves one certificate and the negotiated version."""

    def __init__(self, peer_cert, version: str, raw: FakeRawSocket,
                 der: bytes | None = None) -> None:
        self._cert = peer_cert
        self._version = version
        self._der = der
        self.raw = raw
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.closed = True
        return False

    def getpeercert(self, binary_form: bool = False):
        if binary_form:
            # The Certificate node is keyed on real key material, so the module now
            # legitimately asks for the DER. Derive it deterministically from the
            # parsed cert so a rotated cert yields a different id.
            if self._der is not None:
                return self._der
            return repr(sorted(self._cert.items())).encode() if self._cert else b""
        return self._cert

    def version(self):
        return self._version

    def _no_io(self, *args, **kwargs):
        raise AssertionError("tls_probe performed I/O on the TLS socket")

    sendall = send = recv = _no_io


class CallLog(list):
    """The recorded calls of one run, plus the fake TLS contexts it created."""

    def __init__(self, *args) -> None:
        super().__init__(*args)
        self.contexts: list["FakeContext"] = []


class FakeContext:
    """Stand-in for ``ssl.create_default_context()``'s context object."""

    def __init__(self, certs, version, handshake_raises, calls: list) -> None:
        self._certs = certs
        self._version = version
        self._raises = handshake_raises
        self._calls = calls
        self.sockets: list[FakeTLSSocket] = []

    def wrap_socket(self, sock, server_hostname=None, **kwargs):
        self._calls.append({"kind": "handshake", "server_hostname": server_hostname,
                            "address": getattr(sock, "address", None),
                            "extra": dict(kwargs)})
        if self._raises is not None:
            raise self._raises
        peer = self._certs(server_hostname) if callable(self._certs) else self._certs
        tls = FakeTLSSocket(peer, self._version, sock)
        self.sockets.append(tls)
        return tls


#: Distinguishes "no certificate argument given" from "serve ``None`` as the peer cert".
_DEFAULT_CERT = object()


def install_fake_tls(monkeypatch, one_cert=_DEFAULT_CERT, *, certs=None, version="TLSv1.3",
                     connect_raises=None, handshake_raises=None, log=None) -> CallLog:
    """Patch the module's ``socket``/``ssl`` entry points. Returns the call list.

    ``one_cert`` is a single certificate served to every host; ``certs`` is a callable
    ``host -> cert`` for per-host answers. Either ``*_raises`` makes that step fail.
    """

    calls = log if log is not None else CallLog()
    served = certs if certs is not None else (
        cert() if one_cert is _DEFAULT_CERT else one_cert
    )
    contexts = calls.contexts

    def create_connection(address, timeout=None, **kwargs):
        calls.append({"kind": "connect", "address": address, "timeout": timeout,
                      "extra": dict(kwargs)})
        if connect_raises is not None:
            raise connect_raises
        return FakeRawSocket(address, timeout, calls)

    def create_default_context(*args, **kwargs):
        calls.append({"kind": "context"})
        ctx = FakeContext(served, version, handshake_raises, calls)
        contexts.append(ctx)
        return ctx

    monkeypatch.setattr(tls_probe.socket, "create_connection", create_connection)
    monkeypatch.setattr(tls_probe.ssl, "create_default_context", create_default_context)
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
        include=["*.epicgames.com", "*.fortnite.com", "203.0.113.0/24"],
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
        logger=logging.getLogger("test.tls_probe"),
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


def webapp(host: str = HOST, scheme: str = "https") -> FakeNode:
    return FakeNode(f"web:{scheme}://{host}", "WebApp")


def dns(host: str = HOST) -> FakeNode:
    return FakeNode(f"dns:{host}", "DNSName")


def run(tmp_path, monkeypatch, seeds, one_cert=_DEFAULT_CERT, **kw):
    ctx = make_ctx(tmp_path, **kw.pop("ctx", {}))
    calls = install_fake_tls(monkeypatch, one_cert, **kw)
    summary = tls_probe.TlsProbeModule(ctx).run(seeds)
    return ctx, summary, calls


def of_kind(calls: list, kind: str) -> list[dict]:
    return [c for c in calls if c["kind"] == kind]


def allow_records(ctx: ModuleContext) -> list[dict]:
    return [e.payload for e in ctx.graph.log.by_kind("gate_decision_recorded")
            if e.payload["decision"] == "ALLOW"]


def refuse_records(ctx: ModuleContext) -> list[dict]:
    return [e.payload for e in ctx.graph.log.by_kind("gate_decision_recorded")
            if e.payload["decision"] == "REFUSE"]


def candidates(ctx: ModuleContext) -> list[str]:
    return sorted(n.id for n in ctx.graph.store.iter_type("Hypothesis"))


# --- registration & the verb contract -----------------------------------------


def test_registered_under_its_filename_and_is_active():
    assert get_module("tls_probe") is tls_probe.TlsProbeModule
    assert tls_probe.TlsProbeModule.name == "tls_probe"
    assert tls_probe.TlsProbeModule.active is True
    assert tls_probe.TlsProbeModule.produces == ("WebApp", "Certificate", "Hypothesis")


def test_verb_is_a_whitelisted_active_verb():
    assert tls_probe.VERB in verbs.ALLOWED
    assert tls_probe.VERB in verbs.ACTIVE
    assert tls_probe.VERB not in verbs.BLOCKED
    assert tls_probe.VERB not in verbs.HUMAN_GATED
    verbs.assert_schedulable(tls_probe.VERB)


def test_fingerprint_is_allowed_but_not_active_so_it_cannot_be_spent_here():
    """The documented interface gap: the planner's verb for this module is not active."""

    assert "fingerprint" in verbs.ALLOWED
    assert "fingerprint" not in verbs.ACTIVE  # => gate_active would REFUSE it
    assert tls_probe.VERB != "fingerprint"


def test_the_gate_really_refuses_the_planners_fingerprint_verb(tmp_path):
    ctx = make_ctx(tmp_path)
    with pytest.raises(GateRefused) as excinfo:
        ctx.gate_active(HOST, "fingerprint")
    assert "not an active verb" in excinfo.value.reason
    assert ctx.ledger.log == []  # a refusal never debits


def test_module_imports_no_http_client():
    assert not hasattr(tls_probe, "requests")


def test_only_declared_ontology_types_are_emitted(tmp_path, monkeypatch):
    ctx, _, _ = run(tmp_path, monkeypatch, [webapp()])

    assert {n.type for n in ctx.graph.store.nodes.values()} == \
        {"WebApp", "Certificate", "Hypothesis"}
    # The only edge is WebApp -> Certificate, now that both types are declared.
    assert {e.type for e in ctx.graph.store.edges.values()} == {"presents_certificate"}


# --- the handshake shape -------------------------------------------------------


def test_one_handshake_per_host_with_pinned_connection_shape(tmp_path, monkeypatch):
    ctx, summary, calls = run(tmp_path, monkeypatch, [webapp()])

    connects = of_kind(calls, "connect")
    handshakes = of_kind(calls, "handshake")
    assert len(connects) == len(handshakes) == 1
    assert connects[0]["address"] == (HOST, 443) == (HOST, tls_probe.TLS_PORT)
    assert connects[0]["timeout"] == ctx.timeout
    assert connects[0]["extra"] == {}
    assert handshakes[0]["server_hostname"] == HOST  # SNI is the probed vhost
    assert handshakes[0]["extra"] == {}
    assert summary["handshakes"] == 1 and summary["certificates"] == 1
    assert summary["verb"] == "tls-handshake" and summary["port"] == 443


def test_verification_is_left_enabled_and_sockets_are_closed(tmp_path, monkeypatch):
    _, _, calls = run(tmp_path, monkeypatch, [webapp()])

    # The default context is what is used; nothing weakens check_hostname/verify_mode.
    assert len(of_kind(calls, "context")) == 1
    context = calls.contexts[0]  # type: ignore[attr-defined]
    assert [s.closed for s in context.sockets] == [True]
    assert [s.raw.closed for s in context.sockets] == [True]
    assert [s.raw.timeouts for s in context.sockets] == [[8.0]]  # handshake bounded too


def test_duplicate_and_cross_scheme_seeds_handshake_once(tmp_path, monkeypatch):
    seeds = [webapp(), webapp(scheme="http"), dns(), f"{HOST}.", HOST.upper(),
             webapp(f"{HOST}:443")]
    _, summary, calls = run(tmp_path, monkeypatch, seeds)

    assert summary["hosts"] == [HOST]
    assert summary["seeds_in"] == 6 and summary["seeds_deduped"] == 5
    assert len(of_kind(calls, "connect")) == 1


def test_seed_cap_defers_instead_of_running_away(tmp_path, monkeypatch):
    monkeypatch.setattr(tls_probe, "MAX_SEED_NODES", 2)
    seeds = [webapp(f"h{i}.epicgames.com") for i in range(5)]
    _, summary, calls = run(tmp_path, monkeypatch, seeds)

    assert summary["hosts"] == ["h0.epicgames.com", "h1.epicgames.com"]
    assert summary["seeds_truncated"] is True
    assert len(of_kind(calls, "connect")) == 2


# --- the gate is the chokepoint ------------------------------------------------


def test_every_handshake_is_immediately_preceded_by_its_own_gate(tmp_path, monkeypatch):
    calls = CallLog()
    ctx = make_ctx(tmp_path)
    spy_on_gate(monkeypatch, ctx, calls)
    install_fake_tls(monkeypatch, log=calls)

    tls_probe.TlsProbeModule(ctx).run([webapp(), dns("www.fortnite.com")])

    # Strict ordering: gate first, then the socket — one gate per network touch.
    assert [c["kind"] for c in calls] == ["gate", "context", "connect", "handshake"] * 2
    assert [c["value"] for c in calls if c["kind"] == "gate"] == [HOST, "www.fortnite.com"]
    assert {c["verb"] for c in calls if c["kind"] == "gate"} == {"tls-handshake"}
    assert len(allow_records(ctx)) == 2


def test_each_handshake_debits_the_unified_ledger_once(tmp_path, monkeypatch):
    ctx, summary, calls = run(tmp_path, monkeypatch, [webapp(), dns("www.epicgames.com")])

    assert len(ctx.ledger.log) == len(of_kind(calls, "connect")) == 2
    assert [e.verb for e in ctx.ledger.log] == ["tls-handshake", "tls-handshake"]
    assert {e.target for e in ctx.ledger.log} == {"epicgames.com"}  # keyed by registrable
    assert ctx.ledger.balance(HOST) == pytest.approx(18.0)
    assert all(e.balance_after >= 0 for e in ctx.ledger.log)
    assert summary["refused"] == 0


@pytest.mark.parametrize("override, fragment", [
    ({"allow_active": False}, "allow_active=false"),
    ({"snapshot": None}, "no scope snapshot"),
    ({"snapshot": take_snapshot("old", now=datetime(2026, 1, 1, tzinfo=timezone.utc))},
     "stale"),
])
def test_gate_refusal_skips_without_opening_a_socket(tmp_path, monkeypatch, override,
                                                     fragment):
    ctx, summary, calls = run(tmp_path, monkeypatch, [webapp()], ctx=override)

    assert calls == []  # refused means no packet, not a quieter packet
    assert ctx.graph.store.nodes == {} and ctx.graph.store.edges == {}
    assert ctx.ledger.log == []
    assert summary["handshakes"] == 0 and summary["refused"] == 1
    assert all(fragment in reason for reason in summary["refused_by_reason"])
    assert len(refuse_records(ctx)) == 1


@pytest.mark.parametrize("host", [
    "secure.epicgames.com",      # excluded -> out_of_scope
    "internal.epicgames.dev",    # owned-but-unlisted -> prefilter_only
    "fhir.epic.com",             # default deny
])
def test_out_of_scope_hosts_are_never_touched(tmp_path, monkeypatch, host):
    ctx, summary, calls = run(tmp_path, monkeypatch, [webapp(host)])

    assert calls == []
    assert ctx.graph.store.nodes == {}
    assert summary["handshakes"] == 0 and summary["refused"] == 1
    assert all("not in scope" in r for r in summary["refused_by_reason"])


def test_exhausted_budget_refuses_the_rest_and_never_crashes(tmp_path, monkeypatch):
    ctx, summary, calls = run(
        tmp_path, monkeypatch, [webapp(), dns("www.epicgames.com")],
        ctx={"ledger": RateLedger(global_qps=1.0, capacity=1.0, clock=lambda: 0.0)},
    )

    assert len(of_kind(calls, "connect")) == 1  # the 2nd touch is refused, not borrowed
    assert summary["refused"] == 1
    assert all("rate budget exceeded" in r for r in summary["refused_by_reason"])
    assert all(e.balance_after >= 0 for e in ctx.ledger.log)
    assert invariants.check(ctx.graph.store, ledger=ctx.ledger,
                            current_snapshot=ctx.snapshot.snapshot_id) == []


def test_module_cannot_handshake_by_swallowing_a_refusal(tmp_path, monkeypatch):
    """A refusing gate must stop the connection, however the refusal arrives."""

    ctx = make_ctx(tmp_path)
    calls = install_fake_tls(monkeypatch)
    monkeypatch.setattr(
        ctx, "gate_active",
        lambda value, verb: (_ for _ in ()).throw(GateRefused("synthetic refusal")),
    )

    summary = tls_probe.TlsProbeModule(ctx).run([webapp()])

    assert calls == []
    assert ctx.graph.store.nodes == {}
    assert summary["refused_by_reason"] == {"synthetic refusal": 1}


# --- the fingerprinted WebApp --------------------------------------------------


def test_webapp_envelope_and_certificate_attrs(tmp_path, monkeypatch):
    ctx, summary, _ = run(tmp_path, monkeypatch, [webapp()])

    node = ctx.graph.store.get(APP)
    assert node is not None and node.type == "WebApp"
    assert node.attrs == {
        "active_probed": True,
        "vhost": HOST,
        "scheme": "https",
        "issuer_cn": ISSUER,
        "subject_cn": HOST,
        "not_before": "2026-01-13T00:00:00+00:00",
        "not_after": "2027-02-11T23:59:59+00:00",
        "serial": "0A1B2C3D4E5F",
        "tls_version": "TLSv1.3",
        "tls_sans": ["api.epicgames.com", "cdn.akamai.net", "fortnite.com",
                     "internal.epicgames.dev", "secure.epicgames.com",
                     "www.epicgames.com"],
    }
    assert node.coverage == {"fingerprinted": True}
    assert node.confidence.log_odds == pytest.approx(tls_probe.HANDSHAKE_LOG_ODDS)
    assert node.confidence.state.value == "observed"  # one source never self-promotes
    assert node.sensitivity == Sensitivity.S0
    assert node.data_subject == "none"
    assert node.provenance.chain[0].tool == "tls_probe"
    assert node.provenance.chain[0].rule_id == "tls-certificate"
    assert node.temporal.first_seen == NOW.isoformat()
    assert summary["webapps"] == 1


def test_the_cert_lands_on_the_https_webapp_even_from_an_http_seed(tmp_path, monkeypatch):
    ctx, _, _ = run(tmp_path, monkeypatch, [webapp(scheme="http")])

    assert ctx.graph.store.get(APP) is not None
    assert ctx.graph.store.get(f"web:http://{HOST}") is None


def test_binding_comes_from_the_gate_and_pins_the_snapshot(tmp_path, monkeypatch):
    ctx, _, _ = run(tmp_path, monkeypatch, [webapp()])

    assert ctx.graph.store.nodes
    for node in ctx.graph.store.nodes.values():
        assert node.scope_binding.verdict == Verdict.IN_SCOPE
        assert node.scope_binding.snapshot_id == ctx.snapshot.snapshot_id
        assert node.scope_binding.observed_at == NOW.isoformat()
    assert ctx.graph.store.get(APP).scope_binding.rule_matched == \
        "included by '*.epicgames.com'"


def test_a_cert_without_optional_fields_omits_those_attrs(tmp_path, monkeypatch):
    bare = {"subject": ((("commonName", HOST),),), "version": 3}
    ctx, summary, _ = run(tmp_path, monkeypatch, [webapp()], bare, version="")

    node = ctx.graph.store.get(APP)
    assert node.attrs == {"active_probed": True, "vhost": HOST, "scheme": "https",
                          "subject_cn": HOST}
    assert summary["sans_seen"] == 0 and summary["candidates_emitted"] == 0


@pytest.mark.parametrize("raw, expected", [
    ("Jan 13 00:00:00 2026 GMT", "2026-01-13T00:00:00+00:00"),
    ("Feb  3 23:59:59 2027 GMT", "2027-02-03T23:59:59+00:00"),
    ("Mar 1 05:00:00 2026 UTC", "2026-03-01T05:00:00+00:00"),
    ("Dec 31 23:59:59 2026", "2026-12-31T23:59:59+00:00"),
    ("not a date", "not a date"),  # kept verbatim, never guessed
    ("", ""),
    (None, ""),
])
def test_cert_time_normalization_is_deterministic_utc(raw, expected):
    assert tls_probe.parse_cert_time(raw) == expected


def test_multi_valued_rdn_takes_the_first_commonname_deterministically():
    rdns = ((("commonName", "first.epicgames.com"),),
            (("commonName", "second.epicgames.com"),))
    assert tls_probe.rdn_value(rdns, "commonName") == "first.epicgames.com"
    assert tls_probe.rdn_value((), "commonName") == ""
    assert tls_probe.rdn_value(("junk", 42, (None,)), "commonName") == ""


# --- SAN pivoting --------------------------------------------------------------


def test_in_scope_sans_become_dns_candidate_hypotheses(tmp_path, monkeypatch):
    ctx, summary, _ = run(tmp_path, monkeypatch, [webapp()])

    assert candidates(ctx) == [
        "hyp:dns-candidate:fortnite.com",        # the '*.' wildcard label is stripped
        "hyp:dns-candidate:www.epicgames.com",
    ]
    node = ctx.graph.store.get("hyp:dns-candidate:www.epicgames.com")
    assert node.type == "Hypothesis"
    assert node.attrs == {"candidate_fqdn": "www.epicgames.com",
                          "generator": "san-pivot", "active_probed": True}
    assert node.coverage == {"enumerated": False}  # explicit negative space
    assert node.confidence.log_odds == pytest.approx(tls_probe.SAN_CANDIDATE_LOG_ODDS)
    assert node.confidence.log_odds <= 0  # an unconfirmed guess is never asserted
    assert node.sensitivity == Sensitivity.S0 and node.data_subject == "none"
    assert summary["candidates_emitted"] == 2

    # The candidate id is the handle the gated resolver uses to confirm or decay it.
    assert node.id.startswith(tls_probe.CANDIDATE_ID_PREFIX)
    assert "candidate_fqdn" in node.attrs  # what resolver._target() reads


def test_no_san_is_ever_asserted_as_a_dnsname_or_connected_by_an_edge(tmp_path,
                                                                      monkeypatch):
    ctx, _, calls = run(tmp_path, monkeypatch, [webapp()])

    assert list(ctx.graph.store.iter_type("DNSName")) == []
    # The only edge this module may draw is WebApp -> Certificate; no SAN-derived
    # node is ever an endpoint.
    assert {e.type for e in ctx.graph.store.edges.values()} <= {"presents_certificate"}
    hyp_ids = {n.id for n in ctx.graph.store.iter_type("Hypothesis")}
    for e in ctx.graph.store.edges.values():
        assert e.frm not in hyp_ids and e.to not in hyp_ids
    assert len(of_kind(calls, "connect")) == 1  # a SAN is never probed in turn


def test_out_of_scope_sans_are_counted_and_logged_but_never_emitted(tmp_path, monkeypatch,
                                                                    caplog):
    with caplog.at_level(logging.INFO, logger="test.tls_probe.tls_probe"):
        ctx, summary, _ = run(tmp_path, monkeypatch, [webapp()])

    assert summary["sans_seen"] == 6
    assert summary["sans_self"] == 1  # the probed host is not proposed back to itself
    assert summary["sans_dropped_out_of_scope"] == 3
    assert summary["sans_dropped_by_verdict"] == {"out_of_scope": 2, "prefilter_only": 1}
    assert "3 out-of-scope SAN(s)" in caplog.text

    for name in ("secure.epicgames.com", "internal.epicgames.dev", "cdn.akamai.net"):
        assert ctx.graph.store.get(f"hyp:dns-candidate:{name}") is None
        assert ctx.graph.store.get(f"dns:{name}") is None
        # kept only as data ABOUT the in-scope node it was observed on
        assert name in ctx.graph.store.get(APP).attrs["tls_sans"]


def test_a_san_already_in_the_graph_is_not_re_raised(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    install_fake_tls(monkeypatch)
    module = tls_probe.TlsProbeModule(ctx)
    first = module.run([webapp()])
    second = module.run([webapp()])

    assert first["candidates_emitted"] == 2
    assert second["candidates_emitted"] == 0
    assert second["sans_already_known"] == 2
    assert candidates(ctx) == [
        "hyp:dns-candidate:fortnite.com", "hyp:dns-candidate:www.epicgames.com",
    ]
    assert all("#fork" not in i for i in ctx.graph.store.nodes)


def test_a_san_confirmed_as_a_dnsname_is_not_re_proposed_as_a_guess(tmp_path, monkeypatch):
    from recon.factory import make_node

    ctx = make_ctx(tmp_path)
    install_fake_tls(monkeypatch)
    ctx.graph.upsert_node(make_node(
        "DNSName", "dns:www.epicgames.com",
        binding=ctx.bind("www.epicgames.com"), source="resolver", now=NOW,
        coverage={"enumerated": True},
    ))

    summary = tls_probe.TlsProbeModule(ctx).run([webapp()])

    assert candidates(ctx) == ["hyp:dns-candidate:fortnite.com"]
    assert summary["sans_already_known"] == 1


def test_candidate_cap_truncates_without_losing_the_record(tmp_path, monkeypatch):
    monkeypatch.setattr(tls_probe, "MAX_CANDIDATES_PER_CERT", 1)
    ctx, summary, _ = run(tmp_path, monkeypatch, [webapp()])

    assert summary["candidates_emitted"] == 1
    assert summary["sans_truncated"] is True
    assert len(candidates(ctx)) == 1
    # nothing is lost: every observed SAN is still recorded on the WebApp
    assert len(ctx.graph.store.get(APP).attrs["tls_sans"]) == 6


def test_san_cap_bounds_a_hostile_certificate(tmp_path, monkeypatch):
    monkeypatch.setattr(tls_probe, "MAX_SANS_PER_CERT", 3)
    many = tuple(f"h{i}.epicgames.com" for i in range(50))
    ctx, summary, _ = run(tmp_path, monkeypatch, [webapp()], cert(sans=many))

    assert summary["sans_seen"] == 3
    assert len(ctx.graph.store.get(APP).attrs["tls_sans"]) == 3


@pytest.mark.parametrize("entry", [
    ("IP Address", "203.0.113.5"),
    ("URI", "https://epicgames.com/cps"),
    ("othername", "junk"),
    ("DNS", ""),
    ("DNS", "not a hostname"),
    ("DNS", "*"),
    ("DNS", "a" * 300 + ".epicgames.com"),
    ("DNS",),
])
def test_non_dns_and_malformed_sans_are_dropped(tmp_path, monkeypatch, entry):
    ctx, summary, _ = run(tmp_path, monkeypatch, [webapp()],
                          cert(sans=(HOST,), extra_sans=(entry,)))

    assert summary["sans_seen"] == 1  # only the host's own DNS SAN survived
    assert ctx.graph.store.get(APP).attrs["tls_sans"] == [HOST]
    assert candidates(ctx) == []
    assert list(ctx.graph.store.iter_type("Host")) == []


def test_dns_sans_are_deduplicated_and_sorted():
    raw = cert(sans=("B.Epicgames.com", "b.epicgames.com.", "*.b.epicgames.com",
                     "a.epicgames.com"))
    assert tls_probe.dns_sans(raw) == ("a.epicgames.com", "b.epicgames.com")


# --- privacy: e-mail fields never reach an attr or the evidence store ----------


def test_email_sans_and_rdns_are_stripped_before_storage(tmp_path, monkeypatch):
    person = "someone.private@epicgames.com"
    ctx, summary, _ = run(
        tmp_path, monkeypatch, [webapp()],
        cert(sans=(HOST,), extra_sans=(("email", person),),
             subject_extra=((("emailAddress", person),),)),
    )

    node = ctx.graph.store.get(APP)
    assert summary["email_fields_dropped"] == 2
    assert person not in repr(node.to_dict())
    blob = ctx.evidence.get(node.evidence[0].sha256).decode("utf-8")
    assert person not in blob and "someone.private" not in blob
    assert "email_fields_dropped=2" in blob  # the omission is explicit and replayable
    assert node.attrs["tls_sans"] == [HOST]
    assert all(n.data_subject == "none" for n in ctx.graph.store.nodes.values())


def test_sanitized_cert_leaves_everything_else_untouched():
    raw = cert(sans=(HOST,), extra_sans=(("email", "a@b.com"),))
    safe, dropped = tls_probe.sanitized_cert(raw)

    assert dropped == 1
    assert safe["subjectAltName"] == (("DNS", HOST),)
    assert safe["serialNumber"] == raw["serialNumber"]
    assert safe["issuer"] == raw["issuer"]
    assert tls_probe.sanitized_cert({}) == ({}, 0)


def test_no_credential_or_token_node_is_ever_minted(tmp_path, monkeypatch):
    ctx, _, _ = run(tmp_path, monkeypatch, [webapp()])

    assert not list(ctx.graph.store.iter_type("Credential"))
    assert not list(ctx.graph.store.iter_type("Token"))
    assert all(n.sensitivity == Sensitivity.S0 for n in ctx.graph.store.nodes.values())


# --- evidence ------------------------------------------------------------------


def test_the_certificate_is_stored_as_content_addressed_evidence(tmp_path, monkeypatch):
    ctx, _, _ = run(tmp_path, monkeypatch, [webapp()])

    safe, _ = tls_probe.sanitized_cert(cert())
    expected = "\n".join([
        "tls_probe/0.1.0 verb=tls-handshake",
        f"host={HOST}:443",
        "tls_version=TLSv1.3",
        "dns_sans=api.epicgames.com,cdn.akamai.net,fortnite.com,"
        "internal.epicgames.dev,secure.epicgames.com,www.epicgames.com",
        "certificate=" + json.dumps(safe, sort_keys=True, default=str),
    ])
    sha = sha256_bytes(expected.encode("utf-8"))

    node = ctx.graph.store.get(APP)
    assert [e.sha256 for e in node.evidence] == [sha]
    assert node.evidence[0].region == f"tls_probe:{HOST}:443"
    assert node.evidence[0].encrypted_at_rest is True
    assert node.provenance.chain[0].evidence_id == sha
    assert ctx.evidence.get(sha).decode("utf-8") == expected
    # every candidate points at the same proof it was derived from
    for candidate_id in candidates(ctx):
        assert [e.sha256 for e in ctx.graph.store.get(candidate_id).evidence] == [sha]


def test_san_order_does_not_change_the_evidence_hash(tmp_path, monkeypatch):
    ctx_a, _, _ = run(tmp_path, monkeypatch, [webapp()], cert(sans=SANS))
    ctx_b, _, _ = run(tmp_path, monkeypatch, [webapp()], cert(sans=tuple(reversed(SANS))))

    assert ([e.sha256 for e in ctx_a.graph.store.get(APP).evidence]
            == [e.sha256 for e in ctx_b.graph.store.get(APP).evidence])


def test_unwritable_evidence_store_does_not_fail_the_probe(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    install_fake_tls(monkeypatch)

    def boom(*args, **kwargs):
        raise OSError("read-only filesystem")

    monkeypatch.setattr(ctx.evidence, "put_text", boom)
    summary = tls_probe.TlsProbeModule(ctx).run([webapp()])

    assert summary["webapps"] == 1 and summary["candidates_emitted"] == 2
    assert ctx.graph.store.get(APP).evidence == []


def test_an_oversized_certificate_blob_is_capped(tmp_path, monkeypatch):
    monkeypatch.setattr(tls_probe, "MAX_CERT_JSON_CHARS", 32)
    assert len(tls_probe.cert_json(cert())) == 32
    assert tls_probe.cert_json({"a": object()}).startswith("{")


# --- failure handling ----------------------------------------------------------


@pytest.mark.parametrize("exc, kind", [
    (ssl.SSLCertVerificationError("expired"), "cert_verification_failed"),
    (ssl.SSLError("handshake failure"), "ssl_error:SSLError"),
    (ssl.SSLZeroReturnError("closed"), "ssl_error:SSLZeroReturnError"),
    (TimeoutError("slow"), "timeout"),
    (RuntimeError("unknown tls stack"), "unexpected:RuntimeError"),
])
def test_handshake_failures_are_classified_and_never_crash(tmp_path, monkeypatch, exc,
                                                           kind):
    ctx, summary, calls = run(tmp_path, monkeypatch, [webapp()], handshake_raises=exc)

    assert len(of_kind(calls, "handshake")) == 1  # one attempt, no retry
    assert ctx.graph.store.nodes == {}
    assert summary["errors"] == 1 and summary["errors_by_kind"] == {kind: 1}
    assert summary["certificates"] == 0
    assert len(ctx.ledger.log) == 1  # the budget was spent, and is recorded as spent


@pytest.mark.parametrize("exc, kind", [
    (ConnectionRefusedError("closed"), "socket_error:ConnectionRefusedError"),
    (socket.gaierror("no such host"), "socket_error:gaierror"),
    (OSError("unreachable"), "socket_error:OSError"),
    (TimeoutError("slow"), "timeout"),
])
def test_connect_failures_are_classified_and_never_crash(tmp_path, monkeypatch, exc, kind):
    ctx, summary, calls = run(tmp_path, monkeypatch, [webapp()], connect_raises=exc)

    assert len(of_kind(calls, "connect")) == 1
    assert of_kind(calls, "handshake") == []
    assert ctx.graph.store.nodes == {}
    assert summary["errors_by_kind"] == {kind: 1}


@pytest.mark.parametrize("peer", [None, {}, "not a dict", 42])
def test_a_missing_peer_certificate_asserts_nothing(tmp_path, monkeypatch, peer):
    ctx, summary, _ = run(tmp_path, monkeypatch, [webapp()], peer)

    assert ctx.graph.store.nodes == {}
    assert summary["errors_by_kind"] == {"no_peer_certificate": 1}
    assert summary["certificates"] == 0


def test_one_dead_host_does_not_stop_the_others(tmp_path, monkeypatch):
    other = "www.fortnite.com"

    def certs(host):
        if host == HOST:
            raise ssl.SSLError("handshake failure")
        return cert(subject_cn=other, sans=(other,))

    ctx, summary, _ = run(tmp_path, monkeypatch, [webapp(), webapp(other)], certs=certs)

    assert sorted(n.id for n in ctx.graph.store.iter_type("WebApp")) == [
        f"web:https://{other}",
    ]
    assert summary["errors"] == 1 and summary["certificates"] == 1


# --- seeds ---------------------------------------------------------------------


def test_empty_and_junk_seeds_are_graceful(tmp_path, monkeypatch):
    for seeds in ([], None, ["", "   ", None, 42, "not a host", "*."]):
        ctx, summary, calls = run(tmp_path, monkeypatch, seeds)
        assert calls == []
        assert summary["hosts"] == [] and summary["webapps"] == 0
        assert ctx.ledger.log == []


def test_foreign_seed_node_types_are_ignored(tmp_path, monkeypatch):
    seeds = [
        FakeNode(f"domain:{HOST}", "Domain"),
        FakeNode("svc:203.0.113.5:443/tcp", "Service"),
        FakeNode("hyp:dns-candidate:api.epicgames.com", "Hypothesis"),
        FakeNode("host:203.0.113.5", "Host"),
        FakeNode(f"web:https://{HOST}", "Route"),
        webapp(),
    ]
    _, summary, calls = run(tmp_path, monkeypatch, seeds)

    assert summary["hosts"] == [HOST]
    assert len(of_kind(calls, "connect")) == 1


@pytest.mark.parametrize("seed", [
    FakeNode("web:https://203.0.113.5", "WebApp"),
    FakeNode("web:https://[2001:db8::1]", "WebApp"),
    FakeNode("dns:203.0.113.5", "DNSName"),
    "203.0.113.5",
])
def test_raw_ip_targets_are_skipped_because_sni_needs_a_name(tmp_path, monkeypatch, seed):
    ctx, summary, calls = run(tmp_path, monkeypatch, [seed])

    assert calls == []  # no handshake, so no budget spent either
    assert summary["hosts"] == [] and summary["seeds_skipped"] == 1
    assert ctx.ledger.log == []


# --- idempotence, forking, invariants -----------------------------------------


def test_rerun_with_the_same_certificate_merges_without_forking(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    install_fake_tls(monkeypatch)
    module = tls_probe.TlsProbeModule(ctx)
    module.run([webapp()])
    module.run([webapp()])

    node = ctx.graph.store.get(APP)
    assert "#fork" not in node.id
    assert [i for i in ctx.graph.store.nodes if "#fork" in i] == []
    assert node.coverage == {"fingerprinted": True}
    assert node.attrs["serial"] == "0A1B2C3D4E5F"
    assert len(node.evidence) == 1  # the same proof is not stored twice


def test_a_rotated_certificate_forks_instead_of_overwriting(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    install_fake_tls(monkeypatch)
    tls_probe.TlsProbeModule(ctx).run([webapp()])
    monkeypatch.undo()
    install_fake_tls(monkeypatch, cert(serial="FFFFFFFF", not_after="Mar 1 00:00:00 2028 GMT"))
    tls_probe.TlsProbeModule(ctx).run([webapp()])

    assert ctx.graph.store.get(APP).attrs["serial"] == "0A1B2C3D4E5F"  # history is kept
    fork = ctx.graph.store.get(f"{APP}#fork1")
    assert fork is not None and fork.attrs["serial"] == "FFFFFFFF"
    assert fork.confidence.forked_from == APP
    assert any(e.kind == "contradiction_forked" for e in ctx.graph.log.all())


def test_a_hypothesis_raised_event_is_logged_once_per_candidate(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    install_fake_tls(monkeypatch)
    module = tls_probe.TlsProbeModule(ctx)
    module.run([webapp()])
    module.run([webapp()])

    raised = [e.payload for e in ctx.graph.log.by_kind("hypothesis_raised")]
    assert [r["candidate_fqdn"] for r in raised] == ["fortnite.com", "www.epicgames.com"]
    assert {r["generator"] for r in raised} == {"san-pivot"}
    assert {r["module"] for r in raised} == {"tls_probe"}
    assert all(r["log_odds"] <= 0 for r in raised)


def test_graph_satisfies_the_safety_invariants(tmp_path, monkeypatch):
    seeds = [webapp(), webapp("www.fortnite.com"), dns("store.epicgames.com"),
             webapp("secure.epicgames.com"), webapp("internal.epicgames.dev"),
             FakeNode("host:203.0.113.5", "Host")]
    ctx, summary, _ = run(tmp_path, monkeypatch, seeds,
                          certs=lambda host: cert(subject_cn=host, sans=(host, *SANS)))

    assert ctx.graph.store.nodes and summary["certificates"] == 3
    assert invariants.check(ctx.graph.store, ledger=ctx.ledger,
                            current_snapshot=ctx.snapshot.snapshot_id) == []
    # every node carries the active-probe marker and an in_scope verdict (I2/I3)
    for node in ctx.graph.store.nodes.values():
        assert node.attrs["active_probed"] is True
        assert node.scope_binding.verdict == Verdict.IN_SCOPE
