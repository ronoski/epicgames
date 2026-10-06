"""Offline, deterministic tests for the ACTIVE ``port_scan`` module.

A port scan is the most intrusive-looking verb on the whitelist, so these tests are built
around the four properties a reviewer cares about: **every single ``(host, port)`` probe is
preceded by its own gate ALLOW**, **a refusal ends that host's scan instead of leaking into
a probe-anyway path**, **only a completed handshake is ever asserted as a fact**, and
**nothing but a connect-then-close happens on the wire** (no banner, no payload, no retry).

Everything is offline by construction: an autouse fixture turns every real socket/TLS/HTTP
primitive into a landmine, ``socket.create_connection`` is replaced by an in-memory port
table that records exactly what was dialed, the returned fake socket has **no send/receive
methods at all** (so a banner-grab regression raises instead of succeeding), time is
injected via ``ModuleContext.now`` and the rate ledger runs on a frozen monotonic clock. No
test may contact any host — least of all an Epic one.
"""

from __future__ import annotations

import errno
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
from recon.modules.active import port_scan
from recon.modules.base import GateRefused, ModuleContext, get_module
from recon.ratelimit import RateLedger
from recon.scope import Scope
from recon.snapshot import take_snapshot
from recon.store import Graph

NOW = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)

INCLUDE = ["203.0.113.0/24", "2001:db8::/32", "*.epicgames.com"]  # TEST-NET-3 stands in
EXCLUDE = ["203.0.113.9"]                                         # a /32 exclusion wins
PREFILTER = ["198.51.100.0/24"]                                   # owned-but-unlisted

IP = "203.0.113.5"
OTHER_IP = "203.0.113.6"
EXCLUDED_IP = "203.0.113.9"
OUT_OF_SCOPE_IP = "192.0.2.5"   # TEST-NET-1: matched by no rule (default deny)
PREFILTER_IP = "198.51.100.7"   # TEST-NET-2: owned, unlisted
IPV6 = "2001:db8::1"


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


class FakeSocket:
    """A connected socket that can only be closed.

    It deliberately has no ``send``/``recv``/``sendall``/``makefile`` attribute: the module
    is contractually forbidden from writing or reading a byte, so a regression that tries
    raises ``AttributeError`` instead of quietly grabbing a banner.
    """

    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


class FakeNode:
    """Minimal stand-in for a graph Node seed (only id/type/attrs are read)."""

    def __init__(self, id: str, type: str = "Host", attrs: dict | None = None) -> None:
        self.id = id
        self.type = type
        self.attrs = attrs if attrs is not None else {}


def host(ip: str = IP, **attrs) -> FakeNode:
    return FakeNode(f"host:{ip}", "Host", dict(attrs))


def refused() -> ConnectionRefusedError:
    """A definite closed port."""

    return ConnectionRefusedError(errno.ECONNREFUSED, "Connection refused")


def timed_out() -> TimeoutError:
    """A filtered port: the connect simply never completed."""

    return TimeoutError("timed out")


def unreachable() -> OSError:
    """The whole address is unreachable from here."""

    return OSError(errno.EHOSTUNREACH, "No route to host")


def reset() -> ConnectionResetError:
    return ConnectionResetError(errno.ECONNRESET, "Connection reset by peer")


def make_ctx(tmp_path, *, include=None, exclude=None, prefilter=None, snapshot="fresh",
             now=NOW, allow_active=True, capacity=50.0, timeout=8.0) -> ModuleContext:
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
        # Frozen monotonic clock: the token bucket never refills mid-test.
        ledger=RateLedger(global_qps=2.0, capacity=capacity, clock=lambda: 0.0),
        evidence=EvidenceStore(tmp_path / "evidence"),
        graph=Graph(log=EventLog()),
        snapshot=snap,
        logger=logging.getLogger("recon.test.port_scan"),
        allow_active=allow_active,
        timeout=timeout,
        now=now,
    )


def install(monkeypatch, table: dict | None = None, *, trace: list | None = None,
            sockets: list | None = None) -> list[dict]:
    """Replace the connect primitive with an in-memory port table.

    ``table`` maps ``{ip: {port: "open" | Exception}}``; anything unlisted is a refused
    (closed) port. Returns the list of dials actually made.
    """

    calls: list[dict] = []

    def fake_create_connection(address, timeout=None, **kwargs):
        ip, port = address[0], address[1]
        calls.append({"ip": ip, "port": port, "timeout": timeout, "extra": dict(kwargs)})
        if trace is not None:
            trace.append(("probe", ip, port))
        outcome = (table or {}).get(ip, {}).get(port, refused())
        if isinstance(outcome, BaseException):
            raise outcome
        assert outcome == "open", f"unsupported fake outcome {outcome!r}"
        sock = FakeSocket()
        if sockets is not None:
            sockets.append(sock)
        return sock

    monkeypatch.setattr(socket, "create_connection", fake_create_connection)
    return calls


def spy_gate(ctx, trace: list) -> None:
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


def landmine(monkeypatch) -> None:
    """Make any dial an immediate test failure."""

    def boom(*args, **kwargs):  # pragma: no cover - only runs on a violation
        raise AssertionError("probed a value the gate refused")

    monkeypatch.setattr(socket, "create_connection", boom)


def run(tmp_path, monkeypatch, seeds, table=None, **kw):
    ctx = make_ctx(tmp_path, **kw)
    calls = install(monkeypatch, table or {})
    summary = port_scan.PortScanModule(ctx).run(seeds)
    return ctx, summary, calls


def seed_host(ctx, ip: str = IP, **attrs):
    """Put a Host node (as the resolver would) in the graph and return it."""

    ctx.graph.upsert_node(make_node(
        "Host", f"host:{ip}", binding=ctx.bind(ip), source="resolver", now=NOW,
        attrs={"active_probed": True, **attrs}, log_odds=2.0,
        coverage={"enumerated": False},
    ))
    return ctx.graph.store.get(f"host:{ip}")


def allow_records(ctx) -> list[dict]:
    return [e.payload for e in ctx.graph.log.by_kind("gate_decision_recorded")
            if e.payload["decision"] == "ALLOW"]


def refuse_records(ctx) -> list[dict]:
    return [e.payload for e in ctx.graph.log.by_kind("gate_decision_recorded")
            if e.payload["decision"] == "REFUSE"]


def dialed(calls: list) -> list[tuple[str, int]]:
    return [(c["ip"], c["port"]) for c in calls]


@pytest.fixture
def two_ports(monkeypatch):
    """Shrink the curated list so per-probe assertions stay readable."""

    monkeypatch.setattr(port_scan, "PORTS", (80, 443))


# --- registration & contract ---------------------------------------------------


def test_registered_under_its_filename_and_is_active():
    assert get_module("port_scan") is port_scan.PortScanModule
    assert port_scan.PortScanModule.name == "port_scan"
    assert Path(port_scan.__file__).name == "port_scan.py"
    assert port_scan.PortScanModule.active is True
    assert set(port_scan.PortScanModule.produces) <= ontology.node_types()
    assert set(port_scan.PortScanModule.produces) == {"Service"}


def test_verb_is_whitelisted_and_active():
    assert port_scan.VERB == "port-scan"
    assert port_scan.VERB in verbs.ALLOWED
    assert port_scan.VERB in verbs.ACTIVE
    assert port_scan.VERB not in verbs.BLOCKED
    assert port_scan.VERB not in verbs.HUMAN_GATED
    verbs.assert_schedulable(port_scan.VERB)


@pytest.mark.parametrize("verb", ["dos", "fuzz-at-volume", "exploit", "waf-evasion"])
def test_intrusive_neighbours_of_this_verb_are_never_schedulable(verb):
    assert verb in verbs.BLOCKED
    with pytest.raises(verbs.BlockedVerb):
        verbs.assert_schedulable(verb)


def test_one_connect_call_site_and_no_other_network_machinery():
    """The module's only touch is a single ``create_connection`` call site."""

    src = Path(port_scan.__file__).read_text(encoding="utf-8")
    assert src.count("create_connection(") == 1
    for token in ("import requests", "requests.", "import urllib", "import http",
                  "subprocess", "SOCK_RAW", "IPPROTO", "sendall", ".send(", ".recv(",
                  "makefile", "socket.socket", "getaddrinfo", "gethostbyname",
                  "while True", "sleep(", "ssl."):
        assert token not in src, f"port_scan must not reference {token!r}"


def test_port_list_is_small_curated_and_capped():
    assert isinstance(port_scan.PORTS, tuple)
    assert port_scan.PORTS == (80, 443, 8080, 8443, 22, 25, 53, 3389, 5432, 6379)
    assert len(port_scan.PORTS) <= port_scan.MAX_PORTS_PER_HOST <= 16
    assert all(1 <= p <= 65535 for p in port_scan.PORTS)
    assert len(set(port_scan.PORTS)) == len(port_scan.PORTS)
    assert port_scan.scan_ports() == port_scan.PORTS


def test_scan_ports_validates_dedupes_and_caps():
    assert port_scan.scan_ports((80, "443", 80, 0, 70000, None, "x", 22)) == (80, 443, 22)
    assert port_scan.scan_ports(limit=3) == port_scan.PORTS[:3]
    assert port_scan.scan_ports((), limit=5) == ()
    assert port_scan.scan_ports(None, limit=0) == ()
    assert port_scan.scan_ports(range(1, 100)) == tuple(range(1, 1 + port_scan.MAX_PORTS_PER_HOST))


def test_the_port_cap_is_logged_on_every_run(tmp_path, monkeypatch, caplog):
    caplog.set_level(logging.INFO, logger="recon.test.port_scan")
    monkeypatch.setattr(port_scan, "MAX_PORTS_PER_HOST", 2)
    ctx, summary, calls = run(tmp_path, monkeypatch, [])

    assert summary["ports"] == [80, 443] and summary["ports_capped"] is True
    assert "capped at 2 of 10 port(s) per host" in caplog.text
    assert calls == []


def test_open_port_confidence_is_asserted_but_not_self_promoting():
    assert 0 < port_scan.OPEN_LOG_ODDS < 2.2  # one source never promotes itself


# --- the gate: one ALLOW per (host, port), always before the connect ------------


def test_every_connect_is_preceded_by_its_own_gate_allow(tmp_path, monkeypatch, two_ports):
    ctx = make_ctx(tmp_path)
    trace: list = []
    spy_gate(ctx, trace)
    install(monkeypatch, {IP: {80: "open"}}, trace=trace)

    port_scan.PortScanModule(ctx).run([host(IP)])

    assert trace == [
        ("allowed", IP), ("probe", IP, 80),
        ("allowed", IP), ("probe", IP, 443),
    ]


def test_each_port_pair_is_gated_and_debited_separately(tmp_path, monkeypatch, two_ports):
    ctx, summary, calls = run(tmp_path, monkeypatch, [host(IP)], {IP: {443: "open"}})

    assert dialed(calls) == [(IP, 80), (IP, 443)]
    allows = allow_records(ctx)
    assert [a["decision"] for a in allows] == ["ALLOW", "ALLOW"]
    assert allows[0] == {"decision": "ALLOW", "value": IP, "verb": "port-scan",
                         "rule": "included by '203.0.113.0/24'"}
    debits = [e.payload for e in ctx.graph.log.by_kind("rate_debit")]
    assert len(debits) == 2 and {d["target"] for d in debits} == {IP}
    assert [e.verb for e in ctx.ledger.log] == ["port-scan", "port-scan"]
    assert ctx.ledger.balance(IP) == pytest.approx(ctx.ledger.capacity - 2)
    assert summary["gated"] == 2 and summary["probed"] == 2 and summary["refused"] == 0


def test_active_disabled_refuses_and_dials_nothing(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path, allow_active=False)
    landmine(monkeypatch)

    summary = port_scan.PortScanModule(ctx).run([host(IP)])

    assert summary["probed"] == 0 and summary["refused"] == 1
    assert "allow_active=false" in next(iter(summary["refused_by_reason"]))
    assert summary["hosts_refused_outright"] == 1 and summary["hosts_scanned"] == 0
    assert ctx.graph.store.nodes == {} and ctx.graph.store.edges == {}
    assert ctx.ledger.log == []
    assert [r["decision"] for r in refuse_records(ctx)] == ["REFUSE"]


@pytest.mark.parametrize("snapshot,expected", [
    (None, "no scope snapshot"),
    ("stale", "stale"),
])
def test_missing_or_stale_snapshot_refuses_and_dials_nothing(tmp_path, monkeypatch,
                                                             snapshot, expected):
    ctx = make_ctx(tmp_path, snapshot=snapshot)
    landmine(monkeypatch)

    summary = port_scan.PortScanModule(ctx).run([host(IP)])

    assert summary["probed"] == 0 and summary["refused"] == 1
    assert expected in next(iter(summary["refused_by_reason"]))
    assert ctx.graph.store.nodes == {}


@pytest.mark.parametrize("ip,verdict", [
    (EXCLUDED_IP, "out_of_scope"),      # exclude wins
    (OUT_OF_SCOPE_IP, "out_of_scope"),  # default deny
    (PREFILTER_IP, "prefilter_only"),   # owned but unlisted: never actively touched
])
def test_non_in_scope_hosts_are_refused_not_scanned(tmp_path, monkeypatch, ip, verdict):
    ctx = make_ctx(tmp_path)
    landmine(monkeypatch)

    summary = port_scan.PortScanModule(ctx).run([host(ip)])

    assert summary["refused"] == 1 and summary["probed"] == 0
    assert verdict in next(iter(summary["refused_by_reason"]))
    assert ctx.graph.store.nodes == {} and ctx.graph.store.edges == {}
    assert ctx.ledger.log == []  # a refused gate never debits


def test_one_refusal_per_host_not_one_per_remaining_port(tmp_path, monkeypatch):
    """A refusal ends that host's scan, so an out-of-scope host costs one record."""

    ctx = make_ctx(tmp_path)
    landmine(monkeypatch)

    summary = port_scan.PortScanModule(ctx).run([host(OUT_OF_SCOPE_IP)])

    assert summary["gated"] == 1 and summary["refused"] == 1
    assert len(refuse_records(ctx)) == 1


def test_exhausted_budget_cuts_that_host_short_and_moves_to_the_next(tmp_path, monkeypatch):
    """Each address is its own ledger target, and neither host borrows from the other."""

    monkeypatch.setattr(port_scan, "PORTS", (80, 443, 8080))
    ctx, summary, calls = run(
        tmp_path, monkeypatch, [host(IP), host(OTHER_IP)],
        {IP: {80: "open"}, OTHER_IP: {443: "open"}},
        capacity=2.0,  # two probes per target, then the gate fails closed
    )

    assert dialed(calls) == [(IP, 80), (IP, 443), (OTHER_IP, 80), (OTHER_IP, 443)]
    assert summary["probed"] == 4 and summary["refused"] == 2
    assert summary["hosts_cut_short"] == 2 and summary["hosts_refused_outright"] == 0
    assert "rate budget exceeded" in next(iter(summary["refused_by_reason"]))
    assert all(e.balance_after >= 0 for e in ctx.ledger.log)
    # the partial observation is still kept: an open port found before the cut is a fact
    assert set(ctx.graph.store.nodes) == {f"svc:{IP}:80/tcp", f"svc:{OTHER_IP}:443/tcp"}


def test_module_cannot_probe_by_swallowing_a_refusal(tmp_path, monkeypatch):
    """A refusing gate must stop the connect, however the refusal arrives."""

    ctx = make_ctx(tmp_path)
    calls = install(monkeypatch, {IP: {80: "open"}})
    monkeypatch.setattr(
        ctx, "gate_active",
        lambda value, verb: (_ for _ in ()).throw(GateRefused("synthetic refusal")),
    )

    summary = port_scan.PortScanModule(ctx).run([host(IP), host(OTHER_IP)])

    assert calls == []
    assert ctx.graph.store.nodes == {} and ctx.graph.store.edges == {}
    assert summary["refused_by_reason"] == {"synthetic refusal": 2}
    assert summary["services_emitted"] == 0


def test_a_refused_host_does_not_stop_the_others(tmp_path, monkeypatch, two_ports):
    ctx, summary, calls = run(
        tmp_path, monkeypatch, [host(OUT_OF_SCOPE_IP), host(IP)], {IP: {443: "open"}},
    )

    assert dialed(calls) == [(IP, 80), (IP, 443)]
    assert summary["refused"] == 1 and summary["open"] == 1
    assert f"svc:{IP}:443/tcp" in ctx.graph.store.nodes


# --- the probe itself: a connect, then close, and nothing else -------------------


def test_connect_shape_is_short_single_and_payload_free(tmp_path, monkeypatch, two_ports):
    ctx = make_ctx(tmp_path, timeout=8.0)
    sockets: list[FakeSocket] = []
    calls = install(monkeypatch, {IP: {80: "open", 443: "open"}}, sockets=sockets)

    port_scan.PortScanModule(ctx).run([host(IP)])

    assert [c["timeout"] for c in calls] == [2.0, 2.0]  # min(ctx.timeout, 2.0)
    assert all(c["extra"] == {} for c in calls)          # no source_address, no extras
    assert len(sockets) == 2 and all(s.closed for s in sockets)
    for name in ("send", "sendall", "recv", "makefile"):
        assert not hasattr(sockets[0], name), "the probe must never read or write bytes"


@pytest.mark.parametrize("given,expected", [
    (8.0, 2.0), (2.0, 2.0), (1.0, 1.0), (0.5, 0.5), (0.1, 0.25),
    (0, 0.25), (-5, 0.25), (None, 2.0), ("nonsense", 2.0), (float("nan"), 0.25),
])
def test_connect_timeout_is_clamped_short(given, expected):
    assert port_scan.connect_timeout(given) == pytest.approx(expected)
    assert port_scan.connect_timeout(given) <= port_scan.CONNECT_TIMEOUT_CEILING


def test_connect_outcome_classification():
    assert port_scan.connect_outcome(refused()) == "closed"
    assert port_scan.connect_outcome(reset()) == "closed"
    assert port_scan.connect_outcome(timed_out()) == "filtered"
    assert port_scan.connect_outcome(socket.timeout("timed out")) == "filtered"
    assert port_scan.connect_outcome(unreachable()) == "unreachable"
    assert port_scan.connect_outcome(OSError(errno.ENETUNREACH, "no net")) == "unreachable"
    assert port_scan.connect_outcome(OSError("no errno")) == "error:OSError"


def test_closed_filtered_and_reset_ports_emit_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(port_scan, "PORTS", (80, 443, 8080))
    ctx, summary, calls = run(
        tmp_path, monkeypatch, [host(IP)],
        {IP: {80: refused(), 443: timed_out(), 8080: reset()}},
    )

    assert dialed(calls) == [(IP, 80), (IP, 443), (IP, 8080)]
    assert summary["open"] == 0 and summary["closed"] == 2 and summary["filtered"] == 1
    assert ctx.graph.store.nodes == {} and ctx.graph.store.edges == {}
    assert summary["services_emitted"] == 0
    assert len(ctx.ledger.log) == 3  # the budget was spent whatever the answer was


def test_unreachable_host_abandons_its_remaining_ports(tmp_path, monkeypatch):
    monkeypatch.setattr(port_scan, "PORTS", (80, 443, 8080))
    ctx, summary, calls = run(
        tmp_path, monkeypatch, [host(IP), host(OTHER_IP)],
        {IP: {80: unreachable()}, OTHER_IP: {80: "open"}},
    )

    assert dialed(calls) == [(IP, 80), (OTHER_IP, 80), (OTHER_IP, 443), (OTHER_IP, 8080)]
    assert summary["hosts_unreachable"] == 1
    assert ctx.graph.store.get(f"svc:{OTHER_IP}:80/tcp") is not None


@pytest.mark.parametrize("exc", [
    OSError("socket layer closed"),
    OSError(errno.EINVAL, "invalid argument"),
    RuntimeError("exotic socket stack"),
    ValueError("bad address tuple"),
])
def test_socket_errors_log_and_continue_without_crashing(tmp_path, monkeypatch, exc,
                                                         two_ports):
    ctx, summary, calls = run(
        tmp_path, monkeypatch, [host(IP), host(OTHER_IP)],
        {IP: {80: exc}, OTHER_IP: {80: "open"}},
    )

    assert dialed(calls) == [(IP, 80), (IP, 443), (OTHER_IP, 80), (OTHER_IP, 443)]
    assert summary["errors"] == 1 and sum(summary["errors_by_kind"].values()) == 1
    assert summary["open"] == 1
    assert ctx.graph.store.get(f"svc:{OTHER_IP}:80/tcp") is not None


def test_one_bad_port_does_not_stop_the_rest_of_the_host(tmp_path, monkeypatch):
    monkeypatch.setattr(port_scan, "PORTS", (80, 443))
    ctx, summary, _ = run(
        tmp_path, monkeypatch, [host(IP)],
        {IP: {80: OSError("weird"), 443: "open"}},
    )

    assert summary["errors"] == 1 and summary["open"] == 1
    assert list(ctx.graph.store.nodes) == [f"svc:{IP}:443/tcp"]


# --- what an open port becomes --------------------------------------------------


def test_open_port_becomes_a_service_with_a_hosted_on_edge(tmp_path, monkeypatch, two_ports):
    ctx = make_ctx(tmp_path)
    seed_host(ctx, IP)
    install(monkeypatch, {IP: {443: "open"}})

    summary = port_scan.PortScanModule(ctx).run([ctx.graph.store.get(f"host:{IP}")])

    service = ctx.graph.store.get(f"svc:{IP}:443/tcp")
    assert service is not None and service.type == "Service"
    assert service.attrs == {
        "active_probed": True, "state": "open",
        "ip": IP, "port": 443, "proto": "tcp",
    }
    assert service.coverage == {"enumerated": True}  # listening; nothing fingerprinted
    assert service.confidence.log_odds == pytest.approx(port_scan.OPEN_LOG_ODDS)
    assert service.sensitivity == Sensitivity.S0 and service.data_subject == "none"
    assert service.provenance.chain[0].tool == "port_scan"
    assert service.provenance.chain[0].rule_id == port_scan.RULE_ID
    assert service.provenance.chain[0].rule_version == port_scan.RULE_VERSION
    assert service.temporal.first_seen == NOW.isoformat()
    assert service.temporal.last_verified == NOW.isoformat()

    edge = ctx.graph.store.edges[f"hosted_on:svc:{IP}:443/tcp->host:{IP}"]
    assert edge.type == "hosted_on"
    assert edge.frm == f"svc:{IP}:443/tcp" and edge.to == f"host:{IP}"
    assert edge.attrs == {"active_probed": True}
    assert summary["services_emitted"] == 1 and summary["hosted_on_edges"] == 1
    assert summary["edges_skipped_missing_host"] == 0


def test_several_open_ports_each_become_their_own_service(tmp_path, monkeypatch):
    monkeypatch.setattr(port_scan, "PORTS", (80, 443, 22))
    ctx = make_ctx(tmp_path)
    seed_host(ctx, IP)
    install(monkeypatch, {IP: {80: "open", 443: "open", 22: refused()}})

    summary = port_scan.PortScanModule(ctx).run([host(IP)])

    assert {n.id for n in ctx.graph.store.iter_type("Service")} == {
        f"svc:{IP}:80/tcp", f"svc:{IP}:443/tcp",
    }
    assert len(ctx.graph.store.edges) == 2
    assert summary["open"] == 2 and summary["closed"] == 1


def test_every_emitted_datum_is_in_scope_bound_to_the_current_snapshot(tmp_path, monkeypatch,
                                                                       two_ports):
    ctx = make_ctx(tmp_path)
    seed_host(ctx, IP)
    install(monkeypatch, {IP: {80: "open", 443: "open"}})

    port_scan.PortScanModule(ctx).run([host(IP)])

    data = (list(ctx.graph.store.iter_type("Service"))
            + list(ctx.graph.store.edges.values()))
    assert data
    for datum in data:
        assert datum.scope_binding.verdict == Verdict.IN_SCOPE
        assert datum.scope_binding.snapshot_id == ctx.snapshot.snapshot_id
        assert datum.scope_binding.rule_matched == "included by '203.0.113.0/24'"
        assert datum.scope_binding.observed_at == NOW.isoformat()


def test_service_for_an_unknown_host_is_emitted_without_a_dangling_edge(tmp_path,
                                                                       monkeypatch,
                                                                       two_ports):
    """No ``hosted_on`` edge is minted toward a Host the graph does not hold."""

    ctx, summary, _ = run(tmp_path, monkeypatch, [IP], {IP: {80: "open"}})

    assert ctx.graph.store.get(f"svc:{IP}:80/tcp") is not None
    assert ctx.graph.store.edges == {}
    assert summary["services_emitted"] == 1 and summary["hosted_on_edges"] == 0
    assert summary["edges_skipped_missing_host"] == 1


def test_no_edge_endpoint_is_missing_or_out_of_scope(tmp_path, monkeypatch, two_ports):
    ctx = make_ctx(tmp_path)
    seed_host(ctx, IP)
    install(monkeypatch, {IP: {80: "open"}})

    port_scan.PortScanModule(ctx).run([host(IP)])

    assert ctx.graph.store.edges
    for edge in ctx.graph.store.edges.values():
        for endpoint in (edge.frm, edge.to):
            node = ctx.graph.store.get(endpoint)
            assert node is not None, f"edge {edge.id} points at a missing node"
            assert node.scope_binding.verdict == Verdict.IN_SCOPE
            assert node.data_subject != "other"


def test_ipv6_host_is_scanned_and_its_parts_stay_readable(tmp_path, monkeypatch, two_ports):
    ctx = make_ctx(tmp_path)
    seed_host(ctx, IPV6)
    calls = install(monkeypatch, {IPV6: {443: "open"}})

    summary = port_scan.PortScanModule(ctx).run([host(IPV6)])

    assert dialed(calls) == [(IPV6, 80), (IPV6, 443)]
    service = ctx.graph.store.get(f"svc:{IPV6}:443/tcp")
    assert service is not None
    assert service.attrs["ip"] == IPV6 and service.attrs["port"] == 443
    assert f"hosted_on:svc:{IPV6}:443/tcp->host:{IPV6}" in ctx.graph.store.edges
    assert summary["services_emitted"] == 1


def test_only_declared_ontology_types_are_emitted(tmp_path, monkeypatch, two_ports):
    ctx = make_ctx(tmp_path)
    seed_host(ctx, IP)
    install(monkeypatch, {IP: {80: "open", 443: "open"}})

    port_scan.PortScanModule(ctx).run([host(IP)])

    assert ctx.graph.store.nodes and ctx.graph.store.edges
    for node in ctx.graph.store.nodes.values():
        assert node.type in ontology.node_types()
    for edge in ctx.graph.store.edges.values():
        assert edge.type in ontology.edge_types()
        assert edge.type not in ontology.proposed_edges()
    assert {e.type for e in ctx.graph.store.edges.values()} == {"hosted_on"}


def test_no_credential_token_or_other_person_datum_is_ever_minted(tmp_path, monkeypatch,
                                                                  two_ports):
    ctx = make_ctx(tmp_path)
    seed_host(ctx, IP)
    install(monkeypatch, {IP: {80: "open", 443: "open"}})

    port_scan.PortScanModule(ctx).run([host(IP)])

    for node in ctx.graph.store.iter_type("Service"):
        assert node.type not in ("Credential", "Token")
        assert node.sensitivity == Sensitivity.S0
        assert node.data_subject == "none"
        # port state only: nothing read off the wire can land in an attr
        assert set(node.attrs) == {"active_probed", "state", "ip", "port", "proto"}


def test_graph_satisfies_the_safety_invariants(tmp_path, monkeypatch, two_ports):
    ctx = make_ctx(tmp_path)
    seed_host(ctx, IP)
    seed_host(ctx, OTHER_IP)
    install(monkeypatch, {IP: {80: "open"}, OTHER_IP: {443: "open"}})

    port_scan.PortScanModule(ctx).run([
        host(IP),
        host(OTHER_IP),
        host(PREFILTER_IP),     # refused by the gate
        host(OUT_OF_SCOPE_IP),  # refused by the gate
    ])

    assert ctx.graph.store.nodes
    assert invariants.check(ctx.graph.store, ledger=ctx.ledger,
                            current_snapshot=ctx.snapshot.snapshot_id) == []


def test_rerun_merges_without_forking(tmp_path, monkeypatch, two_ports):
    ctx = make_ctx(tmp_path)
    seed_host(ctx, IP)
    install(monkeypatch, {IP: {80: "open"}})
    module = port_scan.PortScanModule(ctx)

    first = module.run([host(IP)])
    ids_after_first = set(ctx.graph.store.nodes)
    second = module.run([host(IP)])

    assert first["open"] == second["open"] == 1
    assert set(ctx.graph.store.nodes) == ids_after_first
    assert not any("#fork" in node_id for node_id in ctx.graph.store.nodes)
    assert not any("#fork" in edge_id for edge_id in ctx.graph.store.edges)
    assert len(ctx.ledger.log) == 4  # each run pays for its own two probes


# --- evidence -------------------------------------------------------------------


def test_scan_record_is_content_addressed_and_replayable(tmp_path, monkeypatch):
    monkeypatch.setattr(port_scan, "PORTS", (80, 443, 8080))
    ctx, _, _ = run(
        tmp_path, monkeypatch, [host(IP)],
        {IP: {443: "open", 8080: "open"}}, timeout=1.0,
    )

    service = ctx.graph.store.get(f"svc:{IP}:443/tcp")
    ref = service.evidence[0]
    assert ref.region == f"port_scan:{IP}"
    assert ref.encrypted_at_rest
    assert service.provenance.chain[0].evidence_id == ref.sha256

    record = ctx.evidence.get(ref.sha256).decode("utf-8")
    assert record.splitlines() == [
        f"port_scan/{port_scan.RULE_VERSION} verb=port-scan",
        f"target={IP}",
        "proto=tcp",
        "timeout=1.00",
        "result=complete",
        "ports_probed=80,443,8080",
        "open=443,8080",
    ]
    assert sha256_bytes(record.encode("utf-8")) == ref.sha256
    # every service from one host's scan points at that one blob
    assert {n.evidence[0].sha256 for n in ctx.graph.store.iter_type("Service")} == {ref.sha256}


def test_a_budget_cut_scan_records_that_it_is_partial(tmp_path, monkeypatch):
    monkeypatch.setattr(port_scan, "PORTS", (80, 443, 8080))
    ctx, summary, _ = run(
        tmp_path, monkeypatch, [host(IP)], {IP: {80: "open"}}, capacity=2.0,
    )

    service = ctx.graph.store.get(f"svc:{IP}:80/tcp")
    record = ctx.evidence.get(service.evidence[0].sha256).decode("utf-8")
    assert "result=partial:refused" in record
    assert "ports_probed=80,443" in record and "open=80" in record
    assert summary["hosts_cut_short"] == 1


def test_an_unchanged_host_re_scans_to_the_same_evidence_hash(tmp_path, monkeypatch,
                                                              two_ports):
    table = {IP: {80: "open", 443: refused()}}
    ctx_a, summary_a, _ = run(tmp_path / "a", monkeypatch, [host(IP)], table)
    ctx_b, summary_b, _ = run(tmp_path / "b", monkeypatch, [host(IP)], table)

    assert list(ctx_a.graph.store.nodes) == list(ctx_b.graph.store.nodes)
    assert summary_a == summary_b
    sha_a = ctx_a.graph.store.get(f"svc:{IP}:80/tcp").evidence[0].sha256
    sha_b = ctx_b.graph.store.get(f"svc:{IP}:80/tcp").evidence[0].sha256
    assert sha_a == sha_b


def test_unwritable_evidence_store_does_not_crash_the_run(tmp_path, monkeypatch, two_ports):
    ctx = make_ctx(tmp_path)
    seed_host(ctx, IP)
    install(monkeypatch, {IP: {80: "open"}})

    def boom(*args, **kwargs):
        raise OSError("read-only evidence store")

    monkeypatch.setattr(ctx.evidence, "put_text", boom)
    summary = port_scan.PortScanModule(ctx).run([host(IP)])

    assert summary["services_emitted"] == 1 and summary["hosted_on_edges"] == 1
    assert ctx.graph.store.get(f"svc:{IP}:80/tcp").evidence == []


# --- defensiveness --------------------------------------------------------------


@pytest.mark.parametrize("seeds", [[], None, ["", "   ", None, 42, object()]])
def test_empty_and_junk_seeds_are_graceful(tmp_path, monkeypatch, seeds):
    ctx, summary, calls = run(tmp_path, monkeypatch, seeds)

    assert calls == [] and ctx.ledger.log == []
    assert ctx.graph.store.nodes == {}
    assert summary["seeds_used"] == 0 and summary["gated"] == 0


def test_unsupported_seed_kinds_are_ignored(tmp_path, monkeypatch, two_ports):
    seeds = [
        FakeNode("dns:api.epicgames.com", "DNSName"),
        FakeNode("web:https://api.epicgames.com", "WebApp"),
        FakeNode("net:203.0.113.0/24", "NetBlock"),
        FakeNode(f"svc:{IP}:80/tcp", "Service"),
        FakeNode("host:api.epicgames.com"),   # a hostname is not a scannable address
        FakeNode("host:203.0.113.0/24"),      # a range is never expanded into a sweep
        FakeNode("host:not-an-ip"),
        FakeNode(f"host:{IP}%eth0"),          # a scoped literal is not a target
        f"host:{IP}",                         # the one usable seed (a plain string id)
    ]
    ctx, summary, calls = run(tmp_path, monkeypatch, seeds, {IP: {80: "open"}})

    assert dialed(calls) == [(IP, 80), (IP, 443)]
    assert summary["seeds_in"] == 9 and summary["seeds_used"] == 1
    assert summary["seeds_skipped"] == 8


def test_duplicate_hosts_are_scanned_once(tmp_path, monkeypatch, two_ports):
    ctx, summary, calls = run(
        tmp_path, monkeypatch,
        [host(IP), f"host:{IP}", IP, FakeNode(f"host:[{IP}]")],
        {IP: {80: "open"}},
    )

    assert dialed(calls) == [(IP, 80), (IP, 443)]
    assert summary["seeds_deduped"] == 3 and len(ctx.ledger.log) == 2


def test_seed_host_list_is_capped_to_bound_active_spend(tmp_path, monkeypatch, two_ports):
    monkeypatch.setattr(port_scan, "MAX_SEED_HOSTS", 2)
    ips = [f"203.0.113.{i}" for i in (11, 12, 13, 14)]
    ctx, summary, calls = run(
        tmp_path, monkeypatch, [host(ip) for ip in ips],
        {ip: {80: "open"} for ip in ips},
    )

    assert {ip for ip, _ in dialed(calls)} == set(ips[:2])
    assert summary["seeds_used"] == 2 and summary["seeds_truncated"] is True
    assert len(ctx.ledger.log) == 4


@pytest.mark.parametrize("attrs", [
    {"shared_tenant": True},
    {"cdn_or_waf": "cloudflare"},
    {"provider": "aws"},
    {"fronted_by": "akamai"},
])
def test_shared_tenant_hosts_are_never_scanned_as_epics(tmp_path, monkeypatch, attrs):
    """One provider IP fronts many tenants; it is not Epic's to scan."""

    ctx = make_ctx(tmp_path)
    landmine(monkeypatch)

    summary = port_scan.PortScanModule(ctx).run([host(IP, **attrs)])

    assert summary["skipped_shared_tenant"] == 1 and summary["gated"] == 0
    assert ctx.ledger.log == [] and ctx.graph.store.nodes == {}
    assert refuse_records(ctx) == []  # dropped before the gate: no budget, no record


def test_a_fronted_by_edge_in_the_graph_also_stops_the_scan(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    node = seed_host(ctx, IP)
    ctx.graph.upsert_node(make_node("WebApp", "web:https://api.epicgames.com",
                                    binding=ctx.bind("api.epicgames.com"),
                                    source="http_probe", now=NOW))
    ctx.graph.upsert_edge(make_edge("fronted_by", f"host:{IP}",
                                    "web:https://api.epicgames.com",
                                    binding=node.scope_binding, source="http_probe",
                                    now=NOW))
    landmine(monkeypatch)

    summary = port_scan.PortScanModule(ctx).run([node])

    assert summary["skipped_shared_tenant"] == 1 and summary["probed"] == 0
    assert ctx.ledger.log == []


@pytest.mark.parametrize("ip", ["127.0.0.1", "::1", "fe80::1", "224.0.0.1", "0.0.0.0",
                                "240.0.0.1"])
def test_non_routable_addresses_are_dropped_even_when_a_rule_matches(tmp_path, monkeypatch,
                                                                     ip):
    ctx = make_ctx(tmp_path, include=["0.0.0.0/0", "::/0"], exclude=[], prefilter=[])
    landmine(monkeypatch)

    summary = port_scan.PortScanModule(ctx).run([host(ip)])

    assert summary["skipped_non_routable"] == 1 and summary["gated"] == 0
    assert ctx.ledger.log == [] and ctx.graph.store.nodes == {}


def test_canonical_ip_accepts_only_a_single_address():
    assert port_scan.canonical_ip(f"host:{IP}".split(":", 1)[1]) == IP
    assert port_scan.canonical_ip(f" {IP} ") == IP
    assert port_scan.canonical_ip(f"[{IPV6}]") == IPV6
    assert port_scan.canonical_ip("2001:DB8::1") == IPV6
    for junk in ("", None, "   ", "api.epicgames.com", "203.0.113.0/24", "not-an-ip",
                 f"{IPV6}%eth0", "203.0.113.5:443",
                 "203.0.113.005"):  # ambiguous leading zeros are never guessed at
        assert port_scan.canonical_ip(junk) == ""


def test_scannable_address_rejects_non_targets():
    assert port_scan.scannable_address(IP)
    assert port_scan.scannable_address(IPV6)
    assert port_scan.scannable_address("10.0.0.1")  # a lab range is the policy's call
    for junk in ("127.0.0.1", "::1", "fe80::1", "224.0.0.1", "0.0.0.0", "240.0.0.1",
                 "not-an-ip", ""):
        assert not port_scan.scannable_address(junk)


def test_an_empty_port_list_scans_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(port_scan, "PORTS", ())
    ctx, summary, calls = run(tmp_path, monkeypatch, [host(IP)])

    assert calls == [] and ctx.ledger.log == []
    assert summary["gated"] == 0 and summary["ports"] == []


# --- the loop: the planner's scan-host gap --------------------------------------


def test_planner_schedules_this_module_and_the_scan_closes_the_gap(tmp_path, monkeypatch,
                                                                   two_ports):
    """``scan-host`` is the planner's rung for this module, and a Service closes it."""

    from recon import planner

    ctx = make_ctx(tmp_path)
    seed_host(ctx, IP)
    install(monkeypatch, {IP: {443: "open"}})

    gaps = planner.plan(ctx.graph.store, NOW, allow_active=True)
    scan_gaps = [g for g in gaps if g.module == "port_scan"]
    assert {g.verb for g in scan_gaps} == {"port-scan"}
    assert {g.node_id for g in scan_gaps} == {f"host:{IP}"}
    assert all(not g.passive and not g.human_gated for g in scan_gaps)

    seeds = [s for g in scan_gaps for s in planner.seeds_for(g, ctx.graph.store)]
    summary = port_scan.PortScanModule(ctx).run(seeds)

    assert summary["open"] == 1 and summary["hosted_on_edges"] == 1
    assert not [g for g in planner.plan(ctx.graph.store, NOW, allow_active=True)
                if g.module == "port_scan"]
