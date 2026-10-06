"""ACTIVE, rate-limited, non-intrusive TCP connect scan — the ``Host → Service`` rung
(``docs/SPEC.md`` §6.2.2, ``docs/domains/non-binary.md`` §3.2).

Passive scan datasets (Shodan/Censys/Sonar) say a port *was* listening; only a connect
says it is listening **now**. That answer costs real active budget against a real host, so
this is deliberately the thinnest possible probe:

* **One gate per ``(host, port)`` pair.** :meth:`~recon.modules.base.ModuleContext.gate_active`
  is called with the whitelisted active verb ``port-scan`` (``safety-model.md`` §3) **before
  every single connect**, so every probe is individually budgeted, individually bound to the
  current policy snapshot, and individually auditable as an ALLOW/REFUSE record. A
  :class:`~recon.modules.base.GateRefused` is a **skip**: the scan of that host ends there
  (the budget is gone or the verdict is not ``in_scope``) and the next host is considered.
  There is no probe-anyway path, no retry and no second connect.
* **A connect and nothing else.** :func:`socket.create_connection` with a short timeout
  (``min(ctx.timeout, 2.0)``), then the socket is closed. No banner is read, no payload is
  written, no TLS handshake, no raw/SYN socket, no external scanner tool, no volume sweep —
  ``dos`` and ``fuzz-at-volume`` are blocked verbs and ``masscan``-style scanning is
  forbidden outright (``non-binary.md`` §3.2).
* **A small, curated, capped port list.** :data:`PORTS` is a fixed top-ports list bounded by
  :data:`MAX_PORTS_PER_HOST`; the applied cap is logged on every run. A wider sweep is a
  separate, human-authorized decision, not something this module can grow into.

**What it emits.** Only an *open* port is a fact: one ``Service``
(``svc:<ip>:<port>/tcp``) carrying ``attrs["active_probed"] = True`` and ``state="open"``,
with coverage ``{"enumerated": True}`` — the port is known to be listening; nothing about
the service *behind* it is (that needs a fingerprint, which this module refuses to do).
Each Service is joined to its host by the declared ``hosted_on`` edge Service→Host. A
closed, filtered or unreachable port **emits nothing at all**: a negative observation lives
in the scan evidence record, not as an asserted node.

**Safety notes.**

* ``scope != ownership`` (§2). A seed's stored verdict is never trusted — the gate re-binds
  the address against the current snapshot for every probe, and the bindings written to the
  graph are exactly the ones the gate returned (never fabricated, never widened). A
  ``prefilter_only`` host is refused by the gate and so is never probed and never emitted.
* **Shared-tenant hosts are skipped before the gate.** One CDN/cloud IP fronts many
  tenants, so scanning it "as Epic's" is both wrong and other people's traffic
  (``non-binary.md`` §3.2). A seed marked as fronted/provider-owned is dropped without
  spending a probe; only the in-scope hostname path (``http_probe``) characterizes those.
* Loopback / link-local / multicast / unspecified / reserved addresses are dropped too: they
  are never the authorized target, whatever a scope rule happens to say.
* Everything handled is public port state: ``S0``, ``data_subject="none"``. No credential,
  token, banner or other-person datum passes through this module, so nothing needs
  redaction and no ``Credential``/``Token`` node is minted.
* Socket and OS errors are classified, counted and logged; a dead host never crashes the
  run. Active spend is bounded by :data:`MAX_SEED_HOSTS` × :data:`MAX_PORTS_PER_HOST` on
  top of the unified ledger, which fails closed on its own.
"""

from __future__ import annotations

import errno as _errno
import ipaddress
import socket
from dataclasses import dataclass, field

from ... import verbs
from ...factory import make_edge, make_node
from ...models import EvidenceRef, ScopeBinding, Sensitivity, Verdict
from ...urls import (
    canonical_host, host_id as make_host_id, registrable_domain,
    service_id as make_service_id,
)
from ..base import GateRefused, Module, ModuleContext, register

#: The whitelisted verb for this module. It is an **active** verb (``verbs.ACTIVE``): every
#: use of it puts a SYN on an Epic host and debits the unified per-target ledger.
VERB = "port-scan"

SOURCE = "port_scan"

#: Ruleset version. Same observation + same version ⇒ same facts (``SPEC.md`` §3.2).
RULE_ID = "tcp-connect-scan"
RULE_VERSION = "0.1.0"

#: The only transport this module speaks. UDP would need its own verb and its own evidence
#: semantics (no connect handshake exists), so it is simply not implemented.
PROTO = "tcp"

#: The curated top-ports list, in probe order: the web surface first (it feeds the
#: ``http_probe`` rung), then the small set of classic management/data ports worth knowing
#: about. Deliberately TINY — this is a recon signal, not a port inventory.
PORTS: tuple[int, ...] = (80, 443, 8080, 8443, 22, 25, 53, 3389, 5432, 6379)

#: HARD CAP on ports probed per host, applied to :data:`PORTS` and logged every run. The
#: ledger already fails closed; this keeps one host from eating a whole cycle's budget.
MAX_PORTS_PER_HOST = 10

#: HARD CAP on hosts per run. Worst-case spend is this × :data:`MAX_PORTS_PER_HOST`.
MAX_SEED_HOSTS = 10

#: Connect timeout bounds. Short by design: a human-rate, non-intrusive probe waits briefly
#: and moves on (``safety-model.md`` §4). The floor stops a misconfigured ``ctx.timeout``
#: from degenerating into a non-blocking connect that reports every port as filtered.
CONNECT_TIMEOUT_CEILING = 2.0
MIN_CONNECT_TIMEOUT = 0.25

#: A completed handshake is strong first-hand evidence the port is open (~p=0.88), and
#: deliberately below ``models._CORROBORATED_AT`` (2.2): one source never promotes itself.
OPEN_LOG_ODDS = 2.0

#: Node types accepted as seeds; anything else is ignored.
SEED_NODE_TYPES = frozenset({"Host"})

HOST_ID_PREFIX = "host:"
SERVICE_ID_PREFIX = "svc:"

_FOREIGN_ID_PREFIXES = (
    "org:", "bu:", "domain:", "dns:", "net:", "asn:", "svc:", "web:", "route:",
    "op:", "param:", "auth:", "cred:", "tok:", "obj:", "flow:", "art:", "ev:", "hyp:",
)

#: Seed attributes that mark an address as shared-tenant / fronted infrastructure. Such a
#: host is never scanned as Epic's (``non-binary.md`` §3.2): the packets would land on a
#: provider edge serving many customers.
SHARED_TENANT_ATTRS: tuple[str, ...] = (
    "shared_tenant", "cdn_or_waf", "cdn", "cdn_provider", "provider", "fronted_by",
)


def _errnos(*names: str) -> frozenset[int]:
    """The subset of ``errno`` codes that exist on this platform."""

    return frozenset(
        code for code in (getattr(_errno, name, None) for name in names)
        if isinstance(code, int)
    )


#: "This address is not reachable from here at all" — continuing to spend budget on the
#: other ports of this host would be pointless noise, so the host's scan stops.
HOST_LEVEL_ERRNOS = _errnos(
    "EHOSTUNREACH", "ENETUNREACH", "ENETDOWN", "EAFNOSUPPORT", "EPFNOSUPPORT",
    "EACCES", "EPERM",
)

#: "Something is there and it said no" — a definite closed port, like a refused connect.
CLOSED_ERRNOS = _errnos("ECONNRESET", "ECONNABORTED")


def scan_ports(ports=None, limit=None) -> tuple[int, ...]:
    """The validated, deduplicated, capped port list, in probe order.

    Junk entries are dropped rather than probed, and the result is capped so the curated
    list cannot quietly grow into a sweep. Both arguments default to the module constants
    (resolved at call time, so the cap is one knob rather than a baked-in default).
    """

    ports = PORTS if ports is None else ports
    try:
        cap = max(0, int(MAX_PORTS_PER_HOST if limit is None else limit))
    except (TypeError, ValueError):
        cap = MAX_PORTS_PER_HOST
    out: list[int] = []
    for item in ports or ():
        if len(out) >= cap:
            break
        try:
            port = int(item)
        except (TypeError, ValueError):
            continue
        if not 1 <= port <= 65535 or port in out:
            continue
        out.append(port)
    return tuple(out)


def canonical_ip(value: str) -> str:
    """Canonical form of a single IP address, or ``""`` if ``value`` is not one.

    A network/CIDR, a hostname, a scoped IPv6 literal (``%eth0``) and anything malformed
    all return ``""``: this module probes exactly one address at a time and never expands a
    range into a sweep.
    """

    text = str(value or "").strip().strip("[]")
    if not text or "%" in text or "/" in text:
        return ""
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return ""


def scannable_address(ip: str) -> bool:
    """Is ``ip`` an address a scan may legitimately be aimed at?

    Loopback, link-local, multicast, unspecified and reserved space is never the authorized
    target — it is this machine, this LAN or nobody — so it is dropped before the gate even
    if a scope rule would match it. Note that documentation/private ranges are deliberately
    NOT excluded: a lab or an internal in-scope range is the operator's own call, enforced
    by the scope policy rather than by this module.
    """

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_loopback or addr.is_link_local or addr.is_multicast
                or addr.is_unspecified or addr.is_reserved)


def connect_timeout(timeout) -> float:
    """Clamp ``ctx.timeout`` into the short, non-intrusive window used for one connect."""

    try:
        value = float(timeout)
    except (TypeError, ValueError):
        return CONNECT_TIMEOUT_CEILING
    if value != value or value <= 0:  # NaN or nonsense: fall back to the floor
        return MIN_CONNECT_TIMEOUT
    return max(MIN_CONNECT_TIMEOUT, min(value, CONNECT_TIMEOUT_CEILING))


def connect_outcome(exc: BaseException) -> str:
    """Classify a failed connect. Only a *successful* connect ever means ``open``.

    ``closed`` (refused/reset) and ``filtered`` (timed out) are both negative observations
    that emit nothing; ``unreachable`` additionally ends the host's scan.
    """

    if isinstance(exc, ConnectionRefusedError):
        return "closed"
    if isinstance(exc, TimeoutError):  # socket.timeout is an alias since 3.10
        return "filtered"
    errno = getattr(exc, "errno", None)
    if errno in HOST_LEVEL_ERRNOS:
        return "unreachable"
    if errno in CLOSED_ERRNOS:
        return "closed"
    return f"error:{type(exc).__name__}"


@dataclass(frozen=True)
class _Target:
    """One canonicalized address to scan, plus where it came from."""

    ip: str
    seed_id: str = ""
    seed_attrs: dict = field(default_factory=dict)


@dataclass(frozen=True)
class _Open:
    """An open port and the gate binding that authorized the probe which found it."""

    port: int
    binding: ScopeBinding


@register
class PortScanModule(Module):
    """Scan in-scope Host seeds over a tiny curated port list; one gate per port."""

    ctx: ModuleContext

    name = "port_scan"
    produces = ("Service",)
    active = True

    def run(self, seeds: list) -> dict:
        """Gate, connect and fold in one observation per ``(host, port)``. Returns counts."""

        # Self-check: this module's verb must be on the closed whitelist AND be an active
        # verb (an active module reaching for a passive verb would bypass the ledger).
        verbs.assert_schedulable(VERB)
        assert verbs.is_active(VERB), "port_scan is active; its verb must be in verbs.ACTIVE"
        # Non-intrusive by construction: volume scanning and DoS can never be scheduled.
        assert "dos" in verbs.BLOCKED and "fuzz-at-volume" in verbs.BLOCKED

        ports = scan_ports()
        summary: dict = {
            "module": self.name,
            "verb": VERB,
            "active": True,
            "proto": PROTO,
            "ports": list(ports),
            "ports_capped": len(ports) < len(PORTS),
            "timeout": connect_timeout(self.ctx.timeout),
            "seeds_in": 0,
            "seeds_used": 0,
            "seeds_skipped": 0,
            "seeds_deduped": 0,
            "seeds_truncated": False,
            "skipped_shared_tenant": 0,
            "skipped_non_routable": 0,
            "hosts_scanned": 0,
            "hosts_refused_outright": 0,
            "hosts_cut_short": 0,
            "hosts_unreachable": 0,
            "gated": 0,
            "refused": 0,
            "refused_by_reason": {},
            "probed": 0,
            "open": 0,
            "closed": 0,
            "filtered": 0,
            "errors": 0,
            "errors_by_kind": {},
            "services_emitted": 0,
            "hosted_on_edges": 0,
            "edges_skipped_missing_host": 0,
        }

        # The cap is a safety control, so it is stated out loud on every run.
        self.log.info(
            "port_scan: curated top-ports list capped at %d of %d port(s) per host %s, "
            "%d host(s) per run, %.2fs connect timeout — a wider sweep is a separate, "
            "human-authorized decision",
            len(ports), len(PORTS), list(ports), MAX_SEED_HOSTS,
            summary["timeout"],
        )
        if not ports:
            self.log.warning("port_scan: no usable port in the curated list; nothing to do")
            return summary

        targets = self._targets(seeds, summary)
        if not targets:
            self.log.info("port_scan: no Host seeds to scan; nothing to do")
            return summary

        # No pre-flight scope/snapshot check here on purpose: gate_active is the single
        # chokepoint and records every ALLOW/REFUSE, so a disabled, unsnapshotted, stale or
        # out-of-scope run is refused there and stays auditable.
        for target in targets:
            self._scan_host(target, ports, summary)

        self.log.info(
            "port_scan: %d host(s) -> %d gated probe(s), %d refused %s, %d open, %d closed, "
            "%d filtered, %d error(s) — emitted %d Service, %d hosted_on; %d host(s) cut "
            "short by budget, %d unreachable",
            summary["seeds_used"], summary["gated"], summary["refused"],
            summary["refused_by_reason"] or "{}", summary["open"], summary["closed"],
            summary["filtered"], summary["errors"], summary["services_emitted"],
            summary["hosted_on_edges"], summary["hosts_cut_short"],
            summary["hosts_unreachable"],
        )
        return summary

    # --- seeds -------------------------------------------------------------
    def _targets(self, seeds: list, summary: dict) -> list[_Target]:
        """Ordered, deduplicated, scannable targets. Tolerates an empty or junk list."""

        out: list[_Target] = []
        seen: set[str] = set()
        for seed in seeds or []:
            summary["seeds_in"] += 1
            target = self._target(seed)
            if target is None:
                summary["seeds_skipped"] += 1
                continue
            if target.ip in seen:
                # Never spend two scans on one address in one run.
                summary["seeds_deduped"] += 1
                continue
            if not scannable_address(target.ip):
                summary["skipped_non_routable"] += 1
                self.log.info("port_scan: not scanning %s: loopback/link-local/multicast/"
                              "reserved space is never the authorized target", target.ip)
                continue
            if self._shared_tenant(target):
                summary["skipped_shared_tenant"] += 1
                self.log.info(
                    "port_scan: not scanning %s: recorded as shared-tenant/fronted "
                    "infrastructure — one provider IP serves many customers, so it is never "
                    "scanned as Epic's (only the in-scope hostname is characterized)",
                    target.ip,
                )
                continue
            if len(out) >= MAX_SEED_HOSTS:
                summary["seeds_truncated"] = True
                self.log.warning(
                    "port_scan: seed list exceeds MAX_SEED_HOSTS=%d; deferring the rest to a "
                    "later cycle rather than spending the budget in one run", MAX_SEED_HOSTS,
                )
                break
            seen.add(target.ip)
            out.append(target)
        summary["seeds_used"] = len(out)
        return out

    @staticmethod
    def _target(seed) -> _Target | None:
        """Pull a single address out of a graph ``Host`` seed, or out of a string seed."""

        raw = getattr(seed, "id", None)
        if raw is None and isinstance(seed, str):
            raw = seed
        if not isinstance(raw, str) or not raw.strip():
            return None
        node_type = getattr(seed, "type", "")
        if node_type and node_type not in SEED_NODE_TYPES:
            return None
        attrs = getattr(seed, "attrs", None)
        attrs = dict(attrs) if isinstance(attrs, dict) else {}

        if raw.startswith(HOST_ID_PREFIX):
            value = attrs.get("ip") or raw[len(HOST_ID_PREFIX):]
        elif raw.startswith(_FOREIGN_ID_PREFIXES):
            return None  # some other node kind slipped into the seed list
        else:
            value = raw  # a bare address handed over by the orchestrator

        ip = canonical_ip(str(value))
        return _Target(ip=ip, seed_id=raw, seed_attrs=attrs) if ip else None

    def _ledger_key(self, target) -> str:
        """The target the scan should be charged to, never a bare shared IP.

        safety-model.md §4 requires the ledger be keyed by registrable domain / apex /
        vhost and explicitly NOT by a shared IP: one CDN address fronts many tenants, so
        charging the address under-counts aggregate spend against the logical target and
        charges a shared IP to nobody. Prefer the hostname this address was reached
        through; fall back to the address only when the graph knows of none.
        """

        recorded = target.seed_attrs.get("fqdn") or target.seed_attrs.get("resolved_from")
        if recorded:
            return registrable_domain(canonical_host(str(recorded)))
        for edge in self.ctx.graph.store.in_edges(make_host_id(target.ip), "resolves_to"):
            if edge.frm.startswith("dns:"):
                return registrable_domain(edge.frm.split(":", 1)[1])
        return target.ip

    def _shared_tenant(self, target: _Target) -> bool:
        """Is this address recorded as provider/CDN-fronted, shared-tenant space?"""

        if any(target.seed_attrs.get(key) for key in SHARED_TENANT_ATTRS):
            return True
        try:
            return bool(self.ctx.graph.store.out_edges(make_host_id(target.ip),
                                                       "fronted_by"))
        except Exception:  # a store that cannot answer must not break the scan
            return False

    # --- the scan ----------------------------------------------------------
    def _scan_host(self, target: _Target, ports: tuple[int, ...], summary: dict) -> None:
        """One gated connect per port, in order, until the ports or the budget run out."""

        opens: list[_Open] = []
        probed: list[int] = []
        cut_short = ""

        for port in ports:
            # THE CHOKEPOINT. One gate decision per probe, before the probe.
            summary["gated"] += 1
            try:
                binding = self.ctx.gate_active(
                    target.ip, VERB, ledger_key=self._ledger_key(target))
            except GateRefused as exc:
                # A refusal is a skip, never a reason to connect anyway. The budget for this
                # host is gone (or its verdict is not in_scope), so stop here and move on to
                # the next host instead of burning a refusal per remaining port.
                summary["refused"] += 1
                summary["refused_by_reason"][exc.reason] = (
                    summary["refused_by_reason"].get(exc.reason, 0) + 1
                )
                summary["hosts_cut_short" if probed else "hosts_refused_outright"] += 1
                cut_short = "refused"
                self.log.info("port_scan: stopping the scan of %s at port %d/%s: %s",
                              target.ip, port, PROTO, exc.reason)
                break

            probed.append(port)
            summary["probed"] += 1
            outcome = self._connect(target.ip, port)

            if outcome == "open":
                summary["open"] += 1
                opens.append(_Open(port=port, binding=binding))
                self.log.info("port_scan: %s:%d/%s is open", target.ip, port, PROTO)
                continue
            if outcome == "closed":
                summary["closed"] += 1
                continue
            if outcome == "filtered":
                summary["filtered"] += 1
                continue
            if outcome == "unreachable":
                summary["hosts_unreachable"] += 1
                cut_short = "unreachable"
                self.log.info("port_scan: %s is unreachable; abandoning the rest of its "
                              "ports rather than spending more budget", target.ip)
                break
            summary["errors"] += 1
            summary["errors_by_kind"][outcome] = summary["errors_by_kind"].get(outcome, 0) + 1
            self.log.warning("port_scan: %s:%d/%s not observed (%s); leaving the port "
                             "unknown", target.ip, port, PROTO, outcome)

        if probed:
            summary["hosts_scanned"] += 1
        if opens:
            self._emit(target, opens, probed, cut_short, summary)
        elif probed:
            # Negative space, recorded in the log rather than asserted in the graph.
            self.log.info("port_scan: %s had no open port among %s; emitting nothing",
                          target.ip, probed)

    def _connect(self, ip: str, port: int) -> str:
        """Exactly one TCP connect, immediately closed. Returns the outcome string.

        Never raises, never retries, never writes a byte and never reads one: the handshake
        itself *is* the observation (``non-binary.md`` §3.2 — no banner grab here, that is a
        separate ``fingerprint`` verb on its own gate).
        """

        sock = None
        try:
            sock = socket.create_connection((ip, port),
                                            timeout=connect_timeout(self.ctx.timeout))
        except OSError as exc:
            return connect_outcome(exc)
        except Exception as exc:  # unknown socket stack; a module never crashes the run
            return f"error:unexpected:{type(exc).__name__}"
        else:
            return "open"
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:  # pragma: no cover - closing a live socket rarely fails
                    pass

    # --- evidence ----------------------------------------------------------
    def _record(self, ip: str, probed: list[int], opens: list[_Open], cut_short: str) -> str:
        """The canonicalized scan record that is this observation's raw proof.

        Deterministic for a given probe set and result set, so re-observing an unchanged
        host content-addresses to the same sha (``SPEC.md`` §3.1/§4.1). The timeout is part
        of the record because a ``filtered`` verdict depends on it.
        """

        return "\n".join([
            f"{SOURCE}/{RULE_VERSION} verb={VERB}",
            f"target={ip}",
            f"proto={PROTO}",
            f"timeout={connect_timeout(self.ctx.timeout):.2f}",
            f"result={'partial:' + cut_short if cut_short else 'complete'}",
            "ports_probed=" + ",".join(str(p) for p in probed),
            "open=" + ",".join(str(p) for p in sorted(o.port for o in opens)),
        ])

    def _evidence(self, record: str, ip: str) -> list[EvidenceRef]:
        """Content-address the scan record. An unwritable store is not fatal."""

        try:
            return [self.ctx.evidence.put_text(record, region=f"{SOURCE}:{ip}")]
        except OSError as exc:
            self.log.warning("port_scan: evidence store unavailable for %s: %s", ip, exc)
            return []

    # --- emit --------------------------------------------------------------
    def _emit(self, target: _Target, opens: list[_Open], probed: list[int],
              cut_short: str, summary: dict) -> None:
        """Write one ``Service`` per open port plus its ``hosted_on`` edge to the Host."""

        # The gate already guarantees this; assert it so no future refactor can emit a node
        # for an address that was not in scope at observation time (I2/I3).
        assert all(o.binding.verdict == Verdict.IN_SCOPE for o in opens), \
            "every binding here comes from gate_active and must be in_scope"

        now = self.ctx.clock_now()
        evidence = self._evidence(self._record(target.ip, probed, opens, cut_short), target.ip)
        host_id = make_host_id(target.ip)
        host_known = self.ctx.graph.store.get(host_id) is not None

        for open_port in opens:
            service_id = make_service_id(target.ip, open_port.port, PROTO)
            self.ctx.graph.upsert_node(make_node(
                "Service", service_id,
                binding=open_port.binding,  # the gate's own binding for THIS probe
                source=SOURCE,
                now=now,
                attrs={
                    "active_probed": True,
                    "state": "open",
                    # The id convention does not bracket an IPv6 literal, so the parts are
                    # kept as attrs and no consumer has to re-parse a colon-rich id.
                    "ip": target.ip,
                    "port": open_port.port,
                    "proto": PROTO,
                },
                evidence=evidence,
                rule_id=RULE_ID,
                rule_version=RULE_VERSION,
                log_odds=OPEN_LOG_ODDS,
                sensitivity=Sensitivity.S0,  # public port state
                # The port is known to be listening; what answers on it is not (no banner
                # was read), so this stops at `enumerated`.
                coverage={"enumerated": True},
                data_subject="none",
            ))
            summary["services_emitted"] += 1

            if not host_known:
                # Do not mint an edge with a dangling endpoint (same rule as the resolver's
                # candidate promotion): the Service stands alone until the Host is known.
                summary["edges_skipped_missing_host"] += 1
                self.log.warning("port_scan: %s is not in the graph; emitting %s without a "
                                 "hosted_on edge", host_id, service_id)
                continue

            self.ctx.graph.upsert_edge(make_edge(
                "hosted_on", service_id, host_id,
                binding=open_port.binding,
                source=SOURCE,
                now=now,
                attrs={"active_probed": True},
                log_odds=OPEN_LOG_ODDS,
            ))
            summary["hosted_on_edges"] += 1


__all__ = [
    "PortScanModule", "VERB", "SOURCE", "RULE_ID", "RULE_VERSION", "PROTO",
    "PORTS", "MAX_PORTS_PER_HOST", "MAX_SEED_HOSTS", "OPEN_LOG_ODDS",
    "CONNECT_TIMEOUT_CEILING", "MIN_CONNECT_TIMEOUT", "SHARED_TENANT_ATTRS",
    "HOST_LEVEL_ERRNOS", "CLOSED_ERRNOS",
    "canonical_ip", "connect_outcome", "connect_timeout", "scan_ports",
    "scannable_address",
]
