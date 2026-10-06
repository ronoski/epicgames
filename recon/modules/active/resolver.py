"""ACTIVE DNS resolution — the first rung of the active ladder (``docs/SPEC.md`` §6.2.1).

Passive sources say a name *was* published; only a resolver says it is *live today*. This
module spends real active budget to find out, so **every single lookup goes through the one
chokepoint** — :meth:`ModuleContext.gate_active` with the whitelisted active verb
``resolve`` (``docs/safety-model.md`` §3) — which enforces active-enabled, a non-stale
policy snapshot, an ``in_scope`` verdict and a successful debit of the unified per-target
ledger, and writes an ALLOW/REFUSE record either way. A ``GateRefused`` is a **skip**: it is
logged, counted and the name is left alone. There is no fallback path that probes anyway, no
retry, no second resolver, and exactly **one query per gated name per run**.

What it does with an answer:

* The queried name is emitted (or re-emitted) as a ``DNSName`` at :data:`RESOLVED_LOG_ODDS`
  with ``coverage={"enumerated": True}`` — its address records are now known.
* Each returned address earns its **own** verdict (``ctx.bind(ip)``) before anything is
  written, and only an ``in_scope`` address becomes a ``Host`` + ``resolves_to`` edge.
* A ``Hypothesis`` seed (``hyp:dns-candidate:<fqdn>``, from the passive ``permutations``
  generator) that resolves is **PROMOTED**: the real ``DNSName`` is asserted and a
  ``corroborates`` edge Hypothesis→DNSName records what confirmed the guess. The guess node
  itself is left exactly as it was — history is never overwritten (``SPEC.md`` §3.3).
* Alias names in the answer become ``cname_to`` edges DNSName→DNSName, **in-scope aliases
  only**; the full observed chain is also kept as a list attribute so a third-party target
  (the usual CNAME destination) is recorded as *data about an in-scope name* without ever
  minting a node or an edge endpoint for a value we may not retain.

What it does with a **negative** answer — the subdomain-takeover path, first-class given
Epic's history (``SPEC.md`` §6.2.1):

* An unconfirmed candidate that NXDOMAINs gets **nothing written**. A guess that failed is
  not a fact; it is simply left to decay past its half-life.
* A *known* ``DNSName`` that NXDOMAINs **while still pointing at a CNAME target** raises
  ``hyp:dangling-cname:<fqdn>`` — a takeover **CANDIDATE**, detection only. It is a
  ``Hypothesis`` at :data:`DANGLING_LOG_ODDS` (<= 0), never an asserted finding; the
  ``takeover-claim`` verb is on the blocked list and can never be scheduled.
* ``gethostbyname_ex`` reports neither the DNS rcode nor the record chain, so the alias on a
  failed lookup comes from what an earlier successful resolution recorded (its ``cname_to``
  edges / ``cname_targets`` attribute), never from a fresh probe. It is also IPv4-only, so a
  "no address" error is deliberately **not** treated as a vanished name: an AAAA-only host
  must not mint a takeover candidate (see :func:`gaierror_outcome`).

Safety notes:

* ``scope != ownership`` (§2). A seed's stored verdict is never trusted — ``gate_active``
  re-binds the name against the current snapshot, and every address and alias is bound
  individually. Non-``in_scope`` values are counted and logged as negative space, never
  written. A ``prefilter_only`` address is **dropped rather than retained capped**: it was
  observed by an active probe (I3) and may never be actively touched, so retaining it would
  only add a node nothing is allowed to do anything with.
* Every node produced here carries ``attrs["active_probed"] = True`` and an ``in_scope``
  binding taken from ``gate_active``/``ctx.bind`` — never a fabricated one (I2/I3).
* Everything handled is public DNS data: ``S0``, ``data_subject="none"``. No credential,
  token or other-person datum passes through this module, so nothing needs redaction.
* Resolver, socket and OS errors are logged and counted; a broken resolver never crashes
  the run. Active spend is bounded by :data:`MAX_SEED_NODES` on top of the rate ledger.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field

from ... import verbs
from ...factory import make_edge, make_node
from ...models import EvidenceRef, Sensitivity, Verdict
from ...scope import classify
from ...urls import (
    canonical_host, dns_id as make_dns_id, host_id as make_host_id,
    hypothesis_id, valid_fqdn,
)
from ..base import GateRefused, Module, ModuleContext, register

#: The whitelisted verb for this module. It is an **active** verb (``verbs.ACTIVE``): every
#: use of it sends a query on behalf of the operator and debits the per-target ledger.
VERB = "resolve"

SOURCE = "resolver"

#: Ruleset version. Same answer + same version ⇒ same facts (``SPEC.md`` §3.2).
RULE_ID = "dns-resolution"
RULE_VERSION = "0.1.0"

#: A live answer is strong evidence the name exists (~p=0.88). This is also where a promoted
#: candidate lands: a confirmed guess stops being a guess.
RESOLVED_LOG_ODDS = 2.0

#: A name seen only as an alias inside another name's answer: real, but not itself resolved
#: (~p=0.73). Its own ``resolve`` gap corroborates it later.
ALIAS_LOG_ODDS = 1.0

#: A dangling-CNAME *candidate* is an unverified lead, so it is a Hypothesis at <= 0 log-odds
#: (~p=0.38). Detection only — confirming or claiming a takeover is not a recon verb.
DANGLING_LOG_ODDS = -0.5

#: Node-id conventions this module reads and writes.
DNS_ID_PREFIX = "dns:"
HOST_ID_PREFIX = "host:"
CANDIDATE_ID_PREFIX = hypothesis_id("dns-candidate", "")
DANGLING_ID_PREFIX = hypothesis_id("dangling-cname", "")

#: Node types accepted as seeds; anything else is ignored. A ``Hypothesis`` seed must be a
#: ``hyp:dns-candidate:`` node — no other hypothesis kind describes a resolvable name.
SEED_NODE_TYPES = frozenset({"DNSName", "Hypothesis"})

#: HARD CAP on gated lookups per run. The ledger already fails closed, but active work is
#: scheduled one gap at a time and a huge seed list should be deferred, not crammed in.
MAX_SEED_NODES = 25

#: Defensive ceilings on one answer (a round-robin record set can be large).
MAX_ADDRESSES_PER_NAME = 32
MAX_ALIASES_PER_NAME = 16

_FOREIGN_ID_PREFIXES = (
    "org:", "bu:", "domain:", "net:", "asn:", "host:", "svc:", "web:", "route:",
    "op:", "param:", "auth:", "cred:", "tok:", "obj:", "flow:", "art:", "ev:", "hyp:",
)

#: Conservative fqdn shape (same spirit as the CT/permutation modules): no whitespace, no
#: wildcards, no raw unicode (punycode ``xn--`` labels pass), so a junk answer row can never
#: mint a junk node id.
_FQDN_RE = re.compile(
    r"^[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?)+$"
)


def _errnos(*names: str) -> frozenset[int]:
    """The subset of ``socket`` error codes that exist on this platform."""

    return frozenset(
        code for code in (getattr(socket, name, None) for name in names) if code is not None
    )

#: "The name does not exist" — the only outcome that may suggest a dangling record.
NXDOMAIN_ERRNOS = _errnos("EAI_NONAME")

#: "The name exists but has no address of the requested family." ``gethostbyname_ex`` asks
#: for IPv4 only, so an AAAA-only host lands here. Deliberately NOT an NXDOMAIN: treating it
#: as one would invent takeover candidates for perfectly healthy IPv6 hosts.
NO_ADDRESS_ERRNOS = _errnos("EAI_NODATA", "EAI_ADDRFAMILY")



def canonical_addresses(raw, limit: int = MAX_ADDRESSES_PER_NAME) -> list[str]:
    """Validated, deduplicated, deterministically ordered addresses from an answer.

    Resolvers round-robin their answers, so the raw order differs between identical runs.
    Sorting here is what makes the evidence blob content-address to the same sha for the
    same answer set (``SPEC.md`` §3.1/§4.1).
    """

    seen: dict[str, object] = {}
    for item in raw or []:
        try:
            addr = ipaddress.ip_address(str(item).strip())
        except ValueError:
            continue  # a malformed answer row is dropped, never minted into an id
        seen.setdefault(str(addr), addr)
    ordered = sorted(seen.values(), key=lambda a: (a.version, a.packed))  # type: ignore[attr-defined]
    return [str(a) for a in ordered[:limit]]


def alias_names(fqdn: str, canonical: str, aliases, limit: int = MAX_ALIASES_PER_NAME) -> list[str]:
    """The other names the answer mentions, canonical and deduplicated.

    ``gethostbyname_ex`` returns ``(canonical_name, aliaslist, addresses)`` where the
    canonical name is the end of the CNAME chain and the alias list holds the names used
    along the way (including the queried name itself). The queried name is dropped, so what
    remains is exactly the set of names ``<fqdn>`` resolves *through* — the ``cname_to``
    direction: queried name → the name it points at.
    """

    out: list[str] = []
    for item in [canonical, *(aliases or [])]:
        host = canonical_host(str(item or ""))
        if not host or host == fqdn or host in out or not valid_fqdn(host):
            continue
        out.append(host)
    return sorted(out)[:limit]


def gaierror_outcome(exc: BaseException) -> str:
    """Classify a ``socket.gaierror`` into an outcome this module acts on.

    Only a genuine "no such name" is ``nxdomain``; a no-address answer and a temporary
    failure (``EAI_AGAIN``/SERVFAIL) are distinct, because neither means the name is gone
    and a takeover candidate must never rest on a flaky resolver.
    """

    errno = getattr(exc, "errno", None)
    if errno in NXDOMAIN_ERRNOS:
        return "nxdomain"
    if errno in NO_ADDRESS_ERRNOS:
        return "no_address"
    return f"error:gaierror:{errno}"


@dataclass(frozen=True)
class _Target:
    """One canonicalized name to resolve, plus where it came from."""

    fqdn: str
    seed_id: str = ""            # the seed's graph id ("" for a bare string seed)
    candidate: bool = False      # seed was a dns-candidate Hypothesis -> promote on success
    seed_attrs: dict = field(default_factory=dict)


@register
class ResolverModule(Module):
    """Resolve in-scope DNSName / dns-candidate seeds; one gated lookup per name."""

    ctx: ModuleContext

    name = "resolver"
    produces = ("DNSName", "Host", "Hypothesis")
    active = True

    def run(self, seeds: list) -> dict:
        """Gate, resolve and fold in one answer per seed name. Returns counts."""

        # Self-check: this module's verb must be on the closed whitelist AND be an active
        # verb (an active module reaching for a passive verb would bypass the ledger).
        verbs.assert_schedulable(VERB)
        assert verbs.is_active(VERB), "resolver is active; its verb must be in verbs.ACTIVE"
        # Detection only: a dangling CNAME is reported, never claimed.
        assert "takeover-claim" in verbs.BLOCKED

        summary: dict = {
            "module": self.name,
            "verb": VERB,
            "active": True,
            "seeds_in": 0,
            "seeds_used": 0,
            "seeds_skipped": 0,
            "seeds_deduped": 0,
            "seeds_truncated": False,
            "gated": 0,
            "refused": 0,
            "refused_by_reason": {},
            "probed": 0,
            "resolved": 0,
            "nxdomain": 0,
            "no_address": 0,
            "errors": 0,
            "errors_by_kind": {},
            "dns_emitted": 0,
            "promoted": 0,
            "candidates_unconfirmed": 0,
            "hosts_emitted": 0,
            "resolves_to_edges": 0,
            "addresses_seen": 0,
            "addresses_dropped": 0,
            "aliases_seen": 0,
            "aliases_dropped": 0,
            "alias_names_emitted": 0,
            "cname_edges": 0,
            "dangling_candidates": 0,
            "nxdomain_without_cname": 0,
            "dropped_by_verdict": {},
        }

        targets = self._targets(seeds, summary)
        if not targets:
            self.log.info("resolver: no DNSName/dns-candidate seeds to resolve; nothing to do")
            return summary

        for target in targets:
            # THE CHOKEPOINT. One gate decision per lookup, before the lookup.
            summary["gated"] += 1
            try:
                binding = self.ctx.gate_active(target.fqdn, VERB)
            except GateRefused as exc:
                # A refusal is a skip, never a reason to probe anyway.
                summary["refused"] += 1
                summary["refused_by_reason"][exc.reason] = (
                    summary["refused_by_reason"].get(exc.reason, 0) + 1
                )
                self.log.info("resolver: not resolving %s: %s", target.fqdn, exc.reason)
                continue

            summary["probed"] += 1
            answer, outcome = self._resolve(target.fqdn)
            if answer is None:
                self._on_failure(target, binding, outcome, summary)
                continue
            self._on_answer(target, binding, answer, summary)

        self.log.info(
            "resolver: %d seed(s) -> %d gated, %d refused %s, %d resolved, %d nxdomain "
            "(%d takeover candidate(s)), %d error(s) — emitted %d DNSName, %d Host, "
            "%d resolves_to, %d cname_to; dropped %s",
            summary["seeds_used"], summary["gated"], summary["refused"],
            summary["refused_by_reason"] or "{}", summary["resolved"], summary["nxdomain"],
            summary["dangling_candidates"], summary["errors"], summary["dns_emitted"],
            summary["hosts_emitted"], summary["resolves_to_edges"], summary["cname_edges"],
            summary["dropped_by_verdict"] or "{}",
        )
        return summary

    # --- seeds -------------------------------------------------------------
    def _targets(self, seeds: list, summary: dict) -> list[_Target]:
        """Ordered, deduplicated targets. Tolerates an empty or junk seed list."""

        out: list[_Target] = []
        seen: set[str] = set()
        for seed in seeds or []:
            summary["seeds_in"] += 1
            target = self._target(seed)
            if target is None:
                summary["seeds_skipped"] += 1
                continue
            if target.fqdn in seen:
                # Never spend two debits on one name in one run (a DNSName and its own
                # candidate hypothesis can both be handed to us).
                summary["seeds_deduped"] += 1
                continue
            if len(out) >= MAX_SEED_NODES:
                summary["seeds_truncated"] = True
                self.log.warning(
                    "resolver: seed list exceeds MAX_SEED_NODES=%d; deferring the rest to a "
                    "later cycle rather than spending the budget in one run", MAX_SEED_NODES,
                )
                break
            seen.add(target.fqdn)
            out.append(target)
        summary["seeds_used"] = len(out)
        return out

    @staticmethod
    def _target(seed) -> _Target | None:
        """Pull a resolvable name out of a graph Node seed, or out of a string seed."""

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

        candidate = False
        if raw.startswith(CANDIDATE_ID_PREFIX):
            candidate = True
            value = attrs.get("candidate_fqdn") or raw[len(CANDIDATE_ID_PREFIX):]
        elif raw.startswith(DNS_ID_PREFIX):
            value = attrs.get("fqdn") or raw[len(DNS_ID_PREFIX):]
        elif raw.startswith(_FOREIGN_ID_PREFIXES):
            # Another node kind — including a Hypothesis that is not a dns candidate (a
            # dangling-cname lead describes a name we already know does not resolve).
            return None
        else:
            value = raw  # a bare hostname handed over by the orchestrator

        fqdn = canonical_host(str(value).lstrip("*."))
        if not valid_fqdn(fqdn):
            return None
        return _Target(fqdn=fqdn, seed_id=raw, candidate=candidate, seed_attrs=attrs)

    # --- the one network touch ---------------------------------------------
    def _resolve(self, fqdn: str) -> tuple[tuple[str, list, list] | None, str]:
        """Exactly one ``gethostbyname_ex`` lookup. Returns ``(answer, outcome)``.

        Never raises and never retries: a resolver that says no is answered by backing off,
        not by asking again (``safety-model.md`` §4).
        """

        try:
            canonical, aliases, addresses = socket.gethostbyname_ex(fqdn)
        except socket.gaierror as exc:
            return None, gaierror_outcome(exc)
        except OSError as exc:
            return None, f"error:{type(exc).__name__}"
        except Exception as exc:  # unknown resolver stack; a module never crashes the run
            return None, f"error:unexpected:{type(exc).__name__}"
        return (str(canonical or ""), list(aliases or []), list(addresses or [])), "resolved"

    # --- evidence ----------------------------------------------------------
    @staticmethod
    def _record(fqdn: str, *, result: str, canonical: str = "", aliases=(),
                addresses=(), cnames=()) -> str:
        """The canonicalized answer record that is this observation's raw proof."""

        lines = [f"{SOURCE}/{RULE_VERSION} verb={VERB}", f"query={fqdn}", f"result={result}"]
        if canonical:
            lines.append(f"canonical={canonical}")
        if aliases:
            lines.append("aliases=" + ",".join(aliases))
        if addresses:
            lines.append("addresses=" + ",".join(addresses))
        if cnames:
            lines.append("known_cname_targets=" + ",".join(cnames))
        return "\n".join(lines)

    def _evidence(self, record: str, fqdn: str) -> list[EvidenceRef]:
        """Content-address the answer record. An unwritable store is not fatal."""

        try:
            return [self.ctx.evidence.put_text(record, region=f"{SOURCE}:{fqdn}")]
        except OSError as exc:
            self.log.warning("resolver: evidence store unavailable for %s: %s", fqdn, exc)
            return []

    # --- a live answer -----------------------------------------------------
    def _on_answer(self, target: _Target, binding, answer, summary: dict) -> None:
        """Fold one successful answer into the graph."""

        canonical, raw_aliases, raw_addresses = answer
        addresses = canonical_addresses(raw_addresses)
        aliases = alias_names(target.fqdn, canonical, raw_aliases)
        summary["resolved"] += 1

        evidence = self._evidence(self._record(
            target.fqdn, result="OK",
            canonical=canonical_host(str(canonical or "")) or target.fqdn,
            aliases=aliases, addresses=addresses,
        ), target.fqdn)

        # The queried name: live, with its address records enumerated. The observed chain is
        # kept as a LIST (lists never fork on re-observation) so a third-party CNAME target
        # is recorded as data about an in-scope name without becoming a node or an endpoint.
        dns_attrs: dict = {"active_probed": True}
        if aliases:
            dns_attrs["cname_targets"] = list(aliases)
        dns_id = make_dns_id(target.fqdn)
        self.ctx.graph.upsert_node(make_node(
            "DNSName", dns_id,
            binding=binding,  # the gate's own binding: in_scope, bound to this snapshot
            source=SOURCE,
            now=self.ctx.clock_now(),
            attrs=dns_attrs,
            evidence=evidence,
            rule_id=RULE_ID,
            rule_version=RULE_VERSION,
            log_odds=RESOLVED_LOG_ODDS,
            sensitivity=Sensitivity.S0,  # public DNS data
            coverage={"enumerated": True},  # its address records are now known
            data_subject="none",
        ))
        summary["dns_emitted"] += 1

        if target.candidate:
            self._promote(target, binding, dns_id, summary)
        self._emit_hosts(target, dns_id, addresses, evidence, summary)
        self._emit_aliases(target, dns_id, aliases, evidence, summary)

    def _promote(self, target: _Target, binding, dns_id: str, summary: dict) -> None:
        """Promote a confirmed candidate: assert the name, corroborate the guess.

        The Hypothesis node is left untouched — a contradiction or confirmation never
        overwrites history (``SPEC.md`` §3.3); the ``corroborates`` edge *is* the record of
        what the guess turned into.
        """

        if not target.seed_id.startswith(CANDIDATE_ID_PREFIX):
            return
        if self.ctx.graph.store.get(target.seed_id) is None:
            # Nothing to corroborate from: do not mint an edge with a dangling endpoint.
            self.log.warning("resolver: candidate %s is not in the graph; promoting %s "
                             "without a corroborates edge", target.seed_id, target.fqdn)
            return
        self.ctx.graph.upsert_edge(make_edge(
            "corroborates", target.seed_id, dns_id,
            binding=binding,
            source=SOURCE,
            now=self.ctx.clock_now(),
            attrs={"active_probed": True, "promotion": "dns-candidate->DNSName"},
            log_odds=RESOLVED_LOG_ODDS,
        ))
        summary["promoted"] += 1
        self.log.info("resolver: candidate %s confirmed live; promoted to %s",
                      target.seed_id, dns_id)

    def _emit_hosts(self, target: _Target, dns_id: str, addresses: list[str],
                    evidence: list[EvidenceRef], summary: dict) -> None:
        """Emit a ``Host`` + ``resolves_to`` per **in-scope** address.

        An address earns its own verdict: ``scope.py`` deliberately refuses to let a
        hostname rule authorize a raw IP, and laundering the name's verdict onto its
        addresses is exactly the scope expansion §2 forbids. A non-``in_scope`` address is
        counted and logged (it stays visible in the answer evidence), never written.
        """

        for ip in addresses:
            summary["addresses_seen"] += 1
            ip_binding = self.ctx.bind(ip)
            if ip_binding.verdict != Verdict.IN_SCOPE:
                verdict = ip_binding.verdict.value
                summary["dropped_by_verdict"][verdict] = (
                    summary["dropped_by_verdict"].get(verdict, 0) + 1
                )
                summary["addresses_dropped"] += 1
                self.log.info("resolver: not retaining %s (from %s): %s (%s)",
                              ip, target.fqdn, verdict, ip_binding.rule_matched)
                continue

            host_id = make_host_id(ip)
            self.ctx.graph.upsert_node(make_node(
                "Host", host_id,
                binding=ip_binding,
                source=SOURCE,
                now=self.ctx.clock_now(),
                attrs={"active_probed": True},
                evidence=evidence,
                rule_id=RULE_ID,
                rule_version=RULE_VERSION,
                log_odds=RESOLVED_LOG_ODDS,
                sensitivity=Sensitivity.S0,
                coverage={"enumerated": False},  # its services are the port-scan's job
                data_subject="none",
            ))
            summary["hosts_emitted"] += 1

            # The edge carries the binding of the endpoint it introduces, so it can never
            # be bound more permissively than the datum it adds.
            self.ctx.graph.upsert_edge(make_edge(
                "resolves_to", dns_id, host_id,
                binding=ip_binding,
                source=SOURCE,
                now=self.ctx.clock_now(),
                attrs={"active_probed": True},
                log_odds=RESOLVED_LOG_ODDS,
            ))
            summary["resolves_to_edges"] += 1

    def _emit_aliases(self, target: _Target, dns_id: str, aliases: list[str],
                      evidence: list[EvidenceRef], summary: dict) -> None:
        """Emit ``cname_to`` DNSName→DNSName for in-scope aliases only."""

        for alias in aliases:
            summary["aliases_seen"] += 1
            alias_binding = self.ctx.bind(alias)
            if alias_binding.verdict != Verdict.IN_SCOPE:
                verdict = alias_binding.verdict.value
                summary["dropped_by_verdict"][verdict] = (
                    summary["dropped_by_verdict"].get(verdict, 0) + 1
                )
                summary["aliases_dropped"] += 1
                # Recorded in the answer evidence and in cname_targets; no node, no edge.
                self.log.info("resolver: %s points at %s but it is %s (%s); recording the "
                              "chain without an edge", target.fqdn, alias, verdict,
                              alias_binding.rule_matched)
                continue

            alias_id = make_dns_id(alias)
            self.ctx.graph.upsert_node(make_node(
                "DNSName", alias_id,
                binding=alias_binding,
                source=SOURCE,
                now=self.ctx.clock_now(),
                attrs={"active_probed": True},
                evidence=evidence,
                rule_id=RULE_ID,
                rule_version=RULE_VERSION,
                log_odds=ALIAS_LOG_ODDS,  # seen in an answer, not itself resolved
                sensitivity=Sensitivity.S0,
                coverage={"enumerated": False},  # its own resolve gap closes this
                data_subject="none",
            ))
            summary["alias_names_emitted"] += 1
            self.ctx.graph.upsert_edge(make_edge(
                "cname_to", dns_id, alias_id,
                binding=alias_binding,
                source=SOURCE,
                now=self.ctx.clock_now(),
                attrs={"active_probed": True},
                log_odds=RESOLVED_LOG_ODDS,
            ))
            summary["cname_edges"] += 1

    # --- a negative answer -------------------------------------------------
    def _on_failure(self, target: _Target, binding, outcome: str, summary: dict) -> None:
        """Route a failed lookup: NXDOMAIN, no-address, or a plain resolver error."""

        if outcome == "nxdomain":
            summary["nxdomain"] += 1
            self._on_nxdomain(target, binding, summary)
            return
        if outcome == "no_address":
            # The name exists, it just has no A record (this lookup is IPv4-only). Not a
            # vanished name, so no takeover candidate and nothing asserted.
            summary["no_address"] += 1
            self.log.info("resolver: %s exists but returned no IPv4 address; no A-record "
                          "fact to assert", target.fqdn)
            return
        summary["errors"] += 1
        summary["errors_by_kind"][outcome] = summary["errors_by_kind"].get(outcome, 0) + 1
        self.log.warning("resolver: %s not resolved (%s); backing off and leaving the fact "
                         "to decay", target.fqdn, outcome)

    def _on_nxdomain(self, target: _Target, binding, summary: dict) -> None:
        """NXDOMAIN: let a guess decay, or raise a takeover candidate for a known name."""

        if target.candidate:
            # A guess that does not resolve is not a fact. Write nothing: asserting a
            # negative would also reset the candidate's decay clock.
            summary["candidates_unconfirmed"] += 1
            self.log.info("resolver: candidate %s did not resolve; leaving it to decay",
                          target.fqdn)
            return

        cnames = self._known_cnames(target)
        if not cnames:
            summary["nxdomain_without_cname"] += 1
            self.log.info("resolver: %s is NXDOMAIN with no known CNAME target; leaving the "
                          "name to decay", target.fqdn)
            return
        self._emit_dangling(target, binding, cnames, summary)

    def _known_cnames(self, target: _Target) -> tuple[str, ...]:
        """CNAME targets already recorded for this name: graph edges, then seed attrs.

        A failed ``gethostbyname_ex`` returns no records at all, so the alias has to come
        from what an earlier successful resolution wrote — never from a second probe.
        """

        out: list[str] = []
        for edge in self.ctx.graph.store.out_edges(make_dns_id(target.fqdn), "cname_to"):
            host = str(getattr(edge, "to", "") or "")
            if host.startswith(DNS_ID_PREFIX):
                host = host[len(DNS_ID_PREFIX):]
            host = canonical_host(host)
            if valid_fqdn(host) and host not in out:
                out.append(host)

        raw = target.seed_attrs.get("cname_targets") or target.seed_attrs.get("cname_target")
        if isinstance(raw, str):
            raw = [raw]
        if isinstance(raw, (list, tuple)):
            for item in raw:
                host = canonical_host(str(item or ""))
                if valid_fqdn(host) and host not in out:
                    out.append(host)
        return tuple(sorted(out))

    def _emit_dangling(self, target: _Target, binding, cnames: tuple[str, ...],
                       summary: dict) -> None:
        """Raise a subdomain-takeover **candidate**. Detection only — never a claim.

        The hypothesis records the alias it still points at and carries no edge: the target
        is typically a third-party vendor name we are not authorized to retain, let alone
        touch. Confirming the lead means a human reading the report, not a probe.
        """

        node_id = hypothesis_id("dangling-cname", target.fqdn)
        evidence = self._evidence(self._record(
            target.fqdn, result="NXDOMAIN", cnames=cnames,
        ), target.fqdn)
        self.ctx.graph.upsert_node(make_node(
            "Hypothesis", node_id,
            binding=binding,
            source=SOURCE,
            now=self.ctx.clock_now(),
            attrs={
                "dangling_fqdn": target.fqdn,
                "cname_targets": list(cnames),  # a list never fork-conflicts on re-observation
                "candidate_class": "subdomain-takeover",
                "detection_only": True,  # 'takeover-claim' is a blocked verb
                "active_probed": True,
            },
            evidence=evidence,
            rule_id=RULE_ID,
            rule_version=RULE_VERSION,
            log_odds=DANGLING_LOG_ODDS,  # an unverified lead: never > 0
            sensitivity=Sensitivity.S0,  # public DNS data on both sides
            coverage={"enumerated": False},  # nothing about the lead is confirmed
            data_subject="none",
        ))
        self.ctx.graph.log.append(
            "hypothesis_raised",
            {"id": node_id, "dangling_fqdn": target.fqdn, "cname_targets": list(cnames),
             "candidate_class": "subdomain-takeover", "module": self.name,
             "rule": f"{RULE_ID}@{RULE_VERSION}", "log_odds": DANGLING_LOG_ODDS,
             "detection_only": True},
            idempotency_key=f"hypothesis:{node_id}",
        )
        summary["dangling_candidates"] += 1
        self.log.warning(
            "resolver: %s is NXDOMAIN but still points at %s — subdomain-takeover CANDIDATE "
            "(detection only; not verified, not claimed, report it)",
            target.fqdn, ", ".join(cnames),
        )


__all__ = [
    "ResolverModule", "VERB", "SOURCE", "RULE_ID", "RULE_VERSION",
    "RESOLVED_LOG_ODDS", "ALIAS_LOG_ODDS", "DANGLING_LOG_ODDS",
    "MAX_SEED_NODES", "MAX_ADDRESSES_PER_NAME", "MAX_ALIASES_PER_NAME",
    "NXDOMAIN_ERRNOS", "NO_ADDRESS_ERRNOS",
    "CANDIDATE_ID_PREFIX", "DANGLING_ID_PREFIX",
    "alias_names", "canonical_addresses", "gaierror_outcome", "valid_fqdn",
]
