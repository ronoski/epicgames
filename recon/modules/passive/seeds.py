"""Seed ingestion — the entry module (``docs/SPEC.md`` §6.3).

Turns the operator-declared target list (``config.targets``) into the first nodes of the
graph: the ``Domain``/``DNSName``/``Host``/``NetBlock`` anchors every other module later
hangs its discoveries off. This module is **passive and network-free** — it classifies
each seed string, binds it against the current policy snapshot and writes nodes. It never
resolves, never fetches, never calls ``gate_active`` and never debits the rate ledger.

Safety notes:

* ``scope != ownership`` (``docs/safety-model.md`` §2). A seed is retained only on an
  ``in_scope`` verdict; a ``prefilter_only`` (owned-but-unlisted) seed is retained capped
  at ``{"enumerated": True}`` and nothing else, and is never actively probed;
  ``out_of_scope`` and ``adjudication_pending`` seeds are logged and dropped.
* Retention requires a current, non-stale snapshot (I1/I12), so with no snapshot — or a
  stale one — the module emits nothing and says why in its summary.
* A seed is *declared*, not *verified*: the name is not known to resolve, so nodes land at
  ``log_odds=0.0`` (``observed``) with ``enumerated=False`` — known-but-not-yet-enumerated.
  That negative space is exactly what the gap queue schedules a ``resolve`` from.
* A wildcard root (``*.epicgames.com``) seeds the **apex only**; enumerating what lives
  under it is another module's (scope-gated) job.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from ..base import Module, ModuleContext, register
from ...factory import make_edge, make_node
from ...models import EvidenceRef, Sensitivity, Verdict
from ...scope import classify
from ...urls import (
    canonical_host, dns_id, domain_id, host_id, registrable_domain,
)

# Defensive ceiling on one run's seed list; a config that overflows it is truncated and
# the truncation is reported rather than silently dropped.
MAX_SEEDS = 1000

# A seed must be a dotted hostname (LDH labels, trailing label alphabetic so "1.2.3" is
# not mistaken for a host) or an IP/CIDR. Underscore labels (``_dmarc``) are tolerated.
_HOSTNAME_RE = re.compile(
    r"^(?=.{4,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+"
    r"[a-z][a-z0-9-]{0,61}[a-z0-9]$"
)

# Verdicts whose data may be retained at all (capped, for prefilter_only).
_RETAINABLE = (Verdict.IN_SCOPE, Verdict.PREFILTER_ONLY)

_SEED_ORIGIN = "config.targets"


@dataclass
class _Seed:
    """One canonicalized seed plus every raw spelling that collapsed onto it."""

    kind: str  # "host" | "ip" | "net"
    value: str  # canonical form: the fqdn, the IP, or the CIDR
    wildcard: bool = False
    raw: list[str] = field(default_factory=list)


def _seed_text(item: object) -> str:
    """Coerce one orchestrator-supplied seed to a target string.

    ``seeds`` is a list of plain strings for this module, but the orchestrator hands other
    modules graph nodes, so tolerate one here rather than crashing the run.
    """

    if isinstance(item, str):
        return item
    attrs = getattr(item, "attrs", None) or {}
    for key in ("fqdn", "registrable", "cidr", "ip"):
        if attrs.get(key):
            return str(attrs[key])
    node_id = getattr(item, "id", "")
    if isinstance(node_id, str) and ":" in node_id:
        return node_id.split(":", 1)[1]
    return str(item)


def _canonical_ip(text: str) -> tuple[str, str]:
    """Return ``(kind, canonical)`` for an IP address or network. Raises ``ValueError``."""

    try:
        return "ip", str(ipaddress.ip_address(text))
    except ValueError:
        pass
    return "net", str(ipaddress.ip_network(text, strict=False))


def _canonical_host(text: str) -> str:
    """Return the canonical (lowercase, punycode, dot-stripped) fqdn, or ``""``."""

    host = canonical_host(text)
    if not host.isascii():
        try:  # IDN/punycode normalization per docs/SPEC.md §3.1
            host = host.encode("idna").decode("ascii").lower()
        except (UnicodeError, UnicodeDecodeError):
            return ""
    return host if _HOSTNAME_RE.match(host) else ""


def parse_seed(raw: str) -> _Seed | None:
    """Parse one raw seed string into a canonical ``_Seed``, or ``None`` if unusable.

    A leading ``*.`` is stripped: a wildcard root seeds its apex only.
    """

    text = (raw or "").strip()
    if not text or text.startswith("#"):
        return None
    wildcard = text.startswith("*.")
    if wildcard:
        text = text[2:].strip()
    if not text:
        return None
    if classify(text) == "ip":
        try:
            kind, value = _canonical_ip(text)
        except ValueError:
            return None
        return _Seed(kind=kind, value=value, wildcard=wildcard, raw=[raw])
    host = _canonical_host(text)
    if not host:
        return None
    return _Seed(kind="host", value=host, wildcard=wildcard, raw=[raw])


@register
class SeedsModule(Module):
    """Ingest ``config.targets`` into scope-bound Domain/DNSName/Host/NetBlock nodes."""

    name = "seeds"
    produces = ("Domain", "DNSName", "Host", "NetBlock")
    active = False

    ctx: ModuleContext

    # --- emit ----------------------------------------------------------
    def _coverage(self, verdict: Verdict) -> dict:
        """Fresh seeds are known-but-not-enumerated; prefilter_only caps at enumerated."""

        if verdict == Verdict.PREFILTER_ONLY:
            return {"enumerated": True}
        return {"enumerated": False}

    def _evidence(self, seed: _Seed) -> list[EvidenceRef]:
        """Content-address the raw config line(s) this seed came from.

        The operator's config *is* the proof for a seed, so the raw spellings are the
        evidence. An unwritable store is logged and the node is emitted without it.
        """

        try:
            ref = self.ctx.evidence.put_text("\n".join(seed.raw), region=_SEED_ORIGIN)
        except OSError as exc:
            self.log.warning("evidence store unavailable for seed %s: %s", seed.value, exc)
            return []
        return [ref]

    def _emit_containment(self, fqdn: str, apex: str, summary: dict) -> None:
        """Link a seeded hostname to its registrable domain via ``subdomain_of``.

        Both endpoints must already hold a retainable verdict of their own; this edge
        records containment, it never launders one node's verdict onto the other.
        """

        binding = self.ctx.bind(fqdn)
        if binding.verdict not in _RETAINABLE:
            return
        self.ctx.graph.upsert_edge(make_edge(
            "subdomain_of", dns_id(fqdn), domain_id(apex),
            binding=binding, source=self.name, now=self.ctx.clock_now(),
        ))
        summary["containment_edges"] = summary.get("containment_edges", 0) + 1

    def _emit(self, node_type: str, node_id: str, value: str, attrs: dict,
              evidence: list[EvidenceRef], summary: dict) -> str:
        """Bind ``value`` and upsert one node. Returns emitted | deduped | skipped."""

        binding = self.ctx.bind(value)
        if binding.verdict not in _RETAINABLE:
            self.log.info("skipping %s %s: %s (%s)", node_type, value,
                          binding.verdict.value, binding.rule_matched)
            return "skipped"
        if node_id in self._emitted_ids:
            # Same id, same source, same run: re-upserting would self-corroborate.
            summary["deduped"] += 1
            return "deduped"
        node = make_node(
            node_type, node_id,
            binding=binding,
            source=self.name,
            now=self.ctx.clock_now(),
            attrs=attrs,
            evidence=evidence,
            log_odds=0.0,  # declared, not resolution-verified
            sensitivity=Sensitivity.S0,  # public names / program scope text
            coverage=self._coverage(binding.verdict),
            data_subject="none",
        )
        result = self.ctx.graph.upsert_node(node)
        self._emitted_ids.add(node_id)
        summary["nodes"][node_type] += 1
        summary["emitted"] += 1
        self.log.debug("seeded %s (%s, %s)", result.id, binding.verdict.value, result.outcome)
        return "emitted"

    # --- run -----------------------------------------------------------
    def _canonicalize(self, raw_seeds: list, summary: dict) -> dict[str, _Seed]:
        """Collapse the raw seed list to ordered, deduplicated canonical seeds."""

        seen: dict[str, _Seed] = {}
        for item in raw_seeds:
            raw = _seed_text(item)
            seed = parse_seed(raw)
            if seed is None:
                summary["unparsable"] += 1
                self.log.warning("ignoring unparsable seed %r", raw)
                continue
            existing = seen.get(seed.value)
            if existing is not None:
                existing.wildcard = existing.wildcard or seed.wildcard
                existing.raw.extend(seed.raw)
                continue
            if len(seen) >= MAX_SEEDS:
                summary["truncated"] = True
                self.log.warning("seed list exceeds MAX_SEEDS=%d; truncating", MAX_SEEDS)
                break
            seen[seed.value] = seed
        return seen

    def _attrs(self, seed: _Seed) -> dict:
        """Canonical, run-stable attributes (a per-run spelling would spuriously fork)."""

        attrs: dict = {"seed_origin": _SEED_ORIGIN}
        if seed.kind == "host":
            attrs["fqdn"] = seed.value
            attrs["registrable"] = registrable_domain(seed.value)
            if seed.wildcard:
                # Only set when true: a later run seeding the bare apex must merge, not fork.
                attrs["wildcard_seed"] = True
        elif seed.kind == "ip":
            attrs["ip"] = seed.value
            attrs["ip_version"] = ipaddress.ip_address(seed.value).version
        else:
            net = ipaddress.ip_network(seed.value, strict=False)
            attrs["cidr"] = seed.value
            attrs["ip_version"] = net.version
            attrs["prefixlen"] = net.prefixlen
        return attrs

    def run(self, seeds: list) -> dict:
        """Ingest ``seeds`` (plain target strings). Returns counts by verdict."""

        summary: dict = {
            "module": self.name,
            "seeds_in": 0,
            "unique_seeds": 0,
            "unparsable": 0,
            "truncated": False,
            "deduped": 0,
            "domains_skipped": 0,
            "emitted": 0,
            "verdicts": {v.value: 0 for v in Verdict},
            "nodes": {t: 0 for t in self.produces},
        }
        self._emitted_ids: set[str] = set()

        # I1/I12: nothing may be retained against a missing or stale policy snapshot.
        snapshot = self.ctx.snapshot
        if snapshot is None:
            summary["blocked"] = "no scope snapshot (verify live policy first)"
            self.log.warning("seeds: %s", summary["blocked"])
            return summary
        if snapshot.is_stale(self.ctx.clock_now()):
            summary["blocked"] = "scope snapshot is stale; re-fetch + re-bind required"
            self.log.warning("seeds: %s", summary["blocked"])
            return summary

        raw_seeds = list(seeds or [])
        summary["seeds_in"] = len(raw_seeds)
        if not raw_seeds:
            self.log.info("seeds: empty target list, nothing to ingest")
            return summary

        targets = self._canonicalize(raw_seeds, summary)
        summary["unique_seeds"] = len(targets)

        for seed in targets.values():
            binding = self.ctx.bind(seed.value)
            summary["verdicts"][binding.verdict.value] += 1
            self.ctx.graph.log.append("scope_binding_set", {
                "value": seed.value, "kind": seed.kind,
                "verdict": binding.verdict.value, "rule": binding.rule_matched,
                "snapshot_id": binding.snapshot_id, "module": self.name,
            })
            if binding.verdict not in _RETAINABLE:
                self.log.info("skipping seed %s: %s (%s)", seed.value,
                              binding.verdict.value, binding.rule_matched)
                continue

            evidence = self._evidence(seed)
            attrs = self._attrs(seed)
            if seed.kind == "ip":
                self._emit("Host", host_id(seed.value), seed.value, attrs, evidence, summary)
                continue
            if seed.kind == "net":
                self._emit("NetBlock", "net:" + seed.value, seed.value, attrs, evidence, summary)
                continue

            dns_outcome = self._emit("DNSName", dns_id(seed.value), seed.value, attrs,
                                     evidence, summary)
            # The apex earns its own verdict: an exact-host include does not authorize the
            # registrable domain (default-deny), so bind and emit it separately.
            apex = attrs["registrable"]
            apex_attrs = {"registrable": apex, "seed_origin": _SEED_ORIGIN}
            apex_outcome = self._emit("Domain", domain_id(apex), apex, apex_attrs,
                                      evidence, summary)
            if apex_outcome == "skipped":
                summary["domains_skipped"] += 1
            elif dns_outcome != "skipped" and seed.value != apex:
                # subdomain_of is now a DECLARED edge, so apex/subdomain containment is
                # finally expressible. It could not be modelled before: derived_from is the
                # only other containment edge and invariant I5 requires its target to be an
                # Artifact, so using it here would have guaranteed a violation.
                self._emit_containment(seed.value, apex, summary)

        self.log.info("seeds: %d/%d retained (%s)", summary["emitted"],
                      summary["unique_seeds"], summary["verdicts"])
        return summary
