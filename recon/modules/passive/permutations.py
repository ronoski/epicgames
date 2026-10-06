"""Offline sibling-hostname candidate generation (``docs/SPEC.md`` §6.2.1).

Passive DNS and CT only reveal names someone else already published. The names an
organization *also* owns but never certified are reached by guessing — and guessing is
exactly where a recon pipeline usually starts hammering a resolver. This module does the
guessing half **and nothing else**: it is pure, deterministic, and makes **no network call
of any kind** (``safety-model.md`` §4, passive-first). It never calls
:meth:`ModuleContext.gate_active` and never debits the unified per-target rate ledger,
because nothing it does touches an Epic asset.

Two generators run over in-scope ``DNSName`` seeds:

* ``prefix`` — a small curated wordlist (:data:`PREFIX_WORDS`) laid onto the seed's
  registrable apex (``epicgames.com`` → ``api.epicgames.com``, ``dev.epicgames.com``, …).
* ``numeric`` — numeric mutations of the seed's own sub-apex labels, nearest value first
  and zero-padding preserved (``api1`` → ``api2``, ``prod06`` → ``prod07``). The apex's own
  labels are never mutated: a sibling *domain* is not a sibling *host*, and default-deny
  would drop it anyway.

Everything a guess produces is a **guess**, so candidates are emitted as ``Hypothesis``
nodes at a negative ``log_odds`` (:data:`CANDIDATE_LOG_ODDS`, ~p=0.27 — more likely wrong
than right) with coverage ``{"enumerated": False}``: explicit negative space. A candidate
is **never** asserted as a ``DNSName`` and this module emits no edges — a hostname that
does not resolve has nothing to be connected to. The ``hyp:dns-candidate:<fqdn>`` id is the
handle the (active, scope-gated, rate-budgeted) resolver later uses to confirm a candidate
or let it decay past its half-life.

Safety notes:

* ``scope != ownership`` (``safety-model.md`` §2). Every candidate is bound individually
  against the current snapshot and **only an ``in_scope`` verdict is emitted**. A
  ``prefilter_only`` candidate is deliberately dropped rather than retained capped: the
  sole purpose of a candidate is to be actively confirmed later, and an owned-but-unlisted
  value may never drive an active touch, so retaining one would only queue work that must
  refuse itself.
* Retention needs a current, non-stale snapshot (I1/I12), so with no snapshot — or a stale
  one — the module generates nothing and says why in its summary.
* Generation is **hard-capped** at :data:`MAX_CANDIDATES` per run and the overflow is
  counted, sampled into the summary and logged. Nothing is dropped silently.
* A candidate already present in the graph (as ``dns:<fqdn>`` or as its own
  ``hyp:dns-candidate:<fqdn>``) is skipped rather than re-upserted: re-observing a guess
  from its own generator is not independent corroboration, and skipping lets an unconfirmed
  candidate decay on schedule instead of being refreshed forever.
"""

from __future__ import annotations

import re

from ... import verbs
from ...factory import make_node
from ...models import EvidenceRef, Sensitivity, Verdict
from ...scope import classify, normalize_host, registrable_domain
from ..base import Module, ModuleContext, register

#: Whitelisted verb (``verbs.ALLOWED``, deliberately NOT in ``verbs.ACTIVE``). This module
#: enumerates *candidates* offline; the resolver spends the active budget on them later.
VERB = "enumerate"

SOURCE = "permutations"

#: Ruleset version. Same seeds + same wordlist/range + same version ⇒ same candidate set
#: (the reproducibility contract of ``docs/SPEC.md`` §3.2).
RULE_VERSION = "0.1.0"
RULE_ID = "dns-permutation"

#: Curated prefix wordlist. Deliberately short: a long list belongs to the human-gated
#: content/DNS-brute path (``safety-model.md`` §3), not to an auto-running module.
PREFIX_WORDS: tuple[str, ...] = (
    "api", "dev", "stage", "staging", "test", "qa", "internal", "admin",
    "auth", "cdn", "static", "gateway", "graphql", "ws", "mobile",
)

#: Numeric mutation window: ±2 around each observed number. Small on purpose — shard
#: numbering is dense, so the neighbours carry nearly all of the signal.
NUMERIC_DELTA = 2

#: HARD CAP on candidates emitted per run. Candidate generation is combinatorial and the
#: resolver pays for every candidate out of a real rate budget, so the ceiling is here
#: rather than downstream. Overflow is reported, never silently truncated.
MAX_CANDIDATES = 300

#: Defensive ceiling on seeds consumed in one run, and on how many dropped candidate names
#: are echoed into the summary (the full list goes to the debug log).
MAX_SEED_NODES = 50
MAX_DROPPED_SAMPLE = 20

#: A generated name is an unverified guess: negative log-odds (~p=0.27). Never > 0.
CANDIDATE_LOG_ODDS = -1.0

#: Node types accepted as seeds; anything else is ignored.
SEED_NODE_TYPES = frozenset({"DNSName"})

_SEED_ID_PREFIX = "dns:"
_FOREIGN_ID_PREFIXES = (
    "org:", "bu:", "domain:", "net:", "asn:", "host:", "svc:", "web:", "route:",
    "op:", "param:", "auth:", "cred:", "tok:", "obj:", "flow:", "art:", "ev:", "hyp:",
)

#: Conservative fqdn shape (same spirit as the CT module): no whitespace, no wildcards, no
#: raw unicode (punycode ``xn--`` labels pass), so a junk label can never mint a junk id.
_FQDN_RE = re.compile(
    r"^[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?)+$"
)

#: Splits a label around its **last** digit run: ``prod06`` → ``prod`` / ``06`` / ``""``,
#: ``shard-3-west`` → ``shard-`` / ``3`` / ``-west``.
_NUM_RE = re.compile(r"^(?P<stem>.*?)(?P<digits>\d+)(?P<tail>\D*)$")


def numeric_offsets(delta: int = NUMERIC_DELTA) -> tuple[int, ...]:
    """Mutation offsets, nearest value first: ``(+1, -1, +2, -2)``.

    Nearest-first ordering means the hard cap keeps the most plausible guesses when it bites.
    """

    out: list[int] = []
    for step in range(1, max(0, delta) + 1):
        out.extend((step, -step))
    return tuple(out)


def valid_fqdn(host: str) -> bool:
    """Is ``host`` a plausible, canonical hostname we would be willing to mint an id for?"""

    if not host or len(host) > 253 or not _FQDN_RE.match(host):
        return False
    if any(len(label) > 63 for label in host.split(".")):
        return False
    return classify(host) != "ip"


def numeric_mutations(host: str, delta: int = NUMERIC_DELTA) -> list[str]:
    """Numeric sibling guesses for ``host``, one label mutated at a time.

    Only labels **below** the registrable apex are mutated, zero-padding is preserved
    (``prod06`` → ``prod07``, not ``prod7``) and negative numbers are skipped. Pure and
    deterministic: no network, no clock, no randomness.
    """

    labels = host.split(".")
    apex_depth = len(registrable_domain(host).split("."))
    out: list[str] = []
    for i in range(max(0, len(labels) - apex_depth)):
        label = labels[i]
        m = _NUM_RE.match(label)
        if m is None:
            continue
        stem, digits, tail = m.group("stem"), m.group("digits"), m.group("tail")
        width = len(digits) if digits.startswith("0") else 0
        value = int(digits)
        for offset in numeric_offsets(delta):
            n = value + offset
            if n < 0:
                continue
            mutated = f"{stem}{str(n).zfill(width)}{tail}"
            if mutated == label:
                continue
            out.append(".".join(labels[:i] + [mutated] + labels[i + 1:]))
    return out


@register
class PermutationsModule(Module):
    """Generate in-scope sibling-hostname ``Hypothesis`` candidates, fully offline."""

    ctx: ModuleContext

    name = "permutations"
    produces = ("Hypothesis",)
    active = False

    def run(self, seeds: list) -> dict:
        """Generate, scope-bind and emit candidates for ``seeds``. Never touches a network."""

        # Self-check: this module's verb must be on the closed whitelist and must NOT be an
        # active verb (a passive module reaching for one would be a safety bug).
        verbs.assert_schedulable(VERB)
        assert not verbs.is_active(VERB), "permutations is passive; its verb must not be active"

        summary: dict = {
            "module": self.name,
            "verb": VERB,
            "active": False,
            "seeds_in": 0,
            "seeds_used": 0,
            "seeds_truncated": False,
            "seeds_skipped_by_verdict": {},
            "apexes": [],
            "generated": 0,
            "generated_by_generator": {"prefix": 0, "numeric": 0},
            "considered": 0,
            "capped": False,
            "dropped_by_cap": 0,
            "dropped_sample": [],
            "already_known": 0,
            "emitted": 0,
            "emitted_by_generator": {"prefix": 0, "numeric": 0},
            "dropped_out_of_scope": 0,
            "dropped_by_verdict": {},
        }

        # I1/I12: nothing may be retained against a missing or stale policy snapshot, and a
        # candidate nobody may retain is not worth generating.
        snapshot = self.ctx.snapshot
        if snapshot is None:
            summary["blocked"] = "no scope snapshot (verify live policy first)"
            self.log.warning("permutations: %s", summary["blocked"])
            return summary
        if snapshot.is_stale(self.ctx.clock_now()):
            summary["blocked"] = "scope snapshot is stale; re-fetch + re-bind required"
            self.log.warning("permutations: %s", summary["blocked"])
            return summary

        hosts = self._seed_hosts(seeds, summary)
        if not hosts:
            self.log.info("permutations: no in-scope DNSName seeds to permute; nothing to do")
            return summary

        for fqdn, generator, record in self._candidates(hosts, summary):
            self._emit(fqdn, generator, record, summary)

        self.log.info(
            "permutations: %d seed(s) -> %d candidate(s) generated (%s), %d considered, "
            "%d emitted in-scope, %d already known, %d dropped out-of-scope %s",
            summary["seeds_used"], summary["generated"],
            summary["generated_by_generator"], summary["considered"],
            summary["emitted"], summary["already_known"],
            summary["dropped_out_of_scope"], summary["dropped_by_verdict"] or "{}",
        )
        return summary

    # --- seeds -------------------------------------------------------------
    def _seed_hosts(self, seeds: list, summary: dict) -> list[str]:
        """Ordered, deduplicated, currently-``in_scope`` seed hostnames.

        The stored binding of a seed node was taken against whatever snapshot was current
        then, so the seed is **re-bound** here: expanding a name that has since left scope
        would launder a stale verdict into fresh candidates.
        """

        out: list[str] = []
        seen: set[str] = set()
        for seed in seeds or []:
            summary["seeds_in"] += 1
            host = self._seed_host(seed)
            if not host or host in seen:
                continue
            seen.add(host)
            if len(out) >= MAX_SEED_NODES:
                summary["seeds_truncated"] = True
                self.log.warning("permutations: seed list exceeds MAX_SEED_NODES=%d; "
                                 "deferring the rest to a later cycle", MAX_SEED_NODES)
                break
            binding = self.ctx.bind(host)
            if binding.verdict != Verdict.IN_SCOPE:
                verdict = binding.verdict.value
                summary["seeds_skipped_by_verdict"][verdict] = (
                    summary["seeds_skipped_by_verdict"].get(verdict, 0) + 1
                )
                self.log.info("permutations: not permuting seed %s: %s (%s)",
                              host, verdict, binding.rule_matched)
                continue
            out.append(host)
        summary["seeds_used"] = len(out)
        return out

    @staticmethod
    def _seed_host(seed) -> str:
        """Pull a canonical hostname out of a ``DNSName`` node, or out of a string seed."""

        raw = getattr(seed, "id", None)
        if raw is None and isinstance(seed, str):
            raw = seed
        if not isinstance(raw, str) or not raw.strip():
            return ""
        node_type = getattr(seed, "type", "")
        if node_type and node_type not in SEED_NODE_TYPES:
            return ""
        if raw.startswith(_SEED_ID_PREFIX):
            raw = raw[len(_SEED_ID_PREFIX):]
        elif raw.startswith(_FOREIGN_ID_PREFIXES):
            return ""  # some other node kind slipped into the seed list
        host = normalize_host(raw.lstrip("*."))
        return host if valid_fqdn(host) else ""

    # --- generation --------------------------------------------------------
    @staticmethod
    def _record(generator: str, *lines: str) -> str:
        """The deterministic derivation record that is this candidate's evidence.

        A guess has no external proof, so the proof is its own derivation: replaying this
        record with the same ruleset version reproduces the candidate exactly.
        """

        return "\n".join((f"{SOURCE}/{RULE_VERSION} generator={generator}",) + lines)

    def _candidates(self, hosts: list[str], summary: dict) -> list[tuple[str, str, str]]:
        """Deterministic, deduplicated ``(fqdn, generator, record)`` list, hard-capped.

        Order is prefix-on-apex first (cheap, broad), then numeric per seed (nearest value
        first), so the cap keeps the highest-signal guesses. A seed is never proposed back
        to itself.
        """

        out: list[tuple[str, str, str]] = []
        seen: set[str] = set(hosts)

        apexes: list[str] = []
        for host in hosts:
            apex = registrable_domain(host)
            if apex and apex not in apexes:
                apexes.append(apex)
        summary["apexes"] = apexes

        for apex in apexes:
            record = self._record("prefix", f"apex={apex}",
                                  f"wordlist={','.join(PREFIX_WORDS)}")
            for word in PREFIX_WORDS:
                fqdn = f"{word}.{apex}"
                if fqdn in seen or not valid_fqdn(fqdn):
                    continue
                seen.add(fqdn)
                out.append((fqdn, "prefix", record))

        for host in hosts:
            record = self._record("numeric", f"seed={host}",
                                  f"delta=+/-{NUMERIC_DELTA}")
            for fqdn in numeric_mutations(host):
                if fqdn in seen or not valid_fqdn(fqdn):
                    continue
                seen.add(fqdn)
                out.append((fqdn, "numeric", record))

        summary["generated"] = len(out)
        for _, generator, _ in out:
            summary["generated_by_generator"][generator] += 1

        if len(out) > MAX_CANDIDATES:
            dropped = out[MAX_CANDIDATES:]
            out = out[:MAX_CANDIDATES]
            by_generator: dict[str, int] = {}
            for _, generator, _ in dropped:
                by_generator[generator] = by_generator.get(generator, 0) + 1
            summary["capped"] = True
            summary["dropped_by_cap"] = len(dropped)
            summary["dropped_sample"] = [fqdn for fqdn, _, _ in dropped[:MAX_DROPPED_SAMPLE]]
            self.log.warning(
                "permutations: hit the %d-candidate cap; dropped %d candidate(s) %s — "
                "not generated this cycle, requeue with narrower seeds (sample: %s)",
                MAX_CANDIDATES, len(dropped), by_generator,
                ", ".join(summary["dropped_sample"]) or "none",
            )
            self.log.debug("permutations: dropped candidates: %s",
                           ", ".join(fqdn for fqdn, _, _ in dropped))

        summary["considered"] = len(out)
        return out

    # --- emit --------------------------------------------------------------
    def _evidence(self, record: str, fqdn: str) -> list[EvidenceRef]:
        """Content-address the derivation record. An unwritable store is not fatal."""

        try:
            return [self.ctx.evidence.put_text(record, region=f"{SOURCE}:{fqdn}")]
        except OSError as exc:
            self.log.warning("permutations: evidence store unavailable for %s: %s", fqdn, exc)
            return []

    def _emit(self, fqdn: str, generator: str, record: str, summary: dict) -> None:
        """Bind one candidate and, if ``in_scope`` and new, upsert it as a Hypothesis."""

        node_id = f"hyp:dns-candidate:{fqdn}"
        store = self.ctx.graph.store
        if store.get(node_id) is not None or store.get(f"dns:{fqdn}") is not None:
            # Already a known name, or a candidate from an earlier cycle: re-upserting
            # would self-corroborate a guess and reset its decay clock.
            summary["already_known"] += 1
            return

        binding = self.ctx.bind(fqdn)
        if binding.verdict != Verdict.IN_SCOPE:
            verdict = binding.verdict.value
            summary["dropped_by_verdict"][verdict] = (
                summary["dropped_by_verdict"].get(verdict, 0) + 1
            )
            summary["dropped_out_of_scope"] += 1
            self.log.debug("permutations: dropping candidate %s: %s (%s)",
                           fqdn, verdict, binding.rule_matched)
            return

        self.ctx.graph.upsert_node(make_node(
            "Hypothesis", node_id,
            binding=binding,
            source=SOURCE,
            now=self.ctx.clock_now(),
            # Exactly two always-identical scalars: a per-run detail here would be a
            # contradiction fork on re-observation.
            attrs={"candidate_fqdn": fqdn, "generator": generator},
            evidence=self._evidence(record, fqdn),
            rule_id=RULE_ID,
            rule_version=RULE_VERSION,
            log_odds=CANDIDATE_LOG_ODDS,  # an unverified guess: never > 0
            sensitivity=Sensitivity.S0,  # a guessed public hostname, no secret, no PII
            coverage={"enumerated": False},  # explicit negative space: nothing confirmed
            data_subject="none",
        ))
        self.ctx.graph.log.append(
            "hypothesis_raised",
            {"id": node_id, "candidate_fqdn": fqdn, "generator": generator,
             "module": self.name, "rule": f"{RULE_ID}@{RULE_VERSION}",
             "log_odds": CANDIDATE_LOG_ODDS},
            idempotency_key=f"hypothesis:{node_id}",
        )
        summary["emitted"] += 1
        summary["emitted_by_generator"][generator] += 1


__all__ = [
    "PermutationsModule", "VERB", "SOURCE", "PREFIX_WORDS", "NUMERIC_DELTA",
    "MAX_CANDIDATES", "MAX_SEED_NODES", "CANDIDATE_LOG_ODDS",
    "numeric_mutations", "numeric_offsets", "valid_fqdn",
]
