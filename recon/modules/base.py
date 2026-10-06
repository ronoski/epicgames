"""Module framework and the active-action gate.

A module is a unit of discovery. Passive modules touch only third-party/OSINT sources and
never debit an Epic rate budget. Active modules send traffic to the target and MUST pass
:meth:`ModuleContext.gate_active` first, which enforces, in order: active enabled, a
non-stale scope snapshot, an ``in_scope`` verdict, a whitelisted active verb, and a
successful debit of the unified per-target rate ledger. Every decision is written to the
event log as a ``gate_decision_recorded`` ALLOW/REFUSE record.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime

from .. import clock, verbs
from ..evidence import EvidenceStore
from ..models import ScopeBinding, Verdict
from ..ratelimit import RateBudgetExceeded, RateLedger
from ..scope import Scope
from ..snapshot import Snapshot
from ..store import Graph


class GateRefused(RuntimeError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass
class ModuleContext:
    scope: Scope
    ledger: RateLedger
    evidence: EvidenceStore
    graph: Graph
    snapshot: Snapshot | None
    logger: logging.Logger
    allow_active: bool = False
    user_agent: str = "recon-workflow/0.1 (+authorized-testing)"
    timeout: float = 8.0
    now: datetime | None = None
    # A SEPARATE ledger for third-party/OSINT sources (crt.sh, archive.org, ...).
    # safety-model.md §4: passive sources consume a third-party budget and must NEVER
    # debit the target's budget. Keeping them apart means passive politeness is centrally
    # capped and auditable instead of being per-module convention.
    third_party_ledger: RateLedger | None = None

    def clock_now(self) -> datetime:
        return self.now or clock.now()

    def bind(self, value: str) -> ScopeBinding:
        snap_id = self.snapshot.snapshot_id if self.snapshot else ""
        return self.scope.bind(value, snap_id, clock.iso(self.clock_now()))

    def in_scope(self, value: str) -> bool:
        return self.scope.is_in_scope(value)

    def snapshot_ok(self) -> bool:
        """True when a usable (present, non-stale) policy snapshot is pinned.

        Passive modules should check this before retaining anything: without a snapshot
        :meth:`bind` can only produce an empty ``snapshot_id``, which fails invariant I1.
        Active modules get this for free inside :meth:`gate_active`.
        """

        return self.snapshot is not None and not self.snapshot.is_stale(self.clock_now())

    def spend_third_party(self, source_host: str, cost: float = 1.0) -> bool:
        """Debit the third-party source budget for a PASSIVE query. Never the target's.

        Returns False when the budget is exhausted, so a passive module backs off instead
        of hammering an aggregator. A missing third_party_ledger means unmetered (the
        caller's own constants apply) — wire one in :func:`recon.pipeline.build_runtime`.
        """

        if self.third_party_ledger is None:
            return True
        try:
            entry = self.third_party_ledger.debit(source_host, "passive-collect", cost)
        except RateBudgetExceeded as exc:
            self.logger.info("third-party budget exhausted for %s: %s", source_host, exc)
            return False
        self.graph.log.append("third_party_debit", {
            "source": entry.target, "balance_after": entry.balance_after,
        })
        return True

    def can_gate(self, value: str, verb: str) -> tuple[bool, str]:
        """Non-spending pre-check: would :meth:`gate_active` allow this?

        Writes no REFUSE record and debits nothing, so a module can filter a seed list
        without polluting the audit log with a refusal per candidate.
        """

        if not self.allow_active:
            return False, "active modules disabled (allow_active=false)"
        if self.snapshot is None:
            return False, "no scope snapshot (verify live policy first)"
        if self.snapshot.is_stale(self.clock_now()):
            return False, "scope snapshot is stale; re-fetch + re-bind required"
        try:
            verbs.assert_schedulable(verb)
        except verbs.VerbError as exc:
            return False, str(exc)
        if not verbs.is_active(verb):
            return False, f"{verb!r} is not an active verb"
        binding = self.bind(value)
        if binding.verdict != Verdict.IN_SCOPE:
            return False, f"not in scope: {binding.rule_matched} ({binding.verdict.value})"
        return True, binding.rule_matched

    def gate_active(
        self,
        value: str,
        verb: str,
        *,
        ledger_key: str | None = None,
        cost: float = 1.0,
    ) -> ScopeBinding:
        """Authorize one active touch of ``value`` with ``verb`` or raise ``GateRefused``.

        Writes an ALLOW/REFUSE gate_decision_recorded event either way.

        ``ledger_key`` charges the rate budget to an explicit owning target instead of to
        ``value`` itself. Pass it when probing a bare IP: the safety model requires the
        ledger be keyed by registrable domain / apex / vhost and explicitly NOT by a shared
        IP, so a port scan of an address reached via a hostname should be charged to that
        hostname's target, not to the address.

        ``cost`` prices an expensive verb above the flat unit, so a multi-probe action can
        declare what it really spends rather than charging one token per connect.
        """

        def refuse(reason: str):
            self.graph.log.append("gate_decision_recorded",
                                  {"decision": "REFUSE", "value": value, "verb": verb, "reason": reason})
            raise GateRefused(reason)

        if not self.allow_active:
            refuse("active modules disabled (allow_active=false)")
        if self.snapshot is None:
            refuse("no scope snapshot (verify live policy first)")
        if self.snapshot.is_stale(self.clock_now()):
            refuse("scope snapshot is stale; re-fetch + re-bind required")
        try:
            verbs.assert_schedulable(verb)
        except verbs.VerbError as exc:
            refuse(str(exc))
        if not verbs.is_active(verb):
            refuse(f"{verb!r} is not an active verb")
        binding = self.bind(value)
        if binding.verdict != Verdict.IN_SCOPE:
            refuse(f"not in scope: {binding.rule_matched} ({binding.verdict.value})")
        try:
            entry = self.ledger.debit(ledger_key or value, verb, cost)
        except RateBudgetExceeded as exc:
            refuse(str(exc))
        self.graph.log.append("rate_debit",
                              {"target": entry.target, "verb": verb, "balance_after": entry.balance_after})
        self.graph.log.append("gate_decision_recorded",
                              {"decision": "ALLOW", "value": value, "verb": verb,
                               "rule": binding.rule_matched})
        return binding


class Module:
    name: str = "base"
    produces: tuple[str, ...] = ()
    active: bool = False

    def __init__(self, ctx: ModuleContext) -> None:
        self.ctx = ctx
        self.log = ctx.logger.getChild(self.name)

    def run(self, seeds: list) -> dict:
        """Run the module. Returns a small summary dict. Emits via ``self.ctx.graph``."""

        raise NotImplementedError


_REGISTRY: dict[str, type[Module]] = {}


def register(cls: type[Module]) -> type[Module]:
    if cls.name in _REGISTRY and _REGISTRY[cls.name] is not cls:
        raise ValueError(f"duplicate module name: {cls.name}")
    _REGISTRY[cls.name] = cls
    return cls


def get_module(name: str) -> type[Module]:
    if name not in _REGISTRY:
        raise KeyError(f"unknown module {name!r}; registered: {sorted(_REGISTRY)}")
    return _REGISTRY[name]


def registry() -> dict[str, type[Module]]:
    return dict(_REGISTRY)
