"""The autonomous loop (``docs/SPEC.md`` §7).

```
loop (per cycle, bounded by budget + stop conditions):
  1. PERCEIVE   refresh scope snapshot if stale; read coverage + gap queue
  2. DECIDE     pop highest priority(gap); human-gated gaps enqueue, never auto-run
  3. GATE       verb whitelist + scope + rate ledger  (enforced in ModuleContext.gate_active)
  4. ACT        dispatch exactly one module (passive-first)
  5. EVIDENCE   content-address raw proof + attach PROV   (done by the module)
  6. UPDATE     fold into graph: dedupe, log-odds update, fork on contradiction
  7. RECOMPUTE  update coverage; emit per-run diff; enqueue derived gaps
```

Invariants held here: the loop never widens scope, never escalates a verdict, never invents
a verb, never spends a negative budget. It halts on budget exhaustion, a dry gap queue, a
stale/missing snapshot, or any safety-invariant violation.

``dry_run`` is the **default**: the loop plans and reports what it *would* do without
dispatching anything, so an AI session can inspect the plan before authorizing work.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from . import clock, invariants, planner, verbs
from .coverage import Gap, GapQueue
from .modules import GateRefused, load_all
from .modules.base import ModuleContext
from .store import GraphStore


@dataclass
class CycleRecord:
    cycle: int
    gap_id: str
    module: str
    verb: str
    passive: bool
    outcome: str  # "planned" | "ran" | "refused" | "skipped" | "error"
    detail: str = ""
    diff: dict = field(default_factory=dict)


@dataclass
class LoopResult:
    cycles: list[CycleRecord] = field(default_factory=list)
    halted_because: str = ""
    violations: list = field(default_factory=list)
    human_gated: list = field(default_factory=list)
    coverage: dict = field(default_factory=dict)

    @property
    def ran(self) -> int:
        return sum(1 for c in self.cycles if c.outcome == "ran")

    def summary(self) -> dict:
        return {
            "cycles": len(self.cycles),
            "ran": self.ran,
            "halted_because": self.halted_because,
            "violations": len(self.violations),
            "human_gated_gaps": len(self.human_gated),
            "coverage": self.coverage,
        }


class AutonomousLoop:
    def __init__(
        self,
        ctx: ModuleContext,
        *,
        dry_run: bool = True,
        max_cycles: int = 50,
        max_active_actions: int | None = None,
        passive_first: bool = True,
        include_prefilter: bool = False,
    ) -> None:
        self.ctx = ctx
        self.dry_run = dry_run
        self.max_cycles = max_cycles
        self.max_active_actions = max_active_actions
        self.passive_first = passive_first
        self.include_prefilter = include_prefilter
        self._active_spent = 0
        self._attempted: set[str] = set()

    # --- helpers --------------------------------------------------------
    @property
    def store(self) -> GraphStore:
        return self.ctx.graph.store

    def _select(self, queue: GapQueue) -> Gap | None:
        """Passive-first selection; human-gated gaps are never auto-selected."""

        ranked = [g for g in queue.ranked() if not g.human_gated]
        ranked = [g for g in ranked if g.id not in self._attempted]
        if not ranked:
            return None
        if self.passive_first:
            passive = [g for g in ranked if g.passive]
            if passive:
                return passive[0]
        return ranked[0]

    def _counts(self) -> dict:
        return self.store.counts()

    @staticmethod
    def _diff(before: dict, after: dict) -> dict:
        out = {}
        for k in set(before) | set(after):
            delta = after.get(k, 0) - before.get(k, 0)
            if delta:
                out[k] = delta
        return out

    def _halt(self, result: LoopResult, why: str) -> LoopResult:
        result.halted_because = why
        self.ctx.graph.log.append("loop_halted", {"reason": why})
        result.coverage = planner.coverage_report(self.store)
        return result

    # --- the loop -------------------------------------------------------
    def run(self, now: datetime | None = None) -> LoopResult:
        now = now or self.ctx.clock_now()
        result = LoopResult()
        available = load_all()

        for cycle in range(1, self.max_cycles + 1):
            # 1. PERCEIVE — a stale or missing snapshot blocks all downstream action.
            if self.ctx.snapshot is None:
                return self._halt(result, "no scope snapshot (verify live policy first)")
            if self.ctx.snapshot.is_stale(now):
                return self._halt(result, "scope snapshot stale; re-fetch + re-bind required")

            violations = invariants.check(
                self.store, ledger=self.ctx.ledger,
                current_snapshot=self.ctx.snapshot.snapshot_id,
                log=self.ctx.graph.log, snapshot=self.ctx.snapshot,
            )
            if violations:
                result.violations = violations
                for v in violations:
                    self.ctx.graph.log.append("invariant_violation",
                                              {"code": v.code, "detail": v.detail})
                return self._halt(result, f"safety invariant violation ({violations[0].code})")

            queue = GapQueue()
            history = planner.dispatch_history(self.ctx.graph.log)
            for gap in planner.plan(self.store, now, allow_active=self.ctx.allow_active,
                                    include_prefilter=self.include_prefilter,
                                    dispatched=history):
                queue.enqueue(gap)
            result.human_gated = queue.human_gated()
            for gap in queue.ranked():
                self.ctx.graph.log.append("gap_enqueued",
                                          {"id": gap.id, "priority": round(gap.priority, 3),
                                           "module": gap.module, "verb": gap.verb},
                                          cycle=cycle, idempotency_key=f"gap:{gap.id}:{cycle}")

            # 2. DECIDE
            gap = self._select(queue)
            if gap is None:
                return self._halt(result, "gap queue dry")

            self._attempted.add(gap.id)
            is_active = not gap.passive
            if is_active and self.max_active_actions is not None \
                    and self._active_spent >= self.max_active_actions:
                return self._halt(result, "active-action budget exhausted")

            # 3. GATE (verb whitelist here; scope + ledger inside gate_active)
            try:
                verbs.assert_schedulable(gap.verb)
            except verbs.VerbError as exc:
                result.cycles.append(CycleRecord(cycle, gap.id, gap.module, gap.verb,
                                                 gap.passive, "skipped", str(exc)))
                continue

            self.ctx.graph.log.append("gap_dispatched",
                                      {"id": gap.id, "module": gap.module, "verb": gap.verb,
                                       "dry_run": self.dry_run}, cycle=cycle)

            # 4. ACT
            if self.dry_run:
                result.cycles.append(CycleRecord(cycle, gap.id, gap.module, gap.verb,
                                                 gap.passive, "planned", gap.note))
                continue

            module_cls = available.get(gap.module)
            if module_cls is None:
                result.cycles.append(CycleRecord(cycle, gap.id, gap.module, gap.verb,
                                                 gap.passive, "skipped",
                                                 f"module {gap.module!r} not registered"))
                continue

            before = self._counts()
            try:
                # 5./6. the module captures evidence and folds findings into the graph
                module_cls(self.ctx).run(planner.seeds_for(gap, self.store))
                outcome, detail = "ran", ""
                if is_active:
                    self._active_spent += 1
            except GateRefused as exc:
                outcome, detail = "refused", exc.reason
            except Exception as exc:  # one bad module must not kill the run
                outcome, detail = "error", f"{type(exc).__name__}: {exc}"
                self.ctx.logger.warning("module %s failed: %s", gap.module, detail)

            # 7. RECOMPUTE — emit the per-cycle diff
            diff = self._diff(before, self._counts())
            if diff:
                self.ctx.graph.log.append("coverage_updated", {"diff": diff}, cycle=cycle)
            result.cycles.append(CycleRecord(cycle, gap.id, gap.module, gap.verb,
                                             gap.passive, outcome, detail, diff))

        return self._halt(result, "max cycles reached")
