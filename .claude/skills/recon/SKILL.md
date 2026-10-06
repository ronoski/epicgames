---
name: recon
description: Drive the autonomous recon pipeline in this repo — verify scope, inspect the ranked gap queue, dry-run or execute the loop, and check safety invariants. Use when asked to run recon, plan recon, check scope, or continue the autonomous recon loop. Authorized, non-destructive reconnaissance only.
---

# Running the autonomous recon pipeline

This repo implements a scope-aware, event-sourced recon knowledge base. Specification:
`docs/SPEC.md`; binding safety rules: `docs/safety-model.md`; architecture + runbook:
`docs/pipeline.md`.

## Non-negotiables

Read `docs/safety-model.md` before an execute run. In short:

- **Dry-run is the default.** Never pass `--execute` unless the user has explicitly
  authorized active probing for this engagement *in this conversation*.
- **Scope ≠ ownership.** Nothing is probed without an `in_scope` verdict against a pinned,
  non-stale policy snapshot. A target being owned by the org is not authorization.
- **Verify scope against the live program policy first.** Config `scope.include` must be
  filled from the real policy and `policy_text` pinned. If `scope-check` returns exit 2
  (`adjudication_pending`), stop and ask a human.
- If `recon invariants` exits non-zero, **stop**. Fix the data; never re-run around it.
- Human-gated gaps (GraphQL field-suggestion, response-diff param mining, content
  wordlists) are never auto-run. Surface them to the user; don't try to run them manually.
- Never edit `recon/verbs.py`, `recon/scope.py`, `recon/ratelimit.py` or
  `recon/invariants.py` to make something pass. Those are the safety controls.

## Workflow

Run from the repo root with `PYTHONPATH=.` (or install with `pip install -e .` to get the
`recon` entry point).

```bash
# 0. Smoke-test the pipeline safely (reserved domains, active OFF, no packets):
python3 -m recon plan -c configs/lab.selftest.yaml --json

# 1. Verify scope. Exit 2 => ambiguous, ask a human.
python3 -m recon scope-check -c configs/<prog>.yaml --json <host> [<host> ...]

# 2. Inspect the ranked gap queue (read-only).
python3 -m recon plan -c configs/<prog>.yaml --json

# 3. Dry-run the loop (dispatches nothing, spends no rate budget).
python3 -m recon run -c configs/<prog>.yaml --json --max-cycles 25

# 4. ONLY with explicit user authorization + allow_active: true in config:
python3 -m recon run -c configs/<prog>.yaml --execute --max-active 20 --json

# 5. Always finish by gating on the invariants.
python3 -m recon invariants -c configs/<prog>.yaml --json
```

## Interpreting `run` output

- `cycles_detail[].outcome`: `planned` (dry-run) · `ran` · `refused` (gate said no; reason
  in `detail`) · `skipped` (module not registered / verb not schedulable) · `error`.
- `diff` per cycle = nodes added by type. This is the per-run delta that makes the
  knowledge base diffable over time.
- `halted_because` is informative, not a failure: `gap queue dry`, `active-action budget
  exhausted`, `scope snapshot stale`, `safety invariant violation (Ix)`, `max cycles
  reached`.
- `human_gated_gaps` need human authorization — report them, don't run them.

A `refused` outcome is the system working. Report the reason; do not attempt a workaround.

## Reporting back

Summarize: nodes by type, coverage averages, what the cycles did, the per-cycle diffs, any
`refused`/`violations`, and the human-gated gaps awaiting authorization. For a long-term
target the **delta since the last run** is the headline, not the raw totals.

## Extending

To add a recon module see `docs/pipeline.md` §4: one file under
`recon/modules/{passive,active}/` (auto-discovered), plus a `Rule` in `recon/planner.py` so
the loop schedules it. Active modules must gate **every** network touch through
`ctx.gate_active(value, verb)`. Tests must be fully offline (monkeypatch
`requests`/`socket`/`ssl`) — never contact a real host in a test.
