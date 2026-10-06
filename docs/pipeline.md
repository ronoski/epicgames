# Pipeline architecture & AI-session runbook

How the implementation in [`recon/`](../recon/) realizes [`SPEC.md`](SPEC.md), and how an
autonomous AI session drives it safely.

> Dry-run is the default. Active modules are **off** unless config sets `allow_active: true`
> **and** a non-stale scope snapshot exists. `--execute` alone cannot start probing anything.

---

## 1. Layers

```
                 ┌─────────────────────────────────────────────┐
  CLI / AI  ───▶ │ cli.py   scope-check · modules · plan · run · invariants (JSON out)
                 └───────────────┬─────────────────────────────┘
                                 ▼
                 ┌─────────────────────────────────────────────┐
                 │ loop.py      the 7-step autonomous contract │
                 │ planner.py   gap rules → ranked gap queue   │
                 └───────────────┬─────────────────────────────┘
                                 ▼
                 ┌─────────────────────────────────────────────┐
                 │ modules/     passive/* · active/*  (gated)  │
                 └───────────────┬─────────────────────────────┘
                                 ▼
  SAFETY ─────▶  scope.py (default-deny verdicts) · verbs.py (closed whitelist)
                 ratelimit.py (ONE per-target ledger, fail-closed) · snapshot.py (policy pin)
                 invariants.py (I1–I9 over the data)
                                 ▼
  DATA ───────▶  events.py (append-only log = source of truth)
                 store.py (graph projection: dedupe · merge · FORK on contradiction)
                 models.py (per-datum calculus) · evidence.py (content-addressed)
                 ontology.py (closed type registry)
```

Every active network touch funnels through **one** chokepoint —
`ModuleContext.gate_active(value, verb)` in [`modules/base.py`](../recon/modules/base.py) —
which enforces, in order: active enabled → snapshot present → snapshot non-stale → verb on
the whitelist → verb is an active verb → verdict is `in_scope` → rate ledger debit succeeds.
It writes an `ALLOW`/`REFUSE` PROV record either way. A passive module must never call it.

## 2. Why the loop gets *deep* rather than wide

The planner does not run a script; it derives the graph's **negative space** and closes the
highest-value unknown. Because each closure creates the next gap, depth is emergent:

```
Domain  ──enumerate-ct(passive)──▶  DNSName
DNSName ──resolve──▶ Host ──scan-host──▶ Service
DNSName ──probe-http──▶ WebApp ──tls-fingerprint──▶ cert/SAN → new candidates
                           ├──auth-model──▶ AuthScheme · Token · Flow      (L4)
                           └──api-contract──▶ Route · Operation · Parameter (L3)
                                              graphql-contract ──▶ ObjectType (L5)
```

Priority is `value × staleness × confidence_deficit ÷ cost`, so the loop naturally prefers
cheap passive breadth first, then unresolved names, then the deep contract layers — and
re-verifies facts once they pass their decay half-life. Unverified guesses (permutations,
SAN pivots) enter as **`Hypothesis`** nodes and are only promoted to real nodes once an
active probe confirms them; unconfirmed ones simply decay.

## 3. The AI-session runbook

```bash
# 0. Verify scope FIRST. Fill configs/<program>.yaml from the live policy; paste the policy
#    text into policy_text so a content-hashed snapshot can be pinned.
recon scope-check -c configs/prog.yaml --json  api.target.com  out-of-scope.com
#    -> exit 2 means at least one value is adjudication_pending: ask a human.

# 1. See what the loop *would* do. Read-only; touches nothing.
recon plan -c configs/prog.yaml --json

# 2. Dry-run the loop end to end (still touches nothing).
recon run -c configs/prog.yaml --json --max-cycles 25

# 3. Only after scope is verified and allow_active: true is set deliberately:
recon run -c configs/prog.yaml --execute --max-active 20 --json

# 4. Check the safety invariants over the resulting graph. Non-zero exit = stop.
recon invariants -c configs/prog.yaml --json
```

**Reading `run` output.** `cycles_detail[].outcome` is one of `planned` (dry-run),
`ran`, `refused` (the gate said no — the reason is in `detail`), `skipped`, `error`.
`human_gated_gaps` are the volume-probe verbs (GraphQL field-suggestion, response-diff
param mining, content wordlists) that the loop **will never auto-run**: surface them to a
human for authorization. A non-empty `violations` array means the loop halted on a safety
invariant — fix the data, do not re-run around it.

**Halt reasons** are deliberate, not failures: `no scope snapshot`, `scope snapshot stale`,
`gap queue dry`, `active-action budget exhausted`, `safety invariant violation (Ix)`,
`max cycles reached`.

## 4. Adding a module

Create one file under `recon/modules/passive/` or `active/` — auto-discovered by
`load_all()`:

```python
@register
class MyModule(Module):
    name = "my_module"
    produces = ("DNSName",)
    active = True          # active ⇒ MUST gate every network touch

    def run(self, seeds: list) -> dict:
        for node in seeds:
            fqdn = node.id.split(":", 1)[1]
            try:
                binding = self.ctx.gate_active(fqdn, "resolve")   # ← the chokepoint
            except GateRefused as exc:
                self.log.info("skip %s: %s", fqdn, exc.reason)
                continue
            ...                                                    # one probe, no retries
            ev = self.ctx.evidence.put_text(raw)
            self.ctx.graph.upsert_node(make_node(
                "Host", f"host:{ip}", binding=binding, source=self.name,
                attrs={"active_probed": True}, evidence=[ev],
                coverage={"enumerated": True},
            ))
        return {"resolved": n}
```

Then add a `Rule` in [`planner.py`](../recon/planner.py) so the loop knows when to schedule
it. Rules are declarative, so the depth ladder stays auditable.

**Module rules** (a reviewer checks these): never put a secret value in `attrs` (use
`evidence.redact`); `Credential`/`Token` nodes need `sensitivity >= S1`; other-person data
is `data_subject="other"` + `S3` and may never be an edge endpoint; only declared ontology
types; unverified guesses are `Hypothesis`; network errors log-and-continue; and tests must
be fully offline (monkeypatch `requests`/`socket`/`ssl` — never contact a real host).

## 5. What is deliberately *not* here

No exploitation, no fuzzing at volume, no credential use (discovered client-ids stay static
mapping facts), no takeover claiming, no bucket writes, no WAF/rate evasion, no in-process
instrumentation of anti-cheat-coupled clients, no third-party persona lookups. These are on
the blocked verb list in [`verbs.py`](../recon/verbs.py) and cannot be scheduled. See
[`safety-model.md`](safety-model.md).
