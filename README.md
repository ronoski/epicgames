# epicgames

**Autonomous, scope-aware reconnaissance workflow** for Epic Games' authorized
[HackerOne bug-bounty program](https://hackerone.com/epicgames) — designed to be driven by an
autonomous AI session and to grow a **long-lived, event-sourced knowledge graph** of Epic's
federation over time.

> **Authorized security research only.** This is strictly **non-destructive reconnaissance**
> (enumeration, discovery, contract/flow mapping) on assets you are authorized to test, and on your
> **own** accounts/devices only. No exploitation, DoS, data modification, credential abuse,
> anti-cheat tampering, or acting on other users' resources. **Scope is bound to the live program
> policy, not Epic ownership** — confirm the current scope before anything runs.

## Status

This repository currently holds the **design specification only** — no pipeline code yet, by intent,
so the data model and safety model can be redlined against a pinned target first.

## What's here

- **[`docs/SPEC.md`](docs/SPEC.md)** — the authoritative master spec (ontology, per-datum calculus,
  event-sourcing, coverage/gap model, intelligence domains, the autonomous-loop contract).
- **[`docs/safety-model.md`](docs/safety-model.md)** — the authoritative, binding safety model
  (`scope != ownership`, the recon-verb whitelist, the unified rate ledger, the client-RE hard stops
  and legal gate, and the machine-checkable invariants).
- **[`docs/domains/`](docs/domains/)** — detailed, AI-synthesized working references for the binary-RE
  and live/OSINT recon domains (pending verification; corrections banners at top).
- **[`schema/`](schema/)** — JSON schemas pinning the ontology and the per-datum envelope.
- **[`configs/epicgames.example.yaml`](configs/epicgames.example.yaml)** — scope-config skeleton to
  fill from the live policy.

Start with [`docs/README.md`](docs/README.md) for the reading order, and
[`TODO.md`](TODO.md) for what's outstanding.

## The bar for "deep" recon data

A connected, attributed, scope-clean, prioritized, **diff-over-time** graph — with per-datum
provenance, calibrated confidence, content-addressed evidence, temporal decay and a snapshotted
scope-binding — whose **coverage model drives a gap queue that schedules the autonomous loop**.
Not a flat list of subdomains.
