# Safety Model — Authoritative

This is the binding safety model for the autonomous recon workflow. It consolidates the hardening
from the adversarial reviews of both the binary-RE and non-binary domain specs. **The autonomous
loop must not spend any active budget until every control here holds.** Where a domain reference
under [`domains/`](domains/) disagrees, this file wins.

Scope of use: **authorized** reconnaissance for Epic Games' HackerOne program, **strictly
non-destructive**, on assets you are authorized to test and on your **own** accounts/devices only.

---

## 1. First principles

1. **Default-deny.** Nothing is retained or acted on without a positive, current `in_scope` verdict.
2. **`scope != ownership`.** Epic ownership is at most a prefilter (§2).
3. **Non-destructive only.** The verb whitelist is closed (§3); the loop cannot invent a verb.
4. **Passive-first, rate-bounded.** One unified per-target ledger (§4).
5. **Observation, not action, on credentials and other users** (§5, §6).
6. **Everything is evidenced, labeled, and reproducible** (§7).
7. **The controls are machine-checkable** and enforced in CI over the data itself (§9).

---

## 2. Scope binding (`scope != ownership`)

- A value being Epic-owned (domain, netblock, GitHub org, bucket name, cert `O=Epic Games, Inc.`) is
  a **prefilter**, never authorization.
- `retain(x) ⇒ x.scope_binding.snapshot_id == current_nonstale_snapshot`.
- `act(x) ⇒ x.scope_binding.verdict == in_scope`.
- Verdicts: `in_scope | out_of_scope | prefilter_only | adjudication_pending`.
- **Exclusion rules win**; the most-restrictive matching rule wins; policy markdown and
  `structured_scopes` disagreeing ⇒ capture both, most-restrictive wins; ambiguous ⇒
  `adjudication_pending` (no active touch) pending human adjudication.
- `prefilter_only` (owned-but-unlisted) retention is capped at coverage `enumerated`, bounded in
  retention window, sensitivity-labeled, and **never drives an active touch**.
- A snapshot older than its (short) half-life, an ETag change, or a `scope_drift_event` **blocks all
  downstream action** until re-bound. A verdict change **forks** the binding history.
- **Known traps:** Bandcamp (divested to Songtradr, Oct 2023) is out; `fhir.epic.com` /
  `userweb.epic.com` are Epic Systems (healthcare, a different company) — out. Reading the HackerOne
  platform policy targets `hackerone.com`, not Epic, and does not debit an Epic budget.

---

## 3. Closed recon-verb whitelist

**Allowed (non-destructive recon):**
`resolve · enumerate · passive-collect · fingerprint · http-GET · http-HEAD · read-openapi ·
graphql-introspect(read-only) · parse · crawl-within-scope · port-scan(rate-limited) ·
bucket-list(read-only) · hash · unzip · strings · nm/objdump-symbols · static-decompile ·
parse-manifest · parse-catalog · diff-manifest · extract-endpoint · extract-client-id(read-only)`

**Blocked (never schedulable):**
`any write/mutate · credential brute-force · OTP/login brute · exploit · fuzz-at-volume · DoS ·
auth-bypass · WAF/geo/rate evasion · data-exfil · takeover-claim · bucket write · dependency-confusion
publish · email-spoof test · ID enumeration against others · third-party persona/account/email lookup
· patch · inject · hook-runtime · bypass · circumvent · crack · keygen · repack · redistribute ·
memory-write · server-call-with-forged-arg`

**Human-gated (proposed verbs — enqueue, never auto-run):** GraphQL field-suggestion (clairvoyance),
response-diff parameter mining (arjun/kiterunner), content-discovery wordlists. Each has a hard low
ceiling and requires passive JS/HAR/archive extraction to be exhausted first.

---

## 4. One unified per-target rate-budget ledger

- A **single** authoritative per-target token bucket is debited by **every** domain (DNS brute, port
  scan, HTTP, crawl, handshake/JARM, manifest reads, …).
- Ledger key = registrable domain / apex / bucket-name / vhost / authoritative-NS — **not** a shared
  IP (one CDN IP fronts many tenants).
- The scheduler **serializes** active touches per target under a global QPS ceiling + low concurrency
  cap; aggregate spend is recorded in PROV.
- `∀ target: ledger.balance(target) ≥ 0`; a call that would drive any budget negative is **refused
  and requeued**. No borrowing across targets.
- Machine-rate tools (massdns/puredns, naabu/nmap, feroxbuster/ffuf, zgrab2, …) are wrapped in a
  harness that **fails closed** if it would exceed the ceiling, and the enforced rate is recorded so
  a non-compliant run is detectable.
- Detecting a WAF/CDN lowers remaining budget and widens spacing. Back off immediately on
  403/429/challenge. **No evasion of any control.**
- DNS brute: cap wordlist+permutation size per cycle, wildcard-baseline before accepting answers,
  spread across cycles, debit the NS ledger per query batch. AXFR/NSEC3: one attempt,
  REFUSED-is-terminal (no retry), any cracking strictly offline.

---

## 5. Credentials and secrets

- **Default-deny live use.** Discovered `client_id`/secret/EOS creds are **static mapping facts**;
  coverage caps at `enumerated`.
- Any authenticated call (incl. a single `client_credentials` POST) or `deviceAuth` provisioning
  requires an explicit **program-authorization token** and its own gate record, and only ever against
  the researcher's **own** account/session.
- **Sensitivity taxonomy** (the label decides handling):

  | Label | Meaning | Handling |
  |-------|---------|----------|
  | S0 | Public (JWKS verify keys, signing certs, SPKI pins) | Retain; benign read-only fetch (logged) |
  | S1 | Semi-public/embedded (game OAuth pairs, EOS ids, Firebase api_key) | Record as mapping; never used to reach non-own data |
  | S2 | Write/ingest-capable third-party (Sentry DSN, Adjust/AppsFlyer, AWS-shaped) | Encrypt-at-rest; **send no request to the vendor** |
  | S3 | Secret/PII (access/refresh tokens, device_auth secret, email/displayName) | Quarantine, encrypt, redact to prefix+hash, short decay, **report-don't-use** |
  | S4 | Prohibited (anti-cheat/integrity bypass material) | Writer **rejects** the node |

- Evidence is content-addressed and **encrypted at rest** per class; a **pre-commit secret-scan hook**
  is itself a safety invariant. Secret-scanners run with **verification disabled**. Entropy alone is a
  false-positive generator — require entropy + known format + context before minting a `Credential`.
- Firebase api_key / EOS ids / embedded public-client secrets are **public identifiers, not
  vulnerabilities** — label correctly, never operationalize. Honeytokens exist — report-not-use.
- **No redistribution** of any artifact, decrypted binary, extracted asset, or key.

---

## 6. Privacy

- Any field whose `data_subject != self` is **hash-redacted at ingest** and may never be an edge
  endpoint toward a non-owned resource; friends/party/matchmaking rosters drop to counts unless a
  specific self-scoped reason is recorded.
- **Third-party persona/account/email lookups are BLOCKED outright** — issuing a query against
  another user's account is acting on another user's resource; post-hoc redaction does not cure it.
- OSINT attribution is **org-level only** ("which Epic dev org owns which asset"); **no
  per-maintainer/individual profiling**, even with hashed emails.
- Breach/paste data is **metadata-only** (`contents_ingested=false`); never ingested, never
  redistributed. PII minimization applies **before** storage, not after.

---

## 7. Client reverse-engineering: hard stops and the legal gate

### 7.1 Hard stops (machine-enforced; refused regardless of other gate state)

- **§7 controls over §1201.** No unwrapping/decrypting/devirtualizing of DRM, FairPlay, UE-pak AES,
  encrypted BPS/ChunksV5, or anti-cheat integrity — **regardless of any DMCA §1201 posture**.
  `circumvents_tpm == true` ⇒ **REFUSE** absent explicit, documented, per-asset program + legal
  authorization. A generic exemption citation never authorizes it. The §1201 anti-trafficking bars
  separately forbid building/sharing any circumvention tool, key, or patched client.
- **Anti-cheat (Easy Anti-Cheat — Epic-owned; BattlEye):** never defeat, bypass, disable, patch,
  hook, unload, emulate, reverse-for-bypass, or touch kernel drivers. **No in-process instrumentation
  of any AC- or integrity-coupled client process** (Frida/objection/gadget/debugger), including
  pre-match/login surfaces. Observe such clients by **network-layer capture of your own traffic
  only** (PCAPdroid/mitmproxy). Anti-cheat artifacts are capped at coverage `inventoried`.
- **Own device / own account / own session only.** Never another user's account/data/session; no
  cheat creation; no DoS. If a client detects instrumentation and refuses to run, that is a **STOP**
  signal — fall back to network capture, never escalate evasion. Root/unpinning is confined to
  isolated devices never used to reach shared/AC-protected services.
- Mutating MCP verbs (e.g. `MarkItemSeen`) are excluded from the recon whitelist; deeplinks are
  classified by side-effect before any dispatch (own instance only).

### 7.2 The 12-check pre-action gate

Every RE action writes an `ALLOW`/`REFUSE` PROV `gate_decision_record` **before** the activity; a
`REFUSE` blocks it. All must pass:

| # | Check | Pass condition |
|---|-------|----------------|
| 1 | Scope | `scope_binding.verdict == in_scope` vs a non-stale snapshot |
| 2 | Authorization | program authorizes client RE for this asset/finding-class (`unknown` ⇒ REFUSE) |
| 3 | Lawful copy | `acquisition_provenance` proves official channel + own account/device + matching hash |
| 4 | TPM | **if `circumvents_tpm` ⇒ REFUSE** (per §7.1) unless explicit per-asset authorization attached |
| 5 | Anti-cheat | `anti_cheat_classification.action_mode != runtime_circumvent`; no in-process hook on AC client |
| 6 | Ownership | dynamic evidence ⇒ `session_is_own` ∧ `¬touched_other_user` ∧ `data_subjects == [self]` |
| 7 | Verb | `recon_verb_label` on the whitelist (§3) |
| 8 | Sensitivity | handling set for every secret/PII; `¬may_be_used_to_access` |
| 9 | No trafficking | `no_trafficking_guard` all-false; `disclosure_channel == hackerone_report_only` |
| 10 | Rate | unified per-target ledger not exceeded |
| 11 | Corpus | legal corpus pins current EULA/statute versions; §1201 reg-exemption within its window |
| 12 | Record | the `gate_decision_record` is written and linked before the activity |

### 7.3 Legal stack (context for checks 2/4/11)

Four layers must hold simultaneously — none substitutes for another: ① HackerOne program
authorization (the only instrument that contractually addresses Epic's EULA RE-prohibition, within
its grant); ② DMCA §1201 (bounded by §7.1 — a §1201 exemption shields only the anti-circumvention
claim, never EULA/CFAA/anti-cheat, and §7.1 forbids the circumvention regardless); ③ EULA/contract;
④ ethics/CFAA (own-device/own-account/own-session). **All Epic specifics here are verify-live.**

---

## 8. Stop conditions (autonomous loop)

Halt the cycle on any of: budget exhausted; gap queue dry (K consecutive empty cycles); scope
snapshot unreachable/stale and un-refreshable; a safety-invariant violation (halt + alert, do not
continue). Every cycle is replayable from the event log for audit.

---

## 9. Machine-checkable invariants (CI over the data)

```
I1  retain(x)         ⇒ x.scope_binding.snapshot_id == current_nonstale_snapshot
I2  act(x)            ⇒ x.scope_binding.verdict == in_scope
I3  evidence.active   ⇒ node.scope_binding_at_observation == in_scope         (else reject at ingest)
I4  ∀ target          : ledger.balance(target) ≥ 0
I5  derived_from(A)   ⇒ A.authorization_basis ∧ A.acquisition_provenance ∧ A.in_scope
I6  ∄ node            : anti_cheat_classification.action_mode == runtime_circumvent
I7  ∄ Artifact        : no_trafficking_guard.is_circumvention_tool ∨ published_externally
I8  ∀ Credential|Token|non-self ObjectType : has sensitivity_label
I9  ∄ edge            : endpoint ∈ {secret, pii} ∧ target == non_owned_resource
I10 scheduled(verb)   ⇒ verb ∈ whitelist
I11 contradiction     ⇒ fork (never overwrite)
I12 stale(snapshot)   ⇒ block all downstream action until re-bound
```

A build/run that cannot satisfy these over the current graph does not proceed.
