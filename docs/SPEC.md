# Autonomous Recon Workflow — Master Specification

**Target:** Epic Games' authorized HackerOne bug-bounty program (`hackerone.com/epicgames`).
**Nature:** A long-term, autonomous, scope-aware reconnaissance **knowledge base** that an AI
session grows over months — not a one-shot scanner.
**Hard constraint:** Strictly **non-destructive reconnaissance** (enumeration, discovery,
contract/flow mapping) on assets the researcher is authorized to test and on their **own**
accounts/devices only. Never exploitation, DoS, data modification, credential abuse, anti-cheat
tampering, or acting on another user's resources.

> This document is **authoritative**. The detailed domain references under
> [`docs/domains/`](domains/) are AI-synthesized working material pending verification; where they
> disagree with this file or [`safety-model.md`](safety-model.md), **these win**.

---

## 1. Purpose and operating model

The deliverable is a **versioned, event-sourced, typed knowledge graph** of Epic's federation —
breadth across many intelligence domains, depth down to API contracts, auth model, object model and
business flows — where every datum carries provenance, calibrated confidence, evidence, temporal
decay and a snapshotted scope-binding, and where a formal **coverage model** produces a **gap queue**
that *schedules an autonomous AI loop*.

The bar for "deep" is: **a connected, attributed, scope-clean, prioritized, diff-over-time graph with
per-datum provenance and confidence — not a flat list of subdomains.** A one-time dump is not deep;
a tracked, changing, queryable graph is.

### 1.1 Why an AI session runs it

The workflow is designed to be driven by an autonomous AI session (see §7). The AI is the *scheduler
and judge*: it reads the gap queue, picks the highest-value gap, dispatches one recon verb, ingests
the evidence, updates confidence/provenance, recomputes coverage, and emits a diff. Humans redline
the spec, adjudicate scope ambiguity, and authorize anything the gate marks as requiring explicit
authorization.

---

## 2. The data model (ontology)

The graph is **typed**: a closed set of node and edge types. The autonomous loop **cannot invent**
node or edge types; a genuinely new relationship must be added to the proposed-additions table and
promoted by a human before use.

### 2.1 Node types

| Node | Identity | Purpose |
|------|----------|---------|
| `Organization` | `org:<slug>` | Top-level owner (Epic Games, Inc.) |
| `BusinessUnit` | `bu:<slug>` | Acquisition / product line (ArtStation, Psyonix, Mediatonic, SuperAwesome, Fab, …) |
| `Domain` | `domain:<registrable>` | Registrable domain / apex |
| `DNSName` | `dns:<fqdn>` | A hostname and its records |
| `NetBlock` / `ASN` | `net:<cidr>` / `asn:<n>` | IP ranges and autonomous systems |
| `Host` | `host:<ip>` | A resolved IP endpoint |
| `Service` | `svc:<ip>:<port>/<proto>` | A listening service |
| `WebApp` | `web:<scheme>://<vhost>` | A virtual host / web application |
| `Route` | `route:<webapp>/<path-template>` | A path template |
| `Operation` | `op:<method>:<route>` | A typed API operation |
| `Parameter` | `param:<op>#<name>` | A typed input (query/body/path/header) |
| `AuthScheme` | `auth:<id>` | An authentication/authorization mechanism |
| `Credential`/`ClientId` | `cred:<hash>` | An OAuth client id, key, or similar (value stays a mapping fact) |
| `Token` | `tok:<hash>` | A token *shape*/issuer (never a live secret in plaintext) |
| `ObjectType` | `obj:<name>` | A data object/identifier type (accountId, catalogItemId, namespace, …) |
| `Flow` | `flow:<slug>` | A multi-step business/auth process (state machine) |
| `Artifact` | `art:<sha256>` | A client binary/APK/JS bundle/manifest/repo/package |
| `Evidence` | `ev:<sha256>[:region]` | Content-addressed raw proof |
| `Hypothesis` | `hyp:<uuid-from-seed>` | A testable, non-actioned lead (e.g. an IDOR candidate) |

Node ids are **deterministic and content-derived**: `type:<canonicalized-form-or-hash>`.
Canonicalization is specified (§3.1) so merges across runs and sessions are idempotent.

### 2.2 Edge types (closed set)

`resolves_to`, `cname_to`, `hosted_on`, `in_netblock`, `fronted_by`, `vhost_of`, `exposes`, `takes`,
`authenticates_with`, `issued_by`, `grants`, `references_object`, `derived_from`, `calls`, `step_of`,
`evidenced_by`, `corroborates`, `contradicts`, `attributed_to`.

**Proposed additions (declared, human-promote before use):** `originated_by` (NetBlock→ASN),
`same_as` (entity-resolution identity), `co_deploy`, `shared_trust_domain`, `allows_origin`
(WebApp→Origin; requires an `Origin` node declaration first). Until promoted, these are recorded only
as typed `corroborates`/`contradicts` evidence, never as first-class edges. **Naming is unified:**
ownership is always `attributed_to` (never `owned_by`); BGP origin is always `originated_by` (never
`announced_by`); containment (splits/libs/child artifacts) is always `derived_from` (never
`part_of`).

### 2.3 The graph skeleton

```
Organization ─ BusinessUnit/Acquisition
     │
   Domain ── DNSName ── NetBlock/ASN ── Host ── Service ── WebApp ── Route ── Operation ── Parameter
     │   (resolves_to, cname_to, in_netblock, hosted_on, fronted_by, vhost_of, exposes, takes)
     │
 AuthScheme ── Credential/ClientId ── Token        ObjectType ── Flow
 (authenticates_with, issued_by, grants, references_object, step_of, calls)
     │
 Artifact ── Evidence ── Hypothesis
 (derived_from, evidenced_by, corroborates/contradicts, attributed_to)
```

---

## 3. Per-datum calculus (every node AND edge carries this)

### 3.1 Canonical identity

Deterministic ids require specified canonicalization: IDN/punycode normalization + lowercase + strip
trailing dot (hostnames); default-port elision + sorted query + path case rules (URLs); SPKI hash
(certs); `blake2`/`sha256` of the canonical form for hashes. Same input ⇒ same id ⇒ idempotent merge.

### 3.2 Provenance (W3C-PROV DAG)

Not "source: crtsh" but the derivation chain: `Evidence → activity(tool@pinned_version, config_hash)
→ rule(ruleset@version) → derived_fact`. The regex/heuristic **ruleset is itself a versioned `rule`
node**. Reproducibility contract: same evidence + same rule version ⇒ same fact.

### 3.3 Confidence (log-odds calculus)

Confidence is a calibrated **log-odds** value, combined across *independent* sources with declared
independence assumptions. Corroboration from independent sources **raises** it; a **contradiction
FORKS** the node into competing versioned hypotheses and never overwrites history. Thresholds promote
`observed → corroborated → verified`. Penalties (e.g. obfuscation `re_feasibility`) are **additive
log-odds deltas**, not probability multipliers.

### 3.4 Evidence

Content-addressed `{sha256, region}` where region is a byte range / symbol / `class.method` / proto
field-number / manifest xpath / captured request-response hash. Evidence is **encrypted at rest**
per sensitivity class; the graph stores hashes + offsets + derived facts, **never** the copyrighted
artifact or a live secret in plaintext. Every fact is independently replayable.

### 3.5 Temporal + decay

`first_seen / last_seen / last_verified` + a **per-class decay half-life** (DNS short, cert medium,
business-flow long, legal/scope snapshot very short). A fact past its half-life auto-enters the gap
queue for re-validation.

### 3.6 Scope-binding (snapshotted)

Each datum records the **exact scope rule matched**, pinned to a content-hashed, timestamped snapshot
of the live policy *at observation time*. A verdict is one of
`in_scope | out_of_scope | prefilter_only | adjudication_pending`. See §5.

### 3.7 Sensitivity label

`S0 public | S1 semi-public/embedded | S2 sensitive (write/ingest-capable third-party) | S3
secret/PII | S4 prohibited (anti-cheat/integrity bypass material)`. The label, not convenience,
decides handling (§5.6).

---

## 4. Event-sourcing, storage, coverage and the gap queue

### 4.1 Event-sourced store

An **append-only, ordered, idempotent event log is the source of truth**; the queryable graph and
every per-run diff are *projections*. This gives free time-travel to any run, first-class diffs, and
deterministic replay. Events are schema-versioned (`schema/event.schema.json`).

### 4.2 Coverage model

Coverage is a measurable function per entity over weighted booleans — e.g.
`{enumerated, fingerprinted, param_mined, flow_mapped, artifact_correlated}` (plus domain-specific
ladders, see domain docs). It is a **score**, not a boolean. Negative space is explicit: the graph
knows what it has *not* done.

### 4.3 Gap queue (the scheduler)

```
priority(gap) = value × staleness × confidence_deficit ÷ cost
```

The gap queue is the literal scheduler for the autonomous loop. Representative gaps: new build/cert
observed → acquire+diff; wildcard under-enumerated → (scope-gated) resolution; operation with
unmapped params → param discovery; fact past decay half-life → re-verify; scope snapshot stale →
re-fetch + re-bind. **Volume-probe gaps (field-suggestion, response-diff param mining, content
wordlists) never auto-run — they enqueue for human authorization.**

---

## 5. Safety model (authoritative — summary; full text in `safety-model.md`)

This section is binding. Both the binary and non-binary domain specs were adversarially reviewed and
their fixes are consolidated here. **The autonomous loop must not spend any active budget until these
hold.**

### 5.1 `scope != ownership`

Epic ownership (an Epic domain, netblock, GitHub org, bucket name, or a cert with `O=Epic Games,
Inc.`) is **at most a prefilter**. Nothing is retained or acted on unless
`scope_binding.verdict == in_scope` against a **non-stale** content-hashed snapshot of the live
HackerOne policy. Default-deny; **exclusion rules win**; most-restrictive matching rule wins;
ambiguous ⇒ `adjudication_pending`. `prefilter_only` (owned-but-unlisted) retention is capped at
`enumerated` and **never drives an active touch**; its retention is bounded and sensitivity-labeled.

### 5.2 Closed recon-verb whitelist

**Allowed:** `resolve, enumerate, passive-collect, fingerprint, http-GET/HEAD, read-openapi,
graphql-introspect(read-only), parse, crawl-within-scope, port-scan(rate-limited),
bucket-list(read-only), hash, unzip, strings, static-decompile, parse-manifest,
extract-client-id(read-only)`.
**Blocked (the loop cannot invent a verb):** any write/mutate, credential brute-force, exploit,
fuzz-at-volume, DoS, auth/WAF/rate/geo bypass, data-exfil, takeover-claim, bucket write,
dependency-confusion publish, email-spoof test, ID enumeration against others, `patch, inject,
hook-runtime, circumvent, repack, redistribute`.

### 5.3 One unified per-target rate-budget ledger

**All** domains debit a **single** authoritative per-target token bucket (keyed by registrable
domain / apex / bucket-name / vhost / authoritative-NS — **not** by shared IP). The scheduler
serializes active touches per target under a global QPS ceiling + low concurrency cap; aggregate
spend is recorded in PROV. No per-domain parallel budgets; no borrowing across targets; a call that
would drive any budget negative is refused and requeued. Machine-rate tools are wrapped in a harness
that **fails closed** if it would exceed the ceiling. Back off on 403/429/challenge; **no evasion.**

### 5.4 Passive-first

Exhaust third-party/passive/OSINT sources (CT, passive DNS, scan datasets, RDAP/BGP, archives)
before any active touch. Active probing is scope-gated, rate-budgeted, human-rate and non-intrusive.

### 5.5 Default-deny live credential use

Discovered `client_id`/secret/EOS creds are **static mapping facts** (coverage caps at `enumerated`).
Any authenticated call — including a single `client_credentials` POST — or `deviceAuth` provisioning
requires an **explicit program-authorization token and its own gate record**, and only ever against
the researcher's **own** account/session.

### 5.6 Client-RE hard stops

- **§7 of the RE spec controls over the §1201 legal gate.** No unwrapping/decrypting/devirtualizing
  of DRM, FairPlay, UE-pak AES, encrypted BPS/ChunksV5, or anti-cheat integrity — regardless of any
  DMCA §1201 posture. `circumvents_tpm == true` ⇒ **REFUSE** absent explicit, documented, per-asset
  program + legal authorization.
- **No in-process instrumentation of any anti-cheat- or integrity-coupled client process** (EAC /
  BattlEye), including pre-match/login surfaces. Observe such clients by **network-layer capture of
  your own traffic only.** Anti-cheat artifacts are hard-capped at coverage `inventoried`.

### 5.7 Privacy

Any field whose `data_subject != self` is **hash-redacted at ingest** and may never be an edge
endpoint toward a non-owned resource. **Third-party persona/account/email lookups are BLOCKED
outright** (not redacted). OSINT attribution stays **org-level** ("which Epic dev org owns which
asset"); no per-maintainer/individual profiling. Breach/paste data is kept **metadata-only** (never
ingested or redistributed). Secret-scanners run with **verification disabled** (verification = a live
request).

### 5.8 Machine-checkable invariants (checked over the data in CI)

- `retain(x) ⇒ x.scope_binding.snapshot_id == current_nonstale_snapshot`.
- `act(x) ⇒ x.scope_binding.verdict == in_scope`.
- No active-probe/dynamic Evidence may attach to any node whose scope-binding was false at
  observation time (rejected at ingest, not down-weighted).
- `∀ target: ledger.balance(target) ≥ 0` (append-only, auditable).
- Every `derived_from(Artifact)` references an Artifact with non-null `authorization_basis`,
  `acquisition_provenance`, and `in_scope` binding.
- No node with `anti_cheat_classification.action_mode == runtime_circumvent`; no Artifact with
  `no_trafficking_guard.is_circumvention_tool == true` or `published_externally == true`.
- Every `Credential`/`Token`/non-self `ObjectType` carries a `sensitivity_label`; no `secret`/`pii`
  node is an edge endpoint toward a non-owned resource.
- A verb not on the whitelist cannot be scheduled. Contradictions fork; a stale policy snapshot
  blocks all downstream action until re-bound.

### 5.9 Legal gate (client RE)

Every RE action clears a four-layer stack simultaneously — ① HackerOne program authorization,
② DMCA §1201 posture (bounded by §5.6), ③ EULA/contract, ④ ethics/CFAA (own-device/own-account/
own-session) — via a 12-check pre-action gate that writes an `ALLOW`/`REFUSE` PROV
`gate_decision_record` before any activity. Full checklist in [`safety-model.md`](safety-model.md).

---

## 6. Intelligence domains

Two families feed the same graph, oppositely seeded and mutually confirming: **binary RE seeds
candidates that live recon confirms**; live recon corroborates or lets them decay.

### 6.1 Binary & client RE — see [`domains/binary-re.md`](domains/binary-re.md)

Derives recon from Epic's **client software**: Fortnite Android (split APK + OBB), Fortnite iOS (EU
alt-distribution), the Epic Games Launcher, Unreal Engine, the EOS SDK native libs, Rocket League /
Fall Guys, and the BPS/manifest updater. Populates `Artifact → Operation → Parameter → AuthScheme →
Credential → Token → ObjectType → Flow`. Highest-signal extractions: EOS SDK interface census from
exported `EOS_*` symbols; OAuth client-id topology (candidates to re-derive); the buildable surface
from launcher manifest/catalog APIs; protobuf/FlatBuffers schema from real embedded descriptors; and
live Flows from own-session network capture. Static-first; dynamic = own-device network capture only
(no in-process hooks on AC clients).

### 6.2 Non-binary live/OSINT recon — see [`domains/non-binary.md`](domains/non-binary.md)

Twelve interlocking domains over live infrastructure + public/OSINT:

1. **DNS & subdomain** — passive sources + rate-capped brute/permutation, NSEC(3) walk, AXFR (one
   attempt), dangling-record / subdomain-takeover **detection** (first-class given Epic's history).
2. **Network / ASN / IP / ports** — ASN/netblock discovery, reverse-DNS, ownership classification,
   non-intrusive port/service scanning, infra fingerprints (JARM/JA3S/favicon/404/response hashes).
3. **HTTP surface** — liveness, status/title/redirect, security headers, CORS, vhost differential,
   tech/CDN/WAF fingerprint, screenshots. GET/HEAD, one hit, rate-budgeted.
4. **API contract** — OpenAPI/Swagger parse, GraphQL introspection (read-only), gRPC-web/Connect
   reflection, REST route + hidden-param discovery (human-gated at volume), versioning, error
   taxonomy. **(Add: real-time/messaging protocol surface — XMPP/WebSocket/matchmaking/EOS relay.)**
5. **Identity & auth (live)** — OIDC `.well-known`, OAuth2 grants/scopes, JWKS, EOS web auth,
   console account-linking Flows, session model. Metadata + own-account only.
6. **Content / JS / crawl** — in-scope crawl, robots/sitemap, content discovery (capped), JS +
   sourcemap endpoint/secret extraction, Wayback/archive mining. **(Add: AASA / assetlinks.json.)**
7. **Cloud & SaaS** — bucket discovery + **read-only** listing, serverless/API-gateway URLs, SaaS
   tenant attribution (most third-party SaaS is out of scope → record existence, send no probe).
8. **Object / data-model (IDOR/tenancy)** — identifier format taxonomy, per-user vs global objects,
   tenancy boundaries → IDOR/tenancy **hypotheses (detection only, never tested on others)**.
9. **TLS/PKI & email** — CT history + SAN pivot, cert attributes, JARM, SPF/DKIM/DMARC/MTA-STS
   posture, MX/dangling takeover candidates. Passive.
10. **OSINT / leaks / supply chain** — public GitHub/GitLab orgs, public-repo secret scanning
    (verification off), dorks, package registries, breach/paste **mentions** (metadata-only).
    Org-level attribution only.
11. **Scope-drift & attribution** — content-hash + diff the live policy to emit scope-drift events;
    WHOIS/RDAP/ASN/CT attribution to BusinessUnit; **enforces `scope != ownership`.** Gates every
    other domain's retention.
12. **Correlation / entity-resolution / temporal** — collapse identifiers to one logical Service via
    behavior fingerprints; infer the trust/service-mesh graph; cross-corroborate (fork on
    contradiction); emit per-run deltas that feed the gap queue.

### 6.3 Epic seed inventory (all `verify-live` before use)

Wildcard roots: `*.epicgames.com`, `*.epicgames.dev`, `*.fortnite.com`, `*.unrealengine.com`.
Acquisition/product apexes to seed independently: `artstation.com`, `sketchfab.com`, `quixel.com`,
`fab.com` (Epic's unified marketplace — **include**), `rocketleague.com`, `fallguys.com`,
`psyonix.com`, `mediatonic.com`. EOS web auth under `api.epicgames.dev`; dev portal
`dev.epicgames.com`; legacy `*-public-service-prod*.ol.epicgames.com` (each host earns its own
`in_scope` verdict).
**Scope traps (do not include):** Bandcamp (divested to Songtradr, Oct 2023); `fhir.epic.com` /
`userweb.epic.com` (Epic Systems healthcare — a different company). Every apex above must hold a
current `in_scope` verdict against the live snapshot before any active work.

---

## 7. The autonomous-loop contract

```
loop (per cycle, bounded by budget + stop conditions):
  1. PERCEIVE   refresh scope snapshot if stale; read coverage + gap queue
  2. DECIDE     pop highest priority(gap); if gap is a volume-probe → enqueue for human, skip
  3. GATE       scope-bind + verb-whitelist + rate-ledger + (RE) legal gate → ALLOW/REFUSE record
  4. ACT        dispatch exactly one recon verb (passive-first)
  5. EVIDENCE   content-address + encrypt raw proof; attach PROV
  6. UPDATE     fold into graph: dedupe by id, log-odds update, fork on contradiction
  7. RECOMPUTE  update coverage; emit per-run diff; enqueue derived gaps
```

**Invariants:** the loop never widens scope, never escalates a verdict, never invents a verb, never
spends a negative budget. **Stop conditions:** budget exhausted, gap queue dry (K consecutive empty
cycles), scope snapshot unreachable, or a safety-invariant violation (halt + alert). Every cycle is
replayable from the event log.

---

## 8. Schemas, versioning and verification

- `schema/ontology.json` — node & edge type registry (closed set + proposed additions).
- `schema/node.schema.json` — the common node/edge envelope (provenance, confidence, evidence,
  temporal, scope_binding, sensitivity, coverage).
- `schema/event.schema.json` — the event-sourcing event.
- `schema/scope.schema.json` — scope config + the snapshot/binding object + drift event.

The ontology carries a `schema_version`; changes ship with migration transforms and the graph
self-validates on load. A non-reproducible extraction is quarantined as a `Hypothesis` until its
nondeterminism source is pinned.

---

## 9. Status, open questions, corrections

This repository currently holds the **design specification only** — no pipeline code yet, by
intent, so the data model and safety model can be redlined against a pinned target before anything
touches the network.

**Must verify against live sources before building/running (non-exhaustive):** the current
`hackerone.com/epicgames` scope text and whether it is public vs invite-only; whether client RE,
`*.ol.epicgames.com`, `api.epicgames.dev`, and each acquisition apex are in-scope; accepted
finding-classes; anti-cheat scope language; all client_id/secret/EOS identifier values (candidates
only); OAuth paths/grants/token formats; prod-shard numbering; EOS SDK version per client; BPS
format internals; current cloud/ASN footprint; and the §1201 regulatory exemption status.

**Corrections log:** the AI-synthesized domain docs contained hallucinated/over-precise specifics
that have been demoted to verify-live in their corrections banners — the ASN/netblock anchors, the
"EAS 8KB tokens" and "Houseparty takeover" claims, the "Quixel divestiture" error, "deadline" as an
Epic repo, the BPS magic numbers, and all "CONFIRMED" infra tags. Do not let them bias scope or
prioritization.

---

*Authorized security research only. Non-destructive reconnaissance within declared scope.*
