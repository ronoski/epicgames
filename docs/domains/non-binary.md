<!-- AUTHORITATIVE RULES LIVE IN ../SPEC.md AND ../safety-model.md. THIS IS A PENDING-VERIFICATION REFERENCE. -->
> ## ⚠️ Status: AI-synthesized working reference — corrections applied
>
> This document was produced by a multi-agent synthesis and then adversarially reviewed.
> **Treat every concrete Epic identifier, ASN, netblock, host, path, confidence tag, and date below
> as a _candidate to verify against live sources_, never as fact.** The authoritative, de-conflicted
> rules are in [`SPEC.md`](../SPEC.md) and [`safety-model.md`](../safety-model.md); where this file
> disagrees with them, they win.
>
> **Controlling corrections (override the body below):**
> 1. **One unified per-target rate ledger.** Every domain (DNS brute, port scan, HTTP, crawl,
>    handshake/JARM) debits **one** authoritative per-target token bucket; the scheduler serializes
>    active touches per target under a global QPS + low-concurrency cap, and the enforced rate is
>    recorded in PROV. No per-domain parallel budgets against the same asset.
> 2. **Volume-probe verbs are human-gated, never auto-run from the gap queue:** GraphQL
>    field-suggestion (clairvoyance), param-mining via response-diff (arjun/kiterunner), and
>    content-discovery wordlists have hard low ceilings and require passive JS/HAR/archive extraction
>    to be exhausted first.
> 3. **Third-party persona/account/email lookups are BLOCKED outright** (issuing a query against
>    another user’s account is acting on another user’s resource) — not merely redacted. OSINT
>    attribution stays **org-level** (“which Epic dev org owns which asset”); drop per-maintainer
>    tracking.
> 4. **`scope != ownership`.** `prefilter_only` retention of owned-but-unlisted infra never drives an
>    active touch; `*.ol.epicgames.com` and every acquisition apex must earn its own `in_scope`
>    verdict before any active work. Seeds are not membership.
> 5. **Ontology:** D12’s `same_as` / `co_deploy` / `same_team` / `shared_trust_domain` are **proposed
>    additions**, not declared edges; unify `owned_by`→`attributed_to` and `announced_by`→
>    `originated_by`.
>
> **Known-fabricated / unverified specifics to disregard until verified live:** the ASN/netblock
> anchors (“AS4356 / 199.255.40.0/22” and the malformed “148.78.113–122.0/24” set); “EAS tokens up
> to 8 KB from 2026-10-01”; the “Houseparty auth-domain takeover (2020)”; “AWS-dominant PB-scale S3
> lake / Graviton (Confirmed)”; any “Quixel divestiture” (Quixel was folded into **fab.com**, not
> divested); “deadline” as an Epic repo (it is AWS Thinkbox); the `api.epic.foundation` attribution;
> and **every “CONFIRMED” infra claim** (demote to verify-live). The one correct divestiture trap is
> **Bandcamp → Songtradr (Oct 2023)**.
>
> **Missing high-value surface to add when this is built:** `fab.com` (Epic’s unified marketplace);
> the real-time/messaging protocol surface (XMPP party/presence, WebSocket, matchmaking, EOS
> P2P/relay, UDP game services); mobile associated-domains (`apple-app-site-association`,
> `/.well-known/assetlinks.json`); and an explicit acquisition apex seed inventory.

---

# Non-Binary Live-Recon Domains — Knowledge-Base Specification

*Epic Games authorized HackerOne program (hackerone.com/epicgames). Authorized, strictly non-destructive security research only. This section specifies the live-infrastructure / public-OSINT recon domains of the event-sourced, schema-versioned, typed knowledge graph. It is governed in full by the project-wide ontology, provenance, confidence, temporal, and scope-binding invariants; nothing below overrides them.*

---

## 1. Overview and graph placement

### 1.1 What these domains produce

The twelve non-binary domains populate the **middle and right of the ontology**: everything derived from *live infrastructure* and *public/OSINT sources* rather than from client binaries. Concretely they instantiate and connect:

```
Organization ─ BusinessUnit/Acquisition
     │
   Domain ── DNSName ── NetBlock/ASN ── Host ── Service ── WebApp ── Route ── Operation ── Parameter
     │          │                         │        │         │                   │
     └──────────┴── (resolves_to, cname_to, in_netblock, hosted_on, fronted_by, vhost_of, exposes, takes)
                                                              │
                 AuthScheme ── Credential/ClientId ── Token   │   ObjectType ── Flow
                 (authenticates_with, issued_by, grants, references_object, step_of, calls)
                                        │
                              Artifact ── Evidence ── Hypothesis
                              (derived_from, evidenced_by, corroborates/contradicts)
```

Every fact these domains emit carries, without exception: a **W3C-PROV DAG** (`evidence → tool@pinned_version → rule → fact`), a **calibrated log-odds confidence** (contradictions **FORK**, never overwrite), a **content-addressed Evidence handle** (hashed raw request/response/record), **temporal fields** (`first_seen` / `last_seen` / `last_verified` + per-class decay half-life), and a **snapshotted `scope_binding`** recorded at observation time against a content-hashed, timestamped snapshot of the live HackerOne policy.

### 1.2 How the domains interlock

The domains form a directed, mostly-passive-first dependency lattice, not twelve silos:

- **Scope-drift / attribution (D11)** is the *governance gate*. It owns the content-hashed policy snapshot and writes the `scope_binding.verdict` that every other domain must read before retaining or acting on any node/edge. It also produces the ownership (`attributed_to`, proposed) hypotheses that keep *scope* and *ownership* separate.
- **DNS/subdomain (D1)**, **Network/ASN/ports (D2)**, and **TLS-PKI/email (D9)** build the `Domain → DNSName → NetBlock/ASN → Host → Service` skeleton. CT (D9) and passive DNS (D1) are the richest passive name seeds; ASN/BGP + provider feeds (D2) classify Epic-originated vs shared-tenant space.
- **HTTP surface (D3)** promotes suspected `Service`s into confirmed `WebApp(vhost)` nodes and classifies CDN/WAF fronting; it feeds **content/JS/crawl (D6)**, **API contract (D4)**, and **identity/auth (D5)**, which deepen `Route → Operation → Parameter → AuthScheme → Token → ObjectType → Flow`.
- **Cloud/SaaS (D7)** attributes storage/serverless/SaaS tenancy and hands candidate hosts back to D1/D2/D11 for scope-binding.
- **Object/data-model (D8)** types identifiers and emits IDOR/tenancy `Hypothesis` nodes (detection only).
- **OSINT/leaks/supply-chain (D10)** seeds `Organization`/`Artifact`/`Credential(leaked)` and forwards referenced hosts/routes/object-types as *scope-pending prefilter leads*.
- **Correlation / entity-resolution / temporal (D12)** is the glue: it collapses many observed identifiers into one logical `Service` via behavior fingerprints, infers the trust/service-mesh graph, cross-corroborates across independent sources to update log-odds, forks on contradiction, and emits the per-run deltas that schedule the gap queue.

### 1.3 Interlock with the binary-RE domain

The binary-RE domain and these live domains are **mutually confirming, oppositely-seeded**:

- Binary RE **seeds candidates** these domains **confirm live**: host/endpoint base-URLs, legacy `*-public-service-prod*.ol.epicgames.com` service names, EOS `client_id`/`deployment_id`/`sandbox_id`, OAuth grant/scope strings, `.proto` service/method descriptors, and object-type names recovered from launcher/game binaries. These arrive here as low-prior `Hypothesis`/candidate nodes with `scope_binding.verdict == scope_pending`.
- Live recon **corroborates or contradicts** them: a binary-sourced `.proto` method corroborates (and is `derived_from`, cross-domain) a live gRPC/Connect `Operation` discovered by D4; a binary-sourced `client_id` is corroborated as a live `AuthScheme` reference by D5/D10 but **remains a static mapping fact** (default-deny live use); a binary-sourced host is promoted from candidate to `DNSName`/`Host` only after D1 resolution + D11 scope-binding.
- The flow is bidirectional through the `Hypothesis` layer and `corroborates`/`contradicts` edges; D12 is where binary-seeded and live-observed facts meet, are de-duplicated by content hash, and have their log-odds fused. A binary artifact and a live observation of the same fact are **two independent sources** → legitimate corroboration; a binary string that never resolves/serves live **decays** without being deleted.

---

## 2. Scope and safety preconditions for live probing

These are **non-negotiable**, hardened by the adversarial review of the binary-RE domain, and restated here with the machine-checkable invariants specific to *live / active* recon. The autonomous loop cannot invent a verb, cannot widen scope, and cannot escalate a verdict.

### 2.1 `scope != ownership`

An asset being Epic-owned — `*.ol.epicgames.com`, an Epic-originated netblock (`199.255.40.0/22`, `148.78.113–122.0/24`), an Epic GitHub org, an Epic-looking bucket name, a cert whose Subject `O=Epic Games, Inc.` — is at most a **PREFILTER**. Nothing is retained or acted on unless `scope_binding.verdict == in_scope` against a content-hashed, timestamped snapshot of the live policy taken at observation time.

**Invariants (D11-enforced, read by all):**
- `retain(node) ⇒ node.scope_binding.snapshot_id == current_nonstale_snapshot`.
- `act(node) ⇒ node.scope_binding.verdict == in_scope` (default-deny; `prefilter_only` / `out_of_scope` / `adjudication_pending` get **no** active touch).
- Exclusion rules win over inclusion; most-restrictive matching rule wins; ambiguous ⇒ `out_of_scope` pending human adjudication.
- Policy markdown and `structured_scopes` may disagree → capture both, most-restrictive wins.
- A snapshot older than `scope_snapshot_half_life` (short, e.g. `PT24H`), an ETag change, or a `scope_drift_event` **blocks all downstream action** until re-bound; a verdict change **FORKS** the binding history.

### 2.2 Passive-first + per-target rate-budget ledger

Passive third-party/OSINT sources (CT, passive DNS, scan datasets, RDAP/BGP, archives) are exhausted **before** any active touch; they consume a *third-party-source* budget, never an Epic per-target budget.

**Invariants:**
- Every active verb debits an **append-only per-target rate-budget ledger**; keyed by **registrable domain / apex / bucket-name / vhost / authoritative-NS**, **not** by shared IP (one CDN IP fronts many tenants; many vhosts on one IP do not each get a full budget).
- `∀ target: ledger.balance(target) ≥ 0` at all times; a scheduled call that would drive any per-target budget negative is **refused and requeued**. No borrowing across targets.
- Human-rate, non-intrusive pacing; detecting a WAF/CDN (cdncheck/wafw00f/headers) **lowers** remaining budget and widens inter-request spacing. Back off immediately on 403/429/challenge; **no WAF/geo/rate evasion** (that becomes auth/control bypass → BLOCKED).
- Reading the HackerOne *platform* policy targets hackerone.com, not Epic, and draws from a separate platform-rate ledger (ETag/If-None-Match to avoid redundant fetches).

### 2.3 Recon-verb whitelist (closed set)

Permitted: `resolve`, `enumerate`, `passive-collect`, `fingerprint`, `http-GET/HEAD`, `read-openapi`, `graphql-introspect (read-only)`, `parse`, `crawl-within-scope`, `port-scan (rate-limited)`, `bucket-list (read-only)`.

BLOCKED: any write/mutate, brute-force-credentials, exploit, fuzz-at-volume, DoS, auth/WAF bypass, data-exfil, acting on another user's/tenant's resource, registering/claiming any dangling resource, publishing a package.

**Invariant:** `verb ∈ WHITELIST` is checked per request; the loop **cannot synthesize** a verb (no `register`, `claim`, `mutate`, `OPTIONS`, `POST` to probe). Method enumeration reads `Allow`/`405` only. **Proposed read-only verb additions are flagged, not silently used** — see §2.7.

### 2.4 Default-deny live credential use

**Invariant:** any discovered `client_id` / key / `client_secret` / `device_auth` / leaked token is a **STATIC MAPPING FACT**; the owning `Credential/ClientId`/`Token` node is **coverage-capped at `enumerated`** and never advances to a state implying a live request. Any authenticated call requires an **explicit program-authorization token with its own gate record** and uses **only the researcher's OWN account/session**. Secret-scanners run with **verification DISABLED** (verification = a live request). Public-by-design EOS `client_id`/`deployment_id`/`sandbox_id` are recorded at low sensitivity but are still never *exercised* (do not over-label them S3, do not use them).

### 2.5 PII minimization

**Invariant:** any field whose `data_subject != self` (other users' Epic Account IDs/PUIDs, display names, emails, cookie/token values, WHOIS/RDAP registrant data, SOA `RNAME`, CAA `iodef`, DMARC `rua`/`ruf`, commit author emails, persona-lookup results) is **hash-redacted at ingest** and **may never be an edge endpoint toward a non-owned resource**. Role addresses (`security@`, `abuse@`, `dmarc@`) may be kept at S1. Entity resolution clusters **services, not people**; no individual profiling. Breach/paste data is recorded as a **metadata-only mention** (hashed URL + source + timestamp, `contents_ingested=false`) — never ingested or redistributed.

### 2.6 Sensitivity labeling and retention

S0 (public) … S3 (secret/PII). Public DNS/BGP/RDAP/CT/JWKS = S0–S1; banners/certs/fingerprints/structure catalogues = S1; auth/session structure, redacted registrant hashes = S2; any captured secret/token/device-secret, AXFR dumps, internal dev hostnames, third-party-subject data = S3. **Evidence encrypted-at-rest**; retention governed by label. Contradictions FORK with both evidence handles retained.

### 2.7 Flagged proposed schema/verb additions (held for human sign-off, never silently applied)

| Kind | Proposed | Needed by | Current workaround |
|---|---|---|---|
| Edge | `NetBlock --announced_by/originated_by--> ASN` | D2 | ASN carried as NetBlock parent attribute |
| Node | CDN/cloud **Provider** (model as `Organization(role=provider)` or typed attribute) for `fronted_by`/`hosted_on` targets | D2, D3, D7 | Provider recorded as node attribute |
| Edge | `attributed_to` (`Domain/Host/NetBlock/Artifact → BusinessUnit/Acquisition/Organization`) | D2, D7, D10, D11 | Ownership held as node attribute + `Hypothesis` |
| Edge | `trusts` / `allows_origin` (`WebApp → Origin`) | D12 | CORS trust recorded as `corroborates`→Hypothesis |
| Node | `ServiceContract` (gRPC/Connect logical service) | D4 | Mapped to a `Route` grouping of method `Operation`s |
| Node | first-class API **Version** | D4 | Version as `Route`/`Operation` attribute |
| Verbs (read-only, rate-budgeted) | `grpc-reflect`, `http-OPTIONS`, `graphql-field-suggest`, `param-mine`, `route-wordlist` | D4 | Methods via `HEAD`+`Allow`/`405`; suggestion/param/route mining kept hard-capped |

---

## 3. Per-domain specification

> Convention for every subsection: **Objective · Key extractions (extraction → node/edge → evidence → active|passive → confidence) · Tooling (pinned) · Coverage signals · Gap-queue items · Rate/scope/safety boundary.** `(verify live)` marks items that must be confirmed against the live snapshot/service and never assumed.

### 3.1 DNS & subdomain

**Objective.** Discover and continuously re-verify the DNS name surface under Epic's in-scope zones; materialize each name as a `DNSName` with `resolves_to`/`cname_to` edges and record-derived attributes; raise subdomain-takeover candidates as `Hypothesis` nodes (**detected, never claimed**). Passive-first, rate-budgeted, scope-bound at observation time.

| Extraction | → node / edge | Evidence | A/P | Confidence |
|---|---|---|---|---|
| CT SAN harvest (highest yield) | `DNSName` | crt.sh/Censys/CertSpotter/Facebook CT JSON | P | name-exists high; liveness/scope unknown → `last_verified=null`, stays `enumerated` |
| Passive-DNS A/AAAA/CNAME/NS history | `DNSName`; `resolves_to`/`cname_to` (historical) | SecurityTrails/DNSDB/VT/OTX/CIRCL | P | `last_verified=source timestamp` → feeds decay |
| Bulk FDNS/RDNS scan datasets | `DNSName`; `resolves_to`(+PTR) | Columbus/Merklemap/Censys/scans.io (Sonar EOL Feb 2024) | P | historical/decayed; pin snapshot date |
| CAA / TXT-SPF-DKIM-DMARC mining | `DNSName`/`Domain`; `in_netblock`(SPF CIDRs), `references_object`(SaaS/CA) | read-only DNS | P | SaaS/verification TXT = tenancy pivot; mailto = PII→redact |
| NS-delegation / lame-NS; MX; SOA serial | `DNSName`/`Domain`; feeds `Hypothesis` (dangling NS/MX) | read-only DNS | A (rate-limited) | lame≠takeover; serial-delta is cheap staleness trigger |
| AXFR/IXFR probe; NSEC/NSEC3 walk | `DNSName` (bulk) | `dig AXFR`/`ldns-walk`/`nsec3map` | A (one attempt/NS; crack offline) | expect REFUSED on prod; NSEC3 opt-out defeats walk `(verify live)` |
| Dictionary brute + permutation/alteration | `DNSName`; `resolves_to`/`cname_to` | puredns/massdns, gotator/altdns/dnsgen | A (passive-first, last) | wildcard-baseline first; Epic `prodNN` numbering unusually productive |
| Trusted-resolver resolution + wildcard baselining | `DNSName`; `resolves_to`→Host / `cname_to`→DNSName | dnsx `-resp` | A | untrusted resolvers inject false edges → FORK; resolver identity in PROV |
| CNAME chain + CDN/SaaS classification | `cname_to`; `fronted_by` | resolve + fingerprint | A | live CDN CNAME is **never** takeover — suppress FPs |
| Dangling-CNAME / dangling-A / orphaned-SaaS detection | `Hypothesis`; `evidenced_by`, `derived_from` | fingerprint lib + one read-only GET/HEAD | A | **detection only**; Epic has takeover history (Houseparty auth-domain, 2020) |

**Tooling (pinned):** subfinder, amass (pin major; v3/v4 behavior differs), crt.sh/Censys/CertSpotter, passive-DNS APIs (own keys, read-only, source `last_seen` not fetch time), puredns+massdns (pin binaries **and** resolver-list hash **and** wordlist hash), shuffledns, dnsx, altdns/gotator/dnsgen/ripgen (+token wordlist hash), dnsvalidator (snapshot resolver list), dnsrecon/dig/ldns-utils, nsec3map/nsec3walker (+hashcat dict hash), nuclei+templates / dnsReaper / subjack / `can-i-take-over-xyz` (pin commit; **detection templates only**), gau/waybackurls/github-subdomains/CommonCrawl CDX.

**Coverage signals.** `DNSName`: enumerated → resolved → record_complete → takeover_evaluated → monitored. Zone-level on `Domain`: `zone_axfr_checked`, `zone_nsec_walked|n/a`, `zone_wildcard_baselined`. `scope_bound` is orthogonal and required above `enumerated`.

**Gap-queue items.** CT-only names never resolved; stale `resolves_to` past half-life (SOA-serial delta raises priority); zones not AXFR/NSEC-checked; SaaS/NXDOMAIN-terminating CNAMEs lacking a takeover verdict; NetBlocks with no PTR sweep; SPF/verification-TXT not yet expanded to NetBlock/Org; partially-enumerated `prodNN` series.

**Rate/scope/safety boundary.** Passive order mandatory; active brute/permutation only against already-in_scope apexes and last. Resolve only through a vetted trusted-resolver pool (never target NS for bulk, never open resolvers). Wildcard baseline **before** accepting any brute/permutation answer (random-UUID label per zone). Takeover is **detect-only** — registering/claiming any dangling resource is a BLOCKED verb requiring human adjudication + program-authorization token. Bandcamp is **never seeded** (divested Oct 2023).

### 3.2 Network infrastructure — ASN/IP, netblocks, ports & services

**Objective.** Build and maintain `ASN → NetBlock → Host → Service`; classify ownership (Epic-originated vs AWS/GCP/Cloudflare/Akamai/Fastly shared-tenant); map `in_netblock`/`hosted_on`/`fronted_by`; non-intrusively fingerprint services (JARM, JA3S, favicon mmh3, default-page/404 hash, HTTP header-order/HTTP2 fp) for clustering and CDN detection.

| Extraction | → node / edge | Evidence | A/P | Confidence |
|---|---|---|---|---|
| Epic ASN enumeration | `ASN`→`Organization` | RDAP/WHOIS org-handle, PeeringDB | P | RIR authoritative; set drifts with M&A `(verify live)` |
| BGP-originated prefixes | `NetBlock`; `announced_by`(proposed) | RIPEstat/RouteViews/Team Cymru/bgp.he.net | P | strongest Epic-owned signal; snapshot origin+prefix |
| Provider-range classification | `NetBlock`/`Host`; `hosted_on`/`fronted_by` | AWS/GCP/Cloudflare/Fastly/Azure feeds (hash+ETag) | P | proves *provider* owns IP, **not** Epic/scope |
| Deterministic ownership rule node | ownership attr; `derived_from`, `corroborates/contradicts` | RDAP+BGP+range+rDNS fusion | P | conflicts FORK (e.g. RDAP=Epic vs IP∈AWS) |
| PTR attribution sweep | `DNSName`/`Host`; `resolves_to`(inverse), `in_netblock` | RDNS datasets / live PTR | P / A | cloud rDNS = provider, never Epic from rDNS alone |
| Passive ports/banners/certs | `Service`; `exposes` | Shodan(+InternetDB)/Censys/Sonar | P | stale → temporal/decay; corroborate before acting |
| Active rate-limited port-scan (in-scope only) | `Service`; `exposes` | naabu/nmap top-ports, `-T2` low rate | A (ledger-debited) | edge reflects CDN not origin; never scan shared IP as Epic |
| JARM / JA3S / favicon / 404-body / header-order fp | fp attrs; `corroborates` | tlsx/httpx | A (or P via Censys) | CDN JARM/JA3S globally shared → cluster only, never ownership |
| CDN/WAF fronting classification | `WebApp`/`Host`; `fronted_by` | CNAME + headers (cf-ray/x-akamai/x-served-by) + range | P/A | provider target has no node type → proposed Provider node |
| Origin-IP candidate (hypothesis-only) | `Host`(candidate)/`Hypothesis`; `corroborates/contradicts` | CT/passive-DNS/Shodan pivots | P | **no direct origin probing to bypass WAF** (BLOCKED) |

**Confirmed anchors `(verify live)`:** AS4356 (`199.255.40.0/22`), AS393326/AS397645/AS395701/AS207845 announcing `148.78.113–122.0/24`.

**Tooling (pinned):** RDAP(IANA bootstrap)+whois, Team Cymru, RIPEstat/RIS+RouteViews, bgp.he.net, PeeringDB, asnmap+mapcidr, cdncheck (pin version **and** embedded range-DB date), provider feeds (content-addressed), dnsx+massdns, Shodan+InternetDB, Censys, Rapid7 Open Data/Sonar `(verify availability live)`, httpx (record exact flags), tlsx+jarm (JARM algo version matters), naabu, nmap (block intrusive/exploit/brute NSE; record args), mmh3+sha256 normalizer (pin normalization ruleset — hash depends on it).

**Coverage signals.** ASN enumerated; NetBlock enumerated→ownership-classified (with confidence); Host enumerated→fingerprinted; Service enumerated→fingerprinted→state-verified; Fronting resolved; origin-status {behind-cdn|direct-origin|unknown}. Decay: cloud Host↔IP fast; Epic NetBlock/ASN slow; fingerprints decay on observed stack change.

**Gap-queue items.** Unclassified IPs from `*.ol`; provider-feed ETag/hash change → reclassify; JARM/header-cluster new `api.epicgames.dev` edges; service banners past half-life → re-fingerprint passively first; candidate origins (corroborate via CT/passive only); new BGP prefix from an Epic ASN; newly-disclosed acquisition ASN/domain.

**Rate/scope/safety boundary.** Passive order: RDAP/Cymru → BGP → provider feeds/cdncheck → passive DNS/CT → Shodan/Censys/Sonar → *then* active. **CDN/cloud shared-tenant rule:** never actively scan a Cloudflare/Akamai/Fastly/AWS/GCP IP as Epic's; only the specific in-scope hostname via its Host header, never the raw shared IP. `masscan`-style volume BLOCKED. Even Epic-originated ranges require `in_scope` before active touch. Bandcamp/divested infra excluded; each acquisition scope-bound independently.

### 3.3 HTTP surface & fingerprinting (GET/HEAD-only)

**Objective.** Confirm live HTTP services, promote suspected `Service` → confirmed `WebApp(vhost)`, characterize status/headers/cookies/tech/CDN-WAF/TLS-SAN/vhost-differential/default-vs-app, and read discovery files — all read-only, one hit per `(endpoint, probe-type)`.

| Extraction | → node / edge | Evidence | A/P | Confidence |
|---|---|---|---|---|
| HTTP(S) liveness probe | `WebApp`; `vhost_of`, `exposes`(Service) | httpx row (status/tls/hash) | A (P pre-seed) | alive only from live hashed response; read `Age` (CDN cached 200 ≠ live origin) |
| Status + `Allow` (opportunistic, no non-GET sent) | `Operation`; child of `Route` | GET response + 405 `Allow` | A | GET status confirmed; POST-from-Allow is Hypothesis |
| Title + server/banner tokens; tech/framework fp | `WebApp`; `corroborates`(favicon/tech) | headers/body/favicon mmh3 | A (P via Shodan) | single-token = Hypothesis; CONFIRMED when ≥2 signals agree |
| Redirect-chain (do-not-auto-follow) | `Route`; `fronted_by`/`references_object`; login→`authenticates_with` | 30x `Location` chain | A | each hop its own scope decision; SSO redirect ≠ universal auth |
| Security headers / CSP connect-src | `WebApp`/`AuthScheme`; `references_object`(CSP host→candidate Domain) | GET (P via urlscan) | A | missing-header = weakness Hypothesis, never exploited; CSP hosts scope-pending |
| CORS reflection (GET+Origin; **no OPTIONS**) | `AuthScheme`; `authenticates_with`/`corroborates` | GET with probe Origin | A | arbitrary-origin+creds = misconfig Hypothesis only |
| Set-Cookie flags (names+attrs; values S3-redacted) | `AuthScheme`; `authenticates_with` | pre-auth GET | A | only anonymous cookies observed (default-deny) |
| CDN/WAF/front classification | `WebApp`; `fronted_by` | CNAME + cf-ray/x-akamai/x-amz-cf-id | P/A | lowers rate budget; body fp may describe edge not app |
| VHOST/SNI differential | `WebApp` per vhost; `vhost_of` | GET with varied in-scope Host/SNI | A | never send out-of-scope Host to Epic IP nor Epic Host to 3rd-party |
| TLS cert/SAN harvest | `DNSName`/`Domain`; `references_object`/`corroborates` | crt.sh/Censys first, tlsx confirm | P→A | CT SAN existed; host-behind-cert is Hypothesis until handshake |
| default-vs-app discrimination | `WebApp` kind | title/body-hash vs default-signature set | A | default_landing capped at `enumerated` (not param-mined) |
| well-known/robots/sitemap/security.txt; read-openapi; graphql-introspect | `Route`/`AuthScheme`/`Operation`/`Parameter`/`ObjectType`; `exposes`/`issued_by`/`takes` | GET (P via Wayback/dev-portal docs) | A | EOS JWKS at `api.epicgames.dev/epic/oauth/v2/.well-known/jwks.json` CONFIRMED; whether Epic exposes GraphQL `(verify live)` |
| Content-addressed response Evidence (cross-cutting) | `Evidence`; `evidenced_by`/`derived_from` | sha256(req‖resp)+tool@ver+rule+ts+exit_ip | P | anchor for log-odds; 200→403 re-probe FORKS |

**Tooling (pinned):** httpx (pin exact; disable retries so "one hit" holds), tlsx, cdncheck (pin version+range-dataset date), wafw00f (lightest mode; count every request), Wappalyzer/wappalyzergo (over urlscan copies, pin signature DB), gowitness/aquatone (pin Chromium build; disable form submit), urlscan.io (record scan UUID+ts), Shodan/Censys, crt.sh, nuclei **RESTRICTED** (pin engine+template commit; only non-interacting tech/misconfig templates), katana/hakrawler **RESTRICTED** (GET-only, strict scope/depth/rate, no form submit), OpenAPI parser + read-only GraphQL introspection client, curl (pin flags; proxy-aware; never disable TLS verify).

**Coverage signals.** Per `(vhost,Host)` WebApp vector: liveness→status→headers→cookie-flags→cors-reflection→tech→cdn/waf→tls-san→vhost-differential→default-vs-app→screenshot→schema-pulled. `enumerated`=liveness+status (default_landing/WAF-edge terminal here); `fingerprinted`=real app with headers+tech+cdn+cookies+default-vs-app; schema-pull feeds downstream `param-mined`. `last_verified` per-signal (status/headers decay fast, certs slower, tech slowest).

**Gap-queue items.** `api.epicgames.dev` well-known + jwks (top priority: auth core); CSP host lists → scope-adjudication; `*.ol` `prodNN` vhost differential (background, respect Akamai/AWS front budget); divestiture/ownership-trap hosts → human-adjudication sub-queue; `enumerated`-but-not-default WebApps → fingerprint; CT-SAN hosts with no confirmed liveness → single liveness GET. Priority `= value * staleness * confidence_deficit / cost`, WAF-fronted targets carry higher cost (sort lower).

**Rate/scope/safety boundary.** Active verbs limited to the web subset; **no OPTIONS/POST/PUT/DELETE/PATCH** (CORS preflight excluded). Exactly one hit per `(endpoint,probe-type)`; re-verification scheduled by decay, not retry. Budget per registrable-domain **and** per edge. WAF detection lowers budget + widens spacing. Unauthenticated only; discovered secrets stay `enumerated`. Trust zones kept distinct: `api.epicgames.dev` (modern EOS) vs `api.epicgames.com` vs `*-public-service-prodNN.ol.epicgames.com` (legacy). Persona/account lookups on `*.ol` return third-party PII → hash-redact, never an edge endpoint toward a non-owned resource.

### 3.4 API contract (REST / OpenAPI / GraphQL / gRPC-web)

**Objective.** Turn in-scope Routes into typed `Operation`/`Parameter`/`AuthScheme`/`ObjectType` nodes. Prefer reading published specs + read-only introspection/reflection (declared-contract recon) over probing; catalogue write/mutation Operations **without invoking them**.

| Extraction | → node / edge | Evidence | A/P | Confidence |
|---|---|---|---|---|
| OpenAPI/Swagger doc + docs-UI route | `Artifact(openapi)`/`Route`/`Operation`/`Parameter`/`ObjectType`; `exposes`/`takes`/`references_object` | GET `/openapi.json`,`/v3/api-docs`,`/swagger-ui`… | A (P from JS/Wayback) | declared-spec = highest existence confidence; live presence still corroborated (spec drift); whether Epic serves a machine-readable spec `(verify live)` |
| AuthScheme from `securitySchemes` | `AuthScheme`(+`ClientId`); `authenticates_with`/`issued_by` | spec parse | P | embedded client_id stays static `enumerated` |
| GraphQL endpoint + read-only introspection | `Route`/`ObjectType`/`Operation`/`Parameter`; `exposes`/`takes`/`references_object` | one benign probe; `{__schema…}` if enabled | A (P from JS) | store.epicgames.com Apollo, GET+persisted-query, **introspection BLOCKED** (confirmed); mutations mapped never executed |
| GraphQL engine/defense fp; field-suggestion recovery | fp/`Hypothesis`; partial `Operation`/`Parameter` | graphw00f; clairvoyance (bounded) | A | suggestion = `source=inferred`, low log-odds; hard request ceiling → halt (not fuzz) |
| Persisted GraphQL ops (APQ) | `Operation`/`Artifact(manifest)`; `exposes`/`derived_from` | client JS / own-session capture | P | catalogue only OBSERVED op-names/hashes; set changes → decay |
| gRPC-web/Connect surface + reflection | `Service/Route`/`Operation`/`ObjectType`; `exposes`/`takes`/`references_object` | content-types `application/grpc-web+proto`/`connect+json`; `grpcurl list/describe` | A | whether Epic exposes it `(verify live)`; reflection often off → fall back to binary-RE `.proto` (cross-domain `derived_from`); proposed `grpc-reflect`/`ServiceContract` |
| REST routes (passive) + method set | `Route`/`Operation`; `exposes` | gau/urlscan/JS; `Allow`/`405` | P/A | community catalogues (FortniteEndpointsDocumentation) are Hypotheses until live-corroborated |
| Hidden/undeclared params (bounded) | `Parameter`; `takes` | JS/HAR first; arjun/response-diff (capped) | P-first / A | active candidates `source=inferred`; hard ceiling; **not** fuzz-at-volume |
| OAuth/OIDC metadata + JWKS | `AuthScheme`/`ClientId`/`Token`; `authenticates_with`/`issued_by` | well-known GET | A/P | decode-only; discovered client_ids static `enumerated` |
| Error taxonomy (REST/GraphQL) + response ObjectType | `ObjectType`; `references_object`/`evidenced_by` | observed own-account responses | P | Epic `errors.com.epicgames.*` / RFC7807; error bodies may leak internals → S2+ |

**Tooling (pinned):** httpx, katana+linkfinder-style JS parse, gau/waybackurls, nuclei (pin engine+template commit; exposure-detection only), swagger-parser/openapi-core/prance/Redocly (resolve `$ref`, run isolated on untrusted specs), kiterunner (pin binary+routes wordlist; ceiling; last-resort), arjun (capped), graphw00f, clairvoyance (ceiling; `source=inferred`), InQL/graphql-cop/graphqurl (no mutation modules), grpcurl+buf (reflection only), mitmproxy (own session; PII filter), PyJWT/jwcrypto (decode only)+jq/gron, TruffleHog/gitleaks (`--no-verification`, S3).

**Coverage signals.** enumerated (path+method known) → fingerprinted (style/engine/version; introspection/reflection posture) → param-mined (full param set + AuthScheme) → flow-mapped (Operation in a Flow with own-account req/resp Evidence) → artifact-correlated (corroborated by an independent Artifact: OpenAPI doc / JS bundle / persisted query / binary-RE `.proto`).

**Gap-queue items.** store GraphQL introspection blocked → bounded field-suggestion + persisted-query harvest; EOS Ecom/Stats/Connect HTML docs → parse to Operations + probe for `openapi.json`; `account-public-service` params from JS then bounded param-mine; `*.ol` gRPC-web content-type fp pass; Sketchfab `/v3` docs → Operations (gate active on scope); EOS OAuth flow-map **only** with own authorized token + gate record.

**Rate/scope/safety boundary.** Default-deny scope check before any probe; passive-first; declared-contract reads (one introspection = whole schema) outrank iterative probing. Bounded discovery runs only under hard request ceilings; a ceiling halts and enqueues for human review. Writes/mutations catalogued, never invoked; method enum reads `Allow`/`405`. Each acquisition API host its own current in_scope verdict (ArtStation datacenter-IP JSON blocking is a *vantage signal*, not a control to bypass).

### 3.5 Identity & authorization (live)

**Objective.** Reconstruct Epic's live OAuth2/OIDC surface — OIDC/RFC8414 discovery, token endpoints, grants/scopes/response_types, JWKS+`kid`/`alg`, the two EOS tiers (EAS account-level vs Connect product-user), legacy `account-public-service`, the web CSRF/cookie session, MFA/device-trust, and console account-**linking** — from metadata + own-account flow observation only.

| Extraction | → node / edge | Evidence | A/P | Confidence |
|---|---|---|---|---|
| EAS OIDC discovery + RFC8414 existence | `AuthScheme`(+children); `evidenced_by` | GET `/epic/oauth/v1/.well-known/openid-configuration` (discovery under **v1** though token/jwks are v2) | P→A | path confirmed via 3rd-party; live arrays content-hashed, not assumed; RFC8414 doc existence `(verify live)` |
| EAS endpoint set (authorize/token/tokenInfo/userInfo) | `Operation`/`Route`; `exposes`/`authenticates_with`/`takes` | docs+discovery; tokenInfo/userInfo need bearer → default-deny | P (gated A) | authorize host is `www.epicgames.com/id/authorize`, not api.epicgames.dev |
| EAS JWKS + `kid`/`alg`; access-token JWT structure | `Credential`(per `kid`)/`Token`/`ObjectType`(sub); `issued_by`/`grants`/`references_object` | GET jwks; local decode of OWN token | A / P | likely RS256 `(verify live)`; EAS tokens up to 8KB from 2026-10-01 `(verify)` |
| EAS grants / scopes / authorization_code+consent flow | `Parameter`/`Flow`; `takes`/`step_of` | discovery+docs; own-account observe | P / own-A | PKCE (S256) support `(verify live)` |
| EAS `client_id`/application model | `Credential/ClientId`; `authenticates_with`/`references_object` | OSINT/client config | P | static mapping fact; co-leaked secret S3, never exercised |
| EOS Connect tier (PUID tokens) + `external_auth_type` enum | `AuthScheme`(distinct issuer/jwks)/`Parameter`/`ObjectType`; `exposes`/`issued_by`/`takes`/`references_object` | docs; Connect jwks GET | P (gated A) | PUID per-product → tenancy boundary; psn_id_token/nintendo_id_token/steam_*/xbl… (xbl vs XSTS `(verify)`) |
| Legacy `account-public-service` OAuth (token/verify/exchange/sessions-kill) + grant set | `AuthScheme`(legacy)/`Operation`/`Token`; `exposes`/`authenticates_with`/`issued_by` | community research; gated own-A | P-first | in-scope status of legacy `*.ol` hosts `(verify live snapshot)`; `password` grant status/`otp` schema `(verify)` |
| Legacy hardcoded game/launcher client creds | `Credential/ClientId`; `authenticates_with` | OSINT (binaries/community) | P | static `enumerated`; **live use BLOCKED**; secrets S3 |
| Web CSRF+exchange flow; session/cookie model; MFA `otp`; device_auth + device_code | `Flow`/`Operation`/`Credential`/`Token`/`AuthScheme`; `step_of`/`issued_by`/`derived_from` | own-session Set-Cookie/redirects; docs | own-A gated / P | cookie NAMES+attrs recorded, values S3 own-session only; no login brute, no OTP brute/bypass |
| Console/SSO account-LINKING (PSN/Xbox/Nintendo/Steam) | `Flow`/`AuthScheme`(external IdP)/`ObjectType`(linked id); `step_of`/`issued_by`/`references_object` | docs; own-account | P / own-A | external identity with `data_subject≠self` hash-redacted, never an edge toward non-owned |
| Token introspection (tokenInfo/userInfo/verify) — own-token only; JWKS rotation temporal series | `Operation`/`Evidence`/`Credential`/`Hypothesis`; `evidenced_by`/`corroborates`/`contradicts` | gated own-token; periodic jwks GET | gated A / A | introspecting non-own token BLOCKED; alg anomaly (`none`/symmetric) recorded as Hypothesis, never exploited |

**Tooling (pinned):** httpx, curl (pin curl+CA bundle), subfinder/amass (passive), gau/waybackurls, PyJWT/python-jose (`python -I`, local, no egress — decode/verify-locally only, never mint/forge/alter), openssl (local), trufflehog (`--no-verification`), gh/git (read-only; untrusted data quarantine), jq, mitmproxy/devtools (own session, gate record, PII-redact).

**Coverage signals.** enumerated (endpoint/grant/scope listed; client_ids catalogued) → fingerprinted (live discovery/jwks content-hashed; issuer/endpoints/scopes/grants/kid/alg) → param-mined (grant/scope/external_auth_type/response_type enums mapped to Operations+Flows) → flow-mapped (`step_of` chains: authz_code+PKCE, device_code, web csrf→login→exchange, MFA otp, external_auth linking) → artifact-correlated (own-token claims cross-checked vs tokenInfo/verify + offline JWKS validation; cookie attrs vs redirects; key-rotation diffs).

**Gap-queue items.** Read live EAS openid-config (v1) + content-hash arrays; confirm/404 RFC8414 doc on both tiers; diff EAS vs Connect JWKS + start rotation series; verify PKCE; verify legacy grant set / `password` removal / `otp` schema / live prod shards; capture live cookie NAMES; resolve xbl-vs-XSTS and psn variant; find device_authorization path + activation URL; scope-adjudicate each legacy `*.ol` auth host.

**Rate/scope/safety boundary.** Scope-first; passive-first; per-target ledger over `api.epicgames.dev`/`*.ol`/`www.epicgames.com/id`. **Two EOS issuers are DISTINCT AuthScheme nodes** (EAS `/epic/oauth/*` vs Connect `/auth/v1/oauth/*`) — cross-tier token/claim conflation is a flagged modeling error. **No** submitting arbitrary grant/scope/external_auth combos to discover acceptance (fuzz-at-volume). Own-account flow observation only; no mutate/link/unlink/revoke beyond self. **Ownership traps:** Bandcamp (divested); and `fhir.epic.com`/`api.epic.foundation`/`userweb.epic.com` are **Epic Systems (healthcare), not Epic Games** — never ingest. A local egress block is **not** a scope signal.

### 3.6 Content discovery, crawling & JS/source analysis

**Objective.** For each in-scope WebApp, enumerate reachable Routes/Operations/Parameters and the Artifacts (JS bundles, sourcemaps) that reference them; harvest endpoints/hosts/params/object-types from JS; discover/reconstruct sourcemaps; secret-scan inline config (verification disabled); and passively mine Wayback/CommonCrawl/urlscan with temporal. Confirmed-live and historical/JS-inferred facts are **distinct forkable nodes** (the latter Hypothesis until a scoped live GET corroborates).

| Extraction | → node / edge | Evidence | A/P | Confidence |
|---|---|---|---|---|
| robots.txt (Disallow/Allow/Sitemap) | `Route`; `derived_from` | GET /robots.txt | A | listed≠exists≠denied; Disallow is low-confidence candidate; state-changing GET (`/logout`,cart) excluded from auto-crawl |
| sitemap.xml (+index, lastmod) | `Route`; `derived_from` | gzip-aware recursive GET | A (depth-capped) | higher than robots; still Hypothesis until GET-confirmed |
| scope-bound crawl (links/resources/vhosts); forms; headless XHR/fetch/GraphQL | `Route`/`Operation`; `derived_from`/`vhost_of`/`takes` | katana/hakrawler; headless network capture | A | live-observed higher log-odds; forms catalogued never submitted; only own session, no authenticated mutating calls |
| JS bundle inventory + endpoint/host/param extraction | `Artifact`/`Route`/candidate DNSName; `derived_from` | subjs/getJS; jsluice/linkfinder (AST+regex) | A(from Epic)/P(urlscan/Wayback) | JS-inferred = Hypothesis; extracted hosts PREFILTER until `in_scope` |
| sourcemap discovery + reconstruction | `Artifact`/`ObjectType`/`Route`/`Operation`; `derived_from` | `//# sourceMappingURL`; unwebpack-sourcemap | A (P if archived) | prod maps usually stripped → 404 normal, don't retry at volume; **read-only of served files, not binary decompilation** |
| inline client_ids / JWKS / base-URL config / GraphQL ops | `Credential/ClientId`/`WebApp`/`Operation`/`ObjectType`; `references_object`/`derived_from` | offline parse; secret-scan verification OFF | P | public EOS ids low-sensitivity static `enumerated`; private secrets S3 (existence high, validity unknown by design) |
| Wayback CDX / CommonCrawl / urlscan historical URLs+params+JS | `Route`/`Parameter`/`Artifact`/candidate subdomain; `derived_from`/`corroborates/contradicts` | archive APIs | P | historical → Hypothesis; confirm-live before confidence rises; capture-time ≠ creation-time |
| rate-gated content discovery (wordlist, GET-only, WAF-aware) | `Route`; `derived_from` | feroxbuster/ffuf, soft-404 calibrated | A (last) | 200/redirect distinct from soft-404 = confirmed; 403/429/challenge ≠ exists; no WAF-bypass |

**Tooling (pinned):** katana (host-allowlist from snapshot), hakrawler/gospider, gau/waymore/waybackurls (record source per URL), Wayback CDX (record query+response hash), CommonCrawl (record CC-MAIN-ID as version), urlscan.io (scan UUID+date), subjs/getJS, linkfinder/xnLinkFinder (record regex ruleset hash as the `rule`), jsluice, unwebpack-sourcemap/sourcemapper, trufflehog (`--no-verification`; record flag so an un-disabled run is detectable), gitleaks (rules hash), ffuf/feroxbuster (pin version **and** wordlist commit, e.g. SecLists@sha), httpx (separate soft-404 vs real), nuclei (engine+template commit; GET-only exposure templates), robots/sitemap parser (store raw bytes+ts).

**Coverage signals.** enumerated (robots+sitemap parsed, JS inventoried, archive sets pulled) → fingerprinted (tech/bundler, CDN+WAF per host, soft-404+challenge calibrated) → param-mined (params from forms/JS/archives) → flow-mapped (XHR+reconstructed-source multi-step → Flow domain) → artifact-correlated (bundles↔sourcemaps↔archives reconciled across live/JS/archive provenance). Any `enumerated`-but-not-default WebApp re-opens on a new bundle hash (deploy) or new capture.

**Gap-queue items.** Re-harvest store JS after any deploy (bundle hash changed); confirm-live JS/Wayback-only Routes (promote or FORK-as-absent); refresh Wayback/CC/urlscan per in-scope wildcard (passive, no Epic budget) before any active crawl; `.map` probing for new bundles; content discovery only after passive+crawl+JS exhausted; scope-adjudication queue for `*.ol`/static-asset hosts from JS config. Priority formula pushes passive/archive early, content-discovery/live-confirm last.

**Rate/scope/safety boundary.** Active web subset only; `static-assets-prod`/`cdn1.epicgames.com`/`*.ol` are PREFILTERS (scope-gate; CDN edge IPs not Epic-owned). Each sub-request (page+sub-resources+links) debited; one gowitness render can consume a large slice. GET can still mutate (`/logout`, cart, email-confirm links) — excluding state-changing GETs is a safety requirement. Bandcamp and other divested names in archives/JS rejected at the gate. Secret-scanning verification OFF; public EOS ids not over-labeled S3 and never used.

### 3.7 Cloud & SaaS footprint

**Objective.** Attribute Epic's cloud and SaaS surface: S3/GCS/Azure object storage (read-only existence/ACL/listing), serverless/API-gateway URLs, cloud-service fingerprinting via CNAME/IP/TLS, and third-party SaaS tenant attribution branded to Epic/acquisitions. Cloud ownership/Epic-looking names are **prefilters**; most third-party SaaS is **out of scope** and recorded with **zero probing of the vendor**.

| Extraction | → node / edge | Evidence | A/P | Confidence |
|---|---|---|---|---|
| Offline bucket-name candidate synthesis | `Hypothesis`; `derived_from` | lexicon×affix matrix (no network) | P | near-zero prior; name≠ownership |
| S3/GCS/Azure existence+region, anon ACL/listing (read-only) | `WebApp`/`Service`/`ObjectType`/`Artifact`; `vhost_of`/`hosted_on`/`references_object` | HEAD/GET + XML `<Error><Code>`; `--no-sign-request`; `list-type=2` | A (scope-gated, bucket-list) | **parse XML not status** (200 body can say NoSuchBucket); 301=wrong region (read `x-amz-bucket-region`); listable≠exploit, no bulk exfil |
| Lambda URL / API-Gateway / Cloud Run / Azure Functions discovery | `WebApp`/`Service`/`Route`/`Operation`; `hosted_on`/`fronted_by`/`exposes`/`takes` | CT/passive-DNS/in-scope JS; scope-gated GET; read-openapi/introspect | P+A | prefer in-scope custom-domain front over raw `*.on.aws`/`execute-api` |
| CNAME→cloud/CDN + IP→ASN/NetBlock classification | `DNSName`/`NetBlock`/`ASN`/`Host`; `cname_to`/`fronted_by`/`hosted_on`/`in_netblock` | provider suffix match; RDAP/BGP | P | IP = provider not tenant; shared ranges need CNAME/cert corroboration |
| TLS-SAN / favicon / header SaaS fp | `WebApp`/`DNSName`; `fronted_by`/`hosted_on`/`corroborates` | CT + favicon mmh3 + headers | P (A-lite) | CT SAN richest `*.epicgames.dev` seed |
| SaaS vanity-CNAME tenant + passive-OSINT tenant attribution | `ObjectType`(tenant)/external `Organization`/BusinessUnit; `fronted_by`/`hosted_on`/`references_object`/`corroborates/contradicts` | DNS/CNAME resolve + OSINT (no vendor HTTP) | P | in-scope label → out-of-scope vendor target; Zendesk stale (Epic left ~Feb 2024); Okta/Workday internal → attribution-only |
| 3rd-party SDK/key extraction from in-scope assets | `Credential/ClientId`/`ObjectType`; `references_object`/`authenticates_with` | in-scope JS parse | P-lean (A crawl) | Braze/Segment/Sentry DSN/GA/Firebase/Stripe-pk/EOS ids = static `enumerated`, default-deny |
| CloudFront origin correlation; BusinessUnit attribution | `WebApp`/`ObjectType`/`Service`; `fronted_by`/`hosted_on`/`derived_from`/`corroborates` | CNAME/redirect/S3-XML; lexical+cert+ASN | P (A-lite) | CDN 200 (OAC) ≠ public bucket; `amplitude-game.com`/`audicagame.com` = Harmonix titles not SaaS |

**Tooling (pinned):** subfinder+amass (passive), dnsx, httpx (GET/HEAD), tlsx+crt.sh, s3scanner (dump-disabled/list-only), cloud_enum (scope-gate each target BEFORE run — tool has no scope awareness), aws CLI (`--no-sign-request`; list/get-* only), gsutil/gcloud (no creds; list/stat), asnmap+RDAP+BGP, nuclei (pin engine+template commit; exclude fuzz/dos/intrusive; detection only), trufflehog/gitleaks (verification OFF), BBOT (passive/safe modules only; scope+rate enforced at harness).

**Coverage signals.** Bucket: candidate(Hypothesis)→existence-verified(enumerated)→ACL/listing-checked(fingerprinted)→key-namespace(param-mined)→minimal-evidence-sampled(artifact-correlated). Serverless/APIGW: discovered→dns-resolved→http-fingerprinted(enumerated)→route/op-mapped(flow-mapped). SaaS tenant (out-of-scope): attributed(enumerated) **hard-capped**. Keys: `enumerated` capped. Priority weights value by data-sensitivity×BU-criticality (EOS/Store/core > marketing SaaS).

**Gap-queue items.** CT-SAN sweep of `*.epicgames.dev` (EOS); classify `*-public-service-prod*.ol` CNAME chains (CloudFront vs Cloudflare + origin hints); existence-probe top-N synthesized storage candidates after scope-bind; map in-scope execute-api/lambda-url refs from Store/Launcher/EOS SPAs; confirm current Epic SaaS tenants + decay stale Zendesk edges (attribution-only); re-verify previously public/listable buckets + CloudFront origins on half-life (FORK on contradiction).

**Rate/scope/safety boundary.** Candidate synthesis 100% offline; first touch is the scope-gated read-only existence probe. Read-only/list-only on all storage (Put/Delete/PutBucketPolicy/Copy BLOCKED). Serverless active only when that host or its in-scope custom-domain front passes scope-binding. **Zero active probing of out-of-scope SaaS** (DNS resolve is the ceiling); internal SaaS (Okta/Workday) especially off-limits. Minimal non-PII sampling only. CloudFront/OAC caveat: do not report a public-bucket finding from a CDN 200. Dangling-CNAME/takeover = Hypothesis only; claiming BLOCKED. `amplitude-game.com`/`audicagame.com` classify by evidence not lexical coincidence. Confirmed: **AWS-dominant** (EC2/Graviton, PB-scale S3 lake, CloudFront) + Cloudflare + Akamai `(verify per property live)`.

### 3.8 Object & data-model (live IDOR/tenancy)

**Objective.** Catalogue the identifier formats Epic's live APIs expose; type each identifier's **structure** (uuid / 32-hex / sequential / opaque / composite) and **scope** (per-user / global / per-tenant); map tenancy boundaries (EGS namespace/sandbox, EOS org/product/sandbox/deployment, acquisition tenants); record documented state transitions. From (per-user-or-per-tenant object + guessable/typed structure + weak/absent authz tie) **emit IDOR/tenancy `Hypothesis` nodes** — recorded only, **never** validated by requesting another party's object. All structure is inferred from passive corpora, docs, read-only introspection, and the researcher's OWN responses — never by brute-forcing IDs.

| Extraction | → node / edge | Evidence | A/P | Confidence |
|---|---|---|---|---|
| Epic Account ID / EAS `sub` / EOS PUID | `ObjectType`(+Parameter); `references_object`/`authenticates_with`/`corroborates` | community docs + own id-token; own-A GET | P (own-A) | accountId=32-hex (no dashes, ≠UUID); PUID per-product = tenancy key, charset/case `(verify)`; displayName/email lookups return 3rd-party PII — no edge toward non-owned |
| EGS namespace/sandbox; catalogItemId; offerId; artifactId | `ObjectType`(+Parameter); `references_object`/`grants`/`step_of` | docs, purchase URLs, store GraphQL introspection | P | namespace = primary storefront tenancy partition; **mixed** human-readable + 32-hex — don't assume all hex |
| entitlementId (per-user commerce object) | `ObjectType`(+Parameter)/`Hypothesis`; `references_object`/`grants`/`corroborates/contradicts` | own entitlements only | P (own-A) | format (uuid vs 32-hex) **unconfirmed** → IDOR Hypothesis confidence low until own-account fingerprint `(verify)` |
| Dev-portal Org/Product/Sandbox/Deployment chain; OAuth `client_id`; JWT token | `ObjectType`/`Organization`/`Credential`/`Token`; `references_object`/`authenticates_with`/`issued_by`/`grants` | docs, own token claims | P | tenancy isolation boundaries; IDs believed 32-hex `(verify)`; client_id static `enumerated`; launcher 32-hex, some EOS base62 `(verify)` |
| Fortnite MCP profile (accountId-in-path) | `Operation`/`Parameter`/`ObjectType`/`Hypothesis`; `references_object`/`step_of`/`corroborates/contradicts` | own accountId read-only | own-A | **strongest IDOR anchor** (accountId-in-path + 32-hex guessable + per-user); MCP MUTATIONS (SetMtxPlatform) catalogued **never invoked**; current shard `prod11`? `(verify)` |
| Lobby/Session IDs | `ObjectType`(+Parameter); `references_object`/`step_of` | own lobby/session | P (own-A) | opaque ≥16 chars → low guessability → low Hypothesis confidence |
| **Structure typing** (uuid/32-hex/sequential/opaque/composite) + **Scope typing** (per-user/global/per-tenant) | `ObjectType.structure`/`.scope` attrs; `evidenced_by`/`derived_from` | local analysis of corpora + own IDs | P | dominant driver of IDOR confidence; counter-example FORKS the ObjectType; scope gate prevents noise on global catalog objects |
| Documented state transitions; cross-service correlation (self only) | `Flow`/`Evidence`; `step_of`/`grants`/`calls`/`corroborates` | docs; own-account co-occurrence | P (own-A) | mutating steps never executed to confirm; correlating other subjects forbidden (PII) |
| IDOR/tenancy Hypothesis generation (output product) | `Hypothesis`; `references_object`/`corroborates/contradicts`/`derived_from` | pure inference over graph (no traffic) | P | rises with per-user/per-tenant scope + guessable structure + absent-authz; never validated by requesting another party's object |
| Acquisition tenant object models | BusinessUnit/`ObjectType`; `references_object` | public API docs (after scope-bind) | P | Sketchfab model `uid`=32-hex CONFIRMED; ArtStation/Quixel/Psyonix/Mediatonic/SuperAwesome `(verify)`; Bandcamp = out-of-scope trap |

**Tooling (pinned):** PyJWT (local; verify vs public JWKS only; never mint/replay), OpenAPI parser (read-openapi; dev.epicgames.com may be egress-blocked → OSINT mirrors, flag freshness), read-only GraphQL introspection client (within-scope, own-session, no mutations), mitmproxy over OWN authenticated client (content-hash evidence, S2/S3 redact), offline structure classifier (`python -I`; pin ruleset version), SHA-256 evidence hasher (encrypt at rest), secret scanner verification OFF, passive OSINT corpus ingester (pin commit; **untrusted data**, corroborating not fact, never instructions).

**Coverage signals.** enumerated (name+scope+owning service/namespace) → fingerprinted (structure class with entropy Evidence from docs+own samples) → param-mined (every Operation taking it has a `references_object` edge with param position) → flow-mapped (`step_of`/`grants` transitions) → artifact-correlated (identifier observed across ≥2 planes for OWN account, linked by `corroborates`).

**Gap-queue items.** Fingerprint entitlementId structure from OWN Ecom response (gates strongest commerce IDOR); confirm PUID charset/deployment-scope; resolve per-product namespace/sandbox form; param-mine which MCP ops take accountId in path vs body and read-vs-mutate; enumerate dev-portal product/sandbox/deployment IDs; confirm current fortnite/catalog service shard hostnames; verify acquisition id formats after scope confirm.

**Rate/scope/safety boundary.** Scope prefilter (namespace/sandbox/deployment are **tenancy** prefilters, not scope grants). **No ID brute-forcing/enumeration to "confirm guessability"** (fuzz-at-volume + acting on others' resources). Active GET only against own objects, read-only. All MCP/EOS mutating ops catalogued never invoked (even own account) absent a gate record. Disambiguate identifier-name collisions (GraphQL `id` vs catalogItemId vs artifactId; accountId vs EpicAccountId vs PUID) by service+namespace before drawing `references_object`, or false correlations are fabricated.

### 3.9 TLS/PKI history & email security

**Objective.** Turn (a) full CT history + live TLS surface and (b) per-domain email-auth posture into graph facts. CT is a temporal pivot + SAN-expansion seed (`DNSName` `derived_from` Certificate `Artifact`s, `not_before` as `first_seen` lower bound); cert/issuer/SPKI/JARM/mTLS/SNI characterize `Service`/`WebApp`/`AuthScheme`; email posture (SPF/DKIM/DMARC/BIMI/MTA-STS/TLS-RPT/MX/CAA/DNSSEC) populates `Domain` attrs and spawns spoof/dangling/takeover `Hypothesis` nodes.

| Extraction | → node / edge | Evidence | A/P | Confidence |
|---|---|---|---|---|
| CT historical SAN harvest + scope-gated DNSName seeding | `DNSName`/`Artifact(Cert)`/`Evidence`; `derived_from`/`evidenced_by` | crt.sh/CertSpotter/Censys | P | name existed (high), live/scope unknown; wildcard SAN ≠ enumerated labels; divestiture names (artstation/sketchfab/quixel/bandcamp) → adjudication |
| Cert attributes + SPKI-pin + issuing-CA classification + key-reuse correlation | `Artifact(Cert)`/`Host`; `evidenced_by`/`corroborates`/`fronted_by` | cert bytes | P | origin-SPKI reuse = strong shared-infra; CDN-terminated SPKI = SOFT (discount); CA→fronting heuristic |
| Pre-cert predictive seeding; `not_before` pivot; wildcard hidden-surface flag | `DNSName`/`Artifact`/`Hypothesis` | precert SANs; validity | P | predictive low log-odds, capped `enumerated`; wildcard → gap-queue active enumeration |
| Live served-cert read; JARM; mTLS CertificateRequest; SNI/vhost map | `Service`/`WebApp`/`AuthScheme(mTLS)`; `vhost_of`/`authenticates_with`/`evidenced_by` | read-only handshake | A (budgeted) | confirms live state CT can't; observe CertificateRequest only, **never present a client cert**, never bypass; empty-CA-list may be optional |
| CAA; EOS JWKS token-PKI | `Domain`/`AuthScheme`/`Credential`/`Hypothesis`; `authenticates_with`/`issued_by`/`evidenced_by` | read-only DNS/GET jwks | P/A | JWKS public keys S0 static mapping, default-deny use; exact jwks path + kids/algs `(verify live)` |
| SPF record + include-chain + permerror/permissive + dangling-include (SubdoMailing) | `Domain`/`DNSName`/`Hypothesis`; `derived_from`/`cname_to`/`evidenced_by` | read-only DNS | P | >10 lookups=permerror→spoofable; dangling include = high-value Hypothesis, **never register** |
| DKIM selectors; DMARC policy + rua/ruf external-auth; BIMI/VMC | `Domain`/`AuthScheme(DKIM)`/`Artifact(VMC)`/`Hypothesis`; `authenticates_with`/`evidenced_by` | read-only DNS (+in-scope GET of VMC/logo) | P (A-lite) | weak/absent policy → spoof Hypothesis; report addresses PII-redact; `epicgames.com`/`.dev` are distinct org domains (independent DMARC); BIMI deployment `(verify)` |
| MTA-STS + TLS-RPT; MX + provider classification; MX/email-service takeover; DNSSEC posture | `Domain`/`WebApp(mta-sts)`/`DNSName(MX)`/`Service(SMTP)`/`Hypothesis`; `resolves_to`/`exposes`/`cname_to`/`evidenced_by` | read-only DNS + in-scope mta-sts GET | P (A for policy GET) | dangling MX/mta-sts/BIMI = highest-value email takeover (passive-confirm, no claim); unsigned zone lowers confidence of all TXT posture |

**Tooling (pinned):** crt.sh + CertSpotter + Censys CT + direct CT reader (snapshot+hash raw JSON, record query ts), openssl s_client / pinned TLS client (pin version — handshake behavior differs), jarm (pin commit; 10-ClientHello set is part of the definition), zgrab2/tls-scan, dnsx/zdns/dig (pin + record resolver set; prefer public recursive over Epic authoritative NS), checkdmarc / self-hosted SPF-DMARC-MTA-STS parser (offline parse; attribute every lookup to ledger), BIMI/VMC parser + openssl x509, SHA-256 content-addresser.

**Coverage signals.** enumerated (CT SANs + public email-posture records retrieved) → fingerprinted (live cert + SPKI + JARM + mTLS flag + SNI/vhost) → flow-mapped-email (SPF chain within 10-lookup, DMARC org/sp inheritance, MTA-STS fetched, DKIM selectors) → artifact-correlated (SPKI-reuse clusters; VMC↔BIMI↔DMARC; precert→live-cert lifecycle; CT-revealed mail-infra ↔ MX/SPF/MTA-STS). `param-mined` = **N/A** (recorded so the gap queue doesn't demand it).

**Gap-queue items.** CT delta per in-scope wildcard each cycle; resolve+classify every SPF-include/MX/mta-sts/BIMI host for dangling candidates; live cert+JARM+mTLS for new in-scope hosts; complete DMARC/DKIM/MTA-STS posture for `enumerated`-not-`flow-mapped` domains; re-verify EOS JWKS (`kid` rotation) + VMC/BIMI validity + re-snapshot scope (ArtStation/Sketchfab post-KitBash) before action; staleness re-verify of certs near `not_after` and records past half-life.

**Rate/scope/safety boundary.** Passive tier (CT + public-resolver DNS) uses no Epic budget but is logged; active tier (handshake, JARM's 10 ClientHellos as a block, mTLS probe, SNI/vhost, mta-sts GET, EOS jwks/OIDC GET) debits the per-target ledger; ≤1 handshake per `(host,SNI)` per cycle; DKIM-selector enumeration bounded to a curated list (no volume guessing). **BLOCKED specifically:** presenting a client cert / mTLS bypass; using JWKS keys/client_ids to mint/forge/replay/verify live tokens; **sending any test or spoofed email** to prove an SPF/DKIM/DMARC gap (posture + Hypothesis only); **registering/claiming** any dangling SPF-include/MX/mta-sts/BIMI target. Report/WHOIS/S-MIME addresses PII-redacted.

### 3.10 OSINT, code leaks & software supply chain

**Objective.** Populate `Artifact(repo/package/image)`, `Organization/BusinessUnit`, and `Credential(leaked)` nodes for Epic's code/supply-chain surface from **public sources only**, plus candidate hostnames/routes/object-types forwarded as **scope-pending prefilter leads**. Passive-first; secret-scanning verification disabled; PII hash-redacted; ownership attribution answers only "which Epic dev org owns which asset" — never individual OSINT.

| Extraction | → node / edge | Evidence | A/P | Confidence |
|---|---|---|---|---|
| GitHub/GitLab org discovery + ownership verification | `Organization`/BusinessUnit; `derived_from`/`corroborates/contradicts` | forge API; verified-domains; cross-links | P | EpicGames + EpicGamesExt (created ~2024-02-29, consolidating → EpicGames) confirmed; 3rd-party forks/mirrors are NOT Epic |
| Public repo enumeration + fingerprinting (langs/CI/manifests/deps) | `Artifact(repo)`; `derived_from`/`references_object` | API list; shallow clone of PUBLIC repos | P | **UnrealEngine = EULA-gated licensed source, NOT public → `licensed_gated=true`, excluded**; public: Signup, BlenderTools, deadline, MetaHuman-DNA-Calibration, PixelStreamingInfrastructure, Raddebugger |
| Public-repo secret/leak scan (full history, verification OFF) | `Credential/ClientId`/`Token`(leaked, S2/S3); `derived_from`/`evidenced_by`/`issued_by` | trufflehog+gitleaks offline | P | **class CAPPED at `enumerated`**, never verified live; FP (test fixtures) → `contradicts`, not deleted |
| EOS client-id harvesting | `Credential/ClientId`; `issued_by`/`references_object`/`derived_from` | parse public client code | P | client-side-by-design = enumerated static fact; paired server `client_secret` = S3 default-deny; don't over-label ids as secrets |
| Code-search / search-engine / Shodan / Censys dorking | `Artifact`/candidate Domain/Route/Host/Service (scope_pending); `references_object`/`evidenced_by` | 3rd-party indexes (no packets to Epic) | P | SCOPE≠OWNERSHIP: referenced host = prefilter lead; record Shodan/Censys snapshot date |
| Package-registry presence+integrity; dependency-confusion/typosquat (defensive) | `Artifact(package)`/`Hypothesis`; `derived_from`/`references_object`/`corroborates/contradicts` | npm/NuGet/PyPI/Fab metadata | P | @epic* npm / Epic NuGet / PyPI existence `(verify, don't fabricate)`; **publishing a claim/PoC package BLOCKED**; typosquats may be malicious 3rd-party |
| Config infra refs; container image discovery; historical/deleted content recovery | candidate Domain/Host/Service/ObjectType / `Artifact(image)` / `Evidence`; `references_object`/`derived_from` | parse; crane/skopeo manifest-only; Wayback/CC/history | P | `*.ol` refs = prefilter; images inspected not run; historical `first_seen` ≠ current presence |
| Dev/asset attribution across acquisitions; commit/publisher provenance (PII-min); EOS Web API OpenAPI extraction | BusinessUnit/`Organization` attr / candidate Operation/Route (scope_pending); `derived_from`/`corroborates`/`references_object` | verified-domain/maintainer signals; docs | P | professional ORG attribution only (author emails hash-redacted); **Bandcamp divested Oct 2023 = never attribute to Epic**; whether dev-portal publishes machine-readable OpenAPI `(verify)` |

**Tooling (pinned):** gh CLI+REST/GraphQL (pin version+`X-GitHub-Api-Version`; own token S3, never committed), glab/GitLab API, trufflehog (pin; `--no-verification`; detector-set version in PROV), gitleaks (pin+rules hash; validation OFF), git (full/`--mirror` for refs), Shodan/Censys (snapshot ts; scope_pending), npm/NuGet/PyPI APIs (capture packument hash), grep.app/Sourcegraph, Wayback/CommonCrawl (capture ts = `first_seen`), crane/skopeo (inspect only, never pull-and-run), custom dork rule-packs (versioned; each query→evidence; all hits scope_pending).

**Coverage signals.** Organization: enumerated (all forge orgs+registry scopes ownership-verified) → correlated (cross-linked to domains/BUs). Artifact(repo): enumerated (listed+`licensed_gated` flag) → fingerprinted (langs/CI/manifests/deps) → artifact-correlated (↔packages/images/referenced domains). Credential(leaked): enumerated+classified — **capped**. Secret-scan coverage = fraction of in-scope PUBLIC repos + full history scanned at the pinned two-detector ruleset version.

**Gap-queue items.** New/changed public repos (poll ETag/events) → re-enumerate + rescan history delta; EpicGamesExt→EpicGames consolidation drift → re-attribute; unscanned git history → rescan; new package versions → fingerprint+integrity+maintainer-change; dork/Shodan deltas → forward to infra for scope-binding; acquisition-org attribution not confidence-cleared; stale leaked-cred facts past half-life → re-confirm still-present-in-public-source (not re-verify live); unconfirmed registry presence → verify existence live.

**Rate/scope/safety boundary.** Passive-first; 3rd-party lookups use a 3rd-party-source budget, send **zero packets to Epic**. Secret scanning OFFLINE with verification DISABLED (verification = live request = out of whitelist). Discovered creds NEVER used to authenticate; classified, hashed, S2/S3, encrypted, reported through the program. Any live GET to an Epic page referenced in code is deferred to D3/D4/D11 (scope-bound, own target budget). **PUBLIC CODE ONLY** (UnrealEngine EULA-gated excluded). Dependency-confusion = defensive mapping Hypothesis; publishing BLOCKED. Breach/paste = metadata mention only, `contents_ingested=false`.

### 3.11 Scope-drift detection & ownership attribution (governance gate)

**Objective.** Make the live policy at hackerone.com/epicgames the single, content-addressed, timestamped source of truth. (1) Snapshot policy+`structured_scopes` with SHA-256 + trusted timestamp; (2) diff consecutive snapshots → typed `scope_drift_event`s; (3) bind each parsed rule to concrete nodes as a snapshotted `scope_binding` carrying a verdict; (4) independently attribute every asset (RDAP/WHOIS + ASN/BGP + CT + brand) → calibrated log-odds ownership `Hypothesis`; (5) reconcile the two axes to **enforce `scope != ownership`**; (6) force re-binding when stale or drift fires. **This domain's output is the retention gate for the whole KB.**

| Extraction | → node / edge | Evidence | A/P | Confidence |
|---|---|---|---|---|
| `policy_scope_snapshot` | `Evidence`→`Organization(Epic)`; `evidenced_by` | authenticated OWN H1 session read; SHA-256 + RFC3161 ts | A (platform budget, not Epic) | CLOSED scope confirmed; whether API exposes `structured_scopes` vs rendered md `(verify)` — more restrictive wins on disagreement |
| `scope_rule_parse` | `scope_binding` metadata on Domain/WebApp/Host/Service/NetBlock (ObjectType/Artifact for non-URL assets) | snapshot parse | P | non-URL types (App Store/Play/repo/hardware) → ObjectType/Artifact; task wildcard list is a hint, membership is whatever the snapshot says |
| `scope_binding_object` | verdict on node; `derived_from`/`evidenced_by` | rule eval (default-deny; exclusion wins) | P | `in_scope`/`out_of_scope`/`prefilter_only`(owned-unlisted, capped `enumerated`)/`adjudication_pending`; short decay half-life |
| `scope_drift_event` | `Artifact(DriftEvent)`/`Hypothesis`; `derived_from`/`contradicts/corroborates` | diff(N, N-1) of normalized rules | P | `asset_removed` FORKS all derived bindings; high gap-queue priority |
| WHOIS/RDAP + ASN/BGP + CT/brand/SSO ownership signals → fused hypothesis | `Domain`/`NetBlock`/`Host`/`Hypothesis`→Org/BU/Acq; `corroborates/contradicts`, proposed `attributed_to` | RDAP(transfer dates)/Team Cymru/bgp.tools (pin RIB date)/crt.sh (cert `O=`)/favicon/footer/SSO redirect | P (brand GET = A, scope-gated) | GDPR-redacted RDAP → low confidence (no de-anon); cloud ASN ≠ not-Epic; cert `O=` spoofable → fuse; confirmed acquisitions: Psyonix/Quixel 2019, SuperAwesome 2020, ArtStation/Mediatonic/Harmonix/Sketchfab 2021 `(current ownership verify live)` |
| `scope_ownership_reconciliation` (the `scope≠ownership` join) | governance verdict on `scope_binding`; `contradicts` | 2×2 matrix | P | (owned & out_of_scope)→`prefilter_only` retain/don't-act; (listed & not-Epic)→`adjudication_pending`; divestiture traps land here |
| `stale_snapshot_rebind`; `divestiture_trap_watchlist` | binding temporal update / Acquisition+Hypothesis+Artifact(watchlist); `derived_from`/`contradicts` | age/ETag/drift trigger; curated transfer dates | P→triggers A | **Bandcamp→Songtradr CONFIRMED (announced 2023-09-28) out_of_scope**; ArtStation+Sketchfab→Kitbash (~Aug 2026) single lower-reliability source → **VERIFY before trusting**; transfer lag means DNS may still point at Epic after a sale |

**Tooling (pinned):** httpx + authenticated OWN H1 session/API (token S3), SHA-256 + RFC-3161 TSA (record TSA identity/policy OID), structural+semantic differ (diff the normalized model not raw HTML), RDAP client (whoisit/IANA bootstrap)+WHOIS fallback (respect GDPR), ASN/BGP (Team Cymru/bgp.tools/asnmap/pyasn — **pin the RIB/BGP table date**), CT (crt.sh/certspotter/Google CT — record log+STH/query time), favicon/brand fingerprinter (pin mmh3+ruleset; fetch is active+scope-gated), dnsx/passive DNS (dangling-CNAME detect — record only, takeover BLOCKED), log-odds fuser + optional USPTO TSDR trademark (version weight set).

**Coverage signals.** `scope_binding.state`: unbound → bound_in_scope | bound_out_of_scope | prefilter_only | adjudication_pending | stale. `ownership.state`: unattributed → attributed_low → attributed_high | contradicted(forked) | divested. `snapshot.coverage`: missing | fresh | stale. Governance analog: enumerated (snapshot captured+parsed+bound), fingerprinted (attributed_high), artifact-correlated (reconciled, no open contradiction).

**Gap-queue items.** snapshot missing/stale → re-fetch (highest priority, **blocks all retention until re-bound**); drift unreconciled → fork bindings + re-bind; in-scope-but-unattributed → run attribution; ownership contradiction (Epic-looking infra but divested/3rd-party) → human adjudication; wildcard rule unexpanded → hand (gated) to D1 then re-bind each; scope anomaly (listed-but-not-Epic) → adjudication; watchlist transfer-date elapsed → re-verify.

**Rate/scope/safety boundary.** Policy read targets the **platform**, no Epic budget, own authenticated session only, ETag-gated, bounded cadence; RDAP/CT/BGP passive (per-source ledger). Active brand/favicon GET only when the node is already `in_scope`; nothing active on stale/unverified nodes (the rebind gate blocks it). This domain uses only `http-GET/HEAD`, `passive-collect`, `parse`, `resolve`, `fingerprint`; a dangling CNAME to a divested service is recorded as a Hypothesis for the human, **never acted on** (takeover = mutate/exploit BLOCKED). The snapshot **is** the authoritative legal boundary — no asset is in scope because it is Epic-owned, only because the snapshot lists it.

### 3.12 Correlation, entity-resolution & temporal/diff engine (the glue)

**Objective.** Collapse many observed identifiers into one logical `Service` via a tiered fingerprint ontology; infer trust/service-mesh edges; cross-corroborate across independent sources to update calibrated log-odds; fork on contradiction; and emit per-run deltas that schedule the gap queue. **Merges are decided by HARD (near-unique) features; SOFT (shared-infra) features only generate candidates and are collision-discounted** — Epic fronts across four CDNs, so the identity of a logical service is not the identity of its edge stack.

| Feature / operation | → node / edge | Evidence | A/P | Confidence class |
|---|---|---|---|---|
| JARM / JA4S(JA3S) TLS fp | `Service`; `fronted_by`/`corroborates` | tlsx/jarm; Censys/Shodan | A (P from datasets) | **SOFT** — CDN-collides globally (LR≈1 for same-service); blocking/grouping only |
| Favicon mmh3; default-404 fuzzy-hash (TLSH/SimHash); HTTP header-order/HTTP2-SETTINGS fp | `WebApp`/`Service`; `corroborates` | httpx; archived | A (P preferred) | MEDIUM (app-specific) / near-zero (framework/CDN default) — maintain default-hash **denylist** |
| **EOS JWKS key-set fp** (`kid`+RFC7638 thumbprint+SPKI) | `AuthScheme`→`Credential`; `authenticates_with`/`issued_by`/`corroborates`→shared_trust_domain | GET well-known jwks | A (low-cost) | **HARDEST non-cert anchor** — same-operator/shared-trust-domain; long decay, snapshot kid set each run |
| **Cert SPKI hash** (origin) / SAN-set co-listing | `Host`/`DNSName`; `corroborates`→same_as/co_deploy | CT | P | **HARD for origin** (private-key reuse); SOFT for CDN-terminated leaf; broad wildcard SAN ≠ identity |
| **Embedded 3rd-party IDs** (Sentry DSN/GTM/Segment/EOS client_id); JS build-hash; GraphQL/OpenAPI schema fp | `WebApp`/`ObjectType`/`Operation`; `references_object`/`exposes`/`corroborates`→same_as/same_team | JS parse; read-only introspection/read-openapi | A (P archived) | **HARD** when unique/private — but a discovered client_id stays static `enumerated`, **never exercised** |
| PTR/ASN/NetBlock grouping; CNAME/fronting-provider fp | `NetBlock/ASN`/`DNSName`; `in_netblock`/`cname_to`/`fronted_by`/`corroborates` | RIR/passive DNS; resolve | P | **SOFT** — cloud IP ≠ ownership (LR≈1); Epic-owned ASN stronger `(verify)` |
| CORS ACAO trust edge; redirect-chain (OAuth/SSO); CSP connect-src/Link allowlists | `WebApp`/`Flow`; `corroborates`→shared_trust_domain, proposed `trusts`/`allows_origin`, `calls`/`step_of` | GET+Origin; follow 3xx; headers | A (P archived) | HARD directional — but **reflected/echoed Origin is NOT a trust fact** (detect+discard); out-of-scope trusted origin = boundary fact, don't probe |
| Cross-source corroboration scorer (log-odds) | `Hypothesis`; `corroborates` | event store compute | P | `logodds_post = prior + Σ log(LRᵢ)` over **independent, content-hash-distinct** evidence; calibrate per class (isotonic/Platt), track Brier/reliability; **de-dup correlated evidence before summing** (the CT cert and the cert you fetched are one fact) |
| Contradiction fork; subdomain-takeover detector; `same_as` clustering (Fellegi-Sunter); `owned_by`/`in_scope` attribution | `Hypothesis`; `contradicts`/`corroborates`/`cname_to`/`evidenced_by` | compute + one scoped GET for takeover error page | P (A-lite) | fork preserves both branches, stale branch decays toward prior; **takeover DETECT-ONLY** (Epic auth-domain history); cluster = revisable Hypothesis not destructive merge; **attribution ≠ scope**; divested same_as is time-bounded (no resurrection) |
| Per-run temporal diff / delta emitter | deltas across all node types; `derived_from`; re-triggers `corroborates/contradicts` | fold over append-only event log | P (no network) | delta types {new/dead host, port, route/op/param, cert, spki_rotation, cname_change, new jwks_kid, favicon/404_change, new_vhost, takeover_candidate}; per-class half-lives (cert short < DNS < ASN < JWKS) |

**Confirmed Epic fronting `(verify per run)`:** `media-cdn.epicgames.com`→CloudFront; `cdn1`/`store-content.ak`/`store-site-backend-static.ak`/`epicgames-download1.akamaized.net`→Akamai; `cloudflare.epicgamescdn.com`→Cloudflare; `fastly-download.epicgames.com`→Fastly. JARM/JA4S/favicon **will** collide across these — cluster only on origin/hard features. Legacy `*-public-service-prod.ol.epicgames.com` naming is a **blocking feature only**.

**Tooling (pinned):** jarm/tlsx `--jarm` (pin commit; don't compare across versions), JA4+ suite / ja3s (**prefer JA4S** for stability; **verify FoxIO licensing** before automated/commercial use), httpx (favicon/header fp), TLSH+ssdeep+SimHash (pin all three; store merge threshold with the rule), crt.sh/certstream/Censys (content-hash each record for de-dup), Censys/Shodan (dataset age = staleness), passive DNS + dnsx, subfinder/amass (passive only), nuclei (template commit; **detection/takeover-signature templates only**, never exploit/fuzz/DoS), RFC7638 thumbprint + JOSE lib (parse only, never mint with discovered client_id), gau/waybackurls + JS static parser (secret scan verification DISABLED), record-linkage engine (Splink/dedupe/custom F-S; persist feature weights with schema version), calibration (sklearn isotonic/Platt + Brier/reliability), content-addressed append-only event store (git-like + Merkle; sha256; schema-versioned; encrypted).

**Coverage signals.** fingerprinted (≥1 captured feature, per class flagged independently) → clustered/resolved (assigned to a logical-Service cluster via `same_as` above `T_merge`) → corroborated (≥2 **independent** content-hash-distinct sources agree) → trust-mapped (inbound/outbound CORS/redirect/CSP/JWKS-issuer edges enumerated) → diff-tracked (present in ≥2 run snapshots). `confidence_deficit` = distance of log-odds from calibration target; `staleness = (now − last_verified)/half-life` (cert < DNS < ASN < JWKS).

**Gap-queue items.** Fingerprinted-but-unclustered → capture a HARD anchor; SOFT-only clusters → capture origin SPKI / JWKS / embedded-ID to confirm-or-split; forked contradictions awaiting a tie-breaker (high-value → human); clusters stale past cert half-life → fresh CT SPKI; new CT/passive-DNS hosts not fingerprinted; dangling-CNAME takeover candidates (value×staleness high); in-scope wildcard hosts whose CORS/redirect/CNAME points to an unverified 3rd party; acquisition hosts with unresolved `owned_by`; `new_jwks_kid`/`spki_rotation` → re-anchor affected trust clusters.

**Rate/scope/safety boundary.** Clustering, corroboration, forking, and diff are **pure read-only computation over the event log — zero rate budget**; only feature *capture* that touches Epic debits the ledger (JARM 10-probe burst, favicon GET, 404-probe, CORS GET+Origin, redirect-follow, JWKS/OpenAPI/introspection read, one takeover error-page GET). Blocking uses only already-stored features (no budget). SOFT features capped and collision-discounted, **never a merge decider**. A trust edge pointing out of scope is a **boundary fact** — the target is not probed. Attribution may link an acquisition host to the Organization (`owned_by` hypothesis) but linkage ≠ scope; each node keeps its own snapshotted verdict and is re-adjudicated on policy change. Takeover = detect-only; discovered client_ids correlated but never exercised; divestiture (Bandcamp) owned_by edges are time-bounded and never resurrected into the live graph.

---

## 4. Passive-first pipeline order across domains

The global scheduler runs the cheapest, zero-touch, highest-yield sources first, binds scope, and only then spends Epic rate budget. Within each stage the per-domain passive orders (§3) apply.

**Stage 0 — Governance bootstrap (blocks everything).** D11 fetches + content-hashes + timestamps the live policy snapshot (own H1 session, platform budget). No node from any domain may be retained or acted on until it has a `scope_binding` against a non-stale snapshot. A missing/stale snapshot or a `scope_drift_event` re-enters this stage at top priority and blocks downstream action.

**Stage 1 — Passive OSINT & registry (zero Epic touch).**
1. **CT logs** (D9/D1/D7/D12) — highest-yield name + cert + SPKI + SAN seeds. *Why first:* richest, append-only, no target contact, seeds nearly every other domain.
2. **Passive DNS** (D1/D2/D12) — historical `resolves_to`/`cname_to`/NS/PTR with real timestamps; dead-record and dangling-CNAME detection.
3. **RDAP/WHOIS + BGP/ASN/RIR + provider ranges** (D2/D11) — ownership + Epic-originated-vs-cloud classification; pin the RIB date.
4. **Bulk internet-scan datasets** (D2/D3/D12) — Shodan/Censys/(legacy Sonar) banners, ports, JARM, favicon, headers, certs *already collected*.
5. **Archives + code/OSINT** (D6/D10) — Wayback/CommonCrawl/urlscan URLs+params+JS copies; GitHub/registry/dork leads (forwarded as scope-pending prefilters); published dev-portal / EOS / Sketchfab docs. *Why here:* analyze archived JS **before** fetching anything from Epic.

**Stage 2 — Scope-binding gate (D11).** Every candidate from Stages 1 passes the prefilter → verdict against the snapshot. Default-deny; exclusion wins; divestiture suspects → human adjudication. Only `in_scope` survivors proceed to any active touch; `prefilter_only` (owned-unlisted) is retained capped at `enumerated`, never acted on.

**Stage 3 — Read-only record intelligence on in-scope names (low-volume DNS/well-known).** NS/MX/SOA/CAA/TXT-SPF-DKIM-DMARC/MTA-STS/TLS-RPT/DNSSEC (D1/D9); `.well-known` OIDC discovery + JWKS + published OpenAPI (D3/D4/D5). Single-query, cheap, debits the per-target ledger lightly.

**Stage 4 — Active, scope-bound, rate-budgeted confirmation (passive-first within each target).**
1. Trusted-resolver resolution + wildcard baselining (D1) → real `DNSName` nodes.
2. HTTP liveness/fingerprint GET/HEAD (D3), TLS handshake + JARM + mTLS observation + SNI/vhost (D9/D2/D12).
3. Read-only declared-contract reads: `read-openapi`, `graphql-introspect` (D4/D5).
4. Cloud existence/ACL/listing (read-only) on in-scope buckets/serverless (D7).
5. Scope-bound crawl + JS/sourcemap fetch (D6).
6. **Last and most expensive:** rate-limited port-scan (D2), dictionary brute/permutation (D1), bounded param-mine/route-wordlist/field-suggestion (D4), content discovery (D6), live PTR sweep (D1) — each only after passive sources leave a confidence deficit the gap queue prioritizes.

**Stage 5 — Takeover triage + correlation/diff.** Passive fingerprint match first, **single read-only GET/HEAD only to confirm a claimable-state page** (D1/D7/D12); never claim. D12 then clusters, cross-corroborates (de-dup by content hash), forks contradictions, emits deltas, and recomputes the gap queue.

*Rationale:* passive sources are free of Epic budget and legal risk and have the highest breadth; scope-binding is interposed so active budget is never spent on out-of-scope or ambiguous assets; the most intrusive, lowest-prior verbs are deferred until cheaper evidence has narrowed the target set.

---

## 5. Live/active-recon coverage model, gap-queue integration, and temporal diffing

### 5.1 Coverage ladder (per entity, per signal)

Coverage is tracked **per entity and per signal class**, orthogonally to scope-binding (`scope_bound` is required before any coverage state above `enumerated` is *actionable*). The canonical ladder:

| Level | Meaning (live-recon realization) |
|---|---|
| `enumerated` | Entity exists from ≥1 source; no live confirmation yet. CT-only DNSNames, default-landing WebApps, pure-WAF edges, static credential facts, leaked-secret facts, out-of-scope SaaS tenants, and prefilter_only nodes are **terminal here** (capped). |
| `fingerprinted` | Live-confirmed and characterized: resolved + record_complete (D1); ownership-classified + JARM/JA3S/favicon/header fp (D2); headers+tech+cdn/waf+cookies+default-vs-app on a real app (D3); API style/engine/version + introspection posture (D4); live discovery/jwks content-hashed (D5); cert+SPKI+JARM+mTLS+SNI (D9). |
| `param-mined` | Full parameter/identifier set captured — from a declared spec/introspection/structure-classifier (preferred) or bounded discovery (D3/D4/D8). Marked **N/A** for cert/email nodes (D9). |
| `flow-mapped` | Operation placed in a `Flow` via `step_of`/`grants`/`calls` with an own-account request/response Evidence pair (D4/D5/D6/D8); email auth-chain fully resolved (D9). |
| `artifact-correlated` | Fact corroborated by ≥1 **independent, content-hash-distinct** Artifact: OpenAPI doc / JS bundle / persisted query / binary-RE `.proto` / cross-plane own-account identifier co-occurrence / SPKI-reuse cluster (D4/D8/D9/D12). This is where live recon and binary RE close the loop. |

Each entity carries a **coverage vector** (one state per signal class), not a single scalar, and a `last_verified` **per signal** (status/headers decay fast, certs slower, tech/ASN/JWKS slowest).

### 5.2 Gap queue

The gap queue is the scheduler of the autonomous loop. Each open coverage gap (or stale fact) becomes an item with:

```
priority = value * staleness * confidence_deficit / cost
```

- **value** — data-sensitivity × BusinessUnit-criticality (EOS auth / Store / core infra ≫ marketing SaaS; auth-bypass-class and takeover-class findings top-weighted given Epic's history and bounty table).
- **staleness** — `(now − last_verified) / per-class decay half-life`; exceeding the half-life re-opens the gap (which is itself a queue item).
- **confidence_deficit** — log-odds distance from the decision threshold (a SOFT-only cluster, an unconfirmed structure class, an un-adjudicated scope verdict).
- **cost** — projected rate-budget debits + request count; **WAF-fronted targets carry a cost penalty** (sort lower); passive/archive tasks dominate early (near-zero cost).

Cross-domain hand-offs are queue items: D1→D2 PTR sweeps over new NetBlocks; D10/D7→D11 scope-adjudication of referenced hosts; D11→D1 wildcard expansion then re-bind; D4↔binary-RE `.proto` corroboration; D12→human for high-value forks and takeover candidates. Items blocked by a stale snapshot or exhausted per-target budget are requeued, never silently dropped.

### 5.3 Temporal diffing (event-sourced)

Every observation is an **append-only, content-addressed, timestamped event**; current state is a deterministic fold over the event log. Each run computes `diff(snapshot R-1, R)` and emits **typed deltas** that update temporal fields and feed the gap queue:

`new_host | dead_host | new_service/port | new_route/operation/parameter | new_cert | spki_rotation | new_cname / cname_change | new_jwks_kid | favicon/404/body_change | new_vhost | takeover_candidate | scope_drift(asset_added/removed/changed, wildcard_broadened/narrowed, policy_text_changed) | ownership_change/divestiture`.

Each delta carries `first_seen`/`last_seen`/`last_verified` + content hash and **re-runs corroboration** (raising log-odds on independent agreement) or **FORKS** (on contradiction) — nothing is overwritten. Per-class decay half-lives drive re-verification: ephemeral cloud Host↔IP and CDN-config/headers short; DNS medium; certs ≈ rotation cadence; Epic NetBlock/ASN, EOS JWKS (rotates rarely) long. A `scope_drift(asset_removed)` forks every binding derived from the removed rule and reverts affected nodes to `adjudication_pending`/`out_of_scope`. A `new_jwks_kid` is a rotation delta (not a new issuer); an `spki_rotation` re-anchors affected shared-infra clusters; a `dead_host` ages out but is retained as history. The diff engine also **re-opens** a `same_as` cluster whenever a HARD feature changes, so a re-architected/migrated service is not kept as a dead merge.

---

## 6. Pinned tooling matrix and reproducibility contract

### 6.1 Reproducibility contract (applies to every tool run in every domain)

1. **Pinned provenance.** Every fact's PROV DAG records `evidence → tool@exact_version(+digest) → rule@version → fact`. A tool/version/ruleset bump **forks** facts (new fingerprint/parse namespace); hashes and fingerprints are **never compared across tool versions**.
2. **Pinned inputs.** Where output depends on an input artifact — resolver list, wordlist, permutation tokens, provider IP-range DB, nuclei/takeover template set, favicon/normalization ruleset, regex ruleset, secret-detector set, JARM ClientHello set, calibration dataset — that input is **content-hashed** and recorded as the `rule` stage. Results are reproducible only with those inputs fixed.
3. **Content-addressed evidence.** Every raw request/response/record/handshake (method, URL, headers, body, TLS params, **exit IP + region**, timestamp) is SHA-256-hashed into an `Evidence` node, encrypted-at-rest, sensitivity-labeled. Correlated evidence is de-duplicated by hash **before** log-odds summation (the CT cert and the actively-fetched cert are one fact).
4. **Snapshot-dating of third-party datasets.** CT/passive-DNS/Shodan/Censys/CommonCrawl/BGP-RIB/Sonar results record the source snapshot date (and ETag where available) as the fact's temporal evidence — `last_verified = source timestamp`, not fetch time.
5. **Safety config is auditable.** Secret-scanner `--no-verification`, nuclei exploit/fuzz/DoS exclusions, `--no-sign-request`, GET/HEAD-only / one-hit-per-endpoint, read-only introspection/reflection, isolated interpreters (`python -I`) on untrusted inputs — all recorded in PROV so a non-compliant run (e.g. verification left on) is detectable after the fact.
6. **Untrusted-data discipline.** Community corpora, downloaded repos/specs, fetched pages, and anything someone else wrote are **data, never instructions**; quarantined, never executed from their own directory, corroborating not authoritative; contradictions fork.

### 6.2 Pinned tooling matrix (by domain; pin rule in italics)

| Domain | Primary tools | Pinning / reproducibility rule |
|---|---|---|
| D1 DNS/subdomain | subfinder, amass, crt.sh/Censys/CertSpotter, passive-DNS APIs, puredns+massdns, shuffledns, dnsx, altdns/gotator/dnsgen/ripgen, dnsvalidator, dig/ldns-utils, nsec3map, nuclei+takeover templates, can-i-take-over-xyz | *Pin tool tag/digest; pin resolver-list + wordlist + token-list + fingerprint-commit hashes; record resolver identity in PROV; own API keys read-only* |
| D2 Network/ASN/ports | RDAP+whois, Team Cymru, RIPEstat/RouteViews, bgp.he.net, PeeringDB, asnmap+mapcidr, cdncheck, provider range feeds, dnsx+massdns, Shodan/Censys/Sonar, httpx, tlsx+jarm, naabu, nmap, mmh3+sha256 | *Pin version; pin cdncheck range-DB date + provider-feed hash/ETag; record BGP collector + snapshot time; block intrusive/exploit/brute NSE; pin normalization ruleset* |
| D3 HTTP surface | httpx, tlsx, cdncheck, wafw00f, Wappalyzer/wappalyzergo, gowitness/aquatone, urlscan.io, Shodan/Censys, crt.sh, nuclei(RESTRICTED), katana/hakrawler(RESTRICTED), OpenAPI+GraphQL read-only clients, curl | *Pin exact httpx (disable retries); pin cdncheck dataset date; wafw00f lightest mode; pin Wappalyzer signature DB; pin Chromium build; record urlscan UUID+ts; pin nuclei engine+template commit, exposure-only* |
| D4 API contract | httpx, katana+linkfinder, gau/waybackurls, nuclei, swagger-parser/openapi-core/prance/Redocly, kiterunner, arjun, graphw00f, clairvoyance, InQL/graphql-cop, grpcurl+buf, mitmproxy, PyJWT/jwcrypto, jq/gron, TruffleHog/gitleaks | *Pin binary+wordlist(routes-large) hash; enforce request ceilings; introspection/reflection read-only; parsers isolated on untrusted specs; secret scan `--no-verification`* |
| D5 Identity/auth | httpx, curl, subfinder/amass(passive), gau/waybackurls, PyJWT/python-jose, openssl, trufflehog, gh/git(read-only), jq, mitmproxy/devtools | *Pin curl+CA bundle; JWT tooling decode/verify-local only (no mint/forge/alter), `python -I`, no egress; `--no-verification`; own session + gate record; PII-redact* |
| D6 Content/JS/crawl | katana, hakrawler/gospider, gau/waymore, Wayback CDX, CommonCrawl, urlscan.io, subjs/getJS, linkfinder/xnLinkFinder, jsluice, unwebpack-sourcemap, trufflehog, gitleaks, ffuf/feroxbuster, httpx, nuclei, robots/sitemap parser | *Pin tool + wordlist commit (SecLists@sha) as the `rule`; record regex-ruleset hash; record CC-MAIN id + scan UUID + capture ts; secret scan `--no-verification`; GET-only, soft-404 calibrated* |
| D7 Cloud/SaaS | subfinder+amass(passive), dnsx, httpx, tlsx+crt.sh, s3scanner, cloud_enum, aws CLI(`--no-sign-request`), gsutil/gcloud, asnmap+RDAP+BGP, nuclei, trufflehog/gitleaks, BBOT(passive) | *Pin version; scope-gate each target BEFORE run (tools have no scope awareness); list/stat-only; exclude fuzz/dos/intrusive; verification OFF* |
| D8 Object/data-model | PyJWT(local), OpenAPI parser, read-only GraphQL introspection client, mitmproxy(own client), offline structure classifier, SHA-256 hasher, secret scanner(verif OFF), OSINT corpus ingester | *Pin libs; classifier `python -I`, pin ruleset version; corpus pinned by commit, treated as untrusted; evidence encrypted* |
| D9 TLS-PKI/email | crt.sh+CertSpotter+Censys CT+direct reader, openssl s_client, jarm, zgrab2/tls-scan, dnsx/zdns/dig, checkdmarc / SPF-DMARC-MTA-STS parser, BIMI/VMC parser+openssl x509, SHA-256 content-addresser | *Pin openssl + jarm commit (10-ClientHello set fixed); record CT log+STH+query time; prefer public recursive resolvers; attribute every lookup to the ledger* |
| D10 OSINT/leaks/supply-chain | gh CLI+API, glab, trufflehog, gitleaks, git, Shodan/Censys, npm/NuGet/PyPI APIs, grep.app/Sourcegraph, Wayback/CommonCrawl, crane/skopeo, dork rule-packs | *Pin gh+API version; `--no-verification` + detector-set version; capture packument/response hashes; images inspect-only; version dork rule-packs; own token S3, never committed* |
| D11 Scope-drift/attribution | httpx + own H1 session/API, SHA-256+RFC-3161 TSA, structural+semantic differ, RDAP(whoisit)+WHOIS, Team Cymru/bgp.tools/asnmap/pyasn, crt.sh/certspotter/Google CT, favicon/brand fingerprinter, log-odds fuser, USPTO TSDR | ***Pin the RIB/BGP table date***; *record TSA identity+policy OID; diff the normalized model not raw HTML; version the attribution weight set; brand GET is active+scope-gated* |
| D12 Correlation/temporal | jarm/tlsx, JA4+ suite/ja3s, httpx, TLSH+ssdeep+SimHash, crt.sh/certstream/Censys, Shodan/Censys, passive DNS+dnsx, subfinder/amass(passive), nuclei(detection/takeover-signature only), RFC7638+JOSE, gau/waybackurls+JS parser, record-linkage engine (Splink/dedupe/F-S), calibration (sklearn), content-addressed event store | *Pin everything incl. merge-threshold with the rule; **verify JA4/JA4S FoxIO licensing** for automated use; prefer JA4S over JA3S; persist feature weights + calibration dataset hash with schema version; pin sha256; JOSE parse-only* |

### 6.3 Standing live-recon cautions carried into every run

- **Multi-CDN collision** (CloudFront/Akamai/Cloudflare/Fastly) poisons JARM/JA4S/favicon/edge-SPKI — SOFT features never decide a merge or ownership.
- **`scope != ownership`** re-asserted at the tool layer: `*.ol.epicgames.com`, Epic-originated netblocks, Epic GitHub orgs, and Epic-looking buckets are prefilters; the snapshot decides.
- **Ownership/divestiture traps:** Bandcamp (sold to Songtradr, Oct 2023) — never seed/attribute/act; ArtStation + Sketchfab (reported sold to KitBash ~Aug 2026) — treat as suspected traps **`(verify live)`**; `fhir.epic.com`/`api.epic.foundation`/`userweb.epic.com` are **Epic Systems healthcare, not Epic Games** — never ingest. Transfer lag means DNS still pointing at Epic infra is not evidence of current ownership.
- **Default-deny credential use** and **secret-scanner verification OFF** are enforced flags, not defaults — a run with verification on is a safety incident.
- **A local egress block is not a scope signal** and never downgrades a node's verdict.