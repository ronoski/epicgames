# TODO — next tasks

Status as of the merge of the autonomous recon pipeline (846 tests passing, no target ever
contacted). Ordered by what blocks what. See [`docs/SPEC.md`](docs/SPEC.md) and
[`docs/safety-model.md`](docs/safety-model.md) for the rules any of this must respect.

---

## P0 — blocks any real run

Nothing below P0 should be attempted against a live target first.

- [ ] **Verify the live scope.** Fetch `hackerone.com/epicgames/policy_scopes`, fill
      `scope.include` / `scope.exclude` in a real `configs/epicgames.yaml`, and paste the
      policy text into `policy_text` so a content-hashed snapshot can be pinned. The
      committed config is an **empty skeleton** on purpose.
- [ ] **Confirm program visibility** (public vs invite-only). If it is private, policy
      confidentiality and authorization constraints change materially.
- [ ] **Confirm per-asset in-scope status** — do not infer from ownership. Specifically:
      legacy `*-public-service-prod*.ol.epicgames.com`, `api.epicgames.dev`,
      `dev.epicgames.com`, and each acquisition apex (`artstation.com`, `sketchfab.com`,
      `quixel.com`, `fab.com`, `rocketleague.com`, `fallguys.com`, `psyonix.com`,
      `mediatonic.com`). Known traps: Bandcamp (divested to Songtradr, Oct 2023) and
      `fhir.epic.com` / `userweb.epic.com` (Epic Systems — a different company).
- [ ] **Confirm whether client reverse-engineering is in scope**, and which finding
      classes the program accepts, before anything in the binary-RE domain is built.
- [ ] **Only then** flip `allow_active: true`, and run `scope-check` → `plan` → dry-run
      `run` before a single active action.

## P1 — core gaps the module implementations worked around

Each of these is currently re-derived or compromised inside individual modules because the
shared interface could not express it. Fixing them removes duplicated logic and real
correctness risk.

- [x] **Shared URL/FQDN canonicalizer** (`recon/urls.py`, or extend `scope.py`).
      `SPEC.md` §3.1 promises specified URL canonicalization, but host/path/authority
      rules are currently re-implemented in `crtsh`, `resolver`, `permutations`,
      `http_probe`, `tls_probe`, `oidc_discovery`, `wayback` and `openapi_discovery`.
      They will drift apart.
- [x] **Third-party-source budget for passive modules.** `safety-model.md` §4 says passive
      sources consume a third-party budget, never an Epic per-target one — but the only
      ledger on `ModuleContext` is the Epic one, which passive modules must not debit. So
      crt.sh / archive.org politeness is per-module constants with no central ceiling,
      audit record, or cross-module serialization. Needs its own ledger + event kind.
- [x] **`Certificate` node type** in `schema/ontology.json` (or an I5 carve-out for a
      passively served cert). Today `tls_probe` cannot model a cert at all — facts ride as
      `WebApp` attrs — which blocks SPKI-reuse clustering for entity resolution.
- [x] **`scope.wildcard_includes_apex` is dead config.** It is accepted and stored but
      never consulted; `ScopeRule.matches` always treats `*.x` as covering the apex. A
      program whose wildcard excludes the apex would still bind the apex `in_scope`.
- [x] **CIDR seeds are bound by network address only.** `Scope` has no subnet-of
      containment check, so seeding `203.0.113.0/22` against an include of
      `203.0.113.0/24` binds `in_scope` even though most of the block is outside the rule.
- [ ] **`param:<op>#<name>` cannot distinguish a `query` from a `header` (or body)
      parameter of the same name** — they collide on id and would fork the graph on a
      bogus contradiction. `openapi_discovery` de-duplicates by name to avoid it.
- [ ] **`web:<scheme>://<vhost>` has no port slot**, so a seed like
      `web:https://host:8443` is unreachable (`openapi_discovery` skips and logs it).
- [x] **No containment edge for DNSName → Domain.** `derived_from` is the only containment
      edge and I5 requires its target to be an `Artifact`, so apex/subdomain containment
      cannot be modelled. Needs a promoted `subdomain_of` / `apex_of` edge.
- [x] **Missing `factory.DEFAULT_HALF_LIFE` entries** for `Hypothesis`, `NetBlock`, `ASN`
      and `Route` (they silently inherit P14D). A candidate's decay window is the whole
      point of "confirm or let it decay", and a netblock allocation is far more stable
      than 14 days.
- [x] **`gate_active` has no cost parameter and no non-spending "would this be allowed"
      check**, so a module cannot price an expensive verb differently or pre-filter a seed
      list without writing a REFUSE record per seed. A 10-port scan costs 10 flat units.
- [x] **Invariants I10–I12 are unimplemented** (`invariants.py` covers I1, I3–I9).
      Missing: I10 verb-on-dispatch, I11 contradictions-fork, I12 stale-snapshot-blocks.
      I10/I12 are enforced at runtime in the loop but not checked over the data.
- [x] **Event kinds for the Hypothesis lifecycle** (`hypothesis_promoted` /
      `hypothesis_decayed`), so promotion of a candidate to a confirmed node is auditable
      from the log alone rather than inferred from `node_upserted` + a `corroborates` edge.
- [x] **Stale id comment** in `schema/ontology.json`: `Hypothesis` is documented as
      `hyp:<uuid>` but the code requires the structured `hyp:dns-candidate:<fqdn>` form.

### Durability fixes made while building the P2 delta report

- [x] Upsert events now carry the **whole datum**, so the log is a source of truth rather
      than a trace and `recon replay` can rebuild the graph.
- [x] The event sequence **continues across runs** (a fresh log restarted at 0, so
      overlapping seqs made replay interleave runs wrongly).
- [x] The graph is **rehydrated from the log** at run start (every run previously began
      blank and re-"discovered" what earlier runs knew, so every delta looked new).
- [x] A run **no longer silently accepts scope drift** by pinning the new snapshot;
      acceptance is explicit (`recon drift --accept`), and `--execute` is refused while
      drift is unreviewed.
- [x] Idempotency keys distinguish **observations**, not just ids: keying on
      `(id, timestamp)` dropped a second source's corroboration and suppressed the
      `contradiction_forked` event for a fork.

### P1 remainder

- [x] **Migrate the modules onto `recon/urls.py`.** All 11 migrated; a static guard
      (`tests/test_urls_adoption.py`) now fails if a module re-grows a local canonicalizer
      or hand-builds an id, so the duplication cannot come back.
- [ ] **Promote `same_as` / `co_deploy` / `shared_trust_domain`** when entity resolution
      is built (they are still correctly listed as proposed-only).

## P2 — breadth: domains specced but not yet built

From [`docs/domains/non-binary.md`](docs/domains/non-binary.md). Roughly highest value
first.

- [x] **Scope-drift detector** — diff successive policy snapshots and emit drift events.
      This is governance; arguably belongs in P1 for a long-term target.
- [x] **`recon diff`** — the per-run delta report. For a long-lived target the *change*
      since last run is the headline, not the totals. The event log already supports it.
- [x] **`recon replay`** — rebuild the graph projection from the event log (proves the
      event-sourcing claim end to end).
- [ ] **`js_analysis`** — endpoint + secret extraction from stored JS/sourcemap evidence
      (operates offline over the evidence store).
- [ ] **Correlation / entity resolution** — JARM / favicon / 404-body / response-hash
      clustering to collapse identifiers into one logical service (needs the `same_as`
      proposed edge promoted first).
- [ ] **Email security** — SPF/DKIM/DMARC/MTA-STS posture per domain, MX/dangling
      takeover candidates (passive).
- [ ] **Cloud & SaaS footprint** — bucket discovery with **read-only** listing, serverless
      / API-gateway URLs, SaaS tenant attribution (most third-party SaaS is out of scope →
      record existence, send no probe).
- [ ] **DNS depth** — passive DNS, NSEC(3) walking, single-attempt AXFR, wildcard
      baselining (the rate caps in `safety-model.md` §4 apply).
- [ ] **OSINT / public-repo secret scanning** — verification **disabled**, org-level
      attribution only, breach data metadata-only.
- [ ] **Real-time protocol surface** — XMPP party/presence, WebSocket, matchmaking, EOS
      P2P/relay. Flagged as missing by the non-binary review; `openapi`/`graphql` cover
      only request/response.
- [ ] **Mobile associated domains** — `apple-app-site-association` and
      `/.well-known/assetlinks.json` for deep-link trust mapping.
- [ ] **Binary-RE domain** — per [`docs/domains/binary-re.md`](docs/domains/binary-re.md).
      Large, and **gated behind the P0 legal-authorization question** plus implementing
      the 12-check gate as code (it is spec-only today).

## P3 — hygiene

- [ ] **Strip, don't just banner, the hallucinated specifics** in `docs/domains/*.md` (ASN
      and netblock anchors, BPS magic numbers, the "Houseparty takeover", the "Quixel
      divestiture", `deadline` as an Epic repo, all `CONFIRMED` infra tags). The
      corrections banners neutralize them for a careful reader; a careless one still
      inherits bad priors.
- [ ] **CI** — no workflows configured. Run `pytest` and `recon invariants` on push/PR so
      the safety invariants are checked over the data, not just asserted in prose.
- [ ] **`pip install -e .`** in the dev setup so the `recon` entry point works without
      `PYTHONPATH=.`.
- [ ] **Public-suffix handling** — `scope.registrable_domain` uses a small hardcoded
      multi-part-suffix table. Fine for `.com`/`.dev`, wrong in general; the rate-ledger
      key depends on it.
