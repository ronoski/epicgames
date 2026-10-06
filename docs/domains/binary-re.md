<!-- AUTHORITATIVE RULES LIVE IN ../SPEC.md AND ../safety-model.md. THIS IS A PENDING-VERIFICATION REFERENCE. -->
> ## ⚠️ Status: AI-synthesized working reference — corrections applied
>
> This document was produced by a multi-agent synthesis and then adversarially reviewed.
> The review found hallucinated/over-precise Epic specifics and two safety contradictions.
> **Treat every concrete Epic identifier, offset, magic number, host, client_id, version, and
> date below as a _candidate to re-derive from the pinned artifact / live source_, never as
> fact.** The authoritative, de-conflicted rules are in [`SPEC.md`](../SPEC.md) and
> [`safety-model.md`](../safety-model.md); where this file disagrees with them, they win.
>
> **Controlling corrections (override the body below):**
> 1. **§7 controls over the §2 legal gate.** No unwrapping/decrypting/devirtualizing of DRM,
>    FairPlay, UE-pak AES, encrypted BPS/ChunksV5, or anti-cheat integrity — *regardless* of any
>    DMCA §1201 posture. `circumvents_tpm == true` ⇒ **REFUSE** absent explicit, documented,
>    per-asset program+legal authorization. A generic exemption citation never authorizes it.
> 2. **No in-process instrumentation of any anti-cheat- or integrity-coupled client process**
>    (Frida/objection/gadget/debugger), including pre-match/login surfaces. Such clients are
>    observed by **network-layer capture of your own traffic only**. In-process tooling is reserved
>    for confirmed non-AC, non-integrity titles.
> 3. **Default-deny live credential use.** Discovered `client_id`/secret/EOS creds stay **static
>    mapping facts** (coverage caps at `enumerated`). Any authenticated call (incl. a single
>    `client_credentials` POST) or `deviceAuth` provisioning needs an explicit program-authorization
>    token and its own gate record.
> 4. **Capture/retention is bound to `scope_binding == in_scope`, not Epic ownership.**
> 5. **Incidental other-user PII** (friends/party/matchmaking) is hash-redacted at ingest and may
>    never be an edge endpoint toward a non-owned resource; mutating MCP verbs (e.g. `MarkItemSeen`)
>    are excluded from the recon whitelist.
>
> **Known-fabricated / unverified specifics to disregard until re-derived:** EOS “1.19.0.3 / NDK
> r27c”; BPS magic numbers `0x44BEC00C` / `0xB1FE3AA2`, FeatureLevel 15–24+, `group = CRC32(guid) %
> 100`; the SafetyNet turndown date; the UK iOS alt-distribution date; the macOS Team ID; and all
> client_id/secret hex. Ontology: the `part_of` edge is **not** declared — use `derived_from`; the
> `re_feasibility` penalty is a **log-odds delta**, not a probability multiplier.

---

# APK & Binary Reverse-Engineering — Recon Intelligence Domain

## 1. Overview and graph placement

This domain derives reconnaissance from Epic's **client software** — Fortnite Android (split APK + OBB/asset packs), Fortnite iOS (EU alternative distribution under the DMA), the Epic Games Launcher (Windows PE / macOS Mach-O), Unreal Engine editor/runtime, the Epic Online Services (EOS) SDK native libraries, Rocket League / Fall Guys / Rocket League Sideswipe, the Easy Anti-Cheat / BattlEye components, and the Build Patch (BPS) / manifest updater — rather than from the live web. Its facts land primarily on the **Artifact → Operation → Parameter → AuthScheme → Credential/ClientId → Token → ObjectType → Flow** nodes (plus seeding **Domain/DNSName/Host/Service/WebApp/Route** candidates handed to the live-web facet), connected by `derived_from(Artifact)`, `calls`, `takes`, `authenticates_with`, `issued_by`, `grants`, `references_object`, `step_of(Flow)`, and `corroborates/contradicts` edges, each `evidenced_by` a **content-addressed Evidence handle** `= {artifact_sha256, region}` where `region ∈ {file-path-in-container | byte_offset,len | symbol,va_rebased_to_imagebase | class,method | proto_message,field_number | manifest_xpath}`. Every node/edge carries a W3C-PROV chain (`Evidence → tool@pinned_version → rule → fact`), a calibrated log-odds confidence (contradictions **fork**, never overwrite), temporal fields (`first_seen/last_seen/last_verified` + per-class decay half-life), and a **snapshotted scope-binding** captured at observation time; cross-version binary diffing is the domain's primary temporal signal and the gap queue is its autonomous scheduler. The domain is **static-first and strictly non-destructive**, performed only on binaries the researcher lawfully holds on their **own device** and observed only against their **own account/session**.

---

## 2. Legal / scope / ethics HARD GATE (hard precondition — nothing runs before this passes)

Every RE action must clear a **four-layer authorization stack** that must *all* hold simultaneously, because each layer governs a different body of law and none substitutes for another:

1. **Program authorization** — the Epic HackerOne policy (`hackerone.com/epicgames`) is the only instrument that contractually overrides Epic's EULA RE-prohibition. RE is permitted only for in-scope assets and only for the conduct/finding-classes the policy allows *(reportedly: datamining of approved client executables yielding information-disclosure or cryptographic-weakness findings; game/executable/cheat findings judged case-by-case; anti-cheat-detected activity typically unrewarded — **verify against live policy**)*.
2. **Copyright / DMCA §1201** — circumventing any technological protection measure (packing, DRM, encryption, anti-cheat integrity) is lawful only under a §1201 exemption: permanent interoperability (f), encryption-research (g), security-testing (j), or the 2024 regulatory good-faith-security-research exemption (37 CFR 201.40, in force to **2027-10-28** — **re-confirm before expiry**), which requires a *lawfully acquired* device/program, circumvention *solely* for good-faith research, a *controlled environment*, and *no other-law violation*. A §1201 exemption shields only the anti-circumvention claim — never EULA, CFAA, or anti-cheat permission. The §1201(a)(2)/(b) **anti-trafficking** bars separately forbid building/distributing any circumvention tool, key, or patched client even when one's own circumvention is exempt.
3. **Contract** — the Fortnite, Unreal Engine, and Epic Games Store EULAs each prohibit reverse engineering "except as applicable law permits"; program authorization is what resolves that conflict, and only within its grant *(exact clause numbers — verify against live policy)*.
4. **Ethics / CFAA** — own-device, own-account, own-session only; never another user's account/data/session; no anti-cheat circumvention, no cheat creation, no DoS; minimal retention; responsible disclosure.

### Pre-action decision checklist (the autonomous loop must emit an `ALLOW` `gate_decision_record` before any RE Activity runs; a `REFUSE` record blocks it)

| # | Check | Pass condition |
|---|-------|----------------|
| 1 | **Scope** | `scope_binding_snapshot.verdict == in_scope` against a non-stale policy snapshot (policy doc content-hashed + timestamped; ambiguous ⇒ out-of-scope pending human adjudication) |
| 2 | **Authorization** | `authorization_basis.primary == h1_program_safe_harbor`; program authorizes client RE for this asset/finding-class (`unknown` ⇒ REFUSE) |
| 3 | **Lawful copy** | `acquisition_provenance` proves official channel + own account/device + matching artifact hash |
| 4 | **TPM** | if `circumvents_tpm` then a valid §1201 exemption is attached **and** controlled-environment + sole-purpose hold; else §1201 not triggered |
| 5 | **Anti-cheat** | `anti_cheat_classification.action_mode != runtime_circumvent` |
| 6 | **Ownership** | for any dynamic evidence, `session_is_own == true` and `touched_other_user == false`, `data_subjects == ['self_only']` |
| 7 | **Verb** | `recon_verb_label` on the non-destructive whitelist (closed set) |
| 8 | **Sensitivity** | handling set for every secret/PII item; `may_be_used_to_access == false` |
| 9 | **No trafficking** | `no_trafficking_guard` all-false; `disclosure_channel == hackerone_report_only` |
| 10 | **Rate** | `rate_budget_ledger_entry.exceeded == false` for any live corroboration |
| 11 | **Corpus** | `legal_corpus_binding` pins current EULA/statute/regulation versions; §1201 reg-exemption within its effective window |
| 12 | **Record** | W3C-PROV `gate_decision_record` (ALLOW/REFUSE) written and linked before the Activity |

### Machine-checkable safety invariants (hold over all data at all times)

- **No active-probe / dynamic Evidence may attach to any node whose scope-binding was false at observation time.** A runtime/instrumentation Evidence handle on a `dynamic_allowed=false` node is a hard breach — **rejected at ingest**, not down-weighted.
- Every `derived_from(Artifact)` edge references an Artifact with non-null `authorization_basis`, `acquisition_provenance`, and `in_scope` scope-binding.
- **Recon-verb whitelist (closed set):** `hash, unzip, strings, nm/objdump-symbols, static-decompile, parse-manifest, parse-catalog, diff-manifest, extract-endpoint, extract-client-id (read-only)`. **Blocked:** `patch, inject, hook-runtime, bypass, circumvent, crack, keygen, repack, redistribute, memory-write, server-call-with-forged-arg`. The loop cannot invent a verb.
- No Artifact or edge may exist with `anti_cheat_classification.action_mode == runtime_circumvent`; anti-cheat artifacts are hard-capped at coverage `acquired/inventoried`.
- Every `Credential/ClientId`, `Token`, and other-user `ObjectType` carries a `sensitivity_label`; no edge uses a `secret`/`pii` node to reach a non-owned resource.
- No Artifact has `no_trafficking_guard.is_circumvention_tool == true` or `published_externally == true`.
- Every live call is debited on the **per-target rate-budget ledger**; no per-target budget goes negative (append-only, auditable).
- A TPM-circumventing action requires ≥1 valid §1201 exemption **and** a `controlled_environment` flag or it cannot be ALLOWED.
- **Contradictions FORK:** a later decision conflicting with an earlier ALLOW writes a contradicting `gate_decision_record` and quarantines dependent facts; it never overwrites history.
- A **stale policy snapshot** (older than its decay half-life) forces re-fetch + re-match before any new ALLOW; facts authorized under a superseded snapshot are re-queued.

---

## 3. Target matrix — per client/platform, what to acquire and how (legitimately)

| Target | Artifact kinds | Legitimate acquisition (own device/account) | What to pull | Scope / caveats |
|--------|----------------|----------------------------------------------|--------------|-----------------|
| **Fortnite Android** `com.epicgames.fortnite` | `apk_base` + `config.<abi>` (arm64-v8a) + `config.<dpi>` + feature/obb splits + OBB / Play Asset Delivery packs | `adb shell pm path` then `adb pull` from own device; or Epic self-hosted installer. Channels: Epic direct APK, Epic Games Store mobile (EU). Samsung Galaxy Store was a channel until Epic pulled Fortnite in 2024 *(verify)* | Full split set + OBB; per-file sha256; signer cert | **Mirror APKs (apkpure/apkcombo/…) are untrusted/repacked — never seed the graph; quarantine + signer-cert gate** |
| **Fortnite iOS (EU)** bundle id `com.epicgames.fortnite` *(verify from Info.plist)* | `ipa` / ADP / `.app` | Own EU-region device/account: ADP for AltStore PAL / Epic marketplace (notarized, generally **not** FairPlay-wrapped → `cryptid==0` → static works), `.app` from own device filesystem, or own dev build | Mach-O slices, Info.plist, entitlements, embedded frameworks | EU-only under DMA (EGS iOS Aug 2024, UK H2 2025 *(verify)*); **do not break FairPlay**; confirm `cryptid` empirically per build |
| **Epic Games Launcher** | `pe_exe/pe_dll` (Win64 `Portal\Binaries\Win64`), `macho` (`.app`, arm64+x86_64), `EpicWebHelper.exe` (CEF) | Own licensed install | VERSIONINFO, imports, config (`LauncherInstalled.dat`, `*.item`), CEF JS bundles (hand to JS facet) | Much store/account logic is in CEF JS, not the PE |
| **Unreal Engine editor/runtime** | `UnrealEditor.exe`/`UE4Editor.exe`, engine DLLs, `CrashReportClient.exe` | Own install via Launcher; engine source separately on GitHub under UE EULA | Config `.ini`, DataRouter URL, EOS integration | Whether end-user UE is in HackerOne scope — **verify** |
| **EOS SDK native libs** | `libEOSSDK.so` (Android; often inside `eossdk-StaticSTDC .aar`, 64-bit only since 1.19.0.3, NDK r27c), `EOSSDK-Win64-Shipping.dll`, `libEOSSDK-Mac-Shipping.dylib`, `libEOSSDK-Linux-Shipping.so`, iOS `EOSSDK.framework` | From the above clients; **official SDK zip from dev.epicgames.com used only as a decoding oracle** | Exported `EOS_*` symbols, version/CL, platform creds, structs | In UE titles EOS is **frequently statically linked** into the monolith (`libFortniteClient…so`) — a standalone lib may be absent |
| **Rocket League / Fall Guys / Sideswipe** | desktop/console + mobile clients | Own install | EOS integration, client_ids, auth flows | Confirm anti-cheat posture + in-scope status per title; confirm Unreal vs Unity before choosing toolchain |
| **Easy Anti-Cheat / BattlEye** | `EasyAntiCheat_EOS.dll/.sys`, `BEService.exe`, `BEDaisy.sys`, `BEClient_x64.dll` | From own install | **Inventory only** — name, version, sha256, signer | **HARD STOP** (§7); `do_not_instrument=true` |
| **Build Patch / manifest updater** | CDN-served BPS manifest/catalog (JSON/binary chunk) | Own-account launcher session; passive manifest/catalog reads | AppName/BuildVersion/BuildId/catalogItemId/chunk lists | CDN hosts (`*.akamaized.net`, Fastly, Cloudflare) are **third-party, active-probe-forbidden**; reads of in-scope `*.ol.epicgames.com` services only |
| **OUT OF SCOPE by ownership** | Bandcamp (divested to Songtradr, Oct 2023) | — | — | Stale-ownership trap; scope-binding evaluated at observation time excludes it |

---

## 4. Extraction taxonomy → ontology mapping

Columns: **Extraction → maps_to node / edge → Evidence handle → confidence notes**. Grouped by facet. Candidate identifier values are community-sourced hypotheses to **re-derive from the acquired artifact**, never authoritative.

### 4a. Static Android (read bits off disk only)

| Extraction | Node → edge | Evidence | Confidence notes |
|---|---|---|---|
| Build acquisition + content-addressing (all splits + OBB) | Artifact → `evidenced_by` per-file sha256; splits/OBB `derived_from` parent | `sha256(base.apk)`, `sha256(config.arm64_v8a.apk)`, `sha256(main.<ver>.obb)` | High only if signer matches pinned Epic signer; mirror = untrusted |
| Package identity + version pin | Artifact → `derived_from` | aapt2/apkanalyzer | **Pin `versionCode`** (monotonic), not `versionName` |
| Signing cert + APK sig scheme (v1/v2/v3/v3.1/v4) | Artifact → `corroborates` Organization; `evidenced_by` | `apksigner verify --print-certs` SHA-256 vs pinned Epic signer | **Primary anti-tamper gate**; mismatch ⇒ quarantine |
| Exported components (activity/service/receiver/provider) | Operation → `derived_from`, `exposes`, `takes` (intent extras) | AndroidManifest | Static reachability only; **do not fire intents** |
| Deeplink / App Link schemes, hosts, paths | Route → `derived_from`, `references_object`/Domain, `step_of(Flow)` | intent-filter `data`; `autoVerify=true` ⇒ single passive GET `/.well-known/assetlinks.json` | assetlinks fetch is passive/allowed; verify actual schemes |
| Permissions (platform + custom protectionLevel) | Artifact → `derived_from`; informs signature-level inter-app AuthScheme | manifest `uses-permission` / custom perms | Deterministic |
| networkSecurityConfig + cleartext + cert pinning | AuthScheme → `references_object`/Domain | `res/xml/*.xml` pin-set digests | Presence/absence of pinning is load-bearing for dynamic feasibility |
| meta-data / EOS/Firebase/Play config keys | Credential/ClientId → `derived_from`, `issued_by` | `<meta-data>` pairs; EOS Product/Sandbox/Deployment = 32-hex | EOS ids are **public identifiers, not secrets** |
| Endpoint URL + API host-template mining (DEX/smali) | Route/Domain → `derived_from`, `references_object`, `corroborates` live-web | URL regex + Epic host templates `…-public-service-prod<NN>.ol.epicgames.com` | Capture **template + arg source**, not just literals; R8 string-encryption hides these |
| OAuth client_id mining (32-hex, context-gated) | Credential/ClientId → `authenticates_with`, `issued_by`, `derived_from` | `\b[0-9a-f]{32}\b` near `client_id\|ClientId\|Basic`. Candidates: `fortniteAndroidGameClient=3f69e56c…`, `androidPortal=38dbfc31…`, `fortnitePCGameClient=ec684b8c…` *(verify against pinned build)* | Community values may be rotated/stale — **candidates only** |
| OAuth public-client Basic secret pair | AuthScheme → `authenticates_with`, `derived_from` | `Basic [A-Za-z0-9+/=]{20,}` → decode `id:secret` | Hardcoded public-client secret alone ≈ N/A; value is *which client authorizes which scopes* |
| Auth scheme + grant types + token discovery | AuthScheme → `grants` Token, `step_of(Flow)` | `/account/api/oauth/token`; token `eg1~…` / JWT `eyJ…`; EOS `/auth/v1`, `/epic/oauth/v2` | Token internals never exercised, only shapes documented |
| EOS SDK surface + ObjectType/Operation from classes | ObjectType → `derived_from`, `calls`, `references_object` | `EOS_Connect_Login`, `EOS_Ecom_QueryOwnership`; retrofit/okhttp `@GET/@POST` | R8 renames app classes; EOS symbols survive in native libs |
| Feature flags / cvars / config keys | Parameter → `derived_from`, `step_of(Flow)` | UE cvars, `[/Script/…]` ini keys, `bEnable*` | APK holds **defaults only**; live values arrive via hotfix |
| Firebase `google-services.json` | Credential/ClientId → `issued_by`, `references_object`/Domain | `AIza[0-9A-Za-z_-]{35}`, `…apps.googleusercontent.com`, storage bucket | Firebase API key is a **public identifier, not a secret**; don't probe Google |
| Embedded JSON / remote-config defaults / INI | ObjectType → `derived_from`, `references_object`, `takes` | `assets/*.json`, `res/raw/*`, UE configs | Distinguish shipped defaults from runtime-fetched |
| Protobuf descriptors / FileDescriptorSet | ObjectType → `derived_from`, `references_object`, `calls` | `protoc --decode_raw`; `GeneratedMessage*` | Powerful for typed Flow/Operation where protobuf is used |
| UE pak/IoStore + hotfix/cloudcontent refs | Flow → `step_of`, `calls`, `references_object` | `CloudStorage`, `Hotfix`, `.pak/.ucas/.utoc` strings | Explains why config is **absent** from static APK |
| Native lib inventory `lib/<abi>/*.so` (handoff) | Artifact (child) → `derived_from` parent, `evidenced_by` per-.so sha256 | `libUnreal.so`, `libEOSSDK.so`, `libc++_shared.so` | Boundary object to native facet — **inventory, not analysis** |
| Anti-cheat presence (inventory only) | Artifact → `derived_from` | strings/lib names `EAC/BattlEye` | **HARD STOP** beyond inventory |
| Auth/login Flow reconstruction | Flow → `step_of`, `authenticates_with`, `grants` | ordered Operations from mined endpoints | Steps are hypotheses with confidence deficit until live-corroborated |
| Cross-version diff (per `versionCode`) | Artifact → `derived_from`+temporal, `corroborates/contradicts` | normalized string-set + manifest diff vs N-1 | Primary autonomous trigger; contradiction **forks** |

### 4b. Dynamic Android (own device/account — runtime observation; §5)

| Extraction | Node → edge | Evidence | Confidence notes |
|---|---|---|---|
| Observed OAuth token-exchange (own account) | Operation → `authenticates_with`, `derived_from` | full redacted req/resp pair, sha256-addressed; `POST …/account/api/oauth/token grant_type=exchange_code&token_type=eg1` | Captured value is ground truth over cached assumption; shard drifts |
| Android game client_id + Basic secret | Credential/ClientId → `grants` Token, `derived_from` | `Authorization: Basic …` → decode; store hash+length only | `3f69e56c…` historically — **verify live**; secret SENSITIVE |
| Issued access/refresh token + EG1 JWT claims | Token → `issued_by`, `grants`, `evidenced_by` | `{access_token:'eg1~…', refresh_token, account_id, app:'fortnite'}` | High on shape; **HARD SENSITIVE**, redact, never reuse |
| Device-auth provisioning + grant flow | Flow → `step_of`; Credential `grants` Token | `POST …/deviceAuth` → `grant_type=device_auth` | Own deviceAuth only; verify current path/fields |
| Legacy OL OAuth vs EOS OAuth v2 discrimination | AuthScheme → `authenticates_with`, `issued_by` | `account-public-service…/oauth/token` (eg1) vs `api.epicgames.dev/epic/oauth/v2/token` | Both endpoints confirmed; mobile EOS scopes/deploymentId — verify |
| Live host/service/vhost/route inventory (SNI+Host) | Host → `hosted_on`, `exposes`; scope-binding snapshot | `account/fortnite/xmpp/party/lightswitch…-public-service-prod.ol.epicgames.com`, `datarouter`, `api.epicgames.dev` | Separate in-scope Epic hosts from out-of-scope third-party; drop the latter |
| MCP profile-command operations + params | Operation → `takes`, `references_object` | `POST /fortnite/api/game/v2/profile/{accountId}/client/{command}?profileId=athena&rvn=-1`; `QueryProfile`, `MarkItemSeen`… | Route shape stable; command set is season-dependent — param-mine |
| XMPP/websocket social handshake | Flow → `step_of`, `authenticates_with` | `wss://xmpp-service-prod.ol.epicgames.com`, SASL PLAIN + JID + token, `<bind>` | Exact SASL/JID/stanza schema — verify from capture |
| EOS Connect / EAS native-SDK calls | Operation → `derived_from` `libEOSSDK`, `issued_by` EOS | `POST api.epicgames.dev/epic/oauth/v2/token`, Connect → PUID | In-process `.so` correlation must **not** run during a protected session |
| Deeplink/intent dispatch (own instance) | Operation → `takes`, `derived_from` | `adb shell am start -a VIEW -d '<scheme>://…' com.epicgames.fortnite` | Low until confirmed per build; own instance only, no cross-user/mutating actions |
| ObjectType schemas from live responses | ObjectType → `references_object`, `evidenced_by` | athena/common_core profile items, catalog offers, parties | Patch-dependent; label embedded PII SENSITIVE |
| Startup config / lightswitch / hotfix / cloudstorage | Operation → `references_object`; config → Artifact | `GET /lightswitch/api/service/bulk/status?serviceId=Fortnite`, `/cloudstorage/system` | Routes historically stable; verify current |
| TLS-pinning mechanism fingerprint | AuthScheme → `evidenced_by`, `corroborates` static | Java OkHttp `CertificatePinner` vs native BoringSSL `SSL_CTX_set_custom_verify` | Native pinning in EOS SDK is common; Java-only bypass misses EOS plane |
| Client fingerprint / UA / build-version pin | Artifact → `derived_from`, temporal | `User-Agent: Fortnite/++Fortnite+Release-XX.XX-CL-… Android/…` | Pins all captures to a specific build/CL |

### 4c. iOS / IPA + EU alt-distribution (static)

| Extraction | Node → edge | Evidence | Confidence notes |
|---|---|---|---|
| IPA/ADP acquisition + Artifact birth | Artifact → `evidenced_by` | `sha256` of container + per-slice; `delivery_channel ∈ {epic_marketplace, altstore_pal, direct_website, own_devbuild}` | ADP generally not FairPlay-wrapped → analyzable; confirm `cryptid==0` per build |
| Mach-O arch/linkage/encryption fingerprint | Artifact → self-attrs; child frameworks `derived_from` | `otool -l/-L`, LIEF, jtool2: `{arch, cryptid, min_os, team_id, linked[]}` | Load-command parse deterministic/high |
| `__cstring`/`__objc_methname` → endpoint/host candidates | Route/Domain/WebApp/Operation → `derived_from`, `corroborates/contradicts` | `strings -a -t x`, rabin2 `-zzz`, floss; `#__TEXT,__cstring@0x…` | String present ≠ live/in-scope — `coverage=enumerated` until corroborated |
| Info.plist `CFBundleURLTypes` schemes | Operation → `step_of(Flow)`, `derived_from` | `plutil -p` → scheme candidates | Scheme reg authoritative; mapping to a Flow is a Hypothesis |
| `NSAppTransportSecurity` exception map | Domain(posture) + Hypothesis → `derived_from`, `corroborates` | `NSExceptionAllowsInsecureHTTPLoads` per domain | Reflects client intent, not server reality — don't assert weakness from plist |
| Associated Domains entitlement + AASA | Domain/Route/Operation → `references_object`, `step_of(Flow)` | `GET https://<domain>/.well-known/apple-app-site-association` | AASA is public OSINT; still scope-bind listed domains |
| Code-signing entitlements (+ marketplace entitlement) | AuthScheme/Credential/Flow → `authenticates_with`, `step_of` | `codesign -d --entitlements`; `keychain-access-groups`, `com.apple.developer.marketplace.*` | Signed/authoritative; marketplace keys Apple-defined, read the blob |
| Embedded frameworks + SDK inventory | Artifact (per framework) → `derived_from`, `calls` | `Frameworks/EOSSDK.framework` + CFBundleVersion vs EOS release notes | Presence/version high; which EOS interfaces invoked is a Hypothesis |
| EOS runtime config (Product/Sandbox/Deployment/Client/Secret) | Credential/ClientId + Parameter → `authenticates_with`, `references_object` | `POST api.epicgames.dev/auth/v1/oauth/token grant_type=client_credentials` | Endpoint/mechanics confirmed; embedded secret = finding to **report, not use**; possible honeytoken |
| Epic account OAuth client (`fortniteIOSGameClient`-class) | Credential/ClientId → `authenticates_with`, `grants` | community `3446cd72…` *(verify, may be rotated)*; `Basic base64(id:secret)` | Re-extract from in-hand binary; SENSITIVITY=secret |
| ObjC/Swift metadata → Operation/ObjectType/Flow | Operation/Flow/ObjectType → `calls`, `step_of` | class-dump / dsdump / dsdump-swift; `#__objc_methname@0x…` | Names authoritative; implied semantics medium; stripped builds reduce yield |
| Embedded config/asset backend maps | Domain/WebApp/Route/ObjectType → `derived_from`, `corroborates` | `*.plist/*.json` host tables, env switches | High for configured intent; watch third-party SDK config |
| MarketplaceKit / EU alt-distribution surface | WebApp(Epic marketplace)/Route/Operation/AuthScheme → `exposes`, `takes`, `step_of` | `marketplace-kit://` hand-off, ADP hosting, `/oauth/token` JWT relay | **Apple/AltStore MarketplaceKit/notarization endpoints are OUT of Epic scope** |
| MarketplaceKit per-device `client_id` | Credential/ClientId (PII) → `takes`, `step_of(install)` | opaque per-(device,AppleID,marketplace) id | SENSITIVITY=PII; store salted hash, never correlate across accounts |
| APNs/push + third-party SDK attribution | Domain (Epic vs third-party) → `derived_from`, scope snapshot | `aps-environment`; host classification | **Attribution is load-bearing**; default unknown → out-of-scope |

### 4d. Desktop clients (Windows PE + macOS Mach-O, static)

| Extraction | Node → edge | Evidence | Confidence notes |
|---|---|---|---|
| Binary artifact identity + Evidence handle | Artifact + Evidence | sha256 (+ per-slice for fat Mach-O), VERSIONINFO, UE BuildVersion/CL | Hash deterministic; attribution medium until code-sign corroborates |
| PE/Mach-O structural fingerprint | Artifact attrs → `derived_from` | Rich header, DLL characteristics (ASLR/DEP/CFG), TLS callbacks; LC_UUID, min-OS | Packed/high-entropy lowers downstream string confidence |
| Import/delay-import + EOS SDK linkage | Artifact dependency → `derived_from` (consumer→EOS SDK) | IAT/delay-load; `EOS_Platform_Create`, `EOS_Auth_Login` | High when symbols resolve; medium if dynamically resolved |
| Embedded endpoint strings → Domain/Route/Operation | Operation(+Domain/Route/WebApp) → `derived_from`, `exposes`, `corroborates` | `account/launcher/catalog/entitlement-public-service…`, `datarouter`, `api.epicgames.dev` | String→live mapping medium (prod shards rotate) → verify_live |
| OAuth client_id/secret pairs | Credential/ClientId → `authenticates_with`, `issued_by`, `grants` | `launcherAppClient2=34a02cf8…` (secret `daafbccc…`), `fortnitePCGameClient=ec684b8c…` *(verify from current binary)* | Community values are **hypotheses**; **fork on mismatch** (rotation expected) |
| AuthScheme + grant-type map | AuthScheme → `authenticates_with`, `step_of` | `client_credentials/authorization_code/exchange_code/device_code/device_auth/refresh_token/external_auth`; `Basic base64(id:secret)` | Grant types string-confirmable; which a client is *allowed* is Epic-side policy |
| EOS Platform credential bundle | Credential/ClientId + ObjectType → `derived_from`, `grants`, `references_object` | ProductId/SandboxId/DeploymentId=32-hex, ClientId, ClientSecret, EncryptionKey=64-hex | Live Fortnite EOS ids unconfirmed → verify_live; hardcoded secret/key is itself reportable |
| On-disk config `.ini/.json/.dat` | Artifact(config) → `derived_from`, `references_object` | `[CrashReportClient] DataRouterUrl`, `LauncherInstalled.dat`, `*.item` | High plaintext; medium inside AES pak (title key is sensitive — don't publish) |
| Crash-reporter DataRouter endpoint + params | Operation → `takes`, `step_of` | `POST datarouter.ol.epicgames.com/datarouter/api/v1/public/data?AppID=…` | Default documented; per-title override possible |
| Third-party crash/telemetry (BugSplat/Sentry) + DSN | Operation + Credential → `derived_from`, `issued_by` | `{database}.bugsplat.com/post/ue4/…`; Sentry DSN | Whether Epic currently routes here — verify_live |
| Update/patch/manifest/catalog + chunk CDN | Operation/Route + Domain + ObjectType(Manifest/Chunk/Build) → `references_object`, `step_of` | `epicgames-download1.akamaized.net/Builds/…/ChunksV4/…` | Metadata only; **no mass chunk download** |
| Code-signing / publisher identity | Organization + Artifact + Evidence → `issued_by`, `corroborates` | Win `O='Epic Games, Inc.'`; macOS `Developer ID … (96DBZ92D3Y)` *(older ref — verify)* + notarization | Verification deterministic; subject/team-id re-read per build |
| EOS SDK exported-interface catalog | Operation + ObjectType → `derived_from`, `calls` | `EOS_Ecom_QueryOwnership`, `EOS_TitleStorage_ReadFile`… | Export enum high; "linked ≠ invoked" needs xref |
| Anti-cheat existence + declared endpoints | Artifact (+Operation/Domain if plaintext) → `derived_from` | `EasyAntiCheat_EOS.dll`, `BEService.exe`, `BEDaisy.sys` | **Recon-only**; candidate `modules.easy.ac` unconfirmed |
| ObjectType / backend data-model | ObjectType → `references_object`, `derived_from` | `Entitlement{catalogItemId,namespace,…}`, `Manifest{AppName,BuildVersion,…}` | Medium — inferred from field names |
| Flow reconstruction (login/entitlement/download/crash) | Flow → `step_of`, `calls` | Launcher login: `exchange_code → oauth/token(launcherAppClient2) → library/catalog/entitlement` | Medium; rises when live-web observes same sequence |
| Environment/shard + feature-flag strings | WebApp/Operation(env attr) → `derived_from` | `-prod06/-prod03` vs `gamedev/stage/-dev` | gamedev/stage/dev **out-of-scope by default** |
| Embedded public keys / cert-pinning material | Credential(public) + AuthScheme(pinning) → `derived_from`, `authenticates_with` | pinned SPKI sha256 in `.rdata`; EG1-verify key | Distinguish OS trust-store material from Epic pinning; hardcoded **private** key = critical |
| Version/build lineage | Artifact temporal → `derived_from`, `corroborates/contradicts` | `++Fortnite+Release-<ver>-CL-<cl>`; `EngineVersion` | Drives staleness/decay term |

### 4e. Native / EOS SDK / protobuf / protocol

| Extraction | Node → edge | Evidence | Confidence notes |
|---|---|---|---|
| EOS native module location + content-address | Artifact → `derived_from`, `part_of` | path-qualified (`base.apk`/split/OBB/IPA/monolith) + sha256; or in-monolith `.text` range | Standalone vs statically-linked observed per artifact — fork a hypothesis per packaging |
| EOS SDK version + build-CL fingerprint | Artifact → `corroborates/contradicts` release-notes oracle | `'1.17.1.3-CL44532354'`, `EOS_GetVersion` | **Selects the version-matched `eos_*.h` oracle** for all symbol/struct/enum decoding |
| Embedded service base URL | Domain → `derived_from`, later `resolves_to` | `https://api.epicgames.dev`; legacy `*.ol.epicgames.com` | High for presence; scope-bind + resolve (own account) before raising |
| Regional/templated host + relay templates | DNSName → `derived_from`, `exposes` | format strings `%s.api.epicgames.dev`, relay/TURN pools *(exact templates — verify)* | Template shape recoverable; expanded hosts are hypotheses; don't mass-resolve |
| EOS interface census via exported C symbols | Operation → `calls`, `derived_from` (symbol + RVA) | `nm -D \| grep EOS_`; diff vs official "API Functions By Interface" | Flat C ABI survives stripping; presence in monolith can be "linked but unused" — raise on xref, fork otherwise |
| REST route + version reconstruction | Route → `exposes`, `takes`, `step_of` | `…/auth/v1/oauth/token`, `/epic/oauth/v2/token`, `/epic/oauth/v2/.well-known/jwks.json`, ecom/sessions/lobby | Confirmed anchors high; interface→route inference medium; pin SDK→route version |
| Parameter / query/body field recovery | Parameter → `takes`, `derived_from` (struct offset) | `grant_type, scope, external_auth_type, deployment_id, bucketId, nonce` | Header-derived vs literal-derived marked separately |
| AuthScheme + external-credential-type enum | AuthScheme → `authenticates_with`, `issued_by`, `grants` | `EOS_EExternalCredentialType` (EPIC, STEAM_SESSION_TICKET, PSN_ID_TOKEN, XBL_XSTS_TOKEN, APPLE_ID_TOKEN, DEVICEID_ACCESS_TOKEN…) | Enum integers **change ordering across versions** — decode with version-matched header |
| Embedded Product/Sandbox/Deployment/Client creds | Credential/ClientId → `issued_by`, `grants`, `authenticates_with` | ProductId/SandboxId/DeploymentId=32-hex, EncryptionKey=64-hex | ClientSecret/EncryptionKey = **secret**: store salted hash + Evidence pointer only; embedded secret ≠ authorization |
| Token format, scopes & JWKS material | Token → `issued_by`, `grants`, `corroborates` | `Bearer eyJ…`; JWKS GET; `tokenInfo` introspection | Only mint/inspect **own** tokens; store hashes, decay fast |
| Embedded protobuf descriptor / message schema | ObjectType → `references_object`, `derived_from` (descriptor sha256); fields → Parameter | `FileDescriptorSet` → `protoc --decode_raw`/pbtk | Emit `.proto` **only from a real descriptor** — never fabricate; absence is a negative finding |
| gRPC service/method detection | Operation → `calls`, `derived_from` | `/package.Service/Method`, `application/grpc` | EOS Web API is REST/JSON — gRPC **not assumed**; absence expected |
| FlatBuffers schema detection | ObjectType → `references_object` | `flatbuffers::` symbols, embedded `.bfbs` | Low prior for EOS; include only if present |
| XMPP / notification endpoint | Service → `exposes` (xmpp/wss) | `*.ol.epicgames.com`, JID domain `prod.ol.epicgames.com` *(exact host/port — verify)* | Scheme established; exact current host from binary |
| Matchmaking WebSocket endpoint | Service → `exposes` (wss), `step_of`, `takes` | `wss://<mm host>` + Bearer + ticket | Pattern confirmed; exact host — verify |
| P2P / RTC relay (STUN/TURN) + Vivox | Service → `exposes` (stun/turn/udp), `hosted_on` third-party | `*.vivox.com`, STUN/TURN `:3478` *(verify)* | Vivox/relays likely **out-of-scope**; `scope_binding=false`, no active probe |
| ObjectType recovery from EOS structs | ObjectType → `references_object`, `takes` | RTTI + version-matched headers; `EOS_Ecom_CatalogOffer{…}` | High when backed by matched header |
| Flow reconstruction (login/connect/service chains) | Flow → `step_of`, `calls`, `evidenced_by` xrefs | `Platform_Create → Auth_Login → Connect_Login(external_auth) → {Sessions/Lobby/Ecom/RTC}` | Static order is a hypothesis — below live-confirmed |
| Anti-cheat component identification (IDENTIFY ONLY) | Artifact → `part_of`, `derived_from` (metadata only) | `EasyAntiCheat_EOS.dll`, `BEClient_x64.dll`, `BEService` presence/hash/version | **HARD STOP**: no reverse/patch/emulate; no dynamic instrumentation of protected process |

### 4f. Manifest / BPS / CDN / catalog (passive-leaning, own account)

| Extraction | Node → edge | Evidence | Confidence notes |
|---|---|---|---|
| Launcher/catalog/account service hosts (shard-scoped) | Host(+Service 443, +WebApp) → `resolves_to`, `hosted_on`, `exposes` | `launcher/catalog/account/entitlement-public-service-prod<NN>.ol.epicgames.com`, `artifact-public-service-prod.beee…on.epicgames.com`, `.ol` vs `.ak` | Shard numbers rotate — **rediscover, snapshot**; don't hardcode |
| `launcherAppClient2` OAuth identity | Credential/ClientId → Token `issued_by`, Operation `authenticates_with` | `34a02cf8…` (secret `daafbccc…`) | client_id = recon intel; authenticate with **own** account only; secret SENSITIVE |
| OAuth2 bearer AuthScheme + access/refresh Token | AuthScheme + Token → `grants`, `issued_by`, `authenticates_with` | `POST /account/api/oauth/token`; `Authorization: bearer {token}` | Token SECRET; redact |
| Launcher assets-list Operation (platform+label) | Operation + Parameter → `takes`, `authenticates_with` | `GET /launcher/api/public/assets/{platform}?label=Live` | Confirmed |
| Manifest-query v2 + 5 build-coordinate params | Operation + Parameter(platform, namespace, catalogItem, app, label) → `takes`, `references_object` | `GET /launcher/api/public/assets/v2/platform/{p}/namespace/{ns}/catalogItem/{id}/app/{app}/label/{label}` | Highest-value param-mining target — maps the buildable surface |
| Artifact-ticket + by-ticket manifest | Operation + Parameter(sandboxId, artifactId) → `takes`, `references_object` | `POST …/artifact/{artifactId}/ticket` → `GET …/by-ticket/app/{artifactId}` | **Entitlement-scoped** — only apps the account owns; keeps it self-scoped |
| Catalog bulk-items (namespace → ObjectType) | Operation + Parameter → `references_object`, `corroborates` | `GET /catalog/api/shared/namespace/{ns}/bulk/items?id=…&includeDLCDetails=true` | Enriches catalogItemId → ObjectType, DLC/main-game linkage |
| Manifest-pointer JSON (`elements[].manifests[]`) | Artifact + Evidence(sha256 of body) → downstream `derived_from` | `{manifests:[{uri, queryParams, distributionPointBaseUrls}]}` | Structure confirmed; snapshot verbatim |
| `distributionPointBaseUrls` → CDN download Hosts | Host(+Service) + DNSName → `derived_from`, `cname_to` third-party | `download[2-4].epicgames.com`, `epicgames-download1.akamaized.net`, `fastly-download…`, `cloudflare.epicgamescdn.com` | Third-party CDN — **active-probe-forbidden**, reference only |
| Signed CDN query params (ephemeral token) | Token(CDN signature) → `grants` (time-boxed) | `…chunk?{name}={value}` short TTL | SECRET; **host durable, signature ephemeral** — never store as stable Evidence |
| BPS binary manifest (magic `0x44BEC00C`) + header | Artifact + Evidence (offsets) → `derived_from` | header: magic, sizes, SHAHash, `StoredAs` (zlib/encrypted), FeatureLevel 15–24+; chunk magic `0xB1FE3AA2` | Format reverse-engineered (no official spec) |
| `FManifestMeta` → app ObjectType + launch/prereq Flow | ObjectType + Flow → `step_of`, `references_object` | `AppName, BuildId, LaunchExe, LaunchCommand, PrereqIds[]…` | LaunchCommand per-build — capture verbatim |
| `FFileManifestList` → per-file Artifact inventory (handoff) | Artifact(file) + Evidence(declared SHA-1) → `derived_from`, `references_object` | `Filename, FileHash, InstallTags[], ChunkParts[(GUID,Offset,Size)]` | **Primary bridge to binary/APK RE**; InstallTags enumerate optional components without download |
| `FChunkDataList` + chunk-URL formula | Host path convention → `hosted_on`, `derived_from` | `{baseUrl}/ChunksV4/{group:02d}/{hash:016X}_{guid}.chunk`; **`group = CRC32(guid) % 100`** | ChunksV5 encrypted — if client lacks key legitimately, **stop** |
| `FCustomFields` key/value | ObjectType attrs (+ Host/env Hypothesis) → `corroborates/contradicts` | build labels, catalog linkage, occasional env/partner/CDN hints | Keys per-build — verify, don't assume |
| namespace/appName/catalogItemId/labelName/BuildId | ObjectType → `references_object`, `corroborates` | `fn, ue, launcher`; labelName encodes channel/platform; BuildId = temporal anchor | Fortnite **mobile** tuple is non-standard — verify_live |
| Environment + region host/label variants | Host variant(env attr)/label → `cname_to`, scope snapshot | `-prod06.ol` vs `.ak`; `catalogv2-public-service-stage…` | Leaked stage host is a Hypothesis until passively confirmed in-scope |
| Manifest history as temporal signal | Artifact + ObjectType temporal → `corroborates/contradicts` | poll tuple; on `buildVersion` change set-diff FileManifestList | Obey rate-budget; observed 429s confirm rate-limiting |

### 4g. Secrets / credentials / sensitivity

| Extraction | Node → edge | Evidence | Confidence notes |
|---|---|---|---|
| Epic Account-Service OAuth game/launcher pair | Credential/ClientId → `derived_from`, `issued_by`, `authenticates_with`, `evidenced_by` | `fortnitePCGameClient=ec684b8c…`, `fortniteIOSGameClient=3446cd72…`, `fortniteAndroidGameClient=3f69e56c…`, `launcherAppClient2=34a02cf8…`; `Basic base64(id:secret)` | **S1 semi-public/embedded**; validate with **exactly ONE** `client_credentials` POST (rate-ledger), **never** account flows/brute/pivot; fork on contradiction |
| EOS credential bundle | Credential/ClientId + ObjectType → `issued_by`, `references_object` | `POST api.epicgames.dev/auth/v1/oauth/token Basic base64(ClientId:ClientSecret)` | S1; Epic docs say game client id/secret may ship locally with "no security risk" (**not** for trusted-server clients) |
| Firebase / GMS config | Credential/ClientId + ObjectType → `derived_from`, `issued_by` | `AIza…`, `1:<projnum>:android:<hex>` | S1; Firebase api_key is **not a secret** per Google; if project third-party-owned → scope OUT, don't probe |
| Third-party SDK keys (analytics/crash/ads/attribution) | Credential/ClientId + AuthScheme → `derived_from`, `issued_by` | Sentry DSN, Adjust token, AppsFlyer, Unity; fallbacks `AKIA…`, `xox[baprs]-`, `eyJ…` | **S2** when write/ingest-capable; scope usually OUT — record existence only, **send no request to vendor** |
| JWT/JWKS references | AuthScheme + ObjectType(Token) → `references_object`, `exposes` | `iss, aud, jwks_uri, kid`, `.well-known/jwks.json` | S0 (JWKS public); any real session token → reclassify S3 |
| Signing certs / pinned certs / embedded public keys | Credential(public) + Artifact → `issued_by`, `corroborates` ownership | `apksigner … SHA-256`, SPKI pin `base64(sha256(SPKI))`, Authenticode `Epic Games Inc` | S0; matching Epic signer across artifacts strongly corroborates ownership |
| Anti-cheat presence/version/keys (RECORD-ONLY) | Artifact (+ public verification key record-only) → `derived_from`, `evidenced_by` | `EasyAntiCheat_x64.dll/.sys`, `BEService.exe/BEDaisy.sys` + hash | **S4 PROHIBITED** for any bypass-usable material; writer rejects such nodes |
| Runtime-minted tokens & device-auth (OWN only) | Token + Credential(device_auth) → `grants`, `authenticates_with`, `derived_from(Flow)` | `device_auth={accountId,deviceId,secret}`; `eyJ…` (~7200s acct / ~14400s client) | **S3 SECRET/PII** — encrypt-at-rest, quarantine, redact to prefix+hash, never reuse; very short decay |
| Build Patch / manifest / catalog auth material | Credential + AuthScheme + ObjectType + Artifact → `references_object`, `authenticates_with` | `launcherAppClient2`; manifests carry chunk SHA hashes + item ids | Integrity data S0/S1; download-authorizing token S3; verify current hosts live |

---

## 5. Dynamic-analysis recon (own device / own account) — what it uniquely adds, and its boundaries

Static analysis yields *capabilities* (strings prove a value exists, not that the endpoint is live, reachable, in-scope, or non-dead-code). Dynamic observation of the researcher's **own authorized session on their own hardware** is the only thing that promotes a capability to a live-confirmed fact, so it carries the strongest corroboration weight in the log-odds model — and is gated the hardest.

**What it uniquely adds (not derivable statically):**
- The **actual grant type and shard** the client chose at runtime (grant selection and prod-shard are config/runtime-driven), captured as the anchor `oauth/token` transaction.
- **EG1 JWT claim structure and lifetimes**, refresh behavior, and the device-auth silent-re-login two-step.
- The **live service topology** from SNI + HTTP Host (which static strings cannot confirm is active), each host scope-checked and snapshotted at capture time.
- The **season-dependent MCP `{command}` set** and per-command parameters (param-mining from real requests, not assumptions).
- Multi-step **Flows** invisible to static analysis: XMPP-over-WebSocket SASL/bind/presence, matchmaking wss handshakes, EOS Connect → ProductUserId.
- **TLS-pinning mechanism** fingerprint (Java OkHttp vs native BoringSSL in EOS SDK) — tells the scheduler which unpinning technique is required per surface and whether MITM observation is even feasible.
- **Live ObjectType shapes** diffed from response bodies, and the startup config surface (lightswitch/hotfix/cloudstorage) that explains why much config is absent from the static artifact.

**Boundaries (hard):**
- **Own account / own device only**; never capture, replay, or act on another player's traffic, tokens, or account; dispatch intents only to the researcher's own app instance and never drive destructive/cross-user/shared-state mutations.
- **Observation, not attack**: no backend fuzzing at volume, no DoS, no mutation of shared state; human-rate, self-driven traffic only; every live action debited on the rate-budget ledger even for passive capture.
- **Anti-cheat HARD STOP**: the EAC/BattlEye-protected Fortnite game process is **never** tampered, memory-patched, repackaged/resigned, frida-gadget-injected, or in-process-hooked during a protected/match session. Prefer **network-layer capture** (mitmproxy / PCAPdroid) which observes the client's own traffic without touching the process. In-process Frida/objection is reserved for pre-match/login/account surfaces and confirmed non-anti-cheat titles. **If the client detects instrumentation and refuses to run or logs out, that is a STOP signal — fall back to network capture, do not escalate evasion.**
- **No integrity/attestation defeat for unauthorized ends**: root/Zygisk hiding and unpinning observe one's own authorized traffic only; never to reach endpoints the researcher isn't authorized to use.
- **Strict host allowlisting at capture time**: retain only in-scope Epic hosts (`*.epicgames.com`, `*.epicgames.dev`, `*.fortnite.com`, `*.fallguys.com`, `*.psyonix.com`, `*.ol.epicgames.com`, `api.epicgames.dev`); drop/redact third-party (analytics/crash SDKs, store infra, CDNs). Store platforms (AltStore PAL, Apple, Samsung, Google Play) are **not Epic assets** — out of scope.
- **Secrets/PII** (`access_token`, `refresh_token`, device_auth `secret`, decoded `client_secret`, exchange codes, email/displayName/payment) are SENSITIVE: labeled hashes/redactions only, never plaintext, never exfiltrated, never used against any other account.
- `dynamic_allowed = NOT(anti_cheat_locked OR integrity_locked OR connected-to-shared-service)`, default **DENY**; a runtime Evidence handle on a `dynamic_allowed=false` node is a safety-invariant breach rejected at ingest.

---

## 6. Secrets & sensitivity handling for a long-lived store

**Sensitivity taxonomy** (the label, not convenience, decides handling), bound to each `Credential/ClientId`, `AuthScheme`, `Token`, and other-user `ObjectType` node:

| Label | Meaning | Examples | Handling |
|---|---|---|---|
| **S0 PUBLIC** | Intended-public material | JWKS verification keys, signing certs, TLS SPKI pins | Retain; benign read-only fetch (still logged) |
| **S1 SEMI-PUBLIC / EMBEDDED** | Ships in clients by design | Epic game-client OAuth pairs, EOS client secret, Firebase api_key, EOS Product/Sandbox/Deployment ids | Record for mapping; **never used to reach non-own data**; one scoped issuer check max |
| **S2 SENSITIVE** | Write/ingest-capable third-party | Sentry DSN, Adjust/AppsFlyer keys, AWS/Slack-shaped hits | Encrypt-at-rest; **send no request to the vendor** (scope usually OUT) |
| **S3 SECRET / PII** | Live session credentials, personal data | access/refresh tokens, device_auth secret, exchange codes, email/displayName | Quarantine, encrypt-at-rest, redact to prefix+sha256 in every export, short decay, report-don't-use |
| **S4 PROHIBITED** | Anti-cheat bypass-usable / integrity keys | EAC/BattlEye signing/integrity material | Writer **rejects** the node outright |

**Store rules:**
- Evidence is **content-addressed and encrypted-at-rest** (per-sensitivity-class key via `age`/`sops`/`git-crypt`); the graph stores **hashes + offsets + derived facts**, never the copyrighted artifact or raw secret.
- **Never echo a secret into plaintext provenance.** Anchor every Evidence handle to raw file bytes + offset, not reconstructed/decompiled source.
- A **pre-commit secret-scan hook** (gitleaks/detect-secrets) is itself a safety invariant; committing an evidence blob containing a live S3 token is an incident.
- Run third-party-key scanners with **verification DISABLED** (verification = a live request = out of scope).
- **Entropy alone is a false-positive generator**: UUIDs, asset content hashes, build ids, and base64 texture blobs look high-entropy — require entropy **+** known format **+** context before minting a Credential node.
- **Firebase api_key / EOS ids / embedded public-client secrets are public identifiers, not vulnerabilities** — label correctly, don't over-rate, and never operationalize. A genuine out-of-band secret or PII leak is the only report-worthy class; honeytokens exist — **report-not-use**.
- **No redistribution**: IPA/ADP/decrypted binaries/extracted assets and any AES/title key are never published or shared — independent of bounty scope.
- Decompiler output is heuristic; pin tool versions so offsets are reproducible, and fork (never overwrite) when a value contradicts a prior one (rotation is expected — maintain temporal versioning).

---

## 7. Anti-RE feasibility + HARD STOP lines

Each Artifact carries a derived **`re_feasibility`** meta-attribute that both raises gap-queue cost and multiplies **down** the confidence of every fact leaving it:

| Bucket | Meaning | Consequence |
|---|---|---|
| `OPEN` | decompiles cleanly | full extraction expected |
| `PARTIAL` | R8/ProGuard rename, some string encryption | `multiplier≈0.6`, static-only |
| `HARDENED` | heavy native obfuscation (OLLVM cff/opaque predicates/string-enc), stripped | down-weight; mark coverage partial |
| `VM_PROTECTED` | custom-VM bytecode (VMProtect/Themida/Denuvo-class) | **fingerprint-only, `drm_boundary=FINGERPRINT_ONLY_NO_UNWRAP`** |
| `INTEGRITY_LOCKED` | attestation-gated flows | map as boundary, do not defeat |
| `ANTI_CHEAT_LOCKED` | EAC/BattlEye coupled | **dynamic forbidden; inventory only** |

A versioned PROV **obfuscation confidence-penalty rule** (`{protection_class} → logodds_delta`) weights every `derived_from` edge; contradictions **fork** so a later live-verified fact can out-weigh a low-fidelity RE-derived one.

**Protection-independent recon floor** (HIGH confidence even when `re_feasibility` is low, because it lives outside protected code): AndroidManifest (permissions, exported components, deep links, networkSecurityConfig, declared client ids), APK v2/v3 signing cert, native-lib list + NEEDED imports, embedded cleartext assets, iOS Info.plist/entitlements/`embedded.mobileprovision`, PE VERSIONINFO/Authenticode, EOS SDK `.aar` structure. This is the reliable surface that keeps the facet productive against hardened builds — kept distinct in PROV from code-derived (penalized) facts.

**HARD STOP lines (machine-enforced; any flagged action is refused regardless of other gate state):**
- **Anti-cheat (Easy Anti-Cheat — Epic-owned; BattlEye):** never defeat, bypass, disable, patch, hook, unload, emulate, reverse-for-bypass, or load/probe/tamper with kernel drivers (`EasyAntiCheat.sys`, `BEDaisy.sys`). EAC loads a kernel driver while the protected game runs; interfering corrupts shared match integrity and affects **other players**. Fortnite ships a **dual** posture (EAC + BattlEye) *(mobile differs — verify; iOS likely no kernel AC)*. **Permitted: file-level inventory only** (name/version/hash/signer). The EOS `AntiCheat*` API **symbols** may be listed; the protection **binaries** must not be reversed.
- **Integrity / attestation:** never forge, patch, hook, or bypass Play Integrity, hardware KeyMint attestation, iOS App Attest/DeviceCheck, or EOS anti-cheat client attestation to obtain tokens or reach shared services — that attacks the service and other users' trust boundary, not the client. **SafetyNet is defunct (turned down 2025-01-31) — do not build on legacy references.** `MEETS_STRONG_INTEGRITY` requires KeyMint + Verified Boot + locked bootloader.
- **No dynamic analysis of protected/live processes:** no Frida/debugger/hooking/emulator against Fortnite (or any AC/integrity-protected title) while connected to live services/matchmaking; no kernel-driver loading, no BYOVD, no bootloader-unlock/root/jailbreak on any device later used to reach shared Epic services; device-integrity-defeat tooling (Magisk/Zygisk "fixes") is RASP-bypass, not recon.
- **Anti-circumvention (DMCA §1201):** fingerprinting a VM-protector is permitted; **unwrapping/devirtualizing/decrypting** it is not, absent explicit program + legal authorization. Encrypted manifests / ChunksV5 / FairPlay / UE pak AES: if the client doesn't legitimately hold the key, **stop** — do not break it.
- **No trafficking / no modification-and-run:** never build/keep/distribute a circumvention tool, key, crack, patched/resigned client, or redistributable extracted asset; never repack-resign-and-run an Epic client.

---

## 8. RE coverage model, gap-queue integration, and cross-version diffing as a temporal signal

**Coverage ladder** (per entity/artifact, each signal carrying `last_verified` + a per-class decay half-life):

`acquired → integrity_verified → unpacked → {strings_mined / manifest_parsed} → {native_symbols_recovered / proto_recovered} → param_mined → xref_mapped → flow_mapped → dynamic_captured → cross_version_diffed → artifact_correlated`

Concretely, per facet: *artifact-acquired, identity-pinned, manifest-parsed, dex-mined, resources-extracted, native-inventoried, secret-triaged, flow-reconstructed, cross-version-diffed, artifact-correlated* (Android); analogous ladders for iOS (`ipa_obtained → macho_fingerprinted → plist_parsed → entitlements_dumped → frameworks_inventoried → strings_mined → objc_swift_metadata_extracted → secrets_scanned → aasa_fetched → marketplace_surface_mapped → cross_corroborated`), desktop, EOS-native (`artifact_located → fingerprinted → enumerated(interface census %) → param_mined → flow_mapped → artifact_correlated`), and manifest/CDN. Anti-cheat artifacts are **hard-capped at `acquired/inventoried`** and never emit unpack/dynamic/diff coverage — a signal beyond that is a safety-invariant violation.

**Gap-queue** priority `= value × staleness × confidence_deficit / cost`. Representative items the autonomous loop schedules:
- New `versionCode`/BuildId observed (own device or passively via launcher manifest) → acquire all splits+OBB, hash, re-pin, diff.
- A `lib/<abi>/*.so` not yet a child Artifact or handed to the native facet → create `derived_from` child + enqueue handoff.
- 32-hex client_id with no Credential node → create node + `authenticates_with` edge; confidence from corroboration count.
- networkSecurityConfig pin host / host-template placeholder (`prod<NN>`) with no Domain → enqueue (scope-gated) resolution.
- `autoVerify=true` deeplink → single passive `assetlinks.json` GET.
- EOS interface present in census but no Route/Operation mapped → route reconstruction (Ecom/Auth/Connect high value).
- Embedded descriptor/`.bfbs` detected but not decoded → protobuf/flatbuffers reconstruction.
- Feature-flag with only a shipped default → (live-web) hotfix/cloudcontent check.
- Artifact `last_verified` past its decay half-life → re-acquire to refresh staleness.
- Signer mismatch or missing scope-binding → **quarantine + safety-invariant alert**, never ingest.
- Same client_id/endpoint seen on only one platform → cross-platform corroboration pull (raise or fork).
- Candidate Epic targets (EGS mobile `com.epicgames.portal`, Sideswipe, Fall Guys mobile, ArtStation) → verify in-scope, then run the full acquire→mine ladder.

**Cross-version binary diffing (primary temporal engine):** diff build N→N+1 of the same product — native via BinExport+BinDiff/Diaphora, Java via jadx semantic diff, protobuf via descriptor diff. Emit typed deltas (added/removed/changed Operation, Route, Parameter, AuthScheme, ObjectType, host strings). Each **new** entity gets `first_seen=build(N+1)` (a high-value, low-staleness gap seed); each **disappeared** entity gets `last_seen=build(N)` and begins decay; each **changed** entity **forks** into a versioned pair with a `corroborates/contradicts` edge. **Anchor on stable identifiers** — proto field numbers, export symbol names, manifest xpaths — and **rebase VAs to image base before hashing**; raw byte offsets/VAs shift every build and manufacture phantom deltas. Account for obfuscation (R8 renaming, string encryption, OLLVM) before concluding a capability was added/removed. The interpretation of *why* something changed is a Hypothesis (medium), kept separate from the structural delta (high).

---

## 9. Pinned tooling matrix + reproducibility contract

**Reproducibility contract:** every RE fact is a deterministic function of `(tool@pinned_version + exact argv/options + input artifact_sha256)` whose **normalized output hash** is recorded in the PROV DAG (`Evidence → tool@version → rule → fact`). Re-running the pinned invocation on the same artifact hash must reproduce the normalized hash; variable fields (timestamps, temp paths, VAs) are normalized out before hashing. Tools run in **digest-pinned containers**; the **regex/heuristic RULESET is itself the `rule` node**, versioned independently of the tool. A non-reproducible extraction is quarantined as a Hypothesis until the nondeterminism source is pinned. Run interpreters `-I` against untrusted extracted files, each archive in its own empty directory.

| Facet | Tool | Purpose | Pinning note |
|---|---|---|---|
| Android acquire | **adb (platform-tools)** | Pull installed splits + OBB/PAD from own device; dispatch own-instance intents | Record device model + Android build fingerprint (split/PAD layout varies by OS) |
| Android identity | **apksigner + keytool** | Verify v1/v2/v3/v3.1/v4 + extract signer SHA-256 (anti-tamper gate) | Pin build-tools; newer apksigner reports v3.1/v4 |
| Android identity | **aapt2 / apkanalyzer** | Package identity, SDK levels, permissions, components, resolve NSC/meta-data | Pin build-tools; table format tracks AGP |
| Android identity | **bundletool** | AAB split-set reasoning, device-specific install set | Pin; split naming evolves |
| Android static | **apktool** | Decode manifest/resources → readable XML + smali | Pin apktool + bundled AOSP framework (decoding regresses) |
| Android static | **jadx (cli)** | DEX→Java for endpoint/client_id/flag/auth mining | Pin; deobfuscation heuristics affect locators |
| Android static | **dexlib2 / baksmali / dexdump** | Precise method/offset locators; string pools | Pin to DEX format version |
| Android static | **androguard** | Programmatic manifest/DEX for the autonomous loop | Pin (API/parsing change across majors) |
| Android static | **apkid** | Fingerprint packers/obfuscators/anti-cheat protectors | Pin signature-DB version |
| Cross | **ripgrep + curated regex set** | URLs, host templates, 32-hex ids, JWT/EG1, Firebase/Google, secret patterns | **Version the ruleset as the PROV `rule`** |
| Android dyn | **mitmproxy / Burp / HTTP Toolkit** | Own-device TLS capture, in-scope-host allowlist + secret redaction | Pin; install proxy CA on own device; never MITM others |
| Android dyn | **Frida + frida-server / objection** | Unpinning + tracing on **non-AC** surfaces only | frida-server MUST match host CLI exactly; **no auto-patch/gadget-repack on Fortnite** |
| Android dyn | **PCAPdroid / tcpdump / Wireshark** | Pure network-layer capture — **safe path for AC-protected Fortnite** | Preferred when any AC/integrity risk exists |
| Android dyn | **AVD / physical rooted device (Magisk/Zygisk)** | Realistic arm64 runtime (Fortnite is arm64-only, GPU-demanding) | Record image/device + OS; root hiding for capture on non-AC surfaces only |
| iOS | **unzip / Payload extraction** | Unpack `.ipa`/ADP (untrusted, isolated dir) | Log tool |
| iOS | **otool / llvm-otool / jtool2 / LIEF** | Load commands, linkage, `cryptid`, entitlements, arch | Pin LIEF/LLVM (parse output drifts) |
| iOS | **strings / rabin2 / floss** | `__cstring`/objc tables + decoded strings with offsets | Pin radare2 + floss (heuristics drift) |
| iOS | **plutil / plistlib** | Info.plist + embedded config (run `python -I`) | Pin stdlib run |
| iOS | **codesign / entitlements/provision dump** | Entitlements, marketplace keys, team id | Pin CMS parser on non-macOS |
| iOS | **class-dump / class-dump-swift / dsdump** | ObjC/Swift metadata → Operation/ObjectType | Pin + record Swift runtime version |
| Desktop/native | **Ghidra (analyzeHeadless) + BinExport** | Disassembly/decompile, xref, RTTI/ObjectType, diff export | **Pin version + full analyzer options + decompiler version**; rebase to image base before hashing |
| Desktop/native | **rizin / radare2 + Cutter** | Scriptable triage, string/xref, symbol tables | Pin; fixed analysis flags via rz-pipe |
| Desktop/native | **LLVM objdump / nm / readelf / pev / dumpbin** | Deterministic import/export/symbol/load-command dumps; EOS interface census | Pin LLVM/binutils (deterministic baseline) |
| Desktop/native | **capa + FLIRT/sigdb + Detect-It-Easy (DIE)** | Capability + packer/compiler/statically-linked-lib detection | **Pin signature-DB date** (part of provenance) |
| Desktop/native | **FLOSS** | Stacked/obfuscated string recovery | Pin (emulation changes which secrets surface; absence ≠ proof) |
| Desktop/native | **blint / checksec** | Standardized hardening profile (NX/PIE/RELRO/canary/CFG) | Pin (checks evolve with OS mitigations) |
| Cross | **diffoscope / BinDiff / Diaphora** | Cross-build deltas → temporal fields + gap triggers | Pin; record both input hashes + similarity thresholds; anchor on stable ids |
| Proto | **protoc (`--decode_raw`) / protobuf-inspector / pbtk** | Decode FileDescriptorSet → ObjectType/Operation/Parameter | Pin protoc; record descriptor sha256; prefer real descriptor over heuristic |
| Proto | **flatc** | Reconstruct `.fbs` from embedded `.bfbs` (only if present) | Pin |
| UE assets | **CUE4Parse / FModel / UnrealPak** | Read-only extraction of UE `.ini/.json` from pak/utoc/ucas | Pin + UE-version mapping; encrypted paks need title AES key (**don't publish**) |
| Manifest | **legendary** | Own-account auth + manifest-pointer/metadata pull (metadata-only modes) | Pin; verify egs.py shards live; `--disable-sdl`/metadata-only (no content download) |
| Manifest | **meszmate/manifest, er-azh/egmanifest, FabianFG/FortniteDownloader, egs-api-rs/UEVaultManager, EpicManifestParser** | Parse BPS binary manifest (meta/CDL/FML/customfields) + catalog | Pin commit; handle feature-level 15–24+ incl. ChunksV5; re-validate after upgrade |
| EOS oracle | **Official EOS SDK + headers (dev.epicgames.com)** | Ground-truth `eos_*.h` for the recovered version — authoritative signatures/structs/enums | **Pin to the exact recovered SDK version** (a mismatched header silently corrupts enum values) |
| Secrets | **trufflehog / gitleaks / detect-secrets / Nosey Parker + semgrep** | Entropy + format + context secret scan (verification DISABLED) | Pin ruleset hash; "no finding" is version-relative |
| Store | **age / sops / git-crypt + pre-commit secret-scan hook** | Encrypt-at-rest Evidence; block plaintext secrets into git | Pin; rotate per-class key; the hook is a safety invariant |
| Cross | **sha256sum / b3sum** | Content-addressed Evidence handles | SHA-256 canonical; algorithm change = explicit migration |

---

### Preserved uncertainties (verify against live policy / build)

Current `hackerone.com/epicgames` scope text and whether these client binaries/packages and `*.ol.epicgames.com` / `api.epicgames.dev` are explicitly in-scope, the accepted finding-classes, and whether anti-cheat is explicitly out-of-scope; the exact shipped client_id/secret values (all candidate hex is community-sourced and may be rotated — re-derive from the pinned artifact); exact OAuth token paths/grants/token formats and current prod-shard numbering; current host templates and regional/relay patterns; live EOS Product/Sandbox/Deployment ids, SDK version per client, external-credential-type enum members, and whether EOS is standalone vs statically linked per build; whether current builds ship Firebase and which project; networkSecurityConfig cleartext/pin-set specifics; the genuine Epic signer SHA-256 to pin; Fortnite **mobile** manifest coordinates and whether distribution uses launcher-assets v2 or a Fortnite-specific path; ChunksV5 encryption details; current Windows Authenticode subject and macOS Team ID; EU/UK iOS alt-distribution channels and IPA obtainability; current anti-cheat footprint on Android/iOS specifically; §1201 regulatory exemption status before its 2027-10-28 expiry; and exact EULA RE-prohibition clause numbers. Specific client_ids / EOS internals / endpoints are populated by their owning facets — do not fabricate.