"""ACTIVE identity-metadata discovery — the L4 auth rung (``SPEC.md`` §6.2.5).

The HTTP rung says a vhost is alive; the TLS rung says who issued its certificate. Neither
says **how the application authenticates anyone**, and that is where the interesting surface
lives: the issuer, the authorize/token endpoints, the grant and response types on offer, the
scope vocabulary, and the signing keys. An OpenID-Connect issuer publishes all of it, for
free and unauthenticated, at a well-known path (OIDC Discovery 1.0; RFC 8414 for a plain
OAuth 2.0 authorization server) — so this module reads **metadata only** and reconstructs
Epic's live auth model from the issuer's own statements (``domains/non-binary.md`` §3.5).

Reading it is still traffic to an Epic host, so **every single request goes through the one
chokepoint** — :meth:`ModuleContext.gate_active` — *before* it is sent
(``docs/pipeline.md`` §1). A :class:`~recon.modules.base.GateRefused` is a **skip**: logged,
counted, and the target is left alone. There is no path that requests anyway, no retry, and
no second attempt at a path that already answered.

**What it does, per ``WebApp`` seed.** One gated ``GET`` of
``/.well-known/openid-configuration``. **Only** if that answers ``404`` — the server
positively denied the OIDC document — a second, separately gated ``GET`` of
``/.well-known/oauth-authorization-server`` (RFC 8414). Any other status ends the target:
a ``403``/``429``/challenge is backed off from, not worked around (``safety-model.md`` §4),
and a redirect is not followed because each hop is its own scope decision. Then, only if the
document names a ``jwks_uri`` **whose own host is in scope**, one more separately gated
``GET`` of that URI. At most three requests per seed, each with its own ALLOW record and its
own debit of the unified per-target ledger, keyed by the host actually touched.

**What it never does.** It never requests a token. ``requests.get`` is the only sender this
module can reach, so a ``POST`` to a token endpoint is not merely declined but structurally
unreachable; the ``Operation`` minted for ``token_endpoint`` is a *contract fact read out of
the metadata*, not a probe. No credential, cookie, ``Authorization`` or ``Origin`` header is
ever sent. ``tokenInfo``/``userInfo``/``verify`` need a bearer and are therefore default-deny
(``safety-model.md`` §5) — introspection is an explicitly authorized, own-token-only
activity and is not part of this rung. No grant/scope/``response_type`` combination is ever
submitted to see what the server accepts: that is ``fuzz-at-volume`` and is blocked.

**What it emits.**

* One ``AuthScheme`` (``auth:<authority>:oidc``) carrying ``issuer``,
  ``authorization_endpoint``, ``token_endpoint``, ``jwks_uri``, ``grant_types_supported``,
  ``scopes_supported`` and ``response_types_supported``, joined to the seed by the declared
  ``authenticates_with`` edge. Coverage is ``{"fingerprinted": True}`` — the live document is
  content-hashed, not assumed — plus ``{"flow_mapped": True}`` **only when** the document
  actually declares its grant/response-type vocabulary, since that set is what names the
  flows the issuer admits to. A document that declares neither claims ``fingerprinted``
  alone: the ``step_of`` chains themselves need own-account observation, and coverage states
  what was achieved, never what was hoped for (``SPEC.md`` §4.2).
* One ``Operation`` per endpoint the document names — ``op:POST:<route>`` for the token
  endpoint, ``op:GET:<route>`` for the authorize endpoint — with an ``exposes`` edge from the
  ``WebApp`` that actually serves it. Epic's authorize endpoint routinely lives on a
  *different* host from the discovery document (``domains/non-binary.md`` §3.5), so each
  endpoint is keyed under **its own** authority and **earns its own scope verdict** via
  :meth:`ModuleContext.bind`; an endpoint on a host the policy does not list is counted as
  negative space and gets no node and no edge, while its URL stays recorded on the in-scope
  ``AuthScheme`` as data *about* an in-scope asset. These two nodes are declared-but-untouched,
  so they sit at :data:`DECLARED_ENDPOINT_LOG_ODDS` — below the documents we read first-hand —
  with coverage ``{"enumerated": True}``: existence is stated, no parameter was mined.
* One ``Token`` (``tok:<sha16 of the kid set>``) per JWKS actually fetched, with an
  ``issued_by`` edge to the ``AuthScheme``. The id is derived from the key ids, so a key
  rotation mints a **new** node rather than forking the old one — which is exactly the
  rotation series §3.5 asks for. A JWKS holds public verification keys (``S0`` material by
  the §5 taxonomy), but the ``Token`` *node type* is labeled ``S1`` regardless, because
  invariant I8 rejects an ``S0`` ``Credential``/``Token`` and the label, not convenience,
  decides handling.

**Hygiene.** Minimized **before** storage, never cleaned up after (``safety-model.md`` §6):

* only the recognized metadata fields reach ``attrs``; a document that volunteers a
  ``client_secret``-shaped field has it dropped at parse time rather than stored and
  explained;
* a URL value carrying userinfo is **dropped**, not cleaned — ``https://user:pw@host/token``
  is a credential, and a credential may never become an attribute — and the fragment of any
  URL is discarded, since a fragment is where an implicit-flow ``#access_token=`` would sit;
* a JWK that carries a private member (``d``/``p``/``q``/``k``/…) is a leaked signing key,
  not an attribute: the member is replaced by its :func:`recon.evidence.redact` form as the
  document is parsed, so it reaches neither ``attrs`` nor the evidence blob, while the count
  is recorded so the omission stays explicit. Only ``kid`` and ``alg`` are lifted into
  ``attrs``; no key material is;
* nothing here collects data about another person — there is no ``userInfo`` call and no
  persona lookup — so every node is ``data_subject="none"``.

Documents are content-addressed with ``sort_keys``, so re-reading an unchanged document
merges onto the same evidence sha instead of writing a new blob (``SPEC.md`` §3.1/§4.1).
First-hand documents land at :data:`METADATA_LOG_ODDS` (~p=0.88), deliberately below
``models._CORROBORATED_AT``: one source never promotes itself. Transport, status and parse
failures are classified, counted and logged; a dead issuer never crashes the run.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

import requests

from ... import verbs
from ...evidence import redact
from ...factory import make_edge, make_node
from ...models import EvidenceRef, ScopeBinding, Sensitivity, Verdict
from ...urls import (
    authority as make_authority, canonical_host, canonical_url,
    operation_id, route_id as make_route_id, webapp_id_from_url,
)
from ...scope import classify
from ..base import GateRefused, Module, ModuleContext, register

#: The whitelisted **active** verb this module spends (``verbs.ALLOWED`` ∩ ``verbs.ACTIVE``),
#: and the verb ``planner.RULES`` names for the ``auth-model`` gap. One debit per request.
VERB = "http-GET"

SOURCE = "oidc_discovery"

#: Ruleset version. Same document + same version ⇒ same facts (``SPEC.md`` §3.2).
RULE_ID = "oidc-metadata"
RULE_VERSION = "0.1.0"

#: Discovery paths, tried in this order and never more than one each.
OIDC_PATH = "/.well-known/openid-configuration"
OAUTH_AS_PATH = "/.well-known/oauth-authorization-server"
DISCOVERY_PATHS: tuple[str, ...] = (OIDC_PATH, OAUTH_AS_PATH)

#: The only statuses that justify spending a request on the next discovery path: the server
#: positively denied the document, so another standard's path may still hold one. A
#: ``403``/``429``/``503`` means "back off", not "try the other door".
FALLBACK_STATUSES = frozenset({404})

#: ``auth:<id>`` convention for this rung: the authority plus the discovery family.
AUTH_ID_SUFFIX = ":oidc"

#: A document read first-hand from the issuer is strong evidence (~p=0.88) and deliberately
#: below ``models._CORROBORATED_AT`` (2.2): one source never promotes itself.
METADATA_LOG_ODDS = 2.0

#: An endpoint the metadata *declares* but that nothing here touched: an authoritative
#: statement rather than an observation, so it sits a notch lower (~p=0.82).
DECLARED_ENDPOINT_LOG_ODDS = 1.5

#: Node types accepted as seeds; anything else is ignored.
SEED_NODE_TYPES = frozenset({"WebApp"})

WEBAPP_ID_PREFIX = "web:"
ROUTE_ID_PREFIX = "route:"

#: A bare-host seed is assumed to serve discovery over TLS; an issuer identifier is an
#: ``https`` URL by specification, and guessing ``http`` would spend budget on a fact that
#: would be wrong even if it answered.
DEFAULT_SCHEME = "https"

_FOREIGN_ID_PREFIXES = (
    "org:", "bu:", "domain:", "dns:", "net:", "asn:", "host:", "svc:", "route:", "op:",
    "param:", "auth:", "cred:", "tok:", "obj:", "flow:", "art:", "ev:", "hyp:",
)

#: Metadata key -> (HTTP method the standard assigns, role label). The method is recorded as
#: a contract fact; **nothing here ever sends it** — ``requests.get`` is the only sender.
ENDPOINT_OPERATIONS: tuple[tuple[str, str, str], ...] = (
    ("token_endpoint", "POST", "token"),
    ("authorization_endpoint", "GET", "authorize"),
)

#: URL-valued metadata kept verbatim (canonicalized + capped). Anything not listed here —
#: including any ``client_secret``/``*_token``-shaped field a misconfigured document
#: volunteers — never reaches an attribute at all.
URL_FIELDS: tuple[str, ...] = (
    "issuer", "authorization_endpoint", "token_endpoint", "jwks_uri",
)

#: List-valued metadata kept as a sorted, deduplicated list of short tokens. Sorting makes
#: the attribute independent of the order the server happened to serialize.
LIST_FIELDS: tuple[str, ...] = (
    "grant_types_supported", "scopes_supported", "response_types_supported",
)

#: Declaring either of these is what lets this rung claim ``flow_mapped``: together they
#: name every flow the issuer admits to supporting.
FLOW_FIELDS: tuple[str, ...] = ("grant_types_supported", "response_types_supported")

#: JWK members that are private key material. Replaced by their redacted form as the
#: document is parsed — before it can reach an attribute or the evidence store (§5/§6).
PRIVATE_JWK_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "k", "oth"})

#: Conservative fqdn shape (same spirit as the CT/TLS/HTTP rungs): no whitespace, no
#: wildcards, no raw unicode (punycode ``xn--`` labels pass), so a malformed metadata URL
#: can never mint a junk node id or be interpolated into a request.
_FQDN_RE = re.compile(
    r"^[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?)+$"
)

#: Printable, space-free ASCII. A URL outside it is a mangled document, not an endpoint.
_SAFE_URL_RE = re.compile(r"^[\x21-\x7e]+$")

# --- defensive caps (a seed list comes from the graph; a document comes from the network) ---
MAX_SEED_NODES = 25
MAX_RESPONSE_CHARS = 256 * 1024
MAX_DOCUMENT_JSON_CHARS = 64 * 1024
MAX_LIST_ITEMS = 64
MAX_JWKS_KEYS = 64
MAX_URL_CHARS = 512
MAX_PATH_CHARS = 256
MAX_TOKEN_CHARS = 128
MAX_ALG_CHARS = 32


def _bump(counter: dict, key: str) -> None:
    """Increment ``counter[key]``, so a summary histogram stays a one-liner at the callsite."""

    counter[key] = counter.get(key, 0) + 1



def valid_target(host: str) -> bool:
    """Is ``host`` a plausible, canonical target we would request or mint an id for?"""

    if not host or len(host) > 253:
        return False
    if classify(host) == "ip":
        return True  # an IP literal is a legitimate (if unusual) issuer authority
    if not _FQDN_RE.match(host):
        return False
    return all(len(label) <= 63 for label in host.split("."))


def safe_url(value) -> str:
    """Canonicalize a document's URL value for storage, or return ``""``.

    A URL carrying userinfo is **dropped rather than cleaned**: ``https://u:p@host/token``
    embeds a credential, and a credential may never become an attribute
    (``safety-model.md`` §5). The fragment is discarded by construction — only the scheme,
    authority, path and query are read — because a fragment is where an implicit-flow
    ``#access_token=`` would sit. The host is folded to its canonical lowercase form so the
    same endpoint produces the same node id on every run (``SPEC.md`` §3.1); the path and
    query are left as the issuer wrote them, since they are its own statement.
    """

    text = str(value or "").strip()
    if not text or len(text) > MAX_URL_CHARS or not _SAFE_URL_RE.match(text):
        return ""
    try:
        parts = urlsplit(text)
        if parts.scheme.lower() not in ("http", "https"):
            return ""
        if parts.username or parts.password:
            return ""
        host = canonical_host(parts.hostname or "")
        port = parts.port
    except ValueError:
        return ""  # a mangled IPv6 literal or a non-numeric port
    if not valid_target(host):
        return ""
    suffix = f":{port}" if port else ""
    query = f"?{parts.query}" if parts.query else ""
    return f"{parts.scheme.lower()}://{make_authority(host)}{suffix}{parts.path}{query}"


@dataclass(frozen=True)
class _Endpoint:
    """A canonicalized URL, split into the pieces the id conventions need."""

    url: str        # canonical, fetchable
    scheme: str
    authority: str  # host (bracketed if IPv6) plus any explicit port
    host: str       # bare host: what the scope binding and the rate ledger are keyed on
    path: str       # the route template; always starts with "/"


def parse_endpoint(value) -> _Endpoint | None:
    """Split a document's URL value into an :class:`_Endpoint`, or ``None`` if unusable."""

    url = safe_url(value)
    if not url:
        return None
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:  # pragma: no cover - safe_url already parsed this once
        return None
    host = canonical_host(parts.hostname or "")
    suffix = f":{port}" if port else ""
    return _Endpoint(
        url=url,
        scheme=parts.scheme.lower(),
        authority=f"{make_authority(host)}{suffix}",
        host=host,
        path=(parts.path or "/")[:MAX_PATH_CHARS] or "/",
    )


def parse_json_object(raw: str) -> tuple[dict, str]:
    """Parse ``raw`` as a JSON object. Returns ``(data, error)`` and never raises."""

    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return {}, "not_valid_json"
    if not isinstance(data, dict):
        return {}, "json_was_not_an_object"
    return data, ""


def short_tokens(value, limit: int = MAX_LIST_ITEMS) -> list[str]:
    """A metadata array as a sorted, deduplicated list of short printable tokens.

    Non-list values and non-scalar entries are dropped rather than coerced: a document that
    puts an object where the standard wants a string array is reporting something this rung
    does not model, and guessing would invent a fact.
    """

    if not isinstance(value, (list, tuple)):
        return []
    out: list[str] = []
    for entry in value:
        if isinstance(entry, (dict, list, tuple, bytes)) or entry is None:
            continue
        token = str(entry).strip()[:MAX_TOKEN_CHARS]
        if token and token not in out:
            out.append(token)
    return sorted(out)[:limit]


def metadata_attrs(data: dict) -> dict:
    """The recognized discovery fields, empty values omitted.

    An allowlist, not a filter: a field this rung does not model — including anything
    secret-shaped a misconfigured document volunteers — is simply never read, so it cannot
    reach an attribute. Empty values are omitted so a field the issuer stopped publishing
    does not fork the node on re-observation.
    """

    attrs: dict = {}
    for field in URL_FIELDS:
        url = safe_url((data or {}).get(field))
        if url:
            attrs[field] = url
    for field in LIST_FIELDS:
        tokens = short_tokens((data or {}).get(field))
        if tokens:
            attrs[field] = tokens
    return attrs


def canonical_json(data, limit: int = MAX_DOCUMENT_JSON_CHARS) -> str:
    """Deterministic JSON for an (already sanitized) document, capped.

    ``sort_keys`` makes an unchanged document content-address to the same sha on every
    re-read, so re-observing it merges instead of writing a new blob. ``default=str`` keeps
    an exotic value from failing the capture, and ``ensure_ascii=False`` keeps the blob
    readable UTF-8 so a human auditing the proof sees the same text the server sent —
    including a :func:`recon.evidence.redact` marker where a key member was removed.
    """

    try:
        text = json.dumps(data, sort_keys=True, default=str, ensure_ascii=False)
    except (TypeError, ValueError):
        text = repr(data)
    return text[:limit]


@dataclass(frozen=True)
class _Jwks:
    """A JWKS reduced to what may be retained: the public document, kids and algs."""

    document: dict
    kids: tuple[str, ...] = ()
    algs: tuple[str, ...] = ()
    private_members_redacted: int = 0


def sanitized_jwks(data: dict) -> _Jwks:
    """Strip private key material from a JWKS and lift out its ``kid``/``alg`` sets.

    A JWKS is supposed to hold public verification keys only; a private member in one is a
    leaked signing key. It is redacted to its non-reversible ``prefix…+sha`` form **here**,
    at the single parse point, so it can reach neither an attribute nor the evidence blob,
    while the key's presence stays visible to a human reading the proof. Keys are sorted by
    ``kid`` so the stored document is independent of the order the server served them.
    """

    entries = (data or {}).get("keys")
    entries = entries if isinstance(entries, (list, tuple)) else ()
    safe_keys: list[dict] = []
    kids: list[str] = []
    algs: list[str] = []
    redacted = 0
    for entry in list(entries)[:MAX_JWKS_KEYS]:
        if not isinstance(entry, dict):
            continue
        safe: dict = {}
        for name, value in entry.items():
            key = str(name)
            if key in PRIVATE_JWK_MEMBERS:
                redacted += 1
                safe[key] = redact(str(value))
                continue
            safe[key] = value
        safe_keys.append(safe)
        kid = str(entry.get("kid") or "").strip()[:MAX_TOKEN_CHARS]
        if kid and kid not in kids:
            kids.append(kid)
        alg = str(entry.get("alg") or "").strip()[:MAX_ALG_CHARS]
        if alg and alg not in algs:
            algs.append(alg)
    document = {k: v for k, v in (data or {}).items() if k != "keys"}
    document["keys"] = sorted(safe_keys, key=lambda k: str(k.get("kid", "")))
    return _Jwks(
        document=document,
        kids=tuple(sorted(kids)),
        algs=tuple(sorted(algs)),
        private_members_redacted=redacted,
    )


def kid_set_digest(kids) -> str:
    """Stable 16-hex identity for a key set, so a rotation mints a new node, not a fork."""

    canonical = "\n".join(sorted(str(k) for k in kids))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class _Target:
    """One deduplicated WebApp seed, in the exact form the ids and the URL need."""

    webapp_id: str
    scheme: str
    authority: str
    host: str

    @property
    def base(self) -> str:
        return f"{self.scheme}://{self.authority}"


@dataclass(frozen=True)
class _Fetch:
    """One gated request that actually happened, and what came back."""

    binding: ScopeBinding
    status: int = 0
    raw: str = ""
    error: str = ""


@dataclass(frozen=True)
class _Document:
    """A usable discovery document, with the binding that authorized reading it."""

    binding: ScopeBinding
    path: str
    url: str
    status: int
    data: dict
    metadata: dict


@register
class OidcDiscoveryModule(Module):
    """Read in-scope WebApps' OIDC/OAuth metadata into AuthScheme/Operation/Token nodes."""

    ctx: ModuleContext

    name = "oidc_discovery"
    produces = ("AuthScheme", "Operation", "Token")
    active = True

    def run(self, seeds: list) -> dict:
        """Gate, read the metadata, fold it in. Returns counts; never raises on the network."""

        # Self-check: the verb must be on the closed whitelist AND be an active verb — this
        # module sends traffic to the target, and a passive label would mislabel the spend.
        verbs.assert_schedulable(VERB)
        assert verbs.is_active(VERB), \
            "oidc_discovery is active; its verb must be in verbs.ACTIVE"

        summary: dict = {
            "module": self.name,
            "verb": VERB,
            "active": True,
            "paths": list(DISCOVERY_PATHS),
            "seeds_in": 0,
            "webapps": [],
            "seeds_skipped": 0,
            "seeds_deduped": 0,
            "seeds_truncated": False,
            "gated": 0,
            "refused": 0,
            "refused_by_reason": {},
            "requests": 0,
            "fallbacks": 0,
            "documents": 0,
            "errors": 0,
            "errors_by_kind": {},
            "auth_schemes": 0,
            "operations": 0,
            "edges": 0,
            "endpoints_dropped_by_verdict": {},
            "jwks_fetched": 0,
            "jwks_skipped_out_of_scope": 0,
            "jwks_without_kid": 0,
            "tokens": 0,
            "private_jwk_members_redacted": 0,
        }

        targets = self._targets(seeds, summary)
        summary["webapps"] = [t.webapp_id for t in targets]
        if not targets:
            self.log.info("oidc_discovery: no WebApp seeds to query; nothing to do")
            return summary

        # No pre-flight scope/snapshot check on purpose: gate_active is the single
        # chokepoint and writes the ALLOW/REFUSE record for every attempt, so a disabled,
        # unsnapshotted, stale or out-of-scope run is refused there and stays auditable.
        for target in targets:
            self._discover(target, summary)

        self.log.info(
            "oidc_discovery: %d WebApp(s) -> %d gated, %d refused %s, %d request(s) "
            "(%d fallback(s)), %d document(s), %d error(s) %s — emitted %d AuthScheme, "
            "%d Operation(s), %d Token(s), %d edge(s)",
            len(targets), summary["gated"], summary["refused"],
            summary["refused_by_reason"] or "{}", summary["requests"],
            summary["fallbacks"], summary["documents"], summary["errors"],
            summary["errors_by_kind"] or "{}", summary["auth_schemes"],
            summary["operations"], summary["tokens"], summary["edges"],
        )
        return summary

    # --- seeds -------------------------------------------------------------
    def _targets(self, seeds: list, summary: dict) -> list[_Target]:
        """Ordered, deduplicated WebApp targets. Tolerates an empty or junk seed list."""

        out: list[_Target] = []
        seen: set[str] = set()
        for seed in seeds or []:
            summary["seeds_in"] += 1
            target = self._seed_target(seed)
            if target is None:
                summary["seeds_skipped"] += 1
                continue
            if target.webapp_id in seen:
                summary["seeds_deduped"] += 1
                continue
            if len(out) >= MAX_SEED_NODES:
                summary["seeds_truncated"] = True
                self.log.warning(
                    "oidc_discovery: seed list exceeds MAX_SEED_NODES=%d; deferring the "
                    "rest to a later cycle rather than spending the budget in one run",
                    MAX_SEED_NODES,
                )
                break
            seen.add(target.webapp_id)
            out.append(target)
        return out

    @staticmethod
    def _seed_target(seed) -> _Target | None:
        """Pull a queryable WebApp out of a graph Node seed, or out of a plain-string seed.

        The authority is re-canonicalized rather than trusted verbatim, so the
        ``authenticates_with`` edge always points at the id the graph actually uses
        (``SPEC.md`` §3.1).
        """

        raw = getattr(seed, "id", None)
        if raw is None and isinstance(seed, str):
            raw = seed
        if not isinstance(raw, str) or not raw.strip():
            return None
        node_type = getattr(seed, "type", "")
        if node_type and node_type not in SEED_NODE_TYPES:
            return None
        text = raw.strip()
        if text.startswith(WEBAPP_ID_PREFIX):
            text = text[len(WEBAPP_ID_PREFIX):]
        elif text.startswith(_FOREIGN_ID_PREFIXES):
            return None  # some other node kind slipped into the seed list
        if "://" not in text:
            text = f"{DEFAULT_SCHEME}://{text}"
        endpoint = parse_endpoint(text)
        if endpoint is None:
            return None
        return _Target(
            webapp_id=f"{WEBAPP_ID_PREFIX}{endpoint.scheme}://{endpoint.authority}",
            scheme=endpoint.scheme,
            authority=endpoint.authority,
            host=endpoint.host,
        )

    # --- the gated requests -------------------------------------------------
    def _discover(self, target: _Target, summary: dict) -> None:
        """One target: read its discovery document, then emit what it says."""

        document = self._fetch_discovery(target, summary)
        if document is None:
            return
        summary["documents"] += 1
        self._emit(target, document, summary)

    def _fetch_discovery(self, target: _Target, summary: dict) -> _Document | None:
        """Gate + GET the discovery paths in order; return the first usable document.

        The second path is spent **only** on a ``404`` from the first. A gate refusal or a
        transport failure ends the target outright: a refusal is never a reason to try
        another door on the same host, and a failure is answered by backing off rather than
        by asking again (``safety-model.md`` §4).
        """

        status = 0
        for index, path in enumerate(DISCOVERY_PATHS):
            if index and status not in FALLBACK_STATUSES:
                break
            url = f"{target.base}{path}"
            if index:
                summary["fallbacks"] += 1
                self.log.info(
                    "oidc_discovery: %s answered HTTP %d; one separately gated fallback to %s",
                    DISCOVERY_PATHS[index - 1], status, path,
                )

            fetch = self._gated_get(target.host, url, summary)
            if fetch is None:
                return None  # refused: no packet was sent, and none will be
            if fetch.error:
                summary["errors"] += 1
                _bump(summary["errors_by_kind"], fetch.error)
                self.log.warning("oidc_discovery: GET %s failed (%s); skipping",
                                 url, fetch.error)
                return None

            status = fetch.status
            if status != 200:
                self.log.info("oidc_discovery: %s answered HTTP %d; no document", url, status)
                continue  # a 404 falls through to the next path; anything else exits above

            data, error = parse_json_object(fetch.raw)
            if error:
                summary["errors"] += 1
                _bump(summary["errors_by_kind"], error)
                self.log.warning("oidc_discovery: %s returned an unusable body (%s); skipping",
                                 url, error)
                return None

            metadata = metadata_attrs(data)
            if not metadata:
                summary["errors"] += 1
                _bump(summary["errors_by_kind"], "no_recognized_metadata")
                self.log.warning(
                    "oidc_discovery: %s parsed but declares no recognized metadata field; "
                    "emitting nothing rather than an empty AuthScheme", url,
                )
                return None

            return _Document(binding=fetch.binding, path=path, url=url, status=status,
                             data=data, metadata=metadata)
        return None

    def _gated_get(self, value: str, url: str, summary: dict) -> _Fetch | None:
        """THE CHOKEPOINT. Gate ``value``, then send exactly one GET. ``None`` on refusal.

        A :class:`GateRefused` is never swallowed into a request-anyway path: it ends this
        touch here, logged and counted, and the run continues with the next target.
        """

        summary["gated"] += 1
        try:
            binding = self.ctx.gate_active(value, VERB)
        except GateRefused as exc:
            summary["refused"] += 1
            _bump(summary["refused_by_reason"], exc.reason)
            self.log.info("oidc_discovery: not requesting %s: %s", url, exc.reason)
            return None

        summary["requests"] += 1  # the budget was debited whether or not the answer is usable
        resp, error = self._request(url)
        if error:
            return _Fetch(binding=binding, error=error)

        status = getattr(resp, "status_code", None)
        if not isinstance(status, int) or not 100 <= status <= 599:
            return _Fetch(binding=binding, error="no_usable_status_code")
        return _Fetch(binding=binding, status=status, raw=self._body(resp))

    def _request(self, url: str):
        """Send one GET. Returns ``(response, error)`` and never raises.

        ``requests.get`` is the only sender reachable from this module, so a token request
        is structurally impossible, not merely declined. No body, no cookie, no
        ``Authorization``, no ``Origin``, no redirect following (each hop is its own scope
        decision) and no retry.
        """

        try:
            resp = requests.get(
                url,
                timeout=self.ctx.timeout,
                headers={"User-Agent": self.ctx.user_agent, "Accept": "application/json"},
                allow_redirects=False,
            )
        except requests.RequestException as exc:
            return None, f"request_failed:{type(exc).__name__}"
        except Exception as exc:  # unknown transport layer; a module never crashes the run
            return None, f"unexpected_transport_error:{type(exc).__name__}"
        return resp, ""

    @staticmethod
    def _body(resp) -> str:
        """Decoded body, capped. A decode failure is not worth failing the read over."""

        try:
            return (getattr(resp, "text", "") or "")[:MAX_RESPONSE_CHARS]
        except Exception:
            return ""

    # --- evidence ----------------------------------------------------------
    def _evidence(self, record: str, region: str) -> list[EvidenceRef]:
        """Content-address a document record. An unwritable store is not fatal."""

        try:
            return [self.ctx.evidence.put_text(record, region=region)]
        except OSError as exc:
            self.log.warning("oidc_discovery: evidence store unavailable for %s: %s",
                             region, exc)
            return []

    @staticmethod
    def _record(url: str, status: int, document, extra: str = "") -> str:
        """The canonicalized document record that is this observation's raw proof."""

        lines = [f"{SOURCE}/{RULE_VERSION} verb={VERB}", f"url={url}", f"status={status}"]
        if extra:
            lines.append(extra)
        lines.append("document=" + canonical_json(document))
        return "\n".join(lines)

    # --- emit --------------------------------------------------------------
    def _emit(self, target: _Target, document: _Document, summary: dict) -> None:
        """Write the AuthScheme + its edge, then the declared endpoints and the key set."""

        # The gate already guarantees this; assert it so no future refactor can emit a node
        # for a value that was not in scope at observation time (I2/I3).
        assert document.binding.verdict == Verdict.IN_SCOPE, \
            "the binding here comes from gate_active and must be in_scope"

        now = self.ctx.clock_now()
        evidence = self._evidence(
            self._record(document.url, document.status, document.data),
            region=f"{SOURCE}:GET {document.url}",
        )

        # The live arrays are content-hashed, not assumed: "fingerprinted" is earned by the
        # document we just read. "flow_mapped" is claimed only when the issuer actually
        # declares its grant/response-type vocabulary — that set is what names the flows it
        # supports; without it, nothing about the flow model was mapped.
        coverage = {"fingerprinted": True}
        if any(document.metadata.get(field) for field in FLOW_FIELDS):
            coverage["flow_mapped"] = True

        auth_id = f"auth:{target.authority}{AUTH_ID_SUFFIX}"
        self.ctx.graph.upsert_node(make_node(
            "AuthScheme", auth_id,
            binding=document.binding,  # the gate's own binding, pinned to this snapshot
            source=SOURCE,
            now=now,
            attrs={"active_probed": True, **document.metadata},
            evidence=evidence,
            rule_id=RULE_ID,
            rule_version=RULE_VERSION,
            log_odds=METADATA_LOG_ODDS,
            sensitivity=Sensitivity.S0,  # a public, unauthenticated metadata document
            coverage=coverage,
            data_subject="none",
        ))
        summary["auth_schemes"] += 1

        self.ctx.graph.upsert_edge(make_edge(
            "authenticates_with", target.webapp_id, auth_id,
            binding=document.binding,
            source=SOURCE,
            now=now,
            attrs={"active_probed": True},
            log_odds=METADATA_LOG_ODDS,
        ))
        summary["edges"] += 1

        self.log.info(
            "oidc_discovery: %s -> %s issuer=%r, %d grant(s), %d scope(s), jwks=%r",
            document.url, auth_id, document.metadata.get("issuer", ""),
            len(document.metadata.get("grant_types_supported", [])),
            len(document.metadata.get("scopes_supported", [])),
            document.metadata.get("jwks_uri", ""),
        )

        self._emit_operations(document, evidence, summary)
        self._emit_key_set(auth_id, document, summary)

    def _emit_operations(self, document: _Document, evidence: list[EvidenceRef],
                         summary: dict) -> None:
        """One Operation + ``exposes`` edge per declared endpoint, keyed to its own host.

        Epic's authorize endpoint lives on a different host from its discovery document
        (``domains/non-binary.md`` §3.5), so an endpoint is **never** attributed to the
        seed's WebApp by default: each one is keyed under its own authority and earns its own
        scope verdict — ``scope != ownership`` (§2) — and an endpoint the policy does not
        list is recorded as negative space instead of as a node.
        """

        now = self.ctx.clock_now()
        for field, method, role in ENDPOINT_OPERATIONS:
            # Already canonicalized by metadata_attrs, so this only skips an absent field.
            endpoint = parse_endpoint(document.metadata.get(field))
            if endpoint is None:
                continue

            binding = self.ctx.bind(endpoint.host)
            if binding.verdict != Verdict.IN_SCOPE:
                # prefilter_only included: an owned-but-unlisted endpoint may never drive an
                # active touch, so a node whose only purpose is to be probed is not retained.
                _bump(summary["endpoints_dropped_by_verdict"], binding.verdict.value)
                self.log.info(
                    "oidc_discovery: not retaining %s %s: %s (%s) — the url stays on the "
                    "AuthScheme, no node and no edge emitted",
                    role, endpoint.url, binding.verdict.value, binding.rule_matched,
                )
                continue

            webapp_id = f"{WEBAPP_ID_PREFIX}{endpoint.scheme}://{endpoint.authority}"
            route_id = f"{ROUTE_ID_PREFIX}{webapp_id}{endpoint.path}"
            op_id = operation_id(method, route_id)
            self.ctx.graph.upsert_node(make_node(
                "Operation", op_id,
                binding=binding,
                source=SOURCE,
                now=now,
                attrs={
                    "active_probed": True,
                    "method": method,  # the contract's method; never a method we sent
                    "path_template": endpoint.path,
                    "endpoint_role": role,
                    "webapp": webapp_id,
                },
                evidence=evidence,
                rule_id=RULE_ID,
                rule_version=RULE_VERSION,
                log_odds=DECLARED_ENDPOINT_LOG_ODDS,  # declared, not touched
                sensitivity=Sensitivity.S0,
                coverage={"enumerated": True},  # existence stated; no parameter mined
                data_subject="none",
            ))
            self.ctx.graph.upsert_edge(make_edge(
                "exposes", webapp_id, op_id,
                binding=binding,
                source=SOURCE,
                now=now,
                attrs={"active_probed": True},
                log_odds=DECLARED_ENDPOINT_LOG_ODDS,
            ))
            summary["operations"] += 1
            summary["edges"] += 1

    def _emit_key_set(self, auth_id: str, document: _Document, summary: dict) -> None:
        """Read the issuer's JWKS, if its own host is in scope, into one ``Token`` node.

        The key set is the issuer's public verification material, so reading it asserts
        nothing about any token's holder and never touches a credential. The node id is the
        digest of the ``kid`` set, so a rotation mints a *new* Token — the temporal series
        §3.5 wants — instead of forking the old one.
        """

        endpoint = parse_endpoint(document.metadata.get("jwks_uri"))
        if endpoint is None:
            return
        if not self.ctx.in_scope(endpoint.host):
            # The gate would refuse this anyway; checking first keeps a third-party key host
            # from costing a REFUSE record for a touch we were never going to make.
            summary["jwks_skipped_out_of_scope"] += 1
            self.log.info(
                "oidc_discovery: jwks_uri host %s is not in scope; not fetching it (the uri "
                "stays recorded on %s)", endpoint.host, auth_id,
            )
            return

        fetch = self._gated_get(endpoint.host, endpoint.url, summary)
        if fetch is None:
            return
        if fetch.error:
            summary["errors"] += 1
            _bump(summary["errors_by_kind"], fetch.error)
            self.log.warning("oidc_discovery: GET %s failed (%s); skipping",
                             endpoint.url, fetch.error)
            return
        if fetch.status != 200:
            self.log.info("oidc_discovery: %s answered HTTP %d; no key set",
                          endpoint.url, fetch.status)
            return

        data, error = parse_json_object(fetch.raw)
        if error:
            summary["errors"] += 1
            _bump(summary["errors_by_kind"], error)
            self.log.warning("oidc_discovery: %s returned an unusable body (%s); skipping",
                             endpoint.url, error)
            return

        jwks = sanitized_jwks(data)
        summary["jwks_fetched"] += 1
        summary["private_jwk_members_redacted"] += jwks.private_members_redacted
        if jwks.private_members_redacted:
            self.log.warning(
                "oidc_discovery: %s served %d private key member(s) — redacted at parse "
                "time, never stored in full; report, do not use",
                endpoint.url, jwks.private_members_redacted,
            )
        if not jwks.kids:
            # Without a kid there is no stable identity for the set, and a node keyed on
            # anything else would churn on every rotation. Recorded as negative space.
            summary["jwks_without_kid"] += 1
            self.log.info("oidc_discovery: %s declares no kid; no Token node minted",
                          endpoint.url)
            return

        now = self.ctx.clock_now()
        evidence = self._evidence(
            self._record(endpoint.url, fetch.status, jwks.document,
                         extra=(f"private_members_redacted={jwks.private_members_redacted}"
                                if jwks.private_members_redacted else "")),
            region=f"{SOURCE}:GET {endpoint.url}",
        )

        token_id = f"tok:{kid_set_digest(jwks.kids)}"
        self.ctx.graph.upsert_node(make_node(
            "Token", token_id,
            binding=fetch.binding,  # the jwks host's own gate binding
            source=SOURCE,
            now=now,
            # Only the key ids and algorithms: no key material reaches an attribute, and no
            # live token is involved at all. Lists never fork-conflict on re-observation.
            attrs={"active_probed": True, "kids": list(jwks.kids),
                   "algs": list(jwks.algs)},
            evidence=evidence,
            rule_id=RULE_ID,
            rule_version=RULE_VERSION,
            log_odds=METADATA_LOG_ODDS,
            # Public verification keys are S0 material by the §5 taxonomy, but invariant I8
            # rejects an S0 Token node: the label, not convenience, decides handling.
            sensitivity=Sensitivity.S1,
            coverage={"fingerprinted": True},  # live key set, content-hashed, first-hand
            data_subject="none",
        ))
        self.ctx.graph.upsert_edge(make_edge(
            "issued_by", token_id, auth_id,
            binding=fetch.binding,
            source=SOURCE,
            now=now,
            attrs={"active_probed": True},
            log_odds=METADATA_LOG_ODDS,
        ))
        summary["tokens"] += 1
        summary["edges"] += 1
        self.log.info("oidc_discovery: %s -> %s, %d kid(s) %s, alg(s) %s",
                      endpoint.url, token_id, len(jwks.kids), list(jwks.kids),
                      list(jwks.algs))


__all__ = [
    "OidcDiscoveryModule", "VERB", "SOURCE", "RULE_ID", "RULE_VERSION",
    "OIDC_PATH", "OAUTH_AS_PATH", "DISCOVERY_PATHS", "FALLBACK_STATUSES",
    "AUTH_ID_SUFFIX", "METADATA_LOG_ODDS", "DECLARED_ENDPOINT_LOG_ODDS",
    "ENDPOINT_OPERATIONS", "URL_FIELDS", "LIST_FIELDS", "FLOW_FIELDS",
    "PRIVATE_JWK_MEMBERS", "MAX_SEED_NODES", "MAX_JWKS_KEYS", "MAX_LIST_ITEMS",
    "authority", "canonical_json", "kid_set_digest", "metadata_attrs",
    "parse_endpoint", "parse_json_object", "safe_url", "sanitized_jwks",
    "short_tokens", "valid_target",
]
