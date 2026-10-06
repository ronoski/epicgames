"""Active API-contract discovery — a published spec becomes typed Operations (``SPEC.md`` §6.2.4).

This is the L3 rung of the ladder (``docs/pipeline.md`` §2): ``http_probe`` establishes that
a vhost answers, and this module asks that vhost for its **machine-readable contract**, then
folds the contract into the graph as ``Route -> Operation -> Parameter`` so the knowledge
base holds *typed operations* rather than a flat list of hosts. A declared spec is the
highest-confidence statement of an endpoint's existence available (``domains/non-binary.md``
§3.4) and also the cheapest: one GET buys a whole API surface that content discovery would
need thousands of requests — and a human authorization — to guess at.

**What it sends.** Exactly one ``GET`` per well-known path in :data:`SPEC_PATHS`, a fixed
module constant that is never a wordlist and is never derived from a response, on the
``read-openapi`` verb. Redirects are not followed (each hop is its own scope decision) and
nothing is retried. Every single request passes :meth:`ModuleContext.gate_active` **first**
(``safety-model.md`` §3/§4); a :class:`GateRefused` ends that one attempt — logged, counted,
never swallowed into a probe-anyway path — and the walk continues. The walk **stops at the
first body that parses as a spec**: the remaining paths are budget that need not be spent.

**What it never sends.** The operations it learns are *parsed, not called*. Reading
``POST /v1/accounts/{id}/purchase`` out of a document is recon; issuing it would be a write,
which is permanently off the verb whitelist. So:

* no URL is ever built from spec content — ``servers[]``, a ``Location`` header and an
  operation path are all data, never targets;
* an **external** ``$ref`` is never fetched. Only local ``#/...`` pointers are resolved
  (bounded depth, cycle-safe); a remote ref would be an un-gated network touch, so it is
  counted as unresolved and dropped;
* only ``/openapi.json``-style paths are requested, so a spec that exists only behind a
  docs UI is simply not found here — it is not hunted for.

**What it emits**, all from the binding :meth:`gate_active` returned and all marked
``active_probed`` (I2/I3): a ``Route`` per declared path template, an ``Operation`` per
``(path, method)`` carrying the declared ``summary``/``operation_id``/``spec_version``, and a
``Parameter`` per declared input — path, query, header, cookie, ``formData``, plus the
properties of a declared request body — joined by the declared ``exposes``
(WebApp→Route→Operation) and ``takes`` (Operation→Parameter) edges. The Operations carry
coverage ``{"enumerated", "param_mined"}``: the full *declared* parameter set is exactly what
``param_mined`` means for a contract read. The Route carries the same signal because the
planner's ``api-contract`` rule inspects the WebApp's ``exposes`` targets — the Routes — and
a gap that cannot observe its own closure would re-schedule this probe forever.

**Fidelity and hygiene.** Attrs describe the document and nothing more: ``required`` is what
the spec *declares*, not what OpenAPI implies for a path parameter, and a spec's ``example``
values are never read, so the raw document (content-addressed into the evidence store, where
encryption-at-rest and the sensitivity policy live) stays the only place its byte-level
content exists. Enum labels are the one spec-controlled value that does reach an attr, so a
secret-shaped label is passed through :func:`recon.evidence.redact` before storage
(``safety-model.md`` §5) — a published contract should never carry a live credential, and if
one does, this module is not the thing that copies it into the graph. Nothing here collects
data about another person: every node is ``data_subject="none"`` and ``S0`` (a public,
unauthenticated document), and no ``Credential``/``Token`` node is minted at all.

A declared contract lands at ``log_odds=2.0`` (~p=0.88) — deliberately just below the
``corroborated`` threshold of 2.2, since one source must never promote itself; live
corroboration (or spec drift, which **forks**) is what moves it.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime

import requests

from ... import verbs
from ...evidence import redact
from ...factory import make_edge, make_node
from ...models import EvidenceRef, ScopeBinding, Sensitivity, Verdict
from ...urls import (
    authority as make_authority, canonical_host, operation_id, parameter_id,
    route_id as make_route_id, webapp_id as make_webapp_id,
    webapp_id_from_url,
)
from ...scope import classify, normalize_host
from ..base import GateRefused, Module, ModuleContext, register

#: The only verb this module spends. Active: it puts a request on an Epic target.
VERB = "read-openapi"

SOURCE = "openapi_discovery"

#: The fixed, short list of published-spec locations. A module constant on purpose: a
#: generated or response-derived path list would be content discovery at volume, which is
#: human-gated (``safety-model.md`` §3) and never auto-run.
SPEC_PATHS: tuple[str, ...] = (
    "/openapi.json",
    "/swagger.json",
    "/v3/api-docs",
    "/api/openapi.json",
    "/.well-known/openapi.json",
)

#: Methods a path item may declare, in a fixed order so emission is deterministic however
#: the document happened to order its keys. These are **parsed**, never dispatched.
HTTP_METHODS: tuple[str, ...] = (
    "get", "head", "post", "put", "patch", "delete", "options", "trace",
)

#: A published contract is strong evidence an operation exists. ~p=0.88, deliberately below
#: ``models._CORROBORATED_AT`` (2.2): one source never promotes itself.
DECLARED_LOG_ODDS = 2.0

#: Node types accepted as seeds; anything else in the seed list is ignored.
SEED_NODE_TYPES = frozenset({"WebApp"})

# --- defensive caps (a spec is untrusted third-party input of unbounded size) ---
MAX_SEEDS = 25
MAX_OPERATIONS = 500          # total per run; truncation is logged, not silent
MAX_PATHS = 2000              # path items walked per document
MAX_PARAMS_PER_OPERATION = 100
MAX_ENUM_VALUES = 20
MAX_SPEC_CHARS = 4 * 1024 * 1024
MAX_REF_DEPTH = 8
MAX_NAME_CHARS = 128
MAX_PATH_CHARS = 300
MAX_TOKEN_CHARS = 48
MAX_TEXT_CHARS = 200
MAX_ENUM_VALUE_CHARS = 64

#: Conservative fqdn shape, mirroring ``http_probe``: rejects whitespace, raw unicode
#: (punycode ``xn--`` passes) and anything email-shaped, so a junk seed can never be
#: interpolated into a request URL.
_FQDN_RE = re.compile(
    r"^[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?)+\Z"
)

#: A path template is one absolute, printable, space-free path with no query or fragment.
#: Anything else (a full URL used as a key, ``?a=1``, a control character) is a malformed
#: document, not a route. ``\Z`` rather than ``$``: ``$`` also matches before a trailing
#: newline, which would let a control character through.
_TEMPLATE_RE = re.compile(r"^/[\x21-\x22\x24-\x3e\x40-\x7e]*\Z")

#: A parameter name must survive the pinned ``param:<op>#<name>`` id form, so ``#`` and
#: whitespace are rejected rather than escaped.
_NAME_RE = re.compile(r"^[\x21-\x22\x24-\x7e]+\Z")

#: Shapes that mean "this enum label is a live secret, not a label". Matching values are
#: redacted to ``prefix…+sha`` before they can reach an attr (``safety-model.md`` §5).
_SECRET_SHAPED_RE = re.compile(
    r"^(?:"
    r"ey[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}"  # a JWT
    r"|[A-Za-z0-9+/]{32,}={0,2}"                                   # a long base64 blob
    r"|[0-9a-fA-F]{32,}"                                           # a long hex digest
    r")\Z"
)



@dataclass(frozen=True)
class _Target:
    """A seed WebApp split into the pieces a request and a gate each need."""

    webapp_id: str
    scheme: str
    authority: str
    host: str  # the gate value: unbracketed, port-free


def parse_webapp(raw: str) -> _Target | None:
    """Split a ``web:<scheme>://<authority>`` id into a :class:`_Target`, or ``None``.

    Only ``http``/``https`` are spoken here. An authority carrying an explicit port is
    **rejected rather than rewritten**: the pinned ``web:<scheme>://<vhost>`` id has no slot
    for a port, and silently dropping one would probe a different endpoint than the seed
    named. The host is re-canonicalized (lowercased, trailing dot stripped, IPv6 bracketed)
    so the id this module writes edges against is byte-identical to ``http_probe``'s.
    """

    text = (raw or "").strip()
    if text.startswith("web:"):
        text = text[len("web:"):]
    if "://" not in text:
        return None
    scheme, _, authority = text.partition("://")
    scheme = scheme.strip().lower()
    if scheme not in ("http", "https"):
        return None
    authority = authority.strip().rstrip("/")
    if not authority or "/" in authority or "@" in authority:
        return None
    if authority.startswith("["):
        literal, bracket, trailing = authority[1:].partition("]")
        if not bracket or trailing:  # unterminated, or an explicit :port after the bracket
            return None
        host = normalize_host(literal)
    else:
        if ":" in authority:
            return None  # explicit port: see the docstring
        host = normalize_host(authority)
    if not host or len(host) > 253:
        return None
    if classify(host) != "ip" and not _FQDN_RE.match(host):
        return None
    return _Target(
        webapp_id=make_webapp_id(scheme, host),
        scheme=scheme,
        authority=make_authority(host),
        host=host,
    )


def spec_version(doc: dict) -> str:
    """The document's declared ``openapi``/``swagger`` version, or ``""``."""

    for key in ("openapi", "swagger"):
        value = doc.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()[:MAX_TOKEN_CHARS]
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return str(value)[:MAX_TOKEN_CHARS]
    return ""


def looks_like_spec(doc) -> bool:
    """True for a body that is an OpenAPI/Swagger document: a version **and** ``paths``."""

    return (isinstance(doc, dict) and isinstance(doc.get("paths"), dict)
            and bool(spec_version(doc)))


def parse_json(text: str):
    """Parse a response body as JSON, or ``None``. Never raises.

    The cheap ``{`` check keeps an HTML error page or a YAML document out of the parser
    entirely; a spec is untrusted input, so a nesting bomb (``RecursionError``) is a
    non-event rather than a crashed run.
    """

    if not text or not text.lstrip()[:1] == "{":
        return None
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        return None


def declared_path_template(raw) -> str:
    """Validate an OpenAPI ``paths`` key as a template, or ``""`` if it is not one.

    Deliberately NOT :func:`recon.urls.path_template`: that one *derives* a template
    from a concrete observed path by collapsing identifier segments, whereas a spec key
    is already a template and its declared ``{accountId}`` placeholders must survive
    verbatim. Same word, different job — hence the distinct name.
    """

    if not isinstance(raw, str):
        return ""
    text = raw.strip()
    if not _TEMPLATE_RE.match(text) or "://" in text:
        return ""
    return text[:MAX_PATH_CHARS]


def clean_name(raw) -> str:
    """A parameter name safe for the pinned ``param:<op>#<name>`` id, or ``""``."""

    if not isinstance(raw, str):
        return ""
    text = raw.strip()[:MAX_NAME_CHARS]
    return text if _NAME_RE.match(text) else ""


def clean_token(raw) -> str:
    """A short scalar descriptor (``in``, ``type``) as text, or ``""``.

    OpenAPI 3.1 allows ``type: ["string", "null"]``; the first scalar member is used so the
    attr stays a simple comparable token.
    """

    if isinstance(raw, list):
        raw = next((v for v in raw if isinstance(v, str)), "")
    if isinstance(raw, bool) or not isinstance(raw, (str, int, float)):
        return ""
    return str(raw).strip()[:MAX_TOKEN_CHARS]


def clean_text(raw) -> str:
    """A declared human-readable field (``summary``), whitespace-collapsed and capped."""

    if not isinstance(raw, str):
        return ""
    return re.sub(r"\s+", " ", raw).strip()[:MAX_TEXT_CHARS]


def enum_values(raw) -> list[str]:
    """Declared enum labels as capped text, with secret-shaped values redacted."""

    if not isinstance(raw, list):
        return []
    out: list[str] = []
    for value in raw[:MAX_ENUM_VALUES]:
        if value is None:
            text = "null"
        elif isinstance(value, (str, int, float, bool)):
            text = str(value)
        else:
            continue  # a structured enum member is not a label; the raw spec keeps it
        text = text[:MAX_ENUM_VALUE_CHARS]
        out.append(redact(text) if _SECRET_SHAPED_RE.match(text) else text)
    return out


def param_list(raw) -> list:
    """A ``parameters`` array as a plain list (anything else reads as empty)."""

    return [p for p in raw if p is not None] if isinstance(raw, list) else []


def json_pointer(doc, pointer: str):
    """Resolve a local JSON pointer body (``components/schemas/Foo``), or ``None``."""

    node = doc
    for token in pointer.split("/"):
        key = token.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict):
            if key not in node:
                return None
            node = node[key]
        elif isinstance(node, list):
            if not key.isdigit() or int(key) >= len(node):
                return None
            node = node[int(key)]
        else:
            return None
    return node


@dataclass
class _Fetched:
    """One gated GET that returned a body, and the binding that authorized it."""

    url: str
    binding: ScopeBinding
    text: str


@dataclass
class _Spec:
    """A parsed contract plus everything the emitters read off it."""

    target: _Target
    url: str
    doc: dict
    version: str
    binding: ScopeBinding
    now: datetime
    evidence: list[EvidenceRef] = field(default_factory=list)


@register
class OpenApiDiscoveryModule(Module):
    """Turn an in-scope ``WebApp`` into typed ``Route``/``Operation``/``Parameter`` nodes."""

    ctx: ModuleContext

    name = "openapi_discovery"
    produces = ("Route", "Operation", "Parameter")
    active = True

    #: Count of ``$ref``s this module declined to follow (external, or past the depth cap).
    _refs_unresolved = 0

    #: Set when an in-document cap (operations/paths) deferred work, which also stops the
    #: run spending rate budget on further WebApps. Distinct from the seed cap, which
    #: defers *later seeds* and must not stop the ones that were kept.
    _capped = False

    def run(self, seeds: list) -> dict:
        """Walk the fixed spec-path list per WebApp. Gate, one GET, parse, log and continue."""

        # Self-check: the single verb must be on the closed whitelist AND be an active verb
        # (this module sends traffic to the target; a passive verb would mislabel the spend).
        verbs.assert_schedulable(VERB)
        assert verbs.is_active(VERB), f"{VERB!r} must be an active verb"

        self._refs_unresolved = 0
        self._capped = False
        summary: dict = {
            "module": self.name,
            "verb": VERB,
            "active": True,
            "targets": [],
            "requests": 0,
            "specs": 0,
            "routes": 0,
            "operations": 0,
            "parameters": 0,
            "edges": 0,
            "not_a_spec": 0,
            "refs_unresolved": 0,
            "refused": [],
            "errors": [],
            "truncated": False,
        }

        targets = self._targets(seeds, summary)
        summary["targets"] = [t.webapp_id for t in targets]
        if not targets:
            self.log.info("openapi_discovery: no WebApp seeds to read; nothing to do")
            return summary

        # No pre-flight scope/snapshot check on purpose: gate_active is the single chokepoint
        # and writes the ALLOW/REFUSE record for every attempt, so a disabled, unsnapshotted,
        # stale or out-of-scope run is refused there and stays auditable.
        for target in targets:
            if self._capped:
                break  # the operation cap is spent; stop spending rate budget too
            self._discover(target, summary)

        summary["refs_unresolved"] = self._refs_unresolved
        self.log.info(
            "openapi_discovery: done — %d WebApp(s), %d request(s), %d spec(s), %d Route(s), "
            "%d Operation(s), %d Parameter(s), %d edge(s), %d refused, %d error(s)",
            len(targets), summary["requests"], summary["specs"], summary["routes"],
            summary["operations"], summary["parameters"], summary["edges"],
            len(summary["refused"]), len(summary["errors"]),
        )
        return summary

    # --- seeds -------------------------------------------------------------
    def _targets(self, seeds: list, summary: dict) -> list[_Target]:
        """Distinct WebApp targets, in seed order. Tolerates an empty or junk list."""

        out: list[_Target] = []
        seen: set[str] = set()
        for seed in seeds or []:
            raw = self._seed_value(seed)
            if not raw:
                continue
            target = parse_webapp(raw)
            if target is None:
                self.log.info("openapi_discovery: ignoring unusable WebApp seed %r", raw)
                continue
            if target.webapp_id in seen:
                continue
            seen.add(target.webapp_id)
            out.append(target)
        if len(out) > MAX_SEEDS:
            self.log.warning("openapi_discovery: %d WebApp seed(s) exceeds the %d cap; "
                             "deferring the rest", len(out), MAX_SEEDS)
            summary["truncated"] = True
            out = out[:MAX_SEEDS]
        return out

    @staticmethod
    def _seed_value(seed) -> str:
        """Pull a WebApp id out of a graph Node, or out of a plain-string seed."""

        raw = getattr(seed, "id", None)
        if raw is None and isinstance(seed, str):
            raw = seed
        if not isinstance(raw, str) or not raw.strip():
            return ""
        node_type = getattr(seed, "type", "")
        if node_type and node_type not in SEED_NODE_TYPES:
            return ""  # some other node kind slipped into the seed list
        return raw

    # --- fetch -------------------------------------------------------------
    def _discover(self, target: _Target, summary: dict) -> None:
        """Walk :data:`SPEC_PATHS` until one body parses as a contract."""

        for path in SPEC_PATHS:
            url = f"{target.scheme}://{target.authority}{path}"
            fetched = self._gated_fetch(target, url, summary)
            if fetched is None:
                continue
            doc = parse_json(fetched.text)
            if not looks_like_spec(doc):
                self.log.info("openapi_discovery: %s is not a machine-readable spec; "
                              "moving on", url)
                summary["not_a_spec"] += 1
                continue
            summary["specs"] += 1
            self._ingest(target, fetched, doc, summary)
            # One contract is the contract. The rest of the list is budget left unspent.
            return
        self.log.info("openapi_discovery: no published spec under %s", target.webapp_id)

    def _gated_fetch(self, target: _Target, url: str, summary: dict) -> _Fetched | None:
        """Gate, then send exactly one GET. ``None`` on refusal or an unusable answer.

        A :class:`GateRefused` is never swallowed into a fetch-anyway path: it ends this one
        attempt, logged and counted, and the walk continues to the next path.
        """

        try:
            binding = self.ctx.gate_active(target.host, VERB)
        except GateRefused as exc:
            self.log.info("openapi_discovery: skipping GET %s: %s", url, exc.reason)
            summary["refused"].append({"url": url, "verb": VERB, "reason": exc.reason})
            return None

        resp, err = self._request(url)
        summary["requests"] += 1  # the budget was debited whether or not the answer is usable
        if err:
            self.log.warning("openapi_discovery: GET %s failed (%s); skipping", url, err)
            summary["errors"].append({"url": url, "error": err})
            return None

        status = getattr(resp, "status_code", None)
        if not isinstance(status, int) or isinstance(status, bool) or status != 200:
            self.log.debug("openapi_discovery: %s answered %r; no spec there", url, status)
            return None

        text = self._body(resp)
        if not text:
            self.log.info("openapi_discovery: %s answered 200 with no usable body", url)
            return None
        if len(text) > MAX_SPEC_CHARS:
            self.log.warning("openapi_discovery: %s body is %d chars (cap %d); not parsed",
                             url, len(text), MAX_SPEC_CHARS)
            summary["errors"].append({"url": url, "error": "spec exceeds size cap"})
            return None
        return _Fetched(url=url, binding=binding, text=text)

    def _request(self, url: str):
        """Send one GET. Returns ``(response, error)`` and never raises.

        No body, no redirect following, no retry, and no other method is reachable from
        here — reading a published document is a GET and nothing else.
        """

        try:
            resp = requests.get(
                url,
                timeout=self.ctx.timeout,
                headers={"User-Agent": self.ctx.user_agent, "Accept": "application/json"},
                allow_redirects=False,
            )
        except requests.RequestException as exc:
            return None, f"request failed: {type(exc).__name__}"
        except Exception as exc:  # unknown transport layer; a module never crashes the run
            return None, f"unexpected transport error: {type(exc).__name__}"
        return resp, ""

    @staticmethod
    def _body(resp) -> str:
        """Decoded body. A decode failure is not worth failing the fetch over."""

        try:
            return getattr(resp, "text", "") or ""
        except Exception:
            return ""

    def _evidence(self, url: str, text: str) -> list[EvidenceRef]:
        """Content-address the raw spec so every typed fact below is replayable.

        The document is the proof, so it is stored whole — in the evidence store, where
        encryption-at-rest and the sensitivity policy apply — and never summarized into
        attrs. An unwritable store degrades to "no evidence ref", not a failed run.
        """

        try:
            return [self.ctx.evidence.put_text(text, region=f"{SOURCE}:GET {url}")]
        except OSError as exc:
            self.log.warning("openapi_discovery: evidence store unavailable for %s: %s",
                             url, exc)
            return []

    # --- $ref resolution ---------------------------------------------------
    def _deref(self, doc: dict, obj):
        """Follow local ``$ref`` pointers to the object they name.

        Only ``#/...`` is followed. An external/remote ref is a URL, and fetching it would
        be a network touch this module never gated — so it is counted and dropped instead.
        A depth cap makes a ``$ref`` cycle terminate.
        """

        for _ in range(MAX_REF_DEPTH):
            if not isinstance(obj, dict) or not isinstance(obj.get("$ref"), str):
                return obj
            ref = obj["$ref"].strip()
            if not ref.startswith("#/"):
                self._refs_unresolved += 1
                self.log.debug("openapi_discovery: not fetching external $ref %r", ref[:120])
                return None
            obj = json_pointer(doc, ref[2:])
        self._refs_unresolved += 1  # depth cap reached: a cycle or a silly chain
        return None

    # --- parse + emit ------------------------------------------------------
    def _ingest(self, target: _Target, fetched: _Fetched, doc: dict, summary: dict) -> None:
        """Fold one parsed contract into the graph, path by path, method by method."""

        # The gate already guarantees this; assert it so no future refactor can emit a node
        # for a value that was not in scope at observation time (I2/I3).
        assert fetched.binding.verdict == Verdict.IN_SCOPE, \
            "the only binding used here is the one gate_active returned"

        spec = _Spec(
            target=target, url=fetched.url, doc=doc, version=spec_version(doc),
            binding=fetched.binding, now=self.ctx.clock_now(),
            evidence=self._evidence(fetched.url, fetched.text),
        )
        self.log.info("openapi_discovery: %s published an OpenAPI/Swagger %s document",
                      fetched.url, spec.version or "?")

        for index, (raw_path, raw_item) in enumerate(doc["paths"].items()):
            if index >= MAX_PATHS:
                self._truncate(summary, f"path items beyond {MAX_PATHS}")
                return
            template = declared_path_template(raw_path)
            item = self._deref(doc, raw_item)
            if not template or not isinstance(item, dict):
                continue
            shared = param_list(item.get("parameters"))
            route_id = make_route_id(spec.target.webapp_id, template)
            route_emitted = False
            for method in HTTP_METHODS:
                operation = self._deref(doc, item.get(method))
                if not isinstance(operation, dict):
                    continue
                if summary["operations"] >= MAX_OPERATIONS:
                    self._truncate(summary, f"operations beyond the {MAX_OPERATIONS} cap")
                    return
                if not route_emitted:
                    self._emit_route(spec, route_id, template, summary)
                    route_emitted = True
                self._emit_operation(spec, route_id, template, method.upper(), operation,
                                     shared, summary)

    def _truncate(self, summary: dict, what: str) -> None:
        """Record that an in-document cap deferred work. Logged once, never silent."""

        if not self._capped:
            self.log.warning("openapi_discovery: truncated — %s deferred to a later cycle",
                             what)
        self._capped = True
        summary["truncated"] = True

    def _emit_route(self, spec: _Spec, route_id: str, template: str, summary: dict) -> None:
        """One ``Route`` per declared path template, exposed by its WebApp."""

        self.ctx.graph.upsert_node(make_node(
            "Route", route_id,
            binding=spec.binding,
            source=SOURCE,
            now=spec.now,
            attrs={
                "active_probed": True,
                "path_template": template,
                "webapp": spec.target.webapp_id,
                "spec_version": spec.version,
            },
            evidence=spec.evidence,
            log_odds=DECLARED_LOG_ODDS,
            sensitivity=Sensitivity.S0,  # a public, unauthenticated document
            # param_mined is visible here too because the planner's api-contract rule reads
            # the WebApp's exposes targets; see the module docstring.
            coverage={"enumerated": True, "param_mined": True},
            data_subject="none",
        ))
        self.ctx.graph.upsert_edge(make_edge(
            "exposes", spec.target.webapp_id, route_id,
            binding=spec.binding, source=SOURCE, now=spec.now,
            attrs={"active_probed": True}, log_odds=DECLARED_LOG_ODDS,
        ))
        summary["routes"] += 1
        summary["edges"] += 1

    def _emit_operation(self, spec: _Spec, route_id: str, template: str, method: str,
                        operation: dict, shared: list, summary: dict) -> None:
        """One ``Operation`` per declared ``(path, method)``, plus its typed Parameters."""

        op_id = operation_id(method, route_id)
        self.ctx.graph.upsert_node(make_node(
            "Operation", op_id,
            binding=spec.binding,
            source=SOURCE,
            now=spec.now,
            attrs={
                "active_probed": True,     # the contract came from a gated touch
                "method": method,          # declared, NOT dispatched
                "path_template": template,
                "webapp": spec.target.webapp_id,
                "spec_version": spec.version,
                "summary": clean_text(operation.get("summary")),
                "operation_id": clean_text(operation.get("operationId")),
            },
            evidence=spec.evidence,
            log_odds=DECLARED_LOG_ODDS,
            sensitivity=Sensitivity.S0,
            # The full *declared* input set is what param_mined means for a contract read.
            coverage={"enumerated": True, "param_mined": True},
            data_subject="none",
        ))
        self.ctx.graph.upsert_edge(make_edge(
            "exposes", route_id, op_id,
            binding=spec.binding, source=SOURCE, now=spec.now,
            attrs={"active_probed": True}, log_odds=DECLARED_LOG_ODDS,
        ))
        summary["operations"] += 1
        summary["edges"] += 1

        for record in self._parameters(spec, operation, shared):
            self._emit_parameter(spec, op_id, record, summary)

    def _emit_parameter(self, spec: _Spec, op_id: str, record: dict, summary: dict) -> None:
        """One ``Parameter`` per declared input, taken by its Operation."""

        attrs = {
            "active_probed": True,
            "name": record["name"],
            "in": record["in"],
            "type": record["type"],
            "required": record["required"],
        }
        if record["enum"]:
            attrs["enum"] = record["enum"]
        param_id = parameter_id(op_id, record["name"], record["in"])
        self.ctx.graph.upsert_node(make_node(
            "Parameter", param_id,
            binding=spec.binding,
            source=SOURCE,
            now=spec.now,
            attrs=attrs,
            evidence=spec.evidence,
            log_odds=DECLARED_LOG_ODDS,
            sensitivity=Sensitivity.S0,
            coverage={"enumerated": True},  # declared and typed; no value was ever sent
            data_subject="none",
        ))
        self.ctx.graph.upsert_edge(make_edge(
            "takes", op_id, param_id,
            binding=spec.binding, source=SOURCE, now=spec.now,
            attrs={"active_probed": True}, log_odds=DECLARED_LOG_ODDS,
        ))
        summary["parameters"] += 1
        summary["edges"] += 1

    # --- parameters --------------------------------------------------------
    def _parameters(self, spec: _Spec, operation: dict, shared: list) -> list[dict]:
        """Every declared input of one operation, de-duplicated and ordered.

        Path-item parameters come first and an operation-level declaration of the same name
        AND location overrides them (OpenAPI's own precedence), then the properties of a
        declared request body fill in slots not already claimed.

        De-duplication is by ``(location, name)``. It used to be by name alone, because the
        old ``param:<op>#<name>`` id could not tell a ``query`` from a ``header`` of the
        same name and emitting both would have collided on one id — which the store would
        then read as a contradiction and fork on a fact that never disagreed. The id now
        carries the location, so both are recorded as the distinct inputs they are.
        """

        records: dict[tuple[str, str], dict] = {}
        for raw in list(shared) + param_list(operation.get("parameters")):
            declared = self._deref(spec.doc, raw)
            if not isinstance(declared, dict):
                continue
            name = clean_name(declared.get("name"))
            location = clean_token(declared.get("in"))
            schema = self._deref(spec.doc, declared.get("schema"))
            # Swagger 2 bodies carry their shape inline; expand them like an OpenAPI 3 body.
            if location == "body":
                expanded = self._schema_properties(spec, schema)
                if expanded:
                    for record in expanded:
                        records.setdefault((record["in"], record["name"]), record)
                    continue
            if not name:
                continue
            schema = schema if isinstance(schema, dict) else {}
            records[(location or "unknown", name)] = {
                "name": name,
                "in": location or "unknown",
                "type": clean_token(schema.get("type") or declared.get("type")),
                # What the document declares, not what OpenAPI implies for a path param.
                "required": bool(declared.get("required")),
                "enum": enum_values(schema.get("enum") or declared.get("enum")),
            }

        for record in self._body_parameters(spec, operation):
            records.setdefault(record["name"], record)
        return list(records.values())[:MAX_PARAMS_PER_OPERATION]

    def _body_parameters(self, spec: _Spec, operation: dict) -> list[dict]:
        """Properties of an OpenAPI 3 ``requestBody``, from one media type.

        Media types are taken in sorted order and the first one that actually types a body
        wins, so ``application/json`` and ``application/xml`` describing the same object
        produce one parameter set rather than duplicates.
        """

        body = self._deref(spec.doc, operation.get("requestBody"))
        content = body.get("content") if isinstance(body, dict) else None
        if not isinstance(content, dict):
            return []
        for mime in sorted(k for k in content if isinstance(k, str)):
            entry = content.get(mime)
            if not isinstance(entry, dict):
                continue
            records = self._schema_properties(spec, entry.get("schema"))
            if records:
                return records
        return []

    def _schema_properties(self, spec: _Spec, schema) -> list[dict]:
        """A body schema's declared properties as parameter records (``in="body"``)."""

        schema = self._deref(spec.doc, schema)
        if not isinstance(schema, dict):
            return []
        properties = schema.get("properties")
        if not isinstance(properties, dict):
            return []
        required = schema.get("required")
        required = {r for r in required if isinstance(r, str)} if isinstance(required, list) else set()
        records: list[dict] = []
        for raw_name, raw_property in properties.items():
            name = clean_name(raw_name)
            if not name:
                continue
            declared = self._deref(spec.doc, raw_property)
            declared = declared if isinstance(declared, dict) else {}
            records.append({
                "name": name,
                "in": "body",
                "type": clean_token(declared.get("type")),
                "required": name in required,
                "enum": enum_values(declared.get("enum")),
            })
            if len(records) >= MAX_PARAMS_PER_OPERATION:
                break
        return records


__all__ = [
    "OpenApiDiscoveryModule", "VERB", "SOURCE", "SPEC_PATHS", "HTTP_METHODS",
    "DECLARED_LOG_ODDS", "MAX_OPERATIONS", "authority_of", "clean_name", "clean_text",
    "clean_token", "enum_values", "json_pointer", "looks_like_spec", "param_list",
    "parse_json", "parse_webapp", "path_template", "spec_version",
]
