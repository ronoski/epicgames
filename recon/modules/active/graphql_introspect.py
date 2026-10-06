"""ACTIVE GraphQL schema recovery — the L5 rung of the contract ladder (``SPEC.md`` §6.2.4).

``openapi_discovery`` asks a vhost for its REST contract. A GraphQL endpoint publishes a
richer contract still — its **whole typed schema**, root field by root field, argument by
argument — and the protocol provides a read-only way to ask for it: introspection
(``docs/domains/non-binary.md`` §3.4). One gated request buys the operation set, the
argument types and the object model that response-diff parameter mining and field
suggestion would need thousands of requests, and a human authorization, to approximate.

**What it sends.** Per ``WebApp`` seed, at most one ``POST`` per path in
:data:`CANDIDATE_PATHS` — a fixed module constant, never a wordlist and never derived from
a response — carrying exactly ``{"query": INTROSPECTION_QUERY}`` and nothing else. ``POST``
is how the GraphQL protocol transports a query; the verb spent is ``graphql-introspect``,
which is on the closed whitelist as read-only (``safety-model.md`` §3), and the document is
pinned: :data:`INTROSPECTION_QUERY` is an **anonymous shorthand query** (it opens with
``{``), which by the GraphQL grammar cannot be a mutation, and it selects only the
``__schema`` metadata fields §6.2.4 asks for. No ``variables``, no ``operationName``, no
second document, no retry, no redirect following (each hop is its own scope decision).
Every single request passes :meth:`ModuleContext.gate_active` **first**
(``docs/pipeline.md`` §1); a :class:`GateRefused` ends that one attempt — logged, counted,
never swallowed into a probe-anyway path — and the walk continues. The walk **stops at the
first endpoint that answers with a schema**: the remaining paths are budget left unspent.

**What it never sends.** The mutations it learns are *mapped, never executed*: reading
``deleteAccount`` out of a schema is recon, calling it would be a write, which is
permanently off the whitelist. Introspection being **disabled** is likewise a terminal
answer, recorded as negative space — this module never falls back to
``graphql-field-suggestion`` (clairvoyance-style recovery), which is **human-gated** and
must be enqueued for authorization rather than auto-run (``safety-model.md`` §3). A
``403``/``429``/challenge is backed off from, not worked around: no evasion, no second
shape of the same probe. No URL is ever built from response content, and no credential,
cookie or ``Authorization`` header is ever sent, so everything learned here is what the
server tells an anonymous client.

**What it emits**, all from the binding :meth:`gate_active` returned and all marked
``active_probed`` (I2/I3):

* one ``Operation`` per **root field** of the query and mutation types
  (``op:POST:<route>#<fieldName>``), carrying ``graphql_kind`` so a mutation stays
  distinguishable from a query at a glance, with an ``exposes`` edge from the ``WebApp``.
  GraphQL serves its whole surface from one path, so the route segment of the id pins that
  path while the *operation* identity is the field — no ``Route`` node is minted, and the
  ``exposes`` edge therefore runs ``WebApp -> Operation`` directly;
* one ``ObjectType`` (``obj:<TypeName>``) per non-introspection type the schema declares,
  with its ``kind`` and declared ``field_count``, plus a ``references_object`` edge from
  each Operation to its return type (only when that type was actually emitted — a dangling
  endpoint would be a fabricated fact);
* one ``Parameter`` (``param:<op>#<argName>``) per declared argument with its unwrapped
  type name, joined by the declared ``takes`` edge.

Operations carry coverage ``{"param_mined": True, "flow_mapped": False}``: the full
declared argument set is exactly what ``param_mined`` means for a contract read, and the
``False`` is deliberate negative space (``SPEC.md`` §4.2) — mapping a multi-step flow needs
own-session observation, not a schema. ``ObjectType``/``Parameter`` nodes claim
``{"enumerated": True}``: they were declared and typed, and no value was ever sent.

**Hygiene.** The pinned query asks for names, kinds and type references only — no
``defaultValue``, no ``description``, no deprecation text — so no server-chosen *value*
can reach an attr at all (``safety-model.md`` §5). Belt and braces on top of that: every
name must match the GraphQL name grammar (which also protects the pinned ``obj:<name>`` /
``op:…#<field>`` / ``param:<op>#<name>`` id forms), and a name whose shape says "live
secret" rather than "identifier" is **dropped entirely** — not stored, not used in an id,
and logged only through :func:`recon.evidence.redact`. No ``Credential``/``Token`` node is
minted at all, nothing here collects data about another person (every node is
``data_subject="none"`` and ``S0``: a public, unauthenticated schema document), and nothing
is guessed — every fact is the server's own statement, so there is no ``Hypothesis`` to
mint either. The raw schema JSON is content-addressed into the evidence store, where
encryption-at-rest and the sensitivity policy live, so every typed fact below is replayable
from the proof it came from.

A first-hand schema read lands at :data:`SCHEMA_LOG_ODDS` (~p=0.88) — deliberately just
below the ``corroborated`` threshold of 2.2, since one source must never promote itself;
live corroboration (or schema drift, which **forks**) is what moves it.
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
)
from ...scope import classify
from ..base import GateRefused, Module, ModuleContext, register

#: The only verb this module spends, and the verb ``planner.RULES`` names for the
#: ``graphql-contract`` gap. Active: it puts a request on an Epic target. Whitelisted as
#: read-only introspection (``safety-model.md`` §3).
VERB = "graphql-introspect"

SOURCE = "graphql_introspect"

#: Ruleset version. Same response + same version ⇒ same facts (``SPEC.md`` §3.2).
RULE_ID = "graphql-introspection"
RULE_VERSION = "0.1.0"

#: The recovery path this module must never take when introspection is disabled: it is
#: **human-gated** (``verbs.HUMAN_GATED``) and is enqueued for authorization, never
#: auto-run. Named here so the refusal is explicit and testable, not merely absent.
FIELD_SUGGESTION_VERB = "graphql-field-suggestion"

#: The fixed, short list of conventional GraphQL endpoints. A module constant on purpose:
#: a generated or response-derived path list would be content discovery at volume, which is
#: human-gated (``safety-model.md`` §3) and never auto-run.
CANDIDATE_PATHS: tuple[str, ...] = (
    "/graphql",
    "/api/graphql",
    "/gql",
    "/v1/graphql",
)

#: The pinned, minimal introspection document — the whole network payload, every time.
#:
#: It is an **anonymous shorthand query**: it opens with ``{``, which by the GraphQL
#: grammar makes it a query operation and cannot be a mutation. It selects only the
#: metadata ``SPEC.md`` §6.2.4 asks for — root type names, type names/kinds, field names
#: and their argument/return type references — and deliberately asks for no
#: ``description``, no ``defaultValue`` and no deprecation text, so no server-chosen value
#: can reach an attr.
INTROSPECTION_QUERY = (
    "{__schema{queryType{name} mutationType{name} "
    "types{name kind fields{name args{name type{name kind ofType{name}}} "
    "type{name kind ofType{name}}}}}}"
)

#: A schema read first-hand from the server is strong evidence. ~p=0.88, and deliberately
#: below ``models._CORROBORATED_AT`` (2.2): one source never promotes itself.
SCHEMA_LOG_ODDS = 2.0

#: Node types accepted as seeds; anything else in the seed list is ignored.
SEED_NODE_TYPES = frozenset({"WebApp"})

#: A path that simply has no endpoint. Not "introspection disabled" — nothing answered.
NOT_FOUND_STATUS = 404

#: The two root operation kinds this module maps. Subscriptions are not requested by the
#: pinned query (they need a transport upgrade, which is a different rung).
ROOT_KINDS: tuple[str, ...] = ("query", "mutation")

# --- defensive caps (a schema is untrusted third-party input of unbounded size) ---
MAX_SEEDS = 25
MAX_TYPES = 500               # ObjectType nodes per schema
MAX_OPERATIONS = 300          # root fields total per run
MAX_ARGS_PER_FIELD = 50
MAX_RESPONSE_CHARS = 4 * 1024 * 1024
MAX_NAME_CHARS = 128
MAX_KIND_CHARS = 32

#: Conservative fqdn shape, mirroring ``http_probe``: rejects whitespace, raw unicode
#: (punycode ``xn--`` passes) and anything email-shaped, so a junk seed can never be
#: interpolated into a request URL.
_FQDN_RE = re.compile(
    r"^[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?)+\Z"
)

#: The GraphQL name grammar (``/[_A-Za-z][_0-9A-Za-z]*/``). It is also exactly what the
#: pinned ``obj:<name>`` / ``op:…#<field>`` / ``param:<op>#<name>`` id forms can carry, so
#: a name that does not match is rejected rather than escaped.
_NAME_RE = re.compile(r"^[_A-Za-z][_0-9A-Za-z]*\Z")

#: A ``__TypeKind`` enum member (``OBJECT``, ``INPUT_OBJECT``, …).
_KIND_RE = re.compile(r"^[A-Za-z_]+\Z")

#: Shapes that mean "this is a live secret, not an identifier". A GraphQL name cannot hold
#: ``.``/``+``/``/``/``=``, so in practice only the long-hex branch can ever match — but a
#: schema is untrusted input, and a matching name is dropped rather than stored
#: (``safety-model.md`` §5).
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
    so the ids this module writes edges against are byte-identical to ``http_probe``'s.
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
        host = canonical_host(literal)
    else:
        if ":" in authority:
            return None  # explicit port: see the docstring
        host = canonical_host(authority)
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


def looks_secret(text: str) -> bool:
    """True for a value whose shape says "live secret" rather than "identifier"."""

    return bool(text) and bool(_SECRET_SHAPED_RE.match(text))


def clean_name(raw) -> str:
    """A GraphQL name safe for the pinned id forms, or ``""``.

    Rejects anything outside ``/[_A-Za-z][_0-9A-Za-z]*/`` — which is both the protocol's
    own grammar and the character set the ``obj:``/``op:…#``/``param:…#`` ids can carry.
    """

    if not isinstance(raw, str):
        return ""
    text = raw.strip()
    if not text or len(text) > MAX_NAME_CHARS:
        return ""
    return text if _NAME_RE.match(text) else ""


def clean_kind(raw) -> str:
    """A ``__TypeKind`` member as text (``OBJECT``, ``SCALAR``, …), or ``""``."""

    if not isinstance(raw, str):
        return ""
    text = raw.strip()[:MAX_KIND_CHARS]
    return text if _KIND_RE.match(text) else ""


def named_type(ref) -> str:
    """The unwrapped name of a type reference, or ``""``.

    ``NON_NULL``/``LIST`` wrappers carry a ``null`` name and their member under
    ``ofType``, so ``[Account!]`` reads as ``Account``. The pinned query asks for exactly
    one level of ``ofType``, so a doubly-wrapped reference (``[Account!]!``) can read as
    ``""`` — recorded as unknown rather than guessed at.
    """

    if not isinstance(ref, dict):
        return ""
    name = clean_name(ref.get("name"))
    if name:
        return name
    inner = ref.get("ofType")
    return clean_name(inner.get("name")) if isinstance(inner, dict) else ""


def root_type_name(schema: dict, kind: str) -> str:
    """The declared name of the ``query``/``mutation`` root type, or ``""``."""

    entry = schema.get(f"{kind}Type")
    return clean_name(entry.get("name")) if isinstance(entry, dict) else ""


def declared_fields(type_entry) -> list[dict]:
    """A type's ``fields`` array as a plain list of dicts (anything else reads empty).

    A ``SCALAR``/``ENUM``/``UNION`` type has ``fields: null`` by specification, which is a
    well-formed answer meaning "no fields", not a malformed one.
    """

    if not isinstance(type_entry, dict):
        return []
    raw = type_entry.get("fields")
    return [f for f in raw if isinstance(f, dict)] if isinstance(raw, list) else []


def parse_json(text: str):
    """Parse a response body as JSON, or ``None``. Never raises.

    The cheap ``{`` check keeps an HTML error page out of the parser entirely; a response
    is untrusted input, so a nesting bomb (``RecursionError``) is a non-event rather than a
    crashed run.
    """

    if not text or not text.lstrip()[:1] == "{":
        return None
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        return None


def schema_of(body) -> dict | None:
    """The ``data.__schema`` object of a well-formed introspection response, or ``None``."""

    if not isinstance(body, dict):
        return None
    data = body.get("data")
    if not isinstance(data, dict):
        return None
    schema = data.get("__schema")
    return schema if isinstance(schema, dict) else None


def error_count(body) -> int:
    """How many GraphQL ``errors`` the response carried (0 when it carried none)."""

    if not isinstance(body, dict):
        return 0
    errors = body.get("errors")
    return len(errors) if isinstance(errors, list) else (1 if errors else 0)


@dataclass
class _Answer:
    """One gated POST that returned a body, and the binding that authorized it."""

    url: str
    path: str
    binding: ScopeBinding
    text: str


@dataclass
class _Schema:
    """A recovered schema plus everything the emitters read off it."""

    target: _Target
    url: str
    route_id: str
    schema: dict
    binding: ScopeBinding
    now: datetime
    evidence: list[EvidenceRef] = field(default_factory=list)
    #: ``obj:<name>`` nodes actually emitted, so a ``references_object`` edge can never
    #: point at a node that does not exist.
    objects: set[str] = field(default_factory=set)


@register
class GraphqlIntrospectModule(Module):
    """Recover an in-scope ``WebApp``'s GraphQL contract by read-only introspection."""

    ctx: ModuleContext

    name = "graphql_introspect"
    produces = ("Operation", "ObjectType", "Parameter")
    active = True

    #: Set when a cap deferred work, which also stops the run spending rate budget on
    #: further WebApps. Distinct from the seed cap, which defers *later seeds* and must not
    #: stop the ones that were kept.
    _capped = False

    def run(self, seeds: list) -> dict:
        """Walk the fixed candidate-path list per WebApp. Gate, one POST, parse, continue."""

        # Self-checks. The verb must be on the closed whitelist AND be an active verb (this
        # module sends traffic to the target), the human-gated fallback must still be
        # human-gated (so this module is never the thing that quietly promotes it), and the
        # pinned document must still be an anonymous shorthand *query*.
        verbs.assert_schedulable(VERB)
        assert verbs.is_active(VERB), f"{VERB!r} must be an active verb"
        assert FIELD_SUGGESTION_VERB in verbs.HUMAN_GATED, \
            "field suggestion must stay human-gated; this module never auto-runs it"
        assert INTROSPECTION_QUERY.startswith("{__schema{"), \
            "the pinned document must be an anonymous shorthand __schema query"

        self._capped = False
        summary: dict = {
            "module": self.name,
            "verb": VERB,
            "active": True,
            "targets": [],
            "requests": 0,
            "schemas": 0,
            "operations": 0,
            "object_types": 0,
            "parameters": 0,
            "edges": 0,
            "not_found": 0,
            "introspection_disabled": [],
            # Explicit, not merely absent: recovering a schema by field suggestion is a
            # human-gated verb and is never auto-run from here.
            "field_suggestion_fallback": False,
            "dropped_secret_shaped": 0,
            "refused": [],
            "errors": [],
            "truncated": False,
            "caps": [],
        }

        targets = self._targets(seeds, summary)
        summary["targets"] = [t.webapp_id for t in targets]
        if not targets:
            self.log.info("graphql_introspect: no WebApp seeds to introspect; nothing to do")
            return summary

        # No pre-flight scope/snapshot check on purpose: gate_active is the single
        # chokepoint and writes the ALLOW/REFUSE record for every attempt, so a disabled,
        # unsnapshotted, stale or out-of-scope run is refused there and stays auditable.
        for target in targets:
            if self._capped:
                break  # a cap is already spent; stop spending rate budget too
            self._discover(target, summary)

        self.log.info(
            "graphql_introspect: done — %d WebApp(s), %d request(s), %d schema(s), "
            "%d Operation(s), %d ObjectType(s), %d Parameter(s), %d edge(s), "
            "%d disabled, %d refused, %d error(s)",
            len(targets), summary["requests"], summary["schemas"], summary["operations"],
            summary["object_types"], summary["parameters"], summary["edges"],
            len(summary["introspection_disabled"]), len(summary["refused"]),
            len(summary["errors"]),
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
                self.log.info("graphql_introspect: ignoring unusable WebApp seed %r", raw)
                continue
            if target.webapp_id in seen:
                continue
            seen.add(target.webapp_id)
            out.append(target)
        if len(out) > MAX_SEEDS:
            self.log.warning("graphql_introspect: %d WebApp seed(s) exceeds the %d cap; "
                             "deferring the rest", len(out), MAX_SEEDS)
            summary["truncated"] = True
            self._note_cap(summary, f"WebApp seeds beyond {MAX_SEEDS}")
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
        """Walk :data:`CANDIDATE_PATHS` until one endpoint answers with a schema."""

        for path in CANDIDATE_PATHS:
            if self._capped:
                return
            url = f"{target.scheme}://{target.authority}{path}"
            answer = self._gated_post(target, url, path, summary)
            if answer is None:
                continue
            schema = self._read_schema(answer, summary)
            if schema is None:
                continue
            summary["schemas"] += 1
            self._ingest(target, answer, schema, summary)
            # One schema is the contract. The rest of the list is budget left unspent.
            return
        self.log.info("graphql_introspect: no introspectable GraphQL endpoint under %s",
                      target.webapp_id)

    def _gated_post(self, target: _Target, url: str, path: str,
                    summary: dict) -> _Answer | None:
        """Gate, then send exactly one POST. ``None`` on refusal or an unusable answer.

        A :class:`GateRefused` is never swallowed into a post-anyway path: it ends this one
        attempt, logged and counted, and the walk continues to the next path.
        """

        try:
            binding = self.ctx.gate_active(target.host, VERB)
        except GateRefused as exc:
            self.log.info("graphql_introspect: skipping POST %s: %s", url, exc.reason)
            summary["refused"].append({"url": url, "verb": VERB, "reason": exc.reason})
            return None

        resp, err = self._request(url)
        summary["requests"] += 1  # the budget was debited whether or not the answer is usable
        if err:
            self.log.warning("graphql_introspect: POST %s failed (%s); skipping", url, err)
            summary["errors"].append({"url": url, "error": err})
            return None

        status = getattr(resp, "status_code", None)
        if not isinstance(status, int) or isinstance(status, bool) or status != 200:
            # 404 means no endpoint lives here. Any other refusal (400/403/429/5xx) is the
            # server declining introspection: recorded as negative space and backed off
            # from, never retried in another shape.
            if status == NOT_FOUND_STATUS:
                summary["not_found"] += 1
                self.log.debug("graphql_introspect: no endpoint at %s (404)", url)
            else:
                self._note_disabled(url, f"status:{status!r}", summary)
            return None

        text = self._body(resp)
        if not text:
            self._note_disabled(url, "empty body", summary)
            return None
        if len(text) > MAX_RESPONSE_CHARS:
            self.log.warning("graphql_introspect: %s body is %d chars (cap %d); not parsed",
                             url, len(text), MAX_RESPONSE_CHARS)
            summary["errors"].append({"url": url, "error": "response exceeds size cap"})
            self._note_cap(summary, f"response body beyond {MAX_RESPONSE_CHARS} chars")
            return None
        return _Answer(url=url, path=path, binding=binding, text=text)

    def _request(self, url: str):
        """Send one POST carrying only the pinned query. Returns ``(response, error)``.

        Never raises, never retries, never follows a redirect, and no other sender is
        reachable from here — recovering a schema is this one document and nothing else.
        """

        try:
            resp = requests.post(
                url,
                json={"query": INTROSPECTION_QUERY},
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

    def _read_schema(self, answer: _Answer, summary: dict) -> dict | None:
        """The ``__schema`` object of one answer, or ``None`` with the reason recorded.

        Introspection being disabled is a **terminal** answer for this path: nothing is
        emitted, the fact is recorded, and no field-suggestion fallback exists here.
        """

        body = parse_json(answer.text)
        errors = error_count(body)
        if errors:
            # Per-field error text is the server's own string; the count is the fact, and
            # keeping the strings out means nothing server-chosen can land in the summary.
            self._note_disabled(answer.url, f"{errors} schema error(s)", summary)
            return None
        schema = schema_of(body)
        if schema is None:
            self._note_disabled(answer.url, "no __schema in response", summary)
            return None
        return schema

    def _note_disabled(self, url: str, reason: str, summary: dict) -> None:
        """Record that this endpoint did not hand over a schema. Emit nothing.

        The recovery verb for a blocked endpoint (``graphql-field-suggestion``) is
        human-gated, so this is where the walk *stops* rather than escalates.
        """

        self.log.info("graphql_introspect: introspection unavailable at %s (%s); "
                      "not falling back to the human-gated %s verb",
                      url, reason, FIELD_SUGGESTION_VERB)
        summary["introspection_disabled"].append({"url": url, "reason": reason})

    def _note_cap(self, summary: dict, what: str) -> None:
        """Record that a cap deferred work. Logged once per cap, never silent."""

        if what not in summary["caps"]:
            self.log.warning("graphql_introspect: truncated — %s deferred to a later cycle",
                             what)
            summary["caps"].append(what)
        summary["truncated"] = True

    def _truncate(self, summary: dict, what: str) -> None:
        """A cap that also stops this run spending further rate budget."""

        self._note_cap(summary, what)
        self._capped = True

    def _evidence(self, url: str, text: str) -> list[EvidenceRef]:
        """Content-address the raw schema JSON so every typed fact below is replayable.

        The response is the proof, so it is stored whole — in the evidence store, where
        encryption-at-rest and the sensitivity policy apply — and never summarized into
        attrs. An unwritable store degrades to "no evidence ref", not a failed run.
        """

        try:
            return [self.ctx.evidence.put_text(text, region=f"{SOURCE}:POST {url}")]
        except OSError as exc:
            self.log.warning("graphql_introspect: evidence store unavailable for %s: %s",
                             url, exc)
            return []

    # --- parse + emit ------------------------------------------------------
    def _ingest(self, target: _Target, answer: _Answer, schema: dict,
                summary: dict) -> None:
        """Fold one recovered schema into the graph: types first, then root fields."""

        # The gate already guarantees this; assert it so no future refactor can emit a node
        # for a value that was not in scope at observation time (I2/I3).
        assert answer.binding.verdict == Verdict.IN_SCOPE, \
            "the only binding used here is the one gate_active returned"

        recovered = _Schema(
            target=target,
            url=answer.url,
            route_id=make_route_id(target.webapp_id, answer.path),
            schema=schema,
            binding=answer.binding,
            now=self.ctx.clock_now(),
            evidence=self._evidence(answer.url, answer.text),
        )
        self.log.info("graphql_introspect: %s answered introspection with a schema",
                      answer.url)

        types = schema.get("types")
        types = [t for t in types if isinstance(t, dict)] if isinstance(types, list) else []
        self._emit_object_types(recovered, types, summary)
        self._emit_operations(recovered, types, summary)

    def _emit_object_types(self, recovered: _Schema, types: list[dict],
                           summary: dict) -> None:
        """One ``ObjectType`` per non-introspection type the schema declares."""

        for entry in types:
            if len(recovered.objects) >= MAX_TYPES:
                self._truncate(summary, f"schema types beyond the {MAX_TYPES} cap")
                return
            name = clean_name(entry.get("name"))
            if not name or name.startswith("__"):
                continue  # unusable, or the introspection meta-schema itself
            if looks_secret(name):
                self._drop_secret_shaped("type name", name, summary)
                continue
            node_id = f"obj:{name}"
            if node_id in recovered.objects:
                continue  # a duplicate declaration is one type
            self.ctx.graph.upsert_node(make_node(
                "ObjectType", node_id,
                binding=recovered.binding,
                source=SOURCE,
                now=recovered.now,
                attrs={
                    "active_probed": True,
                    "kind": clean_kind(entry.get("kind")),
                    "field_count": len(declared_fields(entry)),
                },
                evidence=recovered.evidence,
                rule_id=RULE_ID,
                rule_version=RULE_VERSION,
                log_odds=SCHEMA_LOG_ODDS,
                # A public, unauthenticated schema document: these are type *names*, not
                # instance data, and no Credential/Token node is minted anywhere here.
                sensitivity=Sensitivity.S0,
                coverage={"enumerated": True},
                data_subject="none",
            ))
            recovered.objects.add(node_id)
            summary["object_types"] += 1

    def _emit_operations(self, recovered: _Schema, types: list[dict],
                         summary: dict) -> None:
        """One ``Operation`` per root query/mutation field, with its Parameters."""

        by_name: dict[str, dict] = {}
        for entry in types:
            name = clean_name(entry.get("name"))
            if name:
                by_name.setdefault(name, entry)

        for kind in ROOT_KINDS:
            root = root_type_name(recovered.schema, kind)
            if not root:
                continue  # a schema need not declare a mutation root
            for declared in declared_fields(by_name.get(root)):
                if summary["operations"] >= MAX_OPERATIONS:
                    self._truncate(summary,
                                   f"root fields beyond the {MAX_OPERATIONS} cap")
                    return
                name = clean_name(declared.get("name"))
                if not name:
                    continue
                if looks_secret(name):
                    self._drop_secret_shaped(f"{kind} field name", name, summary)
                    continue
                self._emit_operation(recovered, kind, name, declared, summary)

    def _emit_operation(self, recovered: _Schema, kind: str, name: str, declared: dict,
                        summary: dict) -> None:
        """Emit one root field as an ``Operation`` — mapped, never executed."""

        op_id = operation_id("POST", recovered.route_id, field=name)
        returns = named_type(declared.get("type"))
        self.ctx.graph.upsert_node(make_node(
            "Operation", op_id,
            binding=recovered.binding,
            source=SOURCE,
            now=recovered.now,
            attrs={
                "active_probed": True,      # the schema came from a gated touch
                "graphql_kind": kind,       # declared, NOT dispatched
                "field": name,
                "return_type": returns,
                "webapp": recovered.target.webapp_id,
            },
            evidence=recovered.evidence,
            rule_id=RULE_ID,
            rule_version=RULE_VERSION,
            log_odds=SCHEMA_LOG_ODDS,
            sensitivity=Sensitivity.S0,
            # The full *declared* argument set is what param_mined means for a contract
            # read; flow_mapped stays explicitly False — a multi-step flow needs
            # own-session observation, not a schema (``SPEC.md`` §4.2).
            coverage={"param_mined": True, "flow_mapped": False},
            data_subject="none",
        ))
        summary["operations"] += 1
        # GraphQL serves its whole surface from one path, so the WebApp exposes the
        # operation directly; there is no intermediate Route node to hang it from.
        self.ctx.graph.upsert_edge(make_edge(
            "exposes", recovered.target.webapp_id, op_id,
            binding=recovered.binding, source=SOURCE, now=recovered.now,
            attrs={"active_probed": True}, log_odds=SCHEMA_LOG_ODDS,
        ))
        summary["edges"] += 1

        returns_id = f"obj:{returns}" if returns else ""
        if returns_id and returns_id in recovered.objects:
            self.ctx.graph.upsert_edge(make_edge(
                "references_object", op_id, returns_id,
                binding=recovered.binding, source=SOURCE, now=recovered.now,
                attrs={"active_probed": True}, log_odds=SCHEMA_LOG_ODDS,
            ))
            summary["edges"] += 1

        self._emit_parameters(recovered, op_id, declared, summary)

    def _emit_parameters(self, recovered: _Schema, op_id: str, declared: dict,
                         summary: dict) -> None:
        """One ``Parameter`` per declared argument, taken by its Operation."""

        raw_args = declared.get("args")
        args = [a for a in raw_args if isinstance(a, dict)] if isinstance(raw_args, list) else []
        if len(args) > MAX_ARGS_PER_FIELD:
            self._note_cap(summary, f"arguments beyond {MAX_ARGS_PER_FIELD} per field")
            args = args[:MAX_ARGS_PER_FIELD]
        seen: set[str] = set()
        for arg in args:
            name = clean_name(arg.get("name"))
            if not name or name in seen:
                continue  # de-duplicated by name: the pinned id form cannot fork on one
            if looks_secret(name):
                self._drop_secret_shaped("argument name", name, summary)
                continue
            seen.add(name)
            param_id = parameter_id(op_id, name, "arg")
            self.ctx.graph.upsert_node(make_node(
                "Parameter", param_id,
                binding=recovered.binding,
                source=SOURCE,
                now=recovered.now,
                attrs={
                    "active_probed": True,
                    "name": name,
                    "in": "argument",
                    "type": named_type(arg.get("type")),
                },
                evidence=recovered.evidence,
                rule_id=RULE_ID,
                rule_version=RULE_VERSION,
                log_odds=SCHEMA_LOG_ODDS,
                sensitivity=Sensitivity.S0,
                coverage={"enumerated": True},  # declared and typed; no value was ever sent
                data_subject="none",
            ))
            self.ctx.graph.upsert_edge(make_edge(
                "takes", op_id, param_id,
                binding=recovered.binding, source=SOURCE, now=recovered.now,
                attrs={"active_probed": True}, log_odds=SCHEMA_LOG_ODDS,
            ))
            summary["parameters"] += 1
            summary["edges"] += 1

    def _drop_secret_shaped(self, what: str, value: str, summary: dict) -> None:
        """Drop a secret-shaped name outright: not an attr, not an id, not a log line.

        Dropping rather than redacting is deliberate — the name would otherwise have to
        appear in the node id, and a redacted id is neither a fact nor a secret.
        """

        self.log.warning("graphql_introspect: dropping secret-shaped %s %s", what,
                         redact(value))
        summary["dropped_secret_shaped"] += 1


__all__ = [
    "GraphqlIntrospectModule", "VERB", "SOURCE", "RULE_ID", "RULE_VERSION",
    "FIELD_SUGGESTION_VERB", "CANDIDATE_PATHS", "INTROSPECTION_QUERY", "SCHEMA_LOG_ODDS",
    "MAX_ARGS_PER_FIELD", "MAX_OPERATIONS", "MAX_SEEDS", "MAX_TYPES",
    "authority_of", "clean_kind", "clean_name", "declared_fields", "error_count",
    "looks_secret", "named_type", "parse_json", "parse_webapp", "root_type_name",
    "schema_of",
]
