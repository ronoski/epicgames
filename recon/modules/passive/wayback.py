"""Passive historical URL mining from the Internet Archive's Wayback CDX API.

Archives are a canonical passive-first source (``docs/SPEC.md`` §5.4/§6.2.6,
``safety-model.md`` §4): the Internet Archive already crawled Epic's web surface, so its
CDX index leaks vhosts and path shapes that existed at capture time without anyone sending
a packet at Epic. ``web.archive.org`` is a **third-party aggregator**, so this module is
strictly passive — it never calls :meth:`ModuleContext.gate_active` and never debits the
unified per-target Epic rate ledger (``safety-model.md`` §4 keys that ledger by Epic
target; the Internet Archive is not one).

The query needs no scope gate because no in-scope asset is touched. **Retention is what is
gated:** an archived URL can name *any* host the crawler happened to follow, so the host of
every row is bound against the current policy snapshot and only an ``in_scope`` verdict is
emitted. ``out_of_scope`` / ``prefilter_only`` / ``adjudication_pending`` hosts are counted
and logged as negative space, never written — ``scope != ownership`` (§2), and a
``prefilter_only`` host capped at ``enumerated`` is the seeds/ownership path's business, not
an archive miner's. Retention also requires a current, non-stale snapshot (I1/I12), so with
no snapshot — or a stale one — the module queries nothing and says why in its summary.

What it emits, per archived URL: a ``WebApp`` for ``<scheme>://<host>`` and a ``Route`` for
the *path template* (numeric / uuid / otherwise-opaque segments normalized to ``{id}``),
joined by the declared ``exposes`` edge. Templates are deduplicated in memory before
emitting so one node is written per distinct shape rather than one per capture.

**These are historical, not live.** A capture proves a URL answered *once*, at capture
time; capture-time is not creation-time and says nothing about today
(``domains/non-binary.md`` D6). So nodes land at ``log_odds=0.0`` (``observed``, p=0.5) with
``attrs["historical"] = True`` and the earliest capture timestamp, and they deliberately do
**not** carry ``active_probed`` — confirming one live is a scope-gated active module's job,
and that corroboration is what may raise confidence from here.

Privacy and secret hygiene happen **before** storage (``safety-model.md`` §5/§6), which
matters because an archived URL is a notorious carrier of both:

* the query string is dropped outright — it is never parsed, stored or evidenced, so an
  ``?access_token=`` / ``?email=`` that the crawler captured cannot reach an attr or an id;
* a URL with userinfo or an ``@`` anywhere in its path is skipped rather than redacted — an
  ``other``-subject datum must not be collected when it can simply be dropped;
* any long opaque path segment (uuid, 32+ hex, JWT-shaped, long base64url blob) collapses
  to ``{id}``, so a credential that once appeared *in a path* cannot become part of a node
  id either. Nothing here is ever a ``Credential``/``Token`` node, so no secret value is
  retained at all and :func:`recon.evidence.redact` has nothing to redact.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urlsplit

import requests

from ... import verbs
from ...factory import make_edge, make_node
from ...models import EvidenceRef, ScopeBinding, Sensitivity, Verdict
from ...scope import classify
from ...urls import (  # the single implementation; re-exported for the module's API
    ID_PLACEHOLDER, canonical_host, is_opaque_segment, path_template, route_id,
    webapp_id,
)
from ..base import Module, ModuleContext, register

#: Wayback CDX query. Built literally rather than via ``params=`` so the emitted URL is
#: exact and reviewable. ``collapse=urlkey`` asks the index for one row per distinct URL
#: and ``limit`` caps the response server-side (it is re-enforced client-side below).
ARCHIVE_HOST = "web.archive.org"
CDX_URL = (
    "https://web.archive.org/cdx/search/cdx"
    "?url={host}/*&output=json&fl=original,timestamp&collapse=urlkey&limit={limit}"
)

#: Whitelisted verb for this module (``verbs.ALLOWED``, deliberately NOT in ``verbs.ACTIVE``).
VERB = "passive-collect"

SOURCE = "wayback"

#: A capture proves historical presence only, so the fact starts at p=0.5 and waits for a
#: live, scope-gated observation to corroborate it.
ARCHIVE_LOG_ODDS = 0.0

#: Node types this module accepts as seeds; anything else is ignored.
SEED_NODE_TYPES = frozenset({"Domain", "DNSName"})

_SEED_ID_PREFIXES = ("domain:", "dns:")
_FOREIGN_ID_PREFIXES = (
    "org:", "bu:", "net:", "asn:", "host:", "svc:", "web:", "route:", "op:",
    "param:", "auth:", "cred:", "tok:", "obj:", "flow:", "art:", "ev:", "hyp:",
)

#: Conservative fqdn shape, shared by seeds and archived hosts. Rejects whitespace, raw
#: unicode (punycode ``xn--`` passes) and anything email-shaped, so a junk CDX row can
#: never mint a junk node id or be interpolated into the query URL.
_FQDN_RE = re.compile(
    r"^[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?)+$"
)

#: CDX capture stamps are ``YYYYMMDDhhmmss``; anything else is dropped rather than stored.
_CDX_TS_RE = re.compile(r"^\d{14}$")

#: Printable, space-free ASCII. A path outside it is a mangled index row, not a route.
_SAFE_PATH_RE = re.compile(r"^[\x21-\x7e]*$")

# --- opaque path segments: identifiers, not route structure ---
_NUMERIC_RE = re.compile(r"^\d+$")
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)
_HEX_BLOB_RE = re.compile(r"^[0-9a-f]{32,}$", re.IGNORECASE)
_JWT_RE = re.compile(r"^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$")
_LONG_BLOB_RE = re.compile(r"^[A-Za-z0-9_-]{40,}$")
#: An unbroken alphanumeric run of 20+ characters containing a digit: a base62 id, hash or
#: token, never a route name (``forgot-password-confirmation`` keeps its separators).
_ALNUM_ID_RE = re.compile(r"^(?=.*\d)[A-Za-z0-9]{20,}$")

#: Placeholder every opaque segment collapses to.
ID_PLACEHOLDER = "{id}"

# --- defensive caps (one busy apex has millions of archived URLs) ---
MAX_HOSTS = 25
MAX_ROWS = 500
MAX_TEMPLATES_PER_HOST = 200
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_PATH_SEGMENTS = 12
MAX_TEMPLATE_CHARS = 200


def _is_opaque(segment: str) -> bool:
    """True if ``segment`` is an identifier/blob rather than route structure."""

    return bool(
        _NUMERIC_RE.match(segment)
        or _UUID_RE.match(segment)
        or _HEX_BLOB_RE.match(segment)
        or _JWT_RE.match(segment)
        or _LONG_BLOB_RE.match(segment)
        or _ALNUM_ID_RE.match(segment)
    )



def parse_archived_url(original: str) -> tuple[str, str, str] | None:
    """Split one CDX ``original`` URL into ``(scheme, host, template)``.

    Returns ``None`` for anything that is not a usable ``http(s)`` URL on a hostname: a
    non-web scheme, a mangled row, a userinfo/``@`` carrier, an unparsable host, or a raw
    IP literal (an archived IP URL is the network/http-probe path's business, not a vhost).
    The query string and fragment are discarded by construction — only ``.path`` is read.
    """

    try:
        parts = urlsplit((original or "").strip())
        scheme = (parts.scheme or "").lower()
        netloc, hostname, path = parts.netloc, parts.hostname, parts.path
    except ValueError:
        return None  # e.g. a mangled IPv6 literal
    if scheme not in ("http", "https"):
        return None
    if "@" in netloc:
        return None  # userinfo may be a credential or another person's identifier
    host = canonical_host(hostname or "")
    if not host or len(host) > 253 or not _FQDN_RE.match(host) or classify(host) == "ip":
        return None
    template = path_template(path)
    if not template:
        return None
    return scheme, host, template


@register
class WaybackModule(Module):
    """Mine the Wayback CDX index into historical ``WebApp``/``Route`` nodes."""

    ctx: ModuleContext

    name = "wayback"
    produces = ("WebApp", "Route")
    active = False

    def run(self, seeds: list) -> dict:
        """Query CDX once per distinct seed host and emit the in-scope shapes it reveals."""

        # Self-check: this module's verb must be on the closed whitelist and must NOT be an
        # active verb (a passive module that reached for one would be a safety bug).
        verbs.assert_schedulable(VERB)
        assert not verbs.is_active(VERB), "wayback is passive; its verb must not be active"

        summary: dict = {
            "module": self.name,
            "verb": VERB,
            "active": False,
            "hosts": [],
            "queried": 0,
            "rows_seen": 0,
            "urls_parsed": 0,
            "urls_skipped": 0,
            "webapps": 0,
            "routes": 0,
            "edges": 0,
            "emitted": 0,
            "dropped_out_of_scope": 0,
            "dropped_by_verdict": {},
            "errors": [],
            "truncated": False,
        }
        self._emitted_ids: set[str] = set()
        self._verdict_counted: set[str] = set()

        # I1/I12: nothing may be retained against a missing or stale policy snapshot, so
        # there is no point spending a CDX query either.
        snapshot = self.ctx.snapshot
        if snapshot is None:
            summary["blocked"] = "no scope snapshot (verify live policy first)"
            self.log.warning("wayback: %s", summary["blocked"])
            return summary
        if snapshot.is_stale(self.ctx.clock_now()):
            summary["blocked"] = "scope snapshot is stale; re-fetch + re-bind required"
            self.log.warning("wayback: %s", summary["blocked"])
            return summary

        hosts = self._hosts(seeds)
        summary["hosts"] = hosts
        if not hosts:
            self.log.info("wayback: no Domain/DNSName seeds to mine; nothing to do")
            return summary

        for host in hosts:
            # web.archive.org is a THIRD-PARTY archive: its politeness budget is
            # separate and never debits the target's ledger (safety-model.md §4).
            if not self.ctx.spend_third_party(ARCHIVE_HOST):
                self.log.info("wayback: third-party budget exhausted; deferring %s", host)
                summary["errors"].append({"host": host,
                                          "error": "third-party budget exhausted"})
                summary["truncated"] = True
                break
            summary["queried"] += 1
            body, err = self._fetch(host)
            if err:
                self.log.warning("wayback: %s/* unusable (%s); skipping", host, err)
                summary["errors"].append({"host": host, "error": err})
                continue

            rows, err = self._rows(body)
            if err:
                self.log.warning("wayback: %s/* unusable (%s); skipping", host, err)
                summary["errors"].append({"host": host, "error": err})
                continue
            summary["rows_seen"] += len(rows)

            apps, routes = self._collect(rows, host, summary)
            if not apps:
                self.log.info("wayback: %s/* -> %d row(s), no usable archived URL",
                              host, len(rows))
                continue

            # One evidence blob per CDX response; every node derived from it points at
            # this sha, so the query and its answer stay replayable.
            evidence = self._evidence(host, body)
            emitted = self._emit(apps, routes, evidence, summary)
            self.log.info(
                "wayback: %s/* -> %d row(s), %d template(s), %d node(s) emitted in-scope",
                host, len(rows), len(routes), emitted,
            )

        self.log.info(
            "wayback: done — %d host(s) queried, %d archived URL(s) parsed, %d WebApp(s), "
            "%d Route(s), %d edge(s), %d host(s) dropped out-of-scope %s",
            summary["queried"], summary["urls_parsed"], summary["webapps"],
            summary["routes"], summary["edges"], summary["dropped_out_of_scope"],
            summary["dropped_by_verdict"] or "{}",
        )
        return summary

    # --- seeds -------------------------------------------------------------
    def _hosts(self, seeds: list) -> list[str]:
        """Distinct hostnames to query, in seed order. Tolerates an empty list."""

        out: list[str] = []
        for seed in seeds or []:
            host = canonical_host(self._seed_host(seed).lstrip("*."))
            if not host or classify(host) == "ip" or not _FQDN_RE.match(host):
                continue  # CDX is queried by name; raw IPs and junk have no url prefix
            if host not in out:
                out.append(host)
        if len(out) > MAX_HOSTS:
            self.log.warning("wayback: %d seed host(s) exceeds the %d cap; deferring the rest",
                             len(out), MAX_HOSTS)
            out = out[:MAX_HOSTS]
        return out

    @staticmethod
    def _seed_host(seed) -> str:
        """Pull a hostname out of a graph Node id, or out of a plain-string seed."""

        raw = getattr(seed, "id", None)
        if raw is None and isinstance(seed, str):
            raw = seed
        if not isinstance(raw, str) or not raw.strip():
            return ""
        node_type = getattr(seed, "type", "")
        if node_type and node_type not in SEED_NODE_TYPES:
            return ""
        for prefix in _SEED_ID_PREFIXES:
            if raw.startswith(prefix):
                return raw[len(prefix):]
        if raw.startswith(_FOREIGN_ID_PREFIXES):
            return ""  # some other node kind slipped into the seed list
        return raw

    # --- fetch / parse -----------------------------------------------------
    def _fetch(self, host: str) -> tuple[str, str]:
        """GET the CDX index for ``host``. Returns ``(body, error)`` and never raises."""

        url = CDX_URL.format(host=host, limit=MAX_ROWS)
        try:
            resp = requests.get(
                url,
                headers={"User-Agent": self.ctx.user_agent, "Accept": "application/json"},
                timeout=self.ctx.timeout,
            )
        except requests.RequestException as exc:
            return "", f"request failed: {type(exc).__name__}"
        except Exception as exc:  # unknown transport layer; a module never crashes the run
            return "", f"unexpected transport error: {type(exc).__name__}"

        status = getattr(resp, "status_code", 0)
        if status != 200:
            # The archive rate-limits with 429/503 under load. Back off, never retry-hammer.
            return "", f"HTTP {status}"
        body = getattr(resp, "text", "") or ""
        if len(body.encode("utf-8", "replace")) > MAX_RESPONSE_BYTES:
            return "", f"response larger than the {MAX_RESPONSE_BYTES}-byte cap"
        return body, ""

    @staticmethod
    def _rows(body: str) -> tuple[list[tuple[str, str]], str]:
        """Parse a CDX JSON response into ``[(original, timestamp), …]``.

        CDX answers with an array of arrays whose **first row is the field header**; an
        empty body is its documented "no captures" answer, not an error. The row cap is
        re-enforced here in case the index ignores ``limit=``.
        """

        if not (body or "").strip():
            return [], ""
        try:
            rows = json.loads(body)
        except (ValueError, TypeError):
            return [], "response was not valid JSON"
        if not isinstance(rows, list):
            return [], "response JSON was not a list of CDX rows"

        out: list[tuple[str, str]] = []
        for row in rows:
            if not isinstance(row, list) or len(row) < 2:
                continue
            original, timestamp = row[0], row[1]
            if not isinstance(original, str) or not isinstance(timestamp, str):
                continue
            if original == "original":
                continue  # the ``fl=`` header row
            out.append((original, timestamp))
            if len(out) >= MAX_ROWS:
                break
        return out, ""

    def _collect(self, rows: list[tuple[str, str]], queried: str,
                 summary: dict) -> tuple[dict, dict]:
        """Fold one host's CDX rows into deduplicated WebApp/Route candidates.

        Returns ``({webapp_id: {...}}, {route_id: {...}})``. Templates are deduplicated
        here, before anything is written, and the **earliest** capture timestamp wins so
        re-running over the same response produces byte-identical attrs (a differing
        scalar attr is a contradiction that forks, per I11 — not something to invent).
        """

        apps: dict[str, dict] = {}
        routes: dict[str, dict] = {}
        for original, timestamp in rows:
            parsed = parse_archived_url(original)
            if parsed is None:
                summary["urls_skipped"] += 1
                continue
            summary["urls_parsed"] += 1
            scheme, host, template = parsed
            ts = timestamp if _CDX_TS_RE.match(timestamp) else ""

            app_id = webapp_id(scheme, host)
            rt_id = route_id(app_id, template)
            if rt_id not in routes and len(routes) >= MAX_TEMPLATES_PER_HOST:
                summary["truncated"] = True
                self.log.warning("wayback: %s/* hit the %d-template cap; requeue for the rest",
                                 queried, MAX_TEMPLATES_PER_HOST)
                break
            self._fold(apps, app_id, {"host": host, "scheme": scheme}, ts)
            self._fold(routes, rt_id, {"host": host, "template": template,
                                       "webapp": app_id}, ts)
        return apps, routes

    @staticmethod
    def _fold(bucket: dict, key: str, fields: dict, ts: str) -> None:
        """Insert or update one candidate, keeping the earliest capture timestamp."""

        entry = bucket.setdefault(key, {**fields, "ts": ts})
        if ts and (not entry["ts"] or ts < entry["ts"]):
            entry["ts"] = ts

    def _evidence(self, host: str, body: str) -> list[EvidenceRef]:
        """Content-address the raw CDX response. An unwritable store is not fatal."""

        region = f"wayback:cdx:{host}/*"
        try:
            return [self.ctx.evidence.put_text(body, region=region)]
        except OSError as exc:
            self.log.warning("wayback: evidence store unavailable for %s: %s", host, exc)
            return []

    # --- emit --------------------------------------------------------------
    def _binding(self, host: str, summary: dict) -> ScopeBinding | None:
        """Bind an archived host. Returns ``None`` (counted + logged) unless in scope."""

        binding = self.ctx.bind(host)
        if binding.verdict == Verdict.IN_SCOPE:
            return binding
        if host not in self._verdict_counted:
            self._verdict_counted.add(host)
            verdict = binding.verdict.value
            summary["dropped_by_verdict"][verdict] = (
                summary["dropped_by_verdict"].get(verdict, 0) + 1
            )
            summary["dropped_out_of_scope"] += 1
            self.log.info("wayback: dropping archived host %s: %s (%s)",
                          host, verdict, binding.rule_matched)
        return None

    def _attrs(self, ts: str, extra: dict) -> dict:
        """Historical marker + earliest capture stamp. Never ``active_probed``."""

        attrs = {"historical": True, **extra}
        if ts:
            attrs["archived_timestamp"] = ts
        return attrs

    def _emit(self, apps: dict, routes: dict, evidence: list[EvidenceRef],
              summary: dict) -> int:
        """Write the in-scope WebApp/Route nodes and their ``exposes`` edges."""

        emitted = 0
        for app_id, app in apps.items():
            binding = self._binding(app["host"], summary)
            if binding is None or app_id in self._emitted_ids:
                continue
            self.ctx.graph.upsert_node(make_node(
                "WebApp", app_id,
                binding=binding,
                source=SOURCE,
                now=self.ctx.clock_now(),
                attrs=self._attrs(app["ts"], {"vhost": app["host"],
                                              "scheme": app["scheme"]}),
                evidence=evidence,
                log_odds=ARCHIVE_LOG_ODDS,  # archived once != live now
                sensitivity=Sensitivity.S0,  # a public crawl of public pages
                coverage={"enumerated": True},  # archive set pulled; nothing fingerprinted
                data_subject="none",
            ))
            self._emitted_ids.add(app_id)
            summary["webapps"] += 1
            summary["emitted"] += 1
            emitted += 1

        for rt_id, route in routes.items():
            app_id = route["webapp"]
            if app_id not in self._emitted_ids:
                continue  # its WebApp was dropped or capped: never orphan a Route
            binding = self._binding(route["host"], summary)
            if binding is None or rt_id in self._emitted_ids:
                continue
            self.ctx.graph.upsert_node(make_node(
                "Route", rt_id,
                binding=binding,
                source=SOURCE,
                now=self.ctx.clock_now(),
                attrs=self._attrs(route["ts"], {"path_template": route["template"]}),
                evidence=evidence,
                log_odds=ARCHIVE_LOG_ODDS,
                sensitivity=Sensitivity.S0,
                coverage={"enumerated": True},
                data_subject="none",
            ))
            self._emitted_ids.add(rt_id)
            summary["routes"] += 1
            summary["emitted"] += 1
            emitted += 1

            edge = make_edge(
                "exposes", app_id, rt_id,
                binding=binding,
                source=SOURCE,
                now=self.ctx.clock_now(),
                attrs={"historical": True},
                log_odds=ARCHIVE_LOG_ODDS,
            )
            if edge.id in self._emitted_ids:
                continue
            self.ctx.graph.upsert_edge(edge)
            self._emitted_ids.add(edge.id)
            summary["edges"] += 1
        return emitted


__all__ = [
    "WaybackModule", "CDX_URL", "VERB", "SOURCE", "ARCHIVE_LOG_ODDS",
    "ID_PLACEHOLDER", "path_template", "parse_archived_url",
]
