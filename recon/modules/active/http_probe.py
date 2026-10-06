"""Active HTTP characterization of an in-scope hostname or IP (``SPEC.md`` §6.2.3).

This is the first module in the ladder that puts a packet on an Epic target, so every
request funnels through the one chokepoint — :meth:`ModuleContext.gate_active` — **before**
it is sent (``docs/pipeline.md`` §1). A :class:`~recon.modules.base.GateRefused` is a skip:
it is logged, recorded in the summary and the loop moves on. Nothing here ever probes a
value the gate did not just authorize, and nothing is emitted for a value that did not bind
``in_scope`` at observation time (I2/I3), because the only bindings used are the ones the
gate itself returned.

**What it does, per ``(host, scheme)`` pair.** Exactly one ``HEAD /`` (``http-HEAD``), with
redirects **not** followed, no body sent, and no retry — a failure is final and
re-verification is scheduled by decay, not by hammering (``safety-model.md`` §4). A server
that *rejects* HEAD (405/501) tells us nothing about the app behind it, so in that one case
the module falls back to exactly one ``GET /`` — a different probe type, on its own verb
(``http-GET``), **gated separately**. That keeps the domain rule "one hit per
``(endpoint, probe-type)``" (``domains/non-binary.md`` §3.3) while still characterizing a
HEAD-hostile host. No other method is ever sent: OPTIONS/POST/PUT/PATCH/DELETE are not on
the whitelist and a CORS preflight is explicitly excluded.

**What it emits.** A ``WebApp`` (``web:<scheme>://<authority>``) carrying the observed
status, ``Server`` token, redirect target, security-header posture, any
``Access-Control-Allow-Origin`` the server volunteered, a best-effort CDN/WAF label and —
only when a GET was actually made — the page title; coverage ``{"fingerprinted": True}``.
Plus one ``Operation`` (``op:<METHOD>:route:<webapp>/``) per request actually made, holding
that method's observed status, joined by the declared ``exposes`` edge. The raw response
status line and headers are content-addressed into the evidence store, so every attr here
is replayable from the proof it came from.

**Hygiene.** Observation only, and minimized **before** storage (``safety-model.md`` §5/§6):

* no ``Origin`` header is sent, so ``cors_allow_origin`` is what the server volunteered,
  never a reflection probe; a permissive value is a weakness *observation*, not an exploit;
* a missing security header is recorded as ``False`` and nothing else — weakness
  hypotheses are a human's call, not an automatic claim;
* ``Set-Cookie``/``Authorization`` values are redacted with :func:`recon.evidence.redact`
  as the headers are parsed, so an anonymous session secret cannot reach an attr *or* the
  evidence blob, while the redaction stays deterministic (prefix + sha16) and therefore
  still comparable across runs;
* a ``Location`` is stored stripped of its query and fragment, and dropped entirely if it
  carries userinfo — an SSO hop routinely carries ``?code=``/``?access_token=``, and a
  secret value must never become an attr. The hop is **not** followed: each hop is its own
  scope decision and would need its own gate.

Nothing here collects data about another person, so every node is ``data_subject="none"``
and ``S0`` (a public, unauthenticated response); no ``Credential``/``Token`` node is minted
at all. A live first-hand response is strong evidence the vhost exists, so nodes land at
``log_odds=2.0`` (~p=0.88) — deliberately just below the ``corroborated`` threshold of 2.2,
since one source must never promote itself; an independent observation is what lifts it.
A status that changes between runs is a **contradiction that forks** (I11), which is the
intended behavior for a ``200 -> 403`` re-probe, not something to smooth over.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import requests

from ... import verbs
from ...evidence import redact
from ...factory import make_edge, make_node
from ...models import EvidenceRef, ScopeBinding, Sensitivity, Verdict
from ...urls import (
    authority, canonical_host, operation_id, route_id as make_route_id,
    webapp_id_from_url,
)
from ...scope import classify
from ..base import GateRefused, Module, ModuleContext, register

#: Whitelisted **active** verbs for this module, in the order they may be spent.
HEAD_VERB = "http-HEAD"
GET_VERB = "http-GET"

SOURCE = "http_probe"

#: Schemes probed per target. Each pair is its own gate, its own request, its own WebApp.
SCHEMES: tuple[str, ...] = ("https", "http")

#: A first-hand live response is strong evidence of existence. ~p=0.88, and deliberately
#: below ``models._CORROBORATED_AT`` (2.2): one source never promotes itself.
LIVE_LOG_ODDS = 2.0

#: The only statuses that justify spending a second (GET) probe on the same endpoint: the
#: server refused the method itself, so the HEAD says nothing about the application.
HEAD_REJECTED_STATUSES = frozenset({405, 501})

#: Node types this module accepts as seeds; anything else is ignored.
SEED_NODE_TYPES = frozenset({"DNSName", "Host"})

_SEED_ID_PREFIXES = ("dns:", "host:")
_FOREIGN_ID_PREFIXES = (
    "org:", "bu:", "domain:", "net:", "asn:", "svc:", "web:", "route:", "op:",
    "param:", "auth:", "cred:", "tok:", "obj:", "flow:", "art:", "ev:", "hyp:",
)

#: Conservative fqdn shape. Rejects whitespace, raw unicode (punycode ``xn--`` passes) and
#: anything email-shaped, so a junk seed can never be interpolated into a request URL.
_FQDN_RE = re.compile(
    r"^[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?)+$"
)

#: Printable, space-free ASCII. A ``Location`` outside it is a mangled header, not a target.
_SAFE_LOCATION_RE = re.compile(r"^[\x21-\x7e]*$")

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_WHITESPACE_RE = re.compile(r"\s+")

#: Header values that may carry a live secret. Redacted as they are parsed — before they
#: can reach an attr or the evidence blob (``safety-model.md`` §5: S3 => redact).
_SECRET_HEADERS = frozenset({
    "set-cookie", "set-cookie2", "authorization", "proxy-authorization",
})

#: Security headers whose presence/absence is recorded as a plain boolean.
SECURITY_HEADERS: tuple[tuple[str, str], ...] = (
    ("hsts", "strict-transport-security"),
    ("csp", "content-security-policy"),
    ("x_frame_options", "x-frame-options"),
    ("x_content_type_options", "x-content-type-options"),
)

#: Vendor-exclusive edge signatures as ``(label, header, needle)``; ``needle=""`` means the
#: header's presence alone is the signal. Checked in this fixed order so the label is
#: deterministic. Best-effort by construction: an edge fronts many tenants, so this names
#: the **front**, never the application behind it, and it never decides ownership.
CDN_WAF_SIGNATURES: tuple[tuple[str, str, str], ...] = (
    ("cloudflare", "cf-ray", ""),
    ("cloudflare", "server", "cloudflare"),
    ("cloudfront", "x-amz-cf-id", ""),
    ("akamai", "x-akamai-request-id", ""),
    ("akamai", "server", "akamaighost"),
    ("fastly", "fastly-debug-digest", ""),
    ("fastly", "x-served-by", "cache-"),
    ("azure-front-door", "x-azure-ref", ""),
    ("google-frontend", "server", "google frontend"),
    ("varnish", "x-varnish", ""),
    ("sucuri", "x-sucuri-id", ""),
    ("imperva", "x-iinfo", ""),
    ("aws-alb-or-apigw", "x-amzn-trace-id", ""),
)

# --- defensive caps (a seed list comes from the graph and can be large) ---
MAX_TARGETS = 50
MAX_HEADERS = 100
MAX_HEADER_VALUE_CHARS = 512
MAX_BODY_CHARS = 64 * 1024
MAX_TITLE_CHARS = 200
MAX_REDIRECT_CHARS = 300


def page_title(body: str) -> str:
    """First ``<title>`` of an HTML body, whitespace-collapsed and capped. ``""`` if none."""

    match = _TITLE_RE.search(body or "")
    if not match:
        return ""
    return _WHITESPACE_RE.sub(" ", match.group(1)).strip()[:MAX_TITLE_CHARS]


def redirect_target(location: str) -> str:
    """Normalize a ``Location`` header to a bare, query-free target, or ``""``.

    The query and fragment are discarded by construction — only the scheme, host and path
    are read — because a redirect to an auth endpoint routinely carries ``?code=`` or
    ``?access_token=`` and a secret value must never reach an attr. A header carrying
    ``@`` anywhere is dropped rather than cleaned: it may hold userinfo (a credential) or
    another person's identifier, and an ``other``-subject datum is not collected when it
    can simply be skipped. A non-web scheme (a deeplink) is not a web target and is
    likewise dropped.
    """

    location = (location or "").strip()
    if not location or "@" in location or not _SAFE_LOCATION_RE.match(location):
        return ""
    try:
        parts = urlsplit(location)
    except ValueError:
        return ""  # e.g. a mangled IPv6 literal
    scheme = (parts.scheme or "").lower()
    if scheme and scheme not in ("http", "https"):
        return ""
    host = canonical_host(parts.hostname or "")
    path = parts.path or ""
    if host and scheme:
        target = f"{scheme}://{authority(host)}{path}"
    elif host:
        target = f"//{authority(host)}{path}"  # protocol-relative hop
    else:
        target = path or "/"  # a relative hop stays relative
    return target[:MAX_REDIRECT_CHARS]


def cdn_or_waf(headers: dict[str, str]) -> str:
    """Best-effort CDN/WAF label from :data:`CDN_WAF_SIGNATURES`, or ``""`` if unknown."""

    for label, header, needle in CDN_WAF_SIGNATURES:
        if header not in headers:
            continue
        if not needle or needle in headers[header].lower():
            return label
    return ""


def header_items(headers) -> list[tuple[str, str]]:
    """Lowercase, sorted, capped ``(name, value)`` pairs with secret values redacted.

    Sorting makes the serialized evidence (and therefore its sha256) independent of the
    order the server happened to send, so re-observing an unchanged response is a merge
    rather than a new blob. Redaction happens **here**, at the single parse point, so no
    later caller can route a cookie value into an attr by accident.
    """

    try:
        items = list(headers.items())
    except Exception:  # a response object that is not dict-like; not worth crashing over
        return []
    out: list[tuple[str, str]] = []
    for name, value in items:
        if not isinstance(name, str):
            continue
        key = name.strip().lower()
        text = str(value).strip()[:MAX_HEADER_VALUE_CHARS]
        if key in _SECRET_HEADERS and text:
            cookie_name, sep, rest = text.partition("=")
            # Keep the cookie's NAME (useful auth signal), redact everything after it.
            text = f"{cookie_name[:64]}={redact(rest)}" if sep else redact(text)
        out.append((key, text))
    out.sort()
    return out[:MAX_HEADERS]


@dataclass
class _Probe:
    """One gated request that actually happened, and what it observed."""

    method: str
    binding: ScopeBinding
    status: int
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: str = ""
    evidence: list[EvidenceRef] = field(default_factory=list)


@register
class HttpProbeModule(Module):
    """Promote in-scope DNSName/Host seeds into fingerprinted ``WebApp`` nodes."""

    ctx: ModuleContext

    name = "http_probe"
    produces = ("WebApp", "Operation")
    active = True

    def run(self, seeds: list) -> dict:
        """Probe each seed once per scheme. Gate first, one request, log and continue."""

        # Self-check: both verbs must be on the closed whitelist AND be active verbs (this
        # module sends traffic to the target; a passive verb here would mislabel the spend).
        for verb in (HEAD_VERB, GET_VERB):
            verbs.assert_schedulable(verb)
            assert verbs.is_active(verb), f"{verb!r} must be an active verb"

        summary: dict = {
            "module": self.name,
            "verbs": [HEAD_VERB, GET_VERB],
            "active": True,
            "targets": [],
            "requests": 0,
            "get_fallbacks": 0,
            "webapps": 0,
            "operations": 0,
            "edges": 0,
            "refused": [],
            "errors": [],
            "truncated": False,
        }

        targets = self._targets(seeds, summary)
        summary["targets"] = targets
        if not targets:
            self.log.info("http_probe: no DNSName/Host seeds to probe; nothing to do")
            return summary

        # No pre-flight scope/snapshot check here on purpose: gate_active is the single
        # chokepoint and writes the ALLOW/REFUSE record for every attempt, so a disabled,
        # unsnapshotted, stale or out-of-scope run is refused there and stays auditable.
        for value in targets:
            for scheme in SCHEMES:
                self._probe(value, scheme, summary)

        self.log.info(
            "http_probe: done — %d target(s), %d request(s) spent (%d GET fallback(s)), "
            "%d WebApp(s), %d Operation(s), %d edge(s), %d refused, %d error(s)",
            len(targets), summary["requests"], summary["get_fallbacks"],
            summary["webapps"], summary["operations"], summary["edges"],
            len(summary["refused"]), len(summary["errors"]),
        )
        return summary

    # --- seeds -------------------------------------------------------------
    def _targets(self, seeds: list, summary: dict) -> list[str]:
        """Distinct hostnames/IPs to probe, in seed order. Tolerates an empty list."""

        out: list[str] = []
        for seed in seeds or []:
            value = canonical_host(self._seed_value(seed))
            if value.startswith("[") and value.endswith("]"):
                value = value[1:-1]  # an IPv6 authority arrives bracketed
            if not value or len(value) > 253:
                continue
            if classify(value) != "ip" and not _FQDN_RE.match(value):
                continue  # junk never reaches a URL
            if value not in out:
                out.append(value)
        if len(out) > MAX_TARGETS:
            self.log.warning("http_probe: %d seed target(s) exceeds the %d cap; deferring "
                             "the rest", len(out), MAX_TARGETS)
            summary["truncated"] = True
            out = out[:MAX_TARGETS]
        return out

    @staticmethod
    def _seed_value(seed) -> str:
        """Pull a hostname/IP out of a graph Node id, or out of a plain-string seed."""

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

    # --- probe -------------------------------------------------------------
    def _probe(self, value: str, scheme: str, summary: dict) -> None:
        """One gated HEAD of ``scheme://value/``, plus a GET only if HEAD was rejected."""

        url = f"{scheme}://{authority(value)}/"
        head = self._gated_request(value, url, "HEAD", HEAD_VERB, summary)
        if head is None:
            return  # refused or unusable: nothing was observed, so nothing is emitted

        probes = [head]
        if head.status in HEAD_REJECTED_STATUSES:
            # "Only if needed": the server refused the method, not the request. One GET,
            # separately gated and separately debited — never a retry of the same probe.
            self.log.info("http_probe: %s answered HEAD with %d; one gated GET fallback",
                          url, head.status)
            got = self._gated_request(value, url, "GET", GET_VERB, summary)
            if got is not None:
                summary["get_fallbacks"] += 1
                probes.append(got)

        self._emit(value, scheme, url, probes, summary)

    def _gated_request(self, value: str, url: str, method: str, verb: str,
                       summary: dict) -> _Probe | None:
        """Gate, then send exactly one request. ``None`` on refusal or an unusable answer.

        A :class:`GateRefused` is never swallowed into a probe-anyway path: it ends this
        ``(endpoint, probe-type)`` here, logged and counted, and the loop continues.
        """

        try:
            binding = self.ctx.gate_active(value, verb)
        except GateRefused as exc:
            self.log.info("http_probe: skipping %s %s: %s", method, url, exc.reason)
            summary["refused"].append({"url": url, "verb": verb, "reason": exc.reason})
            return None

        resp, err = self._request(method, url)
        summary["requests"] += 1  # the budget was debited whether or not the answer is usable
        if err:
            self.log.warning("http_probe: %s %s failed (%s); skipping", method, url, err)
            summary["errors"].append({"url": url, "method": method, "error": err})
            return None

        status = getattr(resp, "status_code", None)
        if not isinstance(status, int) or not 100 <= status <= 599:
            self.log.warning("http_probe: %s %s returned no usable status; skipping",
                             method, url)
            summary["errors"].append({"url": url, "method": method,
                                      "error": "no usable status code"})
            return None

        headers = header_items(getattr(resp, "headers", None) or {})
        body = self._body(resp) if method == "GET" else ""  # HEAD has no body by definition
        return _Probe(
            method=method, binding=binding, status=status, headers=headers, body=body,
            evidence=self._evidence(method, url, status, headers),
        )

    def _request(self, method: str, url: str):
        """Send one HEAD or GET. Returns ``(response, error)`` and never raises.

        No body, no redirect following, no retry, and no other method is reachable from
        here — the dispatch table has exactly two entries.
        """

        send = {"HEAD": requests.head, "GET": requests.get}.get(method)
        assert send is not None, "http_probe only ever sends HEAD or GET"
        try:
            resp = send(
                url,
                timeout=self.ctx.timeout,
                headers={"User-Agent": self.ctx.user_agent},
                allow_redirects=False,
            )
        except requests.RequestException as exc:
            return None, f"request failed: {type(exc).__name__}"
        except Exception as exc:  # unknown transport layer; a module never crashes the run
            return None, f"unexpected transport error: {type(exc).__name__}"
        return resp, ""

    @staticmethod
    def _body(resp) -> str:
        """Decoded body, capped. A decode failure is not worth failing the probe over."""

        try:
            return (getattr(resp, "text", "") or "")[:MAX_BODY_CHARS]
        except Exception:
            return ""

    def _evidence(self, method: str, url: str, status: int,
                  headers: list[tuple[str, str]]) -> list[EvidenceRef]:
        """Content-address the (already redacted) status line + headers.

        Only the response metadata is stored: the body is read for a ``<title>`` and then
        dropped, so a page that happens to embed a secret is never written to disk here.
        An unwritable store degrades to "no evidence ref", not a failed run.
        """

        text = "\n".join(
            [f"{method} {url}", f"HTTP {status}"] + [f"{k}: {v}" for k, v in headers]
        )
        try:
            return [self.ctx.evidence.put_text(text, region=f"{SOURCE}:{method} {url}")]
        except OSError as exc:
            self.log.warning("http_probe: evidence store unavailable for %s: %s", url, exc)
            return []

    # --- emit --------------------------------------------------------------
    def _webapp_attrs(self, value: str, scheme: str, probes: list[_Probe]) -> dict:
        """Characterization attrs, read off the most informative response we hold."""

        last = probes[-1]  # the GET when one was made, else the HEAD
        headers = dict(last.headers)
        attrs: dict = {
            "active_probed": True,
            "vhost": value,
            "scheme": scheme,
            "status": last.status,
        }
        for attr, header in SECURITY_HEADERS:
            attrs[attr] = header in headers  # absent is recorded, never acted on
        optional = {
            "server": headers.get("server", ""),
            "cors_allow_origin": headers.get("access-control-allow-origin", ""),
            "cdn_or_waf": cdn_or_waf(headers),
            "redirect_to": (redirect_target(headers.get("location", ""))
                            if 300 <= last.status < 400 else ""),
            # A title needs a body, so it exists only when a GET was actually spent.
            "title": page_title(last.body) if last.method == "GET" else "",
        }
        attrs.update({k: v for k, v in optional.items() if v})
        return attrs

    def _emit(self, value: str, scheme: str, url: str, probes: list[_Probe],
              summary: dict) -> None:
        """Write the WebApp, one Operation per request made, and their ``exposes`` edges."""

        # The gate already guarantees this; assert it so no future refactor can emit a node
        # for a value that was not in scope at observation time (I2/I3).
        assert all(p.binding.verdict == Verdict.IN_SCOPE for p in probes), \
            "every binding here comes from gate_active and must be in_scope"

        now = self.ctx.clock_now()
        # from the probed URL, so a non-default port is preserved in the id
        webapp_id = webapp_id_from_url(url)
        self.ctx.graph.upsert_node(make_node(
            "WebApp", webapp_id,
            binding=probes[0].binding,
            source=SOURCE,
            now=now,
            attrs=self._webapp_attrs(value, scheme, probes),
            evidence=[ref for probe in probes for ref in probe.evidence],
            log_odds=LIVE_LOG_ODDS,
            sensitivity=Sensitivity.S0,  # a public, unauthenticated response
            coverage={"fingerprinted": True},  # status + headers + front, first-hand
            data_subject="none",
        ))
        summary["webapps"] += 1

        route_id = make_route_id(webapp_id, "/")  # the "/" template
        for probe in probes:
            op_id = operation_id(probe.method, route_id)
            self.ctx.graph.upsert_node(make_node(
                "Operation", op_id,
                binding=probe.binding,
                source=SOURCE,
                now=now,
                attrs={
                    "active_probed": True,
                    "method": probe.method,
                    "path_template": "/",
                    "status": probe.status,
                    "webapp": webapp_id,
                },
                evidence=probe.evidence,
                log_odds=LIVE_LOG_ODDS,
                sensitivity=Sensitivity.S0,
                coverage={"enumerated": True},  # observed to exist; no parameter mined
                data_subject="none",
            ))
            self.ctx.graph.upsert_edge(make_edge(
                "exposes", webapp_id, op_id,
                binding=probe.binding,
                source=SOURCE,
                now=now,
                attrs={"active_probed": True},
                log_odds=LIVE_LOG_ODDS,
            ))
            summary["operations"] += 1
            summary["edges"] += 1

        self.log.info("http_probe: %s -> %d (%s), %d operation(s)",
                      url, probes[-1].status,
                      ", ".join(p.method for p in probes), len(probes))


__all__ = [
    "HttpProbeModule", "HEAD_VERB", "GET_VERB", "SOURCE", "SCHEMES", "LIVE_LOG_ODDS",
    "HEAD_REJECTED_STATUSES", "CDN_WAF_SIGNATURES", "SECURITY_HEADERS",
    "authority", "cdn_or_waf", "header_items", "page_title", "redirect_target",
]
