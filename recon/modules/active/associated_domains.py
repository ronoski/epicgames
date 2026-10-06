"""ACTIVE mobile-association discovery: AASA and assetlinks.json.

A domain declares, in two well-known files, which mobile apps it *trusts*:

* ``/.well-known/apple-app-site-association`` (AASA) — which iOS app handles its universal
  links, and under ``webcredentials`` which app may autofill passwords for it;
* ``/.well-known/assetlinks.json`` — which Android app, identified by its signing
  certificate fingerprint, may claim its App Links.

That makes these files a **trust declaration**, not just configuration, which is why the
non-binary review flagged their absence (``docs/domains/non-binary.md`` §3.6/§3.5). They
are also unusually high-signal for an account-takeover chain: the declared ``paths`` are
exactly the surface a deep link can drive, and a ``webcredentials`` association is the
surface a credential autofill can be aimed at. Both are published for anyone to read, so
collecting them is ordinary recon.

**What it sends.** One gated ``GET`` per path in :data:`CANDIDATE_PATHS` per WebApp, with
no body, no retry and no redirect following (each hop is its own scope decision). Every
request passes :meth:`ModuleContext.gate_active` first.

**What it emits.** An ``AuthScheme`` per association kind carrying the declared app
identities, relations and ``webcredentials`` flag; a ``Route`` per declared app-link path
pattern, with an ``exposes`` edge from the WebApp; and a ``Hypothesis`` when a declaration
looks broken (an empty ``details``/``targets`` list, or a wildcard-only path set), which is
a lead rather than a finding.

**On the signing fingerprints.** Android ``sha256_cert_fingerprints`` and iOS ``appID``s are
*public identifiers*, not secrets, so they stay as ``AuthScheme`` attrs rather than being
minted as ``Credential`` nodes. Inventing a Credential for public material would both
misrepresent it and collide with what the ``S1``-minimum rule (invariant I8) is for.
"""

from __future__ import annotations

import json

import requests

from ... import verbs
from ...factory import make_edge, make_node
from ...models import Sensitivity, Verdict
from ...urls import (
    canonical_url, hypothesis_id, operation_id, route_id as make_route_id,
    webapp_id_from_url,
)
from ..base import GateRefused, Module, ModuleContext, register

VERB = "http-GET"
SOURCE = "associated_domains"

#: Fixed candidate paths — a module constant, never a wordlist and never derived from a
#: response. Apple reads the ``.well-known`` location and (legacy) the root.
CANDIDATE_PATHS: tuple[tuple[str, str], ...] = (
    ("/.well-known/apple-app-site-association", "applinks"),
    ("/apple-app-site-association", "applinks"),
    ("/.well-known/assetlinks.json", "assetlinks"),
)

SEED_NODE_TYPES = frozenset({"WebApp"})

#: A published declaration is first-hand and authoritative about intent, but it describes
#: configuration rather than observed behaviour, so it lands short of "verified".
DECLARED_LOG_ODDS = 1.6

MAX_SEEDS = 25
MAX_PATHS_PER_HOST = 50
MAX_APP_IDS = 50
MAX_RESPONSE_CHARS = 1 * 1024 * 1024
MAX_NAME_CHARS = 200


def _clean(value, limit: int = MAX_NAME_CHARS) -> str:
    return str(value).strip()[:limit] if isinstance(value, (str, int)) else ""


def parse_aasa(doc: dict) -> dict:
    """Extract the declared iOS association from an AASA document.

    Handles both the modern ``components`` form and the legacy ``paths`` form, because a
    long-lived target serves both.
    """

    out: dict = {"app_ids": [], "paths": [], "webcredentials": [],
                 "activitycontinuation": []}
    applinks = doc.get("applinks")
    if isinstance(applinks, dict):
        details = applinks.get("details")
        # The legacy shape is a dict keyed by appID; the modern one is a list.
        entries = details if isinstance(details, list) else (
            [{"appID": k, **(v if isinstance(v, dict) else {})}
             for k, v in details.items()] if isinstance(details, dict) else [])
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            for key in ("appID", "appId"):
                app = _clean(entry.get(key))
                if app:
                    out["app_ids"].append(app)
            for app in entry.get("appIDs", []) if isinstance(entry.get("appIDs"), list) else []:
                app = _clean(app)
                if app:
                    out["app_ids"].append(app)
            for path in entry.get("paths", []) if isinstance(entry.get("paths"), list) else []:
                path = _clean(path)
                if path:
                    out["paths"].append(path)
            components = entry.get("components")
            if isinstance(components, list):
                for comp in components:
                    if isinstance(comp, dict):
                        path = _clean(comp.get("/") or comp.get("path"))
                        if path:
                            out["paths"].append(path)

    for key in ("webcredentials", "activitycontinuation"):
        section = doc.get(key)
        if isinstance(section, dict):
            apps = section.get("apps")
            if isinstance(apps, list):
                out[key] = [a for a in (_clean(x) for x in apps) if a]

    for key in ("app_ids", "paths"):
        # de-duplicate, preserving order, under a cap
        seen, kept = set(), []
        for item in out[key]:
            if item not in seen:
                seen.add(item)
                kept.append(item)
        limit = MAX_APP_IDS if key == "app_ids" else MAX_PATHS_PER_HOST
        out[key] = kept[:limit]
    return out


def parse_assetlinks(doc) -> dict:
    """Extract the declared Android association from an assetlinks document."""

    out: dict = {"relations": [], "packages": [], "fingerprints": [], "web_targets": []}
    statements = doc if isinstance(doc, list) else []
    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        relation = stmt.get("relation")
        if isinstance(relation, list):
            out["relations"].extend(r for r in (_clean(x) for x in relation) if r)
        target = stmt.get("target")
        if not isinstance(target, dict):
            continue
        namespace = _clean(target.get("namespace"))
        if namespace == "android_app":
            package = _clean(target.get("package_name"))
            if package:
                out["packages"].append(package)
            prints = target.get("sha256_cert_fingerprints")
            if isinstance(prints, list):
                out["fingerprints"].extend(p for p in (_clean(x) for x in prints) if p)
        elif namespace == "web":
            site = _clean(target.get("site"))
            if site:
                out["web_targets"].append(site)
    for key in list(out):
        seen, kept = set(), []
        for item in out[key]:
            if item not in seen:
                seen.add(item)
                kept.append(item)
        out[key] = kept[:MAX_APP_IDS]
    return out


@register
class AssociatedDomainsModule(Module):
    """Read a host's declared mobile-app trust relationships."""

    ctx: ModuleContext

    name = "associated_domains"
    produces = ("AuthScheme", "Route", "Hypothesis")
    active = True

    def run(self, seeds: list) -> dict:
        verbs.assert_schedulable(VERB)
        assert verbs.is_active(VERB), "associated_domains is active; its verb must be too"

        summary: dict = {
            "module": self.name, "verb": VERB, "active": True,
            "targets": [], "requests": 0, "found": [], "not_found": 0,
            "auth_schemes": 0, "routes": 0, "hypotheses": 0,
            "webcredentials_hosts": [], "refused": [], "errors": [],
            "truncated": False,
        }

        targets = self._targets(seeds, summary)
        if not targets:
            return summary

        for webapp_id, base in targets:
            self._discover(webapp_id, base, summary)

        self.log.info("associated_domains: %d target(s), %d request(s), %d declaration(s)",
                      len(targets), summary["requests"], len(summary["found"]))
        return summary

    # --- seeds ---------------------------------------------------------
    def _targets(self, seeds: list, summary: dict) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        for seed in seeds or []:
            node_id = getattr(seed, "id", "") or ""
            if not node_id.startswith("web:"):
                continue
            if getattr(seed, "type", "") not in SEED_NODE_TYPES:
                continue
            base = node_id[len("web:"):]
            if "://" not in base:
                continue
            if len(out) >= MAX_SEEDS:
                summary["truncated"] = True
                self.log.warning("associated_domains: seed list exceeds %d; deferring the rest",
                                 MAX_SEEDS)
                break
            out.append((node_id, base))
        summary["targets"] = [t[0] for t in out]
        return out

    # --- discovery -----------------------------------------------------
    def _discover(self, webapp_id: str, base: str, summary: dict) -> None:
        host = base.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
        seen_kinds: set[str] = set()
        for path, kind in CANDIDATE_PATHS:
            if kind in seen_kinds:
                continue  # one declaration per kind is enough; the rest is unspent budget
            url = canonical_url(base.rstrip("/") + path)
            try:
                binding = self.ctx.gate_active(host, VERB)
            except GateRefused as exc:
                summary["refused"].append({"url": url, "verb": VERB, "reason": exc.reason})
                self.log.info("associated_domains: gate refused %s (%s)", url, exc.reason)
                continue

            summary["requests"] += 1
            body, err = self._fetch(url)
            if err:
                summary["errors"].append({"url": url, "error": err})
                continue
            if body is None:
                summary["not_found"] += 1
                continue
            try:
                doc = json.loads(body)
            except (json.JSONDecodeError, ValueError):
                summary["errors"].append({"url": url, "error": "not JSON"})
                continue

            seen_kinds.add(kind)
            summary["found"].append({"url": url, "kind": kind})
            evidence = [self.ctx.evidence.put_text(body, region=f"{SOURCE}:{url}")]
            if kind == "applinks" and isinstance(doc, dict):
                self._emit_applinks(webapp_id, host, url, parse_aasa(doc), binding,
                                    evidence, summary)
            elif kind == "assetlinks":
                self._emit_assetlinks(webapp_id, host, url, parse_assetlinks(doc), binding,
                                      evidence, summary)

    def _fetch(self, url: str) -> tuple[str | None, str]:
        """``(body, error)``. ``(None, "")`` means a clean 404. Never raises."""

        try:
            resp = requests.get(
                url, timeout=self.ctx.timeout,
                headers={"User-Agent": self.ctx.user_agent, "Accept": "application/json"},
                allow_redirects=False,
            )
        except requests.RequestException as exc:
            return None, f"request failed: {type(exc).__name__}"
        except Exception as exc:
            return None, f"unexpected transport error: {type(exc).__name__}"

        status = getattr(resp, "status_code", 0)
        if status == 404:
            return None, ""
        if status != 200:
            # 403/429 is backed off from, never worked around.
            return None, f"HTTP {status}"
        try:
            text = resp.text or ""
        except Exception:
            return None, "unreadable body"
        if len(text) > MAX_RESPONSE_CHARS:
            return None, "response exceeds size cap"
        return text, ""

    # --- emission ------------------------------------------------------
    def _emit_applinks(self, webapp_id, host, url, parsed, binding, evidence,
                       summary) -> None:
        attrs = {
            "active_probed": True,
            "kind": "apple-app-site-association",
            "app_ids": parsed["app_ids"],
            "declared_paths": parsed["paths"],
            # A webcredentials association is the surface a credential autofill can be
            # aimed at, so it is called out rather than buried in the raw document.
            "webcredentials_apps": parsed["webcredentials"],
            "has_webcredentials": bool(parsed["webcredentials"]),
            "source_url": url,
        }
        self._emit_scheme(webapp_id, host, "applinks", attrs, binding, evidence, summary)
        if parsed["webcredentials"]:
            summary["webcredentials_hosts"].append(host)
        self._emit_paths(webapp_id, parsed["paths"], binding, evidence, summary)
        if not parsed["app_ids"]:
            self._emit_hypothesis(
                host, "aasa-declares-no-app",
                "AASA served but declares no appID — a stale or broken association",
                binding, evidence, summary)

    def _emit_assetlinks(self, webapp_id, host, url, parsed, binding, evidence,
                         summary) -> None:
        attrs = {
            "active_probed": True,
            "kind": "assetlinks.json",
            "relations": parsed["relations"],
            "packages": parsed["packages"],
            # Public certificate fingerprints: identifiers, not secrets (see module
            # docstring), so they are recorded as attrs rather than Credential nodes.
            "sha256_cert_fingerprints": parsed["fingerprints"],
            "web_targets": parsed["web_targets"],
            "source_url": url,
        }
        self._emit_scheme(webapp_id, host, "assetlinks", attrs, binding, evidence, summary)
        if parsed["packages"] and not parsed["fingerprints"]:
            self._emit_hypothesis(
                host, "assetlinks-without-fingerprint",
                "assetlinks declares an android_app with no signing fingerprint — "
                "any app claiming that package name would match",
                binding, evidence, summary)

    def _emit_scheme(self, webapp_id, host, kind, attrs, binding, evidence,
                     summary) -> None:
        scheme_id = f"auth:{host}:{kind}"
        self.ctx.graph.upsert_node(make_node(
            "AuthScheme", scheme_id, binding=binding, source=SOURCE,
            now=self.ctx.clock_now(), attrs=attrs, evidence=evidence,
            log_odds=DECLARED_LOG_ODDS, sensitivity=Sensitivity.S0,
            coverage={"fingerprinted": True, "flow_mapped": bool(attrs.get("declared_paths"))},
        ))
        self.ctx.graph.upsert_edge(make_edge(
            "authenticates_with", webapp_id, scheme_id,
            binding=binding, source=SOURCE, now=self.ctx.clock_now(),
            attrs={"active_probed": True},
        ))
        summary["auth_schemes"] += 1

    def _emit_paths(self, webapp_id, paths, binding, evidence, summary) -> None:
        """Declared app-link paths are the surface a deep link can drive."""

        emitted = 0
        for raw in paths:
            if emitted >= MAX_PATHS_PER_HOST:
                summary["truncated"] = True
                break
            # A declared pattern is kept verbatim (it is a declaration, like an OpenAPI
            # key, not an observed path to collapse) minus any NOT- exclusion marker.
            pattern = raw[4:] if raw.startswith("NOT ") else raw
            if not pattern.startswith("/"):
                continue
            rid = make_route_id(webapp_id, pattern)
            self.ctx.graph.upsert_node(make_node(
                "Route", rid, binding=binding, source=SOURCE, now=self.ctx.clock_now(),
                attrs={"active_probed": True, "declared_by": "applinks",
                       "pattern": pattern, "excluded": raw.startswith("NOT ")},
                evidence=evidence, log_odds=DECLARED_LOG_ODDS,
                coverage={"enumerated": True},
            ))
            self.ctx.graph.upsert_edge(make_edge(
                "exposes", webapp_id, rid, binding=binding, source=SOURCE,
                now=self.ctx.clock_now(), attrs={"active_probed": True},
            ))
            emitted += 1
            summary["routes"] += 1

    def _emit_hypothesis(self, host, kind, note, binding, evidence, summary) -> None:
        node_id = hypothesis_id(kind, host)
        self.ctx.graph.upsert_node(make_node(
            "Hypothesis", node_id, binding=binding, source=SOURCE,
            now=self.ctx.clock_now(),
            attrs={"active_probed": True, "note": note, "host": host},
            evidence=evidence,
            log_odds=0.0,  # a lead, not a finding
            coverage={"enumerated": True},
        ))
        self.ctx.graph.log.append("hypothesis_raised", {"id": node_id, "kind": kind})
        summary["hypotheses"] += 1
