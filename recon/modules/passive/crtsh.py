"""Passive subdomain discovery from Certificate Transparency via crt.sh.

CT is the canonical passive-first source (``docs/SPEC.md`` §6.2.9, ``safety-model.md`` §4):
every publicly trusted certificate Epic issues is logged, so the logs leak hostnames that
existed at issuance time without anyone sending a packet at Epic. crt.sh is a **third-party
aggregator**, so this module is strictly passive — it never calls
:meth:`ModuleContext.gate_active` and never debits the unified per-target Epic rate ledger
(``safety-model.md`` §4 keys the ledger by Epic target; crt.sh is not one).

The query itself needs no scope gate because no in-scope asset is touched. **Retention is
what is gated:** every parsed name is bound against the current policy snapshot and only an
``in_scope`` verdict is emitted. Names that bind ``out_of_scope`` / ``prefilter_only`` /
``adjudication_pending`` are counted and logged as negative space, never written —
``scope != ownership`` (§2), and a ``prefilter_only`` name capped at ``enumerated`` is the
seeds/ownership path's business, not a CT-expansion module's.

CT presence proves a name appeared in a certificate, not that it resolves today, so nodes
land at a modest ``log_odds`` of 1.0 (~p=0.73) with coverage ``{"enumerated": True}``;
liveness/fingerprinting is an active module's job and corroborates from there. Email SANs
and IP SANs are dropped at parse time rather than redacted — PII minimization happens
**before** storage (§6), and an ``other``-subject datum must never be collected when it can
simply be skipped.
"""

from __future__ import annotations

import json
import re

import requests

from ...factory import make_node
from ...models import Sensitivity, Verdict
from ...scope import classify, normalize_host, registrable_domain
from ... import verbs
from ..base import Module, ModuleContext, register

#: crt.sh identity search. ``%25`` is a pre-encoded ``%`` (SQL LIKE wildcard); it is built
#: literally rather than via ``params=`` so the emitted URL is exact and reviewable.
CRTSH_URL = "https://crt.sh/?q=%25.{apex}&output=json"

#: Whitelisted verb for this module (``verbs.ALLOWED``, deliberately NOT in ``verbs.ACTIVE``).
VERB = "passive-collect"

SOURCE = "crtsh"

#: CT presence is decent-but-not-conclusive evidence a name existed. ~p=0.73.
CT_LOG_ODDS = 1.0

#: Node types this module accepts as seeds; anything else is ignored.
SEED_NODE_TYPES = frozenset({"Domain", "DNSName"})

_SEED_ID_PREFIXES = ("domain:", "dns:")
_FOREIGN_ID_PREFIXES = (
    "org:", "bu:", "net:", "asn:", "host:", "svc:", "web:", "route:", "op:",
    "param:", "auth:", "cred:", "tok:", "obj:", "flow:", "art:", "ev:", "hyp:",
)

#: Conservative fqdn shape. Rejects emails, whitespace, leftover wildcards and raw unicode
#: (punycode ``xn--`` labels pass), so a malformed CT row can never mint a junk node id.
_FQDN_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?)+$")

# --- defensive caps (a single apex can have tens of thousands of CT rows) ---
MAX_APEXES = 25
MAX_NAMES_PER_APEX = 5000
MAX_RESPONSE_BYTES = 16 * 1024 * 1024


@register
class CrtShModule(Module):
    """Expand Domain/DNSName seeds into in-scope ``DNSName`` nodes from CT logs."""

    ctx: ModuleContext

    name = "crtsh"
    produces = ("DNSName",)
    active = False

    def run(self, seeds: list) -> dict:
        """Query crt.sh once per distinct apex and emit the in-scope names it reveals."""

        # Self-check: this module's verb must be on the closed whitelist and must NOT be
        # an active verb (a passive module that reached for one would be a safety bug).
        verbs.assert_schedulable(VERB)
        assert not verbs.is_active(VERB), "crtsh is passive; its verb must not be active"

        summary: dict = {
            "module": self.name,
            "verb": VERB,
            "active": False,
            "apexes": [],
            "queried": 0,
            "names_seen": 0,
            "emitted": 0,
            "dropped_out_of_scope": 0,
            "dropped_by_verdict": {},
            "errors": [],
            "truncated": False,
        }

        apexes = self._apexes(seeds)
        summary["apexes"] = apexes
        if not apexes:
            self.log.info("crtsh: no Domain/DNSName seeds to expand; nothing to do")
            return summary

        seen: set[str] = set()
        for apex in apexes:
            summary["queried"] += 1
            body, err = self._fetch(apex)
            if err:
                self.log.warning("crtsh: %%.%s unusable (%s); skipping", apex, err)
                summary["errors"].append({"apex": apex, "error": err})
                continue

            names, err = self._names(body)
            if err:
                self.log.warning("crtsh: %%.%s unusable (%s); skipping", apex, err)
                summary["errors"].append({"apex": apex, "error": err})
                continue

            # One evidence blob per response; every node derived from it points at this sha.
            ref = self.ctx.evidence.put_text(body, region=f"crtsh:q=%25.{apex}")
            emitted = dropped = 0
            for host in names:
                if emitted >= MAX_NAMES_PER_APEX:
                    summary["truncated"] = True
                    self.log.warning("crtsh: %%.%s hit the %d-name cap; requeue for the rest",
                                     apex, MAX_NAMES_PER_APEX)
                    break
                if host in seen:
                    continue  # within-run dedupe: re-upserting would self-corroborate
                seen.add(host)
                summary["names_seen"] += 1

                binding = self.ctx.bind(host)
                if binding.verdict != Verdict.IN_SCOPE:
                    verdict = binding.verdict.value
                    summary["dropped_by_verdict"][verdict] = (
                        summary["dropped_by_verdict"].get(verdict, 0) + 1
                    )
                    summary["dropped_out_of_scope"] += 1
                    dropped += 1
                    continue

                self.ctx.graph.upsert_node(make_node(
                    "DNSName", f"dns:{host}",
                    binding=binding,
                    source=SOURCE,
                    now=self.ctx.clock_now(),
                    # Scalar attrs are fork-triggers on re-observation, so keep this to one
                    # always-identical flag; the apex that found the name lives in the
                    # evidence region instead.
                    attrs={"ct_logged": True},
                    evidence=[ref],
                    log_odds=CT_LOG_ODDS,
                    sensitivity=Sensitivity.S0,  # CT is a public append-only log
                    coverage={"enumerated": True},
                ))
                summary["emitted"] += 1
                emitted += 1

            self.log.info(
                "crtsh: %%.%s -> %d parsed name(s), %d emitted in-scope, %d dropped out-of-scope",
                apex, len(names), emitted, dropped,
            )

        self.log.info(
            "crtsh: done — %d apex(es) queried, %d unique name(s), %d emitted, "
            "%d dropped out-of-scope %s",
            summary["queried"], summary["names_seen"], summary["emitted"],
            summary["dropped_out_of_scope"], summary["dropped_by_verdict"] or "{}",
        )
        return summary

    # --- seeds -------------------------------------------------------------
    def _apexes(self, seeds: list) -> list[str]:
        """Distinct registrable apexes to query, in seed order. Tolerates an empty list."""

        out: list[str] = []
        for seed in seeds or []:
            host = normalize_host(self._seed_host(seed).lstrip("*."))
            if not host or classify(host) == "ip":
                continue  # a CT identity search is a name search; raw IPs have no apex
            apex = registrable_domain(host)
            if apex and apex not in out:
                out.append(apex)
        if len(out) > MAX_APEXES:
            self.log.warning("crtsh: %d seed apexes exceeds the %d cap; deferring the rest",
                             len(out), MAX_APEXES)
            out = out[:MAX_APEXES]
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
    def _fetch(self, apex: str) -> tuple[str, str]:
        """GET crt.sh for ``apex``. Returns ``(body, error)`` and never raises."""

        url = CRTSH_URL.format(apex=apex)
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
            # crt.sh rate-limits with 429/503 under load. Back off, never retry-hammer.
            return "", f"HTTP {status}"
        body = getattr(resp, "text", "") or ""
        if len(body.encode("utf-8", "replace")) > MAX_RESPONSE_BYTES:
            return "", f"response larger than the {MAX_RESPONSE_BYTES}-byte cap"
        return body, ""

    @staticmethod
    def _names(body: str) -> tuple[list[str], str]:
        """Parse a crt.sh JSON array into canonical lowercase fqdns.

        ``name_value`` is newline-separated and holds every SAN of the matching cert. A
        leading ``*.`` wildcard label is stripped (the wildcard itself is not a host), and
        email SANs plus IP SANs are dropped rather than ingested (``safety-model.md`` §6).
        """

        try:
            rows = json.loads(body)
        except (ValueError, TypeError):
            return [], "response was not valid JSON"
        if not isinstance(rows, list):
            return [], "response JSON was not a list of certificate rows"

        out: list[str] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            for line in str(row.get("name_value", "")).splitlines():
                line = line.strip()
                if not line or "@" in line:
                    continue  # an email SAN is other-person data: do not collect it
                host = normalize_host(line.lstrip("*."))
                if not host or len(host) > 253 or not _FQDN_RE.match(host):
                    continue
                if classify(host) == "ip":
                    continue  # IP SANs are the network module's domain, not a DNSName
                out.append(host)
        return out, ""


__all__ = ["CrtShModule", "CRTSH_URL", "VERB", "SOURCE", "CT_LOG_ODDS"]
