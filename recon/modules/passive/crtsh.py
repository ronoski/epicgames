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
``adjudication_pending`` are counted, logged as ``scope_binding_set`` negative space and
never written — ``scope != ownership`` (§2), and a ``prefilter_only`` name capped at
``enumerated`` is the seeds/ownership path's business, not a CT-expansion module's.

Retention also requires a current, non-stale snapshot (I1/I12), so with no snapshot — or a
stale one — the module queries nothing, emits nothing, and says why in its summary.

CT presence proves a name appeared in a certificate, not that it resolves today, so nodes
land at a modest ``log_odds`` of 1.0 (~p=0.73) with coverage ``{"enumerated": True}``;
liveness/fingerprinting is an active module's job and corroborates from there.

Two retention details that are easy to get wrong, both ``safety-model.md`` §6 ("PII
minimization applies **before** storage, not after"):

* Email SANs and IP SANs are dropped at parse time, so no ``other``-subject datum is ever
  derived — rule "prefer not collecting it".
* The *raw response* is proof, and raw CT rows can carry a registrant's email SAN, so the
  body is hash-redacted with :func:`recon.evidence.redact` **before** it reaches the
  evidence store. Name extraction is unaffected (those lines are dropped anyway), so the
  blob stays a faithful replay input for every fact derived from it; the raw response's own
  digest is recorded in the ``evidence_captured`` event for audit without storing it.

The blob is also written **lazily**, on the first in-scope name: an apex whose CT rows are
all out of scope leaves nothing behind at all.

A leading wildcard label (``*.``) is stripped exactly once; any other ``*`` in a SAN makes
the name unusable rather than something to repair, because repairing it would assert a host
no certificate ever contained (an unverified guess belongs in a ``Hypothesis``, not a
``DNSName``).
"""

from __future__ import annotations

import json
import re

import requests

from ...evidence import redact, sha256_bytes
from ...factory import make_node
from ...models import Sensitivity, Verdict
from ...scope import classify, normalize_host, registrable_domain
from ... import verbs
from ..base import Module, ModuleContext, register

#: crt.sh identity search. ``%25`` is a pre-encoded ``%`` (SQL LIKE wildcard); it is built
#: literally rather than via ``params=`` so the emitted URL is exact and reviewable. Only
#: an apex that passed :data:`_FQDN_RE` is ever interpolated, so a junk seed cannot shape
#: the query string.
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

#: Email shape, matched over the *whole* raw body (``name_value`` newlines are escaped
#: inside the JSON, so a line-based pass would miss them). Deliberately greedy on the local
#: part but stopped by quotes, commas, whitespace and backslashes, so the surrounding JSON
#: stays intact and parseable after substitution.
_EMAIL_RE = re.compile(
    r"[A-Za-z0-9._%+!#$&'*/=?^`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?"
)

# --- defensive caps (a single apex can have tens of thousands of CT rows) ---
MAX_APEXES = 25
MAX_NAMES_PER_APEX = 5000
MAX_SCAN_PER_APEX = 50_000
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_DROP_EVENTS_PER_APEX = 100

_READ_CHUNK = 65536


def _strip_wildcard(name: str) -> str:
    """Strip one leading ``*.`` label. A name with any other ``*`` is unusable, not fixable.

    ``*.a.epicgames.com`` names the host ``a.epicgames.com``; ``*test.epicgames.com`` names
    no host at all, and rewriting it to ``test.epicgames.com`` would assert a name that was
    never in the certificate.
    """

    if name.startswith("*."):
        name = name[2:]
    return "" if "*" in name else name


def _minimize(body: str) -> tuple[str, int]:
    """Hash-redact every email-shaped substring. Returns ``(minimized, redaction_count)``.

    Run **before** anything is written to the evidence store (``safety-model.md`` §6): a CT
    row may carry a registrant/admin email SAN, which is another person's data and must not
    land on disk in plaintext even as "raw proof".
    """

    count = 0

    def _sub(match: re.Match) -> str:
        nonlocal count
        count += 1
        return redact(match.group(0), keep=0)

    return _EMAIL_RE.sub(_sub, body), count


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
            "rejected_seeds": 0,
            "queried": 0,
            "names_seen": 0,
            "emitted": 0,
            "unchanged": 0,
            "dropped_out_of_scope": 0,
            "dropped_by_verdict": {},
            "drop_events_truncated": 0,
            "pii_redactions": 0,
            "errors": [],
            "truncated": False,
        }

        # I1/I12: nothing may be retained against a missing or stale policy snapshot, so
        # there is no point spending a crt.sh query either.
        snapshot = self.ctx.snapshot
        if snapshot is None:
            summary["blocked"] = "no scope snapshot (verify live policy first)"
            self.log.warning("crtsh: %s", summary["blocked"])
            return summary
        if snapshot.is_stale(self.ctx.clock_now()):
            summary["blocked"] = "scope snapshot is stale; re-fetch + re-bind required"
            self.log.warning("crtsh: %s", summary["blocked"])
            return summary

        apexes = self._apexes(seeds, summary)
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

            names, err, scan_capped = self._names(body)
            if err:
                self.log.warning("crtsh: %%.%s unusable (%s); skipping", apex, err)
                summary["errors"].append({"apex": apex, "error": err})
                continue
            if scan_capped:
                summary["truncated"] = True
                self.log.warning("crtsh: %%.%s exceeded the %d-name scan cap; requeue for the rest",
                                 apex, MAX_SCAN_PER_APEX)

            # Evidence is stored lazily, on the first in-scope name: an apex whose rows are
            # entirely out of scope must leave nothing behind (§2 — retention is the gate).
            ref = None
            evidence_tried = False
            drops = {"events": 0}
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
                    self._record_drop(host, binding, summary, drops)
                    dropped += 1
                    continue

                if not evidence_tried:
                    evidence_tried = True
                    ref = self._store_evidence(apex, body, summary)

                node_id = f"dns:{host}"
                if ref is not None and self._already_recorded(node_id, ref.sha256):
                    # Same source, same evidence sha: a replay, not a new observation.
                    summary["unchanged"] += 1
                    continue

                self.ctx.graph.upsert_node(make_node(
                    "DNSName", node_id,
                    binding=binding,
                    source=SOURCE,
                    now=self.ctx.clock_now(),
                    # Scalar attrs are fork-triggers on re-observation, so keep this to one
                    # always-identical flag; the apex that found the name lives in the
                    # evidence region instead.
                    attrs={"ct_logged": True},
                    evidence=[ref] if ref is not None else [],
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
    def _apexes(self, seeds: list, summary: dict) -> list[str]:
        """Distinct registrable apexes to query, in seed order. Tolerates an empty list."""

        out: list[str] = []
        for seed in seeds or []:
            host = normalize_host(_strip_wildcard(self._seed_host(seed)))
            if not host or classify(host) == "ip":
                continue  # a CT identity search is a name search; raw IPs have no apex
            apex = registrable_domain(host)
            # The apex is interpolated into the query URL and into the evidence region, so
            # accept only a clean fqdn: ``normalize_host`` strips a scheme/path/port but not
            # a stray ``?``/``&``/``@``, and a junk seed must not shape either string.
            if not apex or len(apex) > 253 or not _FQDN_RE.match(apex):
                summary["rejected_seeds"] += 1
                self.log.warning("crtsh: ignoring seed %r: %r is not a usable apex", seed, apex)
                continue
            if apex not in out:
                out.append(apex)
        if len(out) > MAX_APEXES:
            self.log.warning("crtsh: %d seed apexes exceeds the %d cap; deferring the rest",
                             len(out), MAX_APEXES)
            summary["truncated"] = True
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
                stream=True,  # so MAX_RESPONSE_BYTES bounds what is pulled off the wire
            )
        except requests.RequestException as exc:
            return "", f"request failed: {type(exc).__name__}"
        except Exception as exc:  # unknown transport layer; a module never crashes the run
            return "", f"unexpected transport error: {type(exc).__name__}"

        try:
            status = getattr(resp, "status_code", 0)
            if status != 200:
                # crt.sh rate-limits with 429/503 under load. Back off, never retry-hammer.
                return "", f"HTTP {status}"
            return self._read_capped(resp)
        except requests.RequestException as exc:
            return "", f"read failed: {type(exc).__name__}"
        except Exception as exc:  # a half-broken response object must not abort the run
            return "", f"unexpected read error: {type(exc).__name__}"
        finally:
            closer = getattr(resp, "close", None)
            if callable(closer):
                try:
                    closer()
                except Exception:  # pragma: no cover - close() is best-effort
                    pass

    @staticmethod
    def _read_capped(resp) -> tuple[str, str]:
        """Read at most ``MAX_RESPONSE_BYTES``; a longer body is refused mid-stream.

        Prefers the chunked reader so the cap bounds what is actually transferred, and falls
        back to ``.text`` for a response object that cannot stream.
        """

        iter_content = getattr(resp, "iter_content", None)
        if callable(iter_content):
            chunks: list[bytes] = []
            total = 0
            for chunk in iter_content(_READ_CHUNK):
                if not chunk:
                    continue
                if isinstance(chunk, str):
                    chunk = chunk.encode("utf-8", "replace")
                total += len(chunk)
                if total > MAX_RESPONSE_BYTES:
                    return "", f"response larger than the {MAX_RESPONSE_BYTES}-byte cap"
                chunks.append(chunk)
            return b"".join(chunks).decode("utf-8", "replace"), ""

        body = getattr(resp, "text", "") or ""
        if not isinstance(body, str):
            return "", f"response body was {type(body).__name__}, not text"
        if len(body.encode("utf-8", "replace")) > MAX_RESPONSE_BYTES:
            return "", f"response larger than the {MAX_RESPONSE_BYTES}-byte cap"
        return body, ""

    @staticmethod
    def _names(body: str) -> tuple[list[str], str, bool]:
        """Parse a crt.sh JSON array into canonical lowercase fqdns.

        Returns ``(names, error, scan_capped)``. ``name_value`` is newline-separated and
        holds every SAN of the matching cert. A leading ``*.`` wildcard label is stripped
        (the wildcard itself is not a host, and a non-prefix ``*`` makes the name unusable),
        and email SANs plus IP SANs are dropped rather than ingested
        (``safety-model.md`` §6).
        """

        try:
            rows = json.loads(body)
        except (ValueError, TypeError):
            return [], "response was not valid JSON", False
        if not isinstance(rows, list):
            return [], "response JSON was not a list of certificate rows", False

        out: list[str] = []
        for row in rows:
            if len(out) >= MAX_SCAN_PER_APEX:
                return out, "", True
            if not isinstance(row, dict):
                continue
            for line in str(row.get("name_value", "")).splitlines():
                line = line.strip()
                if not line or "@" in line:
                    continue  # an email SAN is other-person data: do not collect it
                host = normalize_host(_strip_wildcard(line))
                if not host or len(host) > 253 or not _FQDN_RE.match(host):
                    continue
                if classify(host) == "ip":
                    continue  # IP SANs are the network module's domain, not a DNSName
                out.append(host)
                if len(out) >= MAX_SCAN_PER_APEX:
                    return out, "", True
        return out, "", False

    # --- retention ---------------------------------------------------------
    def _store_evidence(self, apex: str, body: str, summary: dict):
        """PII-minimize the raw response, store it once, and log the capture.

        Returns the :class:`~recon.models.EvidenceRef`, or ``None`` if the store is
        unwritable — an unusable evidence store downgrades provenance, it does not abort
        the run. The raw response's digest goes in the event (not in node attrs, where a
        per-run scalar would spuriously fork the node) so the minimized blob stays
        auditable against the live source.
        """

        minimized, redactions = _minimize(body)
        region = f"crtsh:q=%25.{apex}"
        if redactions:
            region += ";pii-minimized"
        try:
            ref = self.ctx.evidence.put_text(minimized, region=region)
        except OSError as exc:
            self.log.warning("crtsh: evidence store unavailable for %%.%s: %s", apex, exc)
            return None
        summary["pii_redactions"] += redactions
        self.ctx.graph.log.append("evidence_captured", {
            "sha256": ref.sha256,
            "region": ref.region,
            "module": self.name,
            "source": "crt.sh",
            "source_sha256": sha256_bytes(body.encode("utf-8", "replace")),
            "pii_redactions": redactions,
        })
        return ref

    def _already_recorded(self, node_id: str, sha256: str) -> bool:
        """True if this node already carries this exact evidence sha from this module.

        ``store._merge`` corroborates (log-odds +delta) on *any* re-observation carrying a
        provenance chain, so re-upserting an unchanged response would let one CT source
        corroborate itself across runs. A genuinely changed response has a different sha
        and is folded in normally.
        """

        existing = self.ctx.graph.store.get(node_id)
        if existing is None:
            return False
        if not any(step.tool == SOURCE for step in existing.provenance.chain):
            return False
        return any(e.sha256 == sha256 for e in existing.evidence)

    def _record_drop(self, host: str, binding, summary: dict, drops: dict) -> None:
        """Count a non-retained name and put the refusal in the replayable event log.

        Negative space is first-class (``docs/SPEC.md`` §4.2): a replay must be able to show
        what CT offered and what the policy refused, not only what was kept. The per-apex
        event cap keeps a pathological response from flooding the log, and the overflow is
        counted in the summary rather than silently discarded.
        """

        verdict = binding.verdict.value
        summary["dropped_by_verdict"][verdict] = summary["dropped_by_verdict"].get(verdict, 0) + 1
        summary["dropped_out_of_scope"] += 1
        if drops["events"] >= MAX_DROP_EVENTS_PER_APEX:
            summary["drop_events_truncated"] += 1
            return
        drops["events"] += 1
        self.ctx.graph.log.append("scope_binding_set", {
            "value": host,
            "kind": "host",
            "verdict": verdict,
            "rule": binding.rule_matched,
            "snapshot_id": binding.snapshot_id,
            "module": self.name,
            "retained": False,
        })


__all__ = ["CrtShModule", "CRTSH_URL", "VERB", "SOURCE", "CT_LOG_ODDS"]
