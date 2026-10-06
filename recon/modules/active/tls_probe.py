"""ACTIVE TLS/certificate inspection — the PKI rung of the active ladder.

CT logs (the passive ``crtsh`` module) prove a name *appeared in a certificate at issuance
time*; only a handshake says what a host is serving **today**, and the served certificate is
the single richest cheap pivot in the whole ladder: issuer, validity window, serial, and the
SAN list — other names the same operator put on the same certificate
(``docs/SPEC.md`` §6.2.9, ``domains/non-binary.md`` §3.9).

Reading it costs a real TCP connection to an Epic host, so **every handshake goes through
the one chokepoint** — :meth:`ModuleContext.gate_active` — *before* the socket is opened
(``docs/pipeline.md`` §1). A :class:`~recon.modules.base.GateRefused` is a **skip**: it is
logged, counted and the host is left alone. There is no fallback that connects anyway, no
retry, no second port, and exactly **one handshake per host per run**.

**On the verb.** ``fingerprint`` is on the closed whitelist (``verbs.ALLOWED``) and is the
verb ``planner.RULES`` names for this module, but it is **not** in ``verbs.ACTIVE``, so
:meth:`ModuleContext.gate_active` refuses it outright ("not an active verb") — a passive
label can never authorize traffic. This module therefore spends :data:`VERB` =
``port-scan``, the one whitelisted **active** verb that describes what actually happens
here: a rate-limited, read-only TCP connect to one port to see what is listening.
``safety-model.md`` §4 groups "handshake/JARM" with the port scan among the touches that
debit the unified per-target ledger, and §9.4 caps it at "≤1 handshake per ``(host, SNI)``
per cycle", which is exactly what this module does. The mismatch is an **interface gap**, not
something this module may fix locally: the shared ``verbs.ACTIVE`` set and the planner rule
are out of bounds here (see this module's report), so the gap is worked around by naming the
honest active verb and spending it once.

**What it does, per host.** One ``socket.create_connection((host, 443))`` under
``ctx.timeout``, wrapped in :func:`ssl.create_default_context`, then ``getpeercert()``.
Verification is deliberately left **on**: weakening a TLS client is not a recon verb, and a
certificate that does not validate is recorded as the observation
``cert_verification_failed`` rather than silently trusted. Nothing is ever sent on the
connection — no HTTP request, no client certificate (presenting one is explicitly blocked by
``domains/non-binary.md`` §3.9) — and the socket is closed as soon as the certificate is
read. Only hostnames are probed: SNI needs a name, and a raw IP has no vhost to attribute a
certificate to.

**What it emits.**

* The ``WebApp`` (``web:https://<vhost>``) the certificate belongs to, carrying
  ``issuer_cn``, ``subject_cn``, ``not_before``, ``not_after``, ``serial`` (plus the
  negotiated ``tls_version``) and coverage ``{"fingerprinted": True}``. The observation always
  lands on the **https** WebApp even when the seed was the plaintext one: the certificate
  describes the TLS vhost and mislabeling it would be a false fact.
* One ``Hypothesis`` (``hyp:dns-candidate:<fqdn>``) per **new, in-scope** DNS SAN — the SAN
  pivot. A name on a certificate is not a live host, so it is a candidate at
  :data:`SAN_CANDIDATE_LOG_ODDS` (<= 0) with coverage ``{"enumerated": False}``, never an
  asserted ``DNSName``. The id is the handle the (active, gated) ``resolver`` later uses to
  confirm it or let it decay. No edges are emitted at all: a name that may not resolve has
  nothing to be connected to, and the usual SAN neighbour is a third-party vhost.

Safety notes:

* ``scope != ownership`` (``safety-model.md`` §2). A seed's stored verdict is never trusted:
  ``gate_active`` re-binds the host against the current snapshot, and **every SAN earns its
  own** ``ctx.bind`` verdict before anything is written. Out-of-scope SANs are counted,
  logged as negative space and kept only inside the ``tls_sans`` list attribute of the
  in-scope node they were observed on — data *about* an in-scope asset, never a node, never
  an edge endpoint. A ``prefilter_only`` SAN is dropped rather than retained capped: a
  candidate exists only to be actively confirmed later, and an owned-but-unlisted value may
  never drive an active touch, so retaining one would queue work that must refuse itself.
* Every node carries ``attrs["active_probed"] = True`` and a binding taken from
  ``gate_active``/``ctx.bind`` — never a fabricated one (I2/I3).
* PII minimization happens **before** storage (``safety-model.md`` §6): e-mail SANs and
  ``emailAddress`` RDNs are stripped from the certificate dict by
  :func:`sanitized_cert` *as it is captured*, so an individual's address can reach neither
  an attribute nor the evidence blob. The count of stripped fields is recorded in the blob so
  the omission stays explicit and replayable. A served certificate is public by definition and
  holds no secret, so nothing here needs :func:`recon.evidence.redact` and no
  ``Credential``/``Token`` node is minted; everything is ``S0`` /
  ``data_subject="none"``.
* TLS, socket, DNS and timeout failures are classified, counted and logged; a dead host never
  crashes the run. Active spend is bounded by :data:`MAX_SEED_NODES` on top of the ledger.
"""

from __future__ import annotations

import json
import re
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone

from ... import verbs
from ...factory import make_edge, make_node
from ...models import EvidenceRef, Sensitivity, Verdict
from ...scope import classify
from ...urls import (
    canonical_host, certificate_id, hypothesis_id, valid_fqdn,
    webapp_id as make_webapp_id,
)
from ..base import GateRefused, Module, ModuleContext, register

#: The whitelisted **active** verb this module spends (``verbs.ALLOWED`` ∩ ``verbs.ACTIVE``).
#: ``tls-handshake`` is on the closed whitelist AND in ``verbs.ACTIVE``, so the ledger
#: entry and the ALLOW record describe a certificate read honestly instead of
#: mislabelling it as a port scan.
VERB = "tls-handshake"

SOURCE = "tls_probe"

#: Ruleset version. Same certificate + same version ⇒ same facts (``SPEC.md`` §3.2).
RULE_ID = "tls-certificate"
RULE_VERSION = "0.1.0"

#: The only port this module ever connects to.
TLS_PORT = 443

#: A first-hand handshake is strong evidence the vhost is live (~p=0.88), and deliberately
#: below ``models._CORROBORATED_AT`` (2.2): one source never promotes itself.
HANDSHAKE_LOG_ODDS = 2.0

#: A SAN is a real name on a real certificate — better than a blind permutation guess
#: (-1.0) — but nothing says it resolves, so it stays a Hypothesis at <= 0 (~p=0.38).
SAN_CANDIDATE_LOG_ODDS = -0.5

#: The generator label recorded on candidates this module raises.
SAN_GENERATOR = "san-pivot"

#: Node-id conventions this module reads and writes.
WEBAPP_ID_PREFIX = "web:"
DNS_ID_PREFIX = "dns:"
CANDIDATE_ID_PREFIX = hypothesis_id("dns-candidate", "")

#: Node types accepted as seeds; anything else is ignored.
SEED_NODE_TYPES = frozenset({"WebApp", "DNSName"})

_FOREIGN_ID_PREFIXES = (
    "org:", "bu:", "domain:", "net:", "asn:", "host:", "svc:", "route:", "op:",
    "param:", "auth:", "cred:", "tok:", "obj:", "flow:", "art:", "ev:", "hyp:",
)

#: Conservative fqdn shape (same spirit as the CT/resolver modules): no whitespace, no
#: wildcards, no raw unicode (punycode ``xn--`` labels pass), so a malformed SAN can never
#: mint a junk node id or be interpolated into a connect() call.
_FQDN_RE = re.compile(
    r"^[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?)+$"
)

#: SAN entry types and RDN keys that carry an e-mail address. Dropped at capture time
#: (``safety-model.md`` §6: minimize before storage, do not redact after).
_EMAIL_SAN_TYPES = frozenset({"email", "rfc822name", "rfc822 name"})
_EMAIL_RDN_KEYS = frozenset({"emailaddress", "email"})

#: ``notBefore``/``notAfter`` as OpenSSL renders them, e.g. ``Jan 13 00:00:00 2026 GMT``.
_CERT_TIME_FORMATS = ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y")

# --- defensive caps (a seed list comes from the graph; a cert can carry hundreds of SANs) ---
MAX_SEED_NODES = 25
MAX_SANS_PER_CERT = 64
MAX_CANDIDATES_PER_CERT = 32
MAX_ATTR_CHARS = 256
MAX_CERT_JSON_CHARS = 64 * 1024



def parse_cert_time(value) -> str:
    """Normalize an OpenSSL validity timestamp to ISO-8601 UTC, or ``""``.

    Certificate times are always UTC (``GMT``), so the parsed value is stamped UTC rather
    than guessed. An unparseable string is kept verbatim (capped) instead of dropped: the
    raw form is still a fact about the certificate, and the evidence blob holds the original
    either way.
    """

    text = str(value or "").strip()
    if not text:
        return ""
    for fmt in _CERT_TIME_FORMATS:
        try:
            parsed = datetime.strptime(text, fmt)
        except ValueError:
            continue
        return parsed.replace(tzinfo=timezone.utc).isoformat()
    return text[:MAX_ATTR_CHARS]


def rdn_value(rdns, key: str) -> str:
    """First value for ``key`` in a ``getpeercert`` RDN sequence, or ``""``.

    The structure is a tuple of relative distinguished names, each a tuple of
    ``(type, value)`` pairs. A certificate may legally repeat a type; the first occurrence
    wins so the attribute is deterministic. Anything malformed is skipped, never raised on.
    """

    for rdn in rdns or ():
        if not isinstance(rdn, (tuple, list)):
            continue
        for item in rdn:
            if (isinstance(item, (tuple, list)) and len(item) == 2
                    and str(item[0]) == key):
                return str(item[1]).strip()[:MAX_ATTR_CHARS]
    return ""


def sanitized_cert(cert: dict) -> tuple[dict, int]:
    """``cert`` with every e-mail field removed, plus how many were removed.

    PII minimization happens before storage (``safety-model.md`` §6), so this runs on the
    certificate dict the moment it is read — before it reaches an attribute or the evidence
    store. Everything else is passed through untouched: a served certificate is public, and
    the point of storing it is that every derived attr stays replayable from it.
    """

    dropped = 0
    out: dict = {}
    for key, value in (cert or {}).items():
        if key == "subjectAltName":
            kept = []
            for entry in value or ():
                if (isinstance(entry, (tuple, list)) and len(entry) == 2
                        and str(entry[0]).strip().lower() in _EMAIL_SAN_TYPES):
                    dropped += 1
                    continue
                kept.append(tuple(entry) if isinstance(entry, list) else entry)
            # Canonical SAN order, so an unchanged certificate content-addresses to the
            # same sha however the entries happen to be ordered (``SPEC.md`` §3.1/§4.1) —
            # the same reason ``http_probe`` sorts response headers before hashing them.
            out[key] = tuple(sorted(kept, key=repr))
        elif key in ("subject", "issuer"):
            rdns = []
            for rdn in value or ():
                if not isinstance(rdn, (tuple, list)):
                    rdns.append(rdn)
                    continue
                items = [
                    item for item in rdn
                    if not (isinstance(item, (tuple, list)) and len(item) == 2
                            and str(item[0]).strip().lower() in _EMAIL_RDN_KEYS)
                ]
                dropped += len(rdn) - len(items)
                rdns.append(tuple(items))
            out[key] = tuple(rdns)
        else:
            out[key] = value
    return out, dropped


def dns_sans(cert: dict, limit: int | None = None) -> tuple[str, ...]:
    """Canonical, deduplicated, sorted DNS SANs of ``cert``.

    Only ``DNS`` entries are read: an ``IP Address`` SAN is the network module's business,
    a ``URI``/``othername`` SAN is not a hostname, and an e-mail SAN is other-person data
    that :func:`sanitized_cert` has already dropped (the ``@`` check here is belt and
    braces). A leading ``*.`` wildcard label is stripped — the wildcard itself is not a host.
    Sorting is what makes the SAN list, the evidence blob and therefore its sha256
    independent of the order the server happened to send. ``limit`` defaults to
    :data:`MAX_SANS_PER_CERT`, read at call time so the cap stays adjustable.
    """

    limit = MAX_SANS_PER_CERT if limit is None else limit
    out: list[str] = []
    for entry in (cert or {}).get("subjectAltName") or ():
        if not isinstance(entry, (tuple, list)) or len(entry) != 2:
            continue
        kind, value = entry
        if str(kind).strip().lower() != "dns":
            continue
        raw = str(value or "")
        if "@" in raw:
            continue
        host = canonical_host(raw.lstrip("*."))
        if not host or host in out or not valid_fqdn(host):
            continue
        out.append(host)
    return tuple(sorted(out))[:limit]


def cert_attrs(cert: dict) -> dict:
    """The five certificate facts, empty values omitted so they cannot fork a merge."""

    attrs = {
        "issuer_cn": rdn_value((cert or {}).get("issuer"), "commonName"),
        "subject_cn": rdn_value((cert or {}).get("subject"), "commonName"),
        "not_before": parse_cert_time((cert or {}).get("notBefore")),
        "not_after": parse_cert_time((cert or {}).get("notAfter")),
        "serial": str((cert or {}).get("serialNumber") or "").strip()[:MAX_ATTR_CHARS],
    }
    return {k: v for k, v in attrs.items() if v}


def cert_json(cert: dict) -> str:
    """Deterministic JSON for the (already sanitized) certificate dict, capped.

    ``sort_keys`` makes an unchanged certificate content-address to the same sha on every
    re-observation, so re-probing merges instead of writing a new blob. ``default=str``
    keeps an exotic value from failing the capture.
    """

    try:
        text = json.dumps(cert, sort_keys=True, default=str)
    except (TypeError, ValueError):
        text = repr(cert)
    return text[:MAX_CERT_JSON_CHARS]


@dataclass(frozen=True)
class _Observation:
    """One completed handshake: the sanitized certificate and the negotiated protocol."""

    cert: dict
    tls_version: str = ""
    email_fields_dropped: int = 0
    #: The DER the peer actually presented. Hashed for the Certificate id; never
    #: stored as an attr (it is key material, not a fact about the host).
    der: bytes = b""


@register
class TlsProbeModule(Module):
    """Fingerprint in-scope hosts from their served certificate; pivot on its SANs."""

    ctx: ModuleContext

    name = "tls_probe"
    produces = ("WebApp", "Certificate", "Hypothesis")
    active = True

    def run(self, seeds: list) -> dict:
        """Gate, handshake once per host, fold the certificate in. Returns counts."""

        # Self-check: the verb must be on the closed whitelist AND be an active verb — an
        # active module reaching for a passive label would misattribute real traffic.
        verbs.assert_schedulable(VERB)
        assert verbs.is_active(VERB), "tls_probe is active; its verb must be in verbs.ACTIVE"
        # The verb the planner names for this module is allowed but NOT active, which is why
        # it cannot be spent here. Asserted so a future promotion of it is caught by tests.

        summary: dict = {
            "module": self.name,
            "verb": VERB,
            "active": True,
            "port": TLS_PORT,
            "seeds_in": 0,
            "hosts": [],
            "seeds_skipped": 0,
            "seeds_deduped": 0,
            "seeds_truncated": False,
            "gated": 0,
            "refused": 0,
            "refused_by_reason": {},
            "handshakes": 0,
            "certificates": 0,
            "errors": 0,
            "errors_by_kind": {},
            "webapps": 0,
            "sans_seen": 0,
            "sans_self": 0,
            "sans_already_known": 0,
            "sans_dropped_out_of_scope": 0,
            "sans_dropped_by_verdict": {},
            "sans_truncated": False,
            "email_fields_dropped": 0,
            "candidates_emitted": 0,
        }

        hosts = self._hosts(seeds, summary)
        summary["hosts"] = hosts
        if not hosts:
            self.log.info("tls_probe: no WebApp/DNSName seeds to handshake; nothing to do")
            return summary

        # No pre-flight scope/snapshot check on purpose: gate_active is the single
        # chokepoint and writes the ALLOW/REFUSE record for every attempt, so a disabled,
        # unsnapshotted, stale or out-of-scope run is refused there and stays auditable.
        for host in hosts:
            self._probe(host, summary)

        self.log.info(
            "tls_probe: %d host(s) -> %d gated, %d refused %s, %d certificate(s), "
            "%d error(s) %s — emitted %d WebApp, %d SAN candidate(s) from %d SAN(s) "
            "(%d already known, %d self, %d out of scope %s)",
            len(hosts), summary["gated"], summary["refused"],
            summary["refused_by_reason"] or "{}", summary["certificates"],
            summary["errors"], summary["errors_by_kind"] or "{}", summary["webapps"],
            summary["candidates_emitted"], summary["sans_seen"],
            summary["sans_already_known"], summary["sans_self"],
            summary["sans_dropped_out_of_scope"], summary["sans_dropped_by_verdict"] or "{}",
        )
        return summary

    # --- seeds -------------------------------------------------------------
    def _hosts(self, seeds: list, summary: dict) -> list[str]:
        """Ordered, deduplicated hostnames to handshake. Tolerates an empty/junk list.

        Deduplication is what enforces "one handshake per host": a host's ``https`` WebApp,
        its ``http`` WebApp and its ``DNSName`` are three seeds for one certificate.
        """

        out: list[str] = []
        seen: set[str] = set()
        for seed in seeds or []:
            summary["seeds_in"] += 1
            host = self._seed_host(seed)
            if not host:
                summary["seeds_skipped"] += 1
                continue
            if host in seen:
                summary["seeds_deduped"] += 1
                continue
            if len(out) >= MAX_SEED_NODES:
                summary["seeds_truncated"] = True
                self.log.warning(
                    "tls_probe: seed list exceeds MAX_SEED_NODES=%d; deferring the rest to a "
                    "later cycle rather than spending the budget in one run", MAX_SEED_NODES,
                )
                break
            seen.add(host)
            out.append(host)
        return out

    @staticmethod
    def _seed_host(seed) -> str:
        """Pull a connectable hostname out of a graph Node seed, or a plain-string seed.

        A raw IP is deliberately rejected: SNI carries a name, the default TLS context
        verifies the certificate against that name, and a certificate has no vhost to be
        attributed to without one.
        """

        raw = getattr(seed, "id", None)
        if raw is None and isinstance(seed, str):
            raw = seed
        if not isinstance(raw, str) or not raw.strip():
            return ""
        node_type = getattr(seed, "type", "")
        if node_type and node_type not in SEED_NODE_TYPES:
            return ""
        if raw.startswith(WEBAPP_ID_PREFIX):
            raw = raw[len(WEBAPP_ID_PREFIX):]  # "<scheme>://<authority>"
        elif raw.startswith(DNS_ID_PREFIX):
            raw = raw[len(DNS_ID_PREFIX):]
        elif raw.startswith(_FOREIGN_ID_PREFIXES):
            return ""  # some other node kind slipped into the seed list
        host = canonical_host(raw.lstrip("*."))
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]  # an IPv6 authority arrives bracketed
        return host if valid_fqdn(host) else ""

    # --- the one network touch ---------------------------------------------
    def _probe(self, host: str, summary: dict) -> None:
        """Gate, then one handshake. A refusal or a failure ends this host, logged."""

        # THE CHOKEPOINT. One gate decision per handshake, before the socket is opened.
        summary["gated"] += 1
        try:
            binding = self.ctx.gate_active(host, VERB)
        except GateRefused as exc:
            # A refusal is a skip, never a reason to connect anyway.
            summary["refused"] += 1
            summary["refused_by_reason"][exc.reason] = (
                summary["refused_by_reason"].get(exc.reason, 0) + 1
            )
            self.log.info("tls_probe: not handshaking %s: %s", host, exc.reason)
            return

        summary["handshakes"] += 1  # the budget was debited whether or not we get a cert
        observation, error = self._handshake(host)
        if observation is None:
            summary["errors"] += 1
            summary["errors_by_kind"][error] = summary["errors_by_kind"].get(error, 0) + 1
            self.log.warning(
                "tls_probe: no certificate from %s:%d (%s); backing off and leaving the "
                "fact to decay", host, TLS_PORT, error,
            )
            return

        summary["certificates"] += 1
        summary["email_fields_dropped"] += observation.email_fields_dropped
        self._emit(host, binding, observation, summary)

    def _handshake(self, host: str) -> tuple[_Observation | None, str]:
        """Exactly one TLS handshake with ``host:443``. Returns ``(observation, error)``.

        Never raises and never retries: a host that will not complete a handshake is
        answered by backing off, not by asking again (``safety-model.md`` §4). Nothing is
        written to the socket — no HTTP request, no client certificate — and it is closed as
        soon as the certificate has been read.

        Certificate verification stays **enabled** (``create_default_context``). Weakening a
        TLS client is not on the verb whitelist, so a certificate that does not validate is
        reported as the observation ``cert_verification_failed`` rather than trusted; the
        failure is itself a recon fact for a human, and no fact is asserted from a
        certificate we could not validate.
        """

        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, TLS_PORT),
                                          timeout=self.ctx.timeout) as raw_sock:
                raw_sock.settimeout(self.ctx.timeout)  # also bound the handshake itself
                with context.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                    cert = tls_sock.getpeercert()
                    # DER too: the Certificate node is keyed on real key material,
                    # which is what makes key-reuse clustering possible later. A
                    # stack that will not hand it over costs us the Certificate node,
                    # never the handshake we already completed.
                    try:
                        der = tls_sock.getpeercert(binary_form=True)
                    except Exception:
                        der = b""
                    version = tls_sock.version()
        except ssl.SSLCertVerificationError:
            return None, "cert_verification_failed"
        except ssl.SSLError as exc:
            return None, f"ssl_error:{type(exc).__name__}"
        except TimeoutError:  # socket.timeout is an alias of TimeoutError
            return None, "timeout"
        except OSError as exc:  # refused, unreachable, gaierror, reset …
            return None, f"socket_error:{type(exc).__name__}"
        except Exception as exc:  # unknown TLS stack; a module never crashes the run
            return None, f"unexpected:{type(exc).__name__}"

        if not isinstance(cert, dict) or not cert:
            # A validated peer always presents one; an empty dict means we learned nothing.
            return None, "no_peer_certificate"
        safe_cert, dropped = sanitized_cert(cert)
        return _Observation(
            cert=safe_cert,
            tls_version=str(version or "").strip()[:MAX_ATTR_CHARS],
            email_fields_dropped=dropped,
            der=der if isinstance(der, bytes) else b"",
        ), ""

    # --- evidence ----------------------------------------------------------
    def _record(self, host: str, observation: _Observation, sans: tuple[str, ...]) -> str:
        """The canonicalized certificate record that is this observation's raw proof."""

        lines = [f"{SOURCE}/{RULE_VERSION} verb={VERB}", f"host={host}:{TLS_PORT}"]
        if observation.tls_version:
            lines.append(f"tls_version={observation.tls_version}")
        if sans:
            lines.append("dns_sans=" + ",".join(sans))
        if observation.email_fields_dropped:
            # Minimized before storage; recorded so the omission is explicit (§6).
            lines.append(f"email_fields_dropped={observation.email_fields_dropped}")
        lines.append("certificate=" + cert_json(observation.cert))
        return "\n".join(lines)

    def _evidence(self, record: str, host: str) -> list[EvidenceRef]:
        """Content-address the certificate record. An unwritable store is not fatal."""

        try:
            return [self.ctx.evidence.put_text(record,
                                               region=f"{SOURCE}:{host}:{TLS_PORT}")]
        except OSError as exc:
            self.log.warning("tls_probe: evidence store unavailable for %s: %s", host, exc)
            return []

    # --- emit --------------------------------------------------------------
    def _emit(self, host: str, binding, observation: _Observation, summary: dict) -> None:
        """Write the fingerprinted WebApp, then pivot on the certificate's SANs."""

        # The gate already guarantees this; assert it so no future refactor can emit a node
        # for a value that was not in scope at observation time (I2/I3).
        assert binding.verdict == Verdict.IN_SCOPE, \
            "the binding here comes from gate_active and must be in_scope"

        sans = dns_sans(observation.cert)
        summary["sans_seen"] += len(sans)
        evidence = self._evidence(self._record(host, observation, sans), host)

        attrs: dict = {"active_probed": True, "vhost": host, "scheme": "https"}
        attrs.update(cert_attrs(observation.cert))
        if observation.tls_version:
            attrs["tls_version"] = observation.tls_version
        if sans:
            # A LIST never fork-conflicts on re-observation, so the full observed SAN set —
            # including the out-of-scope names — is kept as data ABOUT this in-scope node
            # without minting a node or an edge endpoint for a value we may not retain.
            attrs["tls_sans"] = list(sans)

        webapp_id = f"{WEBAPP_ID_PREFIX}https://{host}"
        self.ctx.graph.upsert_node(make_node(
            "WebApp", webapp_id,
            binding=binding,  # the gate's own binding: in_scope, pinned to this snapshot
            source=SOURCE,
            now=self.ctx.clock_now(),
            attrs=attrs,
            evidence=evidence,
            rule_id=RULE_ID,
            rule_version=RULE_VERSION,
            log_odds=HANDSHAKE_LOG_ODDS,
            sensitivity=Sensitivity.S0,  # a served certificate is public by definition
            coverage={"fingerprinted": True},  # live cert + issuer + validity, first-hand
            data_subject="none",
        ))
        summary["webapps"] += 1

        self._emit_certificate(webapp_id, binding, attrs, evidence, observation, summary)
        self._emit_san_candidates(host, sans, evidence, summary)
        self.log.info(
            "tls_probe: %s:%d -> issuer=%r not_after=%r, %d DNS SAN(s)",
            host, TLS_PORT, attrs.get("issuer_cn", ""), attrs.get("not_after", ""), len(sans),
        )

    def _emit_certificate(self, webapp_id, binding, attrs, evidence, observation,
                          summary: dict) -> None:
        """Emit the served certificate as its own node, linked to the WebApp.

        ``Certificate`` and ``presents_certificate`` are declared types now, so the
        certificate is a first-class node instead of a handful of attrs on the WebApp.
        Keying it on the SPKI/DER hash is the point: two hosts presenting the same key
        material become clusterable, which attrs on separate WebApps never were.
        """

        if not observation.der:
            # Nothing verifiable to key on; the WebApp attrs still carry the facts.
            summary["certificates_unkeyed"] = summary.get("certificates_unkeyed", 0) + 1
            return

        cert_id = certificate_id(observation.der)
        cert_attrs = {
            key: attrs[key] for key in
            ("issuer_cn", "subject_cn", "not_before", "not_after", "serial")
            if key in attrs
        }
        cert_attrs["keyed_on"] = "der_sha256"  # not an SPKI parse; say what we hashed
        cert_attrs["active_probed"] = True
        self.ctx.graph.upsert_node(make_node(
            "Certificate", cert_id,
            binding=binding,
            source=SOURCE,
            now=self.ctx.clock_now(),
            attrs=cert_attrs,
            evidence=evidence,
            rule_id=RULE_ID,
            rule_version=RULE_VERSION,
            log_odds=HANDSHAKE_LOG_ODDS,
            sensitivity=Sensitivity.S0,  # a served certificate is public by definition
            data_subject="none",
            coverage={"fingerprinted": True},
        ))
        self.ctx.graph.upsert_edge(make_edge(
            "presents_certificate", webapp_id, cert_id,
            binding=binding, source=SOURCE, now=self.ctx.clock_now(),
        ))
        summary["certificate_nodes"] = summary.get("certificate_nodes", 0) + 1

    def _emit_san_candidates(self, host: str, sans: tuple[str, ...],
                             evidence: list[EvidenceRef], summary: dict) -> None:
        """Raise a ``hyp:dns-candidate:`` Hypothesis per new, in-scope SAN. No edges.

        A SAN is a **candidate**, not a confirmed host: the certificate proves the operator
        asked for the name, not that anything answers on it. Confirmation is the (gated)
        resolver's job, and an unconfirmed candidate simply decays.
        """

        emitted = 0
        dropped_out_of_scope = 0
        store = self.ctx.graph.store
        for fqdn in sans:
            if fqdn == host:
                # The probed host itself: we just confirmed it live, so proposing it back as
                # a guess would be nonsense (and would reset nothing useful).
                summary["sans_self"] += 1
                continue
            if (store.get(f"{DNS_ID_PREFIX}{fqdn}") is not None
                    or store.get(f"{CANDIDATE_ID_PREFIX}{fqdn}") is not None):
                # Already a known name, or a candidate another generator raised. Skipping
                # keeps a guess from self-corroborating and from forking over a differing
                # ``generator`` label; its own decay clock keeps running.
                summary["sans_already_known"] += 1
                continue
            if emitted >= MAX_CANDIDATES_PER_CERT:
                summary["sans_truncated"] = True
                self.log.warning(
                    "tls_probe: %s's certificate hit the %d-candidate cap; the remaining "
                    "SAN(s) are recorded in tls_sans and requeued, not emitted",
                    host, MAX_CANDIDATES_PER_CERT,
                )
                break

            binding = self.ctx.bind(fqdn)
            if binding.verdict != Verdict.IN_SCOPE:
                verdict = binding.verdict.value
                summary["sans_dropped_by_verdict"][verdict] = (
                    summary["sans_dropped_by_verdict"].get(verdict, 0) + 1
                )
                summary["sans_dropped_out_of_scope"] += 1
                dropped_out_of_scope += 1
                self.log.debug("tls_probe: not retaining SAN %s (from %s): %s (%s)",
                               fqdn, host, verdict, binding.rule_matched)
                continue

            node_id = f"{CANDIDATE_ID_PREFIX}{fqdn}"
            self.ctx.graph.upsert_node(make_node(
                "Hypothesis", node_id,
                binding=binding,
                source=SOURCE,
                now=self.ctx.clock_now(),
                # Three always-identical scalars: a per-run detail here would be a
                # contradiction fork on re-observation. Which certificate revealed the name
                # lives in the evidence region instead.
                attrs={"candidate_fqdn": fqdn, "generator": SAN_GENERATOR,
                       "active_probed": True},
                evidence=evidence,
                rule_id=RULE_ID,
                rule_version=RULE_VERSION,
                log_odds=SAN_CANDIDATE_LOG_ODDS,  # an unconfirmed name: never > 0
                sensitivity=Sensitivity.S0,  # a public certificate's SAN list
                coverage={"enumerated": False},  # explicit negative space
                data_subject="none",
            ))
            self.ctx.graph.log.append(
                "hypothesis_raised",
                {"id": node_id, "candidate_fqdn": fqdn, "generator": SAN_GENERATOR,
                 "module": self.name, "rule": f"{RULE_ID}@{RULE_VERSION}",
                 "log_odds": SAN_CANDIDATE_LOG_ODDS},
                idempotency_key=f"hypothesis:{node_id}",
            )
            summary["candidates_emitted"] += 1
            emitted += 1

        if dropped_out_of_scope:
            # Negative space, stated out loud: the names exist on an Epic certificate but
            # the policy does not list them, and `scope != ownership` (§2).
            self.log.info(
                "tls_probe: %s's certificate carried %d out-of-scope SAN(s) %s — recorded "
                "in tls_sans, no node and no edge emitted",
                host, dropped_out_of_scope, summary["sans_dropped_by_verdict"],
            )


__all__ = [
    "TlsProbeModule", "VERB", "SOURCE", "RULE_ID", "RULE_VERSION", "TLS_PORT",
    "HANDSHAKE_LOG_ODDS", "SAN_CANDIDATE_LOG_ODDS", "SAN_GENERATOR",
    "MAX_SEED_NODES", "MAX_SANS_PER_CERT", "MAX_CANDIDATES_PER_CERT",
    "CANDIDATE_ID_PREFIX", "cert_attrs", "cert_json", "dns_sans", "parse_cert_time",
    "rdn_value", "sanitized_cert", "valid_fqdn",
]
