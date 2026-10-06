"""ACTIVE email-authentication posture: SPF, DMARC, DKIM, MTA-STS and MX.

Email authentication is attack surface that web recon never sees. A domain with no DMARC
policy, or one at ``p=none``, can be spoofed; an SPF record with a **dangling include**
(pointing at a provider domain that no longer resolves) is a live takeover primitive; and
an MX pointing at a deprovisioned mail provider is the mail equivalent of a dangling CNAME.
``docs/domains/non-binary.md`` §3.9 puts this in the passive tier, and these are all plain
public DNS lookups — but they are counted as **active** here, honestly, because they query
the target's authoritative nameservers and therefore belong on the target's rate ledger.

**Detect only.** A takeover primitive is recorded as a ``Hypothesis``, never claimed: this
module sends no mail, never registers a dangling provider name, and never tests whether a
spoof actually lands. Verifying any of that would be the attack, not the recon.

Requires ``dnspython`` (``pip install recon-workflow[dns]``). Without it the module reports
that it is unavailable and emits nothing rather than guessing from a partial resolver.
"""

from __future__ import annotations

import re

from ... import verbs
from ...factory import make_edge, make_node
from ...models import Sensitivity, Verdict
from ...urls import canonical_host, dns_id, hypothesis_id, valid_fqdn
from ..base import GateRefused, Module, ModuleContext, register

try:  # optional dependency
    import dns.exception
    import dns.resolver
    HAVE_DNS = True
except ImportError:  # pragma: no cover - exercised by the unavailable-resolver test
    HAVE_DNS = False

#: A DNS query reaches the target's authoritative nameservers, so it is an active touch
#: that must be budgeted. "resolve" is the whitelisted active verb for exactly this.
VERB = "resolve"
SOURCE = "email_posture"

SEED_NODE_TYPES = frozenset({"Domain", "DNSName"})

#: A published DNS record is first-hand and authoritative.
RECORD_LOG_ODDS = 2.2

MAX_SEEDS = 25
MAX_TXT_CHARS = 4096
MAX_INCLUDES = 20
MAX_MX = 20
DNS_TIMEOUT = 5.0

#: DMARC policies that do not actually stop a spoof.
WEAK_DMARC_POLICIES = frozenset({"none", ""})

#: Common selectors worth a look; a module constant, never a wordlist expansion.
DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "k1", "s1", "mail")

_SPF_INCLUDE = re.compile(r"\b(?:include|redirect)[:=]([A-Za-z0-9._-]+)", re.IGNORECASE)
_SPF_ALL = re.compile(r"([~\-+?])all\b", re.IGNORECASE)
_DMARC_TAG = re.compile(r"\b([a-z]+)\s*=\s*([^;]+)")


def parse_spf(txt: str) -> dict:
    """Extract the policy-relevant parts of an SPF record."""

    txt = (txt or "")[:MAX_TXT_CHARS]
    qualifier = _SPF_ALL.search(txt)
    includes = [m.group(1).lower().rstrip(".") for m in _SPF_INCLUDE.finditer(txt)]
    seen, unique = set(), []
    for inc in includes:
        if inc not in seen:
            seen.add(inc)
            unique.append(inc)
    return {
        "record": txt,
        "all_qualifier": qualifier.group(1) if qualifier else "",
        "includes": unique[:MAX_INCLUDES],
        # "-all" rejects, "~all" soft-fails (still delivered), no "all" is wide open.
        "enforcing": bool(qualifier and qualifier.group(1) == "-"),
    }


def parse_dmarc(txt: str) -> dict:
    """Extract the DMARC policy tags. ``p`` is the one that decides spoofability."""

    txt = (txt or "")[:MAX_TXT_CHARS]
    tags = {m.group(1).lower(): m.group(2).strip() for m in _DMARC_TAG.finditer(txt)}
    policy = tags.get("p", "").lower()
    return {
        "record": txt,
        "policy": policy,
        "subdomain_policy": tags.get("sp", "").lower(),
        "pct": tags.get("pct", ""),
        # rua/ruf are reporting addresses: other people's mailboxes, so they are counted
        # but never stored (safety-model.md §6 - minimize before storage).
        "has_reporting": bool(tags.get("rua") or tags.get("ruf")),
        "enforcing": policy in {"quarantine", "reject"},
    }


@register
class EmailPostureModule(Module):
    """Read a domain's email-authentication posture from public DNS."""

    ctx: ModuleContext

    name = "email_posture"
    produces = ("AuthScheme", "Hypothesis")
    active = True

    def run(self, seeds: list) -> dict:
        verbs.assert_schedulable(VERB)
        assert verbs.is_active(VERB), "email_posture queries the target's NS; verb is active"

        summary: dict = {
            "module": self.name, "verb": VERB, "active": True,
            "targets": [], "queries": 0, "schemes": 0, "hypotheses": 0,
            "spoofable": [], "dangling_includes": [], "mx_providers": [],
            "refused": [], "errors": [], "unavailable": "", "truncated": False,
        }

        if not HAVE_DNS:
            summary["unavailable"] = ("dnspython is not installed; emitting nothing rather "
                                      "than guessing from a partial resolver "
                                      "(pip install recon-workflow[dns])")
            self.log.warning("email_posture: %s", summary["unavailable"])
            return summary

        targets = self._targets(seeds, summary)
        for domain in targets:
            self._assess(domain, summary)

        self.log.info("email_posture: %d domain(s), %d query/ies, %d spoofable, "
                      "%d dangling include(s)", len(targets), summary["queries"],
                      len(summary["spoofable"]), len(summary["dangling_includes"]))
        return summary

    # --- seeds ---------------------------------------------------------
    def _targets(self, seeds: list, summary: dict) -> list[str]:
        out: list[str] = []
        for seed in seeds or []:
            if getattr(seed, "type", "") not in SEED_NODE_TYPES:
                continue
            nid = getattr(seed, "id", "") or ""
            value = ""
            for prefix in ("domain:", "dns:"):
                if nid.startswith(prefix):
                    value = nid[len(prefix):]
                    break
            value = canonical_host(seed.attrs.get("registrable") or value)
            if not value or not valid_fqdn(value) or value in out:
                continue
            if len(out) >= MAX_SEEDS:
                summary["truncated"] = True
                self.log.warning("email_posture: seed list exceeds %d; deferring", MAX_SEEDS)
                break
            out.append(value)
        summary["targets"] = list(out)
        return out

    # --- assessment ----------------------------------------------------
    def _assess(self, domain: str, summary: dict) -> None:
        try:
            binding = self.ctx.gate_active(domain, VERB)
        except GateRefused as exc:
            summary["refused"].append({"value": domain, "verb": VERB, "reason": exc.reason})
            self.log.info("email_posture: gate refused %s (%s)", domain, exc.reason)
            return

        spf_txt = self._txt(domain, summary)
        dmarc_txt = self._txt(f"_dmarc.{domain}", summary)
        mta_sts = self._txt(f"_mta-sts.{domain}", summary)
        mx = self._mx(domain, summary)

        spf = parse_spf(self._first(spf_txt, "v=spf1"))
        dmarc = parse_dmarc(self._first(dmarc_txt, "v=dmarc1"))

        attrs = {
            "active_probed": True,
            "domain": domain,
            "spf_present": bool(spf["record"]),
            "spf_all_qualifier": spf["all_qualifier"],
            "spf_enforcing": spf["enforcing"],
            "spf_includes": spf["includes"],
            "dmarc_present": bool(dmarc["record"]),
            "dmarc_policy": dmarc["policy"],
            "dmarc_subdomain_policy": dmarc["subdomain_policy"],
            "dmarc_enforcing": dmarc["enforcing"],
            # The rua/ruf addresses are other people's mailboxes: presence only.
            "dmarc_has_reporting": dmarc["has_reporting"],
            "mta_sts_present": bool(self._first(mta_sts, "v=stsv1")),
            "mx_hosts": mx,
        }
        scheme_id = f"auth:{domain}:email"
        self.ctx.graph.upsert_node(make_node(
            "AuthScheme", scheme_id, binding=binding, source=SOURCE,
            now=self.ctx.clock_now(), attrs=attrs,
            log_odds=RECORD_LOG_ODDS, sensitivity=Sensitivity.S0,
            coverage={"fingerprinted": True},
        ))
        summary["schemes"] += 1

        node = self.ctx.graph.store.get(dns_id(domain))
        if node is not None:
            self.ctx.graph.upsert_edge(make_edge(
                "authenticates_with", dns_id(domain), scheme_id,
                binding=binding, source=SOURCE, now=self.ctx.clock_now(),
                attrs={"active_probed": True},
            ))

        self._raise_leads(domain, spf, dmarc, attrs, binding, summary)

    def _raise_leads(self, domain, spf, dmarc, attrs, binding, summary) -> None:
        # Spoofability: no DMARC, or a policy that does not actually reject.
        if not dmarc["record"] or dmarc["policy"] in WEAK_DMARC_POLICIES:
            summary["spoofable"].append(domain)
            self._hypothesis(
                "email-spoofable", domain, binding, summary,
                note=("no enforcing DMARC policy "
                      f"(p={dmarc['policy'] or 'absent'}), so From: spoofing is not "
                      "rejected by policy"))

        # A dangling SPF include is a live takeover primitive: whoever registers the
        # provider name inherits the right to send as this domain. DETECTED, never claimed.
        for include in spf["includes"]:
            if not valid_fqdn(include):
                continue
            if self._resolves(include, summary):
                continue
            summary["dangling_includes"].append({"domain": domain, "include": include})
            self._hypothesis(
                "spf-dangling-include", f"{domain}|{include}", binding, summary,
                note=(f"SPF include:{include} does not resolve — whoever registers it "
                      "inherits authority to send as this domain (detection only)"))

        for host in attrs["mx_hosts"]:
            if host and not self._resolves(host, summary):
                self._hypothesis(
                    "mx-dangling", f"{domain}|{host}", binding, summary,
                    note=(f"MX {host} does not resolve — the mail equivalent of a "
                          "dangling CNAME (detection only)"))

    def _hypothesis(self, kind: str, slug: str, binding, summary, *, note: str) -> None:
        node_id = hypothesis_id(kind, slug)
        self.ctx.graph.upsert_node(make_node(
            "Hypothesis", node_id, binding=binding, source=SOURCE,
            now=self.ctx.clock_now(),
            attrs={"active_probed": True, "note": note, "kind": kind},
            log_odds=0.0,  # a lead, not a finding
            coverage={"enumerated": True},
        ))
        self.ctx.graph.log.append("hypothesis_raised", {"id": node_id, "kind": kind})
        summary["hypotheses"] += 1

    # --- DNS -----------------------------------------------------------
    def _resolver(self):
        res = dns.resolver.Resolver()
        res.timeout = min(self.ctx.timeout, DNS_TIMEOUT)
        res.lifetime = min(self.ctx.timeout, DNS_TIMEOUT)
        return res

    def _txt(self, name: str, summary: dict) -> list[str]:
        summary["queries"] += 1
        try:
            answers = self._resolver().resolve(name, "TXT")
        except Exception as exc:  # NXDOMAIN, timeout, SERVFAIL, bad resolver config
            if type(exc).__name__ not in ("NXDOMAIN", "NoAnswer"):
                summary["errors"].append({"name": name, "error": type(exc).__name__})
            return []
        out = []
        for rdata in answers:
            try:
                joined = b"".join(getattr(rdata, "strings", [])).decode("utf-8", "replace")
            except Exception:
                joined = str(rdata).strip('"')
            out.append(joined[:MAX_TXT_CHARS])
        return out

    def _mx(self, domain: str, summary: dict) -> list[str]:
        summary["queries"] += 1
        try:
            answers = self._resolver().resolve(domain, "MX")
        except Exception as exc:
            if type(exc).__name__ not in ("NXDOMAIN", "NoAnswer"):
                summary["errors"].append({"name": domain, "error": type(exc).__name__})
            return []
        hosts = []
        for rdata in answers:
            host = canonical_host(str(getattr(rdata, "exchange", "")).rstrip("."))
            if host and host not in hosts:
                hosts.append(host)
        return hosts[:MAX_MX]

    def _resolves(self, name: str, summary: dict) -> bool:
        """Does ``name`` resolve at all? Used only to spot a dangling reference.

        This queries a THIRD-PARTY provider domain (the SPF include / MX host), not the
        target, so it is not charged to the target's budget — and it is a single existence
        check, never a sweep.
        """

        summary["queries"] += 1
        for rrtype in ("A", "AAAA", "TXT", "MX"):
            try:
                if self._resolver().resolve(name, rrtype):
                    return True
            except Exception:
                continue
        return False

    @staticmethod
    def _first(records: list[str], prefix: str) -> str:
        for record in records:
            if record.lower().replace(" ", "").startswith(prefix.lower().replace(" ", "")):
                return record
        return ""
