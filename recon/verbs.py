"""The closed recon-verb whitelist (``docs/safety-model.md`` §3).

The scheduler can only dispatch a verb on the allowed list. Blocked verbs can never be
scheduled; human-gated verbs are enqueued for authorization and never auto-run.
"""

from __future__ import annotations

ALLOWED: frozenset[str] = frozenset({
    "resolve", "enumerate", "passive-collect", "fingerprint",
    "http-GET", "http-HEAD", "read-openapi", "graphql-introspect",
    "parse", "crawl-within-scope", "port-scan", "bucket-list",
    "hash", "unzip", "strings", "nm-symbols", "static-decompile",
    "parse-manifest", "parse-catalog", "diff-manifest",
    "extract-endpoint", "extract-client-id",
})

HUMAN_GATED: frozenset[str] = frozenset({
    "graphql-field-suggestion", "response-diff-param-mining", "content-discovery-wordlist",
})

BLOCKED: frozenset[str] = frozenset({
    "write", "mutate", "credential-brute", "otp-brute", "login-brute",
    "exploit", "fuzz-at-volume", "dos", "auth-bypass", "waf-evasion",
    "rate-evasion", "geo-evasion", "data-exfil", "takeover-claim",
    "bucket-write", "dependency-confusion-publish", "email-spoof-test",
    "id-enumeration-others", "persona-lookup", "patch", "inject",
    "hook-runtime", "bypass", "circumvent", "crack", "keygen", "repack",
    "redistribute", "memory-write", "server-call-forged-arg",
})

# Active (traffic-to-target) verbs. Passive verbs touch only third-party/OSINT sources.
ACTIVE: frozenset[str] = frozenset({
    "resolve", "http-GET", "http-HEAD", "read-openapi", "graphql-introspect",
    "crawl-within-scope", "port-scan", "bucket-list",
})


class VerbError(RuntimeError):
    pass


class BlockedVerb(VerbError):
    pass


class HumanGatedVerb(VerbError):
    pass


def assert_schedulable(verb: str) -> None:
    """Raise unless ``verb`` may be auto-dispatched by the autonomous loop."""

    if verb in BLOCKED:
        raise BlockedVerb(f"verb {verb!r} is on the blocked list and can never be scheduled")
    if verb in HUMAN_GATED:
        raise HumanGatedVerb(f"verb {verb!r} is human-gated; enqueue for authorization, do not auto-run")
    if verb not in ALLOWED:
        raise VerbError(f"verb {verb!r} is not on the recon-verb whitelist")


def is_active(verb: str) -> bool:
    return verb in ACTIVE
