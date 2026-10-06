"""Scope enforcement — the safety core (``docs/safety-model.md`` §2).

Policy is default-deny, exclude-wins, most-restrictive-wins. A value is bound to one of
four verdicts against a content-hashed policy snapshot taken at observation time:

* ``in_scope``             — matches an include rule and no exclude rule. Actionable.
* ``out_of_scope``         — matches an exclude rule (exclude always wins), or matches
                             nothing at all (default deny).
* ``prefilter_only``       — owned-but-unlisted: matches an ownership prefilter but no
                             include rule. Retained capped, never acted on.
* ``adjudication_pending`` — ambiguous; needs human adjudication. Never acted on.

Pure and network-free, so the safety property is unit-testable and auditable.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from .models import ScopeBinding, Verdict


def classify(value: str) -> str:
    """Return ``"ip"`` for an IP address or network, else ``"host"``."""

    value = value.strip().rstrip(".")
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass
    try:
        ipaddress.ip_network(value, strict=False)
        return "ip"
    except ValueError:
        return "host"


def normalize_host(host: str) -> str:
    host = host.strip().lower()
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/", 1)[0]
    if host.count(":") == 1 and not host.startswith("["):
        host = host.split(":", 1)[0]
    return host.rstrip(".")


def registrable_domain(host: str) -> str:
    """Best-effort registrable domain for rate-ledger keying.

    Uses a small known multi-part-suffix table; production should use the Public Suffix
    List. Good enough for ``.com``/``.dev`` Epic domains.
    """

    host = normalize_host(host)
    if classify(host) == "ip":
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    two = ".".join(labels[-2:])
    multi = {"co.uk", "org.uk", "com.au", "co.jp", "com.br", "co.in"}
    if two in multi and len(labels) >= 3:
        return ".".join(labels[-3:])
    return two


@dataclass(frozen=True)
class ScopeRule:
    kind: str  # "host" | "wildcard" | "network"
    raw: str
    host: str | None = None
    network: object | None = None

    @classmethod
    def parse(cls, rule: str) -> "ScopeRule":
        rule = rule.strip()
        if not rule:
            raise ValueError("empty scope rule")
        if rule.startswith("*."):
            apex = normalize_host(rule[2:])
            if not apex:
                raise ValueError(f"invalid wildcard rule: {rule!r}")
            return cls(kind="wildcard", raw=rule, host=apex)
        if classify(rule) == "ip":
            return cls(kind="network", raw=rule, network=ipaddress.ip_network(rule, strict=False))
        return cls(kind="host", raw=rule, host=normalize_host(rule))

    def matches(self, value: str) -> bool:
        kind = classify(value)
        if self.kind == "network":
            if kind != "ip":
                return False
            try:
                addr = ipaddress.ip_address(normalize_host(value))
            except ValueError:
                return False
            return addr in self.network  # type: ignore[operator]
        if kind == "ip":
            return False  # hostname rules never authorize raw IPs
        host = normalize_host(value)
        if self.kind == "host":
            return host == self.host
        if self.kind == "wildcard":
            return host == self.host or host.endswith("." + str(self.host))
        return False

    def specificity(self) -> int:
        """Higher = more specific. Exact host > wildcard > network (by prefix length)."""

        if self.kind == "host":
            return 1000
        if self.kind == "wildcard":
            return 500 + len(str(self.host))
        return getattr(self.network, "prefixlen", 0)


class Scope:
    """A default-deny include/exclude policy with ownership prefilter."""

    def __init__(
        self,
        include: list[str] | None = None,
        exclude: list[str] | None = None,
        prefilter: list[str] | None = None,
        *,
        wildcard_includes_apex: bool = True,
    ) -> None:
        self.wildcard_includes_apex = wildcard_includes_apex
        self._include = [ScopeRule.parse(r) for r in (include or [])]
        self._exclude = [ScopeRule.parse(r) for r in (exclude or [])]
        # Ownership prefilter: owned-but-unlisted assets (e.g. Epic domains not in the
        # program) bind to prefilter_only. Never actionable.
        self._prefilter = [ScopeRule.parse(r) for r in (prefilter or [])]
        if not self._include:
            raise ValueError(
                "scope has no include rules; refusing an empty allowlist (default-deny "
                "would touch nothing)"
            )

    # --- verdict logic -----------------------------------------------------
    def _best(self, rules, value: str) -> ScopeRule | None:
        matches = [r for r in rules if r.matches(value)]
        return max(matches, key=lambda r: r.specificity()) if matches else None

    def verdict(self, value: str) -> tuple[Verdict, str]:
        """Return (verdict, rule_matched). Exclude wins; then include; then prefilter."""

        if not value or not value.strip():
            return Verdict.OUT_OF_SCOPE, "empty value"
        exc = self._best(self._exclude, value)
        inc = self._best(self._include, value)
        if exc and inc and exc.specificity() == inc.specificity():
            # ambiguous tie between an include and exclude of equal specificity
            return Verdict.ADJUDICATION_PENDING, f"tie {inc.raw!r} vs {exc.raw!r}"
        if exc and (not inc or exc.specificity() >= inc.specificity()):
            return Verdict.OUT_OF_SCOPE, f"excluded by {exc.raw!r}"
        if inc:
            return Verdict.IN_SCOPE, f"included by {inc.raw!r}"
        pre = self._best(self._prefilter, value)
        if pre:
            return Verdict.PREFILTER_ONLY, f"owned (prefilter) by {pre.raw!r}"
        return Verdict.OUT_OF_SCOPE, "not matched by any include rule (default deny)"

    def is_in_scope(self, value: str) -> bool:
        return self.verdict(value)[0] == Verdict.IN_SCOPE

    def bind(self, value: str, snapshot_id: str, observed_at: str) -> ScopeBinding:
        verdict, rule = self.verdict(value)
        return ScopeBinding(
            verdict=verdict,
            snapshot_id=snapshot_id,
            observed_at=observed_at,
            rule_matched=rule,
        )

    @classmethod
    def from_config(cls, cfg: dict) -> "Scope":
        s = cfg.get("scope", cfg)
        return cls(
            include=s.get("include", []),
            exclude=s.get("exclude", []),
            prefilter=s.get("prefilter", []),
            wildcard_includes_apex=s.get("wildcard_includes_apex", True),
        )


class ScopeViolation(RuntimeError):
    """Raised when code attempts to act on a non-in-scope target."""
