"""Scope enforcement: the safety core of the recon workflow.

Every target that any active or passive module is about to touch is checked
against a :class:`Scope`. The policy is intentionally strict:

* **Default deny.** A value is out of scope unless it matches an explicit
  include rule.
* **Exclude wins.** If a value matches any exclude rule it is out of scope,
  even if it also matches an include rule. Out-of-scope assets listed by a
  program are honored above everything else.
* **Kind-aware.** Hostname rules only match hostnames and IP/CIDR rules only
  match IP addresses, so a wildcard domain can never accidentally authorize an
  unrelated IP range and vice versa.

This module is pure and has no network dependencies, which keeps it fully unit
testable and makes the safety property easy to audit.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass


def classify(value: str) -> str:
    """Return ``"ip"`` for an IP address, else ``"host"``.

    CIDR strings classify as ``"ip"`` as well. Anything that is not a valid IP
    literal or network is treated as a hostname.
    """

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
    """Lower-case and strip a hostname (incl. trailing dot and scheme/port)."""

    host = host.strip().lower()
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/", 1)[0]
    # Strip a :port suffix but keep bracketed IPv6 literals intact.
    if host.count(":") == 1 and not host.startswith("["):
        host = host.split(":", 1)[0]
    return host.rstrip(".")


@dataclass(frozen=True)
class ScopeRule:
    """A single include/exclude rule.

    One of ``host``/``wildcard``/``network`` is set depending on ``kind``.
    """

    kind: str  # "host" | "wildcard" | "network"
    raw: str
    host: str | None = None
    network: ipaddress._BaseNetwork | None = None

    @classmethod
    def parse(cls, rule: str, *, wildcard_includes_apex: bool = True) -> "ScopeRule":
        rule = rule.strip()
        if not rule:
            raise ValueError("empty scope rule")

        if rule.startswith("*."):
            apex = normalize_host(rule[2:])
            if not apex:
                raise ValueError(f"invalid wildcard rule: {rule!r}")
            return cls(kind="wildcard", raw=rule, host=apex)

        if classify(rule) == "ip":
            # strict=False lets a host address like 10.0.0.5/32 or a bare IP
            # both normalize into a network for uniform matching.
            net = ipaddress.ip_network(rule, strict=False)
            return cls(kind="network", raw=rule, network=net)

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
            # Hostname rules never authorize raw IPs.
            return False

        host = normalize_host(value)
        if self.kind == "host":
            return host == self.host
        if self.kind == "wildcard":
            assert self.host is not None
            return host == self.host or host.endswith("." + self.host)
        return False


class Scope:
    """A default-deny include/exclude policy."""

    def __init__(
        self,
        include: list[str] | None = None,
        exclude: list[str] | None = None,
        *,
        wildcard_includes_apex: bool = True,
    ) -> None:
        self.wildcard_includes_apex = wildcard_includes_apex
        self._include = [
            ScopeRule.parse(r, wildcard_includes_apex=wildcard_includes_apex)
            for r in (include or [])
        ]
        self._exclude = [
            ScopeRule.parse(r, wildcard_includes_apex=wildcard_includes_apex)
            for r in (exclude or [])
        ]
        if not self._include:
            raise ValueError(
                "scope has no include rules; refusing to run with an empty "
                "allowlist (default-deny would touch nothing anyway)"
            )

    def is_in_scope(self, value: str) -> bool:
        if not value or not value.strip():
            return False
        if any(rule.matches(value) for rule in self._exclude):
            return False
        return any(rule.matches(value) for rule in self._include)

    def reason(self, value: str) -> str:
        """Human-readable explanation, useful for logs and dry-run output."""

        for rule in self._exclude:
            if rule.matches(value):
                return f"excluded by {rule.raw!r}"
        for rule in self._include:
            if rule.matches(value):
                return f"included by {rule.raw!r}"
        return "not matched by any include rule (default deny)"

    def filter(self, values):
        """Yield only the in-scope values from an iterable."""

        for value in values:
            if self.is_in_scope(value):
                yield value

    @classmethod
    def from_config(cls, cfg: dict) -> "Scope":
        scope_cfg = cfg.get("scope", cfg)
        return cls(
            include=scope_cfg.get("include", []),
            exclude=scope_cfg.get("exclude", []),
            wildcard_includes_apex=scope_cfg.get("wildcard_includes_apex", True),
        )


class ScopeViolation(RuntimeError):
    """Raised when code attempts to act on an out-of-scope target."""
