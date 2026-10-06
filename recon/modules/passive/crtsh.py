"""Passive subdomain discovery via crt.sh certificate transparency logs.

This queries a third-party aggregator (crt.sh) rather than the target itself,
so it is passive from the target's perspective. Every hostname returned is
still scope-checked before being emitted, because CT logs routinely contain
names outside a program's authorized scope.
"""

from __future__ import annotations

import json
from typing import Iterable

import requests

from ...models import Finding, Kind
from ...scope import classify
from ..base import Module, register


@register
class CrtShModule(Module):
    name = "crtsh"
    consumes = ()  # seeded from configured targets
    produces = (Kind.SUBDOMAIN,)
    active = False

    ENDPOINT = "https://crt.sh/"

    def run(self, seeds: list[Finding]) -> Iterable[Finding]:
        domains = self._seed_domains(seeds)
        for domain in domains:
            yield from self._query_domain(domain)

    def _seed_domains(self, seeds: list[Finding]) -> list[str]:
        domains = set()
        for seed in seeds:
            value = seed.value
            if value.startswith("*."):
                value = value[2:]
            if classify(value) == "host":
                domains.add(value)
        return sorted(domains)

    def _query_domain(self, domain: str) -> Iterable[Finding]:
        self.ctx.throttle()
        params = {"q": f"%.{domain}", "output": "json"}
        try:
            resp = requests.get(
                self.ENDPOINT,
                params=params,
                timeout=self.ctx.config.timeout,
                headers={"User-Agent": self.ctx.config.user_agent},
            )
            resp.raise_for_status()
            records = resp.json()
        except (requests.RequestException, json.JSONDecodeError) as exc:
            self.log.warning("crt.sh query for %s failed: %s", domain, exc)
            return

        names: set[str] = set()
        for rec in records:
            raw = rec.get("name_value", "") or ""
            for name in raw.splitlines():
                name = name.strip().lower().lstrip("*.")
                if name:
                    names.add(name)

        emitted = 0
        for name in sorted(names):
            if not self.ctx.in_scope(name):
                self.log.debug("crt.sh: dropping out-of-scope %s", name)
                continue
            emitted += 1
            yield Finding(
                kind=Kind.SUBDOMAIN,
                value=name,
                source=self.name,
                target=domain,
                metadata={"via": "certificate-transparency"},
            )
        self.log.info("crt.sh: %s in-scope names for %s", emitted, domain)
