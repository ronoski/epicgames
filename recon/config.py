"""Configuration loading and defaults.

Config is a YAML (or JSON) file. The only required section is ``scope`` with at
least one ``include`` rule; everything else has conservative defaults.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


DEFAULTS: dict[str, Any] = {
    "concurrency": 10,
    "rate_per_second": 5.0,
    "timeout": 8.0,
    "modules": [
        "crtsh",
        "dns_bruteforce",
        "resolver",
        "http_probe",
        "port_scan",
        "content_discovery",
    ],
    "ports": [80, 443, 8080, 8443, 22, 21, 25, 3389, 8000, 8888],
    "http_schemes": ["https", "http"],
    "user_agent": "recon-workflow/0.1 (+authorized-testing)",
    "subdomain_wordlist": None,
    "content_wordlist": None,
    "max_subdomain_candidates": 2000,
}


@dataclass
class Config:
    scope: dict[str, Any]
    concurrency: int = DEFAULTS["concurrency"]
    rate_per_second: float = DEFAULTS["rate_per_second"]
    timeout: float = DEFAULTS["timeout"]
    modules: list[str] = field(default_factory=lambda: list(DEFAULTS["modules"]))
    ports: list[int] = field(default_factory=lambda: list(DEFAULTS["ports"]))
    http_schemes: list[str] = field(
        default_factory=lambda: list(DEFAULTS["http_schemes"])
    )
    user_agent: str = DEFAULTS["user_agent"]
    subdomain_wordlist: str | None = DEFAULTS["subdomain_wordlist"]
    content_wordlist: str | None = DEFAULTS["content_wordlist"]
    max_subdomain_candidates: int = DEFAULTS["max_subdomain_candidates"]
    targets: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Config":
        if "scope" not in data or not data["scope"].get("include"):
            raise ValueError(
                "config must define scope.include with at least one in-scope rule"
            )
        merged = {**DEFAULTS, **{k: v for k, v in data.items() if k != "scope"}}
        return cls(
            scope=data["scope"],
            concurrency=int(merged["concurrency"]),
            rate_per_second=float(merged["rate_per_second"]),
            timeout=float(merged["timeout"]),
            modules=list(merged["modules"]),
            ports=[int(p) for p in merged["ports"]],
            http_schemes=list(merged["http_schemes"]),
            user_agent=str(merged["user_agent"]),
            subdomain_wordlist=merged.get("subdomain_wordlist"),
            content_wordlist=merged.get("content_wordlist"),
            max_subdomain_candidates=int(merged["max_subdomain_candidates"]),
            targets=list(data.get("targets", [])),
            raw=data,
        )

    @classmethod
    def load(cls, path: str | Path) -> "Config":
        path = Path(path)
        text = path.read_text(encoding="utf-8")
        if path.suffix in (".json",):
            data = json.loads(text)
        else:
            data = yaml.safe_load(text)
        if not isinstance(data, dict):
            raise ValueError(f"config at {path} is not a mapping")
        return cls.from_dict(data)
