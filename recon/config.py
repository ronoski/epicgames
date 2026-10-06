"""Configuration loading."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .scope import Scope


@dataclass
class Config:
    scope: Scope
    targets: list[str] = field(default_factory=list)
    modules: list[str] = field(default_factory=lambda: ["seeds", "crtsh"])
    rate_qps: float = 2.0
    rate_capacity: float = 4.0
    # Third-party/OSINT source budget (crt.sh, archive.org). Separate from the
    # target's budget per safety-model.md section 4.
    third_party_qps: float = 1.0
    third_party_capacity: float = 5.0
    per_target_concurrency: int = 1
    passive_first: bool = True
    allow_active: bool = False  # active modules are OFF by default
    allow_live_credential_use: bool = False
    user_agent: str = "recon-workflow/0.1 (+authorized-testing)"
    timeout: float = 8.0
    # Policy snapshot inputs (verify-live before any active run).
    policy_text: str = ""
    policy_half_life: str = "PT24H"
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Config":
        scope = Scope.from_config(data)
        rate = data.get("rate", {})
        return cls(
            scope=scope,
            targets=list(data.get("targets", []) or data.get("scope", {}).get("include", [])),
            modules=list(data.get("modules", ["seeds", "crtsh"])),
            rate_qps=float(rate.get("global_qps_ceiling", 2.0)),
            rate_capacity=float(rate.get("capacity", max(float(rate.get("global_qps_ceiling", 2.0)), 4.0))),
            third_party_qps=float(rate.get("third_party_qps", 1.0)),
            third_party_capacity=float(rate.get("third_party_capacity", 5.0)),
            per_target_concurrency=int(rate.get("per_target_concurrency", 1)),
            passive_first=bool(data.get("passive_first", True)),
            allow_active=bool(data.get("allow_active", False)),
            allow_live_credential_use=bool(data.get("allow_live_credential_use", False)),
            user_agent=str(data.get("user_agent", "recon-workflow/0.1 (+authorized-testing)")),
            timeout=float(data.get("timeout", 8.0)),
            policy_text=str(data.get("policy_text", "")),
            policy_half_life=str(data.get("policy_half_life", "PT24H")),
            raw=data,
        )

    @classmethod
    def load(cls, path: str | Path) -> "Config":
        path = Path(path)
        text = path.read_text(encoding="utf-8")
        data = json.loads(text) if path.suffix == ".json" else yaml.safe_load(text)
        if not isinstance(data, dict):
            raise ValueError(f"config at {path} is not a mapping")
        return cls.from_dict(data)
