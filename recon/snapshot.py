"""Scope policy snapshots (``docs/safety-model.md`` §2, ``schema/scope.schema.json``).

A snapshot is a content-hashed, timestamped capture of the live program policy. It is
authoritative at observation time; a snapshot older than its half-life forces a re-fetch +
re-bind before any new ALLOW. This module does not fetch the policy itself (that needs
verified network access to the program); it hashes and ages whatever policy text it is
given.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime
from pathlib import Path

from . import clock
from .coverage import parse_duration


@dataclass
class Snapshot:
    snapshot_id: str
    taken_at: str
    content_sha256: str
    half_life: str = "PT24H"
    program_visibility: str = "unknown"
    # The rule set this snapshot pins. Carried on the snapshot (not just in config) so
    # successive snapshots can be *diffed* — the drift detector needs to know which assets
    # the program listed at each point in time, not merely that the text changed.
    include: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    prefilter: list[str] = field(default_factory=list)

    def is_stale(self, now: datetime | None = None) -> bool:
        now = now or clock.now()
        try:
            taken = datetime.fromisoformat(self.taken_at)
        except ValueError:
            return True
        return (now - taken).total_seconds() > parse_duration(self.half_life).total_seconds()

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Snapshot":
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in known})

    def save(self, path: str | Path) -> Path:
        """Persist so the next run can diff against it (drift is cross-run by nature)."""

        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
        return path

    @classmethod
    def load(cls, path: str | Path) -> "Snapshot | None":
        path = Path(path)
        if not path.exists():
            return None
        try:
            return cls.from_dict(json.loads(path.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, TypeError, ValueError):
            return None


def take_snapshot(
    policy_text: str,
    *,
    now: datetime | None = None,
    half_life: str = "PT24H",
    program_visibility: str = "unknown",
    include: list[str] | None = None,
    exclude: list[str] | None = None,
    prefilter: list[str] | None = None,
) -> Snapshot:
    """Pin the policy. The id is derived from the text AND the rule set.

    Both matter: an editorial change to the policy prose with an unchanged asset list is
    not the same event as an asset being added, and a rule set changing under identical
    prose must still produce a new snapshot id so bindings are re-evaluated.
    """

    rules = {
        "include": sorted(include or []),
        "exclude": sorted(exclude or []),
        "prefilter": sorted(prefilter or []),
    }
    material = (policy_text or "") + "\n" + json.dumps(rules, sort_keys=True)
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
    return Snapshot(
        snapshot_id=f"snap:{digest[:16]}",
        taken_at=clock.iso(now),
        content_sha256=hashlib.sha256((policy_text or "").encode("utf-8")).hexdigest(),
        half_life=half_life,
        program_visibility=program_visibility,
        include=rules["include"],
        exclude=rules["exclude"],
        prefilter=rules["prefilter"],
    )
