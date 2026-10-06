"""Scope policy snapshots (``docs/safety-model.md`` §2, ``schema/scope.schema.json``).

A snapshot is a content-hashed, timestamped capture of the live program policy. It is
authoritative at observation time; a snapshot older than its half-life forces a re-fetch +
re-bind before any new ALLOW. This module does not fetch the policy itself (that needs
verified network access to the program); it hashes and ages whatever policy text it is
given.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime

from . import clock
from .coverage import parse_duration


@dataclass
class Snapshot:
    snapshot_id: str
    taken_at: str
    content_sha256: str
    half_life: str = "PT24H"
    program_visibility: str = "unknown"

    def is_stale(self, now: datetime | None = None) -> bool:
        now = now or clock.now()
        try:
            taken = datetime.fromisoformat(self.taken_at)
        except ValueError:
            return True
        return (now - taken).total_seconds() > parse_duration(self.half_life).total_seconds()


def take_snapshot(
    policy_text: str,
    *,
    now: datetime | None = None,
    half_life: str = "PT24H",
    program_visibility: str = "unknown",
) -> Snapshot:
    digest = hashlib.sha256((policy_text or "").encode("utf-8")).hexdigest()
    return Snapshot(
        snapshot_id=f"snap:{digest[:16]}",
        taken_at=clock.iso(now),
        content_sha256=digest,
        half_life=half_life,
        program_visibility=program_visibility,
    )
