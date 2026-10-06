"""Core data models shared across the recon pipeline.

Everything a module discovers is normalized into a :class:`Finding`. A finding
is uniquely identified by ``(kind, value)`` which the storage layer uses for
deduplication. Modules never talk to each other directly; they emit findings
into the pipeline, and the pipeline feeds the relevant ones back in as seeds
for downstream modules.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class Kind(str, Enum):
    """The category of a finding.

    The string values are stable identifiers persisted in storage and used as
    part of the dedup key, so do not rename them casually.
    """

    SUBDOMAIN = "subdomain"
    IP = "ip"
    PORT = "port"
    HTTP = "http"
    CONTENT = "content"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


@dataclass
class Finding:
    """A single normalized discovery.

    Attributes:
        kind: The category (see :class:`Kind`).
        value: The canonical identifier within that kind. For ``subdomain`` it
            is the hostname; for ``ip`` the address; for ``port`` ``ip:port``;
            for ``http`` the URL; for ``content`` the URL of the hit.
        source: Name of the module that produced the finding.
        target: The in-scope seed this finding was derived from. Kept so
            reports can group discoveries by program target.
        metadata: Arbitrary module-specific detail (status code, title,
            service banner, resolved addresses, ...).
        timestamp: Unix epoch seconds when the finding was created.
    """

    kind: Kind
    value: str
    source: str
    target: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        # Accept plain strings for kind so callers and the storage layer can
        # round-trip without importing the enum everywhere.
        if not isinstance(self.kind, Kind):
            self.kind = Kind(self.kind)
        self.value = self.value.strip()

    @property
    def dedup_key(self) -> tuple[str, str]:
        return (self.kind.value, self.value)

    def merge(self, other: "Finding") -> None:
        """Fold another finding for the same key into this one.

        Metadata is unioned (newer non-empty values win) and the source list is
        combined so a report can show every module that corroborated a finding.
        """

        if self.dedup_key != other.dedup_key:
            raise ValueError("cannot merge findings with different keys")
        sources = set(self.source.split(",")) | set(other.source.split(","))
        self.source = ",".join(sorted(s for s in sources if s))
        for key, val in other.metadata.items():
            if val not in (None, "", [], {}):
                self.metadata[key] = val

    def to_row(self) -> dict[str, Any]:
        row = asdict(self)
        row["kind"] = self.kind.value
        row["metadata"] = json.dumps(self.metadata, sort_keys=True)
        return row

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> "Finding":
        meta = row.get("metadata") or "{}"
        if isinstance(meta, str):
            meta = json.loads(meta)
        return cls(
            kind=Kind(row["kind"]),
            value=row["value"],
            source=row["source"],
            target=row.get("target", ""),
            metadata=meta,
            timestamp=row.get("timestamp", time.time()),
        )
