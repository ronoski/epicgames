"""SQLite-backed storage with deduplication.

Findings are keyed by ``(kind, value)``. Re-discovering the same thing merges
sources and metadata into the existing row rather than creating duplicates, so
repeated or resumed runs converge instead of growing without bound. This makes
the store safe for an autonomous loop that re-runs stages as new seeds appear.
"""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path
from typing import Iterable, Iterator

from .models import Finding, Kind


SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    kind       TEXT NOT NULL,
    value      TEXT NOT NULL,
    source     TEXT NOT NULL,
    target     TEXT NOT NULL DEFAULT '',
    metadata   TEXT NOT NULL DEFAULT '{}',
    timestamp  REAL NOT NULL,
    PRIMARY KEY (kind, value)
);
CREATE INDEX IF NOT EXISTS idx_findings_kind ON findings(kind);
CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target);
"""


class Storage:
    """Thread-safe finding store.

    A single connection is shared across threads (guarded by a lock) so worker
    pools can persist as they go. Use as a context manager to ensure the
    connection is closed.
    """

    def __init__(self, path: str | Path = ":memory:") -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    def __enter__(self) -> "Storage":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def add(self, finding: Finding) -> bool:
        """Insert or merge a finding. Returns True if it was newly created."""

        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM findings WHERE kind=? AND value=?",
                (finding.kind.value, finding.value),
            )
            existing_row = cur.fetchone()
            if existing_row is None:
                row = finding.to_row()
                self._conn.execute(
                    "INSERT INTO findings (kind, value, source, target, metadata, "
                    "timestamp) VALUES (:kind, :value, :source, :target, :metadata, "
                    ":timestamp)",
                    row,
                )
                self._conn.commit()
                return True

            existing = Finding.from_row(dict(existing_row))
            existing.merge(finding)
            row = existing.to_row()
            self._conn.execute(
                "UPDATE findings SET source=:source, target=:target, "
                "metadata=:metadata WHERE kind=:kind AND value=:value",
                row,
            )
            self._conn.commit()
            return False

    def add_many(self, findings: Iterable[Finding]) -> int:
        """Add many findings; returns the count of newly created rows."""

        created = 0
        for finding in findings:
            if self.add(finding):
                created += 1
        return created

    def get(self, kind: Kind | str, value: str) -> Finding | None:
        kind_val = kind.value if isinstance(kind, Kind) else kind
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM findings WHERE kind=? AND value=?", (kind_val, value)
            )
            row = cur.fetchone()
        return Finding.from_row(dict(row)) if row else None

    def iter_kind(self, kind: Kind | str) -> Iterator[Finding]:
        kind_val = kind.value if isinstance(kind, Kind) else kind
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM findings WHERE kind=? ORDER BY value", (kind_val,)
            ).fetchall()
        for row in rows:
            yield Finding.from_row(dict(row))

    def all(self) -> list[Finding]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM findings ORDER BY kind, value"
            ).fetchall()
        return [Finding.from_row(dict(r)) for r in rows]

    def counts(self) -> dict[str, int]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT kind, COUNT(*) AS n FROM findings GROUP BY kind"
            ).fetchall()
        return {r["kind"]: r["n"] for r in rows}
