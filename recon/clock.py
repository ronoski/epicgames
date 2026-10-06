"""Time source.

Centralized so tests can inject deterministic timestamps and the event log stays
reproducible. Production code calls :func:`now`; tests pass explicit ``datetime`` values
into the functions that accept them.
"""

from __future__ import annotations

from datetime import datetime, timezone


def now() -> datetime:
    """Return the current time as an aware UTC datetime."""

    return datetime.now(timezone.utc)


def iso(dt: datetime | None = None) -> str:
    """Serialize a datetime to RFC3339/ISO-8601, defaulting to :func:`now`."""

    return (dt or now()).isoformat()
