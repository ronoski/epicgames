"""Scope-drift detection and re-binding (``docs/safety-model.md`` §2).

A bug-bounty scope is not static: a program adds an acquisition, retires a property, or
moves an asset out of scope. For a target worked over months that makes drift a first-class
event, not an edge case — and it is a *safety* event, because every retained datum carries
the scope verdict it was observed under. When the policy changes, those verdicts are
assertions about a policy that no longer exists.

So drift does two things:

1. **Reports what changed** — assets added, removed, or moved between include/exclude —
   from a diff of two pinned snapshots (:func:`detect`).
2. **Forces re-binding** — every retained node is re-evaluated against the new snapshot
   (:func:`rebind`). A node that was ``in_scope`` and is now not loses its actionability
   immediately; its history is kept, because deleting it would destroy the record that it
   was once legitimately collected.

The order matters. Re-binding before reporting would silently rewrite the evidence of what
drifted; reporting without re-binding would leave the graph asserting stale authorizations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from . import clock
from .models import Verdict
from .scope import Scope
from .snapshot import Snapshot
from .store import GraphStore


@dataclass
class DriftReport:
    """What changed between two snapshots."""

    from_snapshot: str = ""
    to_snapshot: str = ""
    added: list[str] = field(default_factory=list)       # newly in scope
    removed: list[str] = field(default_factory=list)     # no longer in scope
    newly_excluded: list[str] = field(default_factory=list)
    no_longer_excluded: list[str] = field(default_factory=list)
    prefilter_changed: bool = False
    policy_text_changed: bool = False

    @property
    def drifted(self) -> bool:
        return bool(
            self.added or self.removed or self.newly_excluded
            or self.no_longer_excluded or self.prefilter_changed
            or self.policy_text_changed
        )

    def to_dict(self) -> dict:
        return {
            "from_snapshot": self.from_snapshot,
            "to_snapshot": self.to_snapshot,
            "drifted": self.drifted,
            "added": self.added,
            "removed": self.removed,
            "newly_excluded": self.newly_excluded,
            "no_longer_excluded": self.no_longer_excluded,
            "prefilter_changed": self.prefilter_changed,
            "policy_text_changed": self.policy_text_changed,
        }

    def summary(self) -> str:
        if not self.drifted:
            return "no scope drift"
        bits = []
        for label, items in (("added", self.added), ("removed", self.removed),
                             ("newly excluded", self.newly_excluded),
                             ("un-excluded", self.no_longer_excluded)):
            if items:
                bits.append(f"{len(items)} {label}")
        if self.policy_text_changed and not bits:
            bits.append("policy text changed (asset list unchanged)")
        return "; ".join(bits) or "scope drift"


def detect(old: Snapshot | None, new: Snapshot) -> DriftReport:
    """Diff two snapshots. With no previous snapshot there is nothing to drift from."""

    if old is None:
        return DriftReport(to_snapshot=new.snapshot_id)

    old_inc, new_inc = set(old.include), set(new.include)
    old_exc, new_exc = set(old.exclude), set(new.exclude)
    return DriftReport(
        from_snapshot=old.snapshot_id,
        to_snapshot=new.snapshot_id,
        added=sorted(new_inc - old_inc),
        removed=sorted(old_inc - new_inc),
        newly_excluded=sorted(new_exc - old_exc),
        no_longer_excluded=sorted(old_exc - new_exc),
        prefilter_changed=set(old.prefilter) != set(new.prefilter),
        policy_text_changed=old.content_sha256 != new.content_sha256,
    )


@dataclass
class RebindResult:
    rebound: int = 0
    unchanged: int = 0
    lost_scope: list[str] = field(default_factory=list)   # in_scope -> not
    gained_scope: list[str] = field(default_factory=list)  # not -> in_scope
    changed: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "rebound": self.rebound,
            "unchanged": self.unchanged,
            "lost_scope": self.lost_scope,
            "gained_scope": self.gained_scope,
            "changed": self.changed,
        }


def binding_subject(node) -> str:
    """The value a node's scope verdict is *about*.

    Re-binding has to re-ask the original question ("is this host in scope?"), so it needs
    the subject back out of the node. Prefer what the module recorded; fall back to the id
    suffix, which the ``recon.urls`` grammars make unambiguous.
    """

    for key in ("fqdn", "ip", "host", "registrable", "candidate_fqdn"):
        value = node.attrs.get(key)
        if isinstance(value, str) and value:
            return value
    nid = node.id
    for prefix in ("dns:", "host:", "domain:", "net:"):
        if nid.startswith(prefix):
            return nid[len(prefix):]
    if nid.startswith("web:"):
        rest = nid.split("://", 1)[-1]
        return rest.split("/", 1)[0]
    if nid.startswith("svc:"):
        return nid[len("svc:"):].rsplit(":", 1)[0]
    if nid.startswith("hyp:"):
        return nid.rsplit(":", 1)[-1]
    return ""


def rebind(
    store: GraphStore,
    scope: Scope,
    snapshot: Snapshot,
    *,
    now: datetime | None = None,
    log=None,
) -> RebindResult:
    """Re-evaluate every retained node against ``snapshot``.

    History is preserved: a node that loses scope keeps its data and its provenance and
    simply stops being actionable. Deleting it would destroy the record that it was
    legitimately collected under the previous policy, which is the opposite of an audit
    trail.
    """

    result = RebindResult()
    stamp = clock.iso(now)
    for node in list(store.nodes.values()):
        subject = binding_subject(node)
        if not subject:
            result.unchanged += 1
            continue
        was = node.scope_binding.verdict
        was_snapshot = node.scope_binding.snapshot_id
        fresh = scope.bind(subject, snapshot.snapshot_id, stamp)
        node.scope_binding = fresh
        result.rebound += 1

        verdict_changed = fresh.verdict != was
        snapshot_changed = fresh.snapshot_id != was_snapshot
        if not (verdict_changed or snapshot_changed):
            continue

        entry = {
            "id": node.id, "subject": subject,
            "from": was.value, "to": fresh.verdict.value,
            # The whole new binding, so a replay can APPLY this change rather than just
            # observe that it happened. Without it the re-bind would be lost on rehydration
            # and the graph would keep asserting the superseded verdict.
            "binding": {
                "verdict": fresh.verdict.value,
                "snapshot_id": fresh.snapshot_id,
                "observed_at": fresh.observed_at,
                "rule_matched": fresh.rule_matched,
            },
        }
        # Every re-binding is logged, not just a verdict flip: the snapshot id is part
        # of the binding and invariant I1 checks it, so a node re-bound under a new
        # snapshot must say so or a replay keeps asserting the superseded snapshot.
        if log is not None:
            log.append("scope_binding_set", entry)
        if verdict_changed:
            result.changed.append(entry)
            if was == Verdict.IN_SCOPE and fresh.verdict != Verdict.IN_SCOPE:
                result.lost_scope.append(node.id)
            elif was != Verdict.IN_SCOPE and fresh.verdict == Verdict.IN_SCOPE:
                result.gained_scope.append(node.id)
    result.unchanged = result.rebound - len(result.changed)
    return result
