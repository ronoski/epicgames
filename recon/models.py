"""The per-datum envelope: Node and Edge with the full calculus from ``docs/SPEC.md`` §3.

Every node AND edge carries provenance (a PROV chain), calibrated log-odds confidence
(contradictions fork, never overwrite), content-addressed evidence, temporal fields with
a decay half-life, a snapshotted scope-binding, a sensitivity label, and coverage signals.

These are plain dataclasses with ``to_dict``/``from_dict`` so the event log and the graph
projection can round-trip them without a heavy ORM.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any

from . import ontology


class Sensitivity(str, Enum):
    S0 = "S0"  # public
    S1 = "S1"  # semi-public / embedded
    S2 = "S2"  # write/ingest-capable third-party
    S3 = "S3"  # secret / PII
    S4 = "S4"  # prohibited (anti-cheat / integrity bypass material)


class Verdict(str, Enum):
    IN_SCOPE = "in_scope"
    OUT_OF_SCOPE = "out_of_scope"
    PREFILTER_ONLY = "prefilter_only"
    ADJUDICATION_PENDING = "adjudication_pending"


class ConfidenceState(str, Enum):
    OBSERVED = "observed"
    CORROBORATED = "corroborated"
    VERIFIED = "verified"


@dataclass
class ProvStep:
    evidence_id: str
    tool: str
    tool_version: str
    rule_id: str
    rule_version: str
    config_hash: str = ""


@dataclass
class Provenance:
    chain: list[ProvStep] = field(default_factory=list)

    def merge(self, other: "Provenance") -> None:
        seen = {(s.evidence_id, s.tool, s.rule_id, s.rule_version) for s in self.chain}
        for step in other.chain:
            key = (step.evidence_id, step.tool, step.rule_id, step.rule_version)
            if key not in seen:
                self.chain.append(step)
                seen.add(key)


# Promotion thresholds in log-odds. ~0.0 => p=0.5; 2.2 => ~0.9; 3.0 => ~0.95.
_CORROBORATED_AT = 2.2
_VERIFIED_AT = 3.0


@dataclass
class Penalty:
    reason: str
    logodds_delta: float  # additive in log-odds (NOT a probability multiplier)


@dataclass
class Confidence:
    log_odds: float = 0.0
    independent_sources: int = 1
    penalties: list[Penalty] = field(default_factory=list)
    forked_from: str | None = None

    @property
    def probability(self) -> float:
        x = self.log_odds + sum(p.logodds_delta for p in self.penalties)
        return 1.0 / (1.0 + math.exp(-x))

    @property
    def state(self) -> ConfidenceState:
        eff = self.log_odds + sum(p.logodds_delta for p in self.penalties)
        if eff >= _VERIFIED_AT:
            return ConfidenceState.VERIFIED
        if eff >= _CORROBORATED_AT:
            return ConfidenceState.CORROBORATED
        return ConfidenceState.OBSERVED

    def corroborate(self, delta: float) -> None:
        """Fold in an independent corroborating observation (log-odds add)."""

        self.log_odds += delta
        self.independent_sources += 1


@dataclass
class EvidenceRef:
    sha256: str
    region: str = ""
    encrypted_at_rest: bool = True


@dataclass
class Temporal:
    first_seen: str
    last_seen: str
    last_verified: str
    decay_half_life: str  # ISO-8601 duration, per fact class


@dataclass
class ScopeBinding:
    verdict: Verdict
    snapshot_id: str
    observed_at: str
    rule_matched: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.verdict, Verdict):
            self.verdict = Verdict(self.verdict)

    @property
    def actionable(self) -> bool:
        return self.verdict == Verdict.IN_SCOPE


@dataclass
class Datum:
    """Common base for Node and Edge."""

    id: str
    type: str
    provenance: Provenance
    confidence: Confidence
    temporal: Temporal
    scope_binding: ScopeBinding
    attrs: dict[str, Any] = field(default_factory=dict)
    evidence: list[EvidenceRef] = field(default_factory=list)
    sensitivity: Sensitivity = Sensitivity.S0
    coverage: dict[str, bool] = field(default_factory=dict)
    data_subject: str = "none"  # self | other | none

    kind: str = "node"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["sensitivity"] = self.sensitivity.value
        d["scope_binding"]["verdict"] = self.scope_binding.verdict.value
        return d


@dataclass
class Node(Datum):
    kind: str = "node"

    def __post_init__(self) -> None:
        ontology.assert_node_type(self.type)


@dataclass
class Edge(Datum):
    frm: str = ""
    to: str = ""
    kind: str = "edge"

    def __post_init__(self) -> None:
        ontology.assert_edge_type(self.type)
        if not self.frm or not self.to:
            raise ValueError("edge requires both endpoints (frm, to)")
