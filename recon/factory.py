"""Convenience constructors so modules don't repeat envelope boilerplate."""

from __future__ import annotations

from datetime import datetime

from . import clock
from .models import (
    Confidence, Datum, Edge, EvidenceRef, Node, Penalty, Provenance, ProvStep,
    ScopeBinding, Sensitivity, Temporal,
)

# Sensible default decay half-lives per node type (ISO-8601 durations).
DEFAULT_HALF_LIFE = {
    "DNSName": "P7D", "Host": "P3D", "Service": "P3D", "WebApp": "P7D",
    "Operation": "P30D", "Parameter": "P30D", "AuthScheme": "P30D",
    "Credential": "P90D", "Token": "PT12H", "ObjectType": "P90D",
    "Flow": "P180D", "Artifact": "P365D", "Domain": "P30D",
}


def _temporal(node_type: str, now: datetime) -> Temporal:
    ts = clock.iso(now)
    return Temporal(
        first_seen=ts, last_seen=ts, last_verified=ts,
        decay_half_life=DEFAULT_HALF_LIFE.get(node_type, "P14D"),
    )


def make_node(
    type: str,
    id: str,
    *,
    binding: ScopeBinding,
    source: str,
    now: datetime | None = None,
    attrs: dict | None = None,
    evidence: list[EvidenceRef] | None = None,
    rule_id: str = "default",
    tool_version: str = "0.1.0",
    rule_version: str = "0.1.0",
    log_odds: float = 0.0,
    sensitivity: Sensitivity = Sensitivity.S0,
    coverage: dict | None = None,
    data_subject: str = "none",
) -> Node:
    now = now or clock.now()
    prov = Provenance(chain=[ProvStep(
        evidence_id=(evidence[0].sha256 if evidence else ""),
        tool=source, tool_version=tool_version,
        rule_id=rule_id, rule_version=rule_version,
    )])
    return Node(
        id=id, type=type, provenance=prov,
        confidence=Confidence(log_odds=log_odds),
        temporal=_temporal(type, now), scope_binding=binding,
        attrs=attrs or {}, evidence=evidence or [],
        sensitivity=sensitivity, coverage=coverage or {}, data_subject=data_subject,
    )


def make_edge(
    type: str,
    frm: str,
    to: str,
    *,
    binding: ScopeBinding,
    source: str,
    now: datetime | None = None,
    attrs: dict | None = None,
    log_odds: float = 0.0,
) -> Edge:
    now = now or clock.now()
    prov = Provenance(chain=[ProvStep(
        evidence_id="", tool=source, tool_version="0.1.0",
        rule_id="edge", rule_version="0.1.0",
    )])
    eid = f"{type}:{frm}->{to}"
    return Edge(
        id=eid, type=type, frm=frm, to=to, provenance=prov,
        confidence=Confidence(log_odds=log_odds),
        temporal=_temporal("_edge", now), scope_binding=binding, attrs=attrs or {},
    )
