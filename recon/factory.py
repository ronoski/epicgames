"""Convenience constructors so modules don't repeat envelope boilerplate."""

from __future__ import annotations

from datetime import datetime

from . import clock
from .models import (
    Confidence, Datum, Edge, EvidenceRef, Node, Penalty, Provenance, ProvStep,
    ScopeBinding, Sensitivity, Temporal,
)

# Default decay half-lives per node type (ISO-8601 durations). Chosen by how fast the fact
# class actually changes: DNS moves in days, a netblock allocation in years, a live token
# in hours. A fact past its half-life is re-queued for verification by the planner.
DEFAULT_HALF_LIFE = {
    # fast-moving
    "Token": "PT12H", "Host": "P3D", "Service": "P3D",
    "DNSName": "P7D", "WebApp": "P7D",
    # a guess is meant to be confirmed or let go quickly
    "Hypothesis": "P3D",
    # contract/structure: stable but not permanent
    "Route": "P30D", "Operation": "P30D", "Parameter": "P30D",
    "AuthScheme": "P30D", "Domain": "P30D", "Certificate": "P30D",
    # slow-moving
    "Credential": "P90D", "ObjectType": "P90D",
    "NetBlock": "P180D", "ASN": "P180D", "Flow": "P180D",
    "BusinessUnit": "P365D", "Organization": "P365D", "Artifact": "P365D",
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
