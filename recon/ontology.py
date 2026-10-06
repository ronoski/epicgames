"""The closed ontology registry.

Loads ``schema/ontology.json`` and exposes the closed set of node and edge types. The
autonomous loop cannot use a type absent from this registry; a genuinely new relationship
must be promoted from ``proposed_additions`` by a human before use. This mirrors the
"cannot invent a type" invariant from the spec.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path


def _schema_path() -> Path:
    # schema/ sits next to the package root (repo/recon/.. -> repo/schema)
    return Path(__file__).resolve().parent.parent / "schema" / "ontology.json"


@lru_cache(maxsize=1)
def _registry() -> dict:
    return json.loads(_schema_path().read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def node_types() -> frozenset[str]:
    return frozenset(_registry()["node_types"].keys())


@lru_cache(maxsize=1)
def edge_types() -> frozenset[str]:
    return frozenset(_registry()["edge_types"])


@lru_cache(maxsize=1)
def proposed_edges() -> frozenset[str]:
    raw = _registry().get("proposed_additions", {}).get("edges", [])
    # entries look like "originated_by (NetBlock->ASN)"; keep the bare name
    return frozenset(e.split(" ", 1)[0] for e in raw)


class OntologyError(ValueError):
    """Raised when a node/edge type is not in the closed registry."""


def assert_node_type(t: str) -> None:
    if t not in node_types():
        raise OntologyError(
            f"unknown node type {t!r}; closed set is {sorted(node_types())}"
        )


def assert_edge_type(t: str) -> None:
    if t in edge_types():
        return
    if t in proposed_edges():
        raise OntologyError(
            f"edge type {t!r} is only PROPOSED; a human must promote it before use "
            f"(record it as corroborates/contradicts evidence meanwhile)"
        )
    raise OntologyError(
        f"unknown edge type {t!r}; closed set is {sorted(edge_types())}"
    )
