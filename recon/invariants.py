"""Machine-checkable safety invariants (``docs/safety-model.md`` §9).

These run over the current graph + rate ledger and return a list of violations. A build or
run that cannot satisfy them does not proceed. They are the data-level enforcement of the
safety model — not advisory lint.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import Sensitivity, Verdict
from .store import GraphStore


@dataclass
class Violation:
    code: str
    detail: str


def check(
    store: GraphStore,
    *,
    ledger=None,
    current_snapshot: str | None = None,
) -> list[Violation]:
    v: list[Violation] = []
    nodes = list(store.nodes.values())

    # I1: retained data is bound to the current (non-stale) snapshot.
    if current_snapshot is not None:
        for n in nodes:
            if n.scope_binding.snapshot_id != current_snapshot:
                v.append(Violation("I1", f"{n.id} bound to stale snapshot "
                                          f"{n.scope_binding.snapshot_id!r} != {current_snapshot!r}"))

    # I2/I3: anything actively probed must have been in_scope at observation time.
    for n in nodes:
        if n.attrs.get("active_probed") and n.scope_binding.verdict != Verdict.IN_SCOPE:
            v.append(Violation("I3", f"{n.id} has active-probe evidence but verdict "
                                     f"{n.scope_binding.verdict.value!r}"))

    # I4: no per-target rate budget ever went negative.
    if ledger is not None:
        for e in getattr(ledger, "log", []):
            if e.balance_after < 0:
                v.append(Violation("I4", f"ledger balance negative for {e.target!r}"))

    # I5: derived_from edges reference an existing Artifact on the 'to' side.
    for e in store.edges.values():
        if e.type == "derived_from":
            tgt = store.get(e.to)
            if tgt is None or tgt.type != "Artifact":
                v.append(Violation("I5", f"derived_from edge {e.id} does not reference an Artifact"))

    # I6: no node authorizes anti-cheat circumvention.
    for n in nodes:
        if n.attrs.get("anti_cheat_action_mode") == "runtime_circumvent":
            v.append(Violation("I6", f"{n.id} has anti_cheat_action_mode=runtime_circumvent"))

    # I7: no Artifact is a circumvention tool or was published externally.
    for n in store.iter_type("Artifact"):
        if n.attrs.get("is_circumvention_tool") or n.attrs.get("published_externally"):
            v.append(Violation("I7", f"Artifact {n.id} violates no-trafficking guard"))

    # I8: Credential/Token and non-self ObjectType carry a sensitivity label (not default-public).
    for n in nodes:
        if n.type in ("Credential", "Token") and n.sensitivity == Sensitivity.S0:
            v.append(Violation("I8", f"{n.type} {n.id} is unlabeled (S0) — credentials/tokens need >= S1"))
        if n.data_subject == "other" and n.sensitivity not in (Sensitivity.S3,):
            v.append(Violation("I8", f"{n.id} is other-user data but not labeled S3"))

    # I9: an other-user (PII) node may never be an edge endpoint.
    for e in store.edges.values():
        for endpoint in (e.frm, e.to):
            node = store.get(endpoint)
            if node is not None and node.data_subject == "other":
                v.append(Violation("I9", f"edge {e.id} has other-user PII endpoint {endpoint}"))

    return v
