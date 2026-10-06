"""Assembly: turn a :class:`~recon.config.Config` into a wired runtime.

Keeps construction of the scope guard, rate ledger, evidence store, graph and module
context in one place so the CLI, the autonomous loop and tests all build the same runtime.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from . import clock
from .config import Config
from .evidence import EvidenceStore
from .events import EventLog
from .modules.base import ModuleContext
from .ratelimit import RateLedger
from . import drift
from .snapshot import Snapshot, take_snapshot
from .store import Graph, GraphStore


@dataclass
class Runtime:
    config: Config
    ctx: ModuleContext
    graph: Graph
    drift: object | None = None
    rehydrated_events: int = 0

    @property
    def store(self) -> GraphStore:
        return self.graph.store


def build_runtime(
    config: Config,
    *,
    workdir: str | Path = ".recon",
    run_id: str = "run",
    snapshot: Snapshot | None = None,
    now: datetime | None = None,
    logger: logging.Logger | None = None,
    persist: bool = True,
) -> Runtime:
    workdir = Path(workdir)
    events_path = workdir / "events.jsonl"

    # Rehydrate the graph from the persisted log before anything else. Without this every
    # run started blank, re-"discovered" what previous runs already knew, and every delta
    # reported the whole graph as new — which defeats the entire point of a long-lived
    # knowledge base. The log is the source of truth, so the projection is rebuilt from it.
    store = GraphStore()
    rehydrated = 0
    if persist and events_path.exists():
        prior = EventLog.replay(events_path)
        store = GraphStore.from_events(prior)
        rehydrated = len(prior)

    log = EventLog(path=events_path if persist else None, run_id=run_id)
    graph = Graph(log=log, store=store)

    scope_cfg = config.raw.get("scope", {}) if isinstance(config.raw, dict) else {}
    if snapshot is None and config.policy_text:
        snapshot = take_snapshot(
            config.policy_text, now=now, half_life=config.policy_half_life,
            include=scope_cfg.get("include", []),
            exclude=scope_cfg.get("exclude", []),
            prefilter=scope_cfg.get("prefilter", []),
        )

    drift_report = None
    if snapshot is not None:
        log.append("scope_snapshot_taken", {
            "snapshot_id": snapshot.snapshot_id,
            "content_sha256": snapshot.content_sha256,
            "half_life": snapshot.half_life,
        })
        # Drift is cross-run by nature, so the previous snapshot is read off disk.
        snapshot_path = workdir / "snapshot.json"
        previous = Snapshot.load(snapshot_path) if persist else None
        drift_report = drift.detect(previous, snapshot)
        if drift_report.drifted:
            log.append("scope_drift_detected", drift_report.to_dict())
        # Pin the snapshot only when there is nothing to review. Saving it on a DRIFTED
        # policy would silently accept the change and dissolve the gate the drift just
        # raised; acceptance is an explicit act (`recon drift --accept`).
        if persist and not drift_report.drifted:
            snapshot.save(snapshot_path)

    ctx = ModuleContext(
        scope=config.scope,
        ledger=RateLedger(global_qps=config.rate_qps, capacity=config.rate_capacity),
        # Separate budget for third-party aggregators (crt.sh, archive.org): passive
        # politeness is capped centrally and never charged to the target.
        third_party_ledger=RateLedger(
            global_qps=config.third_party_qps,
            capacity=config.third_party_capacity,
        ),
        evidence=EvidenceStore(workdir / "evidence"),
        graph=graph,
        snapshot=snapshot,
        logger=logger or logging.getLogger("recon"),
        allow_active=config.allow_active,
        user_agent=config.user_agent,
        timeout=config.timeout,
        now=now,
    )
    return Runtime(config=config, ctx=ctx, graph=graph, drift=drift_report,
                   rehydrated_events=rehydrated)


def seed_graph(rt: Runtime) -> dict:
    """Run the ``seeds`` module to plant the configured targets in the graph."""

    from .modules import load_all

    seeds_cls = load_all().get("seeds")
    if seeds_cls is None:
        rt.ctx.logger.warning("seeds module not registered; graph will start empty")
        return {}
    return seeds_cls(rt.ctx).run(list(rt.config.targets)) or {}
