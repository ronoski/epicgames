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
from .snapshot import Snapshot, take_snapshot
from .store import Graph, GraphStore


@dataclass
class Runtime:
    config: Config
    ctx: ModuleContext
    graph: Graph

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
    log = EventLog(path=(workdir / "events.jsonl") if persist else None, run_id=run_id)
    graph = Graph(log=log, store=GraphStore())

    if snapshot is None and config.policy_text:
        snapshot = take_snapshot(config.policy_text, now=now,
                                 half_life=config.policy_half_life)
    if snapshot is not None:
        log.append("scope_snapshot_taken", {
            "snapshot_id": snapshot.snapshot_id,
            "content_sha256": snapshot.content_sha256,
            "half_life": snapshot.half_life,
        })

    ctx = ModuleContext(
        scope=config.scope,
        ledger=RateLedger(global_qps=config.rate_qps, capacity=config.rate_capacity),
        evidence=EvidenceStore(workdir / "evidence"),
        graph=graph,
        snapshot=snapshot,
        logger=logger or logging.getLogger("recon"),
        allow_active=config.allow_active,
        user_agent=config.user_agent,
        timeout=config.timeout,
        now=now,
    )
    return Runtime(config=config, ctx=ctx, graph=graph)


def seed_graph(rt: Runtime) -> dict:
    """Run the ``seeds`` module to plant the configured targets in the graph."""

    from .modules import load_all

    seeds_cls = load_all().get("seeds")
    if seeds_cls is None:
        rt.ctx.logger.warning("seeds module not registered; graph will start empty")
        return {}
    return seeds_cls(rt.ctx).run(list(rt.config.targets)) or {}
