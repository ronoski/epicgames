"""Command-line interface.

Designed to be driven by an autonomous AI session: every subcommand can emit JSON, and
``run`` is **dry-run by default** so the agent inspects the plan before authorizing work.
Active modules additionally require ``allow_active: true`` in config AND a non-stale scope
snapshot, so ``--execute`` alone can never start probing a target.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import asdict

from pathlib import Path

from . import __version__, drift, invariants, planner, report
from .config import Config
from .loop import AutonomousLoop
from .modules import load_all
from .pipeline import build_runtime, seed_graph
from .events import EventLog
from .snapshot import Snapshot, take_snapshot
from .store import GraphStore


def _emit(obj, as_json: bool) -> None:
    if as_json:
        print(json.dumps(obj, indent=2, default=str))
    else:
        print(_pretty(obj))


def _pretty(obj, indent: int = 0) -> str:
    pad = "  " * indent
    if isinstance(obj, dict):
        return "\n".join(f"{pad}{k}: {_pretty(v, indent + 1).lstrip() if isinstance(v, (dict, list)) else v}"
                         for k, v in obj.items())
    if isinstance(obj, list):
        if not obj:
            return f"{pad}(none)"
        return "\n".join(f"{pad}- {_pretty(v, indent + 1).lstrip() if isinstance(v, (dict, list)) else v}"
                         for v in obj)
    return f"{pad}{obj}"


def cmd_scope_check(args) -> int:
    cfg = Config.load(args.config)
    snap = take_snapshot(cfg.policy_text or "", half_life=cfg.policy_half_life)
    rows = []
    for value in args.values:
        binding = cfg.scope.bind(value, snap.snapshot_id, "n/a")
        rows.append({
            "value": value,
            "verdict": binding.verdict.value,
            "rule": binding.rule_matched,
            "actionable": binding.actionable,
        })
    _emit(rows, args.json)
    return 0 if all(r["verdict"] != "adjudication_pending" for r in rows) else 2


def cmd_modules(args) -> int:
    rows = [
        {"name": name, "active": cls.active, "produces": list(cls.produces)}
        for name, cls in sorted(load_all().items())
    ]
    _emit(rows, args.json)
    return 0


def cmd_plan(args) -> int:
    cfg = Config.load(args.config)
    rt = build_runtime(cfg, workdir=args.workdir, persist=False)
    seed_graph(rt)
    gaps = planner.plan(rt.store, rt.ctx.clock_now(), allow_active=cfg.allow_active)
    gaps.sort(key=lambda g: g.priority, reverse=True)
    _emit({
        "nodes": rt.store.counts(),
        "coverage": planner.coverage_report(rt.store),
        "gaps": [
            {"id": g.id, "priority": round(g.priority, 3), "module": g.module,
             "verb": g.verb, "passive": g.passive, "note": g.note}
            for g in gaps[: args.limit]
        ],
        "gap_total": len(gaps),
    }, args.json)
    return 0


def cmd_run(args) -> int:
    cfg = Config.load(args.config)
    rt = build_runtime(cfg, workdir=args.workdir, run_id=args.run_id)
    seed_graph(rt)
    dry_run = not args.execute
    if args.execute and not cfg.allow_active:
        print("note: --execute given but config has allow_active=false — "
              "active modules stay disabled (passive only).", file=sys.stderr)

    # Unreviewed scope drift blocks action. Every retained datum carries the verdict it was
    # observed under, so acting on a scope that moved underneath us would be acting on an
    # authorization that no longer exists. Downgrade to dry-run and say what to do.
    drift_blocked = None
    if rt.drift is not None and getattr(rt.drift, "drifted", False):
        drift_blocked = rt.drift.summary()
        if args.execute:
            dry_run = True
            print(f"REFUSING to execute: scope drift detected ({drift_blocked}). "
                  "Review with `recon drift --rebind`, then `recon drift --accept`.",
                  file=sys.stderr)
    loop = AutonomousLoop(
        rt.ctx, dry_run=dry_run, max_cycles=args.max_cycles,
        max_active_actions=args.max_active, passive_first=cfg.passive_first,
    )
    result = loop.run()
    _emit({
        **result.summary(),
        "nodes": rt.store.counts(),
        "cycles_detail": [asdict(c) for c in result.cycles][: args.limit],
        "violations": [asdict(v) for v in result.violations],
        "dry_run": dry_run,
        "scope_drift": drift_blocked,
        "delta": report.delta_for(rt.graph.log.all()).to_dict(),
    }, args.json)
    if result.violations:
        return 1
    return 3 if drift_blocked else 0


def cmd_invariants(args) -> int:
    cfg = Config.load(args.config)
    rt = build_runtime(cfg, workdir=args.workdir, persist=False)
    seed_graph(rt)
    snap = rt.ctx.snapshot
    violations = invariants.check(
        rt.store, ledger=rt.ctx.ledger,
        current_snapshot=snap.snapshot_id if snap else None,
        log=rt.graph.log, snapshot=snap,
    )
    _emit({"violations": [asdict(v) for v in violations], "ok": not violations}, args.json)
    return 1 if violations else 0


def cmd_diff(args) -> int:
    """What changed since a previous run — the headline for a long-term target."""

    path = Path(args.workdir) / "events.jsonl"
    if not path.exists():
        _emit({"error": f"no event log at {path}; run `recon run` first"}, args.json)
        return 2
    events = report.load_events(path)
    if args.all_runs:
        payload = {
            "runs": [d.to_dict() for d in report.per_run(events)],
            "headlines": [f"{d.run_id}: {d.headline()}" for d in report.per_run(events)],
        }
    else:
        d = report.delta_since(events, run_id=args.since_run, since_ts=args.since)
        payload = d.to_dict()
    _emit(payload, args.json)
    return 0


def cmd_replay(args) -> int:
    """Rebuild the graph projection from the event log and report what it contains.

    This is the event-sourcing claim made checkable: the log is the source of truth, so a
    replay must reproduce the graph the run produced.
    """

    path = Path(args.workdir) / "events.jsonl"
    if not path.exists():
        _emit({"error": f"no event log at {path}"}, args.json)
        return 2
    events = report.load_events(path)
    store = GraphStore.from_events(events)
    violations = invariants.check(store, log=None)
    _emit({
        "events_replayed": len(events),
        "nodes": store.counts(),
        "edges": len(store.edges),
        "skipped_without_payload": getattr(store, "replay_skipped", 0),
        "coverage": planner.coverage_report(store),
        "violations": [asdict(v) for v in violations],
    }, args.json)
    return 1 if violations else 0


def cmd_drift(args) -> int:
    """Compare the configured policy against the last pinned snapshot."""

    cfg = Config.load(args.config)
    workdir = Path(args.workdir)
    previous = Snapshot.load(workdir / "snapshot.json")
    scope_cfg = cfg.raw.get("scope", {})
    current = take_snapshot(
        cfg.policy_text, half_life=cfg.policy_half_life,
        include=scope_cfg.get("include", []),
        exclude=scope_cfg.get("exclude", []),
        prefilter=scope_cfg.get("prefilter", []),
    )
    rep = drift.detect(previous, current)
    payload = {"summary": rep.summary(), **rep.to_dict(),
               "previous_snapshot_known": previous is not None}

    if args.rebind and rep.drifted:
        # Re-bind what we ALREADY HOLD, which means replaying the persisted log rather
        # than re-seeding from config: the question is whether the data we retained is
        # still authorized, not what a fresh run would collect.
        events_path = workdir / "events.jsonl"
        if not events_path.exists():
            payload["rebind"] = {"error": f"no event log at {events_path}; nothing retained"}
        else:
            store = GraphStore.from_events(report.load_events(events_path))
            log = EventLog(path=events_path, run_id="rebind")
            rebound = drift.rebind(store, cfg.scope, current, log=log)
            payload["rebind"] = rebound.to_dict()
    if args.accept:
        current.save(workdir / "snapshot.json")
        payload["accepted"] = True
    _emit(payload, args.json)
    # a drifted scope is a call to action, not a failure
    return 3 if rep.drifted else 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="recon",
        description="Autonomous, scope-aware reconnaissance pipeline for AUTHORIZED testing. "
                    "Dry-run by default; active modules require explicit config opt-in.",
    )
    p.add_argument("--version", action="version", version=f"recon {__version__}")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("-c", "--config", required=True, help="path to config YAML/JSON")
        sp.add_argument("--workdir", default=".recon")
        sp.add_argument("--json", action="store_true", help="emit JSON (for AI consumption)")
        return sp

    sc = common(sub.add_parser("scope-check", help="bind values against the scope policy"))
    sc.add_argument("values", nargs="+")
    sc.set_defaults(func=cmd_scope_check)

    m = sub.add_parser("modules", help="list registered modules")
    m.add_argument("--json", action="store_true")
    m.set_defaults(func=cmd_modules)

    pl = common(sub.add_parser("plan", help="show the ranked gap queue without acting"))
    pl.add_argument("--limit", type=int, default=25)
    pl.set_defaults(func=cmd_plan)

    r = common(sub.add_parser("run", help="run the autonomous loop (dry-run unless --execute)"))
    r.add_argument("--execute", action="store_true",
                   help="actually dispatch modules (still gated by scope/ledger/allow_active)")
    r.add_argument("--max-cycles", type=int, default=25)
    r.add_argument("--max-active", type=int, default=None,
                   help="cap on active actions this run")
    r.add_argument("--run-id", default="run")
    r.add_argument("--limit", type=int, default=25)
    r.set_defaults(func=cmd_run)

    iv = common(sub.add_parser("invariants", help="check safety invariants over the graph"))
    iv.set_defaults(func=cmd_invariants)

    df = sub.add_parser("diff", help="what changed since a previous run (the delta report)")
    df.add_argument("--workdir", default=".recon")
    df.add_argument("--json", action="store_true")
    df.add_argument("--since-run", default=None,
                    help="report everything after this run id")
    df.add_argument("--since", default=None,
                    help="report everything after this ISO timestamp")
    df.add_argument("--all-runs", action="store_true", help="one delta per run")
    df.set_defaults(func=cmd_diff)

    rp = sub.add_parser("replay", help="rebuild the graph from the event log")
    rp.add_argument("--workdir", default=".recon")
    rp.add_argument("--json", action="store_true")
    rp.set_defaults(func=cmd_replay)

    dr = common(sub.add_parser(
        "drift", help="diff the configured policy against the last pinned snapshot"))
    dr.add_argument("--rebind", action="store_true",
                    help="re-evaluate retained nodes against the new snapshot")
    dr.add_argument("--accept", action="store_true",
                    help="pin the current policy as the new snapshot")
    dr.set_defaults(func=cmd_drift)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if getattr(args, "verbose", False) else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
