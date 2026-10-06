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

from . import __version__, invariants, planner
from .config import Config
from .loop import AutonomousLoop
from .modules import load_all
from .pipeline import build_runtime, seed_graph
from .snapshot import take_snapshot


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
    }, args.json)
    return 1 if result.violations else 0


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
