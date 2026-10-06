"""Autonomous, scope-aware reconnaissance pipeline for authorized engagements.

This package implements the specification under ``docs/`` — a typed, event-sourced
knowledge graph with a default-deny scope guard, a unified per-target rate ledger, a
closed recon-verb whitelist, and machine-checkable safety invariants.

It is intended **only** for reconnaissance against assets you are explicitly authorized
to test (a bug-bounty program's declared scope, your own infrastructure, or a lab you
control). Every network-touching action is gated behind the scope guard in
:mod:`recon.scope` (default-deny, exclude-wins) and the rate ledger in
:mod:`recon.ratelimit`. Active modules are disabled by default and refuse to run without
a verified scope snapshot and an explicit opt-in.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
