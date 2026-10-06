"""Autonomous, scope-aware reconnaissance workflow for authorized engagements.

This package is intended solely for reconnaissance against assets you are
explicitly authorized to test (e.g. a bug-bounty program's declared scope,
your own infrastructure, or a lab you control). Every network-touching module
is gated behind the scope guard in :mod:`recon.scope`, which is default-deny:
a host or IP is only probed when it matches an in-scope rule and matches no
out-of-scope rule.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
