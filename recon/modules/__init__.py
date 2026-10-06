"""Recon modules and their registry.

Modules are auto-discovered from ``passive/`` and ``active/`` so adding a module is just
adding a file that calls ``@register``. Import failures in one module never break the rest
of the registry.
"""

from __future__ import annotations

import importlib
import logging
import pkgutil

from .base import Module, ModuleContext, register, get_module, registry, GateRefused

_log = logging.getLogger(__name__)
_loaded = False


def load_all() -> dict[str, type[Module]]:
    """Import every module under passive/ and active/, populating the registry."""

    global _loaded
    if not _loaded:
        for pkg_name in ("passive", "active"):
            try:
                pkg = importlib.import_module(f".{pkg_name}", __name__)
            except ImportError:  # pragma: no cover - package always present
                continue
            for info in pkgutil.iter_modules(pkg.__path__):
                try:
                    importlib.import_module(f".{pkg_name}.{info.name}", __name__)
                except Exception as exc:  # keep one bad module from breaking discovery
                    _log.warning("skipping module %s.%s: %s", pkg_name, info.name, exc)
        _loaded = True
    return registry()


__all__ = [
    "Module", "ModuleContext", "register", "get_module", "registry",
    "GateRefused", "load_all",
]
