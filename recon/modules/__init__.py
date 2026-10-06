"""Recon modules and their registry."""

from __future__ import annotations

from .base import Module, ModuleContext, register, get_module, registry

# Import side-effect registers the modules.
from .passive import seeds as _seeds  # noqa: F401
from .passive import crtsh as _crtsh  # noqa: F401
from .active import resolver as _resolver  # noqa: F401
from .active import http_probe as _http_probe  # noqa: F401

__all__ = ["Module", "ModuleContext", "register", "get_module", "registry"]
