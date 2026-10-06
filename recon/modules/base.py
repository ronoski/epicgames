"""Base class and registry for recon modules.

A module is a self-contained unit of discovery. It declares what finding
*kinds* it consumes as seeds and what it emits, so the pipeline can order them
and feed outputs forward. Every module receives a :class:`ModuleContext` giving
it the scope guard, rate limiter, config, and a logger. Modules must never act
on a target they have not checked against ``ctx.scope``; the helpers here make
the safe path the easy path.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Iterable, Iterator

from ..config import Config
from ..models import Finding, Kind
from ..ratelimit import RateLimiter
from ..scope import Scope


@dataclass
class ModuleContext:
    scope: Scope
    rate_limiter: RateLimiter
    config: Config
    logger: logging.Logger

    def in_scope(self, value: str) -> bool:
        return self.scope.is_in_scope(value)

    def guard(self, values: Iterable[str]) -> Iterator[str]:
        """Yield only in-scope values, logging anything dropped."""

        for value in values:
            if self.scope.is_in_scope(value):
                yield value
            else:
                self.logger.debug("skip out-of-scope %s (%s)", value, self.scope.reason(value))

    def throttle(self) -> None:
        self.rate_limiter.acquire()


class Module:
    """Subclass and implement :meth:`run`.

    Attributes:
        name: Unique module id used in config ``modules`` lists.
        consumes: Finding kinds this module reads from the store as seeds.
        produces: Finding kinds this module emits.
        active: True if the module sends traffic to the target (vs. querying
            third-party/passive sources). Used for dry-run reporting.
    """

    name: str = "base"
    consumes: tuple[Kind, ...] = ()
    produces: tuple[Kind, ...] = ()
    active: bool = False

    def __init__(self, ctx: ModuleContext) -> None:
        self.ctx = ctx
        self.log = ctx.logger.getChild(self.name)

    def run(self, seeds: list[Finding]) -> Iterable[Finding]:
        """Produce findings from the given seed findings.

        ``seeds`` are the stored findings whose kind is in ``self.consumes``
        (plus the configured targets for the entry modules). Implementations
        should yield :class:`Finding` objects and are responsible for scope
        checks via ``self.ctx``.
        """

        raise NotImplementedError


_REGISTRY: dict[str, type[Module]] = {}


def register(cls: type[Module]) -> type[Module]:
    """Class decorator that adds a module to the global registry."""

    if cls.name in _REGISTRY and _REGISTRY[cls.name] is not cls:
        raise ValueError(f"duplicate module name: {cls.name}")
    _REGISTRY[cls.name] = cls
    return cls


def get_module(name: str) -> type[Module]:
    if name not in _REGISTRY:
        raise KeyError(
            f"unknown module {name!r}; registered: {sorted(_REGISTRY)}"
        )
    return _REGISTRY[name]


def registry() -> dict[str, type[Module]]:
    return dict(_REGISTRY)
