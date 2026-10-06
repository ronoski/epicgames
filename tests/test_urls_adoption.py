"""Guard tests: the modules actually use the shared canonicalizer.

The point of ``recon/urls.py`` is that there is exactly ONE place that decides what a
hostname, an authority, a path template and a node id look like. A module that quietly
keeps its own copy defeats that — the two implementations drift and eventually mint two
ids for one thing. These tests fail if a module re-grows a local duplicate or hand-builds
an id, so the migration cannot silently regress.

They are static (AST/source) checks: no module is executed, nothing touches the network.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

from recon import urls
from recon.modules import load_all

MODULE_DIR = pathlib.Path(__file__).resolve().parent.parent / "recon" / "modules"

# Helper names that live in urls.py and must not be re-implemented in a module.
DUPLICATED_HELPERS = {
    "canonical_host", "normalize_host", "valid_fqdn", "registrable_domain",
    "authority", "canonical_url", "path_template",
}

# Node type -> the urls.py constructor that must build its id.
ID_CONSTRUCTOR = {
    "Domain": "domain_id",
    "DNSName": "dns_id",
    "Host": "host_id",
    "Service": "service_id",
    "WebApp": "webapp_id",
    "Route": "route_id",
    "Operation": "operation_id",
    "Parameter": "parameter_id",
    "Certificate": "certificate_id",
    "Hypothesis": "hypothesis_id",
}

# Raw id prefixes that must never be hand-built with an f-string / concatenation.
RAW_ID_PREFIXES = ("web:", "route:", "op:", "param:", "cert:", "hyp:dns-candidate",
                   "domain:", "svc:")


def module_files() -> list[pathlib.Path]:
    out = []
    for sub in ("passive", "active"):
        out.extend(sorted((MODULE_DIR / sub).glob("[a-z]*.py")))
    return [p for p in out if p.name != "__init__.py"]


def ids() -> list[str]:
    return [p.stem for p in module_files()]


@pytest.fixture(scope="module")
def sources() -> dict[str, str]:
    return {p.stem: p.read_text(encoding="utf-8") for p in module_files()}


def test_there_are_modules_to_check(sources):
    assert len(sources) >= 11


@pytest.mark.parametrize("name", ids())
def test_module_does_not_redefine_a_shared_helper(name, sources):
    """A local copy of canonicalization is exactly the drift this prevents."""

    tree = ast.parse(sources[name])
    defined = {
        n.name for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    clashes = defined & DUPLICATED_HELPERS
    assert not clashes, (
        f"{name} re-implements {sorted(clashes)}; import them from recon.urls instead"
    )


@pytest.mark.parametrize("name", ids())
def test_module_imports_urls_if_it_emits_nodes(name, sources):
    src = sources[name]
    if "make_node(" not in src:
        pytest.skip(f"{name} emits no nodes")
    assert "urls" in src, f"{name} emits nodes but never references recon.urls"


@pytest.mark.parametrize("name", ids())
def test_module_uses_the_shared_constructor_for_each_node_type_it_emits(name, sources):
    """If a module produces WebApp/Parameter/... it must build that id via urls.py."""

    cls = load_all().get(name)
    if cls is None:
        pytest.skip(f"{name} not registered")
    src = sources[name]
    missing = []
    for node_type in cls.produces:
        ctor = ID_CONSTRUCTOR.get(node_type)
        if ctor and ctor not in src:
            missing.append((node_type, ctor))
    assert not missing, (
        f"{name} declares produces={cls.produces} but never calls "
        + ", ".join(f"urls.{c}() for {t}" for t, c in missing)
    )


@pytest.mark.parametrize("name", ids())
def test_module_does_not_hand_build_an_id(name, sources):
    """Catches f'web:{scheme}://{host}' and friends sneaking back in."""

    tree = ast.parse(sources[name])
    offenders = []

    for node in ast.walk(tree):
        # f-strings: look at the literal head of the template
        if isinstance(node, ast.JoinedStr):
            head = next((v.value for v in node.values
                         if isinstance(v, ast.Constant) and isinstance(v.value, str)), "")
            if any(head.startswith(p) for p in RAW_ID_PREFIXES):
                offenders.append(f"f-string starting {head!r}")
        # plain concatenation with a literal id prefix
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = node.left
            if isinstance(left, ast.Constant) and isinstance(left.value, str):
                if any(left.value.startswith(p) for p in RAW_ID_PREFIXES):
                    offenders.append(f"concatenation starting {left.value!r}")

    assert not offenders, (
        f"{name} hand-builds a node id ({offenders}); use the recon.urls constructors"
    )


def test_urls_exposes_every_constructor_the_guard_expects():
    """Keeps this guard honest if urls.py is refactored."""

    for ctor in set(ID_CONSTRUCTOR.values()):
        assert callable(getattr(urls, ctor, None)), f"recon.urls.{ctor} is missing"


def _calls_named(src: str, attr: str) -> list[str]:
    """Actual ``*.attr(...)`` call sites, by AST — not substring matches in prose.

    A docstring that *mentions* gate_active is not a call to it; a grep-based check reads
    "this module never calls gate_active" as a violation.
    """

    found = []
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == attr:
                found.append(attr)
    return found


@pytest.mark.parametrize("name", ids())
def test_active_modules_still_gate_and_handle_refusal(name, sources):
    """A migration must not have dropped a gate. Pins the safety property structurally."""

    cls = load_all().get(name)
    if cls is None or not cls.active:
        pytest.skip(f"{name} is not active")
    src = sources[name]
    assert _calls_named(src, "gate_active"), \
        f"active module {name} never actually calls ctx.gate_active"
    # a refusal must be caught and skipped, not allowed to abort the run
    handlers = [h for h in ast.walk(ast.parse(src)) if isinstance(h, ast.ExceptHandler)]
    names = []
    for h in handlers:
        for sub in ast.walk(h) if h.type is None else ast.walk(h.type):
            if isinstance(sub, ast.Name):
                names.append(sub.id)
            elif isinstance(sub, ast.Attribute):
                names.append(sub.attr)
    assert "GateRefused" in names, \
        f"active module {name} does not catch GateRefused"


@pytest.mark.parametrize("name", ids())
def test_passive_modules_never_gate_or_debit_the_target(name, sources):
    cls = load_all().get(name)
    if cls is None or cls.active:
        pytest.skip(f"{name} is not passive")
    src = sources[name]
    assert not _calls_named(src, "gate_active"), \
        f"passive module {name} must not call gate_active"
    assert not _calls_named(src, "debit"), \
        f"passive module {name} must not debit a ledger directly (use spend_third_party)"
