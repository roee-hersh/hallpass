"""Port of internal/integrations/all/all_test.go."""

from __future__ import annotations

import ast
import importlib.util
import re
from pathlib import Path

import pytest

from hallpass.integrations import registry

# tests/integrations, where each integration's tests live.
ROOT = Path(__file__).resolve().parent

_NON_IDENT = re.compile(r"[^A-Za-z0-9]")


def sanitize(s: str) -> str:
    return _NON_IDENT.sub("_", s)


def action_test_files(name: str) -> list[Path]:
    """The test modules of one integration: tests/integrations/test_<name>.py,
    test_<name>_*.py, or a tests/integrations/<name>/ package of them."""
    files = [ROOT / f"test_{name}.py", *sorted(ROOT.glob(f"test_{name}_*.py"))]
    pkg = ROOT / name
    if pkg.is_dir():
        files.extend(sorted(pkg.rglob("test_*.py")))
    return [f for f in files if f.is_file()]


def module_funcs(files: list[Path]) -> set[str]:
    """Module-level function names (Go: FuncDecl without a receiver),
    lowercased, so TestAction_DELETE_ISSUES_allow may be ported as either
    test_action_DELETE_ISSUES_allow or test_action_delete_issues_allow."""
    out: set[str] = set()
    for f in files:
        tree = ast.parse(f.read_text(), str(f))
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                out.add(node.name.lower())
    return out


@pytest.mark.parametrize("name", registry().names())
def test_every_action_has_allow_and_deny_tests(name: str) -> None:
    """The coverage gate: every non-pattern action of every integration
    needs test_action_<name>_allow and test_action_<name>_deny in the
    integration's own tests, where <name> has every character outside
    [A-Za-z0-9] replaced by "_"."""
    integ = registry().lookup(name)
    assert integ is not None
    errors: list[str] = []
    if importlib.util.find_spec(f"hallpass.integrations.{name}") is None:
        errors.append(f"integration {name}: module hallpass.integrations.{name} missing (the module name must equal the integration name)")
    files = action_test_files(name)
    if not files:
        pytest.fail(f"integration {name}: no tests/integrations/test_{name}.py (or tests/integrations/{name}/) found")
    tests = module_funcs(files)
    for a in integ.actions():
        if a.pattern:
            continue
        base = "test_action_" + sanitize(a.name)
        for suffix in ("_allow", "_deny"):
            if (base + suffix).lower() not in tests:
                errors.append(f'integration {name}: action "{a.name}" has no {base + suffix} test')
    assert not errors, "\n".join(errors)


def test_registry_has_fake() -> None:
    assert registry().lookup("fake") is not None, "fake not registered"
