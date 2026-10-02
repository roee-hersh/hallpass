"""Argument types, validators and scope rules."""

from __future__ import annotations

import re
from typing import Annotated, Any, Literal, Optional

import pytest

from toolpass import Toolkit, ToolRefused
from toolpass._checks import type_matches


@pytest.mark.parametrize(
    ("value", "hint", "ok"),
    [
        ("a", str, True),
        (1, str, False),
        (1, int, True),
        (True, int, False),
        (1, float, True),
        (1.5, int, False),
        (True, bool, True),
        (None, Optional[str], True),
        ("a", Optional[str], True),
        (1, Optional[str], False),
        ("a", str | None, True),
        ("b", Literal["a", "b"], True),
        ("c", Literal["a", "b"], False),
        (1, Literal[True], False),
        (["a", "b"], list[str], True),
        (["a", 1], list[str], False),
        (("a",), list[str], False),
        (("a", 1), tuple[str, int], True),
        (("a", "b"), tuple[str, int], False),
        (("a", "b"), tuple[str, ...], True),
        ({"a": 1}, dict[str, int], True),
        ({"a": "x"}, dict[str, int], False),
        ("a", Annotated[str, "doc"], True),
        (object(), Any, True),
        ("anything", "UnresolvedName", True),
    ],
)
def test_type_matches(value, hint, ok):
    assert type_matches(value, hint) is ok


def test_wrong_type_refuses_before_the_body(events, dana):
    tools = Toolkit(audit=events)
    ran = []

    @tools.tool(effect="write")
    def scale(name: str, replicas: int) -> str:
        ran.append(name)
        return name

    with pytest.raises(ToolRefused) as e:
        scale(name="web", replicas="3; rm -rf /")
    assert e.value.code == "invalid_arguments"
    assert "replicas" in str(e.value)
    assert ran == []


def test_validators(dana):
    tools = Toolkit(audit=None)

    def no_dashes(v: str) -> bool:
        return not v.startswith("-")

    def positive(v: int) -> None:
        if v <= 0:
            raise ValueError("must be positive")

    @tools.tool(effect="write", validate={"ref": no_dashes, "n": positive})
    def checkout(ref: str, n: int = 1) -> str:
        return ref

    assert checkout("main") == "main"
    with pytest.raises(ToolRefused) as e:
        checkout("--upload-pack=evil")
    assert e.value.code == "invalid_arguments"
    with pytest.raises(ToolRefused) as e:
        checkout("main", n=0)
    assert "must be positive" in str(e.value)


def test_unknown_names_fail_at_import():
    tools = Toolkit(audit=None)
    with pytest.raises(TypeError, match="repo_name"):

        @tools.tool(effect="write", scope={"repo_name": "acme/*"})
        def f(repo: str) -> str:
            return repo

    with pytest.raises(TypeError):

        @tools.tool(effect="write", validate={"nope": bool})
        def g(repo: str) -> str:
            return repo


@pytest.mark.parametrize(
    ("value", "ok"),
    [
        ("acme/gitops-prod", True),
        ("acme/gitops-", True),
        ("acme/other", False),
        ("evil/gitops-prod", False),
        ("acme/gitops-prod/../../evil", False),
        ("acme/gitops-x/y", False),
        ("acme/gitops-..", True),  # one segment that merely contains dots
        ("acme/gitops-prod\n", False),
        ("ACME/gitops-prod", False),
        (None, False),
        (42, False),
    ],
)
def test_glob_scope(dana, value, ok):
    tools = Toolkit(audit=None)

    @tools.tool(effect="write", scope={"repo": "acme/gitops-*"})
    def open_pr(repo: Any) -> str:
        return "ok"

    if ok:
        assert open_pr(value) == "ok"
    else:
        with pytest.raises(ToolRefused) as e:
            open_pr(value)
        assert e.value.code in ("out_of_scope", "invalid_arguments")


def test_double_star_crosses_segments_but_not_dot_segments(dana):
    tools = Toolkit(audit=None)

    @tools.tool(effect="write", scope={"path": "apps/**"})
    def edit(path: str) -> str:
        return "ok"

    assert edit("apps/web/values.yaml") == "ok"
    with pytest.raises(ToolRefused):
        edit("apps/../secrets/prod.yaml")
    with pytest.raises(ToolRefused):
        edit("infra/x")


def test_glob_classes(dana):
    tools = Toolkit(audit=None)

    @tools.tool(effect="write", scope={"env": "prod-[abc]", "region": "eu-[!x]?"})
    def deploy(env: str, region: str) -> str:
        return "ok"

    assert deploy("prod-a", "eu-w1") == "ok"
    with pytest.raises(ToolRefused):
        deploy("prod-d", "eu-w1")
    with pytest.raises(ToolRefused):
        deploy("prod-a", "eu-x1")
    with pytest.raises(ToolRefused):
        deploy("prod-/", "eu-w1")


def test_scope_lists_regexes_and_predicates(dana):
    tools = Toolkit(audit=None)

    @tools.tool(
        effect="write",
        scope={
            "ns": ["team-a-*", "team-b-*"],
            "host": re.compile(r"[a-z0-9-]+\.internal\.example\.com"),
            "replicas": lambda n: 0 <= n <= 10,
        },
    )
    def scale(ns: str, host: str, replicas: int) -> str:
        return "ok"

    assert scale("team-b-web", "api.internal.example.com", 3) == "ok"
    with pytest.raises(ToolRefused):
        scale("team-c-web", "api.internal.example.com", 3)
    with pytest.raises(ToolRefused):
        scale("team-a-web", "evil.com/.internal.example.com", 3)
    with pytest.raises(ToolRefused):
        scale("team-a-web", "api.internal.example.com", 11)


def test_scope_applies_to_every_item_of_a_list(dana):
    tools = Toolkit(audit=None)

    @tools.tool(effect="destructive", scope={"branches": "feature/*"})
    def delete_branches(branches: list[str]) -> int:
        return len(branches)

    assert delete_branches(["feature/a", "feature/b"]) == 2
    with pytest.raises(ToolRefused):
        delete_branches(["feature/a", "main"])
