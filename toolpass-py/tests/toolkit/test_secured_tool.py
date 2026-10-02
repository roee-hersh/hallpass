"""The module-level secured_tool, configure, and as_tool."""

from __future__ import annotations

import inspect

import pytest

import toolpass
from toolpass import ApprovalPending, ApprovalQueue, Session, Toolkit, ToolRefused, secured_tool, spec_of


def test_secured_tool_uses_the_configured_defaults(dana):
    @secured_tool(effect="destructive", approve=True)
    def drop(table: str) -> str:
        return "dropped"

    with pytest.raises(ToolRefused) as e:
        drop("users")
    assert e.value.code == "approval_unavailable"

    queue = ApprovalQueue()
    toolpass.configure(approver=queue, audit=None)  # after the tool was declared
    with pytest.raises(ApprovalPending) as p:
        drop("users")
    queue.approve(p.value.request.id)
    assert drop("users") == "dropped"


def test_a_credential_declared_before_configure(dana):
    @secured_tool(effect="write", credential="bot")
    def act(*, credential: str) -> str:
        return credential[:4]

    with pytest.raises(ToolRefused) as e:
        act()
    assert e.value.code == "credential_error"
    toolpass.configure(credentials={"bot": "tok_abcdefgh123"}, audit=None)
    assert act() == "tok_"


def test_configure_returns_the_default_toolkit():
    tk = toolpass.configure(limits={"destructive": 1}, audit=None)
    assert tk is toolpass.default_toolkit()
    assert tk.limits == {"destructive": 1}


def test_a_toolkit_has_secured_tool_too(dana):
    tools = Toolkit(audit=None)

    @tools.secured_tool(effect="read")
    def look(q: str) -> str:
        return q

    assert look("x") == "x"
    assert spec_of(look) is not None


def test_as_tool_applies_any_framework_decorator(dana):
    seen = []

    def framework_tool(fn):
        seen.append(list(inspect.signature(fn).parameters))
        return {"framework_tool": fn}

    @secured_tool(effect="write", scope={"repo": "acme/*"}, as_tool=framework_tool)
    def open_pr(repo: str, title: str) -> str:
        return f"{repo}: {title}"

    assert seen == [["repo", "title"]]
    inner = open_pr["framework_tool"]
    assert inner("acme/web", "bump") == "acme/web: bump"
    with pytest.raises(ToolRefused):
        inner("evil/web", "bump")


def test_as_tool_with_langchain(dana):
    lc = pytest.importorskip("langchain_core.tools")
    toolpass.configure(credentials={"github-bot": "ghp_0123456789abcdef"}, audit=None)

    @secured_tool(effect="write", scope={"repo": "acme/*"}, credential="github-bot", as_tool=lc.tool)
    def open_pr(repo: str, title: str, *, credential: str) -> str:
        """Open a pull request."""
        return f"opened {repo} with {credential}"

    assert isinstance(open_pr, lc.BaseTool)
    assert open_pr.name == "open_pr"
    assert set(open_pr.args) == {"repo", "title"}
    assert open_pr.invoke({"repo": "acme/web", "title": "bump"}) == "opened acme/web with [REDACTED]"
    with pytest.raises(ToolRefused):
        open_pr.invoke({"repo": "evil/web", "title": "bump"})


def test_as_tool_keeps_the_session_rule():
    @secured_tool(effect="read", as_tool=lambda fn: fn)
    def look() -> str:
        return "ok"

    with pytest.raises(ToolRefused) as e:
        look()
    assert e.value.code == "no_session"
    with Session("x@example.com").active():
        assert look() == "ok"
