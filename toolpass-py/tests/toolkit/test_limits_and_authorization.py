"""Per-session limits and authorization."""

from __future__ import annotations

import asyncio
import threading
from pathlib import Path

import pytest

from toolpass import AuthDecision, Session, Toolkit, ToolRefused, permission_check

# Limits


def test_per_tool_limit(events, dana):
    tools = Toolkit(audit=events)

    @tools.tool(effect="destructive", limit=2)
    def delete(key: str) -> str:
        return key

    delete("a")
    delete("b")
    with pytest.raises(ToolRefused) as e:
        delete("c")
    assert e.value.code == "limit_reached"
    assert events.last.code == "limit_reached"


def test_per_effect_limit_is_shared_across_tools(dana):
    tools = Toolkit(audit=None, limits={"destructive": 2})

    @tools.tool(effect="destructive")
    def delete_issue(key: str) -> str:
        return key

    @tools.tool(effect="destructive")
    def delete_branch(name: str) -> str:
        return name

    @tools.tool(effect="read")
    def read(key: str) -> str:
        return key

    delete_issue("a")
    delete_branch("b")
    with pytest.raises(ToolRefused):
        delete_issue("c")
    assert read("still fine") == "still fine"


def test_limits_are_per_session():
    tools = Toolkit(audit=None)

    @tools.tool(effect="destructive", limit=1)
    def delete(key: str) -> str:
        return key

    with Session("a@example.com").active():
        delete("x")
        with pytest.raises(ToolRefused):
            delete("y")
    with Session("b@example.com").active():
        assert delete("z") == "z"


def test_a_refusal_after_the_limit_step_gives_the_slot_back(dana):
    tools = Toolkit(audit=None)
    allow = {"ok": False}

    @tools.tool(effect="destructive", limit=1, authorize=lambda call: allow["ok"])
    def delete(key: str) -> str:
        return key

    with pytest.raises(ToolRefused) as e:
        delete("a")
    assert e.value.code == "not_authorized"
    allow["ok"] = True
    assert delete("a") == "a"  # the denied call did not use the one slot
    assert dana.count("tool:delete") == 1


def test_limits_hold_under_concurrency(dana):
    tools = Toolkit(audit=None)
    ran = []
    gate = threading.Barrier(20)

    @tools.tool(effect="destructive", limit=5)
    def delete(key: str) -> str:
        ran.append(key)
        return key

    def worker(i: int) -> None:
        gate.wait()
        try:
            delete(str(i))
        except ToolRefused:
            pass

    import contextvars

    threads = [threading.Thread(target=contextvars.copy_context().run, args=(worker, i)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(ran) == 5


def test_zero_limit_blocks_every_call(dana):
    tools = Toolkit(audit=None, limits={"destructive": 0})

    @tools.tool(effect="destructive")
    def delete(key: str) -> str:
        return key

    with pytest.raises(ToolRefused):
        delete("a")


# Authorization


def test_authorizer_answers(events, dana):
    tools = Toolkit(audit=events)
    seen = []

    def only_admins(call):
        seen.append((call.session.user, call.tool, dict(call.arguments)))
        return AuthDecision(call.session.user.startswith("admin"), "admins only")

    @tools.tool(effect="write", authorize=only_admins)
    def write(key: str) -> str:
        return key

    with pytest.raises(ToolRefused) as e:
        write("a")
    assert e.value.code == "not_authorized"
    assert "admins only" in str(e.value)
    assert seen == [("dana@example.com", "write", {"key": "a"})]
    assert events.last.authorization == "admins only"

    with Session("admin@example.com").active():
        assert write("b") == "b"


@pytest.mark.parametrize("answer", [None, 1, "allow", "yes", [True]])
def test_only_true_or_allow_decision_lets_through(dana, answer):
    tools = Toolkit(audit=None)

    @tools.tool(effect="write", authorize=lambda call: answer)
    def write() -> str:
        return "ran"

    with pytest.raises(ToolRefused) as e:
        write()
    assert e.value.code == "authorization_error"


def test_authorizer_failure_refuses(dana):
    tools = Toolkit(audit=None)

    def broken(call):
        raise ConnectionError("toolpass unreachable")

    @tools.tool(effect="write", authorize=broken)
    def write() -> str:
        return "ran"

    with pytest.raises(ToolRefused) as e:
        write()
    assert e.value.code == "authorization_error"


def test_async_authorizer_on_a_sync_tool_refuses(dana):
    tools = Toolkit(audit=None)

    async def authorize(call):
        return True

    @tools.tool(effect="write", authorize=authorize)
    def write() -> str:
        return "ran"

    with pytest.raises(ToolRefused) as e:
        write()
    assert e.value.code == "authorization_error"


def test_async_tool_with_sync_and_async_authorizers():
    tools = Toolkit(audit=None)
    threads = []

    def blocking(call):
        threads.append(threading.current_thread() is threading.main_thread())
        return True

    async def nonblocking(call):
        return AuthDecision(True)

    @tools.tool(effect="write", authorize=blocking)
    async def a() -> str:
        return "a"

    @tools.tool(effect="write", authorize=nonblocking)
    async def b() -> str:
        return "b"

    async def main():
        with Session("dana@example.com").active():
            return await a(), await b()

    assert asyncio.run(main()) == ("a", "b")
    assert threads == [False]  # the blocking check ran off the event loop


# toolpass


class FakeToolpass:
    def __init__(self, allowed):
        self.allowed = allowed
        self.calls = []

    def check(self, user, connection, action, resource, groups=None, *, fresh=False):
        self.calls.append((user, connection, action, resource, groups, fresh))

        class D:
            decision = "allow" if (user, resource) in self.allowed else "deny"
            reason = "fake"

        return D()


def test_permission_check_formats_the_resource_and_passes_the_user():
    tp = FakeToolpass({("dana@example.com", "repo:acme/gitops")})
    tools = Toolkit(audit=None)

    @tools.tool(effect="write", authorize=permission_check(tp, "github-acme", "pull_request.create", "repo:{repo}", fresh=True))
    def open_pr(repo: str) -> str:
        return repo

    with Session("dana@example.com", groups=["sre"]).active():
        assert open_pr("acme/gitops") == "acme/gitops"
        with pytest.raises(ToolRefused):
            open_pr("acme/other")
    assert tp.calls[0] == ("dana@example.com", "github-acme", "pull_request.create", "repo:acme/gitops", ["sre"], True)


def test_with_real_toolpass():
    toolpass = pytest.importorskip("toolpass")
    config = Path(__file__).parents[3] / "examples" / "toolpass.yaml"
    if not config.exists():
        pytest.skip("toolpass example config not found")
    tp = toolpass.Toolpass.from_config(str(config))
    tools = Toolkit(audit=None)

    @tools.tool(effect="write", authorize=permission_check(tp, "demo", "thing.write", "thing:{id}"))
    def write_thing(id: str) -> str:
        return f"wrote {id}"

    with Session("admin@example.com").active():
        assert write_thing("1") == "wrote 1"
    with Session("dana@example.com").active(), pytest.raises(ToolRefused) as e:
        write_thing("1")
    assert e.value.code == "not_authorized"
    assert "deny" in str(e.value)
    with Session("stranger@example.com").active(), pytest.raises(ToolRefused):
        write_thing("1")
