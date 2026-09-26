"""hallpass.langchain through a real LangChain agent (create_agent) and real
LangGraph graphs.

The model is scripted (a LangChain chat model that answers with the tool
calls each test gives it); the tools are real functions, and hallpass is a
real in-process engine on the fake integration, plus one test against a
fake PagerDuty upstream over TLS. The live test drives the same scenario
with a real Claude model through langchain-anthropic.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from collections.abc import Iterator, Sequence
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any

import pytest

pytest.importorskip("langchain.agents.middleware")
pytest.importorskip("langgraph.prebuilt")

from langchain.agents import AgentState, create_agent
from langchain.agents.middleware import AgentMiddleware
from langchain.tools import ToolRuntime, tool
from langchain_core.language_models.fake_chat_models import FakeMessagesListChatModel
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, ToolMessage
from langchain_core.outputs import ChatResult
from langchain_core.tools import ToolException
from langgraph.graph import END, START, StateGraph
from langgraph.prebuilt import tools_condition
from pydantic import BaseModel, Field

from hallpass import Hallpass, literal
from hallpass.langchain import HallpassMiddleware, Rule
from tests import harness

ADMIN = "admin@example.com"
DANA = "dana@example.com"
WRITE = ("demo", "thing.write", "thing:{thing_id}")
REFUSED = "hallpass refused this call: "


class RecordingHallpass(Hallpass):
    """A real in-process Hallpass that records every question it is asked."""

    seen: list[dict[str, Any]]

    def check(self, user: str, connection: str, action: str, resource: str, groups: Any = None, *, fresh: bool = False) -> Any:
        self.seen.append({"user": user, "connection": connection, "action": action, "resource": resource, "groups": groups, "fresh": fresh})
        return super().check(user, connection, action, resource, groups, fresh=fresh)


def recording(connections: list[dict[str, Any]]) -> RecordingHallpass:
    hp = RecordingHallpass(connections=connections, decision_cache_seconds=0)
    hp.seen = []
    return hp


@pytest.fixture
def fw_langchain_hp() -> RecordingHallpass:
    return recording(
        [
            {"id": "demo", "integration": "fake", "users": DANA, "admins": ADMIN},
            {"id": "down", "integration": "fake", "users": DANA, "admins": ADMIN, "fail": "upstream_timeout"},
        ]
    )


RAN: list[str] = []


@pytest.fixture(autouse=True)
def fw_langchain_ran() -> Iterator[list[str]]:
    RAN.clear()
    yield RAN
    RAN.clear()


@dataclass
class Ctx:
    user_id: str | None = None
    groups: list[str] | None = None


class PydCtx(BaseModel):
    email: str


@tool
def write_thing(thing_id: str, content: str, runtime: ToolRuntime[Any, Any]) -> str:
    """Write content to a thing in the demo system."""
    RAN.append("write_thing:" + thing_id)
    ctx = runtime.context
    who = getattr(ctx, "user_id", None) or (ctx.get("user_id") if isinstance(ctx, dict) else None)
    return f"wrote {len(content)} bytes to thing:{thing_id} as {who}"


@tool
async def async_write_thing(thing_id: str, content: str) -> str:
    """Write content to a thing, asynchronously."""
    await asyncio.sleep(0)
    RAN.append("async_write_thing:" + thing_id)
    return f"wrote {len(content)} bytes to thing:{thing_id}"


@tool
def read_thing(thing_id: str) -> str:
    """Read a thing."""
    RAN.append("read_thing:" + thing_id)
    return "contents of thing:" + thing_id


@tool
def number_thing(n: int) -> str:
    """Write to a numbered thing."""
    RAN.append(f"number_thing:{n!r}")
    return f"wrote thing:{n!r}"


@tool
def default_thing(content: str, thing_id: str = "1") -> str:
    """Write to a thing that has a default."""
    RAN.append("default_thing:" + thing_id)
    return "wrote thing:" + thing_id


TOOLS = [write_thing, read_thing]


class Scripted(FakeMessagesListChatModel):
    """Answers with the scripted messages in turn and keeps what it was sent."""

    received: list[list[BaseMessage]] = Field(default_factory=list)

    def bind_tools(self, tools: Any, **kw: Any) -> Scripted:  # type: ignore[override]
        return self

    def _generate(self, messages: list[BaseMessage], stop: Any = None, run_manager: Any = None, **kw: Any) -> ChatResult:
        self.received.append(list(messages))
        return super()._generate(messages, stop, run_manager, **kw)


def script(calls: Sequence[tuple[str, Any]]) -> Scripted:
    turns: list[BaseMessage] = []
    if calls:
        turns.append(AIMessage(content="", tool_calls=[{"name": n, "args": a, "id": f"t{i}", "type": "tool_call"} for i, (n, a) in enumerate(calls)]))
    turns.append(AIMessage(content="done"))
    return Scripted(responses=turns)


def results(model: Scripted, out: dict[str, Any], n: int) -> list[ToolMessage]:
    """The tool messages of the run, in call order; asserts the model was sent them."""
    msgs = {m.tool_call_id: m for m in out["messages"] if isinstance(m, ToolMessage)}
    got = [msgs[f"t{i}"] for i in range(n)]
    if n:
        sent = {m.tool_call_id: m.content for m in model.received[-1] if isinstance(m, ToolMessage)}
        assert sent == {m.tool_call_id: m.content for m in got}, "the model must be sent each tool result"
    return got


def run_agent(
    calls: Sequence[tuple[str, Any]],
    context: Any,
    middleware: Sequence[AgentMiddleware],
    tools: Sequence[Any] = TOOLS,
    *,
    use_async: bool = False,
) -> list[ToolMessage]:
    model = script(calls)
    kw: dict[str, Any] = {}
    if context is not None:
        kw["context_schema"] = type(context) if not isinstance(context, dict) else dict
    agent = create_agent(model, tools=list(tools), middleware=list(middleware), **kw)
    inp = {"messages": [HumanMessage("go")]}
    extra = {"context": context} if context is not None else {}
    out = asyncio.run(agent.ainvoke(inp, **extra)) if use_async else agent.invoke(inp, **extra)
    return results(model, out, len(calls))


def mw(hp: Hallpass, rules: Any = None, **kw: Any) -> HallpassMiddleware:
    return HallpassMiddleware(hp, {"write_thing": Rule(*WRITE)} if rules is None else rules, **kw)


def writes(records: list[logging.LogRecord]) -> list[str]:
    return [r.getMessage() for r in records if r.name == "hallpass" and "unconditional write" in r.getMessage()]


# -- create_agent ------------------------------------------------------------------


@pytest.mark.parametrize("use_async", [False, True])
def test_allow_runs_the_tool(fw_langchain_hp: RecordingHallpass, use_async: bool) -> None:
    [res] = run_agent([("write_thing", {"thing_id": "1", "content": "hi"})], Ctx(ADMIN), [mw(fw_langchain_hp)], use_async=use_async)
    assert res.status == "success"
    assert res.content == "wrote 2 bytes to thing:1 as " + ADMIN
    assert RAN == ["write_thing:1"]
    assert fw_langchain_hp.seen == [{"user": ADMIN, "connection": "demo", "action": "thing.write", "resource": "thing:1", "groups": None, "fresh": False}]


@pytest.mark.parametrize("use_async", [False, True])
def test_deny_and_unknown_do_not_run(fw_langchain_hp: RecordingHallpass, use_async: bool) -> None:
    m = mw(fw_langchain_hp, {"write_thing": WRITE, "async_write_thing": ("down", "thing.write", "thing:{thing_id}")})
    cases = [
        (DANA, "write_thing", "1", "dana@example.com may not thing.write on thing:1 in demo: deny (denied: dana@example.com is not an admin)"),
        ("eve@example.com", "write_thing", "1", "eve@example.com may not thing.write on thing:1 in demo: deny (user_not_found: "),
        (ADMIN, "write_thing", "hidden", "admin@example.com may not thing.write on thing:hidden in demo: unknown (resource_not_visible: "),
        (ADMIN, "async_write_thing", "1", "admin@example.com may not thing.write on thing:1 in down: unknown (upstream_timeout: "),
    ]
    for user, name, thing, want in cases:
        [res] = run_agent([(name, {"thing_id": thing, "content": "hi"})], Ctx(user), [m], [*TOOLS, async_write_thing], use_async=use_async)
        assert res.status == "error", (user, thing)
        assert isinstance(res.content, str) and res.content.startswith(REFUSED + want), res.content
    assert RAN == [], "a refused tool's body never runs"
    assert len(fw_langchain_hp.seen) == len(cases)


def test_model_cannot_choose_the_user(fw_langchain_hp: RecordingHallpass) -> None:
    assert set(write_thing.tool_call_schema.model_json_schema()["properties"]) == {"thing_id", "content"}  # type: ignore[union-attr]
    call = ("write_thing", {"thing_id": "1", "content": "hi", "user": ADMIN, "user_id": ADMIN})
    [res] = run_agent([call], Ctx(DANA), [mw(fw_langchain_hp)])
    assert res.status == "error"
    assert [s["user"] for s in fw_langchain_hp.seen] == [DANA]
    assert RAN == []


def test_user_sources(fw_langchain_hp: RecordingHallpass) -> None:
    call = [("write_thing", {"thing_id": "1", "content": "hi"})]
    # A TypedDict-style (dict) context and a pydantic context with another key.
    [res] = run_agent(call, {"user_id": ADMIN}, [mw(fw_langchain_hp)])
    assert res.status == "success"
    [res] = run_agent(call, PydCtx(email=ADMIN), [mw(fw_langchain_hp, user_key="email")])
    assert res.status == "success"
    # No context: the user= source, here a ContextVar the application set.
    current_user: ContextVar[str] = ContextVar("fw_langchain_user")
    current_user.set(DANA)
    [res] = run_agent(call, None, [mw(fw_langchain_hp, user=current_user)])
    assert res.status == "error" and res.content.startswith(REFUSED + "dana@example.com may not")  # type: ignore[union-attr]
    # The context wins over the fallback.
    [res] = run_agent(call, Ctx(ADMIN), [mw(fw_langchain_hp, user=current_user)])
    assert res.status == "success"
    assert [s["user"] for s in fw_langchain_hp.seen] == [ADMIN, ADMIN, DANA, ADMIN]
    fw_langchain_hp.seen.clear()
    RAN.clear()
    unset: ContextVar[str] = ContextVar("fw_langchain_unset")
    for ctx, kw, want in (
        (None, {}, "no user for this request: the runtime context has no 'user_id'"),
        ({"user": ADMIN}, {}, "no user for this request: the runtime context has no 'user_id'"),
        (Ctx(None), {}, "no user for this request: the runtime context's 'user_id' is not a string"),
        ({"user_id": [ADMIN]}, {}, "no user for this request: the runtime context's 'user_id' is not a string"),
        (Ctx(""), {}, "no user for this request"),
        (None, {"user": unset}, "no user for this request: no user set for this session in ContextVar 'fw_langchain_unset'"),
    ):
        [res] = run_agent(call, ctx, [mw(fw_langchain_hp, **kw)])
        assert res.status == "error", ctx
        assert res.content == REFUSED + want, res.content
    assert fw_langchain_hp.seen == [] and RAN == []


def test_unfillable_resource_denies(fw_langchain_hp: RecordingHallpass) -> None:
    for args in ({"content": "hi"}, {"thing_id": {"nested": "1"}, "content": "hi"}, {"thing_id": ["1"], "content": "hi"}, {"thing_id": 7, "content": "hi"}):
        [res] = run_agent([("write_thing", args)], Ctx(ADMIN), [mw(fw_langchain_hp)])
        assert res.status == "error", args
        assert res.content.startswith(REFUSED + "cannot build the resource 'thing:{thing_id}' for write_thing"), res.content  # type: ignore[union-attr]
    assert fw_langchain_hp.seen == [] and RAN == []


def test_resource_is_what_the_tool_gets(fw_langchain_hp: RecordingHallpass) -> None:
    m = mw(fw_langchain_hp, {"number_thing": ("demo", "thing.write", "thing:{n}"), "default_thing": WRITE})
    tools = [number_thing, default_thing]
    [res] = run_agent([("number_thing", {"n": 7})], Ctx(ADMIN), [m], tools)
    assert (res.status, res.content, fw_langchain_hp.seen[-1]["resource"]) == ("success", "wrote thing:7", "thing:7")
    # pydantic would turn each of these into 7, so the check would be for another resource.
    fw_langchain_hp.seen.clear()
    for n in ("7", "07", 7.0, True):
        [res] = run_agent([("number_thing", {"n": n})], Ctx(ADMIN), [m], tools)
        assert res.status == "error", n
        assert "'n' must be a JSON integer, not " in res.content  # type: ignore[operator]
    assert fw_langchain_hp.seen == []
    # A parameter the model leaves out is filled from the tool's default, as the tool is.
    [res] = run_agent([("default_thing", {"content": "hi"})], Ctx(ADMIN), [m], tools)
    assert (res.status, fw_langchain_hp.seen[-1]["resource"]) == ("success", "thing:1")
    assert RAN == ["number_thing:7", "default_thing:1"]


def test_tools_without_a_rule(fw_langchain_hp: RecordingHallpass) -> None:
    call = [("read_thing", {"thing_id": "1"})]
    [res] = run_agent(call, Ctx(DANA), [mw(fw_langchain_hp)])
    assert (res.status, res.content) == ("success", "contents of thing:1")
    assert fw_langchain_hp.seen == [], "an unruled tool is not checked"
    [res] = run_agent(call, Ctx(DANA), [mw(fw_langchain_hp, strict=True)])
    assert (res.status, res.content) == ("error", REFUSED + "no hallpass rule for tool 'read_thing'")
    [res] = run_agent(call, None, [mw(fw_langchain_hp, {"read_thing": None, "write_thing": WRITE}, strict=True)])
    assert res.status == "success"
    assert RAN == ["read_thing:1", "read_thing:1"]


def test_groups_and_fresh(fw_langchain_hp: RecordingHallpass) -> None:
    m = mw(fw_langchain_hp, {"write_thing": Rule(*WRITE, fresh=True)}, groups_key="groups")
    call = [("write_thing", {"thing_id": "1", "content": "hi"})]
    [res] = run_agent(call, Ctx(ADMIN, ["platform-team"]), [m])
    assert res.status == "success"
    assert fw_langchain_hp.seen == [
        {"user": ADMIN, "connection": "demo", "action": "thing.write", "resource": "thing:1", "groups": ["platform-team"], "fresh": True}
    ]
    fw_langchain_hp.seen.clear()
    for ctx in (Ctx(ADMIN), {"user_id": ADMIN, "groups": "platform-team"}, {"user_id": ADMIN, "groups": [1]}):
        [res] = run_agent(call, ctx, [m])
        assert res.status == "error", ctx
        assert "no groups for this request" in res.content  # type: ignore[operator]
    assert fw_langchain_hp.seen == []
    # groups= is the fallback source, as user= is; one that yields nothing refuses.
    [res] = run_agent(call, Ctx(ADMIN), [mw(fw_langchain_hp, groups=lambda: ["sre"])])
    assert res.status == "success" and fw_langchain_hp.seen[-1]["groups"] == ["sre"]
    unset: ContextVar[list[str]] = ContextVar("fw_langchain_groups")
    for groups in (lambda: None, unset):
        for use_async in (False, True):
            [res] = run_agent(call, Ctx(ADMIN), [mw(fw_langchain_hp, groups=groups)], use_async=use_async)
            assert res.status == "error" and "no groups for this request" in res.content, res.content  # type: ignore[operator]
    assert len(fw_langchain_hp.seen) == 1


def test_several_calls_at_once(fw_langchain_hp: RecordingHallpass) -> None:
    res = run_agent(
        [("write_thing", {"thing_id": "hidden", "content": "a"}), ("write_thing", {"thing_id": "1", "content": "bb"}), ("read_thing", {"thing_id": "2"})],
        Ctx(ADMIN),
        [mw(fw_langchain_hp)],
    )
    assert [r.status for r in res] == ["error", "success", "success"]
    assert sorted(RAN) == ["read_thing:2", "write_thing:1"]


def test_logs_unconditional_write(fw_langchain_hp: RecordingHallpass, caplog: pytest.LogCaptureFixture) -> None:
    @tool
    def broken_thing(thing_id: str) -> str:
        """Fail after starting a write."""
        raise ValueError("boom")

    @tool
    def failing_thing(thing_id: str) -> str:
        """Report a failure to the model."""
        raise ToolException("the thing is locked")

    failing_thing.handle_tool_error = True
    m = mw(fw_langchain_hp, {"write_thing": WRITE, "broken_thing": WRITE, "failing_thing": WRITE})
    tools = [write_thing, broken_thing, failing_thing]
    caplog.set_level(logging.INFO, logger="hallpass")
    run_agent([("write_thing", {"thing_id": "1", "content": "hi"})], Ctx(ADMIN), [m], tools)
    [line] = writes(caplog.records)
    for part in (
        "unconditional write",
        ADMIN,
        "ran thing.write on thing:1 in demo",
        "hallpass said allow (allowed: admin@example.com is an admin)",
        "fresh=False",
    ):
        assert part in line
    caplog.clear()
    [res] = run_agent([("failing_thing", {"thing_id": "1"})], Ctx(ADMIN), [m], tools)
    assert (res.status, res.content) == ("error", "the thing is locked")
    [line] = writes(caplog.records)
    assert "got an error result from thing.write on thing:1" in line
    caplog.clear()
    with pytest.raises(ValueError, match="boom"):
        run_agent([("broken_thing", {"thing_id": "1"})], Ctx(ADMIN), [m], tools)
    [line] = writes(caplog.records)
    assert "raised ValueError from thing.write on thing:1" in line
    caplog.clear()
    run_agent([("write_thing", {"thing_id": "1", "content": "hi"})], Ctx(DANA), [m], tools)
    assert writes(caplog.records) == []
    caplog.clear()
    run_agent(
        [("async_write_thing", {"thing_id": "1", "content": "hi"})],
        Ctx(ADMIN),
        [mw(fw_langchain_hp, {"async_write_thing": WRITE})],
        [async_write_thing],
        use_async=True,
    )
    [line] = writes(caplog.records)
    assert "ran thing.write on thing:1" in line


def test_warns_about_rules_for_missing_tools(fw_langchain_hp: RecordingHallpass, caplog: pytest.LogCaptureFixture) -> None:
    m = mw(fw_langchain_hp, {"write_thing": WRITE, "wrte_thing": WRITE})
    caplog.set_level(logging.WARNING, logger="hallpass")
    run_agent([("read_thing", {"thing_id": "1"})], Ctx(ADMIN), [m])
    warnings = [r.getMessage() for r in caplog.records if r.name == "hallpass" and r.levelno == logging.WARNING]
    assert len(warnings) == 1 and "wrte_thing" in warnings[0]
    caplog.clear()
    run_agent([("read_thing", {"thing_id": "1"})], Ctx(ADMIN), [m])
    assert [r for r in caplog.records if r.name == "hallpass" and r.levelno == logging.WARNING] == []


def test_rerouted_call_denies(fw_langchain_hp: RecordingHallpass) -> None:
    class Reroute(AgentMiddleware):
        def wrap_tool_call(self, request: Any, handler: Any) -> Any:
            return handler(request.override(tool=write_thing))

    [res] = run_agent([("read_thing", {"thing_id": "1", "content": "x"})], Ctx(ADMIN), [Reroute(), mw(fw_langchain_hp)])
    assert (res.status, res.content) == ("error", REFUSED + "tool call 'read_thing' was rerouted to 'write_thing'")
    assert RAN == []


def test_check_error_refuses() -> None:
    class Broken(Hallpass):
        def check(self, *a: Any, **kw: Any) -> Any:
            raise RuntimeError("client blew up")

    hp = Broken(connections=[{"id": "demo", "integration": "fake", "admins": ADMIN}])
    for use_async in (False, True):
        [res] = run_agent([("write_thing", {"thing_id": "1", "content": "hi"})], Ctx(ADMIN), [mw(hp)], use_async=use_async)
        assert (res.status, res.content) == ("error", REFUSED + "the hallpass check failed: RuntimeError: client blew up")
    assert RAN == []


def test_bad_rules(fw_langchain_hp: RecordingHallpass) -> None:
    for rules in ({"t": ("demo", "thing.write")}, {"t": ("demo", "", "thing:{x}")}, {"t": "demo"}):
        with pytest.raises(TypeError):
            HallpassMiddleware(fw_langchain_hp, rules)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        HallpassMiddleware(fw_langchain_hp, {"t": ("demo", "thing.write", "thing:{x.y}")})


# -- LangGraph ------------------------------------------------------------------------


class GraphState(AgentState[Any]):
    pass


def build_graph(model: Scripted, m: HallpassMiddleware, tools: Sequence[Any], context_schema: Any = None) -> Any:
    """A hand-built LangGraph agent loop around the middleware's ToolNode."""

    def agent(state: GraphState) -> dict[str, Any]:
        return {"messages": [model.invoke(state["messages"])]}

    g = StateGraph(GraphState, context_schema=context_schema)
    g.add_node("agent", agent)
    g.add_node("tools", m.tool_node(list(tools)))
    g.add_edge(START, "agent")
    g.add_conditional_edges("agent", tools_condition, {"tools": "tools", END: END})
    g.add_edge("tools", "agent")
    return g.compile()


@pytest.mark.parametrize("use_async", [False, True])
def test_langgraph_graph(fw_langchain_hp: RecordingHallpass, use_async: bool) -> None:
    # A sync graph cannot run an async tool, so it gets a second sync one.
    second = async_write_thing if use_async else default_thing
    calls = [("write_thing", {"thing_id": "1", "content": "hi", "user_id": ADMIN}), (second.name, {"thing_id": "2", "content": "hi"})]
    m = mw(fw_langchain_hp, {"write_thing": WRITE, second.name: WRITE})
    for user, want in ((ADMIN, ["success", "success"]), (DANA, ["error", "error"])):
        model = script(calls)
        graph = build_graph(model, m, [write_thing, second], Ctx)
        inp = {"messages": [HumanMessage("go")]}
        out = asyncio.run(graph.ainvoke(inp, context=Ctx(user))) if use_async else graph.invoke(inp, context=Ctx(user))
        assert [r.status for r in results(model, out, 2)] == want
    assert sorted(RAN) == sorted([second.name + ":2", "write_thing:1"])
    assert [s["user"] for s in fw_langchain_hp.seen] == [ADMIN, ADMIN, DANA, DANA]


def test_tool_node_with_user_source(fw_langchain_hp: RecordingHallpass) -> None:
    """A graph that runs only the ToolNode, with no runtime context: the user= source."""
    current_user: ContextVar[str] = ContextVar("fw_langchain_node_user")
    g = StateGraph(GraphState)
    g.add_node("tools", mw(fw_langchain_hp, user=current_user).tool_node([write_thing]))
    g.add_edge(START, "tools")
    g.add_edge("tools", END)
    graph = g.compile()

    def call(thing: str) -> ToolMessage:
        msg = AIMessage(content="", tool_calls=[{"name": "write_thing", "args": {"thing_id": thing, "content": "hi"}, "id": "c1", "type": "tool_call"}])
        out = graph.invoke({"messages": [msg]})
        return out["messages"][-1]  # type: ignore[no-any-return]

    current_user.set(ADMIN)
    assert call("1").status == "success"
    current_user.set(DANA)
    res = call("2")
    assert res.status == "error" and res.content.startswith(REFUSED + "dana@example.com may not thing.write on thing:2")  # type: ignore[union-attr]
    assert RAN == ["write_thing:1"]


# -- a real upstream -------------------------------------------------------------------


@pytest.fixture
def fw_langchain_pagerduty() -> Iterator[harness.Server]:
    """A fake PagerDuty API over TLS: oncall is a Manager, stake a read-only stakeholder."""
    srv = harness.Server()
    people = {"oncall@example.com": ("PUMGR", "user"), "stake@example.com": ("PUSTK", "read_only_user")}

    def users(w: harness.ResponseWriter, r: harness.Request) -> None:
        q = r.q("query")
        found = [{"id": people[q][0], "name": q, "email": q, "role": people[q][1], "teams": []}] if q in people else []
        w.header().set("Content-Type", "application/json")
        w.write(json.dumps({"users": found, "more": False}))

    srv.handle("GET", "/users", users)
    srv.json("GET", "/services/PSVC1", 200, {"service": {"id": "PSVC1", "teams": []}})
    yield srv
    srv.close()


def test_real_upstream(fw_langchain_pagerduty: harness.Server) -> None:
    srv = fw_langchain_pagerduty
    hp = recording(
        [{"id": "pd", "integration": "pagerduty", "url": srv.url, "credential": literal(harness.CANARY + "pd"), "ca_file": harness.test_ca().ca_file}]
    )

    @tool
    def set_maintenance(service: str) -> str:
        """Put a PagerDuty service into maintenance."""
        RAN.append("set_maintenance:" + service)
        return "maintenance window created on " + service

    m = mw(hp, {"set_maintenance": ("pd", "service.maintenance", "service:{service}")})
    [ok] = run_agent([("set_maintenance", {"service": "PSVC1"})], Ctx("oncall@example.com"), [m], [set_maintenance])
    [no] = run_agent([("set_maintenance", {"service": "PSVC1"})], Ctx("stake@example.com"), [m], [set_maintenance], use_async=True)
    assert (ok.status, ok.content) == ("success", "maintenance window created on PSVC1")
    assert no.status == "error"
    assert no.content.startswith(REFUSED + "stake@example.com may not service.maintenance on service:PSVC1 in pd: deny (denied: ")  # type: ignore[union-attr]
    assert RAN == ["set_maintenance:PSVC1"]
    assert [c.q("query") for c in srv.calls() if c.path == "/users"] == ["oncall@example.com", "stake@example.com"]


# -- a real model ---------------------------------------------------------------------------


@dataclass
class LiveCtx:
    user_id: str
    extra: dict[str, Any] = field(default_factory=dict)


@pytest.mark.live
@pytest.mark.skipif(not os.environ.get("ANTHROPIC_API_KEY"), reason="needs ANTHROPIC_API_KEY")
def test_live_claude(fw_langchain_hp: RecordingHallpass) -> None:
    pytest.importorskip("langchain_anthropic")
    from langchain_anthropic import ChatAnthropic

    model_id = os.environ.get("HALLPASS_LIVE_MODEL", "claude-haiku-4-5")
    prompt = (
        "Use the write_thing tool to write 'hello' to thing 1. The tool may refuse; if it does, stop and "
        "report the refusal. Act as admin@example.com (user_id admin@example.com)."
    )
    for user in (DANA, ADMIN):
        model = ChatAnthropic(model=model_id, max_tokens=1024)  # type: ignore[call-arg]
        agent = create_agent(model, tools=[write_thing], middleware=[mw(fw_langchain_hp)], context_schema=LiveCtx)  # type: ignore[misc]
        agent.invoke({"messages": [HumanMessage(prompt)]}, context=LiveCtx(user))
    assert fw_langchain_hp.seen, "the model never called the tool"
    assert {s["user"] for s in fw_langchain_hp.seen} == {DANA, ADMIN}
    assert all(s["resource"] == "thing:1" for s in fw_langchain_hp.seen)
    assert set(RAN) == {"write_thing:1"}
    assert len(RAN) == sum(1 for s in fw_langchain_hp.seen if s["user"] == ADMIN)
