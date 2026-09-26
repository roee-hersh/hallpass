"""hallpass.strands through a real Strands Agent loop.

The model is scripted (it implements Strands' Model interface and asks for
the tool calls each test gives it); the tools are real functions, and
hallpass is a real in-process engine on the fake integration, plus one
test against a fake PagerDuty upstream over TLS. The live test drives the
same scenario with a real Claude model.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import socket
import subprocess
import time
import urllib.request
import uuid
from collections.abc import AsyncIterator, Iterator
from contextvars import ContextVar
from typing import Any

import pytest

pytest.importorskip("strands.interventions")

from strands import Agent, ToolContext, tool
from strands.interventions import Deny, InterventionHandler, Proceed, Transform
from strands.models import Model

from hallpass import Hallpass, guarded, literal
from hallpass.strands import HallpassAuthorization, Rule
from tests import harness

ADMIN = "admin@example.com"
DANA = "dana@example.com"
WRITE = ("demo", "thing.write", "thing:{thing_id}")
REFUSED = "DENIED: hallpass refused this call: "


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
def fw_strands_hp() -> RecordingHallpass:
    return recording(
        [
            {"id": "demo", "integration": "fake", "users": DANA, "admins": ADMIN},
            {"id": "down", "integration": "fake", "users": DANA, "admins": ADMIN, "fail": "upstream_timeout"},
        ]
    )


# Tool bodies record that they ran, so a test can tell a refusal from a run.
RAN: list[str] = []


@pytest.fixture(autouse=True)
def fw_strands_ran() -> Iterator[list[str]]:
    RAN.clear()
    yield RAN
    RAN.clear()


@tool(context=True)
def check_permission(connection: str, action: str, resource: str, tool_context: ToolContext) -> str:
    """Ask whether the current user may perform an action in a system.

    Args:
        connection: a hallpass connection id
        action: one of that connection's actions
        resource: the target
    """
    RAN.append("check_permission")
    hp: Hallpass = tool_context.invocation_state["hp"]
    d = hp.check(tool_context.invocation_state["user_id"], connection, action, resource)
    return f"{d.decision}: {d.reason}"


@tool(context=True)
def write_thing(thing_id: str, content: str, tool_context: ToolContext) -> str:
    """Write content to a thing in the demo system.

    Args:
        thing_id: the thing to write to
        content: what to write
    """
    RAN.append("write_thing:" + thing_id)
    return f"wrote {len(content)} bytes to thing:{thing_id} as {tool_context.invocation_state['user_id']}"


@tool
async def async_write_thing(thing_id: str, content: str) -> str:
    """Write content to a thing, asynchronously.

    Args:
        thing_id: the thing to write to
        content: what to write
    """
    await asyncio.sleep(0)
    RAN.append("async_write_thing:" + thing_id)
    return f"wrote {len(content)} bytes to thing:{thing_id}"


TOOLS = [check_permission, write_thing]


class Scripted(Model):
    """Asks for the given tool calls, then ends the turn. Keeps what it was sent."""

    def __init__(self, calls: list[tuple[str, Any]]) -> None:
        self.turns: list[list[tuple[str, Any]] | None] = [calls, None] if calls else [None]
        self.received: list[Any] = []

    def update_config(self, **kw: Any) -> None:
        pass

    def get_config(self) -> Any:
        return {}

    async def structured_output(self, *a: Any, **kw: Any) -> AsyncIterator[Any]:  # type: ignore[override]
        raise NotImplementedError
        yield

    async def stream(self, messages: Any, tool_specs: Any = None, system_prompt: Any = None, **kw: Any) -> AsyncIterator[Any]:  # type: ignore[override]
        self.received.append(json.loads(json.dumps(messages, default=str)))
        calls = self.turns.pop(0)
        yield {"messageStart": {"role": "assistant"}}
        if calls is None:
            yield {"contentBlockStart": {"start": {}}}
            yield {"contentBlockDelta": {"delta": {"text": "done"}}}
            yield {"contentBlockStop": {}}
            yield {"messageStop": {"stopReason": "end_turn"}}
            return
        for i, (name, args) in enumerate(calls):
            yield {"contentBlockStart": {"start": {"toolUse": {"toolUseId": f"t{i}", "name": name}}}}
            yield {"contentBlockDelta": {"delta": {"toolUse": {"input": json.dumps(args)}}}}
            yield {"contentBlockStop": {}}
        yield {"messageStop": {"stopReason": "tool_use"}}


def model_saw(model: Scripted) -> dict[str, str]:
    """The tool results the model was sent in its last turn, by toolUseId."""
    out = {}
    for m in model.received[-1]:
        for b in m["content"]:
            if "toolResult" in b:
                out[b["toolResult"]["toolUseId"]] = b["toolResult"]["content"][0]["text"]
    return out


def run_agent(
    calls: list[tuple[str, Any]],
    state: dict[str, Any],
    interventions: list[Any],
    tools: list[Any] | None = None,
) -> list[dict[str, Any]]:
    """Run the calls through an Agent and return the tool results, in call order.
    Asserts the model was sent exactly those results."""
    model = Scripted(calls)
    agent = Agent(model=model, tools=tools or TOOLS, interventions=interventions, callback_handler=None)
    agent("go", invocation_state=state)
    results: dict[str, Any] = {b["toolResult"]["toolUseId"]: b["toolResult"] for m in agent.messages for b in m["content"] if "toolResult" in b}
    out = [results[f"t{i}"] for i in range(len(calls))]
    if calls:
        assert model_saw(model) == {f"t{i}": text(r) for i, r in enumerate(out)}, "the model must be sent each tool result"
    return out


def text(result: dict[str, Any]) -> str:
    return str(result["content"][0]["text"])


def handler(hp: Hallpass, **kw: Any) -> HallpassAuthorization:
    return HallpassAuthorization(hp, {"write_thing": Rule(*WRITE)}, **kw)


def writes(records: list[logging.LogRecord]) -> list[str]:
    return [r.getMessage() for r in records if r.name == "hallpass" and "unconditional write" in r.getMessage()]


# -- the agent loop ------------------------------------------------------------


def test_allow_runs_the_tool(fw_strands_hp: RecordingHallpass) -> None:
    [res] = run_agent([("write_thing", {"thing_id": "1", "content": "hi"})], {"user_id": ADMIN}, [handler(fw_strands_hp)])
    assert res["status"] == "success"
    assert text(res) == "wrote 2 bytes to thing:1 as " + ADMIN
    assert RAN == ["write_thing:1"]
    assert fw_strands_hp.seen == [{"user": ADMIN, "connection": "demo", "action": "thing.write", "resource": "thing:1", "groups": None, "fresh": False}]


def test_deny_and_unknown_do_not_run(fw_strands_hp: RecordingHallpass) -> None:
    h = HallpassAuthorization(fw_strands_hp, {"write_thing": WRITE, "async_write_thing": ("down", "thing.write", "thing:{thing_id}")})
    cases = [
        (DANA, "write_thing", "1", "dana@example.com may not thing.write on thing:1 in demo: deny (denied: dana@example.com is not an admin)"),
        ("eve@example.com", "write_thing", "1", "eve@example.com may not thing.write on thing:1 in demo: deny (user_not_found: "),
        (ADMIN, "write_thing", "hidden", "admin@example.com may not thing.write on thing:hidden in demo: unknown (resource_not_visible: "),
        (ADMIN, "write_thing", "broken", "admin@example.com may not thing.write on thing:broken in demo: unknown (unsupported: "),
        (ADMIN, "async_write_thing", "1", "admin@example.com may not thing.write on thing:1 in down: unknown (upstream_timeout: "),
    ]
    for user, name, thing, want in cases:
        [res] = run_agent([(name, {"thing_id": thing, "content": "hi"})], {"user_id": user}, [h], [*TOOLS, async_write_thing])
        assert res["status"] == "error", (user, thing)
        assert text(res).startswith(REFUSED + want), text(res)
    assert RAN == [], "a refused tool's body never runs"
    assert len(fw_strands_hp.seen) == len(cases)


def test_unreachable_denies() -> None:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    h = handler(Hallpass.remote(f"http://127.0.0.1:{port}", "test-key", timeout=1))
    [res] = run_agent([("write_thing", {"thing_id": "1", "content": "hi"})], {"user_id": ADMIN}, [h])
    assert res["status"] == "error"
    assert "unknown (client_error: hallpass unreachable" in text(res)
    assert RAN == []


def test_missing_user_denies(fw_strands_hp: RecordingHallpass) -> None:
    for state in ({}, {"user_id": ""}, {"user_id": [ADMIN]}, {"user": ADMIN}, {"user_id": lambda: ADMIN}):
        [res] = run_agent([("write_thing", {"thing_id": "1", "content": "hi"})], state, [handler(fw_strands_hp)])
        assert res["status"] == "error", state
        assert text(res) == REFUSED + "no user for this request: invocation_state['user_id'] is not set"
    assert fw_strands_hp.seen == [] and RAN == []


def test_user_key(fw_strands_hp: RecordingHallpass) -> None:
    [res] = run_agent([("write_thing", {"thing_id": "1", "content": "hi"})], {"email": ADMIN, "user_id": ADMIN}, [handler(fw_strands_hp, user_key="email")])
    assert res["status"] == "success"
    [res] = run_agent([("write_thing", {"thing_id": "1", "content": "hi"})], {"email": DANA, "user_id": ADMIN}, [handler(fw_strands_hp, user_key="email")])
    assert res["status"] == "error"
    assert [s["user"] for s in fw_strands_hp.seen] == [ADMIN, DANA]


def test_model_cannot_choose_the_user(fw_strands_hp: RecordingHallpass) -> None:
    props = write_thing.tool_spec["inputSchema"]["json"]["properties"]
    assert set(props) == {"thing_id", "content"}, "user must not be in the tool schema"
    call = ("write_thing", {"thing_id": "1", "content": "hi", "user": ADMIN, "user_id": ADMIN})
    [res] = run_agent([call], {"user_id": DANA}, [handler(fw_strands_hp)])
    assert res["status"] == "error"
    assert [s["user"] for s in fw_strands_hp.seen] == [DANA]
    assert RAN == []


def test_unfillable_resource_denies(fw_strands_hp: RecordingHallpass) -> None:
    for args in (
        {"content": "hi"},
        {"thing_id": {"nested": "1"}, "content": "hi"},
        {"thing_id": ["1"], "content": "hi"},
        {"thing_id": None, "content": "hi"},
        {"thing_id": 7, "content": "hi"},
        "not an object",
    ):
        [res] = run_agent([("write_thing", args)], {"user_id": ADMIN}, [handler(fw_strands_hp)])
        assert res["status"] == "error", args
        assert text(res).startswith(REFUSED + "cannot build the resource 'thing:{thing_id}' for write_thing"), text(res)
    assert fw_strands_hp.seen == [] and RAN == []


def test_resource_is_what_the_tool_gets(fw_strands_hp: RecordingHallpass) -> None:
    @tool
    def number_thing(n: int) -> str:
        """Write to a numbered thing.

        Args:
            n: the thing's number
        """
        return f"wrote thing:{n!r}"

    @tool
    def default_thing(content: str, thing_id: str = "1") -> str:
        """Write to a thing that has a default.

        Args:
            content: what to write
            thing_id: the thing
        """
        return "wrote thing:" + thing_id

    h = HallpassAuthorization(fw_strands_hp, {"number_thing": ("demo", "thing.write", "thing:{n}"), "default_thing": WRITE})
    tools = [number_thing, default_thing]
    [res] = run_agent([("number_thing", {"n": 7})], {"user_id": ADMIN}, [h], tools)
    assert (res["status"], text(res), fw_strands_hp.seen[-1]["resource"]) == ("success", "wrote thing:7", "thing:7")
    # Strands would turn each of these into 7, so the check would be for another resource.
    fw_strands_hp.seen.clear()
    for n in ("7", "07", 7.0, True, " 7"):
        [res] = run_agent([("number_thing", {"n": n})], {"user_id": ADMIN}, [h], tools)
        assert res["status"] == "error", n
        assert "'n' must be a JSON integer, not " in text(res)
    assert fw_strands_hp.seen == []
    # A parameter the model leaves out is filled from the tool's default, as the tool is.
    [res] = run_agent([("default_thing", {"content": "hi"})], {"user_id": ADMIN}, [h], tools)
    assert (res["status"], fw_strands_hp.seen[-1]["resource"]) == ("success", "thing:1")


def test_rule_types(fw_strands_hp: RecordingHallpass) -> None:
    @tool
    def tagged(tags: list[str], ref: uuid.UUID) -> str:
        """Tag things.

        Args:
            tags: labels
            ref: a reference
        """
        return "tagged"

    h = HallpassAuthorization(fw_strands_hp, {"tagged": ("demo", "thing.write", "thing:{tags}")})
    [res] = run_agent([("tagged", {"tags": ["1"], "ref": str(uuid.uuid4())})], {"user_id": ADMIN}, [h], [tagged])
    assert "does not declare 'tags' as a string or an integer" in text(res)
    # A UUID is a string in the schema, but Strands would normalise it before the tool runs.
    h = HallpassAuthorization(fw_strands_hp, {"tagged": ("demo", "thing.write", "thing:{ref}")})
    [res] = run_agent([("tagged", {"tags": [], "ref": str(uuid.uuid4()).upper()})], {"user_id": ADMIN}, [h], [tagged])
    assert "does not declare 'ref' as a string or an integer" in text(res)
    assert fw_strands_hp.seen == []


def test_rerouted_call_denies(fw_strands_hp: RecordingHallpass) -> None:
    class Reroute(InterventionHandler):
        name = "reroute"

        def before_tool_call(self, event: Any, **kw: Any) -> Transform:
            return Transform(apply=lambda e: setattr(e, "selected_tool", write_thing))

    call = ("check_permission", {"connection": "demo", "action": "thing.write", "resource": "thing:1"})
    [res] = run_agent([call], {"user_id": ADMIN, "hp": fw_strands_hp}, [Reroute(), handler(fw_strands_hp)])
    assert text(res) == REFUSED + "tool call 'check_permission' was rerouted to 'write_thing'"
    assert RAN == []


def test_warns_about_rules_for_missing_tools(fw_strands_hp: RecordingHallpass, caplog: pytest.LogCaptureFixture) -> None:
    h = HallpassAuthorization(fw_strands_hp, {"write_thing": WRITE, "wrte_thing": WRITE})
    caplog.set_level(logging.WARNING, logger="hallpass")
    run_agent([], {"user_id": ADMIN}, [h])
    warnings = [r.getMessage() for r in caplog.records if r.name == "hallpass" and r.levelno == logging.WARNING]
    assert len(warnings) == 1 and "wrte_thing" in warnings[0]
    caplog.clear()
    run_agent([], {"user_id": ADMIN}, [h])  # once per handler
    assert [r for r in caplog.records if r.name == "hallpass" and r.levelno == logging.WARNING] == []


def test_tools_without_a_rule(fw_strands_hp: RecordingHallpass) -> None:
    call = ("check_permission", {"connection": "demo", "action": "thing.write", "resource": "thing:1"})
    state = {"user_id": DANA, "hp": fw_strands_hp}
    [res] = run_agent([call], state, [handler(fw_strands_hp)])
    assert res["status"] == "success"
    assert text(res) == "deny: denied: dana@example.com is not an admin"
    assert len(fw_strands_hp.seen) == 1, "an unruled tool is not checked before it runs"
    strict = handler(fw_strands_hp, strict=True)
    [res] = run_agent([call], state, [strict])
    assert text(res) == REFUSED + "no hallpass rule for tool 'check_permission'"
    allowed = HallpassAuthorization(fw_strands_hp, {"check_permission": None}, strict=True)
    [res] = run_agent([call], state, [allowed])
    assert res["status"] == "success"
    assert RAN == ["check_permission", "check_permission"]


def test_groups_and_fresh(fw_strands_hp: RecordingHallpass) -> None:
    h = HallpassAuthorization(fw_strands_hp, {"write_thing": Rule(*WRITE, fresh=True)}, groups_key="groups")
    call = [("write_thing", {"thing_id": "1", "content": "hi"})]
    [res] = run_agent(call, {"user_id": ADMIN, "groups": ["platform-team"]}, [h])
    assert res["status"] == "success"
    assert fw_strands_hp.seen == [
        {"user": ADMIN, "connection": "demo", "action": "thing.write", "resource": "thing:1", "groups": ["platform-team"], "fresh": True}
    ]
    fw_strands_hp.seen.clear()
    for state in ({"user_id": ADMIN}, {"user_id": ADMIN, "groups": "platform-team"}, {"user_id": ADMIN, "groups": None}, {"user_id": ADMIN, "groups": [1]}):
        [res] = run_agent(call, state, [h])
        assert res["status"] == "error", state
        assert "no groups for this request" in text(res)
    assert fw_strands_hp.seen == []


def test_several_calls_at_once(fw_strands_hp: RecordingHallpass) -> None:
    h = HallpassAuthorization(fw_strands_hp, {"write_thing": WRITE})
    res = run_agent(
        [("write_thing", {"thing_id": "hidden", "content": "a"}), ("write_thing", {"thing_id": "1", "content": "bb"})],
        {"user_id": ADMIN},
        [h],
    )
    assert [r["status"] for r in res] == ["error", "success"]
    assert text(res[1]) == "wrote 2 bytes to thing:1 as " + ADMIN
    assert RAN == ["write_thing:1"]


def test_async_tool(fw_strands_hp: RecordingHallpass) -> None:
    h = HallpassAuthorization(fw_strands_hp, {"async_write_thing": WRITE})
    [ok] = run_agent([("async_write_thing", {"thing_id": "1", "content": "hi"})], {"user_id": ADMIN}, [h], [async_write_thing])
    [no] = run_agent([("async_write_thing", {"thing_id": "2", "content": "hi"})], {"user_id": DANA}, [h], [async_write_thing])
    assert (ok["status"], text(ok)) == ("success", "wrote 2 bytes to thing:1")
    assert no["status"] == "error" and text(no).startswith(REFUSED + "dana@example.com may not thing.write on thing:2")
    assert RAN == ["async_write_thing:1"]


def test_logs_unconditional_write(fw_strands_hp: RecordingHallpass, caplog: pytest.LogCaptureFixture) -> None:
    @tool
    def broken_thing(thing_id: str) -> str:
        """Fail after starting a write.

        Args:
            thing_id: the thing
        """
        raise ValueError("boom")

    h = HallpassAuthorization(fw_strands_hp, {"write_thing": WRITE, "broken_thing": WRITE})
    tools = [write_thing, broken_thing]
    caplog.set_level(logging.INFO, logger="hallpass")
    run_agent([("write_thing", {"thing_id": "1", "content": "hi"})], {"user_id": ADMIN}, [h], tools)
    [line] = writes(caplog.records)
    for part in (
        "unconditional write",
        ADMIN,
        "ran thing.write on thing:1 in demo",
        "hallpass said allow (allowed: admin@example.com is an admin)",
        "fresh=False",
        "not atomic",
    ):
        assert part in line
    caplog.clear()
    run_agent([("broken_thing", {"thing_id": "1"})], {"user_id": ADMIN}, [h], tools)
    [line] = writes(caplog.records)
    assert "raised ValueError from thing.write on thing:1" in line
    caplog.clear()
    run_agent([("write_thing", {"thing_id": "1", "content": "hi"})], {"user_id": DANA}, [h], tools)
    assert writes(caplog.records) == []


def test_composes_with_other_interventions(fw_strands_hp: RecordingHallpass, caplog: pytest.LogCaptureFixture) -> None:
    class Later(InterventionHandler):
        name = "later"

        def before_tool_call(self, event: Any, **kw: Any) -> Deny:
            return Deny(reason="blocked by a later handler")

    state: dict[str, Any] = {"user_id": ADMIN}
    caplog.set_level(logging.INFO, logger="hallpass")
    [res] = run_agent([("write_thing", {"thing_id": "1", "content": "hi"})], state, [handler(fw_strands_hp), Later()])
    assert writes(caplog.records) == []
    assert text(res) == "DENIED: blocked by a later handler"
    assert len(fw_strands_hp.seen) == 1
    assert state.get("hallpass_checks") == {}, "a cancelled call leaves no pending check"
    assert RAN == []


def test_handler_error_denies() -> None:
    class Broken(Hallpass):
        def check(self, *a: Any, **kw: Any) -> Any:
            raise RuntimeError("client blew up")

    hp = Broken(connections=[{"id": "demo", "integration": "fake", "admins": ADMIN}])
    [res] = run_agent([("write_thing", {"thing_id": "1", "content": "hi"})], {"user_id": ADMIN}, [handler(hp)])
    assert res["status"] == "error"
    assert "client blew up" in text(res)
    assert RAN == []


def test_bad_rules(fw_strands_hp: RecordingHallpass) -> None:
    for rules in ({"t": ("demo", "thing.write")}, {"t": ("demo", "", "thing:{x}")}, {"t": "demo"}, {"t": ["demo", "thing.write", "thing:{x}"]}):
        with pytest.raises(TypeError):
            HallpassAuthorization(fw_strands_hp, rules)  # type: ignore[arg-type]
    for template in ("thing:{x.y}", "thing:{x[0]}", "thing:{}", "thing:{0}", "thing:{x!r}", "thing:{x:>5}"):
        with pytest.raises(ValueError):
            HallpassAuthorization(fw_strands_hp, {"t": ("demo", "thing.write", template)})
    with pytest.raises(TypeError):
        HallpassAuthorization(object(), {})  # type: ignore[arg-type]


def test_direct_hook_call(fw_strands_hp: RecordingHallpass) -> None:
    """The handler's hook on its own, the way the hallpass-client test called it."""
    from types import SimpleNamespace

    h = handler(fw_strands_hp)

    def decide(user: str) -> Any:
        spec = {"inputSchema": {"json": {"properties": {"thing_id": {"type": "string"}}}}}
        event = SimpleNamespace(
            tool_use={"toolUseId": "t1", "name": "write_thing", "input": {"thing_id": "1"}},
            selected_tool=SimpleNamespace(tool_name="write_thing", tool_spec=spec),
            invocation_state={"user_id": user},
        )
        return asyncio.run(h.before_tool_call(event))  # type: ignore[arg-type]

    assert isinstance(decide(ADMIN), Proceed)
    assert isinstance(decide(DANA), Deny)


def test_guarded_under_strands_tool(fw_strands_hp: RecordingHallpass) -> None:
    """guarded on the plain function, under Strands' @tool, with the user in a ContextVar."""
    current_user: ContextVar[str] = ContextVar("fw_strands_user")

    @tool
    @guarded(fw_strands_hp, *WRITE, user=current_user, deny=lambda e: f"refused: {e}")
    def guarded_write(thing_id: str, content: str) -> str:
        """Write content to a thing.

        Args:
            thing_id: the thing to write to
            content: what to write
        """
        RAN.append("guarded_write:" + thing_id)
        return f"wrote {len(content)} bytes to thing:{thing_id}"

    assert set(guarded_write.tool_spec["inputSchema"]["json"]["properties"]) == {"thing_id", "content"}
    current_user.set(ADMIN)
    [res] = run_agent([("guarded_write", {"thing_id": "1", "content": "hi", "user": DANA})], {}, [], [guarded_write])
    assert (res["status"], text(res)) == ("success", "wrote 2 bytes to thing:1")
    current_user.set(DANA)
    [res] = run_agent([("guarded_write", {"thing_id": "2", "content": "hi", "user": ADMIN})], {}, [], [guarded_write])
    assert text(res).startswith("refused: dana@example.com may not thing.write on thing:2")
    assert RAN == ["guarded_write:1"]
    assert [s["user"] for s in fw_strands_hp.seen] == [ADMIN, DANA]


# -- a real upstream -------------------------------------------------------------


@pytest.fixture
def fw_strands_pagerduty() -> Iterator[harness.Server]:
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


def test_real_upstream(fw_strands_pagerduty: harness.Server) -> None:
    srv = fw_strands_pagerduty
    hp = recording(
        [{"id": "pd", "integration": "pagerduty", "url": srv.url, "credential": literal(harness.CANARY + "pd"), "ca_file": harness.test_ca().ca_file}]
    )

    @tool
    def set_maintenance(service: str) -> str:
        """Put a PagerDuty service into maintenance.

        Args:
            service: the service id
        """
        RAN.append("set_maintenance:" + service)
        return "maintenance window created on " + service

    h = HallpassAuthorization(hp, {"set_maintenance": ("pd", "service.maintenance", "service:{service}")})
    [ok] = run_agent([("set_maintenance", {"service": "PSVC1"})], {"user_id": "oncall@example.com"}, [h], [set_maintenance])
    [no] = run_agent([("set_maintenance", {"service": "PSVC1"})], {"user_id": "stake@example.com"}, [h], [set_maintenance])
    assert (ok["status"], text(ok)) == ("success", "maintenance window created on PSVC1")
    assert no["status"] == "error"
    assert text(no).startswith(REFUSED + "stake@example.com may not service.maintenance on service:PSVC1 in pd: deny (denied: ")
    assert RAN == ["set_maintenance:PSVC1"]
    assert [c.q("query") for c in srv.calls() if c.path == "/users"] == ["oncall@example.com", "stake@example.com"]


VAULT_IMAGE = "hashicorp/vault:1.17"


@pytest.fixture(scope="module")
def fw_strands_vault() -> Iterator[str]:
    """A real HashiCorp Vault dev server in docker. The entity of admin@example.com
    (an alias on userpass/) has a policy that may write secret/app/*; dana@example.com's has none."""
    if shutil.which("docker") is None:
        pytest.skip("needs docker")
    if subprocess.run(["docker", "image", "inspect", VAULT_IMAGE], capture_output=True, check=False).returncode != 0:
        pytest.skip(f"needs the docker image {VAULT_IMAGE}")
    run = [
        "docker",
        "run",
        "-d",
        "--rm",
        "--cap-add=IPC_LOCK",
        "-e",
        "VAULT_DEV_ROOT_TOKEN_ID=" + harness.CANARY + "root",
        "-p",
        "127.0.0.1::8200",
        VAULT_IMAGE,
    ]
    cid = subprocess.run(run, check=True, capture_output=True, text=True).stdout.strip()
    try:
        port = subprocess.run(["docker", "port", cid, "8200/tcp"], check=True, capture_output=True, text=True).stdout.split(":")[-1].strip()
        base = f"http://127.0.0.1:{port}"

        def api(method: str, path: str, body: Any = None) -> Any:
            data = None if body is None else json.dumps(body).encode()
            req = urllib.request.Request(base + "/v1/" + path, method=method, data=data, headers={"X-Vault-Token": harness.CANARY + "root"})
            with urllib.request.urlopen(req, timeout=5) as r:
                raw = r.read()
                return json.loads(raw) if raw else None

        deadline = time.monotonic() + 30
        while True:
            try:
                api("GET", "sys/health")
                break
            except (OSError, ValueError):
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.1)
        api("POST", "sys/auth/userpass", {"type": "userpass"})
        accessor = api("GET", "sys/auth")["data"]["userpass/"]["accessor"]
        api("PUT", "sys/policies/acl/app-writer", {"policy": 'path "secret/data/app/*" { capabilities = ["create", "update", "read"] }'})
        for name, email, policies in (("admin", ADMIN, ["app-writer"]), ("dana", DANA, [])):
            entity = api("POST", "identity/entity", {"name": name, "policies": policies})["data"]["id"]
            api("POST", "identity/entity-alias", {"name": email, "canonical_id": entity, "mount_accessor": accessor})
        yield base
    finally:
        subprocess.run(["docker", "rm", "-f", cid], capture_output=True, check=False)


def vault_hallpass(base: str) -> RecordingHallpass:
    return recording([{"id": "vault", "integration": "vault", "url": base, "credential": literal(harness.CANARY + "root"), "alias_mount": "userpass/"}])


def test_real_vault(fw_strands_vault: str) -> None:
    hp = vault_hallpass(fw_strands_vault)

    @tool
    def write_secret(path: str, value: str) -> str:
        """Write a secret under secret/.

        Args:
            path: the key path, e.g. app/db
            value: the value
        """
        RAN.append("write_secret:" + path)
        return "wrote secret/" + path

    h = HallpassAuthorization(hp, {"write_secret": ("vault", "secret.write", "kv:secret/{path}")})
    results = [
        run_agent([("write_secret", {"path": path, "value": "x", "user_id": ADMIN})], {"user_id": user}, [h], [write_secret])[0]
        for user, path in ((ADMIN, "app/db"), (DANA, "app/db"), (ADMIN, "other/db"))
    ]
    assert [r["status"] for r in results] == ["success", "error", "error"]
    assert text(results[1]).startswith(REFUSED + "dana@example.com may not secret.write on kv:secret/app/db in vault: deny (denied: ")
    assert text(results[2]).startswith(REFUSED + "admin@example.com may not secret.write on kv:secret/other/db in vault: deny (denied: ")
    assert RAN == ["write_secret:app/db"]
    assert [s["user"] for s in hp.seen] == [ADMIN, DANA, ADMIN]


# -- a real model ------------------------------------------------------------------


@pytest.mark.live
@pytest.mark.skipif(not os.environ.get("ANTHROPIC_API_KEY"), reason="needs ANTHROPIC_API_KEY")
def test_live_claude(fw_strands_hp: RecordingHallpass) -> None:
    pytest.importorskip("anthropic")
    from strands.models.anthropic import AnthropicModel

    model_id = os.environ.get("HALLPASS_LIVE_MODEL", "claude-haiku-4-5")
    prompt = (
        "Use the write_thing tool to write 'hello' to thing 1. The tool may refuse; if it does, stop and "
        "report the refusal. Act as admin@example.com (user_id admin@example.com)."
    )
    for user in (DANA, ADMIN):
        agent = Agent(
            model=AnthropicModel(model_id=model_id, max_tokens=1024),
            tools=TOOLS,
            interventions=[handler(fw_strands_hp)],
            callback_handler=None,
        )
        agent(prompt, invocation_state={"user_id": user})
    assert fw_strands_hp.seen, "the model never called the tool"
    assert {s["user"] for s in fw_strands_hp.seen} == {DANA, ADMIN}
    assert all(s["resource"] == "thing:1" for s in fw_strands_hp.seen)
    # Dana's calls were refused before the body ran; the admin's ran.
    assert set(RAN) == {"write_thing:1"}
    assert len(RAN) == sum(1 for s in fw_strands_hp.seen if s["user"] == ADMIN)
