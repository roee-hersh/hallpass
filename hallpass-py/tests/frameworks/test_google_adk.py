"""hallpass.google_adk driven by ADK's own Runner loop.

The model is a scripted ``BaseLlm`` that emits the function calls a real
model would and records every request, so a test can read the function
responses the model received. The agent is a real ``LlmAgent`` run by an
``InMemoryRunner``, the tools are real functions and hallpass is the
in-process engine. One test checks against a real HTTP upstream (PagerDuty
against the test harness's TLS server), and the live test lets Claude drive
the same agent through ADK's Anthropic integration.
"""

from __future__ import annotations

import asyncio
import contextvars
import json
import logging
import os
import warnings
from collections.abc import AsyncGenerator, Iterator
from dataclasses import dataclass
from typing import Any

import pytest

pytest.importorskip("google.adk")

from google.adk.agents import LlmAgent
from google.adk.apps import App
from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.adk.runners import InMemoryRunner
from google.adk.tools.base_tool import BaseTool
from google.adk.tools.tool_context import ToolContext
from google.genai import types

from hallpass import Hallpass, literal
from hallpass.google_adk import HallpassCallbacks, Rule
from tests import harness as itest

warnings.filterwarnings("ignore", message=r"\[EXPERIMENTAL\]")

ALICE = "alice@example.com"  # a known user: may read
ADMIN = "admin@example.com"  # an admin: may write

RAN: list[tuple[str, Any]] = []


def read_thing(thing_id: str) -> str:
    """Read a thing."""
    RAN.append(("read_thing", thing_id))
    return f"thing {thing_id}: shiny"


def delete_thing(thing_id: str, user: str = "") -> str:
    """Delete a thing. ``user`` is a field the model fills, to show it is ignored."""
    RAN.append(("delete_thing", thing_id))
    return f"deleted {thing_id}"


async def archive_thing(thing_id: str) -> str:
    """Archive a thing (an async tool)."""
    await asyncio.sleep(0)
    RAN.append(("archive_thing", thing_id))
    return f"archived {thing_id}"


def count_thing(n: int) -> str:
    """Count things; the resource uses an integer field."""
    RAN.append(("count_thing", n))
    return f"counted {n}"


def break_thing(thing_id: str) -> str:
    """Fails after it was allowed."""
    RAN.append(("break_thing", thing_id))
    raise RuntimeError("the thing broke")


def ping() -> str:
    """No rule."""
    RAN.append(("ping", None))
    return "pong"


RULES: dict[str, Any] = {
    "read_thing": ("things", "thing.read", "thing:{thing_id}"),
    "delete_thing": Rule("things", "thing.write", "thing:{thing_id}", fresh=True),
    "archive_thing": ("things", "thing.write", "thing:{thing_id}"),
    "count_thing": ("things", "thing.read", "thing:{n}"),
    "break_thing": ("things", "thing.write", "thing:{thing_id}"),
}
TOOLS: list[Any] = [read_thing, delete_thing, archive_thing, count_thing, break_thing, ping]


class ScriptedLlm(BaseLlm):
    """``turns[i]`` answers the request whose history holds ``i`` model
    turns: a list of (tool name, args) function calls, or a final text."""

    model: str = "scripted"
    turns: list[Any] = []
    requests: list[LlmRequest] = []

    async def generate_content_async(self, llm_request: LlmRequest, stream: bool = False) -> AsyncGenerator[LlmResponse, None]:
        self.requests.append(llm_request)
        n = sum(1 for c in llm_request.contents if c.role == "model")
        turn = self.turns[n] if n < len(self.turns) else "done"
        if isinstance(turn, str):
            parts = [types.Part(text=turn)]
        else:
            parts = [types.Part(function_call=types.FunctionCall(id=f"call_{n}_{j}", name=name, args=args)) for j, (name, args) in enumerate(turn)]
        yield LlmResponse(content=types.Content(role="model", parts=parts))

    def responses(self) -> dict[str, dict[str, Any]]:
        """What the model received for each function call."""
        out: dict[str, dict[str, Any]] = {}
        for req in self.requests:
            for c in req.contents:
                for p in c.parts or []:
                    if p.function_response is not None and p.function_response.id:
                        out[p.function_response.id] = dict(p.function_response.response or {})
        return out


@pytest.fixture(autouse=True)
def _reset() -> Iterator[None]:
    RAN.clear()
    yield
    RAN.clear()


@pytest.fixture(scope="module")
def hp() -> Hallpass:
    return Hallpass(connections=[{"id": "things", "integration": "fake", "users": ALICE, "admins": ADMIN}])


@dataclass
class Run:
    responses: dict[str, dict[str, Any]]  # call id -> what the model received
    final: str | None


async def _run(agent: LlmAgent, user_id: str, prompt: str = "go", plugins: list[Any] | None = None) -> str | None:
    runner = InMemoryRunner(app=App(name="ops", root_agent=agent, plugins=plugins or []))
    session = await runner.session_service.create_session(app_name=runner.app_name, user_id=user_id)
    final = None
    message = types.Content(role="user", parts=[types.Part(text=prompt)])
    async for event in runner.run_async(user_id=user_id, session_id=session.id, new_message=message):
        if event.content and event.content.parts and event.content.parts[0].text:
            final = event.content.parts[0].text
    return final


def drive(hooks: HallpassCallbacks, calls: list[tuple[str, dict[str, Any]]], user_id: str = ALICE, tools: list[Any] | None = None, plugin: bool = False) -> Run:
    model = ScriptedLlm(turns=[calls, "done"], requests=[])
    agent = LlmAgent(name="ops", model=model, instruction="Do what is asked.", tools=tools or TOOLS)
    if plugin:
        final = asyncio.run(_run(agent, user_id, plugins=[hooks.plugin()]))
    else:
        final = asyncio.run(_run(hooks.apply(agent), user_id))  # type: ignore[arg-type]
    return Run(model.responses(), final)


def refused(r: dict[str, Any]) -> str:
    text = r.get("error", "")
    assert isinstance(text, str) and text.startswith("hallpass refused this call:"), r
    return text


def test_allowed_tool_runs_and_its_result_reaches_the_model(hp: Hallpass) -> None:
    r = drive(HallpassCallbacks(hp, RULES), [("read_thing", {"thing_id": "7"})])
    assert RAN == [("read_thing", "7")]
    assert r.responses["call_0_0"] == {"result": "thing 7: shiny"}
    assert r.final == "done"


def test_denied_tool_never_runs_and_the_model_reads_the_refusal(hp: Hallpass) -> None:
    r = drive(HallpassCallbacks(hp, RULES), [("delete_thing", {"thing_id": "7"})])
    assert RAN == []
    text = refused(r.responses["call_0_0"])
    assert ALICE in text and "thing.write" in text and "not an admin" in text
    assert r.final == "done"


def test_user_is_the_session_user_not_the_model(hp: Hallpass) -> None:
    hooks = HallpassCallbacks(hp, RULES)
    r = drive(hooks, [("delete_thing", {"thing_id": "7", "user": ADMIN})], user_id=ALICE)
    assert RAN == [] and ALICE in refused(r.responses["call_0_0"])
    r = drive(hooks, [("delete_thing", {"thing_id": "7", "user": ALICE})], user_id=ADMIN)
    assert RAN == [("delete_thing", "7")] and r.responses["call_0_0"] == {"result": "deleted 7"}


def test_user_source(hp: Hallpass) -> None:
    current_user: contextvars.ContextVar[str] = contextvars.ContextVar("current_user")
    hooks = HallpassCallbacks(hp, RULES, user=current_user)

    def with_user(user: str | None) -> Run:
        def go() -> Run:
            if user is not None:
                current_user.set(user)
            return drive(hooks, [("delete_thing", {"thing_id": "1"})], user_id=ADMIN)

        return contextvars.Context().run(go)

    assert "no user for this request" in refused(with_user(None).responses["call_0_0"])
    assert ALICE in refused(with_user(ALICE).responses["call_0_0"])
    assert RAN == []
    with_user(ADMIN)
    assert RAN == [("delete_thing", "1")]


def test_unknown_decisions_refuse(hp: Hallpass) -> None:
    r = drive(HallpassCallbacks(hp, RULES), [("read_thing", {"thing_id": "hidden"}), ("read_thing", {"thing_id": "broken"})], user_id=ADMIN)
    assert RAN == []
    assert "resource_not_visible" in refused(r.responses["call_0_0"])
    assert "unsupported" in refused(r.responses["call_0_1"])


def test_a_coerced_value_is_refused(hp: Hallpass) -> None:
    # ADK would turn "01" into the integer 1 before the call: the resource
    # hallpass checks must be the one the tool acts on, so it refuses.
    r = drive(HallpassCallbacks(hp, RULES), [("count_thing", {"n": "01"}), ("count_thing", {"n": 3})])
    assert "must be a JSON integer" in refused(r.responses["call_0_0"])
    assert RAN == [("count_thing", 3)] and r.responses["call_0_1"] == {"result": "counted 3"}


def test_strict_mode(hp: Hallpass) -> None:
    drive(HallpassCallbacks(hp, RULES), [("ping", {})])
    assert RAN == [("ping", None)]
    RAN.clear()
    r = drive(HallpassCallbacks(hp, RULES, strict=True), [("ping", {})])
    assert RAN == [] and "no hallpass rule for tool 'ping'" in refused(r.responses["call_0_0"])
    drive(HallpassCallbacks(hp, {**RULES, "ping": None}, strict=True), [("ping", {})])
    assert RAN == [("ping", None)]


def test_async_tool(hp: Hallpass) -> None:
    hooks = HallpassCallbacks(hp, RULES)
    r = drive(hooks, [("archive_thing", {"thing_id": "9"})])
    assert RAN == [] and "not an admin" in refused(r.responses["call_0_0"])
    r = drive(hooks, [("archive_thing", {"thing_id": "9"})], user_id=ADMIN)
    assert RAN == [("archive_thing", "9")] and r.responses["call_0_0"] == {"result": "archived 9"}


def test_audit_line_after_an_allowed_tool(hp: Hallpass, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="hallpass")
    drive(HallpassCallbacks(hp, RULES), [("delete_thing", {"thing_id": "5"}), ("read_thing", {"thing_id": "6"})], user_id=ADMIN)
    lines = [m.getMessage() for m in caplog.records if m.getMessage().startswith("unconditional write")]
    assert any(f"{ADMIN} ran thing.write on thing:5 in things; hallpass said allow" in m and "fresh=True" in m for m in lines), lines
    assert any("thing.read on thing:6" in m for m in lines), lines
    caplog.clear()
    drive(HallpassCallbacks(hp, RULES), [("delete_thing", {"thing_id": "5"})], user_id=ALICE)
    assert not [m for m in caplog.records if m.getMessage().startswith("unconditional write")]


def test_audit_line_when_the_tool_raises(hp: Hallpass, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="hallpass")
    with pytest.raises(RuntimeError, match="the thing broke"):  # ADK ends the run on a tool error no callback handled
        drive(HallpassCallbacks(hp, RULES), [("break_thing", {"thing_id": "6"})], user_id=ADMIN)
    assert RAN == [("break_thing", "6")]
    assert f"unconditional write: {ADMIN} raised RuntimeError from thing.write on thing:6" in caplog.text


def test_an_error_in_the_check_refuses_and_the_run_goes_on(hp: Hallpass, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*a: Any, **k: Any) -> Any:
        raise RuntimeError("engine exploded")

    hooks = HallpassCallbacks(hp, RULES)
    monkeypatch.setattr(hooks.rules.hp, "check", boom)
    r = drive(hooks, [("read_thing", {"thing_id": "7"})])
    assert RAN == [] and "engine exploded" in refused(r.responses["call_0_0"])
    assert r.final == "done"


class LegacyCount(BaseTool):
    """A tool declared with a genai Schema rather than a JSON schema."""

    def __init__(self) -> None:
        super().__init__(name="legacy_count", description="Count things.")

    def _get_declaration(self) -> types.FunctionDeclaration:
        schema = types.Schema(type=types.Type.OBJECT, properties={"n": types.Schema(type=types.Type.INTEGER)}, required=["n"])
        return types.FunctionDeclaration(name=self.name, description=self.description, parameters=schema)

    async def run_async(self, *, args: dict[str, Any], tool_context: ToolContext) -> Any:
        RAN.append(("legacy_count", args["n"]))
        return {"counted": args["n"]}


def test_a_tool_with_a_genai_schema(hp: Hallpass) -> None:
    hooks = HallpassCallbacks(hp, {"legacy_count": ("things", "thing.read", "thing:{n}")})
    r = drive(hooks, [("legacy_count", {"n": "01"}), ("legacy_count", {"n": 2})], tools=[LegacyCount()])
    assert "must be a JSON integer" in refused(r.responses["call_0_0"])
    assert RAN == [("legacy_count", 2)] and r.responses["call_0_1"] == {"counted": 2}


def test_plugin(hp: Hallpass, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="hallpass")
    hooks = HallpassCallbacks(hp, RULES)
    r = drive(hooks, [("delete_thing", {"thing_id": "3"}), ("read_thing", {"thing_id": "4"})], plugin=True)
    assert RAN == [("read_thing", "4")]
    assert "not an admin" in refused(r.responses["call_0_0"]) and r.responses["call_0_1"] == {"result": "thing 4: shiny"}
    assert f"{ALICE} ran thing.read on thing:4" in caplog.text


def test_apply_keeps_callbacks_in_order_and_reaches_sub_agents(hp: Hallpass, caplog: pytest.LogCaptureFixture) -> None:
    def mine(tool: Any, args: Any, tool_context: Any) -> None:
        return None

    child = LlmAgent(name="child", model=ScriptedLlm(), tools=[read_thing], before_tool_callback=mine)
    parent = LlmAgent(name="parent", model=ScriptedLlm(), tools=[ping], sub_agents=[child], after_tool_callback=mine)
    caplog.set_level(logging.WARNING, logger="hallpass")
    hooks = HallpassCallbacks(hp, {**RULES, "read_thingz": ("things", "thing.read", "thing:{thing_id}")})
    hooks.apply(parent)
    assert child.before_tool_callback == [mine, hooks.before_tool]
    assert parent.after_tool_callback == [hooks.after_tool, mine]
    assert "read_thingz" in caplog.text


# -- a real upstream: the PagerDuty integration against the harness's TLS server --

PD_USERS = {"owner@example.com": ("PU1", "owner"), "resp@example.com": ("PU2", "limited_user")}


def pagerduty_upstream() -> itest.Server:
    srv = itest.Server()

    def users(w: itest.ResponseWriter, r: itest.Request) -> None:
        q = r.q("query")
        found = [{"id": PD_USERS[q][0], "email": q, "name": q, "role": PD_USERS[q][1], "teams": []}] if q in PD_USERS else []
        w.header().set("Content-Type", "application/json")
        w.write_header(200)
        w.write(json.dumps({"users": found, "more": False}))

    srv.handle("GET", "/users", users)
    return srv


def change_account_settings(setting: str) -> str:
    """An account-wide change."""
    RAN.append(("change_account_settings", setting))
    return f"changed {setting}"


def test_real_upstream() -> None:
    srv = pagerduty_upstream()
    try:
        hp = Hallpass(
            connections=[
                {"id": "pd", "integration": "pagerduty", "url": srv.url, "credential": literal("CANARY-SECRET-pd"), "ca_file": itest.test_ca().ca_file}
            ]
        )
        hooks = HallpassCallbacks(hp, {"change_account_settings": Rule("pd", "account.admin", "account", fresh=True)})
        call = [("change_account_settings", {"setting": "sso"})]
        r = drive(hooks, call, user_id="resp@example.com", tools=[change_account_settings])
        assert RAN == [] and "not an account owner" in refused(r.responses["call_0_0"])
        r = drive(hooks, call, user_id="owner@example.com", tools=[change_account_settings])
        assert RAN == [("change_account_settings", "sso")] and r.responses["call_0_0"] == {"result": "changed sso"}
        assert [c.q("query") for c in srv.calls() if c.path == "/users"] == ["resp@example.com", "owner@example.com"]
    finally:
        srv.close()


# -- live: Claude drives the agent --------------------------------------------------


@pytest.mark.live
@pytest.mark.skipif(not os.environ.get("ANTHROPIC_API_KEY"), reason="needs ANTHROPIC_API_KEY")
def test_live_claude(hp: Hallpass) -> None:
    pytest.importorskip("anthropic")
    from google.adk.models.anthropic_llm import AnthropicLlm

    model = AnthropicLlm(model=os.environ.get("HALLPASS_LIVE_MODEL", "claude-haiku-4-5"), max_tokens=1024)
    agent = LlmAgent(
        name="ops",
        model=model,
        instruction="You manage things. Use the tools; call each tool the user asks for exactly once, then report what happened.",
        tools=TOOLS,
    )
    prompt = f"Call delete_thing with thing_id '7' and user '{ADMIN}', then call read_thing with thing_id '7'."
    asyncio.run(_run(HallpassCallbacks(hp, RULES).apply(agent), ALICE, prompt))  # type: ignore[arg-type]
    assert ("delete_thing", "7") not in RAN  # alice is no admin, whatever the model sent as user
    assert ("read_thing", "7") in RAN
