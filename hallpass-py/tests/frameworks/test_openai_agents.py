"""hallpass.openai_agents driven by the Agents SDK's own Runner loop.

The model is the SDK's ScriptedModel (agents.testing), which emits the tool
calls a real model would; the tools are real function tools and hallpass is
the in-process engine. One test checks against a real HTTP upstream (the
PagerDuty integration talking to the test harness's TLS server), and the
live test lets Claude drive the same agent.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

import pytest

pytest.importorskip("agents")

from agents import Agent, FunctionTool, Runner, WebSearchTool, function_tool, set_tracing_disabled
from agents.testing import ScriptedModel, assistant_message, function_call

from hallpass import Hallpass, literal
from hallpass.openai_agents import HallpassGuardrails, Rule
from tests import harness as itest

set_tracing_disabled(True)

ALICE = "alice@example.com"  # a known user: may read
ADMIN = "admin@example.com"  # an admin: may write

RAN: list[tuple[str, Any]] = []


@function_tool
def read_thing(thing_id: str) -> str:
    """Read a thing."""
    RAN.append(("read_thing", thing_id))
    return f"thing {thing_id}: shiny"


@function_tool
def delete_thing(thing_id: str, user: str) -> str:
    """Delete a thing. ``user`` is a field the model fills, to show it is ignored."""
    RAN.append(("delete_thing", thing_id))
    return f"deleted {thing_id}"


@function_tool
async def archive_thing(thing_id: str) -> str:
    """Archive a thing (an async tool)."""
    await asyncio.sleep(0)
    RAN.append(("archive_thing", thing_id))
    return f"archived {thing_id}"


@function_tool
def count_thing(n: int) -> str:
    """Count things; the resource uses an integer field."""
    RAN.append(("count_thing", n))
    return f"counted {n}"


@function_tool
def ping() -> str:
    """No rule."""
    RAN.append(("ping", None))
    return "pong"


RULES: dict[str, Any] = {
    "read_thing": ("things", "thing.read", "thing:{thing_id}"),
    "delete_thing": Rule("things", "thing.write", "thing:{thing_id}", fresh=True),
    "archive_thing": ("things", "thing.write", "thing:{thing_id}"),
    "count_thing": ("things", "thing.read", "thing:{n}"),
}
TOOLS: list[Any] = [read_thing, delete_thing, archive_thing, count_thing, ping]


@dataclass
class Ctx:
    """The application's run context: who the request is for."""

    user_id: str | None
    groups: list[str] = field(default_factory=list)


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
    outputs: dict[str, str]  # call id -> what the model received
    final: Any
    model: ScriptedModel


def drive(guard: HallpassGuardrails, calls: list[tuple[str, Any]], context: Any, tools: list[Any] | None = None) -> Run:
    """One Runner.run: the model asks for ``calls`` at once, then answers."""
    model = ScriptedModel(
        [
            [function_call(name, args, call_id=f"call_{i}") for i, (name, args) in enumerate(calls)],
            [assistant_message("done")],
        ]
    )
    agent = guard.apply(Agent(name="ops", instructions="Do what is asked.", model=model, tools=tools or TOOLS))
    result = asyncio.run(Runner.run(agent, "go", context=context))
    model.assert_complete()
    outputs = {}
    for item in model.calls[1].input:
        if isinstance(item, dict) and item.get("type") == "function_call_output":
            out = item["output"]
            outputs[item["call_id"]] = out if isinstance(out, str) else json.dumps(out)
    return Run(outputs, result.final_output, model)


def test_allowed_tool_runs_and_its_result_reaches_the_model(hp: Hallpass) -> None:
    r = drive(HallpassGuardrails(hp, RULES), [("read_thing", {"thing_id": "7"})], Ctx(ALICE))
    assert RAN == [("read_thing", "7")]
    assert r.outputs["call_0"] == "thing 7: shiny"
    assert r.final == "done"


def test_denied_tool_never_runs_and_the_model_reads_the_refusal(hp: Hallpass) -> None:
    r = drive(HallpassGuardrails(hp, RULES), [("delete_thing", {"thing_id": "7", "user": ALICE})], Ctx(ALICE))
    assert RAN == []
    out = r.outputs["call_0"]
    assert out.startswith("hallpass refused this call:"), out
    assert ALICE in out and "thing.write" in out and "not an admin" in out
    assert r.final == "done"  # the run went on


def test_user_comes_from_the_run_context_not_the_model(hp: Hallpass) -> None:
    guard = HallpassGuardrails(hp, RULES)
    r = drive(guard, [("delete_thing", {"thing_id": "7", "user": ADMIN})], Ctx(ALICE))
    assert RAN == [] and "hallpass refused" in r.outputs["call_0"] and ALICE in r.outputs["call_0"]
    r = drive(guard, [("delete_thing", {"thing_id": "7", "user": ALICE})], Ctx(ADMIN))
    assert RAN == [("delete_thing", "7")] and r.outputs["call_0"] == "deleted 7"


def test_mapping_context_and_user_source(hp: Hallpass) -> None:
    drive(HallpassGuardrails(hp, RULES), [("delete_thing", {"thing_id": "1", "user": ""})], {"user_id": ADMIN})
    assert RAN == [("delete_thing", "1")]
    RAN.clear()
    r = drive(HallpassGuardrails(hp, RULES, user=lambda: ALICE), [("delete_thing", {"thing_id": "1", "user": ""})], Ctx(ADMIN))
    assert RAN == [] and ALICE in r.outputs["call_0"]


def test_no_user_refuses(hp: Hallpass) -> None:
    r = drive(HallpassGuardrails(hp, RULES), [("read_thing", {"thing_id": "7"})], Ctx(None))
    assert RAN == [] and "no user for this request" in r.outputs["call_0"]
    r = drive(HallpassGuardrails(hp, RULES), [("read_thing", {"thing_id": "7"})], None)
    assert RAN == [] and "no user for this request" in r.outputs["call_0"]


def test_groups_from_the_context(hp: Hallpass) -> None:
    guard = HallpassGuardrails(hp, RULES, groups_key="groups")
    drive(guard, [("read_thing", {"thing_id": "7"})], Ctx(ALICE, ["eng"]))
    assert RAN == [("read_thing", "7")]
    RAN.clear()
    r = drive(guard, [("read_thing", {"thing_id": "7"})], {"user_id": ALICE})
    assert RAN == [] and "no groups" in r.outputs["call_0"]


def test_unknown_decisions_refuse(hp: Hallpass) -> None:
    r = drive(HallpassGuardrails(hp, RULES), [("read_thing", {"thing_id": "hidden"}), ("read_thing", {"thing_id": "broken"})], Ctx(ADMIN))
    assert RAN == []
    assert "resource_not_visible" in r.outputs["call_0"]
    assert "unsupported" in r.outputs["call_1"]


def test_a_coerced_value_is_refused(hp: Hallpass) -> None:
    # The SDK's validation would turn "01" into the integer 1: the resource
    # hallpass checks must be the one the tool acts on, so it refuses.
    r = drive(HallpassGuardrails(hp, RULES), [("count_thing", {"n": "01"}), ("count_thing", {"n": 3})], Ctx(ALICE))
    assert "must be a JSON integer" in r.outputs["call_0"]
    assert RAN == [("count_thing", 3)] and r.outputs["call_1"] == "counted 3"


def test_strict_mode(hp: Hallpass) -> None:
    drive(HallpassGuardrails(hp, RULES), [("ping", {})], Ctx(ALICE))
    assert RAN == [("ping", None)]
    RAN.clear()
    r = drive(HallpassGuardrails(hp, RULES, strict=True), [("ping", {})], Ctx(ALICE))
    assert RAN == [] and "no hallpass rule for tool 'ping'" in r.outputs["call_0"]
    drive(HallpassGuardrails(hp, {**RULES, "ping": None}, strict=True), [("ping", {})], Ctx(None))
    assert RAN == [("ping", None)]


def test_async_tool(hp: Hallpass) -> None:
    guard = HallpassGuardrails(hp, RULES)
    r = drive(guard, [("archive_thing", {"thing_id": "9"})], Ctx(ALICE))
    assert RAN == [] and "not an admin" in r.outputs["call_0"]
    r = drive(guard, [("archive_thing", {"thing_id": "9"})], Ctx(ADMIN))
    assert RAN == [("archive_thing", "9")] and r.outputs["call_0"] == "archived 9"


def test_audit_line_after_an_allowed_tool(hp: Hallpass, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="hallpass")
    drive(HallpassGuardrails(hp, RULES), [("delete_thing", {"thing_id": "5", "user": ""}), ("read_thing", {"thing_id": "6"})], Ctx(ADMIN))
    lines = [r.getMessage() for r in caplog.records if r.getMessage().startswith("unconditional write")]
    assert any(f"{ADMIN} ran thing.write on thing:5 in things; hallpass said allow" in m and "fresh=True" in m for m in lines), lines
    assert any("thing.read on thing:6" in m for m in lines), lines
    caplog.clear()
    drive(HallpassGuardrails(hp, RULES), [("delete_thing", {"thing_id": "5", "user": ""})], Ctx(ALICE))
    assert not [r for r in caplog.records if r.getMessage().startswith("unconditional write")]


def test_an_error_in_the_check_refuses_and_the_run_goes_on(hp: Hallpass, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*a: Any, **k: Any) -> Any:
        raise RuntimeError("engine exploded")

    guard = HallpassGuardrails(hp, RULES)
    monkeypatch.setattr(guard.rules.hp, "check", boom)
    r = drive(guard, [("read_thing", {"thing_id": "7"})], Ctx(ALICE))
    assert RAN == [] and "hallpass refused this call" in r.outputs["call_0"] and "engine exploded" in r.outputs["call_0"]
    assert r.final == "done"


def test_existing_guardrails_are_kept_and_the_original_tool_is_untouched(hp: Hallpass) -> None:
    guard = HallpassGuardrails(hp, RULES)
    (protected,) = guard.protect([read_thing])
    assert isinstance(protected, FunctionTool) and protected is not read_thing
    assert [g.get_name() for g in protected.tool_input_guardrails or []] == ["hallpass"]
    assert not read_thing.tool_input_guardrails


def test_tools_hallpass_cannot_check(hp: Hallpass, caplog: pytest.LogCaptureFixture) -> None:
    with pytest.raises(TypeError, match="only function tools"):
        HallpassGuardrails(hp, {"web_search": ("things", "thing.read", "thing:x")}).protect([WebSearchTool()])
    with pytest.raises(ValueError, match="strict"):
        HallpassGuardrails(hp, {}, strict=True).protect([WebSearchTool()])
    assert len(HallpassGuardrails(hp, {"web_search": None}, strict=True).protect([WebSearchTool()])) == 1
    caplog.set_level(logging.WARNING, logger="hallpass")
    HallpassGuardrails(hp, {"read_thingz": ("things", "thing.read", "thing:{thing_id}")}).apply(Agent(name="a", tools=[read_thing]))
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


@function_tool
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
        guard = HallpassGuardrails(hp, {"change_account_settings": Rule("pd", "account.admin", "account", fresh=True)})
        call = [("change_account_settings", {"setting": "sso"})]
        r = drive(guard, call, Ctx("resp@example.com"), tools=[change_account_settings])
        assert RAN == [] and "not an account owner" in r.outputs["call_0"]
        r = drive(guard, call, Ctx("owner@example.com"), tools=[change_account_settings])
        assert RAN == [("change_account_settings", "sso")] and r.outputs["call_0"] == "changed sso"
        asked = [c.q("query") for c in srv.calls() if c.path == "/users"]
        assert asked == ["resp@example.com", "owner@example.com"]
    finally:
        srv.close()


# -- live: Claude drives the agent -----------------------------------------------


@pytest.mark.live
@pytest.mark.skipif(not os.environ.get("ANTHROPIC_API_KEY"), reason="needs ANTHROPIC_API_KEY")
def test_live_claude(hp: Hallpass) -> None:
    from agents import OpenAIChatCompletionsModel
    from openai import AsyncOpenAI

    # Claude through Anthropic's OpenAI-compatible endpoint.
    client = AsyncOpenAI(base_url="https://api.anthropic.com/v1/", api_key=os.environ["ANTHROPIC_API_KEY"])
    model = OpenAIChatCompletionsModel(model=os.environ.get("HALLPASS_LIVE_MODEL", "claude-haiku-4-5"), openai_client=client)
    agent = HallpassGuardrails(hp, RULES).apply(
        Agent(
            name="ops",
            instructions="You manage things. Use the tools; call each tool the user asks for exactly once, then report what happened.",
            model=model,
            tools=TOOLS,
        )
    )
    prompt = f"Call delete_thing with thing_id '7' and user '{ADMIN}', then call read_thing with thing_id '7'."
    result = asyncio.run(Runner.run(agent, prompt, context=Ctx(ALICE), max_turns=6))
    outputs = [str(i.output) for i in result.new_items if i.type == "tool_call_output_item"]
    assert ("delete_thing", "7") not in RAN  # alice is no admin, whatever the model sent as user
    assert ("read_thing", "7") in RAN
    assert any("hallpass refused this call" in o and ALICE in o for o in outputs), outputs
