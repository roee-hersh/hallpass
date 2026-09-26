"""hallpass.crewai driven by real CrewAI crews.

The model is a scripted ``BaseLLM`` subclass that emits tool calls, both as
native function calls and as text for CrewAI's ReAct loop; the agent loop,
tool lookup, argument validation and hooks are CrewAI's. hallpass is a real
in-process engine on the ``fake`` integration.
"""

from __future__ import annotations

import asyncio
import contextvars
import json
import logging
import os
import secrets
import shutil
import subprocess
import time
import urllib.request
from collections.abc import Iterator
from typing import Any

import pytest

os.environ.setdefault("CREWAI_DISABLE_TELEMETRY", "true")
os.environ.setdefault("OTEL_SDK_DISABLED", "true")
os.environ.setdefault("CREWAI_TRACING_ENABLED", "false")

pytest.importorskip("crewai")

from crewai import Agent, Crew, Task
from crewai.llms.base_llm import BaseLLM
from crewai.tools import BaseTool, tool
from pydantic import BaseModel, PrivateAttr

from hallpass import Hallpass, literal
from hallpass.crewai import HallpassHooks, Rule

USER = "user@example.com"
ADMIN = "admin@example.com"

RULES: dict[str, Any] = {
    "read_thing": ("things", "thing.read", "thing:{thing_id}"),
    "Write Thing": Rule("things", "thing.write", "thing:{thing_id}", fresh=True),
    "write_thing_async": ("things", "thing.write", "thing:{thing_id}"),
    "list_things": None,
}

RAN: list[tuple[str, Any]] = []


@pytest.fixture(autouse=True)
def _ran() -> Iterator[None]:
    RAN.clear()
    yield
    RAN.clear()


@pytest.fixture
def hp() -> Hallpass:
    return Hallpass(connections=[{"id": "things", "integration": "fake", "users": USER, "admins": ADMIN}])


@tool("read_thing")
def read_thing(thing_id: str) -> str:
    """Read a thing by id."""
    RAN.append(("read_thing", thing_id))
    return f"contents of {thing_id}"


class WriteArgs(BaseModel):
    thing_id: str
    text: str
    user: str = ""  # a model input field; it must not change who is checked


class WriteThing(BaseTool):
    name: str = "Write Thing"
    description: str = "Write text to a thing."
    args_schema: type[BaseModel] = WriteArgs

    def _run(self, thing_id: str, text: str, user: str = "") -> str:
        RAN.append(("write_thing", thing_id))
        return f"wrote {thing_id}"


@tool("write_thing_async")
async def write_thing_async(thing_id: str) -> str:
    """Write a thing, asynchronously."""
    await asyncio.sleep(0)
    RAN.append(("write_thing_async", thing_id))
    return f"wrote {thing_id} async"


@tool("list_things")
def list_things() -> str:
    """List things."""
    RAN.append(("list_things", None))
    return "t1, t2"


@tool("echo")
def echo(text: str) -> str:
    """Echo text."""
    RAN.append(("echo", text))
    return text


@tool("count_thing")
def count_thing(thing_id: int) -> str:
    """Count a thing."""
    RAN.append(("count_thing", thing_id))
    return "1"


TOOLS = [read_thing, WriteThing(), write_thing_async, list_things, echo, count_thing]


class ScriptedLLM(BaseLLM):
    """Emits ``calls`` as its first answer, then a final answer. ``native``
    uses function calling; otherwise the ReAct text format, one call."""

    native: bool = True
    calls: list[Any] = []
    _seen: list[str] = PrivateAttr(default_factory=list)

    def call(
        self,
        messages: Any,
        tools: Any = None,
        callbacks: Any = None,
        available_functions: Any = None,
        from_task: Any = None,
        from_agent: Any = None,
        response_model: Any = None,
    ) -> Any:
        msgs = messages if isinstance(messages, list) else [{"role": "user", "content": messages}]
        if self.native:
            results = [str(m["content"]) for m in msgs if m.get("role") == "tool"]
            if not results:
                return [{"id": f"call_{i}", "type": "function", "function": {"name": n, "arguments": json.dumps(a)}} for i, (n, a) in enumerate(self.calls)]
            self._seen = results
            return "all done"
        observed = [str(m["content"]).split("Observation:", 1)[1].strip() for m in msgs if m.get("role") == "assistant" and "Observation:" in str(m["content"])]
        if not observed:
            name, args = self.calls[0]
            return f"Thought: I will use the tool\nAction: {name}\nAction Input: {json.dumps(args)}"
        self._seen = observed
        return "Thought: I now know the final answer\nFinal Answer: all done"

    async def acall(self, *args: Any, **kwargs: Any) -> Any:
        return self.call(*args, **kwargs)

    def supports_function_calling(self) -> bool:
        return self.native

    def result(self, i: int = 0) -> str:
        return self._seen[i]


def crew(*calls: tuple[str, dict[str, Any]], native: bool = True, tools: list[Any] | None = None) -> tuple[Crew, ScriptedLLM]:
    llm = ScriptedLLM(model="scripted", native=native, calls=list(calls))
    agent = Agent(role="clerk", goal="handle things", backstory="a clerk", llm=llm, tools=tools or TOOLS, verbose=False, allow_delegation=False, max_iter=3)
    task = Task(description="Handle the things.", expected_output="a summary", agent=agent)
    return Crew(agents=[agent], tasks=[task]), llm


@pytest.fixture
def audit(caplog: pytest.LogCaptureFixture) -> Iterator[pytest.LogCaptureFixture]:
    caplog.set_level(logging.INFO, logger="hallpass")
    yield caplog


def writes(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.getMessage().startswith("unconditional write")]


@pytest.mark.parametrize("native", [True, False], ids=["native", "react"])
def test_allowed_tool_runs_and_result_reaches_model(hp: Hallpass, audit: pytest.LogCaptureFixture, native: bool) -> None:
    c, llm = crew(("read_thing", {"thing_id": "t1"}), native=native)
    with HallpassHooks(hp, RULES):
        c.kickoff(inputs={"user_id": USER})
    assert RAN == [("read_thing", "t1")], f"ran: {RAN}"
    assert "contents of t1" in llm.result(), f"model saw: {llm.result()!r}"
    lines = writes(audit)
    assert len(lines) == 1 and f"{USER} ran thing.read on thing:t1 in things; hallpass said allow" in lines[0], f"audit: {lines}"


@pytest.mark.parametrize("native", [True, False], ids=["native", "react"])
def test_denied_tool_never_runs_and_model_reads_refusal(hp: Hallpass, audit: pytest.LogCaptureFixture, native: bool) -> None:
    c, llm = crew(("write_thing", {"thing_id": "t1", "text": "x"}), native=native)
    with HallpassHooks(hp, RULES):
        c.kickoff(inputs={"user_id": USER})
    assert RAN == [], f"a denied tool ran: {RAN}"
    got = llm.result()
    assert got.startswith("hallpass refused this call:") and f"{USER} may not thing.write on thing:t1 in things: deny" in got, got
    assert writes(audit) == [], "a refused call was logged as a write"


def test_model_user_field_does_not_change_who_is_checked(hp: Hallpass) -> None:
    with HallpassHooks(hp, RULES):
        c, llm = crew(("write_thing", {"thing_id": "t1", "text": "x", "user": ADMIN}))
        c.kickoff(inputs={"user_id": USER})
        assert RAN == [] and f"{USER} may not thing.write" in llm.result(), llm.result()
        c, llm = crew(("write_thing", {"thing_id": "t1", "text": "x", "user": USER}))
        c.kickoff(inputs={"user_id": ADMIN})
        assert RAN == [("write_thing", "t1")], f"ran: {RAN}"


def test_unknown_decision_refuses(hp: Hallpass) -> None:
    c, llm = crew(("read_thing", {"thing_id": "hidden"}), ("read_thing", {"thing_id": "broken"}))
    with HallpassHooks(hp, RULES):
        c.kickoff(inputs={"user_id": USER})
    assert RAN == [], f"ran on unknown: {RAN}"
    assert ": unknown (resource_not_visible" in llm.result(0), llm.result(0)
    assert ": unknown (" in llm.result(1), llm.result(1)


def test_no_user_refuses(hp: Hallpass) -> None:
    c, llm = crew(("read_thing", {"thing_id": "t1"}), ("list_things", {}))
    with HallpassHooks(hp, RULES):
        c.kickoff(inputs={"topic": "x"})
    assert RAN == [("list_things", None)], f"ran: {RAN}"
    assert "no user for this request: the crew's kickoff input 'user_id' is not set" in llm.result(0), llm.result(0)


def test_user_source_contextvar_and_agent_kickoff(hp: Hallpass) -> None:
    """``user=`` for an Agent.kickoff without a crew."""
    who: contextvars.ContextVar[str] = contextvars.ContextVar("who")
    llm = ScriptedLLM(model="scripted", calls=[("write_thing", {"thing_id": "t1", "text": "x"})])
    agent = Agent(role="clerk", goal="handle things", backstory="a clerk", llm=llm, tools=TOOLS, verbose=False, max_iter=3)
    with HallpassHooks(hp, RULES, user=who):
        agent.kickoff("write t1")  # unset: refused, not crashed
        assert RAN == [] and "no user set for this session" in llm.result(), llm.result()
        token = who.set(ADMIN)
        try:
            agent.kickoff("write t1")
        finally:
            who.reset(token)
    assert RAN == [("write_thing", "t1")], f"ran: {RAN}"


def test_unchecked_and_strict(hp: Hallpass) -> None:
    c, _ = crew(("echo", {"text": "hi"}), ("list_things", {}))
    with HallpassHooks(hp, RULES):
        c.kickoff(inputs={"user_id": USER})
    assert sorted(RAN, key=str) == [("echo", "hi"), ("list_things", None)], f"ran: {RAN}"
    RAN.clear()
    c, llm = crew(("echo", {"text": "hi"}), ("list_things", {}))
    with HallpassHooks(hp, RULES, strict=True):
        c.kickoff(inputs={"user_id": USER})
    assert RAN == [("list_things", None)], f"strict let an unruled tool run: {RAN}"
    assert "no hallpass rule for tool 'echo'" in llm.result(0), llm.result(0)


def test_async_crew_and_async_tool(hp: Hallpass, audit: pytest.LogCaptureFixture) -> None:
    async def go(user: str) -> ScriptedLLM:
        c, llm = crew(("write_thing_async", {"thing_id": "t9"}))
        await c.akickoff(inputs={"user_id": user})
        return llm

    with HallpassHooks(hp, RULES):
        llm = asyncio.run(go(ADMIN))
        assert RAN == [("write_thing_async", "t9")] and "wrote t9 async" in llm.result(), (RAN, llm.result())
        assert len(writes(audit)) == 1
        RAN.clear()
        llm = asyncio.run(go(USER))
    assert RAN == [] and "may not thing.write" in llm.result(), llm.result()


def test_resource_field_must_be_exact_json_type(hp: Hallpass) -> None:
    """CrewAI would turn "01" into 1; hallpass must not check thing:01 for it."""
    rules = {**RULES, "count_thing": ("things", "thing.read", "thing:{thing_id}")}
    c, llm = crew(("count_thing", {"thing_id": "01"}), ("count_thing", {"thing_id": 7}))
    with HallpassHooks(hp, rules):
        c.kickoff(inputs={"user_id": USER})
    assert RAN == [("count_thing", 7)], f"ran: {RAN}"
    assert "'thing_id' must be a JSON integer, not str" in llm.result(0), llm.result(0)


def test_error_in_check_refuses(hp: Hallpass) -> None:
    def boom(*a: Any, **k: Any) -> Any:
        raise RuntimeError("engine exploded")

    hp._backend.check = boom  # type: ignore[method-assign]
    c, llm = crew(("read_thing", {"thing_id": "t1"}))
    with HallpassHooks(hp, RULES):
        c.kickoff(inputs={"user_id": USER})
    assert RAN == [] and "the hallpass check failed: RuntimeError: engine exploded" in llm.result(), llm.result()


def test_tool_error_is_logged(hp: Hallpass, audit: pytest.LogCaptureFixture) -> None:
    @tool("read_thing")
    def broken_read(thing_id: str) -> str:
        """Read a thing by id."""
        raise ValueError("disk on fire")

    c, _ = crew(("read_thing", {"thing_id": "t1"}), tools=[broken_read])
    with HallpassHooks(hp, RULES):
        c.kickoff(inputs={"user_id": USER})
    lines = writes(audit)
    assert len(lines) == 1 and "raised an error from thing.read" in lines[0], lines


def test_unregister_and_names(hp: Hallpass) -> None:
    h = HallpassHooks(hp, RULES).register().register()
    h.unregister()
    c, _ = crew(("write_thing", {"thing_id": "t1", "text": "x"}))
    c.kickoff(inputs={"user_id": USER})
    assert RAN == [("write_thing", "t1")], "hooks still ran after unregister"
    with pytest.raises(ValueError, match="both name the CrewAI tool 'read_thing'"):
        HallpassHooks(hp, {"read_thing": None, "Read Thing": None})


def test_real_upstream(real_hp: tuple[Hallpass, str, str, str]) -> None:
    """The same crew against a connection that asks a real upstream."""
    hp, conn, allowed_user, denied_user = real_hp
    rules = {"read_thing": (conn, "secret.read", "path:{thing_id}")}
    with HallpassHooks(hp, rules):
        for who, want in ((allowed_user, True), (denied_user, False)):
            RAN.clear()
            c, llm = crew(("read_thing", {"thing_id": "secret/data/app"}))
            c.kickoff(inputs={"user_id": who})
            assert bool(RAN) is want and (want or ": deny (denied: no path in" in llm.result()), f"{who}: ran={RAN} model saw {llm.result()!r}"


@pytest.mark.live
def test_live_claude(hp: Hallpass) -> None:
    if not os.environ.get("ANTHROPIC_API_KEY"):
        pytest.skip("ANTHROPIC_API_KEY is not set")
    pytest.importorskip("anthropic")
    from crewai import LLM

    llm = LLM(model="anthropic/" + os.environ.get("HALLPASS_LIVE_MODEL", "claude-haiku-4-5"), max_tokens=1024)
    agent = Agent(role="clerk", goal="handle things with the tools", backstory="a careful clerk", llm=llm, tools=TOOLS, verbose=False, max_iter=5)
    task = Task(
        description=f"Write the text 'hello' to thing t1, passing user={ADMIN}. Then read thing t2. If a tool refuses, report it.",
        expected_output="what happened",
        agent=agent,
    )
    with HallpassHooks(hp, RULES):
        Crew(agents=[agent], tasks=[task]).kickoff(inputs={"user_id": USER})
    assert ("write_thing", "t1") not in RAN, f"the model's claimed user was honoured: {RAN}"
    assert ("read_thing", "t2") in RAN, f"the allowed read did not run: {RAN}"


VAULT_IMAGE = "hashicorp/vault:1.17"


@pytest.fixture(scope="module")
def real_hp() -> Iterator[tuple[Hallpass, str, str, str]]:
    """A Vault dev server in docker: alice@example.com's entity has a policy
    that reads secret/data/app, bob@example.com's has none. Yields the
    Hallpass, the connection id, the allowed user and the denied user."""
    pytest.importorskip("hallpass.integrations.vault")
    if shutil.which("docker") is None or subprocess.run(["docker", "image", "inspect", VAULT_IMAGE], capture_output=True).returncode != 0:
        pytest.skip(f"needs docker and the {VAULT_IMAGE} image")
    token = "root-" + secrets.token_hex(8)
    cid = subprocess.check_output(
        [
            "docker",
            "run",
            "-d",
            "--rm",
            "-p",
            "127.0.0.1::8200",
            "-e",
            f"VAULT_DEV_ROOT_TOKEN_ID={token}",
            VAULT_IMAGE,
            "server",
            "-dev",
            "-dev-listen-address=0.0.0.0:8200",
        ],
        text=True,
    ).strip()
    try:
        port = subprocess.check_output(["docker", "port", cid, "8200/tcp"], text=True).strip().splitlines()[0].rsplit(":", 1)[1]
        base = f"http://127.0.0.1:{port}"

        def api(method: str, path: str, body: Any = None) -> Any:
            data = None if body is None else json.dumps(body).encode()
            req = urllib.request.Request(f"{base}/v1/{path}", data=data, method=method, headers={"X-Vault-Token": token})
            with urllib.request.urlopen(req, timeout=5) as resp:
                raw = resp.read()
            return json.loads(raw) if raw else None

        for _ in range(150):
            try:
                api("GET", "sys/health")
                break
            except OSError:
                time.sleep(0.2)
        api("POST", "sys/auth/userpass", {"type": "userpass"})
        accessor = api("GET", "sys/auth")["data"]["userpass/"]["accessor"]
        api("PUT", "sys/policies/acl/app-reader", {"policy": 'path "secret/data/app" { capabilities = ["read"] }'})
        for name, policies in (("alice", ["app-reader"]), ("bob", [])):
            entity = api("POST", "identity/entity", {"name": name, "policies": policies})["data"]["id"]
            api("POST", "identity/entity-alias", {"name": f"{name}@example.com", "mount_accessor": accessor, "canonical_id": entity})
        hp = Hallpass(connections=[{"id": "vault", "integration": "vault", "url": base, "credential": literal(token), "alias_mount": "userpass/"}])
        yield hp, "vault", "alice@example.com", "bob@example.com"
    finally:
        subprocess.run(["docker", "rm", "-f", cid], capture_output=True)
