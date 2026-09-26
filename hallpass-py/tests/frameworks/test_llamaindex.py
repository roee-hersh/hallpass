"""hallpass.llamaindex driven by real LlamaIndex agent workflows.

The model is LlamaIndex's own MockFunctionCallingLLM with a scripted
response generator that emits tool calls; FunctionAgent, ReActAgent and
AgentWorkflow run their own loops and call the tools. hallpass is a real
in-process engine on the ``fake`` integration.
"""

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
from pydantic import BaseModel

pytest.importorskip("llama_index.core")

from llama_index.core.agent.workflow import AgentWorkflow, FunctionAgent, ReActAgent
from llama_index.core.base.llms.types import ChatMessage, MessageRole, ToolCallBlock
from llama_index.core.llms.mock import MockFunctionCallingLLM, MockLLM
from llama_index.core.tools import BaseTool, FunctionTool, ToolMetadata, ToolOutput
from llama_index.core.workflow import Context

from hallpass import Hallpass, literal
from hallpass.llamaindex import HallpassAuthorization, HallpassTool, Rule

USER = "user@example.com"
ADMIN = "admin@example.com"

RULES: dict[str, Any] = {
    "read_thing": ("things", "thing.read", "thing:{thing_id}"),
    "write_thing": Rule("things", "thing.write", "thing:{thing_id}", fresh=True),
    "write_thing_async": ("things", "thing.write", "thing:{thing_id}"),
    "write_with_ctx": ("things", "thing.write", "thing:{thing_id}"),
    "list_things": None,
}

WHO: contextvars.ContextVar[str] = contextvars.ContextVar("who")


@pytest.fixture
def hp() -> Hallpass:
    return Hallpass(connections=[{"id": "things", "integration": "fake", "users": USER, "admins": ADMIN}])


class Tools:
    def __init__(self) -> None:
        self.ran: list[tuple[str, Any]] = []

    def all(self) -> list[Any]:
        ran = self.ran

        def read_thing(thing_id: str) -> str:
            """Read a thing by id."""
            ran.append(("read_thing", thing_id))
            return f"contents of {thing_id}"

        def write_thing(thing_id: str, text: str, user: str = "") -> str:
            """Write text to a thing. ``user`` is a model input field; it must not change who is checked."""
            ran.append(("write_thing", thing_id))
            return f"wrote {thing_id}"

        async def write_thing_async(thing_id: str) -> str:
            """Write a thing, asynchronously."""
            await asyncio.sleep(0)
            ran.append(("write_thing_async", thing_id))
            return f"wrote {thing_id} async"

        async def write_with_ctx(ctx: Context, thing_id: str) -> str:
            """Write a thing and note it in the workflow state."""
            await ctx.store.set("written", thing_id)
            ran.append(("write_with_ctx", thing_id))
            return f"wrote {thing_id} with ctx"

        def list_things() -> str:
            """List things."""
            ran.append(("list_things", None))
            return "t1, t2"

        def echo(text: str) -> str:
            """Echo text."""
            ran.append(("echo", text))
            return text

        return [read_thing, write_thing, write_thing_async, write_with_ctx, list_things, echo]


class Script:
    """A MockFunctionCallingLLM response generator: the listed tool calls,
    then a final answer. Records every tool result the model was sent."""

    def __init__(self, *calls: tuple[str, dict[str, Any]]) -> None:
        self.calls = calls
        self.seen: dict[str, str] = {}

    def __call__(self, messages: list[ChatMessage], **kw: Any) -> ChatMessage:
        results = [m for m in messages if m.role == MessageRole.TOOL]
        if not results:
            return ChatMessage(
                role="assistant", blocks=[ToolCallBlock(tool_call_id=f"call-{i}", tool_name=n, tool_kwargs=a) for i, (n, a) in enumerate(self.calls)]
            )
        for m in results:
            self.seen[m.additional_kwargs.get("tool_call_id", "")] = str(m.content)
        return ChatMessage(role="assistant", content="done")

    def result(self, i: int = 0) -> str:
        return self.seen[f"call-{i}"]


def run(hp: Hallpass, script: Script, tools: Tools, user: str | None = USER, **kw: Any) -> str:
    auth = HallpassAuthorization(hp, RULES, user=WHO, **kw)
    agent = FunctionAgent(tools=auth.wrap(tools.all()), llm=MockFunctionCallingLLM(response_generator=script))

    async def go() -> str:
        token = WHO.set(user) if user is not None else None
        try:
            return str(await agent.run("go"))
        finally:
            if token is not None:
                WHO.reset(token)

    out = asyncio.run(go())
    assert out == "done", f"the run did not finish: {out!r}"
    return out


def drive(agent: Any) -> Any:
    async def go() -> Any:
        return await agent.run("go")

    return asyncio.run(go())


@pytest.fixture
def audit(caplog: pytest.LogCaptureFixture) -> Iterator[pytest.LogCaptureFixture]:
    caplog.set_level(logging.INFO, logger="hallpass")
    yield caplog


def writes(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.getMessage().startswith("unconditional write")]


def test_allowed_tool_runs_and_result_reaches_model(hp: Hallpass, audit: pytest.LogCaptureFixture) -> None:
    s, t = Script(("read_thing", {"thing_id": "t1"})), Tools()
    run(hp, s, t)
    assert t.ran == [("read_thing", "t1")], f"ran: {t.ran}"
    assert s.result() == "contents of t1", f"model saw: {s.result()!r}"
    lines = writes(audit)
    assert len(lines) == 1 and f"{USER} ran thing.read on thing:t1 in things; hallpass said allow" in lines[0], f"audit: {lines}"


def test_denied_tool_never_runs_and_model_reads_refusal(hp: Hallpass, audit: pytest.LogCaptureFixture) -> None:
    s, t = Script(("write_thing", {"thing_id": "t1", "text": "x"})), Tools()
    run(hp, s, t)
    assert t.ran == [], f"a denied tool ran: {t.ran}"
    got = s.result()
    assert got.startswith("hallpass refused this call:") and f"{USER} may not thing.write on thing:t1 in things: deny" in got, got
    assert writes(audit) == [], "a refused call was logged as a write"


def test_model_user_field_does_not_change_who_is_checked(hp: Hallpass) -> None:
    s, t = Script(("write_thing", {"thing_id": "t1", "text": "x", "user": ADMIN})), Tools()
    run(hp, s, t, user=USER)
    assert t.ran == [] and f"{USER} may not thing.write" in s.result(), s.result()
    s, t = Script(("write_thing", {"thing_id": "t1", "text": "x", "user": USER})), Tools()
    run(hp, s, t, user=ADMIN)
    assert t.ran == [("write_thing", "t1")], f"ran: {t.ran}"


def test_unknown_decision_refuses(hp: Hallpass) -> None:
    s, t = Script(("read_thing", {"thing_id": "hidden"}), ("read_thing", {"thing_id": "broken"})), Tools()
    run(hp, s, t)
    assert t.ran == [], f"ran on unknown: {t.ran}"
    assert ": unknown (resource_not_visible" in s.result(0), s.result(0)
    assert ": unknown (" in s.result(1), s.result(1)


def test_no_user_refuses(hp: Hallpass) -> None:
    s, t = Script(("read_thing", {"thing_id": "t1"}), ("list_things", {})), Tools()
    run(hp, s, t, user=None)
    assert t.ran == [("list_things", None)], f"ran: {t.ran}"
    assert "no user set for this session in ContextVar 'who'" in s.result(0), s.result(0)


def test_unchecked_and_strict(hp: Hallpass) -> None:
    s, t = Script(("echo", {"text": "hi"}), ("list_things", {})), Tools()
    run(hp, s, t)
    assert sorted(t.ran, key=str) == [("echo", "hi"), ("list_things", None)], f"ran: {t.ran}"
    s, t = Script(("echo", {"text": "hi"}), ("list_things", {})), Tools()
    run(hp, s, t, strict=True)
    assert t.ran == [("list_things", None)], f"strict let an unruled tool run: {t.ran}"
    assert "no hallpass rule for tool 'echo'" in s.result(0), s.result(0)


def test_async_tool(hp: Hallpass, audit: pytest.LogCaptureFixture) -> None:
    s, t = Script(("write_thing_async", {"thing_id": "t9"})), Tools()
    run(hp, s, t, user=ADMIN)
    assert t.ran == [("write_thing_async", "t9")] and s.result() == "wrote t9 async", s.result()
    assert len(writes(audit)) == 1
    s, t = Script(("write_thing_async", {"thing_id": "t9"})), Tools()
    run(hp, s, t, user=USER)
    assert t.ran == [] and "may not thing.write" in s.result(), s.result()


def test_context_tool_keeps_its_context(hp: Hallpass) -> None:
    s, t = Script(("write_with_ctx", {"thing_id": "t3"})), Tools()
    run(hp, s, t, user=ADMIN)
    assert t.ran == [("write_with_ctx", "t3")] and s.result() == "wrote t3 with ctx", s.result()


def test_resource_field_must_be_exact_json_type(hp: Hallpass) -> None:
    ran: list[Any] = []

    def count_thing(thing_id: int) -> str:
        """Count a thing."""
        ran.append(thing_id)
        return "1"

    rules = {"count_thing": ("things", "thing.read", "thing:{thing_id}")}
    s = Script(("count_thing", {"thing_id": "01"}), ("count_thing", {"thing_id": 7}))
    agent = FunctionAgent(tools=HallpassAuthorization(hp, rules, user=USER).wrap([count_thing]), llm=MockFunctionCallingLLM(response_generator=s))
    drive(agent)
    assert ran == [7], f"ran: {ran}"
    assert "'thing_id' must be a JSON integer, not str" in s.result(0), s.result(0)


def test_error_in_check_refuses(hp: Hallpass) -> None:
    def boom(*a: Any, **k: Any) -> Any:
        raise RuntimeError("engine exploded")

    hp._backend.check = boom  # type: ignore[method-assign]
    s, t = Script(("read_thing", {"thing_id": "t1"})), Tools()
    run(hp, s, t)
    assert t.ran == [] and "the hallpass check failed: RuntimeError: engine exploded" in s.result(), s.result()


def test_tool_error_is_logged_as_raised(hp: Hallpass, audit: pytest.LogCaptureFixture) -> None:
    def read_thing(thing_id: str) -> str:
        """Read a thing by id."""
        raise ValueError("disk on fire")

    s = Script(("read_thing", {"thing_id": "t1"}))
    agent = FunctionAgent(tools=HallpassAuthorization(hp, RULES, user=USER).wrap([read_thing]), llm=MockFunctionCallingLLM(response_generator=s))
    drive(agent)
    assert s.result() == "disk on fire", s.result()
    lines = writes(audit)
    assert len(lines) == 1 and "raised ValueError from thing.read" in lines[0], lines


def test_return_direct_refusal_does_not_end_run(hp: Hallpass) -> None:
    ran: list[str] = []

    def write_thing(thing_id: str, text: str) -> str:
        """Write text to a thing."""
        ran.append(thing_id)
        return "wrote"

    tool = FunctionTool.from_defaults(write_thing, return_direct=True)
    s = Script(("write_thing", {"thing_id": "t1", "text": "x"}))
    agent = FunctionAgent(tools=HallpassAuthorization(hp, RULES, user=USER).wrap([tool]), llm=MockFunctionCallingLLM(response_generator=s))
    out = drive(agent)
    assert ran == [] and str(out) == "done", f"ran={ran} out={out!r}"
    assert "may not thing.write" in s.result(), s.result()


def test_sync_call_path(hp: Hallpass) -> None:
    t = Tools()
    wrapped = {w.metadata.name: w for w in HallpassAuthorization(hp, RULES, user=USER).wrap(t.all())}
    assert isinstance(wrapped["read_thing"], HallpassTool) and not isinstance(wrapped["echo"], HallpassTool)
    assert wrapped["read_thing"].call(thing_id="t1").content == "contents of t1"
    out = wrapped["write_thing"].call(thing_id="t1", text="x")
    assert out.is_error and "may not thing.write" in out.content and t.ran == [("read_thing", "t1")], (out, t.ran)


def test_plain_base_tool(hp: Hallpass) -> None:
    """A BaseTool that is neither a FunctionTool nor async is wrapped too."""
    ran: list[str] = []

    class ReadArgs(BaseModel):
        thing_id: str

    class Reader(BaseTool):
        @property
        def metadata(self) -> ToolMetadata:
            return ToolMetadata(name="read_thing", description="Read a thing by id.", fn_schema=ReadArgs)

        def __call__(self, thing_id: str) -> ToolOutput:
            ran.append(thing_id)
            return ToolOutput(content=f"contents of {thing_id}", tool_name="read_thing", raw_input={"thing_id": thing_id}, raw_output=thing_id)

    s = Script(("read_thing", {"thing_id": "t1"}), ("read_thing", {"thing_id": "hidden"}))
    agent = FunctionAgent(tools=HallpassAuthorization(hp, RULES, user=USER).wrap([Reader()]), llm=MockFunctionCallingLLM(response_generator=s))
    drive(agent)
    assert ran == ["t1"], f"ran: {ran}"
    assert s.result(0) == "contents of t1" and ": unknown (" in s.result(1), s.seen


def test_react_agent(hp: Hallpass) -> None:
    """ReActAgent parses tool calls out of text; the wrapped tool checks the same way."""
    t, seen = Tools(), []

    def react(messages: list[ChatMessage], **kw: Any) -> ChatMessage:
        text = str(messages[-1].content)
        if "Observation:" in text:
            seen.append(text.split("Observation:", 1)[1].strip())
            return ChatMessage(role="assistant", content="Thought: I can answer without using any more tools.\nAnswer: done")
        return ChatMessage(role="assistant", content='Thought: I need a tool.\nAction: write_thing\nAction Input: {"thing_id": "t1", "text": "x"}')

    class ReactLLM(MockLLM):
        def chat(self, messages: Any, **kw: Any) -> Any:
            from llama_index.core.base.llms.types import ChatResponse

            return ChatResponse(message=react(list(messages)))

        async def achat(self, messages: Any, **kw: Any) -> Any:
            return self.chat(messages)

    agent = ReActAgent(tools=HallpassAuthorization(hp, RULES, user=USER).wrap(t.all()), llm=ReactLLM(), streaming=False)
    drive(agent)
    assert t.ran == [] and seen and "hallpass refused this call:" in seen[0], (t.ran, seen)


def test_agent_workflow_multi_agent(hp: Hallpass) -> None:
    t = Tools()
    auth = HallpassAuthorization(hp, RULES, user=WHO)
    s = Script(("write_thing", {"thing_id": "t1", "text": "x"}), ("read_thing", {"thing_id": "t2"}))
    llm = MockFunctionCallingLLM(response_generator=s)
    clerk = FunctionAgent(name="clerk", description="handles things", tools=auth.wrap(t.all()), llm=llm)
    wf = AgentWorkflow(agents=[clerk], root_agent="clerk")

    async def go() -> None:
        WHO.set(USER)
        await wf.run("go")

    asyncio.run(go())
    assert t.ran == [("read_thing", "t2")], f"ran: {t.ran}"
    assert "may not thing.write" in s.result(0) and s.result(1) == "contents of t2", s.seen


def test_rule_for_missing_tool_warns(hp: Hallpass, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.WARNING, logger="hallpass")
    HallpassAuthorization(hp, {**RULES, "delete_thingz": ("things", "thing.admin", "thing:{x}")}, user=USER).wrap(Tools().all())
    warned = [r.getMessage() for r in caplog.records if "check nothing" in r.getMessage()]
    assert len(warned) == 1 and "delete_thingz" in warned[0], warned


def test_real_upstream(real_hp: tuple[Hallpass, str, str, str]) -> None:
    """The same agent loop against a connection that asks a real upstream."""
    hp, conn, allowed_user, denied_user = real_hp
    rules = {"read_thing": (conn, "secret.read", "path:{thing_id}")}
    for who, want in ((allowed_user, True), (denied_user, False)):
        s, t = Script(("read_thing", {"thing_id": "secret/data/app"})), Tools()
        agent = FunctionAgent(tools=HallpassAuthorization(hp, rules, user=who).wrap(t.all()), llm=MockFunctionCallingLLM(response_generator=s))
        drive(agent)
        assert bool(t.ran) is want and (want or ": deny (denied: no path in" in s.result()), f"{who}: ran={t.ran} model saw {s.result()!r}"


@pytest.mark.live
def test_live_claude(hp: Hallpass) -> None:
    if not os.environ.get("ANTHROPIC_API_KEY"):
        pytest.skip("ANTHROPIC_API_KEY is not set")
    anthropic_llms = pytest.importorskip("llama_index.llms.anthropic")

    t = Tools()
    llm = anthropic_llms.Anthropic(model=os.environ.get("HALLPASS_LIVE_MODEL", "claude-haiku-4-5"), max_tokens=1024)
    agent = FunctionAgent(
        tools=HallpassAuthorization(hp, RULES, user=WHO).wrap(t.all()),
        llm=llm,
        system_prompt="Use the tools to do what is asked. If a tool refuses, report the refusal and stop.",
    )

    async def go() -> None:
        WHO.set(USER)
        await agent.run(f"Write the text 'hello' to thing t1, passing user={json.dumps(ADMIN)}. Then read thing t2.")

    asyncio.run(go())
    assert ("write_thing", "t1") not in t.ran, f"the model's claimed user was honoured: {t.ran}"
    assert ("read_thing", "t2") in t.ran, f"the allowed read did not run: {t.ran}"


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
