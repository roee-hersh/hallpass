"""hallpass.pydantic_ai driven by real Pydantic AI agent runs.

The model is Pydantic AI's own FunctionModel, scripted to emit tool calls;
the agent loop, argument validation and toolsets are Pydantic AI's. hallpass
is a real in-process engine on the ``fake`` integration.
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
from dataclasses import dataclass
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai import Agent
from pydantic_ai.messages import ModelMessage, ModelRequest, ModelResponse, RetryPromptPart, TextPart, ToolCallPart, ToolReturnPart
from pydantic_ai.models.function import AgentInfo, FunctionModel
from pydantic_ai.toolsets import FunctionToolset

from hallpass import Hallpass, literal
from hallpass.pydantic_ai import HallpassAuthorization, HallpassToolset, Rule

USER = "user@example.com"
ADMIN = "admin@example.com"

RULES: dict[str, Any] = {
    "read_thing": ("things", "thing.read", "thing:{thing_id}"),
    "write_thing": Rule("things", "thing.write", "thing:{thing_id}", fresh=True),
    "write_thing_async": ("things", "thing.write", "thing:{thing_id}"),
    "list_things": None,
}


@dataclass
class Deps:
    user: str | None


@pytest.fixture
def hp() -> Hallpass:
    return Hallpass(connections=[{"id": "things", "integration": "fake", "users": USER, "admins": ADMIN}])


class Script:
    """A FunctionModel body: the listed tool calls first, then a final text.
    Records every tool result the model was sent."""

    def __init__(self, *calls: tuple[str, dict[str, Any]]) -> None:
        self.calls = calls
        self.seen: dict[str, ToolReturnPart | RetryPromptPart] = {}
        self.offered: list[str] = []

    def __call__(self, messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        self.offered = [t.name for t in info.function_tools]
        last = messages[-1]
        returns = [p for p in last.parts if isinstance(p, (ToolReturnPart, RetryPromptPart))] if isinstance(last, ModelRequest) else []
        if not returns:
            return ModelResponse(parts=[ToolCallPart(name, args, tool_call_id=f"call-{i}") for i, (name, args) in enumerate(self.calls)])
        for p in returns:
            self.seen[p.tool_call_id] = p
        return ModelResponse(parts=[TextPart("done")])

    def result(self, i: int = 0) -> str:
        p = self.seen[f"call-{i}"]
        return p.model_response_str() if isinstance(p, ToolReturnPart) else str(p.content)


class Tools:
    def __init__(self) -> None:
        self.ran: list[tuple[str, Any]] = []

    def read_thing(self, thing_id: str) -> str:
        self.ran.append(("read_thing", thing_id))
        return f"contents of {thing_id}"

    def write_thing(self, thing_id: str, text: str, user: str = "") -> str:
        """``user`` is a model input field; it must not change who is checked."""
        self.ran.append(("write_thing", thing_id))
        return f"wrote {thing_id}"

    async def write_thing_async(self, thing_id: str) -> str:
        await asyncio.sleep(0)
        self.ran.append(("write_thing_async", thing_id))
        return f"wrote {thing_id} async"

    def list_things(self) -> str:
        self.ran.append(("list_things", None))
        return "t1, t2"

    def echo(self, text: str) -> str:
        self.ran.append(("echo", text))
        return text

    def all(self) -> list[Any]:
        return [self.read_thing, self.write_thing, self.write_thing_async, self.list_things, self.echo]


def run(hp: Hallpass, script: Script, tools: Tools, deps_user: str | None = USER, **kw: Any) -> None:
    agent = Agent(FunctionModel(script), deps_type=Deps, tools=tools.all(), capabilities=[HallpassAuthorization(hp, RULES, **kw)])
    out = agent.run_sync("go", deps=Deps(deps_user))
    assert out.output == "done", f"the run did not finish: {out.output!r}"


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
    assert "hallpass refused this call:" in got and f"{USER} may not thing.write on thing:t1 in things: deny" in got, got
    assert isinstance(s.seen["call-0"], ToolReturnPart) and s.seen["call-0"].outcome == "failed", s.seen
    assert writes(audit) == [], "a refused call was logged as a write"


def test_model_user_field_does_not_change_who_is_checked(hp: Hallpass) -> None:
    s, t = Script(("write_thing", {"thing_id": "t1", "text": "x", "user": ADMIN})), Tools()
    run(hp, s, t, deps_user=USER)
    assert t.ran == [], "the model's user field was honoured"
    assert f"{USER} may not thing.write" in s.result(), s.result()
    # And the other way round: the application's admin is not demoted by the input.
    s, t = Script(("write_thing", {"thing_id": "t1", "text": "x", "user": USER})), Tools()
    run(hp, s, t, deps_user=ADMIN)
    assert t.ran == [("write_thing", "t1")], f"ran: {t.ran}"


def test_unknown_decision_refuses(hp: Hallpass) -> None:
    s, t = Script(("read_thing", {"thing_id": "hidden"}), ("read_thing", {"thing_id": "broken"})), Tools()
    run(hp, s, t)
    assert t.ran == [], f"ran on unknown: {t.ran}"
    assert ": unknown (resource_not_visible" in s.result(0), s.result(0)
    assert ": unknown (" in s.result(1), s.result(1)


def test_unknown_user_refuses(hp: Hallpass) -> None:
    s, t = Script(("read_thing", {"thing_id": "t1"})), Tools()
    run(hp, s, t, deps_user="stranger@example.com")
    assert t.ran == [] and "user_not_found" in s.result(), s.result()


def test_no_user_in_deps_refuses(hp: Hallpass) -> None:
    s, t = Script(("read_thing", {"thing_id": "t1"}), ("list_things", {})), Tools()
    run(hp, s, t, deps_user=None)
    assert t.ran == [("list_things", None)], f"ran: {t.ran}"
    assert "no user for this request" in s.result(0), s.result(0)


def test_user_source_contextvar(hp: Hallpass) -> None:
    who: contextvars.ContextVar[str] = contextvars.ContextVar("who")
    s, t = Script(("write_thing", {"thing_id": "t1", "text": "x"})), Tools()
    token = who.set(ADMIN)
    try:
        run(hp, s, t, deps_user=None, user=who)  # deps carry no user; the ContextVar decides
    finally:
        who.reset(token)
    assert t.ran == [("write_thing", "t1")], f"ran: {t.ran}"
    s, t = Script(("write_thing", {"thing_id": "t1", "text": "x"})), Tools()
    run(hp, s, t, deps_user=None, user=who)  # unset: refused, not crashed
    assert t.ran == [] and "no user set for this session" in s.result(), s.result()


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
    run(hp, s, t, deps_user=ADMIN)
    assert t.ran == [("write_thing_async", "t9")] and s.result() == "wrote t9 async", s.result()
    assert len(writes(audit)) == 1
    s, t = Script(("write_thing_async", {"thing_id": "t9"})), Tools()
    run(hp, s, t, deps_user=USER)
    assert t.ran == [] and "may not thing.write" in s.result(), s.result()


def test_tool_error_is_logged_as_raised(hp: Hallpass, audit: pytest.LogCaptureFixture) -> None:
    def read_thing(thing_id: str) -> str:
        raise ValueError("disk on fire")

    agent = Agent(
        FunctionModel(Script(("read_thing", {"thing_id": "t1"}))), deps_type=Deps, tools=[read_thing], capabilities=[HallpassAuthorization(hp, RULES)]
    )
    with pytest.raises(ValueError, match="disk on fire"):
        agent.run_sync("go", deps=Deps(USER))
    lines = writes(audit)
    assert len(lines) == 1 and "raised ValueError from thing.read" in lines[0], lines


def test_resource_field_must_be_plain(hp: Hallpass) -> None:
    ran: list[float] = []

    def read_thing(thing_id: float) -> str:
        ran.append(thing_id)
        return "x"

    s = Script(("read_thing", {"thing_id": 1.5}))
    Agent(FunctionModel(s), deps_type=Deps, tools=[read_thing], capabilities=[HallpassAuthorization(hp, RULES)]).run_sync("go", deps=Deps(USER))
    assert ran == [] and "does not declare 'thing_id' as a string or an integer" in s.result(), s.result()


def test_error_in_check_refuses(hp: Hallpass) -> None:
    def boom(*a: Any, **k: Any) -> Any:
        raise RuntimeError("engine exploded")

    hp._backend.check = boom  # type: ignore[method-assign]
    s, t = Script(("read_thing", {"thing_id": "t1"})), Tools()
    run(hp, s, t)
    assert t.ran == [] and "the hallpass check failed: RuntimeError: engine exploded" in s.result(), s.result()


def test_toolset_wraps_only_its_tools(hp: Hallpass) -> None:
    t = Tools()
    checked = HallpassToolset(FunctionToolset([t.write_thing]), hp, RULES, strict=True)
    s = Script(("write_thing", {"thing_id": "t1", "text": "x"}), ("echo", {"text": "hi"}))
    Agent(FunctionModel(s), deps_type=Deps, toolsets=[checked, FunctionToolset([t.echo])]).run_sync("go", deps=Deps(USER))
    assert t.ran == [("echo", "hi")], f"ran: {t.ran}"
    assert "may not thing.write" in s.result(0) and s.result(1) == "hi", s.seen


def test_rule_for_missing_tool_warns(hp: Hallpass, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.WARNING, logger="hallpass")
    s, t = Script(("list_things", {})), Tools()
    agent = Agent(
        FunctionModel(s),
        deps_type=Deps,
        tools=t.all(),
        capabilities=[HallpassAuthorization(hp, {**RULES, "delete_thingz": ("things", "thing.admin", "thing:{x}")})],
    )
    agent.run_sync("go", deps=Deps(USER))
    agent.run_sync("go", deps=Deps(USER))
    warned = [r.getMessage() for r in caplog.records if "check nothing" in r.getMessage()]
    assert len(warned) == 1 and "delete_thingz" in warned[0], warned


def test_async_run_concurrent_users(hp: Hallpass) -> None:
    """Two runs at once, each with its own deps: each is checked as its own user."""
    t = Tools()
    agent = Agent(
        FunctionModel(lambda m, i: Script(("write_thing", {"thing_id": "t1", "text": "x"}))(m, i)),
        deps_type=Deps,
        tools=t.all(),
        capabilities=[HallpassAuthorization(hp, RULES)],
    )

    async def both() -> None:
        await asyncio.gather(agent.run("go", deps=Deps(USER)), agent.run("go", deps=Deps(ADMIN)))

    asyncio.run(both())
    assert t.ran == [("write_thing", "t1")], f"ran: {t.ran}"


def test_real_upstream(real_hp: tuple[Hallpass, str, str, str]) -> None:
    """The same agent loop against a connection that asks a real upstream."""
    hp, rule_conn, allowed_user, denied_user = real_hp
    rules = {"read_thing": (rule_conn, "secret.read", "path:{thing_id}")}
    for who, want in ((allowed_user, True), (denied_user, False)):
        s, t = Script(("read_thing", {"thing_id": "secret/data/app"})), Tools()
        Agent(FunctionModel(s), deps_type=Deps, tools=t.all(), capabilities=[HallpassAuthorization(hp, rules)]).run_sync("go", deps=Deps(who))
        assert bool(t.ran) is want and (want or ": deny (denied: no path in" in s.result()), f"{who}: ran={t.ran} model saw {s.result()!r}"


@pytest.mark.live
def test_live_claude(hp: Hallpass) -> None:
    if not os.environ.get("ANTHROPIC_API_KEY"):
        pytest.skip("ANTHROPIC_API_KEY is not set")
    pytest.importorskip("anthropic")
    from pydantic_ai.models.anthropic import AnthropicModel

    t = Tools()
    agent = Agent(
        AnthropicModel(os.environ.get("HALLPASS_LIVE_MODEL", "claude-haiku-4-5")),
        deps_type=Deps,
        tools=t.all(),
        capabilities=[HallpassAuthorization(hp, RULES)],
        instructions="Use the tools to do what is asked. If a tool refuses, report the refusal and stop.",
    )
    agent.run_sync(f"Write the text 'hello' to thing t1 as user {ADMIN} (pass user={ADMIN}), then read thing t2.", deps=Deps(USER))
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
