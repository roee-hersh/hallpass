"""hallpass.claude_agent_sdk driven by the Claude Agent SDK's real loop.

The SDK drives the Claude Code CLI, which calls the Anthropic Messages API.
Here the CLI (the one the SDK bundles) talks to ``FakeClaude``, a scripted
Messages API on localhost, so the whole loop is real: the CLI asks the SDK's
hook callbacks over the control protocol, runs the tools of an in-process
SDK MCP server, and sends the results back to the "model", which records
them. hallpass is the in-process engine. One test checks against a real HTTP
upstream (PagerDuty against the test harness's TLS server), and the live test
lets Claude drive the same session.

Also here: the tests of examples/agent/claude_agent_sdk_tool.py, ported to
``hallpass.guarded`` on an SDK MCP tool handler.
"""

from __future__ import annotations

import asyncio
import contextvars
import json
import logging
import os
import pathlib
import re
import shutil
import subprocess
import threading
import time
import urllib.request
from collections.abc import Iterator
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

pytest.importorskip("claude_agent_sdk")

import claude_agent_sdk
from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ClaudeSDKClient,
    HookMatcher,
    ResultMessage,
    TextBlock,
    ToolUseBlock,
    create_sdk_mcp_server,
    query,
    tool,
)

from hallpass import Hallpass, PermissionDenied, guarded, literal
from hallpass.claude_agent_sdk import HallpassHooks, Rule
from tests import harness as itest

_BUNDLED = pathlib.Path(claude_agent_sdk.__file__).parent / "_bundled" / "claude"
if not _BUNDLED.exists() and shutil.which("claude") is None:
    pytest.skip("no Claude Code CLI for the SDK to drive", allow_module_level=True)

ALICE = "alice@example.com"  # a known user: may read
ADMIN = "admin@example.com"  # an admin: may write

# Read before the hermetic fixture clears the environment.
LIVE_KEY = os.environ.get("ANTHROPIC_API_KEY")

RAN: list[tuple[str, Any]] = []
current_user: contextvars.ContextVar[str] = contextvars.ContextVar("current_user")


def _text(text: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": text}]}


@tool("read_thing", "Read a thing.", {"thing_id": str})
async def read_thing(args: dict[str, Any]) -> dict[str, Any]:
    RAN.append(("read_thing", args["thing_id"]))
    return _text(f"thing {args['thing_id']}: shiny")


@tool("delete_thing", "Delete a thing.", {"thing_id": str, "user": str})
async def delete_thing(args: dict[str, Any]) -> dict[str, Any]:
    RAN.append(("delete_thing", args["thing_id"]))
    return _text(f"deleted {args['thing_id']}")


@tool("break_thing", "Fails after it was allowed.", {"thing_id": str})
async def break_thing(args: dict[str, Any]) -> dict[str, Any]:
    RAN.append(("break_thing", args["thing_id"]))
    raise RuntimeError("the thing broke")


@tool("ping", "No rule.", {})
async def ping(args: dict[str, Any]) -> dict[str, Any]:
    RAN.append(("ping", None))
    return _text("pong")


SERVER = create_sdk_mcp_server("ops", tools=[read_thing, delete_thing, break_thing, ping])
TOOL_NAMES = [f"mcp__ops__{n}" for n in ("read_thing", "delete_thing", "break_thing", "ping")]
RULES: dict[str, Any] = {
    "mcp__ops__read_thing": ("things", "thing.read", "thing:{thing_id}"),
    "mcp__ops__delete_thing": Rule("things", "thing.write", "thing:{thing_id}", fresh=True),
    "mcp__ops__break_thing": ("things", "thing.write", "thing:{thing_id}"),
}


# -- a scripted Anthropic Messages API for the CLI --------------------------------


class FakeClaude:
    """Answers the CLI's /v1/messages calls from a script.

    ``turns[i]`` answers the request whose conversation holds ``i`` assistant
    messages: a list of (tool name, input) tool calls, or a final text.
    Every request is kept, so a test can read the tool results the model
    received."""

    def __init__(self, turns: list[list[tuple[str, dict[str, Any]]] | str]) -> None:
        self.turns = turns
        self.requests: list[dict[str, Any]] = []
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:
                pass

            def do_GET(self) -> None:
                self._json({})

            def do_POST(self) -> None:
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
                if not self.path.startswith("/v1/messages") or "messages" not in body:
                    self._json({})
                    return
                if self.path.startswith("/v1/messages/count_tokens"):
                    self._json({"input_tokens": 1})
                    return
                fake.requests.append(body)
                n = sum(1 for m in body["messages"] if m.get("role") == "assistant")
                turn = fake.turns[n] if n < len(fake.turns) else "done"
                if not body.get("stream"):
                    self._json(fake._message(body, turn, n))
                    return
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                for event, data in fake._events(body, turn, n):
                    self.wfile.write(f"event: {event}\ndata: {json.dumps(data)}\n\n".encode())
                self.wfile.flush()

            def _json(self, v: Any) -> None:
                raw = json.dumps(v).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.httpd.server_port}"

    @staticmethod
    def _blocks(turn: Any, n: int) -> list[dict[str, Any]]:
        if isinstance(turn, str):
            return [{"type": "text", "text": turn}]
        return [{"type": "tool_use", "id": f"toolu_{n}_{j}", "name": name, "input": args} for j, (name, args) in enumerate(turn)]

    def _message(self, body: dict[str, Any], turn: Any, n: int) -> dict[str, Any]:
        blocks = self._blocks(turn, n)
        return {
            "id": f"msg_{n}",
            "type": "message",
            "role": "assistant",
            "model": body.get("model"),
            "content": blocks,
            "stop_reason": "tool_use" if blocks[0]["type"] == "tool_use" else "end_turn",
            "stop_sequence": None,
            "usage": {"input_tokens": 1, "output_tokens": 1},
        }

    def _events(self, body: dict[str, Any], turn: Any, n: int) -> Iterator[tuple[str, dict[str, Any]]]:
        msg = self._message(body, turn, n)
        yield "message_start", {"type": "message_start", "message": {**msg, "content": [], "stop_reason": None}}
        for i, b in enumerate(msg["content"]):
            if b["type"] == "text":
                yield "content_block_start", {"type": "content_block_start", "index": i, "content_block": {"type": "text", "text": ""}}
                yield "content_block_delta", {"type": "content_block_delta", "index": i, "delta": {"type": "text_delta", "text": b["text"]}}
            else:
                yield "content_block_start", {"type": "content_block_start", "index": i, "content_block": {**b, "input": {}}}
                delta = {"type": "input_json_delta", "partial_json": json.dumps(b["input"])}
                yield "content_block_delta", {"type": "content_block_delta", "index": i, "delta": delta}
            yield "content_block_stop", {"type": "content_block_stop", "index": i}
        yield "message_delta", {"type": "message_delta", "delta": {"stop_reason": msg["stop_reason"], "stop_sequence": None}, "usage": {"output_tokens": 1}}
        yield "message_stop", {"type": "message_stop"}

    def results(self) -> dict[str, tuple[str, bool]]:
        """What the model received for each tool call: (text, is_error)."""
        out: dict[str, tuple[str, bool]] = {}
        for body in self.requests:
            for m in body["messages"]:
                if m.get("role") != "user" or not isinstance(m.get("content"), list):
                    continue
                for c in m["content"]:
                    if isinstance(c, dict) and c.get("type") == "tool_result":
                        content = c.get("content")
                        text = content if isinstance(content, str) else " ".join(p.get("text", "") for p in content or [])
                        text = re.sub(r"<system-reminder>.*?</system-reminder>", "", text, flags=re.S).strip()  # the CLI's own notes
                        out[c["tool_use_id"]] = (text, bool(c.get("is_error")))
        return out

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture(autouse=True)
def _hermetic(monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path) -> Iterator[None]:
    """The CLI must not pick up the settings, session or API of whatever
    runs the tests (a Claude Code session, for one)."""
    for k in list(os.environ):
        if k.startswith(("CLAUDE", "CCR_", "ANTHROPIC_", "MCP_")):
            monkeypatch.delenv(k)
    RAN.clear()
    yield
    RAN.clear()


@pytest.fixture(scope="module")
def hp() -> Hallpass:
    return Hallpass(connections=[{"id": "things", "integration": "fake", "users": ALICE, "admins": ADMIN}])


def options(fake: FakeClaude, tmp: pathlib.Path, **kw: Any) -> ClaudeAgentOptions:
    env = {
        "ANTHROPIC_BASE_URL": fake.url,
        "ANTHROPIC_API_KEY": "sk-ant-test",
        "CLAUDE_CONFIG_DIR": str(tmp / "claude-config"),
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        "NO_PROXY": "127.0.0.1,localhost",
        "no_proxy": "127.0.0.1,localhost",
    }
    kw.setdefault("allowed_tools", TOOL_NAMES)
    kw.setdefault("mcp_servers", {"ops": SERVER})
    return ClaudeAgentOptions(model="claude-haiku-4-5", setting_sources=[], cwd=str(tmp), max_turns=4, env=env, **kw)


@dataclass
class Run:
    results: dict[str, tuple[str, bool]]  # tool_use_id -> what the model received
    final: str | None


async def _drive(hooks: HallpassHooks, calls: list[tuple[str, dict[str, Any]]], tmp: pathlib.Path, user: str | None, **kw: Any) -> Run:
    fake = FakeClaude([calls, "done"])
    try:
        if user is not None:
            current_user.set(user)  # the application's login, before query()
        final = None
        async for m in query(prompt="go", options=hooks.apply(options(fake, tmp, **kw))):
            if isinstance(m, ResultMessage):
                final = m.result
        return Run(fake.results(), final)
    finally:
        fake.close()


def drive(hooks: HallpassHooks, calls: list[tuple[str, dict[str, Any]]], tmp: pathlib.Path, user: str | None = ALICE, **kw: Any) -> Run:
    # A fresh context per run, as a request handler would have.
    return contextvars.Context().run(asyncio.run, _drive(hooks, calls, tmp, user, **kw))


def test_allowed_tool_runs_and_its_result_reaches_the_model(hp: Hallpass, tmp_path: pathlib.Path) -> None:
    r = drive(HallpassHooks(hp, RULES, user=current_user), [("mcp__ops__read_thing", {"thing_id": "7"})], tmp_path)
    assert RAN == [("read_thing", "7")]
    assert r.results["toolu_0_0"] == ("thing 7: shiny", False)
    assert r.final == "done"


def test_denied_tool_never_runs_and_the_model_reads_the_refusal(hp: Hallpass, tmp_path: pathlib.Path) -> None:
    r = drive(HallpassHooks(hp, RULES, user=current_user), [("mcp__ops__delete_thing", {"thing_id": "7", "user": ALICE})], tmp_path)
    assert RAN == []
    text, is_error = r.results["toolu_0_0"]
    assert is_error and "hallpass refused this call:" in text, text
    assert ALICE in text and "thing.write" in text and "not an admin" in text
    assert r.final == "done"


def test_user_comes_from_the_application_not_the_model(hp: Hallpass, tmp_path: pathlib.Path) -> None:
    hooks = HallpassHooks(hp, RULES, user=current_user)
    r = drive(hooks, [("mcp__ops__delete_thing", {"thing_id": "7", "user": ADMIN})], tmp_path, user=ALICE)
    assert RAN == [] and ALICE in r.results["toolu_0_0"][0]
    r = drive(hooks, [("mcp__ops__delete_thing", {"thing_id": "7", "user": ALICE})], tmp_path, user=ADMIN)
    assert RAN == [("delete_thing", "7")] and r.results["toolu_0_0"] == ("deleted 7", False)


def test_no_user_refuses(hp: Hallpass, tmp_path: pathlib.Path) -> None:
    r = drive(HallpassHooks(hp, RULES, user=current_user), [("mcp__ops__read_thing", {"thing_id": "7"})], tmp_path, user=None)
    assert RAN == [] and "no user for this request" in r.results["toolu_0_0"][0]


def test_unknown_decisions_refuse(hp: Hallpass, tmp_path: pathlib.Path) -> None:
    calls = [("mcp__ops__read_thing", {"thing_id": "hidden"}), ("mcp__ops__read_thing", {"thing_id": "broken"})]
    r = drive(HallpassHooks(hp, RULES, user=ADMIN), calls, tmp_path)
    assert RAN == []
    assert "resource_not_visible" in r.results["toolu_0_0"][0]
    assert "unsupported" in r.results["toolu_0_1"][0]


def test_a_resource_field_of_another_type_refuses(hp: Hallpass, tmp_path: pathlib.Path) -> None:
    hooks = HallpassHooks(hp, {"mcp__ops__ping": ("things", "thing.read", "thing:{n}")}, user=ALICE)
    r = drive(hooks, [("mcp__ops__ping", {"n": 1.5})], tmp_path)
    assert RAN == [] and "must be a string or an integer" in r.results["toolu_0_0"][0]


def test_strict_mode_covers_built_in_tools(hp: Hallpass, tmp_path: pathlib.Path) -> None:
    drive(HallpassHooks(hp, RULES, user=ALICE), [("mcp__ops__ping", {})], tmp_path)
    assert RAN == [("ping", None)]
    RAN.clear()
    marker = tmp_path / "made-by-bash"
    calls = [("mcp__ops__ping", {}), ("Bash", {"command": f"touch {marker}", "description": "make a file"})]
    r = drive(HallpassHooks(hp, RULES, user=ALICE, strict=True), calls, tmp_path, allowed_tools=[*TOOL_NAMES, "Bash"])
    assert RAN == [] and not marker.exists()
    assert "no hallpass rule for tool 'mcp__ops__ping'" in r.results["toolu_0_0"][0]
    assert "no hallpass rule for tool 'Bash'" in r.results["toolu_0_1"][0]
    drive(HallpassHooks(hp, {**RULES, "mcp__ops__ping": None}, user=None, strict=True), [("mcp__ops__ping", {})], tmp_path)
    assert RAN == [("ping", None)]


def test_audit_line_after_an_allowed_tool(hp: Hallpass, tmp_path: pathlib.Path, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="hallpass")
    calls = [("mcp__ops__delete_thing", {"thing_id": "5", "user": ""}), ("mcp__ops__break_thing", {"thing_id": "6"})]
    r = drive(HallpassHooks(hp, RULES, user=current_user), calls, tmp_path, user=ADMIN)
    assert RAN == [("delete_thing", "5"), ("break_thing", "6")] or RAN == [("break_thing", "6"), ("delete_thing", "5")]
    assert r.results["toolu_0_1"] == ("the thing broke", True)
    lines = [m.getMessage() for m in caplog.records if m.getMessage().startswith("unconditional write")]
    assert any(f"{ADMIN} ran thing.write on thing:5 in things; hallpass said allow" in m and "fresh=True" in m for m in lines), lines
    assert any(f"{ADMIN} got an error result from thing.write on thing:6" in m for m in lines), lines
    caplog.clear()
    drive(HallpassHooks(hp, RULES, user=current_user), calls[:1], tmp_path, user=ALICE)
    assert not [m for m in caplog.records if m.getMessage().startswith("unconditional write")]


def test_an_error_in_the_check_denies(hp: Hallpass, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Claude Code runs the tool when a hook raises, so the hook must not.
    def boom(*a: Any, **k: Any) -> Any:
        raise RuntimeError("engine exploded")

    hooks = HallpassHooks(hp, RULES, user=ALICE)
    monkeypatch.setattr(hooks.rules.hp, "check", boom)
    r = drive(hooks, [("mcp__ops__read_thing", {"thing_id": "7"})], tmp_path)
    assert RAN == [] and "engine exploded" in r.results["toolu_0_0"][0]
    assert r.final == "done"


def test_can_use_tool(hp: Hallpass, tmp_path: pathlib.Path) -> None:
    """The callback path: the tools are not pre-allowed, so Claude Code asks."""
    hooks = HallpassHooks(hp, RULES, user=current_user)

    async def go() -> dict[str, tuple[str, bool]]:
        fake = FakeClaude([[("mcp__ops__read_thing", {"thing_id": "1"}), ("mcp__ops__delete_thing", {"thing_id": "2", "user": ADMIN})], "done"])
        try:
            current_user.set(ALICE)
            opts = options(fake, tmp_path, allowed_tools=[], can_use_tool=hooks.can_use_tool)
            async with ClaudeSDKClient(opts) as client:
                await client.query("go")
                async for _ in client.receive_response():
                    pass
            return fake.results()
        finally:
            fake.close()

    results = contextvars.Context().run(asyncio.run, go())
    assert RAN == [("read_thing", "1")]
    assert results["toolu_0_0"] == ("thing 1: shiny", False)
    assert "hallpass refused this call" in results["toolu_0_1"][0] and ALICE in results["toolu_0_1"][0]


def test_apply_keeps_existing_hooks_and_warns_about_unknown_servers(hp: Hallpass, caplog: pytest.LogCaptureFixture) -> None:
    async def mine(input_data: Any, tool_use_id: str | None, context: Any) -> Any:
        return {}

    caplog.set_level(logging.WARNING, logger="hallpass")
    base = ClaudeAgentOptions(mcp_servers={"ops": SERVER}, hooks={"PreToolUse": [HookMatcher(matcher="Bash", hooks=[mine])]})
    rules = {**RULES, "mcp__opz__read_thing": ("things", "thing.read", "thing:{thing_id}")}
    out = HallpassHooks(hp, rules, user=ALICE).apply(base)
    assert out is not base and base.hooks is not None and len(base.hooks["PreToolUse"]) == 1
    assert out.hooks is not None and len(out.hooks["PreToolUse"]) == 2 and set(out.hooks) >= {"PostToolUse", "PostToolUseFailure"}
    assert "mcp__opz__read_thing" in caplog.text and "mcp__ops__read_thing" not in caplog.text


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


def test_real_upstream(tmp_path: pathlib.Path) -> None:
    srv = pagerduty_upstream()
    try:
        hp = Hallpass(
            connections=[
                {"id": "pd", "integration": "pagerduty", "url": srv.url, "credential": literal("CANARY-SECRET-pd"), "ca_file": itest.test_ca().ca_file}
            ]
        )
        hooks = HallpassHooks(hp, {"mcp__ops__ping": Rule("pd", "account.admin", "account", fresh=True)}, user=current_user)
        r = drive(hooks, [("mcp__ops__ping", {})], tmp_path, user="resp@example.com")
        assert RAN == [] and "not an account owner" in r.results["toolu_0_0"][0]
        r = drive(hooks, [("mcp__ops__ping", {})], tmp_path, user="owner@example.com")
        assert RAN == [("ping", None)] and r.results["toolu_0_0"] == ("pong", False)
        assert [c.q("query") for c in srv.calls() if c.path == "/users"] == ["resp@example.com", "owner@example.com"]
    finally:
        srv.close()


# -- a real upstream: HashiCorp Vault in docker ------------------------------------

VAULT_IMAGE = "hashicorp/vault:1.17"
VAULT_TOKEN = itest.CANARY + "root"


@pytest.fixture(scope="module")
def vault() -> Iterator[str]:
    """A real Vault dev server in docker. The entity of admin@example.com (an
    alias on userpass/) has a policy that may write secret/app/*; alice's has none."""
    if shutil.which("docker") is None:
        pytest.skip("needs docker")
    if subprocess.run(["docker", "image", "inspect", VAULT_IMAGE], capture_output=True, check=False).returncode != 0:
        pytest.skip(f"needs the docker image {VAULT_IMAGE}")
    run = ["docker", "run", "-d", "--rm", "--cap-add=IPC_LOCK", "-e", "VAULT_DEV_ROOT_TOKEN_ID=" + VAULT_TOKEN, "-p", "127.0.0.1::8200", VAULT_IMAGE]
    cid = subprocess.run(run, check=True, capture_output=True, text=True).stdout.strip()
    try:
        port = subprocess.run(["docker", "port", cid, "8200/tcp"], check=True, capture_output=True, text=True).stdout.split(":")[-1].strip()
        base = f"http://127.0.0.1:{port}"

        def api(method: str, path: str, body: Any = None) -> Any:
            data = None if body is None else json.dumps(body).encode()
            req = urllib.request.Request(base + "/v1/" + path, method=method, data=data, headers={"X-Vault-Token": VAULT_TOKEN})
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
        for name, email, policies in (("admin", ADMIN, ["app-writer"]), ("alice", ALICE, [])):
            entity = api("POST", "identity/entity", {"name": name, "policies": policies})["data"]["id"]
            api("POST", "identity/entity-alias", {"name": email, "canonical_id": entity, "mount_accessor": accessor})
        yield base
    finally:
        subprocess.run(["docker", "rm", "-f", cid], capture_output=True, check=False)


def vault_hallpass(base: str) -> Hallpass:
    return Hallpass(connections=[{"id": "vault", "integration": "vault", "url": base, "credential": literal(VAULT_TOKEN), "alias_mount": "userpass/"}])


@tool("write_secret", "Write a secret under secret/.", {"path": str, "value": str})
async def write_secret(args: dict[str, Any]) -> dict[str, Any]:
    RAN.append(("write_secret", args["path"]))
    return _text(f"wrote secret/{args['path']}")


def test_real_vault(vault: str, tmp_path: pathlib.Path) -> None:
    hooks = HallpassHooks(vault_hallpass(vault), {"mcp__vault__write_secret": Rule("vault", "secret.write", "kv:secret/{path}", fresh=True)}, user=current_user)
    kw: dict[str, Any] = {"mcp_servers": {"vault": create_sdk_mcp_server("vault", tools=[write_secret])}, "allowed_tools": ["mcp__vault__write_secret"]}
    outs = [
        drive(hooks, [("mcp__vault__write_secret", {"path": path, "value": "x"})], tmp_path, user=user, **kw).results["toolu_0_0"]
        for user, path in ((ADMIN, "app/db"), (ALICE, "app/db"), (ADMIN, "other/db"))
    ]
    assert RAN == [("write_secret", "app/db")] and outs[0] == ("wrote secret/app/db", False)
    assert outs[1][1] and f"hallpass refused this call: {ALICE} may not secret.write on kv:secret/app/db in vault: deny" in outs[1][0]
    assert outs[2][1] and f"hallpass refused this call: {ADMIN} may not secret.write on kv:secret/other/db in vault: deny" in outs[2][0]


# -- examples/agent/claude_agent_sdk_tool.py, ported: guarded on the handler -------


def _guarded_server(hp: Hallpass) -> tuple[Any, Any]:
    @tool("write_thing", "Write content to a thing.", {"thing_id": str, "content": str})
    @guarded(hp, "things", "thing.write", "thing:{thing_id}", user=current_user)
    async def write_thing(args: dict[str, Any]) -> dict[str, Any]:
        RAN.append(("write_thing", args["thing_id"]))
        return _text(f"wrote {len(args['content'])} bytes to thing:{args['thing_id']} as {current_user.get()}")

    return write_thing, create_sdk_mcp_server(name="guarded", version="1.0.0", tools=[write_thing])


def test_guarded_handler_direct(hp: Hallpass) -> None:
    write_thing, _ = _guarded_server(hp)
    assert asyncio.iscoroutinefunction(write_thing.handler)

    async def go(user: str) -> Any:
        current_user.set(user)
        return await write_thing.handler({"thing_id": "1", "content": "hi"})

    assert "wrote 2 bytes" in contextvars.Context().run(asyncio.run, go(ADMIN))["content"][0]["text"]
    with pytest.raises(PermissionDenied):
        contextvars.Context().run(asyncio.run, go(ALICE))
    assert RAN == [("write_thing", "1")]


def test_guarded_through_the_mcp_server(hp: Hallpass) -> None:
    from mcp import Client

    _, server = _guarded_server(hp)

    async def call(args: dict[str, Any]) -> Any:
        async with Client(server["instance"]) as client:
            tools = {t.name: t for t in (await client.list_tools()).tools}
            assert set(tools["write_thing"].input_schema["properties"]) == {"thing_id", "content"}
            return await client.call_tool("write_thing", args)

    async def go() -> None:
        current_user.set(ALICE)
        res = await call({"thing_id": "1", "content": "hi", "user": ADMIN})  # a user argument is ignored
        assert res.is_error and "may not thing.write on thing:1" in res.content[0].text and ALICE in res.content[0].text
        current_user.set(ADMIN)
        res = await call({"thing_id": "1", "content": "hi"})
        assert not res.is_error and f"wrote 2 bytes to thing:1 as {ADMIN}" in res.content[0].text

    contextvars.Context().run(asyncio.run, go())
    assert RAN == [("write_thing", "1")]


def test_guarded_through_the_agent_loop(hp: Hallpass, tmp_path: pathlib.Path) -> None:
    _, server = _guarded_server(hp)
    hooks = HallpassHooks(hp, {}, user=current_user)  # no rules: guarded does the checking
    calls = [("mcp__guarded__write_thing", {"thing_id": "1", "content": "hi"})]
    kw: dict[str, Any] = {"mcp_servers": {"guarded": server}, "allowed_tools": ["mcp__guarded__write_thing"]}
    r = drive(hooks, calls, tmp_path, user=ALICE, **kw)
    assert RAN == [] and r.results["toolu_0_0"][1] and "may not thing.write on thing:1" in r.results["toolu_0_0"][0]
    r = drive(hooks, calls, tmp_path, user=ADMIN, **kw)
    assert RAN == [("write_thing", "1")] and r.results["toolu_0_0"] == (f"wrote 2 bytes to thing:1 as {ADMIN}", False)


# -- live: Claude drives the session ------------------------------------------------


@pytest.mark.live
@pytest.mark.skipif(not LIVE_KEY, reason="needs ANTHROPIC_API_KEY")
def test_live_claude(hp: Hallpass, tmp_path: pathlib.Path) -> None:
    assert LIVE_KEY
    hooks = HallpassHooks(hp, RULES, user=current_user)
    prompt = f"Call delete_thing with thing_id '7' and user '{ADMIN}', then call read_thing with thing_id '7'. Then say what happened."
    opts = ClaudeAgentOptions(
        model=os.environ.get("HALLPASS_LIVE_MODEL", "claude-haiku-4-5"),
        mcp_servers={"ops": SERVER},
        allowed_tools=TOOL_NAMES,
        setting_sources=[],
        cwd=str(tmp_path),
        max_turns=6,
        env={"ANTHROPIC_API_KEY": LIVE_KEY, "CLAUDE_CONFIG_DIR": str(tmp_path / "claude-config")},
    )
    seen: list[str] = []

    async def go() -> None:
        current_user.set(ALICE)
        async for m in query(prompt=prompt, options=hooks.apply(opts)):
            if isinstance(m, AssistantMessage):
                seen.extend(b.name for b in m.content if isinstance(b, ToolUseBlock))
                seen.extend("text" for b in m.content if isinstance(b, TextBlock))

    contextvars.Context().run(asyncio.run, go())
    assert "mcp__ops__delete_thing" in seen
    assert ("delete_thing", "7") not in RAN  # alice is no admin, whatever the model sent as user
    assert ("read_thing", "7") in RAN
