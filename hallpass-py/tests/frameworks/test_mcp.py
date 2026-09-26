"""hallpass.mcp with a real MCP client talking to a real MCPServer.

Transports: in-memory (``Client(server)``), stdio (the example server as a
subprocess) and Streamable HTTP with bearer-token auth (uvicorn on a local
port), where the user comes from the verified access token. The client is
driven by a scripted loop that makes the tool calls a model would; the tools
are real functions, and hallpass is a real in-process engine on the fake
integration, plus one test against a fake PagerDuty upstream over TLS. The
live test lets a real Claude model pick the calls through the Anthropic API.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import sys
import threading
import time
from collections.abc import Iterator, Sequence
from contextvars import ContextVar
from typing import Any

import pytest

pytest.importorskip("mcp.server.mcpserver")

from mcp import Client
from mcp.client.stdio import StdioServerParameters
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp_types import CallToolResult

from hallpass import Hallpass, literal
from hallpass.mcp import HallpassMiddleware, Rule, guard
from tests import harness

ADMIN = "admin@example.com"
DANA = "dana@example.com"
WRITE = ("demo", "thing.write", "thing:{thing_id}")
REFUSED = "hallpass refused this call: "
EXAMPLES = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "examples")


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
def fw_mcp_hp() -> RecordingHallpass:
    return recording(
        [
            {"id": "demo", "integration": "fake", "users": DANA, "admins": ADMIN},
            {"id": "down", "integration": "fake", "users": DANA, "admins": ADMIN, "fail": "upstream_timeout"},
        ]
    )


RAN: list[str] = []


@pytest.fixture(autouse=True)
def fw_mcp_ran() -> Iterator[list[str]]:
    RAN.clear()
    yield RAN
    RAN.clear()


def make_server(**kw: Any) -> MCPServer[Any]:
    """A server with the tools every test uses."""
    server: MCPServer[Any] = MCPServer("fw-mcp-test", **kw)

    @server.tool()
    def write_thing(thing_id: str, content: str) -> str:
        """Write content to a thing."""
        RAN.append("write_thing:" + thing_id)
        return f"wrote {len(content)} bytes to thing:{thing_id}"

    @server.tool()
    async def async_write_thing(thing_id: str, content: str) -> str:
        """Write content to a thing, asynchronously."""
        await asyncio.sleep(0)
        RAN.append("async_write_thing:" + thing_id)
        return f"wrote {len(content)} bytes to thing:{thing_id}"

    @server.tool()
    def read_thing(thing_id: str) -> str:
        """Read a thing."""
        RAN.append("read_thing:" + thing_id)
        return "contents of thing:" + thing_id

    @server.tool()
    def number_thing(n: int) -> str:
        """Write to a numbered thing."""
        RAN.append(f"number_thing:{n!r}")
        return f"wrote thing:{n!r}"

    @server.tool()
    def default_thing(content: str, thing_id: str = "1") -> str:
        """Write to a thing that has a default."""
        RAN.append("default_thing:" + thing_id)
        return "wrote thing:" + thing_id

    @server.tool()
    def broken_thing(thing_id: str) -> str:
        """Fail after starting a write."""
        raise ValueError("boom")

    @server.tool()
    def failing_thing(thing_id: str) -> str:
        """Report a failure to the client."""
        raise ToolError("the thing is locked")

    return server


def text(res: CallToolResult) -> str:
    [block] = res.content
    return str(block.text)  # type: ignore[union-attr]


async def drive(client: Client, calls: Sequence[tuple[str, dict[str, Any]]]) -> list[CallToolResult]:
    """The scripted model: make each call over MCP and hand back what the client got."""
    return [await client.call_tool(name, args) for name, args in calls]


def run(server: Any, calls: Sequence[tuple[str, dict[str, Any]]]) -> list[CallToolResult]:
    async def go() -> list[CallToolResult]:
        async with Client(server) as client:
            return await drive(client, calls)

    return asyncio.run(go())


def writes(records: list[logging.LogRecord]) -> list[str]:
    return [r.getMessage() for r in records if r.name == "hallpass" and "unconditional write" in r.getMessage()]


# -- in-memory ------------------------------------------------------------------------


def test_allow_runs_the_tool(fw_mcp_hp: RecordingHallpass) -> None:
    server = make_server()
    guard(server, fw_mcp_hp, {"write_thing": WRITE}, user=ADMIN)
    [res] = run(server, [("write_thing", {"thing_id": "1", "content": "hi"})])
    assert (res.is_error, text(res)) == (False, "wrote 2 bytes to thing:1")
    assert RAN == ["write_thing:1"]
    assert fw_mcp_hp.seen == [{"user": ADMIN, "connection": "demo", "action": "thing.write", "resource": "thing:1", "groups": None, "fresh": False}]


def test_deny_and_unknown_do_not_run(fw_mcp_hp: RecordingHallpass) -> None:
    cases = [
        (DANA, "write_thing", "1", "dana@example.com may not thing.write on thing:1 in demo: deny (denied: dana@example.com is not an admin)"),
        ("eve@example.com", "write_thing", "1", "eve@example.com may not thing.write on thing:1 in demo: deny (user_not_found: "),
        (ADMIN, "write_thing", "hidden", "admin@example.com may not thing.write on thing:hidden in demo: unknown (resource_not_visible: "),
        (ADMIN, "async_write_thing", "1", "admin@example.com may not thing.write on thing:1 in down: unknown (upstream_timeout: "),
    ]
    for user, name, thing, want in cases:
        server = make_server()
        guard(server, fw_mcp_hp, {"write_thing": WRITE, "async_write_thing": ("down", "thing.write", "thing:{thing_id}")}, user=user)
        [res] = run(server, [(name, {"thing_id": thing, "content": "hi"})])
        assert res.is_error, (user, thing)
        assert text(res).startswith(REFUSED + want), text(res)
    assert RAN == [], "a refused tool's body never runs"
    assert len(fw_mcp_hp.seen) == len(cases)


def test_model_cannot_choose_the_user(fw_mcp_hp: RecordingHallpass) -> None:
    server = make_server()
    guard(server, fw_mcp_hp, {"write_thing": WRITE}, user=DANA)

    async def go() -> tuple[Any, list[CallToolResult]]:
        async with Client(server) as client:
            tools = {t.name: t for t in (await client.list_tools()).tools}
            return tools, await drive(client, [("write_thing", {"thing_id": "1", "content": "hi", "user": ADMIN, "user_id": ADMIN})])

    tools, [res] = asyncio.run(go())
    assert set(tools["write_thing"].input_schema["properties"]) == {"thing_id", "content"}
    assert res.is_error
    assert [s["user"] for s in fw_mcp_hp.seen] == [DANA]
    assert RAN == []


def test_user_sources(fw_mcp_hp: RecordingHallpass) -> None:
    call = [("write_thing", {"thing_id": "1", "content": "hi"})]
    current_user: ContextVar[str] = ContextVar("fw_mcp_user")
    current_user.set(ADMIN)
    for source in (current_user, lambda: ADMIN):
        server = make_server()
        guard(server, fw_mcp_hp, {"write_thing": WRITE}, user=source)
        [res] = run(server, call)
        assert not res.is_error, text(res)
    unset: ContextVar[str] = ContextVar("fw_mcp_unset")
    for kw, want in (
        ({}, "no user for this request: the request carries no access token"),
        ({"user": unset}, "no user for this request: no user set for this session in ContextVar 'fw_mcp_unset'"),
        ({"user": ""}, "no user for this request"),
        ({"user": lambda: None}, "no user for this request"),
    ):
        server = make_server()
        guard(server, fw_mcp_hp, {"write_thing": WRITE}, **kw)
        [res] = run(server, call)
        assert (res.is_error, text(res)) == (True, REFUSED + want)
    assert RAN == ["write_thing:1", "write_thing:1"]
    assert len(fw_mcp_hp.seen) == 2


def test_unfillable_resource_denies(fw_mcp_hp: RecordingHallpass) -> None:
    server = make_server()
    guard(server, fw_mcp_hp, {"write_thing": WRITE}, user=ADMIN)
    results = run(
        server,
        [
            ("write_thing", args)
            for args in (
                {"content": "hi"},
                {"thing_id": {"nested": "1"}, "content": "hi"},
                {"thing_id": ["1"], "content": "hi"},
                {"thing_id": 7, "content": "hi"},
            )
        ],
    )
    for res in results:
        assert res.is_error and text(res).startswith(REFUSED + "cannot build the resource 'thing:{thing_id}' for write_thing"), text(res)
    assert fw_mcp_hp.seen == [] and RAN == []


def test_resource_is_what_the_tool_gets(fw_mcp_hp: RecordingHallpass) -> None:
    server = make_server()
    guard(server, fw_mcp_hp, {"number_thing": ("demo", "thing.write", "thing:{n}"), "default_thing": WRITE}, user=ADMIN)
    [ok, *coerced, default] = run(
        server,
        [("number_thing", {"n": 7}), *[("number_thing", {"n": n}) for n in ("7", "07", 7.0, True)], ("default_thing", {"content": "hi"})],
    )
    assert (ok.is_error, text(ok)) == (False, "wrote thing:7")
    # pydantic would turn each of these into 7, so the check would be for another resource.
    for res in coerced:
        assert res.is_error and "'n' must be a JSON integer, not " in text(res)
    # A parameter the model leaves out is filled from the tool's default, as the tool is.
    assert not default.is_error
    assert [s["resource"] for s in fw_mcp_hp.seen] == ["thing:7", "thing:1"]
    assert RAN == ["number_thing:7", "default_thing:1"]


def test_tools_without_a_rule(fw_mcp_hp: RecordingHallpass) -> None:
    call = [("read_thing", {"thing_id": "1"})]
    server = make_server()
    guard(server, fw_mcp_hp, {"write_thing": WRITE}, user=DANA)
    [res] = run(server, call)
    assert (res.is_error, text(res)) == (False, "contents of thing:1")
    strict = make_server()
    guard(strict, fw_mcp_hp, {"write_thing": WRITE}, user=DANA, strict=True)
    [res] = run(strict, [*call, ("no_such_tool", {})])[:1]
    assert (res.is_error, text(res)) == (True, REFUSED + "no hallpass rule for tool 'read_thing'")
    allowed = make_server()
    guard(allowed, fw_mcp_hp, {"write_thing": WRITE, "read_thing": None}, strict=True)
    [res] = run(allowed, call)
    assert not res.is_error
    assert fw_mcp_hp.seen == []
    assert RAN == ["read_thing:1", "read_thing:1"]


def test_groups_and_fresh(fw_mcp_hp: RecordingHallpass) -> None:
    server = make_server()
    guard(server, fw_mcp_hp, {"write_thing": Rule(*WRITE, fresh=True)}, user=ADMIN, groups=["platform-team"])
    [res] = run(server, [("write_thing", {"thing_id": "1", "content": "hi"})])
    assert not res.is_error
    assert fw_mcp_hp.seen == [{"user": ADMIN, "connection": "demo", "action": "thing.write", "resource": "thing:1", "groups": ["platform-team"], "fresh": True}]
    bad_groups: list[Any] = ["platform-team", lambda: None, lambda: [1]]
    for groups in bad_groups:
        server = make_server()
        guard(server, fw_mcp_hp, {"write_thing": WRITE}, user=ADMIN, groups=groups)
        [res] = run(server, [("write_thing", {"thing_id": "1", "content": "hi"})])
        assert res.is_error and "no groups for this request" in text(res), text(res)
    assert len(fw_mcp_hp.seen) == 1


def test_async_tool(fw_mcp_hp: RecordingHallpass) -> None:
    server = make_server()
    guard(server, fw_mcp_hp, {"async_write_thing": WRITE}, user=ContextVar("fw_mcp_async_user", default=ADMIN))
    [ok] = run(server, [("async_write_thing", {"thing_id": "1", "content": "hi"})])
    assert (ok.is_error, text(ok)) == (False, "wrote 2 bytes to thing:1")
    assert RAN == ["async_write_thing:1"]


def test_logs_unconditional_write(fw_mcp_hp: RecordingHallpass, caplog: pytest.LogCaptureFixture) -> None:
    server = make_server()
    guard(server, fw_mcp_hp, {"write_thing": WRITE, "broken_thing": WRITE, "failing_thing": WRITE}, user=ADMIN)
    caplog.set_level(logging.INFO, logger="hallpass")
    run(server, [("write_thing", {"thing_id": "1", "content": "hi"})])
    [line] = writes(caplog.records)
    for part in (
        "unconditional write",
        ADMIN,
        "ran thing.write on thing:1 in demo",
        "hallpass said allow (allowed: admin@example.com is an admin)",
        "fresh=False",
    ):
        assert part in line
    for tool, want in (("broken_thing", "Error executing tool broken_thing"), ("failing_thing", "the thing is locked")):
        caplog.clear()
        [res] = run(server, [(tool, {"thing_id": "1"})])
        assert res.is_error and want in text(res)
        [line] = writes(caplog.records)
        assert "got an error result from thing.write on thing:1" in line
    caplog.clear()
    denied = make_server()
    guard(denied, fw_mcp_hp, {"write_thing": WRITE}, user=DANA)
    run(denied, [("write_thing", {"thing_id": "1", "content": "hi"})])
    assert writes(caplog.records) == []


def test_warns_about_rules_for_missing_tools(fw_mcp_hp: RecordingHallpass, caplog: pytest.LogCaptureFixture) -> None:
    server = make_server()
    guard(server, fw_mcp_hp, {"write_thing": WRITE, "wrte_thing": WRITE}, user=ADMIN)
    caplog.set_level(logging.WARNING, logger="hallpass")
    run(server, [("read_thing", {"thing_id": "1"}), ("read_thing", {"thing_id": "2"})])
    warnings = [r.getMessage() for r in caplog.records if r.name == "hallpass" and r.levelno == logging.WARNING]
    assert len(warnings) == 1 and "wrte_thing" in warnings[0]


def test_check_error_refuses() -> None:
    class Broken(Hallpass):
        def check(self, *a: Any, **kw: Any) -> Any:
            raise RuntimeError("client blew up")

    server = make_server()
    guard(server, Broken(connections=[{"id": "demo", "integration": "fake", "admins": ADMIN}]), {"write_thing": WRITE}, user=ADMIN)
    [res] = run(server, [("write_thing", {"thing_id": "1", "content": "hi"})])
    assert (res.is_error, text(res)) == (True, REFUSED + "the hallpass check failed: RuntimeError: client blew up")
    assert RAN == []


def test_bad_arguments(fw_mcp_hp: RecordingHallpass) -> None:
    server = make_server()
    mw = guard(server, fw_mcp_hp, {"write_thing": WRITE}, user=ADMIN)
    assert server.middleware[-1] is mw
    for rules in ({"t": ("demo", "thing.write")}, {"t": ("demo", "", "thing:{x}")}, {"t": "demo"}):
        with pytest.raises(TypeError):
            guard(make_server(), fw_mcp_hp, rules)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        guard(make_server(), fw_mcp_hp, {"t": ("demo", "thing.write", "thing:{x.y}")})
    with pytest.raises(TypeError):
        HallpassMiddleware(object(), fw_mcp_hp, {})  # type: ignore[arg-type]


# -- stdio: the example server as a subprocess ---------------------------------------------


def test_stdio_example_server() -> None:
    async def go(user: str) -> list[CallToolResult]:
        params = StdioServerParameters(
            command=sys.executable,
            args=[os.path.join(EXAMPLES, "mcp_server.py")],
            env={"AGENT_USER": user, "PYTHONPATH": os.pathsep.join(p for p in sys.path if p)},
        )
        async with Client(params) as client:
            return await drive(
                client,
                [("write_thing", {"thing_id": "1", "content": "hi", "user": ADMIN}), ("read_thing", {"thing_id": "1"})],
            )

    admin_write, admin_read = asyncio.run(go(ADMIN))
    assert (admin_write.is_error, text(admin_write)) == (False, "wrote 2 bytes to thing:1")
    assert (admin_read.is_error, text(admin_read)) == (False, "contents of thing:1")
    dana_write, dana_read = asyncio.run(go(DANA))
    assert dana_write.is_error
    assert text(dana_write) == REFUSED + "dana@example.com may not thing.write on thing:1 in demo: deny (denied: dana@example.com is not an admin)"
    assert not dana_read.is_error


# -- Streamable HTTP with bearer-token auth: the user from the access token --------------------


class Tokens:
    """A token verifier: each bearer token names one user, in its claims."""

    def __init__(self, tokens: dict[str, dict[str, Any]]) -> None:
        self.tokens = tokens

    async def verify_token(self, token: str) -> AccessToken | None:
        claims = self.tokens.get(token)
        if claims is None:
            return None
        return AccessToken(token=token, client_id="fw-mcp-client", scopes=[], subject=claims.get("sub"), claims=claims)


@pytest.fixture
def fw_mcp_http(fw_mcp_hp: RecordingHallpass) -> Iterator[str]:
    uvicorn = pytest.importorskip("uvicorn")
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    url = f"http://127.0.0.1:{port}/mcp"
    tokens = Tokens(
        {
            "admin-token": {"sub": "u-admin", "email": ADMIN, "groups": ["platform-team"]},
            "dana-token": {"sub": "u-dana", "email": DANA, "groups": ["platform-team"]},
            "no-email-token": {"sub": "u-nobody"},
        }
    )
    server = make_server(
        token_verifier=tokens,
        auth=AuthSettings(issuer_url="https://auth.example.com", resource_server_url=url, validate_token_resource=False),  # type: ignore[arg-type]
    )
    guard(server, fw_mcp_hp, {"write_thing": WRITE}, groups_claim="groups")
    srv = uvicorn.Server(uvicorn.Config(server.streamable_http_app(), host="127.0.0.1", port=port, log_level="warning"))
    t = threading.Thread(target=srv.run, daemon=True)
    t.start()
    deadline = time.monotonic() + 10
    while not srv.started:
        assert time.monotonic() < deadline, "uvicorn did not start"
        time.sleep(0.02)
    yield url
    srv.should_exit = True
    t.join(5)


def test_http_user_from_access_token(fw_mcp_http: str, fw_mcp_hp: RecordingHallpass) -> None:
    import httpx2
    from mcp.client.streamable_http import streamable_http_client

    async def call(token: str) -> CallToolResult:
        async with httpx2.AsyncClient(headers={"Authorization": "Bearer " + token}) as http:
            async with Client(streamable_http_client(fw_mcp_http, http_client=http)) as client:
                [res] = await drive(client, [("write_thing", {"thing_id": "1", "content": "hi", "user": ADMIN})])
                return res

    async def both() -> list[CallToolResult]:
        # Concurrent sessions for two users: each call is checked as its own token's user.
        return list(await asyncio.gather(call("admin-token"), call("dana-token")))

    admin, dana = asyncio.run(both())
    assert (admin.is_error, text(admin)) == (False, "wrote 2 bytes to thing:1")
    assert dana.is_error and text(dana).startswith(REFUSED + "dana@example.com may not thing.write on thing:1")
    assert sorted((s["user"], tuple(s["groups"])) for s in fw_mcp_hp.seen) == [(ADMIN, ("platform-team",)), (DANA, ("platform-team",))]
    [nobody] = [asyncio.run(call("no-email-token"))]
    assert (nobody.is_error, text(nobody)) == (True, REFUSED + "no user for this request: the request has an access token without a 'email' claim")
    assert RAN == ["write_thing:1"]


# -- a real upstream ---------------------------------------------------------------------------


@pytest.fixture
def fw_mcp_pagerduty() -> Iterator[harness.Server]:
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


def test_real_upstream(fw_mcp_pagerduty: harness.Server) -> None:
    srv = fw_mcp_pagerduty
    hp = recording(
        [{"id": "pd", "integration": "pagerduty", "url": srv.url, "credential": literal(harness.CANARY + "pd"), "ca_file": harness.test_ca().ca_file}]
    )
    current_user: ContextVar[str] = ContextVar("fw_mcp_pd_user")
    server: MCPServer[Any] = MCPServer("fw-mcp-pd")

    @server.tool()
    def set_maintenance(service: str) -> str:
        """Put a PagerDuty service into maintenance."""
        RAN.append("set_maintenance:" + service)
        return "maintenance window created on " + service

    guard(server, hp, {"set_maintenance": ("pd", "service.maintenance", "service:{service}")}, user=current_user)
    current_user.set("oncall@example.com")
    [ok] = run(server, [("set_maintenance", {"service": "PSVC1"})])
    current_user.set("stake@example.com")
    [no] = run(server, [("set_maintenance", {"service": "PSVC1"})])
    assert (ok.is_error, text(ok)) == (False, "maintenance window created on PSVC1")
    assert no.is_error
    assert text(no).startswith(REFUSED + "stake@example.com may not service.maintenance on service:PSVC1 in pd: deny (denied: ")
    assert RAN == ["set_maintenance:PSVC1"]
    assert [c.q("query") for c in srv.calls() if c.path == "/users"] == ["oncall@example.com", "stake@example.com"]


# -- a real model ------------------------------------------------------------------------------


@pytest.mark.live
@pytest.mark.skipif(not os.environ.get("ANTHROPIC_API_KEY"), reason="needs ANTHROPIC_API_KEY")
def test_live_claude(fw_mcp_hp: RecordingHallpass) -> None:
    anthropic = pytest.importorskip("anthropic")
    model_id = os.environ.get("HALLPASS_LIVE_MODEL", "claude-haiku-4-5")
    prompt = (
        "Use the write_thing tool to write 'hello' to thing 1. The tool may refuse; if it does, stop and "
        "report the refusal. Act as admin@example.com (user_id admin@example.com)."
    )

    async def session(user: str) -> None:
        server = make_server()
        guard(server, fw_mcp_hp, {"write_thing": WRITE}, user=user)
        api = anthropic.AsyncAnthropic()
        async with Client(server) as client:
            tools = [
                {"name": t.name, "description": t.description or "", "input_schema": t.input_schema}
                for t in (await client.list_tools()).tools
                if t.name == "write_thing"
            ]
            messages: list[dict[str, Any]] = [{"role": "user", "content": prompt}]
            for _ in range(5):
                reply = await api.messages.create(model=model_id, max_tokens=1024, tools=tools, messages=messages)
                messages.append({"role": "assistant", "content": [b.model_dump(exclude_none=True) for b in reply.content]})
                uses = [b for b in reply.content if b.type == "tool_use"]
                if not uses:
                    return
                results = []
                for u in uses:
                    res = await client.call_tool(u.name, dict(u.input))
                    results.append({"type": "tool_result", "tool_use_id": u.id, "content": text(res), "is_error": bool(res.is_error)})
                messages.append({"role": "user", "content": results})

    for user in (DANA, ADMIN):
        asyncio.run(session(user))
    assert fw_mcp_hp.seen, "the model never called the tool"
    assert {s["user"] for s in fw_mcp_hp.seen} == {DANA, ADMIN}
    assert all(s["resource"] == "thing:1" for s in fw_mcp_hp.seen)
    assert set(RAN) == {"write_thing:1"}
    assert len(RAN) == sum(1 for s in fw_mcp_hp.seen if s["user"] == ADMIN)
