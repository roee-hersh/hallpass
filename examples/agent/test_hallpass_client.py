"""Tests for the agent examples against a fake hallpass.

    python3 -m unittest discover -s examples/agent -v

The client tests need only the standard library. Each framework's test runs
when its package is installed and skips otherwise; with
HALLPASS_EXAMPLE_REQUIRE_DEPS=1 (CI) a missing package fails instead.
"""

from __future__ import annotations

import asyncio
import http.server
import json
import os
import socket
import sys
import threading
import unittest
from contextvars import ContextVar

sys.path.insert(0, os.path.dirname(__file__))

from hallpass_client import Decision, Hallpass, PermissionDenied, guarded  # noqa: E402

API_KEY = "test-key"
DANA = "dana@example.com"

# What the fake answers per resource id. (status, body)
ANSWERS = {
    "allowed": (200, {"decision": "allow", "reason": "allowed: admin"}),
    "denied": (200, {"decision": "deny", "reason": "denied: not an admin"}),
    "nobody": (200, {"decision": "deny", "reason": "user_not_found: no account"}),
    "timeout": (200, {"decision": "unknown", "reason": "upstream_timeout: jira took too long"}),
    "badreq": (400, {"decision": "unknown", "reason": "unknown_action: no such action"}),
    "garbage": (200, b"<html>not json</html>"),
    "weird": (200, {"decision": "maybe", "reason": "allowed: ?"}),
    "proxyallow": (502, {"decision": "allow", "reason": "allowed: from a broken proxy"}),
    "boom": (500, b"internal error"),
    "redirect": (302, {"decision": "allow", "reason": "allowed: from the redirect itself"}),
    "badline": None,  # the fake writes a non-HTTP response
    "short": None,  # the fake announces more bytes than it sends
}


class FakeHallpass(http.server.BaseHTTPRequestHandler):
    seen: list[dict] = []

    def log_message(self, *a):  # keep test output quiet
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        FakeHallpass.seen.append({"headers": dict(self.headers), "body": body})
        thing = body["resource"].split(":", 1)[1]
        if thing == "badline":
            self.wfile.write(b"garbage\r\n\r\n")
            self.close_connection = True
            return
        if thing == "short":
            self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n{\"decision\":\"allow\"}")
            self.close_connection = True
            return
        if self.headers.get("Authorization") != "Bearer " + API_KEY:
            status, ans = 401, {"decision": "unknown", "reason": "unauthorized: missing or wrong API key"}
        else:
            status, ans = ANSWERS[thing]
        raw = ans if isinstance(ans, bytes) else json.dumps(ans).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        if status == 302:
            # An allow at the other end of a redirect must not count.
            self.send_header("Location", "http://127.0.0.1:%d/check" % SINK.server_address[1])
        self.end_headers()
        self.wfile.write(raw)


class Sink(http.server.BaseHTTPRequestHandler):
    """Where the redirect points. Answers allow to anything and records the request."""

    seen: list[dict] = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        self.do_POST()

    def do_POST(self):
        Sink.seen.append(dict(self.headers))
        raw = b'{"decision":"allow","reason":"allowed: by the sink"}'
        self.send_response(200)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def serve(handler):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


FAKE = serve(FakeHallpass)
SINK = serve(Sink)
FAKE_URL = "http://127.0.0.1:%d" % FAKE.server_address[1]

# The example modules build their client from the environment at import.
os.environ["HALLPASS_URL"] = FAKE_URL
os.environ["HALLPASS_API_KEY"] = API_KEY
os.environ["AGENT_USER"] = DANA
os.environ["AGENT_GROUPS"] = "platform-team, sre"


def last_request() -> dict:
    return FakeHallpass.seen[-1]["body"]


class ClientTest(unittest.TestCase):
    hp = Hallpass(FAKE_URL, API_KEY, timeout=2)

    def setUp(self):
        FakeHallpass.seen.clear()

    def check(self, thing: str, **kw) -> Decision:
        return self.hp.check(DANA, "demo", "thing.write", "thing:" + thing, **kw)

    def test_allow(self):
        d = self.check("allowed")
        self.assertEqual((d.decision, d.code, d.status), ("allow", "allowed", 200))
        self.assertTrue(d.allowed)

    def test_deny_is_not_allowed(self):
        for thing in ("denied", "nobody"):
            d = self.check(thing)
            self.assertEqual(d.decision, "deny")
            self.assertFalse(d.allowed)
        self.assertEqual(self.check("nobody").code, "user_not_found")

    def test_unknown_is_not_allowed(self):
        d = self.check("timeout")
        self.assertEqual((d.decision, d.code), ("unknown", "upstream_timeout"))
        self.assertFalse(d.allowed)

    def test_400_carries_the_reason(self):
        d = self.check("badreq")
        self.assertEqual((d.decision, d.code, d.status), ("unknown", "unknown_action", 400))
        self.assertFalse(d.allowed)

    def test_wrong_api_key_is_unknown(self):
        d = Hallpass(FAKE_URL, "wrong", timeout=2).check(DANA, "demo", "thing.write", "thing:allowed")
        self.assertEqual((d.decision, d.code, d.status), ("unknown", "unauthorized", 401))
        self.assertFalse(d.allowed)

    def test_unusable_responses_are_unknown(self):
        for thing in ("garbage", "weird", "proxyallow", "boom", "badline", "short"):
            d = self.check(thing)
            self.assertEqual(d.decision, "unknown", thing)
            self.assertEqual(d.code, "client_error", thing)
            self.assertFalse(d.allowed, thing)

    def test_redirect_is_not_followed(self):
        Sink.seen.clear()
        d = self.check("redirect")
        self.assertEqual((d.decision, d.code, d.status), ("unknown", "client_error", 302))
        self.assertFalse(d.allowed)
        self.assertEqual(Sink.seen, [], "the API key must not be sent to the redirect target")

    def test_unreachable_is_unknown(self):
        with socket.socket() as s:  # a port nobody listens on
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        d = Hallpass("http://127.0.0.1:%d" % port, API_KEY, timeout=1).check("u", "demo", "thing.read", "thing:1")
        self.assertEqual((d.decision, d.code, d.status), ("unknown", "client_error", 0))
        self.assertFalse(d.allowed)

    def test_url_rules(self):
        for ok in ("https://hallpass.internal", "http://localhost:8080/", "http://127.0.0.1:1", "http://[::1]:8080"):
            Hallpass(ok, API_KEY)
        for bad in ("http://hallpass.internal", "localhost:8080", "ftp://x", "http://10.0.0.5:8080"):
            with self.assertRaises(ValueError, msg=bad):
                Hallpass(bad, API_KEY)
        self.assertEqual(Hallpass("http://localhost:8080/", API_KEY).url, "http://localhost:8080")

    def test_request_shape(self):
        self.check("allowed", groups=["platform-team"])
        req = FakeHallpass.seen[-1]
        self.assertEqual(req["headers"]["Authorization"], "Bearer " + API_KEY)
        self.assertEqual(req["headers"]["Content-Type"], "application/json")
        self.assertEqual(
            req["body"],
            {"user": DANA, "groups": ["platform-team"], "connection": "demo",
             "action": "thing.write", "resource": "thing:allowed"},
        )
        self.check("allowed")
        self.assertNotIn("groups", last_request(), "groups omitted when not given")
        with self.assertRaises(TypeError):
            self.check("allowed", groups="platform-team")  # a string is not a list of groups

    def test_require_and_allowed(self):
        self.assertTrue(self.hp.allowed("u", "demo", "thing.write", "thing:allowed"))
        self.assertFalse(self.hp.allowed("u", "demo", "thing.write", "thing:timeout"))
        self.hp.require("u", "demo", "thing.write", "thing:allowed")
        with self.assertRaises(PermissionDenied) as cm:
            self.hp.require("u", "demo", "thing.write", "thing:timeout")
        self.assertEqual(cm.exception.decision.code, "upstream_timeout")
        self.assertIn("unknown", str(cm.exception))

    def test_missing_api_key(self):
        env = dict(os.environ)
        os.environ.pop("HALLPASS_API_KEY", None)
        try:
            with self.assertRaises(ValueError):
                Hallpass(FAKE_URL)
        finally:
            os.environ.clear()
            os.environ.update(env)


class GuardedTest(unittest.TestCase):
    hp = Hallpass(FAKE_URL, API_KEY, timeout=2)

    def setUp(self):
        FakeHallpass.seen.clear()

    def test_runs_only_on_allow(self):
        ran = []

        @guarded(self.hp, "demo", "thing.write", "thing:{thing_id}", user=DANA, groups=["platform-team"])
        def write(thing_id: str) -> str:
            ran.append(thing_id)
            return "ok"

        self.assertEqual(write(thing_id="allowed"), "ok")
        for thing in ("denied", "timeout", "garbage", "badline"):
            with self.assertRaises(PermissionDenied):
                write(thing_id=thing)
        self.assertEqual(ran, ["allowed"])
        self.assertEqual(last_request(), {"user": DANA, "groups": ["platform-team"], "connection": "demo",
                                          "action": "thing.write", "resource": "thing:badline"})

    def test_user_is_never_an_argument(self):
        @guarded(self.hp, "demo", "thing.write", "thing:{thing_id}", user=DANA)
        def write(thing_id: str) -> str:
            return "ok"

        import inspect

        self.assertEqual(list(inspect.signature(write).parameters), ["thing_id"])
        with self.assertRaises(TypeError):
            write(thing_id="allowed", user="admin@example.com")  # not a parameter
        with self.assertRaises(TypeError):
            write("allowed")  # positional arguments could bypass the resource template
        self.assertEqual(FakeHallpass.seen, [])
        # In the dict shape an extra "user" key is ignored, not honoured.
        write({"thing_id": "allowed", "user": "admin@example.com"})
        self.assertEqual(last_request()["user"], DANA)

    def test_user_sources(self):
        seen = []

        def make(source, groups=None):
            @guarded(self.hp, "demo", "thing.write", "thing:{thing_id}", user=source, groups=groups)
            def write(thing_id: str) -> str:
                return "ok"

            return write

        make("fixed@example.com")(thing_id="allowed")
        seen.append(last_request())
        make(lambda: "called@example.com", groups=lambda: ["g1"])(thing_id="allowed")
        seen.append(last_request())
        var: ContextVar[str] = ContextVar("u")
        gvar: ContextVar[list] = ContextVar("g")
        var.set("context@example.com")
        gvar.set(["g2"])
        make(var, groups=gvar)(thing_id="allowed")
        seen.append(last_request())
        self.assertEqual([(r["user"], r.get("groups")) for r in seen], [
            ("fixed@example.com", None),
            ("called@example.com", ["g1"]),
            ("context@example.com", ["g2"]),
        ])
        # Nothing set for the session: fail before any request.
        with self.assertRaises(RuntimeError):
            make(ContextVar("unset"))(thing_id="allowed")
        with self.assertRaises(RuntimeError):
            make("")(thing_id="allowed")
        with self.assertRaises(TypeError):
            make(DANA, groups="platform-team")(thing_id="allowed")
        self.assertEqual(len(FakeHallpass.seen), 3)

    def test_dict_shape(self):
        @guarded(self.hp, "demo", "thing.write", "thing:{thing_id}", user=DANA)
        def write(args: dict) -> str:
            return "wrote " + args["thing_id"]

        self.assertEqual(write({"thing_id": "allowed", "content": "x"}), "wrote allowed")
        self.assertEqual(last_request()["resource"], "thing:allowed")
        with self.assertRaises(PermissionDenied):
            write({"thing_id": "denied"})
        with self.assertRaises(KeyError):
            write({"content": "no thing_id"})  # cannot form the resource: no request, no action
        self.assertEqual(len(FakeHallpass.seen), 2)

    def test_async(self):
        ran = []

        @guarded(self.hp, "demo", "thing.write", "thing:{thing_id}", user=DANA)
        async def write(thing_id: str) -> str:
            await asyncio.sleep(0)
            ran.append(thing_id)
            return "ok"

        @guarded(self.hp, "demo", "thing.write", "thing:{thing_id}", user=DANA)
        async def write_dict(args: dict) -> str:
            return "ok " + args["thing_id"]

        self.assertEqual(asyncio.run(write(thing_id="allowed")), "ok")
        self.assertEqual(asyncio.run(write_dict({"thing_id": "allowed"})), "ok allowed")
        with self.assertRaises(PermissionDenied):
            asyncio.run(write(thing_id="denied"))
        self.assertEqual(ran, ["allowed"])
        self.assertTrue(asyncio.iscoroutinefunction(write))

    def test_deny_hook(self):
        @guarded(self.hp, "demo", "thing.write", "thing:{thing_id}", user=DANA, deny=lambda e: f"refused: {e}")
        def write(thing_id: str) -> str:
            return "ok"

        self.assertEqual(write(thing_id="allowed"), "ok")
        out = write(thing_id="denied")
        self.assertTrue(out.startswith("refused: dana@example.com may not thing.write on thing:denied"), out)


# Set to 1 where the optional packages are expected (CI), so a missing
# package fails instead of silently skipping.
REQUIRE_DEPS = os.environ.get("HALLPASS_EXAMPLE_REQUIRE_DEPS") == "1"


def optional(module: str, what: str):
    try:
        __import__(module)
    except ImportError:
        if REQUIRE_DEPS:
            raise
        return unittest.skip(what + " not installed")
    return lambda cls: cls


@optional("mcp", "mcp package")
class MCPServerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import mcp_server

        cls.mod = mcp_server

    def setUp(self):
        FakeHallpass.seen.clear()

    def call(self, name: str, **args):
        from mcp import Client

        async def go():
            async with Client(self.mod.mcp) as client:
                names = {t.name for t in (await client.list_tools()).tools}
                self.assertEqual(names, {"check_permission", "write_thing"})
                tool = next(t for t in (await client.list_tools()).tools if t.name == "write_thing")
                self.assertEqual(set(tool.input_schema["properties"]), {"thing_id", "content"})
                return await client.call_tool(name, args)

        return asyncio.run(go())

    def test_check_permission(self):
        res = self.call("check_permission", connection="demo", action="thing.write", resource="thing:timeout")
        self.assertFalse(res.is_error)
        self.assertEqual(res.structured_content["decision"], "unknown")
        self.assertFalse(res.structured_content["allowed"])
        self.assertEqual((last_request()["user"], last_request()["groups"]), (DANA, ["platform-team", "sre"]))

    def test_write_thing(self):
        res = self.call("write_thing", thing_id="allowed", content="hi")
        self.assertIn("wrote 2 bytes", res.content[0].text)
        self.assertEqual(last_request()["groups"], ["platform-team", "sre"])
        for thing in ("denied", "timeout", "badline"):
            res = self.call("write_thing", thing_id=thing, content="hi")
            self.assertFalse(res.is_error)
            self.assertTrue(res.content[0].text.startswith("refused: dana@example.com may not"), res.content[0].text)


@optional("langchain_core", "langchain-core package")
class LangChainToolTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import langchain_tool

        cls.mod = langchain_tool
        langchain_tool.current_user.set(DANA)
        langchain_tool.current_groups.set(["platform-team"])

    def setUp(self):
        FakeHallpass.seen.clear()

    def test_tools(self):
        check, write = self.mod.tools
        self.assertEqual((check.name, write.name), ("check_permission", "write_thing"))
        self.assertEqual(set(write.args), {"thing_id", "content"})
        out = check.invoke({"connection": "demo", "action": "thing.write", "resource": "thing:timeout"})
        self.assertTrue(out.startswith("unknown: upstream_timeout"), out)
        self.assertEqual((last_request()["user"], last_request()["groups"]), (DANA, ["platform-team"]))
        # A model-supplied user is dropped by the framework; the check is still for dana.
        out = write.invoke({"thing_id": "allowed", "content": "hi", "user": "admin@example.com"})
        self.assertIn("wrote 2 bytes to thing:allowed as " + DANA, out)
        self.assertEqual(last_request()["user"], DANA)
        for thing in ("denied", "timeout"):
            out = write.invoke({"thing_id": thing, "content": "hi"})
            self.assertTrue(out.startswith("refused: dana@example.com may not thing.write on thing:" + thing), out)


@optional("langgraph", "langgraph package")
class LangGraphTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from langchain_core.messages import AIMessage
        from langgraph.graph import END, START, MessagesState, StateGraph

        import langgraph_agent

        langgraph_agent.current_user.set(DANA)
        g = StateGraph(MessagesState)
        g.add_node("tools", langgraph_agent.tool_node)
        g.add_edge(START, "tools")
        g.add_edge("tools", END)
        cls.graph = g.compile()
        cls.AIMessage = AIMessage

    def setUp(self):
        FakeHallpass.seen.clear()

    def call(self, name: str, args: dict):
        msg = self.AIMessage(content="", tool_calls=[{"name": name, "args": args, "id": "c1", "type": "tool_call"}])
        out = self.graph.invoke({"messages": [msg]})
        return out["messages"][-1]

    def test_tool_node(self):
        m = self.call("write_thing", {"thing_id": "allowed", "content": "hi", "user": "admin@example.com"})
        self.assertEqual(m.status, "success")
        self.assertIn("wrote 2 bytes to thing:allowed as " + DANA, m.content)
        self.assertEqual(last_request()["user"], DANA)
        m = self.call("write_thing", {"thing_id": "denied", "content": "hi"})
        self.assertTrue(m.content.startswith("refused: dana@example.com may not thing.write on thing:denied"), m.content)
        m = self.call("check_permission", {"connection": "demo", "action": "thing.read", "resource": "thing:timeout"})
        self.assertTrue(m.content.startswith("unknown: upstream_timeout"), m.content)


@optional("strands", "strands-agents package")
class StrandsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import strands_tool

        cls.mod = strands_tool
        strands_tool.current_user.set(DANA)
        strands_tool.current_groups.set(["platform-team"])

    def setUp(self):
        FakeHallpass.seen.clear()

    def stream(self, tool, args: dict):
        """Invoke the way the Strands agent loop does."""

        async def go():
            last = None
            async for event in tool.stream({"toolUseId": "t1", "name": tool.tool_name, "input": args}, {}):
                last = event
            return last["tool_result"]

        return asyncio.run(go())

    def test_tools(self):
        check, write = self.mod.tools
        self.assertEqual((check.tool_name, write.tool_name), ("check_permission", "write_thing"))
        props = write.tool_spec["inputSchema"]["json"]["properties"]
        self.assertEqual(set(props), {"thing_id", "content"}, "user must not be in the tool schema")
        res = self.stream(check, {"connection": "demo", "action": "thing.write", "resource": "thing:timeout"})
        self.assertEqual(res["status"], "success")
        self.assertTrue(res["content"][0]["text"].startswith("unknown: upstream_timeout"), res)
        self.assertEqual((last_request()["user"], last_request()["groups"]), (DANA, ["platform-team"]))
        res = self.stream(write, {"thing_id": "allowed", "content": "hi", "user": "admin@example.com"})
        self.assertEqual(res["status"], "success")
        self.assertIn("wrote 2 bytes to thing:allowed as " + DANA, res["content"][0]["text"])
        self.assertEqual(last_request()["user"], DANA)
        for thing in ("denied", "timeout"):
            res = self.stream(write, {"thing_id": thing, "content": "hi"})
            self.assertEqual(res["status"], "error")
            self.assertIn("may not thing.write on thing:" + thing, res["content"][0]["text"])


@optional("claude_agent_sdk", "claude-agent-sdk package")
class ClaudeAgentSDKTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import claude_agent_sdk_tool

        cls.mod = claude_agent_sdk_tool
        claude_agent_sdk_tool.current_user.set(DANA)
        claude_agent_sdk_tool.current_groups.set(["platform-team"])

    def setUp(self):
        FakeHallpass.seen.clear()

    def call(self, name: str, args: dict):
        """Call through the in-process MCP server the SDK hands to Claude Code."""
        from mcp import Client

        async def go():
            async with Client(self.mod.server["instance"]) as client:
                tools = {t.name: t for t in (await client.list_tools()).tools}
                self.assertEqual(set(tools), {"check_permission", "write_thing"})
                self.assertEqual(set(tools["write_thing"].input_schema["properties"]), {"thing_id", "content"})
                return await client.call_tool(name, args)

        return asyncio.run(go())

    def test_handlers_direct(self):
        for t in (self.mod.check_permission, self.mod.write_thing):
            self.assertTrue(asyncio.iscoroutinefunction(t.handler))
        out = asyncio.run(self.mod.write_thing.handler({"thing_id": "allowed", "content": "hi"}))
        self.assertIn("wrote 2 bytes", out["content"][0]["text"])
        with self.assertRaises(PermissionDenied):
            asyncio.run(self.mod.write_thing.handler({"thing_id": "denied", "content": "hi"}))

    def test_through_server(self):
        res = self.call("check_permission", {"connection": "demo", "action": "thing.write", "resource": "thing:timeout"})
        self.assertFalse(res.is_error)
        self.assertTrue(res.content[0].text.startswith("unknown: upstream_timeout"), res)
        self.assertEqual((last_request()["user"], last_request()["groups"]), (DANA, ["platform-team"]))
        res = self.call("write_thing", {"thing_id": "allowed", "content": "hi", "user": "admin@example.com"})
        self.assertFalse(res.is_error)
        self.assertIn("wrote 2 bytes to thing:allowed as " + DANA, res.content[0].text)
        self.assertEqual(last_request()["user"], DANA)
        for thing in ("denied", "timeout"):
            res = self.call("write_thing", {"thing_id": thing, "content": "hi"})
            self.assertTrue(res.is_error)
            self.assertIn("may not thing.write on thing:" + thing, res.content[0].text)


if __name__ == "__main__":
    unittest.main()
