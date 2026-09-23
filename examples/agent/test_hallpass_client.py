"""Tests for the example client against a fake hallpass. Standard library only.

    python3 -m unittest discover -s examples/agent -v

The MCP, LangChain, Claude Agent SDK and Strands tests run only when their
packages are installed.
"""

from __future__ import annotations

import http.server
import json
import os
import socket
import sys
import threading
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))

from hallpass_client import Decision, Hallpass, PermissionDenied, guarded  # noqa: E402

API_KEY = "test-key"

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


SINK = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Sink)
threading.Thread(target=SINK.serve_forever, daemon=True).start()


class ClientTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeHallpass)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.url = "http://127.0.0.1:%d" % cls.server.server_address[1]
        cls.hp = Hallpass(cls.url, API_KEY, timeout=2)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        FakeHallpass.seen.clear()

    def check(self, thing: str, **kw) -> Decision:
        return self.hp.check("dana@example.com", "demo", "thing.write", "thing:" + thing, **kw)

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
        d = Hallpass(self.url, "wrong", timeout=2).check("dana@example.com", "demo", "thing.write", "thing:allowed")
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

    def test_bad_url_is_unknown(self):
        d = Hallpass("localhost:1", API_KEY).check("u", "demo", "thing.read", "thing:1")
        self.assertEqual((d.decision, d.code), ("unknown", "client_error"))

    def test_unreachable_is_unknown(self):
        with socket.socket() as s:  # a port nobody listens on
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        d = Hallpass("http://127.0.0.1:%d" % port, API_KEY, timeout=1).check("u", "demo", "thing.read", "thing:1")
        self.assertEqual((d.decision, d.code, d.status), ("unknown", "client_error", 0))
        self.assertFalse(d.allowed)

    def test_request_shape(self):
        self.check("allowed", groups=["platform-team"])
        req = FakeHallpass.seen[-1]
        self.assertEqual(req["headers"]["Authorization"], "Bearer " + API_KEY)
        self.assertEqual(req["headers"]["Content-Type"], "application/json")
        self.assertEqual(
            req["body"],
            {"user": "dana@example.com", "groups": ["platform-team"], "connection": "demo",
             "action": "thing.write", "resource": "thing:allowed"},
        )
        self.check("allowed")
        self.assertNotIn("groups", FakeHallpass.seen[-1]["body"], "groups omitted when not given")

    def test_require_and_allowed(self):
        self.assertTrue(self.hp.allowed("u", "demo", "thing.write", "thing:allowed"))
        self.assertFalse(self.hp.allowed("u", "demo", "thing.write", "thing:timeout"))
        self.hp.require("u", "demo", "thing.write", "thing:allowed")
        with self.assertRaises(PermissionDenied) as cm:
            self.hp.require("u", "demo", "thing.write", "thing:timeout")
        self.assertEqual(cm.exception.decision.code, "upstream_timeout")
        self.assertIn("unknown", str(cm.exception))

    def test_guarded_runs_only_on_allow(self):
        ran = []

        @guarded(self.hp, "demo", "thing.write", "thing:{thing_id}", groups=["platform-team"])
        def write(*, user: str, thing_id: str) -> str:
            ran.append(thing_id)
            return "ok"

        self.assertEqual(write(user="u", thing_id="allowed"), "ok")
        for thing in ("denied", "timeout", "garbage", "badline"):
            with self.assertRaises(PermissionDenied):
                write(user="u", thing_id=thing)
        self.assertEqual(ran, ["allowed"])
        with self.assertRaises(TypeError):
            write("u", "allowed")  # positional arguments could bypass the resource template
        first = FakeHallpass.seen[0]["body"]
        self.assertEqual((first["resource"], first["groups"]), ("thing:allowed", ["platform-team"]))

    def test_missing_api_key(self):
        env = dict(os.environ)
        os.environ.pop("HALLPASS_API_KEY", None)
        try:
            with self.assertRaises(ValueError):
                Hallpass(self.url)
        finally:
            os.environ.clear()
            os.environ.update(env)


try:
    import mcp  # noqa: F401
    HAVE_MCP = True
except ImportError:
    HAVE_MCP = False


try:
    import langchain_core  # noqa: F401
    HAVE_LANGCHAIN = True
except ImportError:
    HAVE_LANGCHAIN = False

# Set to 1 where the optional dependencies are expected (CI), so a missing
# package fails instead of silently skipping.
REQUIRE_DEPS = os.environ.get("HALLPASS_EXAMPLE_REQUIRE_DEPS") == "1"


def optional(have: bool, what: str, required: bool = True):
    """Skip a test class when its package is absent. CI requires the packages
    from requirements.txt; those in requirements-frameworks.txt stay optional."""
    if have:
        return lambda cls: cls
    if REQUIRE_DEPS and required:
        raise ImportError(what + " not installed but HALLPASS_EXAMPLE_REQUIRE_DEPS=1")
    return unittest.skip(what + " not installed")


def fake_server():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeHallpass)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, Hallpass("http://127.0.0.1:%d" % server.server_address[1], API_KEY, timeout=2)


@optional(HAVE_MCP, "mcp package")
class MCPServerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeHallpass)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.env = mock.patch.dict(os.environ, {
            "HALLPASS_URL": "http://127.0.0.1:%d" % cls.server.server_address[1],
            "HALLPASS_API_KEY": API_KEY,
            "AGENT_USER": "dana@example.com",
            "AGENT_GROUPS": "platform-team, sre",
        })
        cls.env.start()
        import mcp_server

        cls.mod = mcp_server

    @classmethod
    def tearDownClass(cls):
        cls.env.stop()
        cls.server.shutdown()

    def call(self, name: str, **args):
        import asyncio

        from mcp import Client

        async def go():
            async with Client(self.mod.mcp) as client:
                names = {t.name for t in (await client.list_tools()).tools}
                self.assertEqual(names, {"check_permission", "write_thing"})
                return await client.call_tool(name, args)

        return asyncio.run(go())

    def test_check_permission(self):
        res = self.call("check_permission", connection="demo", action="thing.write", resource="thing:timeout")
        self.assertFalse(res.is_error)
        self.assertEqual(res.structured_content["decision"], "unknown")
        self.assertFalse(res.structured_content["allowed"])
        body = FakeHallpass.seen[-1]["body"]
        self.assertEqual((body["user"], body["groups"]), ("dana@example.com", ["platform-team", "sre"]))

    def test_write_thing(self):
        res = self.call("write_thing", thing_id="allowed", content="hi")
        self.assertIn("wrote 2 bytes", res.content[0].text)
        self.assertEqual(FakeHallpass.seen[-1]["body"]["groups"], ["platform-team", "sre"])
        for thing in ("denied", "timeout", "badline"):
            res = self.call("write_thing", thing_id=thing, content="hi")
            self.assertFalse(res.is_error)
            self.assertTrue(res.content[0].text.startswith("refused:"), res.content[0].text)


@optional(HAVE_LANGCHAIN, "langchain-core package")
class LangChainToolTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeHallpass)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        from langchain_tool import make_tools

        hp = Hallpass("http://127.0.0.1:%d" % cls.server.server_address[1], API_KEY, timeout=2)
        cls.check, cls.write = make_tools("dana@example.com", groups=["platform-team"], hp=hp)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_tools(self):
        self.assertEqual({self.check.name, self.write.name}, {"check_permission", "write_thing"})
        out = self.check.invoke({"connection": "demo", "action": "thing.write", "resource": "thing:timeout"})
        self.assertTrue(out.startswith("unknown: upstream_timeout"), out)
        self.assertEqual(FakeHallpass.seen[-1]["body"]["groups"], ["platform-team"])
        self.assertIn("wrote 2 bytes", self.write.invoke({"thing_id": "allowed", "content": "hi"}))
        self.assertEqual(FakeHallpass.seen[-1]["body"]["groups"], ["platform-team"])
        for thing in ("denied", "timeout"):
            out = self.write.invoke({"thing_id": thing, "content": "hi"})
            self.assertTrue(out.startswith("refused:"), out)


try:
    import claude_agent_sdk  # noqa: F401
    HAVE_CLAUDE_SDK = True
except ImportError:
    HAVE_CLAUDE_SDK = False

try:
    import strands  # noqa: F401
    HAVE_STRANDS = True
except ImportError:
    HAVE_STRANDS = False


@optional(HAVE_CLAUDE_SDK, "claude-agent-sdk package", required=False)
class ClaudeAgentSDKToolTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, hp = fake_server()
        from claude_agent_sdk_tool import make_server, make_tools

        cls.check, cls.write = make_tools("dana@example.com", groups=["platform-team"], hp=hp)
        cls.config = make_server("dana@example.com", groups=["platform-team"], hp=hp)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_handlers(self):
        import asyncio

        self.assertEqual((self.check.name, self.write.name), ("check_permission", "write_thing"))
        out = asyncio.run(self.check.handler({"connection": "demo", "action": "thing.write", "resource": "thing:timeout"}))
        self.assertTrue(out["content"][0]["text"].startswith("unknown: upstream_timeout"), out)
        self.assertEqual(FakeHallpass.seen[-1]["body"]["groups"], ["platform-team"])
        out = asyncio.run(self.write.handler({"thing_id": "allowed", "content": "hi"}))
        self.assertIn("wrote 2 bytes", out["content"][0]["text"])
        self.assertNotIn("is_error", out)
        for thing in ("denied", "timeout"):
            out = asyncio.run(self.write.handler({"thing_id": thing, "content": "hi"}))
            self.assertTrue(out["content"][0]["text"].startswith("refused:"), out)
            self.assertTrue(out["is_error"])


@optional(HAVE_STRANDS, "strands-agents package", required=False)
class StrandsToolTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, cls.hp = fake_server()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_tools_build(self):
        from strands_tool import make_tools

        check, write = make_tools("dana@example.com", groups=["platform-team"], hp=self.hp)
        self.assertEqual(check.tool_name, "check_permission")
        self.assertEqual(write.tool_name, "write_thing")


if __name__ == "__main__":
    unittest.main()
