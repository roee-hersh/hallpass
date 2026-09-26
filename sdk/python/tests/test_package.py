"""Checks the installed package, not the source tree.

    pip install ./sdk/python && python -m unittest discover -s sdk/python/tests

The client's behaviour is tested in examples/agent/test_hallpass_client.py.
This makes sure the distribution itself is complete and works.
"""

from __future__ import annotations

import http.server
import json
import os
import sys
import threading
import unittest
from contextvars import ContextVar

import hallpass_client
from hallpass_client import Hallpass, PermissionDenied, guarded


class _Fake(http.server.BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        ok = self.headers.get("Authorization") == "Bearer k" and body["user"] == "admin@example.com"
        out = json.dumps({"decision": "allow" if ok else "deny", "reason": "allowed: x" if ok else "denied: x"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *args):
        pass


class InstalledPackage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Fake)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.hp = Hallpass(url=f"http://127.0.0.1:{cls.srv.server_address[1]}", api_key="k", timeout=2)

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_imported_from_site_packages(self):
        if os.environ.get("HALLPASS_SDK_REQUIRE_INSTALLED") == "1":
            src = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
            self.assertFalse(os.path.abspath(hallpass_client.__file__).startswith(src), hallpass_client.__file__)

    def test_typed_marker_shipped(self):
        self.assertTrue(os.path.exists(os.path.join(os.path.dirname(hallpass_client.__file__), "py.typed")))

    def test_allow_and_deny(self):
        self.assertEqual(self.hp.check("admin@example.com", "demo", "thing.write", "thing:1").decision, "allow")
        with self.assertRaises(PermissionDenied):
            self.hp.require("dana@example.com", "demo", "thing.write", "thing:1")

    def test_unreachable_is_unknown(self):
        hp = Hallpass(url="http://127.0.0.1:9", api_key="k", timeout=1)
        self.assertEqual(hp.check("admin@example.com", "demo", "thing.write", "thing:1").decision, "unknown")

    def test_guarded(self):
        user: ContextVar[str] = ContextVar("user")

        @guarded(self.hp, "demo", "thing.write", "thing:{thing_id}", user=user)
        def write(thing_id: str) -> str:
            return "wrote " + thing_id

        user.set("admin@example.com")
        self.assertEqual(write(thing_id="1"), "wrote 1")
        user.set("dana@example.com")
        with self.assertRaises(PermissionDenied):
            write(thing_id="1")

    def test_strands_handler(self):
        path = os.path.join(os.path.dirname(hallpass_client.__file__), "strands.py")
        self.assertTrue(os.path.exists(path), "hallpass_client.strands must ship in the wheel")
        try:
            from hallpass_client.strands import HallpassAuthorization
        except ImportError:
            if os.environ.get("HALLPASS_SDK_REQUIRE_STRANDS") == "1":
                raise
            self.skipTest("strands-agents not installed (the strands extra)")
        import asyncio
        from types import SimpleNamespace

        from strands.interventions import Deny, Proceed

        handler = HallpassAuthorization(self.hp, {"write": ("demo", "thing.write", "thing:{thing_id}")})

        def decide(user: str):
            event = SimpleNamespace(tool_use={"toolUseId": "t1", "name": "write", "input": {"thing_id": "1"}},
                                    invocation_state={"user_id": user})
            return asyncio.run(handler.before_tool_call(event))

        self.assertIsInstance(decide("admin@example.com"), Proceed)
        self.assertIsInstance(decide("dana@example.com"), Deny)


if __name__ == "__main__":
    sys.exit(unittest.main())
