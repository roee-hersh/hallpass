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


if __name__ == "__main__":
    sys.exit(unittest.main())
