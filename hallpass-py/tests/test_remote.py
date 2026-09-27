"""Hallpass.remote end to end: the client against a real hallpass server
(and against a recording one for the wire format), over HTTP."""

from __future__ import annotations

import http.server
import importlib.resources
import json
import threading
from collections.abc import Iterator
from typing import Any

import pytest

from hallpass import Hallpass, PermissionDenied, guarded
from hallpass._api import _validate_url
from hallpass.authx.token import Token
from hallpass.core import secret
from tests.test_server import KEY, Running, StubChecker, start


@pytest.fixture
def running() -> Iterator[list[Running]]:
    started: list[Running] = []
    yield started
    for r in started:
        r.server.shutdown()


def remote(r: Running, key: str = KEY) -> Hallpass:
    return Hallpass.remote(f"http://{r.host}:{r.port}", api_key=key, timeout=5)


def test_allow_deny_require(running: list[Running]) -> None:
    hp = remote(start(running, StubChecker(), secret.literal(KEY)))
    d = hp.check("a@x.com", "c", "thing.read", "thing:1")
    assert d.allowed and d.decision == "allow" and d.reason == "allowed: ok" and d.status == 200, d
    d = hp.check("b@x.com", "c", "thing.read", "thing:1")
    assert not d.allowed and d.decision == "deny" and d.reason == "denied: no", d
    assert hp.allowed("a@x.com", "c", "thing.read", "thing:1")
    assert hp.require("a@x.com", "c", "thing.read", "thing:1").allowed
    with pytest.raises(PermissionDenied) as ei:
        hp.require("b@x.com", "c", "thing.read", "thing:1")
    assert ei.value.decision.decision == "deny"


def test_groups_and_fresh_reach_the_server(running: list[Running]) -> None:
    c = StubChecker()
    hp = remote(start(running, c, secret.literal(KEY)))
    hp.check("a@x.com", "c", "thing.read", "thing:1", ["g1", "g2"], fresh=True)
    assert c.last is not None and c.last.groups == ["g1", "g2"] and c.last.fresh, c.last


def test_wrong_key_is_unknown(running: list[Running]) -> None:
    hp = remote(start(running, StubChecker(), secret.literal(KEY)), key="not-the-key")
    d = hp.check("a@x.com", "c", "thing.read", "thing:1")
    assert d.decision == "unknown" and d.status == 401 and not d.allowed, d


def test_guarded_over_remote(running: list[Running]) -> None:
    hp = remote(start(running, StubChecker(), secret.literal(KEY)))
    ran: list[str] = []

    def make(user: str) -> Any:
        @guarded(hp, "c", "thing.write", "thing:{thing_id}", user=user)
        def write(thing_id: str) -> str:
            ran.append(thing_id)
            return "wrote " + thing_id

        return write

    assert make("a@x.com")(thing_id="1") == "wrote 1"
    with pytest.raises(PermissionDenied):
        make("b@x.com")(thing_id="2")
    assert ran == ["1"], ran


class _Recording(http.server.BaseHTTPRequestHandler):
    seen: list[dict[str, Any]] = []
    reply: bytes = b'{"decision":"allow","reason":"allowed: ok"}'

    def do_POST(self) -> None:
        n = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(n)
        type(self).seen.append({"path": self.path, "headers": dict(self.headers), "body": json.loads(body)})
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(type(self).reply)))
        self.end_headers()
        self.wfile.write(type(self).reply)

    def log_message(self, format: str, *args: Any) -> None:
        pass


@pytest.fixture
def recording() -> Iterator[tuple[str, type[_Recording]]]:
    handler = type("Rec", (_Recording,), {"seen": [], "reply": _Recording.reply})
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}", handler
    finally:
        srv.shutdown()
        srv.server_close()


def test_wire_format(recording: tuple[str, type[_Recording]]) -> None:
    url, rec = recording
    hp = Hallpass.remote(url, api_key="k-123", timeout=5)
    assert hp.check("a@x.com", "c", "thing.read", "thing:1").allowed
    [call] = rec.seen
    assert call["path"] == "/check"
    assert call["headers"]["Authorization"] == "Bearer k-123"
    assert call["headers"]["Content-Type"] == "application/json"
    assert call["body"] == {"user": "a@x.com", "connection": "c", "action": "thing.read", "resource": "thing:1"}


def test_oversized_response_is_unknown(recording: tuple[str, type[_Recording]]) -> None:
    url, rec = recording
    rec.reply = b'{"decision":"allow","reason":"' + b"x" * (1 << 20) + b'"}'
    d = Hallpass.remote(url, api_key="k", timeout=5).check("a@x.com", "c", "thing.read", "thing:1")
    assert d.decision == "unknown" and "larger than" in d.reason, d


def test_loopback_never_goes_through_a_proxy(running: list[Running], monkeypatch: pytest.MonkeyPatch) -> None:
    # A proxy would see the API key; a dead one makes any use of it fail.
    for var in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"):
        monkeypatch.setenv(var, "http://127.0.0.1:9")
    for var in ("NO_PROXY", "no_proxy"):
        monkeypatch.delenv(var, raising=False)
    hp = remote(start(running, StubChecker(), secret.literal(KEY)))
    assert hp.check("a@x.com", "c", "thing.read", "thing:1").allowed


@pytest.mark.parametrize("url", ["http://localhost:8080", "http://127.0.0.1:8080", "http://[::1]:8080", "http://[::ffff:127.0.0.1]:8080"])
def test_plain_http_only_to_loopback(url: str) -> None:
    assert _validate_url(url) == url


@pytest.mark.parametrize("url", ["http://10.0.0.1:8080", "http://hallpass.internal", "ftp://localhost"])
def test_plain_http_elsewhere_is_refused(url: str) -> None:
    with pytest.raises(ValueError):
        _validate_url(url)


def test_package_ships_type_information() -> None:
    assert importlib.resources.files("hallpass").joinpath("py.typed").is_file()


def test_token_repr_hides_the_value() -> None:
    assert "s3cr3t" not in repr(Token(value="s3cr3t", expiry=1.0))
