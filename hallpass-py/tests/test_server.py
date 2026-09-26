"""Port of internal/server/server_test.go.

Go drives the handler with httptest.NewRecorder; here every request goes
over a real socket to the server listening on 127.0.0.1."""

from __future__ import annotations

import http.client
import io
import json
from collections.abc import Iterator
from typing import Any

import pytest

from hallpass.core import secret
from hallpass.core.context import Context
from hallpass.core.decision import allowed, denied
from hallpass.core.engine import Request, Result
from hallpass.core.log import JSONHandler, Logger
from hallpass.server import MAX_REQUEST_BODY, Server

KEY = "CANARY-SECRET-apikey"


class StubChecker:
    def __init__(self) -> None:
        self.last: Request | None = None

    def check(self, ctx: Context | None, req: Request) -> Result:
        self.last = req
        if req.user == "a@x.com":
            return Result(allowed("ok"), 200)
        return Result(denied("no"), 200)


class Running:
    """A Server listening on 127.0.0.1 with an ephemeral port."""

    def __init__(self, s: Server) -> None:
        self.server = s
        self.host, self.port = s.listen("127.0.0.1:0")
        s.serve_in_thread()

    def request(self, method: str, path: str, body: bytes | None = None, headers: dict[str, str] | None = None) -> tuple[http.client.HTTPResponse, bytes]:
        conn = http.client.HTTPConnection(self.host, self.port, timeout=5)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            res = conn.getresponse()
            return res, res.read()
        finally:
            conn.close()

    def post(self, auth: str, body: str, ct: str) -> tuple[http.client.HTTPResponse, dict[str, Any]]:
        h = {}
        if auth != "":
            h["Authorization"] = auth
        if ct != "":
            h["Content-Type"] = ct
        res, b = self.request("POST", "/check", body.encode(), h)
        try:
            out = json.loads(b)
        except ValueError:
            out = {}
        return res, out


@pytest.fixture
def running() -> Iterator[list[Running]]:
    started: list[Running] = []
    yield started
    for r in started:
        r.server.shutdown()


def start(started: list[Running], checker: StubChecker, key: secret.Secret, logger: Logger | None = None) -> Running:
    r = Running(Server(checker, key, logger))
    started.append(r)
    return r


def test_check(running: list[Running]) -> None:
    logs = io.StringIO()
    c = StubChecker()
    h = start(running, c, secret.literal(KEY), Logger(JSONHandler(logs)))

    res, out = h.post("Bearer " + KEY, '{"user":"a@x.com","groups":["g1"],"connection":"c","action":"thing.read","resource":"thing:1"}', "application/json")
    assert res.status == 200 and out["decision"] == "allow" and out["reason"] == "allowed: ok", (res.status, out)
    assert c.last is not None and c.last.groups is not None
    assert c.last.groups[0] == "g1" and c.last.connection == "c", c.last
    assert res.getheader("Content-Type") == "application/json", "content type"
    assert KEY not in logs.getvalue() and "a@x.com" not in logs.getvalue(), f"log leaked: {logs.getvalue()}"

    res, out = h.post("Bearer " + KEY, '{"user":"b@x.com","connection":"c","action":"thing.read","resource":"thing:1"}', "application/x-www-form-urlencoded")
    assert res.status == 200 and out["decision"] == "deny", (res.status, out)
    assert not c.last.fresh, "fresh without the field"
    # "fresh": true reaches the engine.
    res, out = h.post("Bearer " + KEY, '{"user":"a@x.com","connection":"c","action":"thing.read","resource":"thing:1","fresh":true}', "application/json")
    assert res.status == 200 and out["decision"] == "allow" and c.last.fresh, f"fresh: {res.status} {out} {c.last}"
    res, out = h.post("Bearer " + KEY, '{"user":"a@x.com","fresh":"yes"}', "")
    assert res.status == 400 and "wrong type for field fresh" in out["reason"], f"fresh wrong type: {res.status} {out}"


def test_auth(running: list[Running], monkeypatch: pytest.MonkeyPatch) -> None:
    h = start(running, StubChecker(), secret.literal(KEY))
    for auth in ("", "Bearer wrong", "Basic abc", "Bearer " + KEY + "x", "Bearer " + KEY[:-1]):
        res, out = h.post(auth, "{}", "")
        assert res.status == 401 and out["decision"] == "unknown" and out["reason"].startswith("unauthorized"), f"auth {auth!r}: {res.status} {out}"
        assert res.getheader("WWW-Authenticate"), "missing WWW-Authenticate"
    res, _ = h.post("bearer " + KEY, '{"user":"a@x.com"}', "")
    assert res.status == 200, f"case-insensitive scheme: {res.status}"
    monkeypatch.setenv("HALLPASS_TEST_KEY", "")
    h2 = start(running, StubChecker(), secret.must_parse("env:HALLPASS_TEST_KEY"))
    res, _ = h2.post("Bearer ", "{}", "")
    assert res.status == 401, f"empty key must not authorize: {res.status}"


@pytest.mark.parametrize(
    ("body", "ct", "status", "reason"),
    [
        ('{"user":1}', "", 400, "wrong type for field user"),
        ('{"usr":"a"}', "", 400, 'unknown field "usr"'),
        ("{", "", 400, "syntax error"),
        ("", "", 400, "empty body"),
        ("{} {}", "", 400, "trailing data"),
        ('{"user":"' + "x" * MAX_REQUEST_BODY + '"}', "", 413, "larger than"),
    ],
)
def test_bad_requests(running: list[Running], body: str, ct: str, status: int, reason: str) -> None:
    h = start(running, StubChecker(), secret.literal(KEY))
    res, out = h.post("Bearer " + KEY, body, ct)
    assert res.status == status and out.get("decision") == "unknown" and reason in out.get("reason", ""), f"{body[:30]!r}: {res.status} {out}"


def test_bad_requests_get_check(running: list[Running]) -> None:
    # Go: the tail of TestBadRequests.
    h = start(running, StubChecker(), secret.literal(KEY))
    res, _ = h.request("GET", "/check")
    assert res.status == 405, f"GET /check = {res.status}"


def test_healthz(running: list[Running]) -> None:
    h = start(running, StubChecker(), secret.literal(KEY))
    res, body = h.request("GET", "/healthz")
    assert res.status == 200 and b'"ok"' in body, (res.status, body)
    res, _ = h.request("POST", "/healthz")
    assert res.status == 405, res.status
    res, _ = h.request("GET", "/nope")
    assert res.status == 404, res.status


def test_null_body_is_an_empty_request(running: list[Running]) -> None:
    """Go decodes a JSON null into the request struct as a no-op: the
    engine gets an empty request (and answers it invalid), the connection
    is not dropped."""
    c = StubChecker()
    h = start(running, c, secret.literal(KEY))
    res, out = h.post("Bearer " + KEY, "null", "")
    assert res.status == 200 and out["decision"] == "deny", (res.status, out)
    assert c.last is not None and c.last.user == "" and c.last.connection == "" and not c.last.groups, c.last
