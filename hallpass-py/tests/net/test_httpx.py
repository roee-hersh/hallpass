"""Port of internal/httpx/httpx_test.go, plus proxy and TLS server name
tests for the transport the Python port builds itself."""

from __future__ import annotations

import email.utils
import hashlib
import http.client
import io
import json
import os
import select
import socket
import ssl
import threading
import time
import urllib.parse
from collections.abc import Callable, Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from hallpass.core import evidence
from hallpass.core.context import Cancelled, Context, background, with_timeout
from hallpass.core.decision import Code
from hallpass.core.errors import as_error, is_error
from hallpass.core.integration import DEFAULT_TIMEOUT
from hallpass.core.log import DEBUG, JSONHandler, Logger
from hallpass.net import httpx
from hallpass.net.httpx import (
    MAX_PAGES,
    BodyTooLarge,
    Client,
    Headers,
    Options,
    Request,
    StatusError,
    TooManyPages,
    TransportError,
    bearer_auth,
    classify,
    link_next,
    new_http_client,
    path_escape,
    status,
)
from tests import harness as itest

CANARY = "CANARY-SECRET-httpx"


class _Counter:
    """Go's atomic.Int32."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._n = 0

    def add(self, d: int) -> int:
        with self._lock:
            self._n += d
            return self._n

    def load(self) -> int:
        with self._lock:
            return self._n

    def store(self, n: int) -> None:
        with self._lock:
            self._n = n


def _no_sleep(ctx: Context, d: float) -> None:
    return None


def new_test_client(srv: itest.Server, logs: io.StringIO) -> Client:
    hc = new_http_client(Options(ssl_context=itest.test_ca().client_context(), timeout=2.0))
    return Client(http=hc, base=srv.url, logger=Logger(JSONHandler(logs, DEBUG)), sleep=_no_sleep)


def _err(fn: Callable[[], Any]) -> BaseException | None:
    """The exception fn raises, or None: Go's (value, error) second result."""
    try:
        fn()
    except Exception as e:
        return e
    return None


@pytest.fixture
def servers() -> Iterator[Callable[..., itest.Server]]:
    """Start test servers; close them all when the test ends."""
    started: list[itest.Server] = []

    def start(handler: itest.Handler, tls: bool = True) -> itest.Server:
        s = itest.Server(tls=tls)
        s.unmatched = handler
        started.append(s)
        return s

    yield start
    for s in started:
        s.close()


def test_get_json_and_no_body_in_logs(servers: Callable[..., itest.Server]) -> None:
    bad_ua: list[str] = []

    def h(w: itest.ResponseWriter, r: itest.Request) -> None:
        if r.header.get("Authorization") != "Bearer " + CANARY:
            w.write_header(401)
            return
        if not r.header.get("User-Agent").startswith("hallpass/"):
            bad_ua.append(r.header.get("User-Agent"))
        w.header().set("Content-Type", "application/json")
        w.write('{"ok":true,"secret":"' + CANARY + '-body"}')

    srv = servers(h)
    logs = io.StringIO()
    c = new_test_client(srv, logs)
    c.auth = bearer_auth(lambda ctx: CANARY)
    resp, out = c.get_json(background(), "/x?a=b", {"token": [CANARY + "-q"]})
    assert out["ok"] is True and resp.status == 200, (out, resp)
    assert not bad_ua, f"user agent {bad_ua}"
    assert CANARY not in logs.getvalue(), f"log leaked: {logs.getvalue()}"
    assert '"path":"/x"' in logs.getvalue(), f"log missing path: {logs.getvalue()}"


def test_status_error_and_classify(servers: Callable[..., itest.Server]) -> None:
    calls = _Counter()

    def h(w: itest.ResponseWriter, r: itest.Request) -> None:
        calls.add(1)
        if r.path == "/401":
            w.write_header(401)
        elif r.path == "/403":
            w.write_header(403)
            w.write('{"message":"' + CANARY + '"}')
        elif r.path == "/429":
            w.header().set("Retry-After", "1")
            w.write_header(429)
        elif r.path == "/429long":
            w.header().set("Retry-After", "120")
            w.write_header(429)
        elif r.path == "/503":
            w.write_header(503)
        elif r.path == "/500post":
            w.write_header(500)

    srv = servers(h)
    c = new_test_client(srv, io.StringIO())
    ctx = background()

    err = _err(lambda: c.do(ctx, Request(path="/401")))
    assert classify(err).code == Code.CREDENTIAL_REJECTED, f"401 -> {classify(err)}"
    calls.store(0)
    err = _err(lambda: c.do(ctx, Request(path="/403")))
    assert status(err) == 403 and calls.load() == 1, f"403 status={status(err)} calls={calls.load()}"
    se = as_error(err, StatusError)
    assert se is not None and CANARY in se.snippet, "snippet not kept for the integration"
    assert CANARY not in str(se), "str() leaked the body"
    calls.store(0)
    err = _err(lambda: c.do(ctx, Request(path="/429")))
    assert classify(err).code == Code.UPSTREAM_RATE_LIMIT and calls.load() == 3, f"429: {classify(err)} calls={calls.load()}"
    calls.store(0)
    err = _err(lambda: c.do(ctx, Request(path="/429long")))
    assert classify(err).code == Code.UPSTREAM_RATE_LIMIT and calls.load() == 1, f"429 long: {classify(err)} calls={calls.load()}"
    calls.store(0)
    err = _err(lambda: c.do(ctx, Request(path="/503")))
    assert classify(err).code == Code.UPSTREAM_ERROR and calls.load() == 3, f"503: {classify(err)} calls={calls.load()}"
    calls.store(0)
    err = _err(lambda: c.do(ctx, Request(method="POST", path="/500post", json={"a": 1})))
    assert classify(err).code == Code.UPSTREAM_ERROR and calls.load() == 1, f"POST 500 retried: calls={calls.load()}"
    resp = c.do(ctx, Request(path="/403", accept_4xx=True))
    assert resp.status == 403, f"accept_4xx: {resp}"


def test_timeout_and_body_cap(servers: Callable[..., itest.Server]) -> None:
    done = threading.Event()

    def h(w: itest.ResponseWriter, r: itest.Request) -> None:
        if r.path == "/slow":
            done.wait(3)
        elif r.path == "/big":
            w.write(b"x" * 2048)

    srv = servers(h)
    try:
        c = new_test_client(srv, io.StringIO())
        ctx, cancel = with_timeout(background(), 0.2)
        try:
            err = _err(lambda: c.do(ctx, Request(path="/slow")))
        finally:
            cancel()
        assert classify(err).code == Code.UPSTREAM_TIMEOUT, f"timeout -> {classify(err)}"
        c.max_body = 1024
        err = _err(lambda: c.do(background(), Request(path="/big")))
        assert is_error(err, BodyTooLarge), f"big -> {err!r}"
    finally:
        done.set()


def test_no_redirects(servers: Callable[..., itest.Server]) -> None:
    def h(w: itest.ResponseWriter, r: itest.Request) -> None:
        # Go's http.Redirect: Location and the status, with a short body.
        w.header().set("Location", "https://evil.example/")
        w.header().set("Content-Type", "text/html; charset=utf-8")
        w.write_header(302)
        w.write('<a href="https://evil.example/">Found</a>.\n')

    srv = servers(h)
    c = new_test_client(srv, io.StringIO())
    resp = c.do(background(), Request(path="/"))
    assert resp.status == 302, resp
    assert len(srv.calls()) == 1


def test_ca_file_and_tls_min(servers: Callable[..., itest.Server], tmp_path: Any) -> None:
    # Go: TestCAFileAndTLSMin writes the self-signed server certificate as
    # PEM (its base64Lines helper); the harness certificate is issued by a
    # test CA, so the CA's PEM is what trusts it here.
    srv = servers(lambda w, r: w.write("{}"))
    pem_path = tmp_path / "ca.pem"
    pem_path.write_bytes(itest.test_ca().ca_pem)
    os.chmod(pem_path, 0o600)
    hc = new_http_client(Options(ca_file=str(pem_path)))
    c = Client(http=hc, base=srv.url)
    c.do(background(), Request(path="/"))  # with ca_file

    hc2 = new_http_client(Options())
    c2 = Client(http=hc2, base=srv.url)
    assert _err(lambda: c2.do(background(), Request(path="/"))) is not None, "system roots accepted the test certificate"
    with pytest.raises(ValueError):
        new_http_client(Options(ca_file=str(tmp_path / "missing")))
    with pytest.raises(ValueError):
        new_http_client(Options(proxy_url="socks5://x"))
    # The TLS floor is 1.2.
    assert hc.ssl_context.minimum_version == ssl.TLSVersion.TLSv1_2


def test_link_next_and_paginate(servers: Callable[..., itest.Server]) -> None:
    h = Headers()
    h.add("Link", '<https://api.example/x?page=2>; rel="next", <https://api.example/x?page=9>; rel="last"')
    assert link_next(h) == "https://api.example/x?page=2", link_next(h)
    assert link_next(Headers()) == "", "empty"
    pages = _Counter()

    def handler(w: itest.ResponseWriter, r: itest.Request) -> None:
        pages.add(1)
        w.header().set("Link", "<" + "https://" + r.host + '/p>; rel="next"')
        w.write("[]")

    srv = servers(handler)
    c = new_test_client(srv, io.StringIO())

    def page(r: httpx.Response) -> Request | None:
        n = link_next(r.header)
        if n != "":
            return Request(path=n)
        return None

    err = _err(lambda: c.paginate(background(), Request(path="/p"), page))
    assert is_error(err, TooManyPages) and pages.load() == MAX_PAGES, f"err={err!r} pages={pages.load()}"


def test_next_link_stays_within_base() -> None:
    c = Client(base="https://gitlab.example/api/v4")

    def link(u: str) -> Headers:
        h = Headers()
        h.set("Link", "<" + u + '>; rel="next"')
        return h

    for ok in (
        "https://gitlab.example/api/v4/projects/1/protected_branches?page=2",
        "https://GITLAB.example/api/v4/x",
        "/api/v4/x?page=2",
    ):
        got = c.next_link(link(ok))
        assert got != "", f"{ok}: got {got!r}"
    for bad in (
        "https://evil.example/api/v4/x",
        "http://gitlab.example/api/v4/x",
        "https://gitlab.example/oauth/token",
        "https://gitlab.example/api/v4x",
        "https://" + CANARY + "@gitlab.example/api/v4/x",
        "https://gitlab.example:8443/api/v4/x",
    ):
        got = None
        try:
            got = c.next_link(link(bad))
        except ValueError as e:
            assert CANARY not in str(e), f"error leaks userinfo: {e}"
        else:
            pytest.fail(f"{bad}: got {got!r}, no error")
    assert c.next_link(Headers()) == "", "no header"


def test_retry_after_date() -> None:
    h = Headers()
    h.set("Retry-After", email.utils.formatdate(time.time() + 3, usegmt=True))
    d = httpx._retry_after(h)
    assert 0 < d <= 4, d
    h.set("Retry-After", "garbage")
    assert httpx._retry_after(h) == 0, "garbage"


def test_redact() -> None:
    s = httpx._redact_url("https://u:" + CANARY + "@h/p?token=" + CANARY)
    assert CANARY not in s, s
    # Go builds a *url.Error{Op: "Get", URL: ..., Err: x}; Python's
    # transport errors carry the URL in their message, which is what
    # _redact_err redacts.
    e = OSError(f'Get "https://h/p?token={CANARY}": x')
    assert CANARY not in httpx._redact_err(e), "redact_err"
    assert CANARY not in str(TransportError(e)), "TransportError"
    assert path_escape("a/b c") == "a%2Fb%20c", path_escape("a/b c")


def test_transport_timeouts_follow_option() -> None:
    """A long per-connection timeout must not be capped by a fixed header
    wait; connect and handshake stay bounded by min(5s, timeout)."""
    # Go: the transport's ResponseHeaderTimeout and TLSHandshakeTimeout are
    # Transport.timeout (the whole wait for a response) and
    # Transport.connect_timeout (the dial and the handshake) here.
    tr = new_http_client(Options(timeout=12.0))
    assert tr.timeout >= 12.0, f"timeout {tr.timeout} caps a 12s timeout"
    assert tr.connect_timeout == 5.0, f"connect_timeout {tr.connect_timeout}, want 5s for a 12s timeout"
    tr = new_http_client(Options(timeout=2.0))
    assert tr.connect_timeout == 2.0, f"connect_timeout {tr.connect_timeout}, want 2s for a 2s timeout"
    tr = new_http_client(Options())
    assert tr.timeout >= DEFAULT_TIMEOUT, f"timeout {tr.timeout} caps the default timeout"


@pytest.mark.parametrize(("timeout", "ok"), [(3.0, True), (0.5, False)])
def test_slow_headers_within_timeout(servers: Callable[..., itest.Server], timeout: float, ok: bool) -> None:
    """The upstream answers after 1.5 s. A connection whose timeout is 3 s
    must get the response; one whose timeout is 500 ms must time out."""
    gone = threading.Event()

    def h(w: itest.ResponseWriter, r: itest.Request) -> None:
        if gone.wait(1.5):
            return
        w.write('{"ok":true}')

    srv = servers(h)
    try:
        hc = new_http_client(Options(ssl_context=itest.test_ca().client_context(), timeout=timeout))
        c = Client(http=hc, base=srv.url, sleep=_no_sleep)
        out: dict[str, Any] = {}

        def get() -> None:
            _, v = c.get_json(background(), "/", None)
            out.update(v)

        err = _err(get)
        if ok:
            assert err is None and out.get("ok"), f"timeout {timeout}: {err!r} (ok={out.get('ok')})"
        else:
            assert classify(err).code == Code.UPSTREAM_TIMEOUT, f"timeout {timeout}: got {classify(err)}, want upstream_timeout"
    finally:
        gone.set()


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def test_evidence(servers: Callable[..., itest.Server]) -> None:
    """Every completed response is recorded as evidence on the context's
    recorder: method, path, status and the ETag or the body's hash. The
    query, the headers and the body stay out, and a token exchange made
    from auth is not recorded at all."""

    def h(w: itest.ResponseWriter, r: itest.Request) -> None:
        if r.path == "/token":
            w.write('{"access_token":"' + CANARY + '-token"}')
        elif r.path == "/etag":
            w.header().set("ETag", 'W/"v7"')
            w.write('{"a":1}')
        elif r.path == "/badetag":
            w.header().set("ETag", "x" * 200)
            w.write('{"a":1}')
        elif r.path == "/plain":
            w.write('{"secret":"' + CANARY + '-body"}')
        elif r.path == "/empty":
            w.write_header(204)
        elif r.path == "/denied":
            w.write_header(403)
            w.write('{"message":"no"}')

    srv = servers(h)
    c = new_test_client(srv, io.StringIO())
    # Auth fetches a token through a plain client, as integrations do.
    plain = new_test_client(srv, io.StringIO())

    def token(ctx: Context) -> str:
        _, tok = plain.post_json(ctx, "/token", {}, True)
        return str(tok["access_token"])

    c.auth = bearer_auth(token)
    ctx, rec = evidence.with_recorder(background())
    for p in ("/etag", "/badetag", "/plain", "/empty"):
        c.do(ctx, Request(path=p + "?token=" + CANARY + "-q", header=Headers({"X-Secret": [CANARY + "-h"]})))
    err = _err(lambda: c.do(ctx, Request(path="/denied")))
    assert status(err) == 403, repr(err)
    ev = rec.evidence()
    assert ev is not None and len(ev.calls()) == 5, ev
    want = [
        evidence.Call(method="GET", path="/etag", status=200, etag='W/"v7"'),
        evidence.Call(method="GET", path="/badetag", status=200, sha256=_sha(b'{"a":1}')),
        evidence.Call(method="GET", path="/plain", status=200, sha256=_sha(('{"secret":"' + CANARY + '-body"}').encode())),
        evidence.Call(method="GET", path="/empty", status=204),
        evidence.Call(method="GET", path="/denied", status=403, sha256=_sha(b'{"message":"no"}')),
    ]
    for i, w in enumerate(want):
        assert ev.calls()[i] == w, f"call {i}:\n got {ev.calls()[i]}\nwant {w}"
    b = json.dumps(ev.to_json())
    assert CANARY not in b and "token" not in b, f"evidence leaked: {b}"

    # Only the response do() returns is evidence: a retried 503 is not.
    flaps = _Counter()

    def flaky_h(w: itest.ResponseWriter, r: itest.Request) -> None:
        if flaps.add(1) == 1:
            w.write_header(503)
            return
        w.write('{"ok":true}')

    flaky = servers(flaky_h)
    fc = new_test_client(flaky, io.StringIO())
    fctx, frec = evidence.with_recorder(background())
    fc.do(fctx, Request(path="/flaky"))
    assert flaps.load() == 2, flaps.load()
    fev = frec.evidence()
    assert fev is not None and len(fev.calls()) == 1 and fev.calls()[0].status == 200, f"retried attempt recorded: {fev}"

    # A call to a host other than the client's own names the host; one to
    # the base host does not.
    other = servers(lambda w, r: w.write("{}"))
    oc = new_test_client(srv, io.StringIO())
    oc.http = new_http_client(Options(ssl_context=itest.test_ca().client_context()))
    octx, orec = evidence.with_recorder(background())
    oc.do(octx, Request(path=other.url + "/elsewhere"))
    oc.do(octx, Request(path=srv.url + "/empty"))
    # A client with no base names the host too: it may be an instance
    # learned at login, and the record must say which answered.
    oc.base = ""
    oc.do(octx, Request(path=other.url + "/elsewhere"))
    other_host = other.url.removeprefix("https://")
    oev = orec.evidence()
    assert oev is not None
    oc_calls = oev.calls()
    assert len(oc_calls) == 3 and oc_calls[0].host == other_host and oc_calls[1].host == "" and oc_calls[2].host == other_host, f"host evidence: {oc_calls}"
    # The base host in another spelling (case, an explicit default port)
    # is still the base host.
    for base, u in (
        ("https://api.example.com", "https://API.example.com/x"),
        ("https://api.example.com", "https://api.example.com:443/x"),
        ("https://api.example.com:443", "https://api.example.com/x"),
        ("http://localhost:8080", "http://LOCALHOST:8080/x"),
    ):
        fh = Client(base=base)._foreign_host(urllib.parse.urlsplit(u))
        assert fh == "", f"{u} under {base}: foreign host {fh!r}"
    for base, u in (
        ("https://api.example.com", "https://api.example.com:8443/x"),
        ("https://api.example.com", "http://api.example.com/x"),
        ("https://api.example.com", "https://iam.example.com/x"),
    ):
        fh = Client(base=base)._foreign_host(urllib.parse.urlsplit(u))
        assert fh != "", f"{u} under {base}: not foreign"
    # A next-page link on the base host with its default port spelled
    # out is within the base, by the same rule.
    wc = Client(base="https://api.example.com/v1")
    assert wc.within("https://api.example.com:443/v1/users?page=2") and wc.within("https://API.example.com/v1/x"), (
        "within: the base host in another spelling was rejected"
    )
    assert not wc.within("https://api.example.com:8443/v1/x") and not wc.within("http://api.example.com/v1/x"), "within: another port or scheme was accepted"

    # A retry cut short by the caller's context still records the
    # response the caller is told about.
    attempts = _Counter()

    def always503_h(w: itest.ResponseWriter, r: itest.Request) -> None:
        attempts.add(1)
        w.write_header(503)
        w.write('{"down":true}')

    always503 = servers(always503_h)
    ic = new_test_client(always503, io.StringIO())

    def cancelled(ctx: Context, d: float) -> None:
        raise Cancelled()

    ic.sleep_fn = cancelled
    ictx, irec = evidence.with_recorder(background())
    err = _err(lambda: ic.do(ictx, Request(path="/x")))
    assert status(err) == 503 and attempts.load() == 1, (repr(err), attempts.load())
    iev = irec.evidence()
    assert iev is not None and len(iev.calls()) == 1 and iev.calls()[0].status == 503, f"interrupted retry not recorded: {iev}"

    # A request that never got a response leaves no evidence.
    srv.close()
    rec2ctx, rec2 = evidence.with_recorder(background())
    assert _err(lambda: c.do(rec2ctx, Request(path="/plain"))) is not None
    assert rec2.evidence() is None, f"evidence for a failed transport: {rec2.evidence()}"


# -- beyond the Go tests: the transport the Python port builds itself ----------
#
# Go's net/http supplies proxying, CONNECT tunnels and TLS server names; the
# Python port implements them on http.client, so these exercise them against
# real local servers.


def _pipe(a: socket.socket, b: socket.socket) -> None:
    """Copy bytes both ways until either side closes. TLS sockets can hold
    decrypted bytes select() does not see, so those are drained first."""
    socks = [a, b]
    try:
        while True:
            ready = [s for s in socks if isinstance(s, ssl.SSLSocket) and s.pending()]
            if not ready:
                ready, _, _ = select.select(socks, [], [], 5)
                if not ready:
                    return
            for s in ready:
                data = s.recv(65536)
                if not data:
                    return
                (b if s is a else a).sendall(data)
    except OSError:
        return
    finally:
        b.close()


class _Proxy:
    """A forward proxy: CONNECT tunnels and absolute-form requests. Over
    TLS (an https:// proxy) with tls=True."""

    def __init__(self, tls: bool = False) -> None:
        self._lock = threading.Lock()
        # (method, request target, Proxy-Authorization) per request.
        self.seen: list[tuple[str, str, str]] = []
        outer = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: Any) -> None:
                pass

            def _saw(self) -> None:
                with outer._lock:
                    outer.seen.append((self.command, self.path, self.headers.get("Proxy-Authorization", "")))

            def do_CONNECT(self) -> None:
                self._saw()
                host, _, port = self.path.rpartition(":")
                try:
                    up = socket.create_connection((host.strip("[]"), int(port)), 2)
                except OSError:
                    self.send_error(502)
                    return
                self.send_response_only(200, "Connection established")
                self.end_headers()
                self.close_connection = True
                _pipe(self.connection, up)

            def _forward(self) -> None:
                self._saw()
                u = urllib.parse.urlsplit(self.path)
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n) if n else None
                hdrs = {k: v for k, v in self.headers.items() if k.lower() not in ("proxy-authorization", "proxy-connection", "connection")}
                conn = http.client.HTTPConnection(u.hostname or "", u.port or 80, timeout=5)
                try:
                    conn.request(self.command, (u.path or "/") + ("?" + u.query if u.query else ""), body=body, headers=hdrs)
                    r = conn.getresponse()
                    data = r.read()
                finally:
                    conn.close()
                self.send_response_only(r.status, r.reason)
                for k, v in r.getheaders():
                    if k.lower() not in ("transfer-encoding", "connection", "content-length"):
                        self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = _forward  # noqa: N815

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self._httpd.daemon_threads = True
        self._httpd.block_on_close = False
        if tls:
            self._httpd.socket = itest.test_ca().server_context().wrap_socket(self._httpd.socket, server_side=True)
        threading.Thread(target=self._httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        host, port = self._httpd.server_address[:2]
        self.host = f"{host}:{port}"
        self.scheme = "https" if tls else "http"

    def url(self, userinfo: str = "") -> str:
        return f"{self.scheme}://{userinfo + '@' if userinfo else ''}{self.host}"

    def requests(self) -> list[tuple[str, str, str]]:
        with self._lock:
            return list(self.seen)

    def close(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()


@pytest.fixture
def proxies() -> Iterator[Callable[..., _Proxy]]:
    started: list[_Proxy] = []

    def start(tls: bool = False) -> _Proxy:
        p = _Proxy(tls)
        started.append(p)
        return p

    yield start
    for p in started:
        p.close()


def _ok(w: itest.ResponseWriter, r: itest.Request) -> None:
    w.header().set("Content-Type", "application/json")
    w.write(json.dumps({"path": r.path, "q": r.q("q"), "proxy_auth": r.header.get("Proxy-Authorization")}))


def test_proxy_plain_http_absolute_form(servers: Callable[..., itest.Server], proxies: Callable[..., _Proxy]) -> None:
    """An http:// target goes to the proxy as an absolute-form request,
    with Proxy-Authorization from the proxy URL's userinfo, which the
    target never sees."""
    srv = servers(_ok, tls=False)
    p = proxies()
    c = Client(http=new_http_client(Options(proxy_url=p.url("bot:pa%20ss"), timeout=2.0)), base=srv.url)
    _, out = c.get_json(background(), "/x", {"q": "1"})
    assert out == {"path": "/x", "q": "1", "proxy_auth": ""}, out
    assert p.requests() == [("GET", srv.url + "/x?q=1", "Basic Ym90OnBhIHNz")], p.requests()


def test_proxy_connect_tunnel(servers: Callable[..., itest.Server], proxies: Callable[..., _Proxy]) -> None:
    """An https:// target goes through a CONNECT tunnel, verified against
    the target's certificate; the tunnel is kept alive for the next call."""
    srv = servers(_ok)
    p = proxies()
    hc = new_http_client(Options(ssl_context=itest.test_ca().client_context(), proxy_url=p.url("u:pw"), timeout=2.0))
    c = Client(http=hc, base=srv.url)
    for i in range(2):
        _, out = c.get_json(background(), "/t", {"q": str(i)})
        assert out == {"path": "/t", "q": str(i), "proxy_auth": ""}, out
    assert p.requests() == [("CONNECT", srv.host, "Basic dTpwdw==")], p.requests()
    assert len(srv.calls()) == 2


def test_proxy_tls_in_tls(servers: Callable[..., itest.Server], proxies: Callable[..., _Proxy]) -> None:
    """An https:// proxy: the tunnel runs inside TLS to the proxy, verified
    with the connection's own trust (its CA file), and the target's TLS
    runs inside that."""
    srv = servers(_ok)
    p = proxies(tls=True)
    hc = new_http_client(Options(ssl_context=itest.test_ca().client_context(), proxy_url=p.url(), timeout=2.0))
    c = Client(http=hc, base=srv.url)
    for i in range(2):
        _, out = c.get_json(background(), "/tt", {"q": str(i)})
        assert out["path"] == "/tt" and out["q"] == str(i), out
    assert [r[:2] for r in p.requests()] == [("CONNECT", srv.host)], p.requests()
    # A plain http:// target through the https:// proxy.
    plain = servers(_ok, tls=False)
    c2 = Client(http=hc, base=plain.url)
    _, out = c2.get_json(background(), "/pp", None)
    assert out["path"] == "/pp", out
    assert p.requests()[-1][:2] == ("GET", plain.url + "/pp"), p.requests()


def test_proxy_ca_file_trusts_https_proxy(servers: Callable[..., itest.Server], proxies: Callable[..., _Proxy], tmp_path: Any) -> None:
    """The proxy's certificate is verified with the connection's ca_file,
    as Go verifies it with the transport's TLS config; the system roots
    alone do not trust it."""
    srv = servers(_ok)
    p = proxies(tls=True)
    ca = tmp_path / "ca.pem"
    ca.write_bytes(itest.test_ca().ca_pem)
    c = Client(http=new_http_client(Options(ca_file=str(ca), proxy_url=p.url(), timeout=2.0)), base=srv.url)
    _, out = c.get_json(background(), "/ca", None)
    assert out["path"] == "/ca"
    c2 = Client(http=new_http_client(Options(proxy_url=p.url(), timeout=2.0)), base=srv.url, sleep=_no_sleep)
    err = _err(lambda: c2.do(background(), Request(path="/ca")))
    assert as_error(err, TransportError) is not None, repr(err)


def test_proxy_refuses_connect(servers: Callable[..., itest.Server], proxies: Callable[..., _Proxy]) -> None:
    """A proxy that cannot open the tunnel is a transport error, never a
    response from the target."""
    p = proxies()
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    c = Client(
        http=new_http_client(Options(ssl_context=itest.test_ca().client_context(), proxy_url=p.url(), timeout=2.0)),
        base=f"https://127.0.0.1:{port}",
        sleep=_no_sleep,
    )
    err = _err(lambda: c.do(background(), Request(path="/")))
    assert as_error(err, TransportError) is not None and classify(err).code == Code.UPSTREAM_ERROR, repr(err)


def test_environment_proxy_selection(monkeypatch: pytest.MonkeyPatch) -> None:
    """With no proxy_url the environment decides, as Go's
    ProxyFromEnvironment: HTTPS_PROXY for https, HTTP_PROXY for http,
    NO_PROXY honoured, loopback never proxied."""
    for k in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("HTTPS_PROXY", "http://sproxy.example:3128")
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.example:8080")
    monkeypatch.setenv("NO_PROXY", "internal.example")
    t = new_http_client(Options())
    p = t._proxy_for("https", "api.example.com")
    assert p is not None and (p.host, p.port) == ("sproxy.example", 3128)
    p = t._proxy_for("http", "api.example.com")
    assert p is not None and (p.host, p.port) == ("proxy.example", 8080)
    assert t._proxy_for("https", "internal.example") is None
    assert t._proxy_for("https", "127.0.0.1") is None
    assert t._proxy_for("https", "localhost") is None
    assert t._proxy_for("https", "::1") is None
    # An explicit proxy_url applies to every host.
    t2 = new_http_client(Options(proxy_url="http://explicit.example:1"))
    p = t2._proxy_for("https", "127.0.0.1")
    assert p is not None and p.host == "explicit.example"


def test_tls_server_name(servers: Callable[..., itest.Server]) -> None:
    """tls_server_name is the name verified against the certificate for a
    system addressed by IP; a name the certificate does not carry fails."""
    srv = servers(_ok)
    ca = itest.test_ca()
    c = Client(http=new_http_client(Options(ssl_context=ca.client_context(), tls_server_name="example.com", timeout=2.0)), base=srv.url)
    _, out = c.get_json(background(), "/sni", None)
    assert out["path"] == "/sni"
    bad = Client(
        http=new_http_client(Options(ssl_context=ca.client_context(), tls_server_name="wrong.example", timeout=2.0)),
        base=srv.url,
        sleep=_no_sleep,
    )
    err = _err(lambda: bad.do(background(), Request(path="/sni")))
    te = as_error(err, TransportError)
    assert te is not None and is_error(err, ssl.SSLCertVerificationError), repr(err)
    assert classify(err).code == Code.UPSTREAM_ERROR


def test_tls_server_name_is_sent_as_sni(tmp_path: Any) -> None:
    """The server name also goes out as SNI."""
    ca = itest.test_ca()
    sctx = ca.server_context()
    got: list[str | None] = []

    def sni(sock: ssl.SSLSocket, name: str | None, _: ssl.SSLContext) -> None:
        got.append(name)

    sctx.sni_callback = sni
    lsock = socket.socket()
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(1)
    port = lsock.getsockname()[1]

    def serve() -> None:
        conn, _ = lsock.accept()
        try:
            with sctx.wrap_socket(conn, server_side=True) as tls:
                f = tls.makefile("rb")
                while f.readline() not in (b"\r\n", b""):
                    pass
                tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
        except OSError:
            pass

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    try:
        c = Client(http=new_http_client(Options(ssl_context=ca.client_context(), tls_server_name="example.com", timeout=2.0)), base=f"https://127.0.0.1:{port}")
        c.do(background(), Request(path="/"))
    finally:
        t.join(3)
        lsock.close()
    assert got == ["example.com"], got


@pytest.mark.parametrize(
    ("value", "want"),
    [("3", 3.0), ("+3", 3.0), ("-3", 0.0), ("0", 0.0), ("+-5", 0.0), ("٣", 0.0), (" 7 ", 7.0), ("99999999999999999999", 0.0), ("1.5", 0.0)],
)
def test_retry_after_seconds_parse_like_atoi(value: str, want: float) -> None:
    """Retry-After in seconds is read as Go's strconv.Atoi reads it: an
    optional sign and ASCII digits within int64; anything else is not a
    delay (and not an exception)."""
    h = Headers()
    h.set("Retry-After", value)
    assert httpx._retry_after(h) == want


def test_json_helpers_can_skip_decoding(servers: Callable[..., itest.Server]) -> None:
    """Go's GetJSON/PostJSON with a nil out do not decode: an empty 204
    is not an error then."""
    srv = servers(lambda w, r: w.write_header(204))
    c = new_test_client(srv, io.StringIO())
    resp, v = c.get_json(background(), "/x", None, decode=False)
    assert resp.status == 204 and v is None
    resp, v = c.post_json(background(), "/x", {"a": 1}, decode=False)
    assert resp.status == 204 and v is None
    with pytest.raises(ValueError, match="empty body"):
        c.get_json(background(), "/x", None)


def test_transport_error_unwraps_to_its_cause(servers: Callable[..., itest.Server]) -> None:
    """A TransportError's chain reaches the underlying error, as Go's
    transportError unwraps to it."""
    srv = servers(_ok)
    c = Client(http=new_http_client(Options(timeout=2.0)), base=srv.url, sleep=_no_sleep)
    err = _err(lambda: c.do(background(), Request(path="/")))
    assert as_error(err, TransportError) is not None and is_error(err, ssl.SSLCertVerificationError), repr(err)
