"""The shared test harness for integrations: a fake upstream over TLS with
recorded calls and failure injection, Deps wired to it, and a canary check
that fails a test when a secret shows up in logs.

A port of the original Go harness (internal/integration/itest). Handlers
take (w, r) the way Go handlers do, so tests port line by line:

    srv = itest.Server()
    srv.json("GET", "/rest/api/3/myself", 200, {"accountId": "a1"})
    def h(w, r):
        w.header().set("ETag", '"v1"')
        w.write_header(200)
        w.write(b"{}")
    srv.handle("POST", "/rest/api/3/permissions/check", h)
"""

from __future__ import annotations

import datetime
import io
import ipaddress
import json
import os
import socket
import ssl
import tempfile
import threading
import time
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from hallpass.core import catalog
from hallpass.core.context import background, with_timeout
from hallpass.core.decision import Code, Decision, outcome_of, to_decision
from hallpass.core.integration import CheckRequest, Connection, Deps, Integration, Settings, User, find_action
from hallpass.core.log import DEBUG, JSONHandler, Logger
from hallpass.core.secret import Secret
from hallpass.core.secret import literal as secret_literal
from hallpass.net import httpx

__all__ = [
    "CANARY",
    "Call",
    "Failure",
    "Logs",
    "Server",
    "assert_no_canary",
    "check",
    "deps",
    "expect_code",
    "failure_cases",
    "literal",
    "settings",
    "test_ca",
]

# The substring every test secret must contain. Any log line containing it
# fails the test.
CANARY = "CANARY-SECRET-"


class Failure:
    NONE = ""
    SERVER_ERROR = "500"
    RATE_LIMITED = "429"
    TIMEOUT = "timeout"
    UNAUTHORIZED = "401"


# -- a test CA and server certificate, made once per process ---------------


@dataclass
class _CA:
    ca_pem: bytes
    cert_file: str
    key_file: str
    ca_file: str

    def client_context(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_verify_locations(cadata=self.ca_pem.decode())
        return ctx

    def server_context(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.cert_file, self.key_file)
        return ctx


_CA_LOCK = threading.Lock()
_CA_ONE: _CA | None = None


def test_ca() -> _CA:
    """A CA and a server certificate for 127.0.0.1, ::1, localhost and
    example.com, written to a temporary directory once per process."""
    global _CA_ONE
    with _CA_LOCK:
        if _CA_ONE is not None:
            return _CA_ONE
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        now = datetime.datetime.now(datetime.timezone.utc)
        ca_key = ec.generate_private_key(ec.SECP256R1())
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "hallpass test CA")])
        ca = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(hours=1))
            .not_valid_after(now + datetime.timedelta(days=2))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(ca_key, hashes.SHA256())
        )
        key = ec.generate_private_key(ec.SECP256R1())
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
            .issuer_name(ca_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(hours=1))
            .not_valid_after(now + datetime.timedelta(days=2))
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.DNSName("localhost"),
                        x509.DNSName("example.com"),
                        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                        x509.IPAddress(ipaddress.ip_address("::1")),
                    ]
                ),
                critical=False,
            )
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256())
        )
        d = tempfile.mkdtemp(prefix="hallpass-test-ca-")
        ca_pem = ca.public_bytes(serialization.Encoding.PEM)
        paths = {}
        for name, data in (
            ("ca.pem", ca_pem),
            ("cert.pem", cert.public_bytes(serialization.Encoding.PEM)),
            ("key.pem", key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())),
        ):
            p = os.path.join(d, name)
            with open(p, "wb") as f:
                f.write(data)
            paths[name] = p
        _CA_ONE = _CA(ca_pem, paths["cert.pem"], paths["key.pem"], paths["ca.pem"])
        return _CA_ONE


# -- the fake upstream ------------------------------------------------------


@dataclass
class Call:
    """One recorded upstream request."""

    method: str
    path: str
    query: dict[str, list[str]]
    header: httpx.Headers
    body: bytes
    raw_path: str = ""

    def json(self) -> Any:
        return json.loads(self.body)

    def q(self, key: str) -> str:
        vs = self.query.get(key)
        return vs[0] if vs else ""


class Request:
    """What a handler sees: Go's *http.Request, reduced to what tests use."""

    def __init__(self, method: str, target: str, header: httpx.Headers, body: bytes, host: str) -> None:
        self.method = method
        u = urllib.parse.urlsplit(target)
        self.raw_path = u.path
        self.path = urllib.parse.unquote(u.path)
        self.raw_query = u.query
        self.query = urllib.parse.parse_qs(u.query, keep_blank_values=True)
        self.header = header
        self.body = body
        self.host = host
        self.target = target

    def q(self, key: str) -> str:
        vs = self.query.get(key)
        return vs[0] if vs else ""

    def json(self) -> Any:
        return json.loads(self.body)

    def form(self) -> dict[str, list[str]]:
        return urllib.parse.parse_qs(self.body.decode(), keep_blank_values=True)

    def basic_auth(self) -> tuple[str, str] | None:
        import base64

        h = self.header.get("Authorization")
        if not h.lower().startswith("basic "):
            return None
        try:
            user, _, pw = base64.b64decode(h[6:]).decode().partition(":")
        except Exception:
            return None
        return user, pw


class ResponseWriter:
    """Go's http.ResponseWriter."""

    def __init__(self) -> None:
        self._header = httpx.Headers()
        self.status = 0
        self.buf = io.BytesIO()

    def header(self) -> httpx.Headers:
        return self._header

    def write_header(self, status: int) -> None:
        if self.status == 0:
            self.status = status

    def write(self, b: bytes | str) -> int:
        if self.status == 0:
            self.status = 200
        if isinstance(b, str):
            b = b.encode()
        return self.buf.write(b)


Handler = Callable[[ResponseWriter, Request], None]


@dataclass
class _Route:
    method: str
    path: str  # exact, or prefix when ending in "*"
    h: Handler


class _Abort(Exception):
    """Drop the connection without a response."""


class Server:
    """A fake upstream over TLS (or plain HTTP with tls=False)."""

    def __init__(self, tls: bool = True) -> None:
        self._lock = threading.Lock()
        self._routes: list[_Route] = []
        self._calls: list[Call] = []
        self._fail = Failure.NONE
        # Called for requests no route matches (default 404).
        self.unmatched: Handler | None = None
        self.spec: Any = None
        self.spec_opts: Any = None
        self.spec_errors: list[str] = []
        self.tls = tls
        self._closed = threading.Event()
        # Open client connections, dropped by close() as Go's
        # httptest.Server.Close drops them.
        self._conns: set[Any] = set()
        outer = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: Any) -> None:
                pass

            def setup(self) -> None:
                super().setup()
                with outer._lock:
                    outer._conns.add(self.connection)

            def finish(self) -> None:
                with outer._lock:
                    outer._conns.discard(self.connection)
                try:
                    super().finish()
                except OSError:
                    pass

            def _serve(self) -> None:
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n) if n else b""
                if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
                    body = _read_chunked(self.rfile)
                h = httpx.Headers()
                for k, v in self.headers.items():
                    h.add(k, v)
                r = Request(self.command, self.path, h, body, self.headers.get("Host", ""))
                try:
                    w = outer._dispatch(r)
                except _Abort:
                    self.close_connection = True
                    return
                data = w.buf.getvalue()
                try:
                    self.send_response_only(w.status or 200)
                    for k, vs in w.header().items():
                        for v in vs:
                            self.send_header(k, v)
                    if "Content-Length" not in w.header():
                        self.send_header("Content-Length", str(len(data)))
                    self.send_header("Date", self.date_time_string())
                    self.end_headers()
                    if self.command != "HEAD":
                        self.wfile.write(data)
                except (BrokenPipeError, ConnectionResetError):
                    # The client gave up (its timeout); Go's server drops
                    # the write the same way, silently.
                    self.close_connection = True

            do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = _serve  # noqa: N815

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self._httpd.daemon_threads = True
        self._httpd.block_on_close = False
        if tls:
            self._httpd.socket = test_ca().server_context().wrap_socket(self._httpd.socket, server_side=True)
        self._thread = threading.Thread(target=self._httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self._thread.start()
        host, port = self._httpd.server_address[:2]
        self.url = f"{'https' if tls else 'http'}://{host}:{port}"
        self.host = f"{host}:{port}"

    # -- behaviour --

    def _dispatch(self, r: Request) -> ResponseWriter:
        with self._lock:
            self._calls.append(Call(r.method, r.path, r.query, r.header.clone(), r.body, r.raw_path))
            fail = self._fail
            routes = list(self._routes)
        if self.spec is not None:
            from tests.harness import spec as _spec

            err = _spec.validate_request(self, r)
            if err:
                with self._lock:
                    self.spec_errors.append(err)
        w = ResponseWriter()
        if fail == Failure.SERVER_ERROR:
            w.write_header(500)
            return w
        if fail == Failure.RATE_LIMITED:
            w.header().set("Retry-After", "1")
            w.write_header(429)
            return w
        if fail == Failure.UNAUTHORIZED:
            w.write_header(401)
            return w
        if fail == Failure.TIMEOUT:
            # Hold the request past any client timeout, then drop it: the
            # client only ever sees its own timeout.
            self._closed.wait(5)
            raise _Abort()
        for rt in reversed(routes):
            if rt.method and rt.method != r.method:
                continue
            if rt.path.endswith("*"):
                if not r.path.startswith(rt.path[:-1]):
                    continue
            elif rt.path != r.path:
                continue
            rt.h(w, r)
            return w
        if self.unmatched is not None:
            self.unmatched(w, r)
            return w
        w.write_header(404)
        w.write(json.dumps({"message": f"no route in test server for {r.method} {r.path}"}))
        return w

    def handle(self, method: str, path: str, h: Handler) -> None:
        """Register a handler. Later registrations win. A path ending in "*"
        matches by prefix. An empty method matches any."""
        with self._lock:
            self._routes.append(_Route(method, path, h))

    def json(self, method: str, path: str, status: int, body: Any, headers: dict[str, str] | None = None) -> None:
        """Register a static JSON response."""
        if isinstance(body, (bytes, bytearray)):
            data = bytes(body)
        elif isinstance(body, str):
            data = body.encode()
        else:
            data = json.dumps(body).encode()

        def h(w: ResponseWriter, r: Request) -> None:
            w.header().set("Content-Type", "application/json")
            for k, v in (headers or {}).items():
                w.header().set(k, v)
            w.write_header(status)
            w.write(data)

        self.handle(method, path, h)

    def fail(self, f: str) -> None:
        with self._lock:
            self._fail = f

    def calls(self) -> list[Call]:
        with self._lock:
            return list(self._calls)

    def reset(self) -> None:
        with self._lock:
            self._calls = []

    def last_call(self) -> Call:
        calls = self.calls()
        assert calls, "no upstream calls recorded"
        return calls[-1]

    def use_spec(self, spec: Any, opts: Any = None) -> None:
        """Validate every following request against the API description.
        A None spec (none found in $HALLPASS_SPECS_DIR) is a no-op."""
        if spec is None:
            return
        # Compile the patterns now, as Go's UseSpec does, so a bad one fails
        # here rather than inside a request handler.
        import re

        for p in (*getattr(opts, "strip_prefix", ()), *getattr(opts, "ignore_paths", ())):
            re.compile(p)
        with self._lock:
            self.spec, self.spec_opts = spec, opts

    def close(self) -> None:
        """Stop listening and drop every open connection, so a client's
        idle keep-alive connection cannot reach the closed server."""
        self._closed.set()
        self._httpd.shutdown()
        self._httpd.server_close()
        with self._lock:
            conns = list(self._conns)
            self._conns.clear()
        for c in conns:
            try:
                c.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                c.close()
            except OSError:
                pass

    def __enter__(self) -> Server:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _read_chunked(f: Any) -> bytes:
    out = bytearray()
    while True:
        size = int(f.readline().split(b";", 1)[0].strip() or b"0", 16)
        if size == 0:
            while f.readline() not in (b"\r\n", b"\n", b""):
                pass
            return bytes(out)
        out.extend(f.read(size))
        f.readline()


# -- logs and deps -----------------------------------------------------------


class Logs(io.StringIO):
    """Captures log output for canary checks. Thread-safe."""

    def __init__(self) -> None:
        super().__init__()
        self._lock = threading.Lock()

    def write(self, s: str) -> int:
        with self._lock:
            return super().write(s)

    def text(self) -> str:
        with self._lock:
            return self.getvalue()


def assert_no_canary(text: str) -> None:
    i = text.find(CANARY)
    if i >= 0:
        raise AssertionError(f"a secret leaked into the logs: ...{text[max(0, i - 120) : i + 60]}...")


_OPEN: list[Logs] = []


def deps(srv: Server | None = None, *, now: Callable[[], float] | None = None, connection: Callable[[str], Connection] | None = None) -> tuple[Deps, Logs]:
    """Deps whose HTTP clients trust the test CA and whose logger writes to
    the returned Logs at debug level. The conftest checks every Logs for
    the canary when the test ends."""
    logs = Logs()
    _OPEN.append(logs)
    ca = test_ca()

    def http_client(s: Settings) -> httpx.Transport:
        return httpx.new_http_client(
            httpx.Options(ssl_context=ca.client_context(), timeout=s.effective_timeout(), tls_server_name=s.tls_server_name, proxy_url=s.proxy_url)
        )

    def no_connection(id: str) -> Connection:
        raise AssertionError(f'Connection("{id}") called but no connections wired')

    d = Deps(
        logger=Logger(JSONHandler(logs, DEBUG)),
        connection=connection or no_connection,
        http_client=http_client,
        now=now or time.time,
    )
    return d, logs


def settings(id: str, integ: str, values: dict[str, str] | None = None, secrets: dict[str, Secret] | None = None, **kw: Any) -> Settings:
    """Settings with a short timeout for tests."""
    kw.setdefault("timeout", 2.0)
    return Settings(id, integ, values or {}, secrets or {}, **kw)


def literal(suffix: str) -> Secret:
    """A test secret carrying the canary."""
    return secret_literal(CANARY + suffix)


def check(c: Connection, integ: Integration, u: User, action: str, resource: str) -> Decision:
    """resolve_identity then check the way the engine does, errors turned
    into decisions."""
    ctx, cancel = with_timeout(background(), 3.0)
    try:
        try:
            ident = c.resolve_identity(ctx, u)
        except Exception as e:
            return to_decision(e)
        res = catalog.parse_resource(resource)
        act = find_action(integ, action)
        assert act is not None, f'integration {integ.name()} has no action "{action}"'
        try:
            d = c.check(ctx, CheckRequest(user=u, identity=ident, action=act, action_name=action, resource=res))
        except Exception as e:
            return to_decision(e)
        return d.with_(outcome=outcome_of(d.code))
    finally:
        cancel()


def expect_code(d: Decision, code: Code) -> None:
    assert d.code == code, f"decision = {d.code} ({d.text}), want code {code}"
    assert d.outcome == outcome_of(d.code), f"outcome {d.outcome} does not match code {d.code}"


def failure_cases(srv: Server, check_fn: Callable[[], Decision]) -> None:
    """Run check_fn under every injected failure mode and assert the matching
    unknown code. The check must make at least one upstream call."""
    cases = [
        (Failure.SERVER_ERROR, Code.UPSTREAM_ERROR),
        (Failure.RATE_LIMITED, Code.UPSTREAM_RATE_LIMIT),
        (Failure.UNAUTHORIZED, Code.CREDENTIAL_REJECTED),
        (Failure.TIMEOUT, Code.UPSTREAM_TIMEOUT),
    ]
    for f, code in cases:
        srv.fail(f)
        try:
            d = check_fn()
        finally:
            srv.fail(Failure.NONE)
        assert d.outcome.value == "unknown", f"failure {f}: outcome {d.outcome}, want unknown ({d.code}: {d.text})"
        assert d.code == code, f"failure {f}: code {d.code}, want {code} ({d.text})"
