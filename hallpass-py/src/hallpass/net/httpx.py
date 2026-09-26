"""The one HTTP client every integration uses.

It builds a per-connection transport (TLS 1.2+, private CA, proxy, server
name), never follows redirects, caps response bodies, retries only
idempotent calls with jittered backoff, honours Retry-After, and never logs
request or response bodies. Standard library only.
"""

from __future__ import annotations

import base64
import email.utils
import hashlib
import http.client
import json
import os
import random
import re
import socket
import ssl
import threading
import time
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, NoReturn

from hallpass.core import evidence
from hallpass.core.context import Context, DeadlineExceeded, context_ended
from hallpass.core.decision import Code, HallpassError, wrap_error
from hallpass.core.errors import JoinedError, as_error, is_error
from hallpass.core.integration import DEFAULT_TIMEOUT, is_loopback_host
from hallpass.core.log import Logger

__all__ = [
    "MAX_BODY",
    "MAX_PAGES",
    "BodyTooLarge",
    "Client",
    "Headers",
    "Options",
    "PreparedRequest",
    "Request",
    "Response",
    "StatusError",
    "TooManyPages",
    "Transport",
    "TransportError",
    "basic_auth",
    "bearer_auth",
    "classify",
    "encode_query",
    "header_auth",
    "link_next",
    "new_http_client",
    "path_escape",
    "status",
]

# Stamped into the User-Agent header. The CLI sets it from the package.
VERSION = "dev"

# The response size cap. Larger bodies are an error.
MAX_BODY = 10 << 20

# Caps pagination loops.
MAX_PAGES = 50

# Bounds connecting and the TLS handshake regardless of the connection's
# timeout: an unreachable host should fail fast.
_CONNECT_TIMEOUT_CAP = 5.0

_MAX_ETAG = 128


# -- headers ----------------------------------------------------------------

_TOKEN = frozenset("!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")


def canonical_key(k: str) -> str:
    """Go's textproto.CanonicalMIMEHeaderKey."""
    if not k or any(c not in _TOKEN for c in k):
        return k
    out = []
    upper = True
    for c in k:
        out.append(c.upper() if upper else c.lower())
        upper = c == "-"
    return "".join(out)


class Headers:
    """A case-insensitive, multi-valued header map (Go's http.Header)."""

    def __init__(self, items: Mapping[str, str | Iterable[str]] | Iterable[tuple[str, str]] | None = None) -> None:
        self._d: dict[str, list[str]] = {}
        if items is None:
            return
        pairs = items.items() if isinstance(items, Mapping) else items
        for k, v in pairs:
            if isinstance(v, str):
                self.add(k, v)
            else:
                for x in v:
                    self.add(k, x)

    def get(self, k: str) -> str:
        vs = self._d.get(canonical_key(k))
        return vs[0] if vs else ""

    def values(self, k: str) -> list[str]:
        return list(self._d.get(canonical_key(k), []))

    def set(self, k: str, v: str) -> None:
        self._d[canonical_key(k)] = [v]

    def add(self, k: str, v: str) -> None:
        self._d.setdefault(canonical_key(k), []).append(v)

    def delete(self, k: str) -> None:
        self._d.pop(canonical_key(k), None)

    def __contains__(self, k: object) -> bool:
        return isinstance(k, str) and canonical_key(k) in self._d

    def items(self) -> list[tuple[str, list[str]]]:
        return [(k, list(v)) for k, v in self._d.items()]

    def keys(self) -> list[str]:
        return list(self._d)

    def clone(self) -> Headers:
        h = Headers()
        h._d = {k: list(v) for k, v in self._d.items()}
        return h

    def __repr__(self) -> str:
        return f"Headers({self._d!r})"


# -- errors -----------------------------------------------------------------


class TransportError(Exception):
    """The request did not complete: a connection, TLS or read failure."""

    def __init__(self, err: BaseException, msg: str = "") -> None:
        self.err = err
        self.__cause__ = err
        super().__init__("transport: " + (msg or _redact_err(err)))

    def timeout(self) -> bool:
        return any(isinstance(e, (socket.timeout, TimeoutError)) and not isinstance(e, DeadlineExceeded) for e in _chain_all(self.err))


def _chain_all(err: BaseException) -> Iterable[BaseException]:
    from hallpass.core.errors import chain

    return chain(err)


class BodyTooLarge(Exception):
    def __init__(self) -> None:
        super().__init__("response body exceeds size limit")


class TooManyPages(Exception):
    def __init__(self) -> None:
        super().__init__("pagination exceeded the page limit")


class StatusError(Exception):
    """A 4xx or 5xx response (unless the request accepted 4xx)."""

    def __init__(self, status: int, method: str, url: str, snippet: str, header: Headers) -> None:
        self.status = status
        self.method = method
        self.url = url
        # The first bytes of the body, for the integration's own
        # classification. Never copied into a decision text verbatim.
        self.snippet = snippet
        self.header = header
        super().__init__(f"{method} {_redact_url(url)}: HTTP {status}")

    def retry_after(self) -> float:
        return _retry_after(self.header)


# -- transport --------------------------------------------------------------


@dataclass
class Options:
    # Replaces the system roots when set.
    ca_file: str = ""
    # Overrides the name verified against the certificate (and sent as SNI),
    # for systems addressed by IP.
    tls_server_name: str = ""
    # Routes requests through an HTTP(S) proxy. Empty means the environment
    # proxy settings (HTTPS_PROXY, HTTP_PROXY, NO_PROXY; never for loopback).
    proxy_url: str = ""
    # Bounds one whole request. Zero means 8 s. Connecting and the TLS
    # handshake are each capped at the smaller of 5 s and this.
    timeout: float = 0.0
    # Lets tests inject a context directly.
    ssl_context: ssl.SSLContext | None = None

    def effective_timeout(self) -> float:
        return self.timeout if self.timeout > 0 else DEFAULT_TIMEOUT


@dataclass
class PreparedRequest:
    """A request as it will be sent. Auth functions may change headers."""

    method: str
    url: str
    headers: Headers
    body: bytes = b""

    @property
    def parsed(self) -> urllib.parse.SplitResult:
        return urllib.parse.urlsplit(self.url)


@dataclass
class RawResponse:
    status: int
    headers: Headers
    body: bytes


def _make_ssl_context(o: Options) -> ssl.SSLContext:
    if o.ssl_context is not None:
        return o.ssl_context
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    if o.ca_file:
        try:
            with open(o.ca_file, "rb") as f:
                pem = f.read()
        except OSError as e:
            raise ValueError(f"ca_file: open {o.ca_file}: {e.strerror or e}") from None
        try:
            ctx.load_verify_locations(cadata=pem.decode("ascii", "replace"))
        except (ssl.SSLError, ValueError):
            raise ValueError(f"ca_file {o.ca_file}: no PEM certificates found") from None
    else:
        ctx.load_default_certs(ssl.Purpose.SERVER_AUTH)
        cafile = os.environ.get("SSL_CERT_FILE")
        if cafile and os.path.exists(cafile):
            ctx.load_verify_locations(cafile=cafile)
    ctx.set_alpn_protocols(["http/1.1"])
    return ctx


@dataclass
class _Proxy:
    scheme: str
    host: str
    port: int
    auth: str = ""  # a Proxy-Authorization value, when the URL carried userinfo


def _parse_proxy(raw: str) -> _Proxy:
    if "://" not in raw:
        raw = "http://" + raw
    u = urllib.parse.urlsplit(raw)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise ValueError(f'proxy_url "{raw}" must be an http:// or https:// URL')
    port = u.port or (443 if u.scheme == "https" else 80)
    auth = ""
    if u.username is not None:
        cred = f"{urllib.parse.unquote(u.username)}:{urllib.parse.unquote(u.password or '')}"
        auth = "Basic " + base64.b64encode(cred.encode()).decode()
    return _Proxy(u.scheme, u.hostname, port, auth)


class _PooledConn:
    __slots__ = ("conn", "used")

    def __init__(self, conn: http.client.HTTPConnection) -> None:
        self.conn = conn
        self.used = False


class Transport:
    """Go's *http.Client with the transport NewHTTPClient builds: no
    redirects, the per-connection TLS settings, a whole-request timeout,
    and a small keep-alive pool."""

    _MAX_IDLE_PER_HOST = 10

    def __init__(self, o: Options) -> None:
        self.options = o
        self.timeout = o.effective_timeout()
        self.connect_timeout = min(_CONNECT_TIMEOUT_CAP, self.timeout)
        self.ssl_context = _make_ssl_context(o)
        self._proxy: _Proxy | None = _parse_proxy(o.proxy_url) if o.proxy_url else None
        self._lock = threading.Lock()
        self._idle: dict[tuple[str, str, int, str], list[http.client.HTTPConnection]] = {}

    # -- proxy selection --

    def _proxy_for(self, scheme: str, host: str) -> _Proxy | None:
        if self._proxy is not None:
            return self._proxy
        # The environment, as Go's ProxyFromEnvironment reads it: never for
        # loopback, honouring NO_PROXY.
        if is_loopback_host(host):
            return None
        env = urllib.request.getproxies_environment()
        raw = env.get(scheme)
        if not raw:
            return None
        if urllib.request.proxy_bypass_environment(host, env):  # type: ignore[attr-defined]
            return None
        try:
            return _parse_proxy(raw)
        except ValueError:
            return None

    # -- connections --

    def _new_conn(self, scheme: str, host: str, port: int, proxy: _Proxy | None, timeout: float) -> http.client.HTTPConnection:
        server_name = self.options.tls_server_name or host
        if scheme == "https":
            if proxy is None:
                return _HTTPSConnection(host, port, timeout, self.ssl_context, server_name)
            return _TunnelConnection(host, port, timeout, self.ssl_context, server_name, proxy)
        if proxy is None:
            return http.client.HTTPConnection(host, port, timeout=timeout)
        # Plain HTTP through a proxy: absolute-form requests to the proxy.
        if proxy.scheme == "https":
            return _HTTPSConnection(proxy.host, proxy.port, timeout, self.ssl_context, proxy.host)
        return http.client.HTTPConnection(proxy.host, proxy.port, timeout=timeout)

    def _get_conn(self, key: tuple[str, str, int, str]) -> http.client.HTTPConnection | None:
        with self._lock:
            idle = self._idle.get(key)
            while idle:
                c = idle.pop()
                if c.sock is not None:
                    return c
        return None

    def _put_conn(self, key: tuple[str, str, int, str], c: http.client.HTTPConnection) -> None:
        with self._lock:
            idle = self._idle.setdefault(key, [])
            if len(idle) < self._MAX_IDLE_PER_HOST:
                idle.append(c)
                return
        c.close()

    def close(self) -> None:
        with self._lock:
            conns = [c for idle in self._idle.values() for c in idle]
            self._idle.clear()
        for c in conns:
            c.close()

    def send(self, ctx: Context, req: PreparedRequest, max_body: int = MAX_BODY) -> RawResponse:
        """One exchange, bounded by the transport's timeout and ctx's
        deadline. Redirects are returned as responses, never followed."""
        ctx.check()
        u = urllib.parse.urlsplit(req.url)
        scheme = u.scheme.lower()
        if scheme not in ("http", "https"):
            raise TransportError(ValueError(f"unsupported protocol scheme {scheme!r}"))
        host = u.hostname or ""
        try:
            port = u.port or (443 if scheme == "https" else 80)
        except ValueError as e:
            raise TransportError(e) from e
        proxy = self._proxy_for(scheme, host)
        deadline = time.monotonic() + self.timeout
        cd = ctx.deadline()
        if cd is not None:
            deadline = min(deadline, cd)
        target = u.path or "/"
        if u.query:
            target += "?" + u.query
        headers = req.headers.clone()
        hostport = u.netloc.rpartition("@")[2]
        if proxy is not None and scheme == "http":
            target = f"{scheme}://{hostport}{target}"
            if proxy.auth:
                headers.set("Proxy-Authorization", proxy.auth)
        key = (scheme, host.lower(), port, f"{proxy.host}:{proxy.port}" if proxy else "")
        attempts = 0
        while True:
            attempts += 1
            conn = self._get_conn(key)
            reused = conn is not None
            if conn is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise _deadline_error(ctx)
                conn = self._new_conn(scheme, host, port, proxy, min(self.connect_timeout, remaining))
            try:
                resp = self._exchange(conn, req.method, target, headers, req.body, hostport, deadline, max_body, ctx)
            except _Stale as stale:
                conn.close()
                # A keep-alive connection the server closed while idle: try
                # a new one, as Go's transport does, when the request was not
                # written yet or can be replayed safely.
                if reused and attempts < 3 and (not stale.sent or _replayable(req)):
                    continue
                raise TransportError(ConnectionResetError("connection closed by the server")) from None
            except BaseException:
                conn.close()
                raise
            if resp[3]:
                self._put_conn(key, conn)
            else:
                conn.close()
            return RawResponse(resp[0], resp[1], resp[2])

    def _exchange(
        self,
        conn: http.client.HTTPConnection,
        method: str,
        target: str,
        headers: Headers,
        body: bytes,
        hostport: str,
        deadline: float,
        max_body: int,
        ctx: Context,
    ) -> tuple[int, Headers, bytes, bool]:
        def remaining() -> float:
            r = deadline - time.monotonic()
            if r <= 0:
                raise _deadline_error(ctx)
            return r

        sent = False
        try:
            if conn.sock is None:
                conn.timeout = min(self.connect_timeout, remaining())
                conn.connect()
            assert conn.sock is not None
            conn.sock.settimeout(remaining())
            conn.putrequest(method, target, skip_host=True, skip_accept_encoding=True)
            if "Host" not in headers:
                conn.putheader("Host", hostport)
            for k, vs in headers.items():
                for v in vs:
                    conn.putheader(k, v)
            if body or method in ("POST", "PUT", "PATCH"):
                conn.putheader("Content-Length", str(len(body)))
            conn.endheaders(body if body else None)
            sent = True
            conn.sock.settimeout(remaining())
            r = conn.getresponse()
        except (http.client.RemoteDisconnected, BrokenPipeError, ConnectionResetError) as e:
            if not sent or isinstance(e, http.client.RemoteDisconnected):
                raise _Stale(sent) from e
            raise TransportError(e) from e
        except TimeoutError as e:
            if ctx.err() is not None or time.monotonic() >= deadline:
                _raise_timeout(ctx, e)
            raise TransportError(e) from e
        except (OSError, http.client.HTTPException, ssl.SSLError) as e:
            raise TransportError(e) from e
        try:
            out = bytearray()
            while True:
                if conn.sock is not None:
                    conn.sock.settimeout(remaining())
                chunk = r.read1(65536) if hasattr(r, "read1") else r.read(65536)
                if not chunk:
                    break
                out.extend(chunk)
                if len(out) > max_body:
                    r.close()
                    raise BodyTooLarge()
        except BodyTooLarge:
            raise
        except TimeoutError as e:
            _raise_timeout(ctx, e)
        except (OSError, http.client.HTTPException) as e:
            raise TransportError(e) from e
        h = Headers()
        for k, v in r.getheaders():
            h.add(k, v)
        return r.status, h, bytes(out), not r.will_close


class _Stale(Exception):
    """A reused keep-alive connection the server had already closed."""

    def __init__(self, sent: bool) -> None:
        super().__init__("stale connection")
        self.sent = sent


def _replayable(req: PreparedRequest) -> bool:
    """Go's Request.isReplayable: safe methods, or an idempotency key."""
    return req.method in ("GET", "HEAD", "OPTIONS", "TRACE") or bool(req.headers.get("Idempotency-Key") or req.headers.get("X-Idempotency-Key"))


def _deadline_error(ctx: Context) -> BaseException:
    e = ctx.err()
    if e is not None:
        return e
    return TransportError(TimeoutError("Client.Timeout exceeded while awaiting headers"))


def _raise_timeout(ctx: Context, cause: BaseException) -> NoReturn:
    """Raise the context's own error when it ended, else a TransportError
    whose cause is the socket timeout (Go's transportError unwraps to it).
    The context's error is shared by every caller, so it gets no cause."""
    err = _timeout_error(ctx, cause)
    if isinstance(err, TransportError):
        raise err from cause
    raise err from None


def _timeout_error(ctx: Context, cause: BaseException) -> BaseException:
    e = ctx.err()
    if e is not None:
        return e
    return TransportError(cause, "Client.Timeout exceeded")


class _HTTPSConnection(http.client.HTTPConnection):
    """HTTPS with a separate server name for SNI and verification."""

    default_port = 443

    def __init__(self, host: str, port: int, timeout: float, ssl_context: ssl.SSLContext, server_name: str) -> None:
        super().__init__(host, port, timeout=timeout)
        self._ssl_context = ssl_context
        self._server_name = server_name

    def connect(self) -> None:
        super().connect()
        assert self.sock is not None
        self.sock = self._ssl_context.wrap_socket(self.sock, server_hostname=self._server_name)


class _TunnelConnection(http.client.HTTPConnection):
    """HTTPS to host:port through a CONNECT tunnel on an HTTP or HTTPS proxy."""

    default_port = 443

    def __init__(self, host: str, port: int, timeout: float, ssl_context: ssl.SSLContext, server_name: str, proxy: _Proxy) -> None:
        super().__init__(proxy.host, proxy.port, timeout=timeout)
        self._target = (host, port)
        self._ssl_context = ssl_context
        self._server_name = server_name
        self._proxy = proxy

    def connect(self) -> None:
        sock = socket.create_connection((self._proxy.host, self._proxy.port), self.timeout)
        try:
            if self._proxy.scheme == "https":
                # The proxy is verified with the connection's own TLS
                # settings (its ca_file, TLS 1.2+), as Go's transport
                # verifies an https:// proxy with its TLSClientConfig.
                sock = self._ssl_context.wrap_socket(sock, server_hostname=self._proxy.host)
            th, tp = self._target
            hp = f"[{th}]:{tp}" if ":" in th else f"{th}:{tp}"
            lines = [f"CONNECT {hp} HTTP/1.1", f"Host: {hp}"]
            if self._proxy.auth:
                lines.append(f"Proxy-Authorization: {self._proxy.auth}")
            sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1"))
            resp = http.client.HTTPResponse(sock, method="CONNECT")
            resp.begin()
            if resp.status != 200:
                raise OSError(f"proxy CONNECT {hp}: {resp.status} {resp.reason}")
            if self._proxy.scheme == "https":
                # TLS inside TLS: the target's handshake runs over the
                # proxy's TLS session through memory BIOs.
                self.sock = _TLSInTLS(sock, self._ssl_context, self._server_name)  # type: ignore[arg-type]
            else:
                self.sock = self._ssl_context.wrap_socket(sock, server_hostname=self._server_name)
        except BaseException:
            sock.close()
            raise


class _TLSInTLS:
    """A minimal socket over an SSLObject running on an outer TLS socket.
    Enough for http.client: sendall, recv/recv_into, makefile, settimeout."""

    def __init__(self, outer: ssl.SSLSocket, ctx: ssl.SSLContext, server_name: str) -> None:
        self._outer = outer
        self._in = ssl.MemoryBIO()
        self._out = ssl.MemoryBIO()
        self._obj = ctx.wrap_bio(self._in, self._out, server_hostname=server_name)
        self._handshake()

    def _pump_out(self) -> None:
        data = self._out.read()
        if data:
            self._outer.sendall(data)

    def _pump_in(self) -> bool:
        data = self._outer.recv(65536)
        if not data:
            self._in.write_eof()
            return False
        self._in.write(data)
        return True

    def _handshake(self) -> None:
        while True:
            try:
                self._obj.do_handshake()
                self._pump_out()
                return
            except ssl.SSLWantReadError:
                self._pump_out()
                if not self._pump_in():
                    raise ConnectionResetError("proxy closed the tunnel during the TLS handshake") from None

    def settimeout(self, t: float | None) -> None:
        self._outer.settimeout(t)

    def sendall(self, data: bytes) -> None:
        view = memoryview(data)
        while view:
            n = self._obj.write(view)
            view = view[n:]
            self._pump_out()

    def recv(self, n: int) -> bytes:
        while True:
            try:
                return self._obj.read(n)
            except ssl.SSLWantReadError:
                self._pump_out()
                if not self._pump_in():
                    return b""
            except ssl.SSLZeroReturnError:
                return b""

    def recv_into(self, buf: Any, n: int = 0) -> int:
        data = self.recv(n or len(buf))
        buf[: len(data)] = data
        return len(data)

    def makefile(self, mode: str = "rb", buffering: int = -1) -> Any:
        return _BufferedReader(self)

    def close(self) -> None:
        try:
            self._outer.close()
        except OSError:
            pass


class _BufferedReader:
    """A read-only binary file over _TLSInTLS for http.client."""

    def __init__(self, s: _TLSInTLS) -> None:
        self._s = s
        self._buf = bytearray()
        self.closed = False

    def _fill(self) -> bool:
        data = self._s.recv(65536)
        if not data:
            return False
        self._buf.extend(data)
        return True

    def readline(self, limit: int = -1) -> bytes:
        while b"\n" not in self._buf:
            if limit >= 0 and len(self._buf) >= limit:
                break
            if not self._fill():
                break
        i = self._buf.find(b"\n")
        n = i + 1 if i >= 0 else len(self._buf)
        if limit >= 0:
            n = min(n, limit)
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out

    def read(self, n: int = -1) -> bytes:
        if n is None or n < 0:
            while self._fill():
                pass
            out = bytes(self._buf)
            self._buf.clear()
            return out
        while len(self._buf) < n and self._fill():
            pass
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out

    def read1(self, n: int = -1) -> bytes:
        if not self._buf:
            self._fill()
        if n is None or n < 0:
            n = len(self._buf)
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out

    def readinto(self, b: Any) -> int:
        data = self.read(len(b))
        b[: len(data)] = data
        return len(data)

    def peek(self, n: int = 0) -> bytes:
        if not self._buf:
            self._fill()
        return bytes(self._buf)

    def flush(self) -> None:
        pass

    def close(self) -> None:
        self.closed = True


def new_http_client(o: Options) -> Transport:
    """A transport that never follows redirects."""
    return Transport(o)


# -- client -----------------------------------------------------------------

AuthFunc = Callable[[Context, PreparedRequest], None]


@dataclass
class Request:
    """One call."""

    method: str = "GET"
    # Absolute (https://...) or relative to Client.base.
    path: str = ""
    query: Mapping[str, str | list[str]] | None = None
    header: Headers | Mapping[str, str] | None = None
    # Sent as-is. json sets body and Content-Type from a value.
    body: bytes | None = None
    json: Any = None
    # Sets body and Content-Type from URL-encoded values.
    form: Mapping[str, str | list[str]] | None = None
    # Overrides the method-based default (GET/HEAD/OPTIONS).
    idempotent: bool | None = None
    # Keeps 4xx responses from becoming errors.
    accept_4xx: bool = False

    def is_idempotent(self) -> bool:
        if self.idempotent is not None:
            return self.idempotent
        return (self.method or "GET") in ("GET", "HEAD", "OPTIONS")


@dataclass
class Response:
    """What do() returns for any HTTP status."""

    status: int
    header: Headers
    body: bytes
    # The request, for the evidence record; host is "" for a call to the
    # client's own base host.
    method: str = field(default="", repr=False)
    path: str = field(default="", repr=False)
    host: str = field(default="", repr=False)

    def json(self) -> Any:
        """Decode the body. Trailing data after the first value is ignored,
        as a streaming decoder would."""
        text = self.body.decode("utf-8", "replace")
        stripped = text.lstrip(" \t\r\n")
        if not stripped:
            raise ValueError("empty body")
        v, _ = json.JSONDecoder(parse_constant=_reject_constant).raw_decode(stripped)
        return v


def _reject_constant(name: str) -> Any:
    """NaN, Infinity and -Infinity are not JSON; Go's decoder rejects them."""
    raise ValueError(f"invalid character {name[0]!r} looking for beginning of value")


def encode_query(q: Mapping[str, str | list[str]] | None) -> str:
    """Go's url.Values.Encode: keys sorted, values in order, QueryEscape."""
    if not q:
        return ""
    parts = []
    for k in sorted(q):
        v = q[k]
        vs = [v] if isinstance(v, str) else list(v)
        ek = urllib.parse.quote_plus(k, safe="-_.~")
        for x in vs:
            parts.append(ek + "=" + urllib.parse.quote_plus(x, safe="-_.~"))
    return "&".join(parts)


def _escape_url(u: str) -> str:
    """Percent-encode what a request line cannot carry (spaces, controls,
    non-ASCII) while keeping existing escapes, as Go's URL.String does."""
    return urllib.parse.quote(u, safe="%/:?#[]@!$&'()*+,;=-._~")


def _absolute(p: str) -> bool:
    return p.startswith("https://") or p.startswith("http://")


class Client:
    """A Transport with the conventions integrations need."""

    def __init__(
        self,
        http: Transport | None = None,
        base: str = "",
        auth: AuthFunc | None = None,
        logger: Logger | None = None,
        retries: int = 0,
        max_body: int = 0,
        sleep: Callable[[Context, float], None] | None = None,
        user_agent: str = "",
    ) -> None:
        self.http = http
        # Prepended to relative request paths.
        self.base = base
        # Adds credentials to each request, before every attempt, so a
        # refreshed token is picked up on retry.
        self.auth = auth
        # One debug line per call: method, host, path, status, duration.
        self.logger = logger
        # Extra attempts for idempotent calls (default 2).
        self.retries = retries
        self.max_body = max_body
        self.sleep_fn = sleep
        self.user_agent = user_agent

    def _base_url(self) -> urllib.parse.SplitResult | None:
        try:
            u = urllib.parse.urlsplit(self.base)
        except ValueError:
            return None
        if not u.netloc:
            return None
        return u

    def _sleep(self, ctx: Context, d: float) -> None:
        if self.sleep_fn is not None:
            self.sleep_fn(ctx, d)
            return
        ev = threading.Event()
        rem = ctx.remaining()
        if rem is not None and rem < d:
            ctx.wait(ev)  # returns when the deadline passes
            ctx.check()
            return
        cancelled = threading.Event()
        remove = ctx.on_cancel(cancelled.set)
        try:
            if cancelled.wait(d):
                ctx.check()
        finally:
            remove()

    def build(self, ctx: Context, r: Request) -> PreparedRequest:
        u = r.path
        if not _absolute(u):
            if self.base == "":
                raise ValueError(f'relative path "{r.path}" with no base URL')
            u = self.base.rstrip("/") + "/" + r.path.lstrip("/")
        if r.query:
            u += ("&" if "?" in u else "?") + encode_query(r.query)
        u = _escape_url(u)
        body = b""
        ctype = ""
        if r.json is not None:
            body = json.dumps(r.json, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            ctype = "application/json"
        elif r.form is not None:
            body = encode_query(r.form).encode("ascii")
            ctype = "application/x-www-form-urlencoded"
        elif r.body is not None:
            body = r.body
        method = r.method or "GET"
        h = r.header.clone() if isinstance(r.header, Headers) else Headers(r.header or {})
        if ctype and not h.get("Content-Type"):
            h.set("Content-Type", ctype)
        if not h.get("Accept"):
            h.set("Accept", "application/json")
        h.set("User-Agent", self.user_agent or ("hallpass/" + VERSION))
        req = PreparedRequest(method=method, url=u, headers=h, body=body)
        if self.auth is not None:
            # A token exchange made from auth is not evidence for the
            # decision and its response carries the credential.
            self.auth(evidence.without_recorder(ctx), req)
        return req

    def do(self, ctx: Context, r: Request) -> Response:
        """Perform the request. Retries happen only for idempotent requests
        on connection errors, 502/503/504 and 429 with a short Retry-After.

        The response of any status is recorded as evidence on the context's
        recorder; attempts that were retried are not. A 4xx/5xx raises
        StatusError; the response is on the exception as ``response``.
        """
        resp: Response | None = None
        try:
            resp = self._do(ctx, r)
            return resp
        except BaseException as e:
            resp = getattr(e, "response", None)
            raise
        finally:
            if resp is not None:
                rec = evidence.recorder_from(ctx)
                if rec is not None:
                    rec.record(_evidence_of(resp))

    def _do(self, ctx: Context, r: Request) -> Response:
        retries = self.retries or 2
        if not r.is_idempotent():
            retries = 0
        attempt = 0
        while True:
            try:
                return self._once(ctx, r)
            except Exception as err:
                last = err
                if attempt >= retries or not _retryable(err):
                    raise
                wait = _backoff(attempt)
                se = as_error(err, StatusError)
                if se is not None:
                    ra = se.retry_after()
                    if ra > 0:
                        if ra > 5.0:
                            raise
                        wait = ra
                try:
                    self._sleep(ctx, wait)
                except BaseException as serr:  # noqa: BLE001 - re-raised joined with the last error
                    # The response that was going to be retried is what the
                    # caller is told about; the context's end travels with it.
                    joined = JoinedError(serr, last)
                    joined.response = getattr(last, "response", None)  # type: ignore[attr-defined]
                    raise joined from None
            attempt += 1

    def _once(self, ctx: Context, r: Request) -> Response:
        req = self.build(ctx, r)
        start = time.monotonic()
        hc = self.http or _default_transport()
        max_body = self.max_body if self.max_body > 0 else MAX_BODY
        u = urllib.parse.urlsplit(req.url)
        try:
            raw = hc.send(ctx, req, max_body)
        except BodyTooLarge as e:
            self._log_call(req, 0, start, e)
            raise
        except TransportError as e:
            self._log_call(req, 0, start, e)
            raise
        except BaseException as e:
            self._log_call(req, 0, start, e)
            raise
        self._log_call(req, raw.status, start, None)
        out = Response(raw.status, raw.headers, raw.body, method=req.method, path=u.path)
        if _absolute(r.path):
            out.host = self._foreign_host(u)
        if raw.status >= 400 and not (r.accept_4xx and raw.status < 500):
            se = StatusError(raw.status, req.method, req.url, _snippet(raw.body), raw.headers)
            se.response = out  # type: ignore[attr-defined]
            raise se
        return out

    def _foreign_host(self, u: urllib.parse.SplitResult) -> str:
        base = self._base_url()
        if base is not None and _same_host(base, u):
            return ""
        return u.netloc.rpartition("@")[2]

    def _log_call(self, req: PreparedRequest, status: int, start: float, err: BaseException | None) -> None:
        if self.logger is None:
            return
        u = urllib.parse.urlsplit(req.url)
        attrs: dict[str, Any] = {
            "method": req.method,
            "host": u.netloc.rpartition("@")[2],
            "path": urllib.parse.unquote(u.path),
            "status": status,
            "duration_ms": int((time.monotonic() - start) * 1000),
        }
        if err is not None:
            attrs["error"] = _redact_err(err)
        self.logger.debug("http", **attrs)

    # -- helpers --

    def get_json(self, ctx: Context, path: str, q: Mapping[str, str | list[str]] | None = None, decode: bool = True) -> tuple[Response, Any]:
        """do + JSON decode for a GET. decode=False skips the decode (Go's
        nil out) and returns None as the value."""
        resp = self.do(ctx, Request(method="GET", path=path, query=q))
        if not decode:
            return resp, None
        try:
            return resp, resp.json()
        except ValueError as e:
            raise ValueError(f"decode {_redact_url(path)}: {e}") from e

    def post_json(self, ctx: Context, path: str, body: Any, idempotent: bool = False, decode: bool = True) -> tuple[Response, Any]:
        """do + JSON decode for a POST with a JSON body. POST is not
        retried unless idempotent is set. decode=False skips the decode."""
        resp = self.do(ctx, Request(method="POST", path=path, json=body, idempotent=idempotent))
        if not decode:
            return resp, None
        try:
            return resp, resp.json()
        except ValueError as e:
            raise ValueError(f"decode {_redact_url(path)}: {e}") from e

    def next_link(self, h: Headers) -> str:
        """The rel="next" URL of a Link header when it stays within the
        base URL, "" when there is none; ValueError when the upstream points
        elsewhere, since the credential goes with every request."""
        nxt = link_next(h)
        if nxt == "":
            return ""
        if not self.within(nxt):
            raise ValueError(f"next page link {_redact_url(nxt)} is outside the client's base URL")
        return nxt

    def within(self, raw_url: str) -> bool:
        """raw_url is a page under base: same scheme and host, and a path
        under the base path. A relative path always is."""
        if not _absolute(raw_url):
            return True
        base = self._base_url()
        if base is None:
            return False
        try:
            u = urllib.parse.urlsplit(raw_url)
            _ = u.port
        except ValueError:
            return False
        if "@" in u.netloc:
            return False
        if u.scheme != base.scheme or not _same_host(base, u):
            return False
        prefix = urllib.parse.unquote(base.path).rstrip("/")
        path = urllib.parse.unquote(u.path)
        return path == prefix or path.startswith(prefix + "/")

    def paginate(self, ctx: Context, req: Request | None, page: Callable[[Response], Request | None]) -> None:
        """Run req, call page with each response, follow the request page
        returns until None. TooManyPages after MAX_PAGES."""
        n = 0
        while req is not None:
            if n >= MAX_PAGES:
                raise TooManyPages()
            resp = self.do(ctx, req)
            req = page(resp)
            n += 1


_DEFAULT: Transport | None = None
_DEFAULT_LOCK = threading.Lock()


def _default_transport() -> Transport:
    global _DEFAULT
    with _DEFAULT_LOCK:
        if _DEFAULT is None:
            _DEFAULT = Transport(Options())
        return _DEFAULT


def _same_host(a: urllib.parse.SplitResult, b: urllib.parse.SplitResult) -> bool:
    return (a.hostname or "").lower() == (b.hostname or "").lower() and _effective_port(a) == _effective_port(b)


def _effective_port(u: urllib.parse.SplitResult) -> str:
    try:
        p = u.port
    except ValueError:
        p = None
    if p is not None:
        return str(p)
    s = u.scheme.lower()
    if s == "https":
        return "443"
    if s == "http":
        return "80"
    return ""


def _evidence_of(r: Response) -> evidence.Call:
    """Method, path (no query), the host when not the client's own, status,
    and the ETag or the body's SHA-256. Nothing else."""
    etag = r.header.get("ETag").strip()
    if _valid_etag(etag):
        return evidence.Call(method=r.method, path=r.path, host=r.host, status=r.status, etag=etag)
    sha = hashlib.sha256(r.body).hexdigest() if r.body else ""
    return evidence.Call(method=r.method, path=r.path, host=r.host, status=r.status, sha256=sha)


def _valid_etag(s: str) -> bool:
    if s == "" or len(s) > _MAX_ETAG:
        return False
    return all(0x21 <= ord(c) <= 0x7E for c in s)


def _retryable(err: BaseException) -> bool:
    se = as_error(err, StatusError)
    if se is not None:
        return se.status in (429, 502, 503, 504)
    if context_ended(err) or is_error(err, BodyTooLarge):
        return False
    te = as_error(err, TransportError)
    if te is not None:
        # Resets, refused connections and DNS hiccups are worth one more
        # try. Client-side timeouts are not: the budget is spent.
        return not te.timeout()
    return False


def _backoff(attempt: int) -> float:
    base = min(0.2 * (1 << attempt), 2.0)
    return base / 2 + random.random() * (base / 2)


_ATOI = re.compile(r"[+-]?[0-9]+")


def _retry_after(h: Headers) -> float:
    v = h.get("Retry-After").strip()
    if v == "":
        return 0.0
    if _ATOI.fullmatch(v):
        # Go's strconv.Atoi: an optional sign and ASCII digits within
        # int64; anything else falls through to the date form.
        secs = int(v)
        if -(1 << 63) <= secs < (1 << 63):
            return float(secs) if secs >= 0 else 0.0
    try:
        t = email.utils.parsedate_to_datetime(v)
    except (TypeError, ValueError):
        return 0.0
    if t is None:
        return 0.0
    d = t.timestamp() - time.time()
    return d if d > 0 else 0.0


def _snippet(b: bytes) -> str:
    s = b.decode("utf-8", "ignore")
    enc = s.encode("utf-8")
    if len(enc) > 256:
        s = enc[:256].decode("utf-8", "ignore")
    return s


def _redact_url(s: str) -> str:
    """Strip query strings, fragments and userinfo, which may carry tokens."""
    try:
        u = urllib.parse.urlsplit(s)
    except ValueError:
        return "<url>"
    netloc = u.netloc.rpartition("@")[2]
    return urllib.parse.urlunsplit((u.scheme, netloc, u.path, "", ""))


def _redact_err(err: BaseException) -> str:
    """A transport error's message with any URL redacted, kept short."""
    msg = str(err)
    for word in msg.split():
        if _absolute(word.strip("\"'()<>,")):
            w = word.strip("\"'()<>,")
            msg = msg.replace(w, _redact_url(w))
    return msg


def classify(err: BaseException | None) -> HallpassError | None:
    """A transport or status error as a HallpassError with the right code:
    timeout, rate limit, 401 -> credential_rejected, 5xx and other 4xx ->
    upstream_error. Integrations that need finer handling of 403/404
    inspect the StatusError first."""
    if err is None:
        return None
    he = as_error(err, HallpassError)
    if he is not None:
        return he
    if is_error(err, DeadlineExceeded):
        return wrap_error(Code.UPSTREAM_TIMEOUT, err, "upstream call timed out")
    se = as_error(err, StatusError)
    if se is not None:
        if se.status == 401:
            return wrap_error(Code.CREDENTIAL_REJECTED, err, "the connection's credential was rejected (HTTP 401)")
        if se.status == 429:
            return wrap_error(Code.UPSTREAM_RATE_LIMIT, err, "rate limited by the upstream system")
        return wrap_error(Code.UPSTREAM_ERROR, err, f"upstream returned HTTP {se.status}")
    if is_error(err, BodyTooLarge):
        return wrap_error(Code.UPSTREAM_ERROR, err, "upstream response too large")
    te = as_error(err, TransportError)
    if te is not None:
        if te.timeout():
            return wrap_error(Code.UPSTREAM_TIMEOUT, err, "upstream call timed out")
        return wrap_error(Code.UPSTREAM_ERROR, err, "could not reach the upstream system")
    return wrap_error(Code.UPSTREAM_ERROR, err, "upstream call failed")


def status(err: BaseException | None) -> int:
    """The HTTP status carried by err, or 0. An error already classified
    into a HallpassError reports 0, so a failure from an earlier stage is
    never mistaken for a status of the call at hand."""
    if err is None or as_error(err, HallpassError) is not None:
        return 0
    se = as_error(err, StatusError)
    return se.status if se is not None else 0


def link_next(h: Headers) -> str:
    """The rel="next" URL from an RFC 8288 Link header."""
    for link in h.values("Link"):
        for part in link.split(","):
            seg = part.strip().split(";")
            if len(seg) < 2:
                continue
            u = seg[0].strip()
            if not (u.startswith("<") and u.endswith(">")):
                continue
            for p in seg[1:]:
                p = p.strip()
                if p in ('rel="next"', "rel=next"):
                    return u[1:-1]
    return ""


def path_escape(s: str) -> str:
    """Escape one path segment (Go's url.PathEscape). Slashes are encoded,
    so the value cannot climb out of its position in a path template."""
    return urllib.parse.quote(s, safe="-_.~$&+=:@")


TokenFunc = Callable[[Context], str]


def bearer_auth(token: TokenFunc) -> AuthFunc:
    def auth(ctx: Context, r: PreparedRequest) -> None:
        r.headers.set("Authorization", "Bearer " + token(ctx))

    return auth


def basic_auth(user: str, password: TokenFunc) -> AuthFunc:
    def auth(ctx: Context, r: PreparedRequest) -> None:
        p = password(ctx)
        r.headers.set("Authorization", "Basic " + base64.b64encode(f"{user}:{p}".encode()).decode())

    return auth


def header_auth(name: str, value: TokenFunc) -> AuthFunc:
    def auth(ctx: Context, r: PreparedRequest) -> None:
        r.headers.set(name, value(ctx))

    return auth
