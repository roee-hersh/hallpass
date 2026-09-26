"""The engine over HTTP: POST /check and GET /healthz. Standard library only."""

from __future__ import annotations

import hmac
import json
import re
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Protocol

from hallpass.core.context import Context, background
from hallpass.core.decision import Code, Decision, unknown_decision
from hallpass.core.engine import Request, Result
from hallpass.core.log import Logger, go_json
from hallpass.core.secret import Secret

__all__ = ["MAX_REQUEST_BODY", "Checker", "Server", "check_body", "decision_body"]

# Bounds a /check body.
MAX_REQUEST_BODY = 64 << 10
_MAX_HEADER_BYTES = 16 << 10
_FIELDS = ("user", "groups", "connection", "action", "resource", "fresh")


class Checker(Protocol):
    def check(self, ctx: Context | None, req: Request) -> Result: ...


def decision_body(d: Decision) -> bytes:
    """The wire response of POST /check."""
    return (go_json({"decision": d.outcome.value, "reason": d.reason()}) + "\n").encode()


def check_body(req: Request) -> dict[str, Any]:
    """The wire request of POST /check, as the CLI's -server mode sends it."""
    out: dict[str, Any] = {"user": req.user}
    if req.groups:
        out["groups"] = list(req.groups)
    out.update(connection=req.connection, action=req.action, resource=req.resource)
    if req.fresh:
        out["fresh"] = True
    return out


_SURROGATE = re.compile("[\ud800-\udfff]")


def _clean(s: str) -> str:
    """A lone surrogate from a \\uD800 escape becomes U+FFFD, as a Go JSON
    decoder makes it, so it can neither slip past validation nor fail an
    encoder later."""
    return _SURROGATE.sub("�", s)


class _BadRequest(Exception):
    pass


def _decode(body: bytes) -> dict[str, Any]:
    """Strict decoding: an object, known fields only, the right types, no
    trailing data."""
    try:
        text = body.decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        raise _BadRequest("malformed body") from None
    stripped = text.lstrip(" \t\r\n")
    if not stripped:
        raise _BadRequest("empty body")
    try:
        v, end = json.JSONDecoder().raw_decode(stripped)
    except json.JSONDecodeError:
        raise _BadRequest("syntax error") from None
    if stripped[end:].strip(" \t\r\n"):
        raise _BadRequest("trailing data")
    if v is None:
        # Go decodes null into the struct as a no-op: an empty request,
        # which the engine answers as invalid.
        v = {}
    if not isinstance(v, dict):
        raise _BadRequest("wrong type for field ")
    # Field names match case-insensitively, as Go's decoder matches them;
    # a later key for the same field wins.
    folded: dict[str, Any] = {}
    for k, x in v.items():
        name = k if k in _FIELDS else next((f for f in _FIELDS if f.casefold() == k.casefold()), None)
        if name is None:
            raise _BadRequest(f'unknown field "{k}"')
        folded[name] = x
    v = folded
    out: dict[str, Any] = {}
    for k in ("user", "connection", "action", "resource"):
        x = v.get(k)
        if x is None:
            out[k] = ""
        elif isinstance(x, str):
            out[k] = _clean(x)
        else:
            raise _BadRequest(f"wrong type for field {k}")
    g = v.get("groups")
    if g is None:
        out["groups"] = []
    elif isinstance(g, list) and all(isinstance(x, str) or x is None for x in g):
        out["groups"] = [_clean(x) if x is not None else "" for x in g]
    else:
        raise _BadRequest("wrong type for field groups")
    f = v.get("fresh")
    if f is None:
        out["fresh"] = False
    elif isinstance(f, bool):
        out["fresh"] = f
    else:
        raise _BadRequest("wrong type for field fresh")
    return out


class Server:
    """The HTTP handler and its listener."""

    def __init__(self, checker: Checker, api_key: Secret, logger: Logger | None = None) -> None:
        self.checker = checker
        self.api_key = api_key
        self.logger = logger or Logger()
        self._httpd: ThreadingHTTPServer | None = None

    def authorized(self, header: str) -> bool:
        try:
            want = self.api_key.get()
        except Exception as e:  # noqa: BLE001
            self.logger.error("api key unavailable", error=str(e))
            return False
        prefix = "Bearer "
        if len(header) < len(prefix) or header[: len(prefix)].lower() != prefix.lower():
            return False
        got = header[len(prefix) :].strip().encode("utf-8", "surrogateescape")
        return hmac.compare_digest(got, want)

    def handle_check(self, method: str, auth: str, body: bytes | None, remote: str, too_large: bool = False) -> tuple[int, dict[str, str], bytes]:
        headers = {"Content-Type": "application/json", "Cache-Control": "no-store"}
        if method != "POST":
            headers["Allow"] = "POST"
            return 405, headers, decision_body(unknown_decision(Code.INVALID_REQUEST, "use POST"))
        if not self.authorized(auth):
            headers["WWW-Authenticate"] = 'Bearer realm="hallpass"'
            return 401, headers, decision_body(unknown_decision(Code.UNAUTHORIZED, "missing or wrong API key"))
        if too_large:
            return 413, headers, decision_body(unknown_decision(Code.INVALID_REQUEST, f"body larger than {MAX_REQUEST_BODY} bytes"))
        if body is None:
            return 400, headers, decision_body(unknown_decision(Code.INVALID_REQUEST, "could not read body"))
        try:
            v = _decode(body)
        except _BadRequest as e:
            return 400, headers, decision_body(unknown_decision(Code.INVALID_REQUEST, f"invalid JSON: {e}"))
        res = self.checker.check(
            background(),
            Request(
                user=v["user"],
                groups=v["groups"],
                connection=v["connection"],
                action=v["action"],
                resource=v["resource"],
                fresh=v["fresh"],
                remote=remote,
            ),
        )
        return res.status, headers, decision_body(res.decision)

    def handler_class(self) -> type[BaseHTTPRequestHandler]:
        server = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "hallpass"
            sys_version = ""
            protocol_version = "HTTP/1.1"
            # Bounds reading the request line, headers and body.
            timeout = 15

            def log_message(self, format: str, *args: Any) -> None:
                pass

            def _send(self, status: int, headers: dict[str, str], body: bytes) -> None:
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)

            def _route(self) -> None:
                start = time.monotonic()
                path = self.path.split("?", 1)[0]
                status = 200
                try:
                    if sum(len(k) + len(v) for k, v in self.headers.items()) > _MAX_HEADER_BYTES:
                        status = 431
                        self._send(431, {"Content-Type": "text/plain; charset=utf-8"}, b"request header fields too large\n")
                        self.close_connection = True
                        return
                    if path == "/check":
                        body, too_large = self._body()
                        status, headers, out = server.handle_check(self.command, self.headers.get("Authorization", ""), body, self.client_address[0], too_large)
                        if too_large:
                            self.close_connection = True
                        self._send(status, headers, out)
                    elif path == "/healthz":
                        self._drain()
                        if self.command not in ("GET", "HEAD"):
                            status = 405
                            self._send(
                                405,
                                {"Allow": "GET, HEAD", "Content-Type": "text/plain; charset=utf-8", "X-Content-Type-Options": "nosniff"},
                                b"method not allowed\n",
                            )
                        else:
                            self._send(200, {"Content-Type": "application/json", "Cache-Control": "no-store"}, b'{"status":"ok"}\n')
                    else:
                        self._drain()
                        status = 404
                        self._send(404, {"Content-Type": "text/plain; charset=utf-8", "X-Content-Type-Options": "nosniff"}, b"404 page not found\n")
                finally:
                    server.logger.info(
                        "request",
                        method=self.command,
                        path=path,
                        status=status,
                        duration_ms=int((time.monotonic() - start) * 1000),
                        remote=self.client_address[0],
                    )

            def _length(self) -> int | None:
                if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
                    return None
                cl = self.headers.get("Content-Length")
                if cl is None:
                    return 0
                try:
                    n = int(cl)
                except ValueError:
                    return -1
                return n

            def _body(self) -> tuple[bytes | None, bool]:
                n = self._length()
                if n is None:
                    return self._chunked()
                if n < 0:
                    self.close_connection = True
                    return None, False
                if n > MAX_REQUEST_BODY:
                    # Read at most the cap, then close: the rest is not ours.
                    self.close_connection = True
                    return None, True
                try:
                    data = self.rfile.read(n)
                except (TimeoutError, OSError):
                    self.close_connection = True
                    return None, False
                if len(data) < n:
                    self.close_connection = True
                    return None, False
                return data, False

            def _chunked(self) -> tuple[bytes | None, bool]:
                out = bytearray()
                try:
                    while True:
                        line = self.rfile.readline(1024)
                        size = int(line.split(b";", 1)[0].strip() or b"0", 16)
                        if size == 0:
                            while self.rfile.readline(1024) not in (b"\r\n", b"\n", b""):
                                pass
                            return bytes(out), False
                        if len(out) + size > MAX_REQUEST_BODY:
                            self.close_connection = True
                            return None, True
                        out.extend(self.rfile.read(size))
                        self.rfile.readline(1024)
                except (TimeoutError, OSError, ValueError):
                    self.close_connection = True
                    return None, False

            def _drain(self) -> None:
                n = self._length()
                if n is None or n < 0 or n > MAX_REQUEST_BODY:
                    self.close_connection = True
                    return
                if n:
                    try:
                        self.rfile.read(n)
                    except (TimeoutError, OSError):
                        self.close_connection = True

            do_GET = _route  # noqa: N815
            do_POST = _route  # noqa: N815
            do_HEAD = _route  # noqa: N815
            do_PUT = _route  # noqa: N815
            do_DELETE = _route  # noqa: N815
            do_PATCH = _route  # noqa: N815
            do_OPTIONS = _route  # noqa: N815

        return Handler

    def listen(self, addr: str) -> tuple[str, int]:
        """Bind addr ("host:port", ":port"); return the bound address."""
        host, _, port = addr.rpartition(":")
        host = host.strip("[]")
        handler = self.handler_class()
        httpd: ThreadingHTTPServer
        if host in ("", "::"):
            try:
                httpd = _DualStackServer(("::", int(port or 0)), handler)
            except OSError:
                # No IPv6 on this host: every IPv4 address.
                httpd = ThreadingHTTPServer(("0.0.0.0", int(port or 0)), handler)
        elif ":" in host:
            httpd = _V6Server((host, int(port or 0)), handler)
        else:
            httpd = ThreadingHTTPServer((host, int(port or 0)), handler)
        httpd.daemon_threads = True
        self._httpd = httpd
        bound = httpd.server_address
        return str(bound[0]), int(bound[1])

    def serve_forever(self) -> None:
        assert self._httpd is not None
        self._httpd.serve_forever(poll_interval=0.2)

    def serve_in_thread(self) -> threading.Thread:
        t = threading.Thread(target=self.serve_forever, name="hallpass-server", daemon=True)
        t.start()
        return t

    def shutdown(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()


class _V6Server(ThreadingHTTPServer):
    address_family = socket.AF_INET6


class _DualStackServer(ThreadingHTTPServer):
    """ ":8080" listens on every address, IPv4 and IPv6, as Go does."""

    address_family = socket.AF_INET6

    def server_bind(self) -> None:
        try:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        except OSError:
            pass
        super().server_bind()
