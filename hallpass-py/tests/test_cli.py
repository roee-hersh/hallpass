"""Port of cmd/hallpass/main_test.go."""

from __future__ import annotations

import http.client
import io
import json
import os
import socket
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

import hallpass
from hallpass import cli
from hallpass.core.catalog import Action
from hallpass.core.context import Context
from hallpass.core.integration import Connection, Deps, Field, Integration, Registry, Settings, credential_field, url_field
from hallpass.integrations import registry as all_registry
from tests import harness as itest


def capture(*args: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = cli.run(list(args), out, err)
    return code, out.getvalue(), err.getvalue()


@pytest.fixture
def write_config(tmp_path_factory: pytest.TempPathFactory) -> Any:
    def write(body: str) -> str:
        p = tmp_path_factory.mktemp("cfg") / "hallpass.yaml"
        p.write_text(body)
        os.chmod(p, 0o600)
        return str(p)

    return write


GOOD_CONFIG = """
api_key: env:HALLPASS_API_KEY
decision_log: none
connections:
  - id: demo
    integration: fake
    users: dana@example.com
    admins: admin@example.com
"""


def test_validate_and_probe_and_catalog(monkeypatch: pytest.MonkeyPatch, write_config: Any) -> None:
    monkeypatch.setenv("HALLPASS_API_KEY", "k")
    p = write_config(GOOD_CONFIG)
    code, out, errs = capture("validate", "-config", p)
    assert code == 0 and "ok, 1 connection" in out and errs == "", f"validate: {code} {out!r} {errs!r}"
    code, out, _ = capture("probe", "-config", p)
    assert code == 0 and "ok   demo" in out, f"probe: {code} {out!r}"
    code, _, errs = capture("validate", "-config", write_config("api_key: nope\n"))
    assert code == 1 and "inline secret" in errs, f"validate bad: {code} {errs!r}"
    code, out, _ = capture("catalog")
    assert code == 0 and "fake" in out, f"catalog: {code} {out!r}"
    code, out, _ = capture("catalog", "fake")
    assert code == 0 and "thing.write" in out and "ca_file" in out, f"catalog fake: {code} {out!r}"
    assert capture("catalog", "nope")[0] == 1, "catalog unknown"
    assert capture()[0] == 2, "no args"
    assert capture("bogus")[0] == 2, "bad command"
    # Go: the build's version defaults to "dev"; the package's version is
    # what the Python command prints.
    code, out, _ = capture("version")
    assert code == 0 and hallpass.__version__ in out, "version"


def free_port() -> str:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    addr = f"127.0.0.1:{s.getsockname()[1]}"
    s.close()
    return addr


def test_serve_end_to_end(monkeypatch: pytest.MonkeyPatch, write_config: Any) -> None:
    monkeypatch.setenv("HALLPASS_API_KEY", "CANARY-SECRET-key")
    p = write_config(GOOD_CONFIG)
    addr = free_port()
    errf = itest.Logs()
    # Go: the test cancels serveParent; serve takes a stop event here.
    stop = threading.Event()
    done: list[int] = []

    def serve() -> None:
        done.append(cli.serve(["-config", p, "-listen", addr, "-log-level", "debug"], errf, stop=stop))

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    host, port = addr.split(":")

    def request(method: str, path: str, body: bytes | None = None, headers: dict[str, str] | None = None) -> tuple[int, bytes]:
        conn = http.client.HTTPConnection(host, int(port), timeout=5)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            res = conn.getresponse()
            return res.status, res.read()
        finally:
            conn.close()

    err: Exception | None = None
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            request("GET", "/healthz")
            err = None
            break
        except OSError as e:
            err = e
            time.sleep(0.05)
    assert err is None, f"server did not start: {err}"

    def check(user: str, action: str) -> tuple[int, dict[str, str]]:
        body = '{"user":"' + user + '","connection":"demo","action":"' + action + '","resource":"thing:1"}'
        st, b = request("POST", "/check", body.encode(), {"Authorization": "Bearer CANARY-SECRET-key", "Content-Type": "application/json"})
        try:
            return st, json.loads(b)
        except ValueError:
            return st, {}

    try:
        st, out = check("admin@example.com", "thing.write")
        assert st == 200 and out["decision"] == "allow", f"admin: {st} {out}"
        st, out = check("dana@example.com", "thing.write")
        assert st == 200 and out["decision"] == "deny", f"dana: {st} {out}"
        st, out = check("nobody@example.com", "thing.read")
        assert st == 200 and out["decision"] == "deny" and out["reason"].startswith("user_not_found"), f"nobody: {st} {out}"
        st, _ = request("POST", "/check", b"{}")
        assert st == 401, f"no key: {st}"
    finally:
        stop.set()
    t.join(10)
    assert not t.is_alive(), "serve did not stop"
    assert done == [0], f"serve exit {done}"
    logs = errf.text()
    assert "CANARY-SECRET" not in logs, f"server log leaked the api key: {logs}"
    assert '"listening"' in logs, f"no listening line: {logs}"


class StandInKubernetes(Integration):
    """Stands in for the kubernetes integration while the Python port has
    not registered it: like it, it builds its HTTP client (and so parses
    the connection's CA file) when the connection is built."""

    def name(self) -> str:
        return "kubernetes"

    def fields(self) -> list[Field]:
        return [url_field(True, "API server URL"), credential_field(True, "bearer token")]

    def actions(self) -> list[Action]:
        return [Action("pods.get", "read pods")]

    def new(self, ctx: Context, s: Settings, d: Deps) -> Connection:
        d.http_client(s)
        raise AssertionError("the CA file should not have parsed")


@pytest.fixture
def with_kubernetes(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """The registry the command uses, with a kubernetes integration."""
    if all_registry().lookup("kubernetes") is None:

        def reg() -> Registry:
            r = all_registry()
            r.register(StandInKubernetes())
            return r

        monkeypatch.setattr(cli, "all_registry", reg)
    yield


def test_check(monkeypatch: pytest.MonkeyPatch, write_config: Any, tmp_path: Path, with_kubernetes: None) -> None:
    # No API key: a CLI check runs the engine in-process and never needs it.
    monkeypatch.setenv("HALLPASS_API_KEY", "")
    p = write_config(GOOD_CONFIG)

    def ask(user: str, *extra: str) -> tuple[int, str, str]:
        return capture("check", "-config", p, "-connection", "demo", "-user", user, "-action", "thing.write", "-resource", "thing:1", *extra)

    code, out, errs = ask("admin@example.com")
    assert code == 0 and out.startswith("allow\n") and "allowed: admin@example.com is an admin" in out and errs == "", f"allow: {code} {out!r} {errs!r}"
    code, out, _ = ask("dana@example.com")
    assert code == 1 and out.startswith("deny\n") and "denied:" in out, f"deny: {code} {out!r}"
    # -fresh is accepted in-process too, where there is no cache to skip.
    code, out, errs = ask("admin@example.com", "-fresh")
    assert code == 0 and out.startswith("allow\n") and errs == "", f"fresh: {code} {out!r} {errs!r}"
    code, out, _ = ask("nobody@example.com")
    assert code == 1 and "user_not_found" in out, f"not found: {code} {out!r}"
    code, out, _ = ask("ambiguous@example.com")
    assert code == 3 and out.startswith("unknown\n") and "user_ambiguous" in out, f"unknown: {code} {out!r}"
    code, out, _ = ask("not-an-email")
    assert code == 3 and "invalid_request" in out, f"invalid: {code} {out!r}"
    code, out, _ = capture(
        "check",
        "-config",
        p,
        "-connection",
        "nope",
        "-user",
        "admin@example.com",
        "-action",
        "thing.write",
        "-resource",
        "thing:1",
        "-group",
        "a",
        "-group",
        "b",
    )
    assert code == 3 and "unknown_connection" in out, f"unknown connection: {code} {out!r}"

    # -json prints exactly the HTTP response body.
    code, out, _ = ask("admin@example.com", "-json")
    body = json.loads(out)
    assert code == 0, f"json: {code} {out!r}"
    assert body["decision"] == "allow" and body["reason"].startswith("allowed: ") and len(body) == 2, f"json body: {body}"

    # Usage errors are 2, never mistaken for a decision.
    code, _, errs = capture("check", "-config", p, "-user", "admin@example.com")
    assert code == 2 and "missing -connection, -action, -resource" in errs, f"missing flags: {code} {errs!r}"
    code, _, errs = ask("admin@example.com", "extra")
    assert code == 2 and 'unexpected argument "extra"' in errs, f"positional: {code} {errs!r}"
    code, _, errs = capture("check", "-config", write_config("api_key: nope\n"), "-connection", "demo", "-user", "a@b", "-action", "x", "-resource", "y:1")
    assert code == 2 and "inline secret" in errs, f"bad config: {code} {errs!r}"
    code, _, errs = ask("admin@example.com", "-ca-file", "x.pem", "-timeout", "5s")
    assert code == 2 and "-ca-file, -timeout only goes with -server" in errs, f"server flags without -server: {code} {errs!r}"

    # Only the connection asked about is built: a sibling whose CA file
    # holds no certificate on this machine (an empty placeholder) must not
    # stop the answer. The loader only checks that the file exists; the
    # engine parses it.
    empty_ca = tmp_path / "ca.pem"
    empty_ca.write_bytes(b"")
    os.chmod(empty_ca, 0o600)
    broken = write_config(
        GOOD_CONFIG
        + f"""
  - id: k8s
    integration: kubernetes
    url: https://10.0.0.1:6443
    ca_file: {empty_ca}
    credential: env:HALLPASS_API_KEY
"""
    )
    code, out, errs = capture("check", "-config", broken, "-connection", "demo", "-user", "admin@example.com", "-action", "thing.write", "-resource", "thing:1")
    assert code == 0 and out.startswith("allow"), f"broken sibling: {code} {out!r} {errs!r}"
    code, _, errs = capture("probe", "-config", broken)
    assert code == 1 and "no PEM certificates" in errs, f"probe still sees the broken connection: {code} {errs!r}"
    code, out, _ = capture("check", "-config", broken, "-connection", "k8s", "-user", "admin@example.com", "-action", "thing.write", "-resource", "thing:1")
    assert code == 2 and out == "", f"asking the broken one: {code} {out!r}"


def test_printable() -> None:
    got = cli._printable("x\nallow\n  allowed: ok\x1b[2J\x7f")
    assert got == "x allow   allowed: ok [2J ", f"printable: {got!r}"


def test_check_server(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    mu = threading.Lock()
    got = {"auth": "", "ua": "", "body": ""}
    release = threading.Event()

    def handler(w: itest.ResponseWriter, r: itest.Request) -> None:
        if r.path != "/check" or r.method != "POST":
            w.header().set("Content-Type", "text/plain; charset=utf-8")
            w.write_header(404)
            w.write("wrong endpoint\n")
            return
        b = r.body
        auth = r.header.get("Authorization")
        with mu:
            got["auth"], got["ua"], got["body"] = auth, r.header.get("User-Agent"), b.decode()
        w.header().set("Content-Type", "application/json")
        try:
            inp = json.loads(b)
        except ValueError:
            inp = {}
        user = inp.get("user")
        if auth != "Bearer CANARY-SECRET-key":
            w.write_header(401)
            w.write('{"decision":"unknown","reason":"unauthorized: missing or wrong API key"}')
        elif user == "admin@example.com":
            w.write('{"decision":"allow","reason":"allowed: admin"}')
        elif user == "html@example.com":
            w.header().set("Content-Type", "text/html")
            w.write_header(502)
            w.write("<html>bad gateway</html>")
        elif user == "weird@example.com":
            w.write('{"decision":"maybe","reason":"x"}')
        elif user == "forge@example.com":
            w.write('{"decision":"deny","reason":"no\\nallow\\n  allowed: forged"}')
        elif user == "slow@example.com":
            release.wait(5)  # until the test ends: the client gives up first
            w.write('{"decision":"allow","reason":"allowed: late"}')
        else:
            w.write('{"decision":"deny","reason":"denied: no"}')

    srv = itest.Server(tls=False)
    srv.unmatched = handler
    try:
        monkeypatch.setenv("HALLPASS_API_KEY", "CANARY-SECRET-key")

        def ask(user: str, *extra: str) -> tuple[int, str, str]:
            return capture(
                "check",
                "-server",
                srv.url + "/",
                "-connection",
                "demo",
                "-user",
                user,
                "-action",
                "thing.write",
                "-resource",
                "thing:1",
                "-group",
                "b",
                "-group",
                "a",
                *extra,
            )

        code, out, errs = ask("admin@example.com")
        assert code == 0 and out.startswith("allow\n  allowed: admin") and errs == "", f"allow: {code} {out!r} {errs!r}"
        with mu:
            assert got["auth"] == "Bearer CANARY-SECRET-key" and got["ua"].startswith("hallpass/"), f"headers: {got['auth']!r} {got['ua']!r}"
            want = '{"user":"admin@example.com","groups":["b","a"],"connection":"demo","action":"thing.write","resource":"thing:1"}'
            assert got["body"] == want, f"body:\n got {got['body']}\nwant {want}"
        code, out, _ = ask("dana@example.com", "-json")
        assert code == 1 and out.strip() == '{"decision":"deny","reason":"denied: no"}', f"deny json: {code} {out!r}"
        # -fresh is sent as the request's fresh field, and only then.
        code, _, errs = ask("admin@example.com", "-fresh")
        assert code == 0 and errs == "", f"fresh: {code} {errs!r}"
        with mu:
            assert got["body"].endswith(',"resource":"thing:1","fresh":true}'), f"fresh body: {got['body']}"

        # A wrong key is an unknown decision from the server, not a CLI error.
        monkeypatch.setenv("HALLPASS_API_KEY", "wrong")
        code, out, _ = ask("admin@example.com")
        assert code == 3 and "unauthorized" in out, f"wrong key: {code} {out!r}"
        monkeypatch.setenv("HALLPASS_API_KEY", "CANARY-SECRET-key")

        # The endpoint itself is accepted as the URL, since the README names it.
        code, out, errs = capture(
            "check", "-server", srv.url + "/check", "-connection", "demo", "-user", "admin@example.com", "-action", "thing.write", "-resource", "thing:1"
        )
        assert code == 0 and out.startswith("allow"), f"endpoint url: {code} {out!r} {errs!r}"
        # A reason from the far end cannot forge a second decision line;
        # -json keeps it verbatim, escaped.
        code, out, _ = ask("forge@example.com")
        assert code == 1 and out == "deny\n  no allow   allowed: forged\n", f"forged reason: {code} {out!r}"
        code, out, _ = ask("forge@example.com", "-json")
        assert code == 1 and '"reason":"no\\nallow\\n  allowed: forged"' in out, f"forged reason json: {code} {out!r}"
        code, out, errs = ask("slow@example.com", "-timeout", "200ms")
        assert code == 2 and out == "" and errs != "", f"timeout: {code} {out!r} {errs!r}"
        code, _, errs = ask("admin@example.com", "-config", "x.yaml")
        assert code == 2 and "-config only goes with -config, not -server" in errs, f"config with server: {code} {errs!r}"

        # Not an answer: exit 2 and no decision printed, never a secret echoed.
        for user in ("html@example.com", "weird@example.com"):
            code, out, errs = ask(user)
            assert code == 2 and out == "" and "is it hallpass?" in errs and "CANARY" not in errs, f"{user}: {code} {out!r} {errs!r}"

        # Key must be a reference; the value never goes on the command line.
        code, _, errs = ask("admin@example.com", "-api-key", "CANARY-SECRET-key")
        assert code == 2 and "-api-key:" in errs and "CANARY" not in errs, f"inline key: {code} {errs!r}"
        code, _, errs = ask("admin@example.com", "-api-key", "env:HALLPASS_NOPE")
        assert code == 2 and "HALLPASS_NOPE is not set" in errs, f"unset key: {code} {errs!r}"
        key_file = tmp_path / "key"
        key_file.write_text("CANARY-SECRET-key\n")
        os.chmod(key_file, 0o600)
        code, out, _ = ask("admin@example.com", "-api-key", "file:" + str(key_file))
        assert code == 0 and out.startswith("allow"), f"file key: {code} {out!r}"

        # Plain http is only for loopback; the key would travel in clear text.
        code, _, errs = capture("check", "-server", "http://hallpass.example.com", "-connection", "demo", "-user", "a@b", "-action", "x", "-resource", "y:1")
        assert code == 2 and "must start with https://" in errs, f"http url: {code} {errs!r}"
        # Unreachable server: exit 2, no decision.
        code, out, errs = capture("check", "-server", "http://127.0.0.1:1", "-connection", "demo", "-user", "a@b", "-action", "x", "-resource", "y:1")
        assert code == 2 and out == "" and errs != "", f"unreachable: {code} {out!r} {errs!r}"
    finally:
        release.set()
        srv.close()


@pytest.mark.parametrize(
    ("body", "code", "out", "err"),
    [
        ('{"Decision":"allow","REASON":"allowed: case"}', 0, "allow\n  allowed: case\n", ""),
        ('{"decision":"deny","reason":null,"extra":1}', 1, "deny\n  \n", ""),
        ("null", 2, "", 'with decision ""; is it hallpass?'),
        ('{"decision":1,"reason":"x"}', 2, "", "without a decision; is it hallpass?"),
        ('{"decision":"allow","reason":5}', 2, "", "without a decision; is it hallpass?"),
        ('{"decision":"allow"} {}', 2, "", "without a decision; is it hallpass?"),
    ],
)
def test_check_server_response_decoding(monkeypatch: pytest.MonkeyPatch, body: str, code: int, out: str, err: str) -> None:
    """The -server answer is read as Go's json.Unmarshal reads it into the
    response struct."""

    def handler(w: itest.ResponseWriter, r: itest.Request) -> None:
        w.header().set("Content-Type", "application/json")
        w.write(body)

    srv = itest.Server(tls=False)
    srv.unmatched = handler
    try:
        monkeypatch.setenv("HALLPASS_API_KEY", "k")
        got = capture("check", "-server", srv.url, "-connection", "demo", "-user", "a@b", "-action", "x", "-resource", "y:1")
    finally:
        srv.close()
    assert got[0] == code and got[1] == out and err in got[2], got
