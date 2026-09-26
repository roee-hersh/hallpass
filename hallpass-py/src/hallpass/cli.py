"""The hallpass command.

    hallpass serve    -config /etc/hallpass/hallpass.yaml
    hallpass validate -config /etc/hallpass/hallpass.yaml
    hallpass probe    -config /etc/hallpass/hallpass.yaml [-connection id]
    hallpass check    -config FILE -connection id -user email -action name -resource res
    hallpass check    -server URL -api-key env:HALLPASS_API_KEY -connection id ... [-fresh]
    hallpass catalog  [integration]

Flags keep the single-dash form the command has always taken (``-config
FILE``, ``--config=FILE`` works too), so scripts and the Helm chart do not
change.
"""

from __future__ import annotations

import json
import signal
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import IO, Any

from hallpass import __version__
from hallpass.core import secret as secretmod
from hallpass.core.config import Config, ConfigError, ConfigErrors
from hallpass.core.config import load as load_config
from hallpass.core.context import background, with_cancel
from hallpass.core.declog import open_log
from hallpass.core.duration import parse_duration
from hallpass.core.engine import EngineError, Options, Request, build
from hallpass.core.integration import Registry, validate_https_url
from hallpass.core.log import WARN, JSONHandler, Logger, TextHandler, parse_level
from hallpass.integrations import registry as all_registry
from hallpass.net import httpx
from hallpass.server import Server, check_body

__all__ = ["main", "run"]

DEFAULT_CONFIG = "/etc/hallpass/hallpass.yaml"

# Exit codes of check. 0, 1 and 3 mirror the decision so that
# `if hallpass check ...` treats unknown as deny. 2 means no decision was
# reached: bad flags, a config that does not load, an interrupted run or a
# server that did not answer.
EXIT_ALLOW, EXIT_DENY, EXIT_ERROR, EXIT_UNKNOWN = 0, 1, 2, 3


def _usage(w: IO[str]) -> None:
    w.write(
        f"""hallpass {__version__} - permission check service

Usage:
  hallpass serve    -config FILE [-listen ADDR] [-log-level LEVEL]
  hallpass validate -config FILE
  hallpass probe    -config FILE [-connection ID]
  hallpass check    -config FILE -connection ID -user EMAIL -action NAME -resource RES [-group G]... [-json]
  hallpass check    -server URL [-api-key REF] [-ca-file PEM] [-timeout D] [-fresh] -connection ID -user EMAIL -action NAME -resource RES ...
  hallpass catalog  [INTEGRATION]
  hallpass version

Default config: {DEFAULT_CONFIG}
"""
    )


# -- Go-style flags ---------------------------------------------------------


class _FlagError(Exception):
    pass


@dataclass
class _Flag:
    name: str
    kind: str  # "str", "bool", "duration", "list"
    default: Any
    usage: str


@dataclass
class _FlagSet:
    name: str
    out: IO[str]
    flags: dict[str, _Flag] = field(default_factory=dict)
    values: dict[str, Any] = field(default_factory=dict)
    set: set[str] = field(default_factory=set)
    args: list[str] = field(default_factory=list)

    def add(self, name: str, kind: str, default: Any, usage: str) -> None:
        self.flags[name] = _Flag(name, kind, default, usage)
        self.values[name] = list(default) if kind == "list" else default

    def print_usage(self) -> None:
        self.out.write(f"Usage of {self.name}:\n")
        for f in sorted(self.flags.values(), key=lambda f: f.name):
            typ = {"str": " string", "duration": " duration", "list": " value", "bool": ""}[f.kind]
            self.out.write(f"  -{f.name}{typ}\n    \t{f.usage}")
            if f.kind == "str" and f.default:
                self.out.write(f' (default "{f.default}")')
            elif f.kind == "duration" and f.default:
                from hallpass.core.duration import format_duration

                self.out.write(f" (default {format_duration(f.default)})")
            self.out.write("\n")

    def parse(self, argv: list[str]) -> None:
        i = 0
        while i < len(argv):
            a = argv[i]
            if len(a) < 2 or a[0] != "-":
                break
            if a == "--":
                i += 1
                break
            name = a[2:] if a.startswith("--") else a[1:]
            if not name or name[0] in "-=":
                self.out.write(f"bad flag syntax: {a}\n")
                self.print_usage()
                raise _FlagError()
            value: str | None = None
            if "=" in name:
                name, value = name.split("=", 1)
            if name in ("h", "help") and name not in self.flags:
                self.print_usage()
                raise _FlagError()
            f = self.flags.get(name)
            if f is None:
                self.out.write(f"flag provided but not defined: -{name}\n")
                self.print_usage()
                raise _FlagError()
            if f.kind == "bool":
                if value is None:
                    v: Any = True
                elif value.lower() in ("1", "t", "true"):
                    v = True
                elif value.lower() in ("0", "f", "false"):
                    v = False
                else:
                    self.out.write(f'invalid boolean value "{value}" for -{name}: parse error\n')
                    self.print_usage()
                    raise _FlagError()
            else:
                if value is None:
                    i += 1
                    if i >= len(argv):
                        self.out.write(f"flag needs an argument: -{name}\n")
                        self.print_usage()
                        raise _FlagError()
                    value = argv[i]
                if f.kind == "duration":
                    try:
                        v = parse_duration(value)
                    except ValueError:
                        self.out.write(f'invalid value "{value}" for flag -{name}: parse error\n')
                        self.print_usage()
                        raise _FlagError() from None
                else:
                    v = value
            if f.kind == "list":
                self.values[name].append(v)
            else:
                self.values[name] = v
            self.set.add(name)
            i += 1
        self.args = argv[i:]


# -- commands ---------------------------------------------------------------


def _new_logger(level: str, w: IO[str]) -> Logger:
    return Logger(JSONHandler(w, parse_level(level)))


def _load(path: str, stderr: IO[str]) -> tuple[Config, Registry] | None:
    reg = all_registry()
    try:
        cfg = load_config(path, reg)
    except (ConfigError, ConfigErrors) as e:
        stderr.write(str(e) + "\n")
        return None
    except OSError as e:
        stderr.write(f"open {path}: {e.strerror or e}\n")
        return None
    return cfg, reg


def serve(args: list[str], stderr: IO[str], stop: threading.Event | None = None, ready: Callable[[str, int], None] | None = None) -> int:
    fs = _FlagSet("serve", stderr)
    fs.add("config", "str", DEFAULT_CONFIG, "config file")
    fs.add("listen", "str", "", "listen address (overrides the config)")
    fs.add("log-level", "str", "info", "debug, info, warn or error")
    try:
        fs.parse(args)
    except _FlagError:
        return 2
    try:
        logger = _new_logger(fs.values["log-level"], stderr)
    except ValueError as e:
        stderr.write(f'log level "{fs.values["log-level"]}": {e}\n')
        return 2
    loaded = _load(fs.values["config"], stderr)
    if loaded is None:
        return 1
    cfg, _ = loaded
    if fs.values["listen"]:
        cfg.listen = fs.values["listen"]
    try:
        dl = open_log(cfg.decision_log)
    except OSError as e:
        stderr.write(f"decision_log: open {cfg.decision_log}: {e.strerror or e}\n")
        return 1
    try:
        try:
            eng = build(
                background(),
                cfg,
                Options(logger=logger, decision_log=dl, decision_cache=cfg.decision_cache, identity_cache=cfg.identity_cache),
            )
        except EngineError as e:
            stderr.write(str(e) + "\n")
            return 1

        # Startup probe: warn, never block. One broken upstream must not
        # take down the healthy connections.
        def startup_probe() -> None:
            for r in eng.probe(background()):
                if r.err is not None:
                    logger.warn("probe failed", connection=r.id, integration=r.integration, error=str(r.err))
                    continue
                for w in r.result.warnings:
                    logger.warn("probe warning", connection=r.id, integration=r.integration, warning=w)
                logger.info("probe ok", connection=r.id, integration=r.integration, summary=r.result.summary)

        threading.Thread(target=startup_probe, name="hallpass-probe", daemon=True).start()
        srv = Server(eng, cfg.api_key, logger)
        try:
            host, port = srv.listen(cfg.listen)
        except (OSError, ValueError) as e:
            stderr.write(f"listen tcp {cfg.listen}: {e}\n")
            return 1
        stop = stop or threading.Event()
        installed = []
        if threading.current_thread() is threading.main_thread():
            for sig in (signal.SIGINT, signal.SIGTERM):
                installed.append((sig, signal.signal(sig, lambda *_: stop.set())))
        try:
            srv.serve_in_thread()
            logger.info("listening", addr=cfg.listen, connections=len(eng.connections()), version=__version__)
            if ready is not None:
                ready(host, port)
            stop.wait()
            logger.info("shutting down")
            srv.shutdown()
        finally:
            for sig, prev in installed:
                signal.signal(sig, prev)
        return 0
    finally:
        dl.close()


def validate(args: list[str], stdout: IO[str], stderr: IO[str]) -> int:
    fs = _FlagSet("validate", stderr)
    fs.add("config", "str", DEFAULT_CONFIG, "config file")
    try:
        fs.parse(args)
    except _FlagError:
        return 2
    loaded = _load(fs.values["config"], stderr)
    if loaded is None:
        return 1
    cfg, _ = loaded
    # Building connections parses credentials and certificates without
    # touching the network.
    logger = Logger(TextHandler(stderr, WARN))
    try:
        build(background(), cfg, Options(logger=logger))
    except EngineError as e:
        stderr.write(str(e) + "\n")
        return 1
    try:
        cfg.api_key.get()
    except secretmod.SecretError as e:
        stderr.write(f"api_key: {e}\n")
        return 1
    stdout.write(f"{fs.values['config']}: ok, {len(cfg.connections)} connection(s)\n")
    for c in cfg.connections:
        stdout.write(f"  {c.id:<24} {c.integration}\n")
    return 0


def probe(args: list[str], stdout: IO[str], stderr: IO[str]) -> int:
    fs = _FlagSet("probe", stderr)
    fs.add("config", "str", DEFAULT_CONFIG, "config file")
    fs.add("connection", "str", "", "probe only this connection id")
    try:
        fs.parse(args)
    except _FlagError:
        return 2
    loaded = _load(fs.values["config"], stderr)
    if loaded is None:
        return 1
    cfg, _ = loaded
    logger = Logger(TextHandler(stderr, WARN))
    try:
        eng = build(background(), cfg, Options(logger=logger))
    except EngineError as e:
        stderr.write(str(e) + "\n")
        return 1
    ids = (fs.values["connection"],) if fs.values["connection"] else ()
    failed = 0
    for r in eng.probe(background(), *ids):
        if r.err is not None:
            failed += 1
            stdout.write(f"FAIL {r.id:<24} {r.integration:<12} {r.err}\n")
            continue
        stdout.write(f"ok   {r.id:<24} {r.integration:<12} {r.result.summary}\n")
        for w in r.result.warnings:
            stdout.write(f"     warning: {w}\n")
    return 1 if failed else 0


def check(args: list[str], stdout: IO[str], stderr: IO[str]) -> int:
    """One question from the command line, on the same code path as POST
    /check but in-process: it needs the config file and the connection's
    credential, not a running server. Caches and the decision log are off.

    With -server it asks a running hallpass instead, from a machine that
    holds the API key but no upstream credential. The key is an env:NAME
    or file:/path reference, never a value on the command line.
    """
    fs = _FlagSet("check", stderr)
    fs.add("config", "str", DEFAULT_CONFIG, "config file")
    fs.add("server", "str", "", "ask a running hallpass at this URL instead of the config file")
    fs.add("api-key", "str", "env:HALLPASS_API_KEY", "API key for -server, as env:NAME or file:/path")
    fs.add("ca-file", "str", "", "PEM file that replaces the system roots for -server")
    fs.add("timeout", "duration", 60.0, "how long to wait for -server to answer")
    fs.add("connection", "str", "", "connection id from the config")
    fs.add("user", "str", "", "email of the user asking")
    fs.add("action", "str", "", "action name (see hallpass catalog INTEGRATION)")
    fs.add("resource", "str", "", "resource such as namespace:payments or issue:PAY-123")
    fs.add("json", "bool", False, "print the same JSON as POST /check")
    fs.add("fresh", "bool", False, "skip the server's caches and ask the upstream system now (a -config check never caches)")
    fs.add("group", "list", [], "group the user belongs to (repeatable)")
    try:
        fs.parse(args)
    except _FlagError:
        return EXIT_ERROR
    v = fs.values
    if fs.args:
        stderr.write(f'check takes flags only, unexpected argument "{fs.args[0]}"\n')
        fs.print_usage()
        return EXIT_ERROR
    missing = ["-" + n for n in ("connection", "user", "action", "resource") if not v[n]]
    if missing:
        stderr.write(f"check: missing {', '.join(missing)}\n")
        fs.print_usage()
        return EXIT_ERROR
    # A flag for the other mode is a mistake, not something to ignore.
    if v["server"]:
        stray = ["-config"] if "config" in fs.set else []
    else:
        stray = ["-" + n for n in ("api-key", "ca-file", "timeout") if n in fs.set]
    if stray:
        with_, without = ("-server", "-config") if v["server"] else ("-config", "-server")
        stderr.write(f"check: {', '.join(stray)} only goes with {without}, not {with_}\n")
        return EXIT_ERROR
    req = Request(
        user=v["user"], groups=list(v["group"]), connection=v["connection"], action=v["action"], resource=v["resource"], fresh=v["fresh"], remote="cli"
    )
    ctx, cancel = with_cancel(background())
    interrupted = threading.Event()
    installed = []
    if threading.current_thread() is threading.main_thread():

        def on_signal(*_: Any) -> None:
            interrupted.set()
            cancel()

        for sig in (signal.SIGINT, signal.SIGTERM):
            installed.append((sig, signal.signal(sig, on_signal)))
    try:
        if v["server"]:
            try:
                outcome, reason = _remote_check(v["server"], v["api-key"], v["ca-file"], v["timeout"], req)
            except _RemoteError as e:
                stderr.write(f"check: {e}\n")
                return EXIT_ERROR
            return _print_decision(stdout, outcome, reason, v["json"])
        loaded = _load(v["config"], stderr)
        if loaded is None:
            return EXIT_ERROR
        cfg, _ = loaded
        _select_connection(cfg, v["connection"])
        logger = Logger(TextHandler(stderr, WARN))
        try:
            eng = build(ctx, cfg, Options(logger=logger))
        except EngineError as e:
            stderr.write(str(e) + "\n")
            return EXIT_ERROR
        d = eng.check(ctx, req).decision
        if interrupted.is_set():
            # A cancelled upstream call is an unknown decision, right for
            # the server but a script would mistake Ctrl-C for an answer.
            stderr.write("check: interrupted\n")
            return EXIT_ERROR
        return _print_decision(stdout, d.outcome.value, d.reason(), v["json"])
    finally:
        for sig, prev in installed:
            signal.signal(sig, prev)


def _select_connection(cfg: Config, cid: str) -> None:
    """Keep only the connection asked about and the ones it refers to, so
    an unrelated connection with a credential or CA file missing on this
    machine cannot stop the question being answered."""
    by_id = {s.id: s for s in cfg.connections}
    keep: set[str] = set()

    def walk(i: str) -> None:
        s = by_id.get(i)
        if i in keep or s is None:
            return
        keep.add(i)
        integ = cfg.integrations.get(i)
        if integ is None:
            return
        for f in integ.fields():
            if f.ref:
                walk(s.get(f.name))

    walk(cid)
    cfg.connections = [s for s in cfg.connections if s.id in keep]


def _print_decision(stdout: IO[str], outcome: str, reason: str, as_json: bool) -> int:
    if as_json:
        stdout.write(json.dumps({"decision": outcome, "reason": reason}, ensure_ascii=False, separators=(",", ":")) + "\n")
    else:
        stdout.write(f"{outcome}\n  {_printable(reason)}\n")
    return {"allow": EXIT_ALLOW, "deny": EXIT_DENY}.get(outcome, EXIT_UNKNOWN)


def _printable(s: str) -> str:
    """Control characters become spaces, so a reason (in -server mode
    whatever the far end sent) cannot forge a line or drive the terminal."""
    return "".join(" " if ord(c) < 0x20 or ord(c) == 0x7F else c for c in s)


class _RemoteError(Exception):
    pass


# Bounds a /check response; a real one is under 1 KiB.
_MAX_REMOTE_BODY = 64 << 10


def _remote_check(base: str, api_key: str, ca_file: str, timeout: float, req: Request) -> tuple[str, str]:
    """POST {base}/check on a running hallpass. Any HTTP status with a
    well-formed body is an answer; anything else is an error."""
    try:
        validate_https_url(base)
    except ValueError as e:
        raise _RemoteError(f"-server: {e}") from None
    base = base.rstrip("/").removesuffix("/check")
    try:
        key = secretmod.parse(api_key)
        token = key.get_string()
    except secretmod.SecretError as e:
        raise _RemoteError(f"-api-key: {e}") from None
    if timeout <= 0:
        raise _RemoteError("-timeout must be positive")
    try:
        t = httpx.new_http_client(httpx.Options(ca_file=ca_file, timeout=timeout))
    except ValueError as e:
        raise _RemoteError(f"-ca-file: {e}") from None
    body = json.dumps(check_body(req), ensure_ascii=False, separators=(",", ":")).encode()
    h = httpx.Headers(
        {"Authorization": "Bearer " + token, "Content-Type": "application/json", "Accept": "application/json", "User-Agent": f"hallpass/{__version__}"}
    )
    try:
        raw = t.send(background(), httpx.PreparedRequest("POST", base + "/check", h, body), _MAX_REMOTE_BODY)
    except httpx.BodyTooLarge:
        raise _RemoteError(f"{base}: response larger than {_MAX_REMOTE_BODY} bytes") from None
    except Exception as e:  # noqa: BLE001
        raise _RemoteError(f'Post "{base}/check": {e}') from None
    finally:
        t.close()
    try:
        out = json.loads(raw.body)
    except ValueError:
        raise _RemoteError(f"{base} answered HTTP {raw.status} without a decision; is it hallpass?") from None
    if not isinstance(out, dict):
        raise _RemoteError(f"{base} answered HTTP {raw.status} without a decision; is it hallpass?")
    decision, reason = out.get("decision"), out.get("reason", "")
    if decision not in ("allow", "deny", "unknown"):
        raise _RemoteError(f'{base} answered HTTP {raw.status} with decision "{decision if isinstance(decision, str) else ""}"; is it hallpass?')
    return decision, reason if isinstance(reason, str) else ""


def catalog(args: list[str], stdout: IO[str], stderr: IO[str]) -> int:
    reg = all_registry()
    if not args:
        for n in reg.names():
            i = reg.lookup(n)
            assert i is not None
            stdout.write(f"{n:<18} {len(i.actions())} action(s)\n")
        return 0
    i = reg.lookup(args[0])
    if i is None:
        stderr.write(f'unknown integration "{args[0]}" (known: {", ".join(reg.names())})\n')
        return 1
    stdout.write(f"integration: {i.name()}\n\nconfig keys:\n")
    fields = sorted(i.fields(), key=lambda f: not f.required)
    for f in fields:
        flags = []
        if f.required:
            flags.append("required")
        if f.secret:
            flags.append("secret: env:NAME or file:/path")
        if f.ref:
            flags.append(f"id of a {f.ref} connection")
        if f.default:
            flags.append(f"default {f.default}")
        if f.enum:
            flags.append("one of " + "|".join(f.enum))
        line = f"  {f.name:<26} {f.description}"
        if flags:
            line += f" ({'; '.join(flags)})"
        stdout.write(line + "\n")
    stdout.write(f"  {'ca_file':<26} PEM file that replaces the system roots (optional)\n")
    stdout.write(f"  {'tls_server_name':<26} name verified against the server certificate (optional)\n")
    stdout.write(f"  {'proxy_url':<26} http:// or https:// proxy (optional)\n")
    stdout.write(f"  {'timeout':<26} per-check budget such as 10s (default 8s)\n")
    stdout.write("\nactions:\n")
    for a in i.actions():
        stdout.write(f"  {a.name:<40} {a.description}\n")
    return 0


def run(args: list[str], stdout: IO[str] | None = None, stderr: IO[str] | None = None) -> int:
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    httpx.VERSION = __version__
    if not args:
        _usage(stderr)
        return 2
    cmd, rest = args[0], args[1:]
    if cmd == "serve":
        return serve(rest, stderr)
    if cmd == "validate":
        return validate(rest, stdout, stderr)
    if cmd == "probe":
        return probe(rest, stdout, stderr)
    if cmd == "check":
        return check(rest, stdout, stderr)
    if cmd == "catalog":
        return catalog(rest, stdout, stderr)
    if cmd == "version":
        stdout.write(__version__ + "\n")
        return 0
    if cmd in ("-h", "--help", "help"):
        _usage(stdout)
        return 0
    stderr.write(f'unknown command "{cmd}"\n\n')
    _usage(stderr)
    return 2


def main() -> None:
    sys.exit(run(sys.argv[1:]))


if __name__ == "__main__":
    main()
