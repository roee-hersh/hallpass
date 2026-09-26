"""Port of internal/engine/engine_test.go."""

from __future__ import annotations

import dataclasses
import json
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from hallpass.core.catalog import Action
from hallpass.core.config import parse
from hallpass.core.context import Context, background
from hallpass.core.decision import Code, Decision, Outcome, user_not_found
from hallpass.core.declog import DecisionLog
from hallpass.core.engine import Engine, EngineError, Options, Request, Result, build, validate_user
from hallpass.core.integration import (
    CheckRequest,
    Connection,
    Deps,
    Field,
    Identity,
    Integration,
    ProbeResult,
    Registry,
    Settings,
    User,
    connection_ref_field,
)
from hallpass.core.log import JSONHandler, Logger
from hallpass.integrations.fake import Fake
from tests import harness as itest


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


class Counting(Integration):
    """Wraps the fake to count upstream calls and to inject behaviour."""

    def __init__(self, slow: float = 0.0, bad_allow: bool = False, need_group: str = "", panic_resolve: bool = False) -> None:
        self.inner = Fake()
        self.resolves = _Counter()
        self.checks = _Counter()
        self.slow = slow
        self.bad_allow = bad_allow
        # When set, resolve_identity answers user_not_found unless the
        # request carries that group (like aws static_map).
        self.need_group = need_group
        # Makes resolve_identity crash, as a bug in an integration would
        # inside the identity cache's fill.
        self.panic_resolve = panic_resolve
        self.mu = threading.Lock()
        # Identity.groups as the last check saw it.
        self.identity_groups: list[str] = []

    def name(self) -> str:
        return "counting"

    def fields(self) -> list[Field]:
        return [*self.inner.fields(), connection_ref_field("fake_connection", "fake", False, "")]

    def actions(self) -> list[Action]:
        return self.inner.actions()

    def new(self, ctx: Context, s: Settings, d: Deps) -> Connection:
        if s.get("fake_connection") != "":
            d.connection(s.get("fake_connection"))
            try:
                d.connection("not-referenced")
            except Exception:
                pass
            else:
                raise RuntimeError("unreferenced connection resolvable")
        inner = self.inner.new(ctx, s, d)
        return CountingConn(inner, self)


class CountingConn(Connection):
    def __init__(self, inner: Connection, p: Counting) -> None:
        self.inner = inner
        self.p = p

    def resolve_identity(self, ctx: Context, u: User) -> Identity:
        """Embeds the request's groups in the identity, as the kubernetes
        and argocd integrations do."""
        self.p.resolves.add(1)
        if self.p.panic_resolve:
            # Go: panic("resolve bug " + u.Email); a bug type is a panic here.
            raise TypeError("resolve bug " + u.email)
        if self.p.need_group != "" and self.p.need_group not in u.groups:
            raise user_not_found(f"{u.email} and its groups are not mapped")
        ident = self.inner.resolve_identity(ctx, u)
        return dataclasses.replace(ident, groups=tuple(u.groups))

    def check(self, ctx: Context, r: CheckRequest) -> Decision:
        self.p.checks.add(1)
        with self.p.mu:
            self.p.identity_groups = list(r.identity.groups)
        if self.p.slow > 0:
            done = threading.Event()
            t = threading.Timer(self.p.slow, done.set)
            t.daemon = True
            t.start()
            try:
                if not ctx.wait(done):
                    ctx.check()
            finally:
                t.cancel()
        if self.p.bad_allow:
            return Decision(Outcome.ALLOW, Code.UNSUPPORTED, "bug")
        return self.inner.check(ctx, r)

    def probe(self, ctx: Context) -> ProbeResult:
        return self.inner.probe(ctx)


CFG_YAML = """
api_key: env:K
connections:
  - id: f
    integration: fake
    users: u@x.com
    admins: a@x.com
  - id: c
    integration: counting
    fake_connection: f
    users: u@x.com
    admins: a@x.com
    timeout: 300ms
"""


def build_engine(c: Counting, o: Options) -> tuple[Engine, itest.Logs]:
    reg = Registry()
    reg.register(Fake())
    reg.register(c)
    cfg = parse("t.yaml", CFG_YAML.encode(), reg)
    # One buffer both the decision log and the logger write to, safe for
    # concurrent checks (Go: lockedBuffer).
    logbuf = itest.Logs()
    o.decision_log = DecisionLog(logbuf)
    o.logger = Logger(JSONHandler(logbuf))
    return build(background(), cfg, o), logbuf


def req(user: str, action: str, resource: str) -> Request:
    return Request(user=user, groups=["g"], connection="c", action=action, resource=resource)


def test_flow_and_caches() -> None:
    c = Counting()
    e, logs = build_engine(c, Options(decision_cache=30.0, identity_cache=15 * 60.0))
    ctx = background()

    r = e.check(ctx, req("a@x.com", "thing.write", "thing:1"))
    assert r.status == 200 and r.decision.outcome == Outcome.ALLOW and not r.cached, r
    r = e.check(ctx, req("a@x.com", "thing.write", "thing:1"))
    assert r.cached and r.decision.outcome == Outcome.ALLOW, f"decision not cached: {r}"
    assert c.checks.load() == 1, f"checks = {c.checks.load()}"
    # Same user, different resource: identity cached, check runs.
    r = e.check(ctx, req("a@x.com", "thing.write", "thing:2"))
    assert not r.cached and c.resolves.load() == 1 and c.checks.load() == 2, f"identity cache: resolves={c.resolves.load()} checks={c.checks.load()}"
    # Unknown decisions are not cached.
    r = e.check(ctx, req("u@x.com", "thing.read", "thing:hidden"))
    assert r.decision.code == Code.RESOURCE_NOT_VISIBLE, r
    r = e.check(ctx, req("u@x.com", "thing.read", "thing:hidden"))
    assert not r.cached, "unknown was cached"
    # Negative identity is cached.
    before = c.resolves.load()
    e.check(ctx, req("nobody@x.com", "thing.read", "thing:1"))
    r = e.check(ctx, req("nobody@x.com", "thing.read", "thing:1"))
    assert r.decision.code == Code.USER_NOT_FOUND and r.decision.outcome == Outcome.DENY and c.resolves.load() == before + 1, (
        f"negative identity: {r} resolves={c.resolves.load()}"
    )
    # Decision log has one line per check with the right fields.
    lines = 0
    for line in logs.text().strip().split("\n"):
        try:
            ent = json.loads(line)
        except ValueError:
            continue
        if ent.get("decision") is not None:
            lines += 1
            assert ent["connection"] == "c" and ent.get("action") is not None and ent.get("status") is not None, f"bad log entry: {line}"
    assert lines == 7, f"decision log lines = {lines}"


def groups_req(user: str, *groups: str) -> Request:
    return Request(user=user, groups=list(groups), connection="c", action="thing.read", resource="thing:1")


def test_identity_cache_keyed_by_groups() -> None:
    """The identity cache is keyed by the request's groups too:
    integrations that embed the caller's groups in the Identity must not
    serve a later request with the first request's groups."""
    c = Counting()
    e, _ = build_engine(c, Options(identity_cache=15 * 60.0))
    ctx = background()

    def seen() -> list[str]:
        with c.mu:
            return list(c.identity_groups)

    r = e.check(ctx, groups_req("a@x.com", "system:masters"))
    assert r.decision.outcome == Outcome.ALLOW and c.resolves.load() == 1, f"{r} resolves={c.resolves.load()}"
    assert seen() == ["system:masters"], f"identity groups = {seen()}"
    # Same user, no groups: a second resolve, and check sees no groups.
    r = e.check(ctx, groups_req("a@x.com"))
    assert r.decision.outcome == Outcome.ALLOW and c.resolves.load() == 2, f"{r} resolves={c.resolves.load()}, want 2"
    assert seen() == [], f"identity groups = {seen()}, want none (cached identity carried the first request's groups)"
    # The first key is still cached.
    e.check(ctx, groups_req("a@x.com", "system:masters"))
    assert c.resolves.load() == 2 and seen() == ["system:masters"], f"resolves={c.resolves.load()} groups={seen()}"
    # Order and duplicates do not matter for the key.
    e.check(ctx, groups_req("a@x.com", "b", "a", "a"))
    e.check(ctx, groups_req("a@x.com", "a", "b"))
    assert c.resolves.load() == 3 and seen() == ["a", "b"], f"resolves={c.resolves.load()} groups={seen()}"
    # Negative entries are keyed the same way.
    before = c.resolves.load()
    e.check(ctx, groups_req("nobody@x.com", "x"))
    e.check(ctx, groups_req("nobody@x.com", "y"))
    e.check(ctx, groups_req("nobody@x.com", "x"))
    assert c.resolves.load() == before + 2, f"negative resolves = {c.resolves.load()}, want {before + 2}"


def test_negative_identity_not_shared_across_groups() -> None:
    """A user_not_found for one set of groups must not be served to the same
    user arriving with a group that does map (aws static_map)."""
    c = Counting(need_group="platform")
    e, _ = build_engine(c, Options(identity_cache=15 * 60.0))
    ctx = background()
    r = e.check(ctx, groups_req("u@x.com"))
    assert r.decision.code == Code.USER_NOT_FOUND, r
    r = e.check(ctx, groups_req("u@x.com", "platform"))
    assert r.decision.outcome == Outcome.ALLOW and c.resolves.load() == 2, f"mapped group after a miss: {r} resolves={c.resolves.load()}"
    # The miss is still remembered for the unmapped shape.
    r = e.check(ctx, groups_req("u@x.com"))
    assert r.decision.code == Code.USER_NOT_FOUND and c.resolves.load() == 2, f"{r} resolves={c.resolves.load()}"


def test_decision_cache_key_group_boundaries() -> None:
    """Group boundaries are part of the decision cache key: ["a","b,c"] and
    ["a,b","c"] are different requests, whatever the join character."""
    c = Counting()
    e, _ = build_engine(c, Options(decision_cache=30.0))
    ctx = background()
    r = e.check(ctx, groups_req("a@x.com", "a", "b,c"))
    assert not r.cached and r.decision.outcome == Outcome.ALLOW, f"first partition: {r}"
    r = e.check(ctx, groups_req("a@x.com", "a,b", "c"))
    assert not r.cached, f"second partition served from the first's entry: {r}"
    r = e.check(ctx, groups_req("a@x.com", "b,c", "a"))
    assert r.cached, f"first partition not cached on repeat: {r}"
    assert c.checks.load() == 2, f"checks = {c.checks.load()}"


def test_no_caches() -> None:
    c = Counting()
    e, _ = build_engine(c, Options())
    ctx = background()
    e.check(ctx, req("a@x.com", "thing.write", "thing:1"))
    r = e.check(ctx, req("a@x.com", "thing.write", "thing:1"))
    assert not r.cached and c.checks.load() == 2 and c.resolves.load() == 2, f"caches disabled: {r} {c.checks.load()} {c.resolves.load()}"


@pytest.mark.parametrize(
    ("r", "code"),
    [
        (Request(user="", connection="c", action="thing.read", resource="thing:1"), Code.INVALID_REQUEST),
        (Request(user="not-an-email", connection="c", action="thing.read", resource="thing:1"), Code.INVALID_REQUEST),
        (Request(user="a@x.com", groups=[""], connection="c", action="thing.read", resource="thing:1"), Code.INVALID_REQUEST),
        (Request(user="a@x.com", connection="", action="thing.read", resource="thing:1"), Code.INVALID_REQUEST),
        (Request(user="a@x.com", connection="c", action="", resource="thing:1"), Code.INVALID_REQUEST),
        (Request(user="a@x.com", connection="c", action="thing.read", resource=""), Code.INVALID_REQUEST),
        (Request(user="a@x.com", connection="c", action="thing.read", resource="Thing:1"), Code.INVALID_REQUEST),
        (Request(user="a@x.com", connection="zzz", action="thing.read", resource="thing:1"), Code.UNKNOWN_CONNECTION),
        (Request(user="a@x.com", connection="c", action="thing.fly", resource="thing:1"), Code.UNKNOWN_ACTION),
    ],
)
def test_bad_requests(r: Request, code: Code) -> None:
    c = Counting()
    e, _ = build_engine(c, Options())
    res = e.check(background(), r)
    assert res.status == 400 and res.decision.code == code and res.decision.outcome == Outcome.UNKNOWN, f"{r} -> {res}"
    assert c.checks.load() == 0, "bad requests reached the integration"


def test_timeout_and_bad_allow() -> None:
    import time

    c = Counting(slow=2.0)
    e, _ = build_engine(c, Options())
    start = time.monotonic()
    r = e.check(background(), req("a@x.com", "thing.read", "thing:1"))
    assert r.decision.code == Code.UPSTREAM_TIMEOUT and r.decision.outcome == Outcome.UNKNOWN, r
    assert time.monotonic() - start <= 1.0, "timeout not enforced"
    c2 = Counting(bad_allow=True)
    e2, _ = build_engine(c2, Options())
    r = e2.check(background(), req("a@x.com", "thing.read", "thing:1"))
    assert r.decision.outcome == Outcome.UNKNOWN, f"allow with a non-allow code got through: {r}"


def test_lookup_panic_logged() -> None:
    """A crash inside a lookup is an unknown decision, logged once with its
    stack and the exception's type, never its value."""
    c = Counting(panic_resolve=True)
    e, logs = build_engine(c, Options(identity_cache=15 * 60.0))
    ctx = background()
    barrier = threading.Barrier(4)

    def one() -> Result:
        barrier.wait()
        return e.check(ctx, req("a@x.com", "thing.read", "thing:1"))

    with ThreadPoolExecutor(4) as pool:
        results = list(pool.map(lambda _: one(), range(4)))
    for r in results:
        assert r.decision.outcome == Outcome.UNKNOWN and r.decision.code == Code.UPSTREAM_ERROR, r
    n = logs.text().count('"lookup panicked"')
    assert 1 <= n <= 4, f"panic logged {n} times"
    assert '"stack"' in logs.text() and "resolve bug" not in logs.text(), f"log: {logs.text()}"
    # One fill, one PanicError, one log line: callers that shared it do not
    # each log it.
    if c.resolves.load() == 1:
        assert logs.text().count('"lookup panicked"') == 1, f"one panic logged {logs.text().count(chr(34) + 'lookup panicked' + chr(34))} times"


def test_probe_and_connections() -> None:
    c = Counting()
    e, _ = build_engine(c, Options())
    got = e.connections()
    assert len(got) == 2 and got[0] == "f", got
    reps = e.probe(background())
    assert len(reps) == 2 and reps[0].err is None and reps[1].err is None, reps
    reps = e.probe(background(), "nope")
    assert len(reps) == 1 and reps[0].err is not None, reps
    assert e.connection("c") is not None, "connection"


@pytest.mark.parametrize("ok", ["a@b", "dana@example.com", "o'neil+x@ex.co.uk"])
def test_validate_user_accepts(ok: str) -> None:
    validate_user(ok)


@pytest.mark.parametrize("bad", ["", "a", "@b", "a@", "a b@c", "a@b@c", "a\n@b", "a" * 320 + "@b"])
def test_validate_user_rejects(bad: str) -> None:
    with pytest.raises(ValueError):
        validate_user(bad)


class Failing(Integration):
    def name(self) -> str:
        return "failing"

    def fields(self) -> list[Field]:
        return []

    def actions(self) -> list[Action]:
        return []

    def new(self, ctx: Context, s: Settings, d: Deps) -> Connection:
        raise RuntimeError("cannot build")


def test_build_errors() -> None:
    reg = Registry()
    reg.register(Failing())
    cfg = parse("t.yaml", b"api_key: env:K\nconnections:\n  - id: a\n    integration: failing\n", reg)
    with pytest.raises(EngineError) as ei:
        build(background(), cfg, Options())
    assert 'connection "a" (failing)' in str(ei.value), str(ei.value)
