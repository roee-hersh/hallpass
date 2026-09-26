"""Port of internal/engine/evidence_test.go."""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Iterator
from typing import Any

import pytest

from hallpass.core import evidence
from hallpass.core.catalog import Action
from hallpass.core.config import parse
from hallpass.core.context import Context, background
from hallpass.core.decision import Code, Decision, Outcome, allowed, denied
from hallpass.core.declog import DecisionLog
from hallpass.core.engine import Engine, Options, Request, build
from hallpass.core.integration import CheckRequest, Connection, Deps, Field, Identity, Integration, ProbeResult, Registry, Settings, User, url_field
from hallpass.core.log import DEBUG, JSONHandler, Logger
from hallpass.net import httpx
from tests import harness as itest

CANARY = "CANARY-SECRET-engine"


class _Counter:
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


class Upstream:
    """A fake system behind an HTTP server: it answers a token exchange, a
    user lookup with an ETag, and a permission read whose answer the test
    flips. It counts the calls so the tests can see the caches work."""

    def __init__(self) -> None:
        self.allow = True
        self.users = _Counter()
        self.perms = _Counter()
        self.tokens = _Counter()
        self.etag = '"user-v1"'
        self.srv = itest.Server(tls=False)
        self.srv.unmatched = self.handle

    def handle(self, w: itest.ResponseWriter, r: itest.Request) -> None:
        if r.path.startswith("/users/"):
            if r.header.get("Authorization") != "Bearer " + CANARY + "-token":
                w.write_header(401)
                return
            self.users.add(1)
            w.header().set("ETag", self.etag)
            w.write('{"id":"u1","secret":"' + CANARY + '-userbody"}')
            return
        if r.path == "/token":
            self.tokens.add(1)
            w.write('{"access_token":"' + CANARY + '-token"}')
        elif r.path == "/perm":
            self.perms.add(1)
            w.write('{"allow":' + ("true" if self.allow else "false") + "}")
        else:
            w.write_header(404)


@pytest.fixture
def u() -> Iterator[Upstream]:
    up = Upstream()
    yield up
    up.srv.close()


class Web(Integration):
    """The integration that talks to upstream through httpx, the way a real
    integration does: a plain client for the token, an authenticated one
    for the lookups."""

    def name(self) -> str:
        return "web"

    def fields(self) -> list[Field]:
        return [url_field(True, "base url")]

    def actions(self) -> list[Action]:
        return [Action("thing.write", "write")]

    def new(self, ctx: Context, s: Settings, d: Deps) -> Connection:
        hc = d.http_client(s)
        plain = httpx.Client(http=hc, base=s.get("url"), logger=d.logger)
        api = httpx.Client(http=hc, base=s.get("url"), logger=d.logger)

        def token(ctx: Context) -> str:
            _, tok = plain.post_json(ctx, "/token", {"grant": CANARY + "-secret"}, True)
            return str(tok["access_token"])

        api.auth = httpx.bearer_auth(token)
        return WebConn(api)


# Whether the last check ran under a fresh context, which is what an
# integration's own cache looks at.
last_fresh = threading.Event()


class WebConn(Connection):
    def __init__(self, api: httpx.Client) -> None:
        self.api = api

    def resolve_identity(self, ctx: Context, u: User) -> Identity:
        try:
            _, out = self.api.get_json(ctx, "/users/" + httpx.path_escape(u.email), None)
        except Exception as e:
            raise httpx.classify(e)
        return Identity(id=out["id"], display=u.email)

    def check(self, ctx: Context, r: CheckRequest) -> Decision:
        if evidence.fresh(ctx):
            last_fresh.set()
        else:
            last_fresh.clear()
        q = {"user": [r.identity.id], "token": [CANARY + "-query"]}
        try:
            _, out = self.api.get_json(ctx, "/perm", q)
        except Exception as e:
            raise httpx.classify(e)
        if out["allow"]:
            return allowed(f"{r.identity.display} may write")
        return denied(f"{r.identity.display} may not write")

    def probe(self, ctx: Context) -> ProbeResult:
        return ProbeResult(summary="ok")


def build_web(u: Upstream, o: Options) -> tuple[Engine, itest.Logs]:
    reg = Registry()
    reg.register(Web())
    cfg = parse("t.yaml", ("api_key: env:K\nconnections:\n  - id: w\n    integration: web\n    url: " + u.srv.url + "\n").encode(), reg)
    logs = itest.Logs()
    o.decision_log = DecisionLog(logs)
    o.logger = Logger(JSONHandler(logs, DEBUG))
    return build(background(), cfg, o), logs


def entries(logs: itest.Logs) -> list[dict[str, Any]]:
    """The decision log entries written so far."""
    out = []
    for line in logs.text().strip().split("\n"):
        try:
            ent = json.loads(line)
        except ValueError:
            continue
        if ent.get("decision"):
            out.append(ent)
    return out


def calls(ent: dict[str, Any]) -> list[evidence.Call]:
    ev = ent.get("evidence")
    return evidence.Evidence.from_json(ev).calls() if ev is not None else []


def web_req(resource: str, fresh: bool) -> Request:
    return Request(user="a@x.com", connection="w", action="thing.write", resource=resource, fresh=fresh)


def test_evidence_in_decision_log(u: Upstream) -> None:
    e, logs = build_web(u, Options(decision_cache=30.0, identity_cache=15 * 60.0))
    ctx = background()

    r = e.check(ctx, web_req("thing:1", False))
    assert r.decision.outcome == Outcome.ALLOW and not r.cached, r
    ev = r.decision.evidence
    assert ev is not None and len(ev.calls()) == 2 and not ev.truncated(), f"evidence: {ev}"
    # The identity lookup: ETag kept, no hash. Made by this check.
    c = ev.calls()[0]
    assert c.method == "GET" and c.path == "/users/a@x.com" and c.status == 200 and c.etag == '"user-v1"' and c.sha256 == "" and not c.cached, (
        f"identity call: {c}"
    )
    # The permission read: no ETag, so the body hash; the query is not there.
    c = ev.calls()[1]
    assert c.method == "GET" and c.path == "/perm" and c.status == 200 and c.etag == "" and len(c.sha256) == 64 and not c.cached, f"permission call: {c}"
    # The token exchange is not evidence.
    assert u.tokens.load() != 0, "no token exchange happened"

    # A cached decision logs the evidence that produced it.
    r = e.check(ctx, web_req("thing:1", False))
    assert r.cached and r.decision.evidence is not None and len(r.decision.evidence.calls()) == 2, f"cached: {r}"
    # Another resource: the identity comes from the cache and says so, the
    # permission read is live.
    r = e.check(ctx, web_req("thing:2", False))
    assert not r.cached and u.users.load() == 1, f"{r} users={u.users.load()}"
    assert r.decision.evidence is not None
    c = r.decision.evidence.calls()[0]
    assert c.cached and c.etag == '"user-v1"', f"cached identity call: {c}"
    c = r.decision.evidence.calls()[1]
    assert not c.cached and c.path == "/perm", f"live permission call: {c}"

    ents = entries(logs)
    assert len(ents) == 3, f"entries = {len(ents)}"
    assert not ents[0]["cached"] and len(calls(ents[0])) == 2, f"entry 0: {ents[0]}"
    assert ents[1]["cached"] and calls(ents[1]) and calls(ents[1])[0].etag == '"user-v1"', f"entry 1: {ents[1]}"
    assert not ents[2]["cached"] and calls(ents[2])[0].cached and not calls(ents[2])[1].cached, f"entry 2: {ents[2]}"
    # Nothing secret-shaped reaches a decision log line: not the token,
    # the query, the grant, the bodies, nor the token exchange itself.
    for ent in ents:
        s = json.dumps(ent)
        assert CANARY not in s and "/token" not in s and "?" not in s, f"decision log leaked: {s}"
    assert CANARY not in logs.text(), f"log leaked: {logs.text()}"


def test_fresh_check(u: Upstream) -> None:
    """A cached allow, then the upstream answer changes: a fresh check sees
    the new answer, bypassing the decision cache and the identity cache,
    and what it learns replaces both entries."""
    clock_mu = threading.Lock()
    clock = [time.time()]

    def now() -> float:
        with clock_mu:
            return clock[0]

    e, logs = build_web(u, Options(decision_cache=30.0, identity_cache=15 * 60.0, now=now))
    ctx = background()

    r = e.check(ctx, web_req("thing:1", False))
    assert r.decision.outcome == Outcome.ALLOW and not last_fresh.is_set(), f"{r} fresh={last_fresh.is_set()}"
    u.allow = False
    u.etag = '"user-v2"'
    # The cache still says allow.
    r = e.check(ctx, web_req("thing:1", False))
    assert r.cached and r.decision.outcome == Outcome.ALLOW, f"cached: {r}"
    # A fresh check reads again what was read more than a second ago.
    with clock_mu:
        clock[0] += 2.0
    # Fresh sees the change and re-resolves the identity.
    r = e.check(ctx, web_req("thing:1", True))
    assert not r.cached and r.decision.outcome == Outcome.DENY and u.users.load() == 2 and u.perms.load() == 2, (
        f"fresh: {r} users={u.users.load()} perms={u.perms.load()}"
    )
    assert r.decision.evidence is not None
    c = r.decision.evidence.calls()[0]
    assert not c.cached and c.etag == '"user-v2"', f"fresh identity call: {c}"
    assert last_fresh.is_set(), "the integration did not see a fresh context"
    # The fresh answer is what the caches now hold.
    r = e.check(ctx, web_req("thing:1", False))
    assert r.cached and r.decision.outcome == Outcome.DENY, f"after fresh: {r}"
    r = e.check(ctx, web_req("thing:2", False))
    assert r.decision.evidence is not None
    assert u.users.load() == 2 and r.decision.evidence.calls()[0].etag == '"user-v2"' and r.decision.evidence.calls()[0].cached, (
        f"identity cache not refreshed: users={u.users.load()} {r.decision.evidence.calls()}"
    )
    ents = entries(logs)
    assert len(ents) == 5, f"entries = {len(ents)}"
    for i, ent in enumerate(ents):
        assert bool(ent.get("fresh", False)) == (i == 2), f"entry {i} fresh = {ent.get('fresh')}"
    assert not ents[2]["cached"] and ents[2]["decision"] == "deny", f"fresh entry: {ents[2]}"
    # The fresh flag is honoured with the caches off too, and the fresh
    # entry is not written to a cache that is off.
    e2, _ = build_web(u, Options())
    r = e2.check(ctx, web_req("thing:1", True))
    assert not r.cached and r.decision.outcome == Outcome.DENY, f"no caches: {r}"
    assert e2._decs.len() == 0 and e2._id_cache.len() == 0, "fresh check stored into a disabled cache"


def test_evidence_on_failed_lookup(u: Upstream) -> None:
    """A failed identity lookup still leaves its evidence on the unknown
    decision, and an unknown decision is never cached, fresh or not."""
    e, _ = build_web(u, Options(decision_cache=30.0, identity_cache=15 * 60.0))

    def failing(w: itest.ResponseWriter, r: itest.Request) -> None:
        if r.path == "/token":
            w.write('{"access_token":"t"}')
            return
        w.write_header(503)

    u.srv.unmatched = failing
    for fresh in (False, True):
        r = e.check(background(), web_req("thing:1", fresh))
        assert r.decision.outcome == Outcome.UNKNOWN and r.decision.code == Code.UPSTREAM_ERROR, f"fresh={fresh}: {r}"
        ev = r.decision.evidence
        assert ev is not None and len(ev.calls()) != 0, f"fresh={fresh} evidence: {ev}"
        c = ev.calls()[0]
        assert c.path == "/users/a@x.com" and c.status == 503 and not c.cached, f"fresh={fresh} evidence: {ev.calls()}"
    assert e._decs.len() == 0 and e._id_cache.len() == 0, "a failed lookup was cached"
