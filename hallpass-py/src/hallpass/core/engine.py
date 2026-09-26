"""The check flow:

    validate request -> find connection -> find action -> decision cache ->
    resolve identity (cached) -> check under a timeout -> cache allow/deny ->
    decision log.

A fresh request skips both cache lookups and stores what it learns as
usual. Every upstream call the HTTP client completes during identity
resolution and check is recorded as evidence on the decision and in the log.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from hallpass.core import evidence
from hallpass.core.cache import TTL, PanicError, is_panic_type, panic_stack
from hallpass.core.catalog import ResourceError, parse_resource, validate_action_name
from hallpass.core.config import Config
from hallpass.core.context import Context, background, with_timeout
from hallpass.core.decision import (
    Code,
    Decision,
    HallpassError,
    outcome_of,
    to_decision,
    unknown_decision,
    unsupported,
)
from hallpass.core.declog import DecisionLog, Entry
from hallpass.core.errors import as_error, go_lower
from hallpass.core.integration import CheckRequest, Connection, Deps, Identity, Integration, ProbeResult, Settings, User
from hallpass.core.log import Logger

if TYPE_CHECKING:
    from hallpass.net.httpx import Transport

__all__ = ["Engine", "EngineError", "Options", "ProbeReport", "Request", "Result", "build", "validate_user"]


@dataclass
class Request:
    """One check after JSON decoding."""

    user: str
    connection: str
    action: str
    resource: str
    groups: list[str] | tuple[str, ...] | None = None
    # An answer straight from the upstream system: the decision cache, the
    # identity cache and the lookups integrations cache themselves are not
    # consulted, and what the request learns replaces their entries.
    fresh: bool = False
    # The caller's address, for the decision log only.
    remote: str = ""


@dataclass
class Result:
    """The answer plus the HTTP status the server should use."""

    decision: Decision
    status: int = 200
    cached: bool = False


@dataclass
class Options:
    logger: Logger | None = None
    decision_log: DecisionLog | None = None
    decision_cache: float = 0.0
    identity_cache: float = 0.0
    # How long user_not_found / user_ambiguous are remembered (default 60 s).
    negative_identity_cache: float = 0.0
    now: Callable[[], float] | None = None
    # Builds the transport for a connection. Tests replace it.
    http_client: Callable[[Settings], Transport] | None = None


@dataclass
class ProbeReport:
    id: str
    integration: str = ""
    result: ProbeResult = field(default_factory=ProbeResult)
    err: BaseException | None = None


class EngineError(Exception):
    pass


class _Conn:
    __slots__ = ("c", "integ", "settings")

    def __init__(self, settings: Settings, integ: Integration, c: Connection) -> None:
        self.settings = settings
        self.integ = integ
        self.c = c


class _IdEntry:
    __slots__ = ("err", "id")

    def __init__(self, id: Identity | None = None, err: HallpassError | None = None) -> None:
        self.id = id
        self.err = err


def _default_http_client(s: Settings) -> Transport:
    from hallpass.net import httpx

    return httpx.new_http_client(httpx.Options(ca_file=s.ca_file, tls_server_name=s.tls_server_name, proxy_url=s.proxy_url, timeout=s.effective_timeout()))


def _refers_to(i: Integration, s: Settings, id: str) -> bool:
    return any(f.ref and s.get(f.name) == id for f in i.fields())


def build(ctx: Context | None, cfg: Config, o: Options | None = None) -> Engine:
    """Construct every connection in dependency order."""
    return Engine(ctx or background(), cfg, o or Options())


class Engine:
    def __init__(self, ctx: Context, cfg: Config, o: Options) -> None:
        from hallpass.core.log import Logger as _L

        self._logger = o.logger if o.logger is not None else _L()
        self._declog = o.decision_log
        self._now = o.now or time.time
        self._id_ttl = o.identity_cache
        self._neg_ttl = o.negative_identity_cache or 60.0
        self._dec_ttl = o.decision_cache
        self._conns: dict[str, _Conn] = {}
        self._order: list[str] = []
        http_client = o.http_client or _default_http_client
        self.flush()
        for s in cfg.connections:
            integ = cfg.integrations.get(s.id)
            if integ is None:
                raise EngineError(f'connection "{s.id}": no integration')
            deps = Deps(
                logger=self._logger.with_("connection", s.id, "integration", s.integration),
                connection=self._resolver(integ, s),
                http_client=http_client,
                now=self._now,
            )
            try:
                c = integ.new(ctx, s, deps)
            except Exception as e:
                raise EngineError(f'connection "{s.id}" ({s.integration}): {e}') from e
            if c is None:
                raise EngineError(f'connection "{s.id}" ({s.integration}): integration returned no connection')
            self._conns[s.id] = _Conn(s, integ, c)
            self._order.append(s.id)

    def _resolver(self, integ: Integration, settings: Settings) -> Callable[[str], Connection]:
        def connection(id: str) -> Connection:
            if not _refers_to(integ, settings, id):
                raise EngineError(f'connection "{settings.id}" does not reference "{id}"')
            c = self._conns.get(id)
            if c is None:
                raise EngineError(f'connection "{id}" is not built')
            return c.c

        return connection

    def connections(self) -> list[str]:
        """Connection ids in build order."""
        return list(self._order)

    def connection(self, id: str) -> Connection | None:
        c = self._conns.get(id)
        return c.c if c is not None else None

    def integration(self, id: str) -> Integration | None:
        c = self._conns.get(id)
        return c.integ if c is not None else None

    def probe(self, ctx: Context | None = None, *ids: str) -> list[ProbeReport]:
        """Probe every connection (or the listed ones). A failure never
        stops the others."""
        ctx = ctx or background()
        out: list[ProbeReport] = []
        for id in ids or tuple(self._order):
            c = self._conns.get(id)
            if c is None:
                out.append(ProbeReport(id=id, err=EngineError("unknown connection")))
                continue
            pctx, cancel = with_timeout(ctx, 2 * c.settings.effective_timeout())
            try:
                r = c.c.probe(pctx)
                out.append(ProbeReport(id=id, integration=c.settings.integration, result=r))
            except Exception as e:  # noqa: BLE001 - a probe failure is a report
                if is_panic_type(e):
                    self._logger.error("probe panicked", connection=id, type=type(e).__name__, stack=panic_stack(e))
                self._log_panic(id, "probe", e)
                out.append(ProbeReport(id=id, integration=c.settings.integration, err=e))
            finally:
                cancel()
        return out

    def check(self, ctx: Context | None, req: Request) -> Result:
        """Answer one request."""
        ctx = ctx or background()
        start = self._now()
        res = self._check(ctx, req)
        # Safety: the outcome always follows the code. Allow needs ALLOWED.
        d = res.decision.with_(outcome=outcome_of(res.decision.code))
        res.decision = d
        if self._declog is not None:
            self._declog.log(
                Entry(
                    connection=req.connection,
                    user=req.user,
                    groups=list(req.groups) if req.groups else None,
                    action=req.action,
                    resource=req.resource,
                    decision=d.outcome.value,
                    code=d.code.value if d.code else "",
                    reason=d.text,
                    cached=res.cached,
                    fresh=req.fresh,
                    duration_ms=int((self._now() - start) * 1000),
                    status=res.status,
                    remote=req.remote,
                    evidence=d.evidence,
                )
            )
        return res

    def _check(self, ctx: Context, req: Request) -> Result:
        groups_in = list(req.groups or [])
        try:
            validate_user(req.user)
            _validate_groups(groups_in)
            if req.connection == "":
                raise ValueError("connection is empty")
            validate_action_name(req.action)
            resource = parse_resource(req.resource)
        except (ValueError, ResourceError) as e:
            return Result(unknown_decision(Code.INVALID_REQUEST, str(e)), 400)
        c = self._conns.get(req.connection)
        if c is None:
            return Result(unknown_decision(Code.UNKNOWN_CONNECTION, f'no connection with id "{req.connection}"'), 400)
        from hallpass.core.integration import find_action

        action = find_action(c.integ, req.action)
        if action is None:
            return Result(unknown_decision(Code.UNKNOWN_ACTION, f'integration {c.settings.integration} has no action "{req.action}"'), 400)

        groups = _normalize_groups(groups_in)
        user = User(email=req.user, groups=tuple(groups))
        dec_key = "\x00".join([req.connection, req.user, "\x01".join(groups), req.action, req.resource])
        started = self._now()
        if self._dec_ttl > 0 and not req.fresh:
            d, ok = self._decs.get(dec_key)
            if ok and d is not None:
                return Result(d.with_(evidence=evidence.as_cached(d.evidence)), 200, True)

        cctx, cancel = with_timeout(ctx, c.settings.effective_timeout())
        try:
            cctx, rec = evidence.with_recorder(cctx)
            if req.fresh:
                cctx = evidence.with_fresh(cctx)
            try:
                identity = self._identity(cctx, c, user)
            except Exception as e:  # noqa: BLE001 - every failure is an unknown decision
                if is_panic_type(e):
                    # A crash outside the identity cache (it is off): logged
                    # like one inside it, type and stack, never the value.
                    self._logger.error("lookup panicked", connection=req.connection, action=req.action, type=type(e).__name__, stack=panic_stack(e))
                self._log_panic(req.connection, req.action, e)
                return Result(to_decision(e).with_(evidence=rec.evidence()), 200)
            try:
                d = c.c.check(cctx, CheckRequest(user=user, identity=identity, action=action, action_name=req.action, resource=resource))
            except Exception as e:  # noqa: BLE001
                if is_panic_type(e):
                    self._logger.error("check panicked", connection=req.connection, action=req.action, type=type(e).__name__, stack=panic_stack(e))
                self._log_panic(req.connection, req.action, e)
                d = to_decision(e)
                self._logger.debug("check failed", connection=req.connection, action=req.action, code=str(d.code), error=str(e))
            if not isinstance(d, Decision) or d.code is None:
                d = unsupported("integration returned no reason code")
            d = d.with_(outcome=outcome_of(d.code), evidence=rec.evidence())
            if self._dec_ttl > 0 and d.outcome.value != "unknown":
                # store, not set: a decision is as old as the oldest read it
                # rests on, and one built on older reads must not replace the
                # answer of a later one (a fresh check's, in particular).
                inputs = started
                o = rec.oldest()
                if o is not None and o < inputs:
                    inputs = o
                self._decs.store(dec_key, d, self._dec_ttl, inputs, started)
            return Result(d, 200)
        finally:
            cancel()

    def _log_panic(self, connection: str, action: str, err: BaseException) -> None:
        """Log, once per panic and with its stack, a crash a cache fill
        turned into a PanicError. Its type is logged, not its value, which
        may quote upstream data."""
        pe = as_error(err, PanicError)
        if pe is not None and pe.first_report():
            self._logger.error("lookup panicked", connection=connection, action=action, type=type(pe.value).__name__, stack=pe.stack)

    def _identity(self, ctx: Context, c: _Conn, u: User) -> Identity:
        """Resolve u through the identity cache, which also carries the
        evidence of the lookup to every check it serves."""
        key = _identity_key(c.settings.id, u)

        def fill(fctx: Context) -> tuple[_IdEntry, float]:
            try:
                return _IdEntry(id=c.c.resolve_identity(fctx, u)), self._id_ttl
            except Exception as e:
                ie = as_error(e, HallpassError)
                if ie is not None and ie.code in (Code.USER_NOT_FOUND, Code.USER_AMBIGUOUS):
                    return _IdEntry(err=ie), self._neg_ttl
                raise

        if self._id_ttl > 0:
            ent = self._id_cache.do(ctx, key, fill)
        else:
            ent, _ = fill(ctx)
        if ent.err is not None:
            raise ent.err
        assert ent.id is not None
        return ent.id

    def flush(self) -> None:
        """Empty both caches. They run on the engine's clock, since the
        engine dates decisions against the reads they rest on."""
        self._id_cache: TTL[str, _IdEntry] = TTL()
        self._id_cache.set_clock(self._now)
        self._decs: TTL[str, Decision] = TTL()
        self._decs.set_clock(self._now)


_MAX_EMAIL = 320
_MAX_GROUPS = 200
_MAX_GROUP = 256


def validate_user(u: str) -> None:
    """Check the shape of the caller's user string; raise ValueError."""
    if not isinstance(u, str) or u == "":
        raise ValueError("user is empty")
    if len(u.encode("utf-8", "surrogatepass")) > _MAX_EMAIL:
        raise ValueError(f"user is longer than {_MAX_EMAIL} bytes")
    for ch in u:
        if ord(ch) <= 0x20 or ord(ch) == 0x7F:
            raise ValueError("user contains whitespace or a control character")
    local, at, domain = u.partition("@")
    if not at or local == "" or domain == "" or "@" in domain:
        raise ValueError("user must be an email address")


def _validate_groups(gs: list[str]) -> None:
    if len(gs) > _MAX_GROUPS:
        raise ValueError(f"more than {_MAX_GROUPS} groups")
    for g in gs:
        if not isinstance(g, str) or g == "":
            raise ValueError("groups contains an empty entry")
        if len(g.encode("utf-8", "surrogatepass")) > _MAX_GROUP:
            raise ValueError(f"group longer than {_MAX_GROUP} bytes")
        for ch in g:
            if ord(ch) < 0x20 or ord(ch) == 0x7F:
                raise ValueError("group contains a control character")


def _normalize_groups(gs: list[str]) -> list[str]:
    """Sorted and deduplicated, so the same set looks the same to the
    integration and to both caches. Sorted by UTF-8 bytes, as Go sorts."""
    return sorted(set(gs), key=lambda s: s.encode("utf-8", "surrogatepass"))


def _identity_key(conn_id: str, u: User) -> str:
    """The connection, the lowercased email and the normalized groups:
    integrations such as kubernetes embed the groups in the Identity."""
    return "\x00".join([conn_id, go_lower(u.email), *u.groups])
