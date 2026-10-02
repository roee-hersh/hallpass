"""The public Python API: ``Toolpass`` (in-process or remote), ``guarded``.

    from toolpass import Toolpass, guarded

    tp = Toolpass.from_config("toolpass.yaml")          # in-process engine
    tp = Toolpass(connections=[{"id": "github-main", "integration": "github", ...}])
    tp = Toolpass.remote("https://toolpass.internal")  # a toolpass server

The one rule an agent has to follow: perform an action on behalf of a user
only when toolpass answered ``allow``. ``deny`` and ``unknown`` both mean
"do not act", and so does any failure to get an answer at all.
"""

from __future__ import annotations

import asyncio
import contextvars
import datetime
import functools
import http.client
import inspect
import json
import logging
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, TypeVar, Union

__all__ = [
    "ALLOW",
    "DENY",
    "UNKNOWN",
    "Decision",
    "GroupsSource",
    "PermissionDenied",
    "Toolpass",
    "UserSource",
    "current",
    "guarded",
]

ALLOW = "allow"
DENY = "deny"
UNKNOWN = "unknown"

# Where guarded reports each write it let through. toolpass never sees the
# write itself, so this is the record that ties the action to the check.
log = logging.getLogger("toolpass")


@dataclass(frozen=True)
class Decision:
    """One answer.

    ``decision`` is ``allow``, ``deny`` or ``unknown``. ``reason`` is
    ``"<code>: <text>"``, or ``"client_error: ..."`` when a remote request
    never produced a usable answer. ``status`` is the HTTP status the server
    used (the in-process engine reports the one it would have used), 0 when
    no response arrived.
    """

    decision: str
    reason: str
    status: int = 200

    @property
    def allowed(self) -> bool:
        """True only for a positive ``allow``. ``unknown`` is not allowed."""
        return self.decision == ALLOW

    @property
    def code(self) -> str:
        """The machine-readable code in front of the colon, e.g. ``user_not_found``."""
        return self.reason.split(":", 1)[0].strip()


class PermissionDenied(Exception):
    """Raised by ``Toolpass.require`` when the answer was not ``allow``."""

    def __init__(self, decision: Decision, user: str, connection: str, action: str, resource: str):
        self.decision = decision
        self.user, self.connection, self.action, self.resource = user, connection, action, resource
        super().__init__(f"{user} may not {action} on {resource} in {connection}: {decision.decision} ({decision.reason})")


class Toolpass:
    """Permission checks for one set of connections, answered live.

    Three ways to make one, all with the same methods:

    - ``Toolpass.from_config(path)``: the engine runs in this process, from
      a toolpass YAML file. No service to deploy.
    - ``Toolpass(connections=[...])``: the same, with the connections given
      in code as mappings with exactly the keys of the file. Secret keys
      take ``toolpass.env("NAME")``, ``toolpass.file("/path")`` or
      ``toolpass.literal(value)``, or the file's ``"env:NAME"`` strings.
    - ``Toolpass.remote(url, api_key)``: ask a running toolpass server.

    ``check`` never raises for a failed lookup: every failure is an
    ``unknown`` decision. ``require`` raises ``PermissionDenied`` for
    anything but ``allow``.
    """

    def __init__(
        self,
        connections: Sequence[Mapping[str, Any]] | None = None,
        *,
        decision_cache_seconds: int = 30,
        identity_cache_seconds: int = 900,
        decision_log: str = "none",
        logger: Any = None,
    ):
        if connections is None:
            raise TypeError("Toolpass needs connections: Toolpass(connections=[...]), Toolpass.from_config(path) or Toolpass.remote(url, api_key)")
        from toolpass.core.config import from_mapping
        from toolpass.integrations import registry

        doc: dict[str, Any] = {
            "decision_log": decision_log,
            "decision_cache_seconds": decision_cache_seconds,
            "identity_cache_seconds": identity_cache_seconds,
            "connections": list(connections),
        }
        self._backend: _Backend = _Local(from_mapping(doc, registry(), "<connections>", require_api_key=False), logger)

    @classmethod
    def from_config(cls, path: str | os.PathLike[str], *, logger: Any = None) -> Toolpass:
        """The in-process engine from a toolpass YAML file. The file's
        caches and decision log apply; ``listen`` and ``api_key`` are for
        the server and are not needed here."""
        from toolpass.core.config import load
        from toolpass.integrations import registry

        self = cls.__new__(cls)
        self._backend = _Local(load(os.fspath(path), registry(), require_api_key=False), logger)
        return self

    @classmethod
    def remote(cls, url: str | None = None, api_key: str | None = None, timeout: float = 10.0) -> Toolpass:
        """A client for a running toolpass server. ``url`` defaults to
        ``$TOOLPASS_URL`` or ``http://localhost:8080``, ``api_key`` to
        ``$TOOLPASS_API_KEY``."""
        self = cls.__new__(cls)
        self._backend = _Remote(url, api_key, timeout)
        return self

    @property
    def local(self) -> bool:
        """True when the engine runs in this process."""
        return isinstance(self._backend, _Local)

    def check(
        self,
        user: str,
        connection: str,
        action: str,
        resource: str,
        groups: Iterable[str] | None = None,
        *,
        fresh: bool = False,
    ) -> Decision:
        """Ask. Never raises for a failed lookup: every failure becomes an
        ``unknown`` decision.

        ``fresh=True`` asks for an answer straight from the upstream system,
        skipping the caches. It narrows the window between the check and the
        action to the time between the two; it does not close it.
        """
        grp = None if groups is None else _group_list(groups)
        return self._backend.check(user, connection, action, resource, grp, fresh)

    def allowed(self, user: str, connection: str, action: str, resource: str, groups=None, *, fresh: bool = False) -> bool:
        """True only when the answer was ``allow``."""
        return self.check(user, connection, action, resource, groups, fresh=fresh).allowed

    def require(self, user: str, connection: str, action: str, resource: str, groups=None, *, fresh: bool = False) -> Decision:
        """Return the decision when it is ``allow``; raise ``PermissionDenied`` otherwise."""
        d = self.check(user, connection, action, resource, groups, fresh=fresh)
        if not d.allowed:
            raise PermissionDenied(d, user, connection, action, resource)
        return d

    async def acheck(self, user: str, connection: str, action: str, resource: str, groups=None, *, fresh: bool = False) -> Decision:
        """``check`` for async code; the lookup runs in a worker thread."""
        return await asyncio.to_thread(self.check, user, connection, action, resource, groups, fresh=fresh)

    async def arequire(self, user: str, connection: str, action: str, resource: str, groups=None, *, fresh: bool = False) -> Decision:
        """``require`` for async code."""
        return await asyncio.to_thread(self.require, user, connection, action, resource, groups, fresh=fresh)

    def probe(self) -> list[tuple[str, bool, str]]:
        """Verify every connection's credential (in-process only): a list
        of (connection id, ok, summary or error)."""
        if not isinstance(self._backend, _Local):
            raise TypeError("probe runs only in-process; use `toolpass probe` on the server")
        return self._backend.probe()

    def connections(self) -> list[str]:
        """The configured connection ids (in-process only)."""
        if not isinstance(self._backend, _Local):
            raise TypeError("connections are known only in-process")
        return self._backend.engine.connections()

    def __repr__(self) -> str:
        return f"Toolpass({self._backend!r})"


class _Backend:
    def check(self, user: str, connection: str, action: str, resource: str, groups: list[str] | None, fresh: bool) -> Decision:
        raise NotImplementedError


class _Local(_Backend):
    def __init__(self, cfg: Any, logger: Any) -> None:
        from toolpass.core.context import background
        from toolpass.core.declog import open_log
        from toolpass.core.engine import Options, build
        from toolpass.core.log import Logger, StdlibHandler

        if logger is None:
            lg = Logger(StdlibHandler())
        elif isinstance(logger, logging.Logger):
            lg = Logger(StdlibHandler(logger))
        else:
            lg = logger
        self.engine = build(
            background(),
            cfg,
            Options(
                logger=lg,
                decision_log=open_log(cfg.decision_log),
                decision_cache=cfg.decision_cache,
                identity_cache=cfg.identity_cache,
            ),
        )

    def check(self, user: str, connection: str, action: str, resource: str, groups: list[str] | None, fresh: bool) -> Decision:
        from toolpass.core.engine import Request

        for name, v in (("user", user), ("connection", connection), ("action", action), ("resource", resource)):
            if not isinstance(v, str):
                raise TypeError(f"{name} must be a string")
        res = self.engine.check(
            None, Request(user=user, connection=connection, action=action, resource=resource, groups=groups, fresh=fresh, remote="in-process")
        )
        return Decision(res.decision.outcome.value, res.decision.reason(), res.status)

    def probe(self) -> list[tuple[str, bool, str]]:
        out = []
        for r in self.engine.probe():
            if r.err is not None:
                out.append((r.id, False, str(r.err)))
            else:
                out.append((r.id, True, r.result.summary))
        return out

    def __repr__(self) -> str:
        return f"in-process, connections={self.engine.connections()!r}"


class _Remote(_Backend):
    """Client for one toolpass service.

    The URL must be ``https://``; plain ``http://`` is accepted only for
    ``localhost`` or a loopback address, because the API key travels in a
    header. ``timeout`` is the seconds the client waits for the connection
    and then for each read; toolpass waits up to the connection's
    ``timeout`` (8 s by default) for the upstream, so keep this a little
    above that. Redirects are not followed: a redirect would re-send the API
    key to whatever host the ``Location`` header names.
    """

    def __init__(self, url: str | None, api_key: str | None, timeout: float):
        self.url = _validate_url(url or os.environ.get("TOOLPASS_URL") or "http://localhost:8080")
        self.api_key = api_key if api_key is not None else os.environ.get("TOOLPASS_API_KEY", "")
        if not self.api_key:
            raise ValueError("toolpass API key missing: pass api_key or set TOOLPASS_API_KEY")
        self.timeout = timeout
        handlers: list[urllib.request.BaseHandler] = [_NoRedirect()]
        from toolpass.core.integration import is_loopback_host

        host = urllib.parse.urlsplit(self.url).hostname or ""
        if is_loopback_host(host):
            # Never through a proxy: the API key would travel to it, and Go's
            # proxy selection skips loopback too.
            handlers.append(urllib.request.ProxyHandler({}))
        self._opener = urllib.request.build_opener(*handlers)

    def check(self, user: str, connection: str, action: str, resource: str, groups: list[str] | None, fresh: bool) -> Decision:
        body: dict[str, Any] = {"user": user, "connection": connection, "action": action, "resource": resource}
        if groups is not None:
            body["groups"] = groups
        if fresh:
            body["fresh"] = True
        try:
            req = urllib.request.Request(
                self.url + "/check",
                data=json.dumps(body).encode(),
                method="POST",
                headers={
                    "Authorization": "Bearer " + self.api_key,
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
            )
            with self._opener.open(req, timeout=self.timeout) as resp:
                return _parse(resp.status, resp.read(_MAX_RESPONSE + 1))
        except urllib.error.HTTPError as e:
            # 400 and 401 still carry a decision body; anything else is unusable.
            try:
                raw = e.read(_MAX_RESPONSE + 1)
            except (OSError, http.client.HTTPException):
                raw = b""
            return _parse(e.code, raw)
        except (urllib.error.URLError, OSError, http.client.HTTPException, ValueError) as e:
            return Decision(UNKNOWN, f"client_error: toolpass unreachable: {e}", 0)

    def __repr__(self) -> str:
        return f"remote, url={self.url!r}"


def _validate_url(url: str) -> str:
    """The rule toolpass applies to its own upstream URLs."""
    if any(c in url for c in " \t\r\n?#"):
        raise ValueError(f"toolpass url {url!r} must not contain whitespace, '?' or '#'")
    u = urllib.parse.urlsplit(url)
    if u.username is not None or u.password is not None:
        raise ValueError(f"toolpass url {url!r} must not contain userinfo")
    if u.scheme == "https" and u.hostname:
        return url.rstrip("/")
    if u.scheme == "http" and u.hostname:
        from toolpass.core.integration import is_loopback_host

        if is_loopback_host(u.hostname):
            return url.rstrip("/")
    raise ValueError(f"toolpass url {url!r} must start with https:// (http:// only for localhost)")


def _group_list(groups: Iterable[str]) -> list[str]:
    if isinstance(groups, bool):
        raise TypeError("groups must be a list of strings; fresh is keyword-only (fresh=True)")
    if isinstance(groups, str):
        raise TypeError("groups must be a list of strings, not a string")
    out = list(groups)
    if not all(isinstance(g, str) for g in out):
        raise TypeError("groups must be a list of strings")
    return out


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Turn every redirect into an HTTPError instead of following it."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# A decision is a few hundred bytes; a body past this is not one.
_MAX_RESPONSE = 1 << 20


def _parse(status: int, raw: bytes) -> Decision:
    if len(raw) > _MAX_RESPONSE:
        return Decision(UNKNOWN, f"client_error: response larger than {_MAX_RESPONSE} bytes (HTTP {status})", status)
    try:
        data = json.loads(raw)
        decision, reason = data["decision"], str(data.get("reason", ""))
    except (ValueError, KeyError, TypeError, AttributeError):
        return Decision(UNKNOWN, f"client_error: unexpected response (HTTP {status})", status)
    if decision not in (ALLOW, DENY, UNKNOWN):
        return Decision(UNKNOWN, f"client_error: unexpected decision {decision!r}", status)
    if decision == ALLOW and status != 200:
        # toolpass never allows with a non-200 status; do not trust a proxy that does.
        return Decision(UNKNOWN, f"client_error: allow with HTTP {status}", status)
    return Decision(decision, reason, status)


def _log_write(
    who: str,
    outcome: str,
    connection: str,
    action: str,
    resource: str,
    d: Decision,
    checked_at: datetime.datetime,
    fresh: bool,
) -> None:
    """The line logged after a checked write ran, from ``guarded`` and the Strands handler."""
    log.info(
        "unconditional write: %s %s %s on %s in %s; toolpass said %s (%s) at %s, fresh=%s; "
        "the write was not conditioned on the state toolpass saw (no If-Match), "
        "so check and write were not atomic",
        who,
        outcome,
        action,
        resource,
        connection,
        d.decision,
        d.reason,
        checked_at.isoformat(timespec="milliseconds"),
        fresh,
    )


F = TypeVar("F", bound=Callable[..., Any])

# Where the acting user (or their groups) comes from: a fixed value, a
# zero-argument callable, or a contextvars.ContextVar the application sets
# for the current session or request.
UserSource = Union[str, Callable[[], str], "contextvars.ContextVar[str]"]
GroupsSource = Union[Iterable[str], Callable[[], Iterable[str]], "contextvars.ContextVar[Iterable[str]]"]


def current(source: Any, what: str = "user") -> Any:
    """Resolve a user or groups source now.

    A ``ContextVar`` with nothing set for this session raises ``RuntimeError``
    naming it, rather than a bare ``LookupError`` from inside a framework.
    """
    if isinstance(source, contextvars.ContextVar):
        try:
            return source.get()
        except LookupError:
            raise RuntimeError(f"no {what} set for this session in ContextVar {source.name!r}") from None
    if callable(source):
        return source()
    return source


def _takes_one_dict(sig: inspect.Signature) -> bool:
    """True for the Claude Agent SDK handler shape: one positional parameter
    annotated as a dict or Mapping, which receives all the arguments."""
    params = list(sig.parameters.values())
    if len(params) != 1 or params[0].kind not in (params[0].POSITIONAL_ONLY, params[0].POSITIONAL_OR_KEYWORD):
        return False
    ann = params[0].annotation
    if ann is inspect.Parameter.empty:
        return False
    name = ann if isinstance(ann, str) else getattr(ann, "__name__", None) or str(ann)
    origin = getattr(ann, "__origin__", None)
    if isinstance(origin, type) and issubclass(origin, Mapping):
        return True
    if isinstance(ann, type) and issubclass(ann, Mapping):
        return True
    return bool(re.match(r"(typing\.)?(dict|Dict|Mapping|MutableMapping)\b", name))


def guarded(
    tp: Toolpass,
    connection: str,
    action: str,
    resource: str,
    *,
    user: UserSource,
    groups: GroupsSource | None = None,
    deny: Callable[[PermissionDenied], Any] | None = None,
    fresh: bool = False,
) -> Callable[[F], F]:
    """Decorate a function so it runs only after toolpass allowed it.

    The user the check is for comes from ``user``: a string, a zero-argument
    callable, or a ``contextvars.ContextVar`` the application sets for the
    current session. It is never read from the call's arguments, so a
    framework's ``@tool`` can sit directly on top and the model cannot pick
    who it acts as; the decorated function's signature is exactly the
    original's. ``groups`` works the same way and must yield a list.

    ``resource`` is a format string over the call's arguments, e.g.
    ``"issue:{key}"``; a parameter left at its default is available too. A
    function with ordinary parameters is called with keyword arguments
    (LangChain, Strands, MCP); a function whose only parameter is a dict
    (the Claude Agent SDK handler shape, ``async def f(args: dict)``)
    receives all the arguments in that dict, and a ``user`` key in it is
    ignored, never honoured. ``async def`` is supported and the check then
    runs in a worker thread.

    Any answer other than ``allow`` raises ``PermissionDenied`` before the
    body runs. With ``deny`` given, its return value is returned instead of
    raising; use that where the framework would hide the exception's text
    from the model (MCPServer does).

    ``fresh=True`` makes every check skip toolpass's caches and ask the
    upstream system now. Use it for destructive actions.

    After the body has run, ``guarded`` logs one line on the ``toolpass``
    logger (INFO): the decision, when the check was made, whether it was
    fresh, and that the write was unconditional. toolpass only checked;
    the write itself ran afterwards with no ``If-Match`` on the state
    toolpass saw, so nobody reading the logs later should take check and
    write for one atomic step.

        @tool
        @guarded(tp, "jira-main", "DELETE_ISSUES", "issue:{key}", user=current_user, fresh=True)
        def delete_issue(key: str) -> str: ...
    """

    def wrap(fn: F) -> F:
        sig = inspect.signature(fn)
        one_dict = _takes_one_dict(sig)

        def prepare(args: tuple[Any, ...], kwargs: dict[str, Any]):
            if one_dict:
                if len(args) != 1 or kwargs or not isinstance(args[0], Mapping):
                    raise TypeError(f"{fn.__name__} takes one dict of arguments")
                fields, call = args[0], functools.partial(fn, args[0])
            else:
                if args:
                    raise TypeError(f"{fn.__name__} takes keyword arguments only")
                bound = sig.bind(**kwargs)  # a stray or missing argument fails here, before any check
                bound.apply_defaults()
                fields, call = bound.arguments, functools.partial(fn, **kwargs)
            who = current(user, "user")
            if not isinstance(who, str) or not who:
                raise RuntimeError("guarded: user must be a non-empty string")
            grp = None if groups is None else current(groups, "groups")
            return who, grp, resource.format(**fields), call

        def refused(e: PermissionDenied):
            if deny is None:
                raise e
            return deny(e)

        def ran(who: str, res: str, d: Decision, checked_at: datetime.datetime, outcome: str) -> None:
            _log_write(who, outcome, connection, action, res, d, checked_at, fresh)

        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def inner(*args, **kwargs):
                who, grp, res, call = prepare(args, kwargs)
                checked_at = datetime.datetime.now(datetime.timezone.utc)
                try:
                    d = await asyncio.to_thread(tp.require, who, connection, action, res, grp, fresh=fresh)
                except PermissionDenied as e:
                    return refused(e)
                try:
                    result = await call()
                except BaseException as e:
                    ran(who, res, d, checked_at, f"raised {type(e).__name__} from")
                    raise
                ran(who, res, d, checked_at, "ran")
                return result

        else:

            @functools.wraps(fn)
            def inner(*args, **kwargs):
                who, grp, res, call = prepare(args, kwargs)
                checked_at = datetime.datetime.now(datetime.timezone.utc)
                try:
                    d = tp.require(who, connection, action, res, grp, fresh=fresh)
                except PermissionDenied as e:
                    return refused(e)
                try:
                    result = call()
                except BaseException as e:
                    ran(who, res, d, checked_at, f"raised {type(e).__name__} from")
                    raise
                ran(who, res, d, checked_at, "ran")
                return result

        inner.__signature__ = sig  # type: ignore[attr-defined]
        return inner  # type: ignore[return-value]

    return wrap
