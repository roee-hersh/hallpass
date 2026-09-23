"""A minimal hallpass client for agents. Standard library only.

The one rule an agent has to follow: perform an action on behalf of a user
only when hallpass answered ``allow``. ``deny`` and ``unknown`` both mean
"do not act", and so does any failure to reach hallpass at all.

    hp = Hallpass()  # HALLPASS_URL and HALLPASS_API_KEY from the environment
    hp.require("dana@example.com", "jira-main", "DELETE_ISSUES", "issue:PAY-123")
    jira.delete_issue("PAY-123")  # only reached when the answer was allow

Or, for a tool an agent framework exposes to a model, ``guarded``:

    current_user: ContextVar[str] = ContextVar("current_user")

    @tool  # any framework's decorator
    @guarded(hp, "jira-main", "DELETE_ISSUES", "issue:{key}", user=current_user)
    def delete_issue(key: str) -> str:
        jira.delete_issue(key)
        return f"deleted {key}"

The user comes from the application, never from the tool's arguments.
"""

from __future__ import annotations

import asyncio
import contextvars
import functools
import http.client
import inspect
import ipaddress
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Callable, Iterable, TypeVar, Union

ALLOW = "allow"
DENY = "deny"
UNKNOWN = "unknown"


@dataclass(frozen=True)
class Decision:
    """One answer from ``POST /check``.

    ``decision`` is ``allow``, ``deny`` or ``unknown``. ``reason`` is
    ``"<code>: <text>"`` as hallpass sent it, or ``"client_error: ..."`` when
    the request never produced a usable answer. ``status`` is the HTTP status,
    0 when no response arrived.
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
    """Raised by ``Hallpass.require`` when the answer was not ``allow``."""

    def __init__(self, decision: Decision, user: str, connection: str, action: str, resource: str):
        self.decision = decision
        self.user, self.connection, self.action, self.resource = user, connection, action, resource
        super().__init__(
            f"{user} may not {action} on {resource} in {connection}: "
            f"{decision.decision} ({decision.reason})"
        )


class Hallpass:
    """Client for one hallpass service.

    ``url`` defaults to ``$HALLPASS_URL`` or ``http://localhost:8080``.
    ``api_key`` defaults to ``$HALLPASS_API_KEY``. The URL must be ``https://``;
    plain ``http://`` is accepted only for ``localhost`` or a loopback address,
    the same rule hallpass applies to its own upstream URLs, because the API
    key travels in a header. ``timeout`` is the seconds
    the client waits for the connection and then for each read; hallpass itself
    waits up to the connection's ``timeout`` (8 s by default) for the upstream
    system, so keep this a little above that. It is not a total wall-clock
    budget: a peer that keeps trickling bytes keeps the request alive.

    Redirects are not followed. A redirect would re-send the API key to
    whatever host the ``Location`` header names, and its answer would not be
    hallpass's, so a 3xx becomes an ``unknown`` decision like any other
    unusable response.
    """

    def __init__(self, url: str | None = None, api_key: str | None = None, timeout: float = 10.0):
        self.url = _validate_url(url or os.environ.get("HALLPASS_URL") or "http://localhost:8080")
        self.api_key = api_key if api_key is not None else os.environ.get("HALLPASS_API_KEY", "")
        if not self.api_key:
            raise ValueError("hallpass API key missing: pass api_key or set HALLPASS_API_KEY")
        self.timeout = timeout
        self._opener = urllib.request.build_opener(_NoRedirect)

    def check(
        self,
        user: str,
        connection: str,
        action: str,
        resource: str,
        groups: Iterable[str] | None = None,
    ) -> Decision:
        """Ask hallpass. Never raises on transport: every failure becomes an ``unknown`` decision."""
        body: dict = {"user": user, "connection": connection, "action": action, "resource": resource}
        if groups is not None:
            body["groups"] = _group_list(groups)
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
                return _parse(resp.status, resp.read())
        except urllib.error.HTTPError as e:
            # 400 and 401 still carry a decision body; anything else is unusable.
            try:
                raw = e.read()
            except (OSError, http.client.HTTPException):
                raw = b""
            return _parse(e.code, raw)
        except (urllib.error.URLError, OSError, http.client.HTTPException, ValueError) as e:
            # URLError covers refused connections and DNS failures, OSError the
            # socket timeout, HTTPException a malformed response, ValueError a
            # malformed URL.
            return Decision(UNKNOWN, f"client_error: hallpass unreachable: {e}", 0)

    def allowed(self, user: str, connection: str, action: str, resource: str, groups=None) -> bool:
        """True only when hallpass said ``allow``."""
        return self.check(user, connection, action, resource, groups).allowed

    def require(self, user: str, connection: str, action: str, resource: str, groups=None) -> Decision:
        """Return the decision when it is ``allow``; raise ``PermissionDenied`` otherwise."""
        d = self.check(user, connection, action, resource, groups)
        if not d.allowed:
            raise PermissionDenied(d, user, connection, action, resource)
        return d


def _validate_url(url: str) -> str:
    u = urllib.parse.urlsplit(url)
    if u.scheme == "https" and u.hostname:
        return url.rstrip("/")
    if u.scheme == "http" and u.hostname:
        host = u.hostname
        try:
            loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = host == "localhost"
        if loopback:
            return url.rstrip("/")
    raise ValueError(f"hallpass url {url!r} must start with https:// (http:// only for localhost)")


def _group_list(groups: Iterable[str]) -> list[str]:
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


def _parse(status: int, raw: bytes) -> Decision:
    try:
        data = json.loads(raw)
        decision, reason = data["decision"], str(data.get("reason", ""))
    except (ValueError, KeyError, TypeError):
        return Decision(UNKNOWN, f"client_error: unexpected response (HTTP {status})", status)
    if decision not in (ALLOW, DENY, UNKNOWN):
        return Decision(UNKNOWN, f"client_error: unexpected decision {decision!r}", status)
    if decision == ALLOW and status != 200:
        # hallpass never allows with a non-200 status; do not trust a proxy that does.
        return Decision(UNKNOWN, f"client_error: allow with HTTP {status}", status)
    return Decision(decision, reason, status)


F = TypeVar("F", bound=Callable)

# Where the acting user (or their groups) comes from: a fixed value, a
# zero-argument callable, or a contextvars.ContextVar the application sets
# for the current session or request.
Source = Union[Any, Callable[[], Any], "contextvars.ContextVar[Any]"]


def _resolve(source: Source, what: str) -> Any:
    if isinstance(source, contextvars.ContextVar):
        try:
            return source.get()
        except LookupError:
            raise RuntimeError(f"guarded: no {what} set in ContextVar {source.name!r}") from None
    if callable(source):
        return source()
    return source


def guarded(
    hp: Hallpass,
    connection: str,
    action: str,
    resource: str,
    *,
    user: Source,
    groups: Source | None = None,
    deny: Callable[[PermissionDenied], Any] | None = None,
) -> Callable[[F], F]:
    """Decorate a function so it runs only after hallpass allowed it.

    The user the check is for comes from ``user``: a string, a zero-argument
    callable, or a ``contextvars.ContextVar`` the application sets for the
    current session. It is never read from the call's arguments, so a
    framework's ``@tool`` can sit directly on top and the model cannot pick
    who it acts as; the decorated function's signature is exactly the
    original's. ``groups`` works the same way and must yield a list.

    ``resource`` is a format string over the call's arguments, e.g.
    ``"issue:{key}"``. The function may be called with keyword arguments
    (LangChain, Strands, MCP) or with one positional dict of arguments (the
    Claude Agent SDK handler shape); ``async def`` is supported and the
    check then runs in a worker thread.

    Any answer other than ``allow`` raises ``PermissionDenied`` before the
    body runs. With ``deny`` given, its return value is returned instead of
    raising; use that where the framework would hide the exception's text
    from the model (MCPServer does).

        @tool
        @guarded(hp, "jira-main", "DELETE_ISSUES", "issue:{key}", user=current_user)
        def delete_issue(key: str) -> str: ...
    """

    def wrap(fn: F) -> F:
        sig = inspect.signature(fn)

        def prepare(args: tuple, kwargs: dict):
            if len(args) == 1 and not kwargs and isinstance(args[0], Mapping):
                fields, call = args[0], functools.partial(fn, args[0])
            elif args:
                raise TypeError(f"{fn.__name__} takes keyword arguments or one dict of arguments")
            else:
                sig.bind(**kwargs)  # a stray or missing argument fails here, before any check
                fields, call = kwargs, functools.partial(fn, **kwargs)
            who = _resolve(user, "user")
            if not isinstance(who, str) or not who:
                raise RuntimeError("guarded: user must be a non-empty string")
            grp = None if groups is None else _group_list(_resolve(groups, "groups"))
            return who, grp, resource.format(**fields), call

        def refused(e: PermissionDenied):
            if deny is None:
                raise e
            return deny(e)

        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def inner(*args, **kwargs):
                who, grp, res, call = prepare(args, kwargs)
                try:
                    await asyncio.to_thread(hp.require, who, connection, action, res, grp)
                except PermissionDenied as e:
                    return refused(e)
                return await call()

        else:

            @functools.wraps(fn)
            def inner(*args, **kwargs):
                who, grp, res, call = prepare(args, kwargs)
                try:
                    hp.require(who, connection, action, res, grp)
                except PermissionDenied as e:
                    return refused(e)
                return call()

        inner.__signature__ = inspect.signature(fn)  # type: ignore[attr-defined]
        return inner  # type: ignore[return-value]

    return wrap
