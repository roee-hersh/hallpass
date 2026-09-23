"""A minimal hallpass client for agents. Standard library only.

The one rule an agent has to follow: perform an action on behalf of a user
only when hallpass answered ``allow``. ``deny`` and ``unknown`` both mean
"do not act", and so does any failure to reach hallpass at all.

    hp = Hallpass()  # HALLPASS_URL and HALLPASS_API_KEY from the environment
    hp.require("dana@example.com", "jira-main", "DELETE_ISSUES", "issue:PAY-123")
    jira.delete_issue("PAY-123")  # only reached when the answer was allow
"""

from __future__ import annotations

import functools
import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable, Iterable, TypeVar

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
    ``api_key`` defaults to ``$HALLPASS_API_KEY``. ``timeout`` is seconds per
    request; hallpass itself waits up to the connection's ``timeout`` (8 s by
    default) for the upstream system, so keep this a little above that.
    """

    def __init__(self, url: str | None = None, api_key: str | None = None, timeout: float = 10.0):
        self.url = (url or os.environ.get("HALLPASS_URL") or "http://localhost:8080").rstrip("/")
        self.api_key = api_key if api_key is not None else os.environ.get("HALLPASS_API_KEY", "")
        if not self.api_key:
            raise ValueError("hallpass API key missing: pass api_key or set HALLPASS_API_KEY")
        self.timeout = timeout

    def check(
        self,
        user: str,
        connection: str,
        action: str,
        resource: str,
        groups: Iterable[str] | None = None,
    ) -> Decision:
        """Ask hallpass. Never raises: every failure becomes an ``unknown`` decision."""
        body: dict = {"user": user, "connection": connection, "action": action, "resource": resource}
        if groups is not None:
            body["groups"] = list(groups)
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
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return _parse(resp.status, resp.read())
        except urllib.error.HTTPError as e:
            # 400 and 401 still carry a decision body; anything else is unusable.
            return _parse(e.code, e.read())
        except (urllib.error.URLError, TimeoutError, OSError) as e:
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


def guarded(hp: Hallpass, connection: str, action: str, resource: str) -> Callable[[F], F]:
    """Decorate a function so it runs only after hallpass allowed it.

    The decorated function must be called with keyword arguments and take a
    ``user`` keyword. ``resource`` is a format string over those keyword
    arguments, e.g. ``"issue:{key}"``. Any answer other than ``allow`` raises
    ``PermissionDenied`` before the function body runs.

        @guarded(hp, "jira-main", "DELETE_ISSUES", "issue:{key}")
        def delete_issue(*, user: str, key: str) -> str: ...
    """

    def wrap(fn: F) -> F:
        @functools.wraps(fn)
        def inner(*args, **kwargs):
            if args:
                raise TypeError(f"{fn.__name__} must be called with keyword arguments")
            user = kwargs["user"]
            hp.require(user, connection, action, resource.format(**kwargs))
            return fn(**kwargs)

        return inner  # type: ignore[return-value]

    return wrap
