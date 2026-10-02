"""Authorization answered by hallpass: may this user do this, asked live of
the system that owns the resource.

    from hallpass import Hallpass
    hp = Hallpass.from_config("hallpass.yaml")          # or Hallpass.remote(url, key)

    @tools.tool(effect="write", authorize=hallpass_check(hp, "github-acme", "pull_request.create", "repo:{repo}"))
    def open_pr(repo: str, title: str) -> str: ...

Works with anything that has hallpass's ``check`` method, in-process or
remote; securetools does not import hallpass itself.
"""

from __future__ import annotations

from typing import Any, Protocol

from securetools._toolkit import AuthDecision, Call


class _Checker(Protocol):
    def check(self, user: str, connection: str, action: str, resource: str, groups: Any = None, *, fresh: bool = False) -> Any: ...


def hallpass_check(hp: _Checker, connection: str, action: str, resource: str, *, fresh: bool = False) -> Any:
    """An authorizer that asks hallpass about the session's user.

    ``resource`` is a format string over the call's arguments, e.g.
    ``"issue:{key}"``. Only hallpass's ``allow`` lets the call through:
    ``deny``, ``unknown`` and an unreachable hallpass all refuse. Use
    ``fresh=True`` on destructive tools to skip hallpass's caches.
    """

    def authorize(call: Call) -> AuthDecision:
        target = resource.format(**call.arguments)
        groups = None if call.session.groups is None else list(call.session.groups)
        d = hp.check(call.session.user, connection, action, target, groups, fresh=fresh)
        outcome = getattr(d, "decision", None)
        return AuthDecision(outcome == "allow", f"hallpass {outcome} {action} on {target} in {connection}: {getattr(d, 'reason', '')}")

    authorize.__name__ = f"hallpass_check({connection}, {action})"
    return authorize
