"""Authorization answered by toolpass: may this user do this, asked live of
the system that owns the resource.

    from toolpass import Toolpass
    tp = Toolpass.from_config("toolpass.yaml")          # or Toolpass.remote(url, key)

    @tools.tool(effect="write", authorize=permission_check(tp, "github-acme", "pull_request.create", "repo:{repo}"))
    def open_pr(repo: str, title: str) -> str: ...

Works with anything that has toolpass's ``check`` method, in-process or
remote; toolpass does not import toolpass itself.
"""

from __future__ import annotations

import string
from typing import Any, Protocol

from toolpass._toolkit import AuthDecision, Call


class _Checker(Protocol):
    def check(self, user: str, connection: str, action: str, resource: str, groups: Any = None, *, fresh: bool = False) -> Any: ...


def permission_check(tp: _Checker, connection: str, action: str, resource: str, *, fresh: bool = False) -> Any:
    """An authorizer that asks toolpass about the session's user.

    ``resource`` is a format string over the call's arguments, e.g.
    ``"issue:{key}"``. Only toolpass's ``allow`` lets the call through:
    ``deny``, ``unknown`` and an unreachable toolpass all refuse. Use
    ``fresh=True`` on destructive tools to skip toolpass's caches.
    """

    fields = set()
    for _, field, _, _ in string.Formatter().parse(resource):
        if field is None:
            continue
        name = field.split(".")[0].split("[")[0]
        if not name or name.isdigit():
            raise ValueError(f"permission_check: resource {resource!r} must name the tool's parameters, as in 'issue:{{key}}'")
        fields.add(name)

    def authorize(call: Call) -> AuthDecision:
        target = resource.format(**call.arguments)
        groups = None if call.session.groups is None else list(call.session.groups)
        d = tp.check(call.session.user, connection, action, target, groups, fresh=fresh)
        outcome = getattr(d, "decision", None)
        return AuthDecision(outcome == "allow", f"toolpass {outcome} {action} on {target} in {connection}: {getattr(d, 'reason', '')}")

    authorize.__name__ = f"permission_check({connection}, {action})"
    authorize.__toolpass_fields__ = frozenset(fields)  # type: ignore[attr-defined]
    return authorize
