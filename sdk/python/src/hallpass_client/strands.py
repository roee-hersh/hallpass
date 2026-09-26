"""hallpass as a Strands Agents intervention handler.

    pip install "hallpass-client[strands]"

Configured once on the agent, it checks every tool call that has a rule,
before the tool runs, and composes with Strands' other interventions:

    from hallpass_client import Hallpass
    from hallpass_client.strands import HallpassAuthorization, Rule

    hallpass = HallpassAuthorization(Hallpass(), {
        "open_config_pr": Rule("github-main", "repo.push", "repo:{owner}/{repo}", fresh=True),
        "delete_issue": ("jira-main", "DELETE_ISSUES", "issue:{key}"),
    })
    agent = Agent(tools=tools, interventions=[hallpass])
    agent(prompt, invocation_state={"user_id": user.email})  # from your auth

The user comes from ``invocation_state``, which the application passes and
the model cannot write.
"""

from __future__ import annotations

import asyncio
import datetime
import string
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Tuple, Union

from strands.hooks import AfterToolCallEvent, BeforeToolCallEvent
from strands.interventions import Deny, InterventionHandler, OnError, Proceed

from . import Decision, Hallpass, PermissionDenied, _group_list, _log_write

__all__ = ["HallpassAuthorization", "Rule"]

# Where a checked call's decision waits in invocation_state for the write log
# line, keyed by toolUseId. Strands keeps its own per-invocation keys there too.
_STATE_KEY = "hallpass_checks"


@dataclass(frozen=True)
class Rule:
    """What to ask hallpass before one tool runs.

    ``resource`` is a format string over the tool's input, e.g.
    ``"issue:{key}"``. Each field must be a plain input name. ``fresh=True``
    makes the check skip hallpass's caches; use it for destructive tools.
    """

    connection: str
    action: str
    resource: str
    fresh: bool = False


RuleLike = Union[Rule, Tuple[str, str, str], None]


@dataclass(frozen=True)
class _Check:
    user: str
    rule: Rule
    resource: str
    decision: Decision
    checked_at: datetime.datetime


def _as_rule(tool: str, r: Any) -> Rule | None:
    if r is None:
        return None
    if isinstance(r, tuple) and len(r) == 3:
        r = Rule(*r)
    if not isinstance(r, Rule) or not all(isinstance(v, str) and v for v in (r.connection, r.action, r.resource)):
        raise TypeError(f"rule for tool {tool!r} must be a Rule or a (connection, action, resource) tuple of strings")
    for _, field, _, _ in string.Formatter().parse(r.resource):
        if field is not None and not field.isidentifier():
            raise ValueError(f"resource {r.resource!r} for tool {tool!r}: {{{field}}} must name one input field")
    return r


def _resource(template: str, tool_input: Any) -> str:
    """Fill the template from the tool's input. Raises ValueError when it cannot."""
    if not isinstance(tool_input, Mapping):
        raise ValueError("the input is not an object")
    fields = {}
    for _, field, _, _ in string.Formatter().parse(template):
        if field is None:
            continue
        if field not in tool_input:
            raise ValueError(f"the input has no {field!r}")
        value = tool_input[field]
        if not isinstance(value, (str, int, float)):
            raise ValueError(f"{field!r} is a {type(value).__name__}, not a string or number")
        fields[field] = value
    return template.format_map(fields)


class HallpassAuthorization(InterventionHandler):
    """Check each tool call with hallpass before it runs.

    ``rules`` maps a tool name to a ``Rule`` or a ``(connection, action,
    resource)`` tuple. A tool without a rule runs unchecked, so reads stay
    fast; with ``strict=True`` it is denied instead, and a rule of ``None``
    names a tool that may run unchecked.

    The user is read from ``invocation_state[user_key]`` and must be a
    non-empty string, and with ``groups_key`` the groups from
    ``invocation_state[groups_key]`` as a list of strings; if either is
    missing the call is denied. Any answer other than ``allow`` denies the
    call, and the model sees the user, the action and hallpass's reason.
    A resource the input cannot fill denies too, and so does any error in the
    handler (``on_error`` is ``"deny"``).

    After a checked tool has run, the handler logs the same ``unconditional
    write`` line as ``guarded`` on the ``hallpass`` logger.

    List it last in ``interventions``: a later handler or hook that rewrites
    the tool call changes what runs after hallpass has checked it.
    """

    name = "hallpass-authorization"

    def __init__(
        self,
        hp: Hallpass,
        rules: Mapping[str, RuleLike],
        *,
        user_key: str = "user_id",
        groups_key: str | None = None,
        strict: bool = False,
    ) -> None:
        self._hp = hp
        self._rules = {tool: _as_rule(tool, r) for tool, r in rules.items()}
        self._user_key = user_key
        self._groups_key = groups_key
        self._strict = strict

    @property
    def on_error(self) -> OnError:
        """A handler that raises denies the call."""
        return "deny"

    async def before_tool_call(self, event: BeforeToolCallEvent, **kwargs: Any) -> Proceed | Deny:
        """Ask hallpass whether the invocation's user may make this call."""
        tool = event.tool_use["name"]
        if tool not in self._rules:
            return Deny(reason=f"no hallpass rule for tool {tool!r}") if self._strict else Proceed()
        rule = self._rules[tool]
        if rule is None:
            return Proceed()
        state = event.invocation_state
        user = state.get(self._user_key)
        if not isinstance(user, str) or not user:
            return Deny(reason=f"no user for this request: invocation_state[{self._user_key!r}] is not set")
        groups = None
        if self._groups_key is not None:
            try:
                groups = _group_list(state[self._groups_key])
            except (KeyError, TypeError):
                return Deny(reason=f"no groups for this request: invocation_state[{self._groups_key!r}] "
                                   "is not a list of strings")
        try:
            resource = _resource(rule.resource, event.tool_use.get("input"))
        except ValueError as e:
            return Deny(reason=f"cannot build the resource {rule.resource!r} for {tool}: {e}")
        checked_at = datetime.datetime.now(datetime.timezone.utc)
        d = await asyncio.to_thread(
            self._hp.check, user, rule.connection, rule.action, resource, groups, fresh=rule.fresh
        )
        if not d.allowed:
            return Deny(reason=str(PermissionDenied(d, user, rule.connection, rule.action, resource)))
        state.setdefault(_STATE_KEY, {})[event.tool_use["toolUseId"]] = _Check(user, rule, resource, d, checked_at)
        return Proceed()

    def after_tool_call(self, event: AfterToolCallEvent, **kwargs: Any) -> Proceed:
        """Log that a checked tool ran, and that the check did not make it atomic."""
        checks = event.invocation_state.get(_STATE_KEY)
        c = checks.pop(event.tool_use["toolUseId"], None) if isinstance(checks, dict) else None
        if c is None or event.cancel_message is not None:
            return Proceed()
        if event.exception is not None:
            outcome = f"raised {type(event.exception).__name__} from"
        elif event.result.get("status") != "success":
            outcome = "got an error result from"
        else:
            outcome = "ran"
        _log_write(c.user, outcome, c.rule.connection, c.rule.action, c.resource, c.decision, c.checked_at,
                   c.rule.fresh)
        return Proceed()
