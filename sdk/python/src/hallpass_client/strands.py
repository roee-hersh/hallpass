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

try:
    from strands.hooks import AfterToolCallEvent, BeforeInvocationEvent, BeforeToolCallEvent
    from strands.interventions import Deny, InterventionHandler, OnError, Proceed
except ImportError as e:
    raise ImportError(
        "hallpass_client.strands needs strands-agents 1.57.1 or later, on Python 3.10 or later: "
        'pip install "hallpass-client[strands]"'
    ) from e

from . import Decision, Hallpass, PermissionDenied, _group_list, _log_write, log

__all__ = ["HallpassAuthorization", "Rule"]

# Where a checked call's decision waits in invocation_state for the write log
# line, keyed by toolUseId. Strands keeps its own per-invocation keys there too.
_STATE_KEY = "hallpass_checks"

# The JSON Schema types a resource field may have, and the one Python type the
# model's value must have for each. Strands validates the input before the tool
# runs and converts, for example, "01", 1.0 and true to the integer 1; a value of
# exactly this type reaches the tool unchanged, so the resource hallpass checks
# is the one the tool acts on.
_FIELD_TYPES = {"string": str, "integer": int}


@dataclass(frozen=True)
class Rule:
    """What to ask hallpass before one tool runs.

    ``resource`` is a format string over the tool's input, e.g.
    ``"issue:{key}"``. Each field must be a plain input name, and the tool
    must declare that input as a string or an integer. ``fresh=True`` makes
    the check skip hallpass's caches; use it for destructive tools.
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


def _as_rule(tool: str, r: Any) -> tuple[Rule, tuple[str, ...]] | None:
    """The rule and the input fields its resource uses."""
    if r is None:
        return None
    if isinstance(r, tuple) and len(r) == 3:
        r = Rule(*r)
    if not isinstance(r, Rule) or not all(isinstance(v, str) and v for v in (r.connection, r.action, r.resource)):
        raise TypeError(f"rule for tool {tool!r} must be a Rule or a (connection, action, resource) tuple of strings")
    fields = []
    for _, field, _, _ in string.Formatter().parse(r.resource):
        if field is None:
            continue
        if not field.isidentifier():
            raise ValueError(f"resource {r.resource!r} for tool {tool!r}: {{{field}}} must name one input field")
        fields.append(field)
    return r, tuple(fields)


def _resource(template: str, fields: tuple[str, ...], tool_input: Any, schema: Any) -> str:
    """Fill the template from the tool's input. Raises ValueError when it cannot."""
    if not isinstance(tool_input, Mapping):
        raise ValueError("the input is not an object")
    props = schema.get("properties") if isinstance(schema, Mapping) else None
    values = {}
    for field in fields:
        prop = props.get(field) if isinstance(props, Mapping) else None
        want = _FIELD_TYPES.get(prop.get("type")) if isinstance(prop, Mapping) else None
        if want is None:
            raise ValueError(f"the tool does not declare {field!r} as a string or an integer")
        if field in tool_input:
            value = tool_input[field]
        elif "default" in prop:
            value = prop["default"]  # what the tool runs with when the model leaves it out
        else:
            raise ValueError(f"the input has no {field!r}")
        if type(value) is not want:  # not isinstance: a bool is an int, and Strands would convert it
            raise ValueError(f"{field!r} must be a JSON {prop['type']}, not {type(value).__name__}")
        values[field] = value
    return template.format_map(values)


class HallpassAuthorization(InterventionHandler):
    """Check each tool call with hallpass before it runs.

    ``rules`` maps a tool name to a ``Rule`` or a ``(connection, action,
    resource)`` tuple. A tool without a rule runs unchecked, so reads stay
    fast; with ``strict=True`` it is denied instead, and a rule of ``None``
    names a tool that may run unchecked. A rule that names no tool the agent
    has is logged as a warning, since it is usually a typo that leaves the
    real tool unchecked.

    The user is read from ``invocation_state[user_key]`` and must be a
    non-empty string, and with ``groups_key`` the groups from
    ``invocation_state[groups_key]`` as a list of strings; if either is
    missing the call is denied. Any answer other than ``allow`` denies the
    call, and the model sees the user, the action and hallpass's reason.
    A resource the input cannot fill denies too, and so does any error in the
    handler (``on_error`` is ``"deny"``).

    After a checked tool has run, the handler logs the same ``unconditional
    write`` line as ``guarded`` on the ``hallpass`` logger.

    It checks the call as it stands when interventions run. List it last in
    ``interventions``, and do not rewrite tool calls in hooks registered after
    it or in tool middleware: those change what runs after hallpass checked it.
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
        self._warned: set[str] = set()

    @property
    def on_error(self) -> OnError:
        """A handler that raises denies the call."""
        return "deny"

    def before_invocation(self, event: BeforeInvocationEvent, **kwargs: Any) -> Proceed:
        """Warn once about rules that name no tool this agent has."""
        missing = set(self._rules) - set(event.agent.tool_names) - self._warned
        if missing:
            self._warned |= missing
            log.warning("hallpass rules name tools the agent does not have, so they check nothing: %s",
                        ", ".join(sorted(missing)))
        return Proceed()

    async def before_tool_call(self, event: BeforeToolCallEvent, **kwargs: Any) -> Proceed | Deny:
        """Ask hallpass whether the invocation's user may make this call."""
        tool = event.tool_use["name"]
        selected = event.selected_tool
        if selected is not None and selected.tool_name != tool:
            # A hook swapped the tool without renaming the call; neither name says what runs.
            if tool in self._rules or selected.tool_name in self._rules or self._strict:
                return Deny(reason=f"tool call {tool!r} was rerouted to {selected.tool_name!r}")
            return Proceed()
        if tool not in self._rules:
            return Deny(reason=f"no hallpass rule for tool {tool!r}") if self._strict else Proceed()
        entry = self._rules[tool]
        if entry is None:
            return Proceed()
        rule, fields = entry
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
        schema = selected.tool_spec.get("inputSchema", {}).get("json") if selected is not None else None
        try:
            resource = _resource(rule.resource, fields, event.tool_use.get("input"), schema)
        except ValueError as e:
            return Deny(reason=f"cannot build the resource {rule.resource!r} for {tool}: {e}")
        checked_at = datetime.datetime.now(datetime.timezone.utc)
        d = await asyncio.to_thread(
            self._hp.check, user, rule.connection, rule.action, resource, groups, fresh=rule.fresh
        )
        if not d.allowed:
            return Deny(reason=str(PermissionDenied(d, user, rule.connection, rule.action, resource)))
        state.setdefault(_STATE_KEY, {})[event.tool_use.get("toolUseId")] = _Check(
            user, rule, resource, d, checked_at
        )
        return Proceed()

    def after_tool_call(self, event: AfterToolCallEvent, **kwargs: Any) -> Proceed:
        """Log that a checked tool ran, and that the check did not make it atomic."""
        checks = event.invocation_state.get(_STATE_KEY)
        c = checks.pop(event.tool_use.get("toolUseId"), None) if isinstance(checks, dict) else None
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
