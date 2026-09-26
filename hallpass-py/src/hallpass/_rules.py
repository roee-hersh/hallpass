"""What every framework adapter shares: the rule for a tool, filling its
resource from the tool's input, and the one decision flow.

A framework hook (Strands interventions, LangChain middleware, OpenAI
Agents guardrails, Claude Agent SDK hooks, ADK callbacks, ...) sees a tool
name and the input the model sent. ``Rules.decide`` turns that into allow
or a refusal the model can read, the same way for every framework:

- a tool with no rule runs unchecked, unless ``strict``; a rule of ``None``
  names a tool that may run unchecked even under ``strict``;
- the user (and groups) come from the application, never from the input;
- the resource is filled only from input fields the tool declares as a
  plain string or integer, with the exact JSON type, since frameworks
  coerce ("01", 1.0 and true all become the integer 1) and the resource
  checked must be the one the tool acts on;
- anything other than ``allow`` refuses, with the user, the action and
  hallpass's reason in the text.
"""

from __future__ import annotations

import asyncio
import datetime
import string
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Union

from hallpass._api import Decision, Hallpass, PermissionDenied, _group_list, _log_write, current

__all__ = ["Checked", "Outcome", "Rule", "RuleLike", "Rules", "refusal"]

# The JSON Schema types a resource field may have, and the one Python type
# the model's value must have for each.
_FIELD_TYPES: dict[str, type] = {"string": str, "integer": int}


@dataclass(frozen=True)
class Rule:
    """What to ask hallpass before one tool runs.

    ``resource`` is a format string over the tool's input, e.g.
    ``"issue:{key}"``. Each field must be a plain input name, and the tool
    must declare that input as a plain ``str`` or ``int`` parameter.
    ``fresh=True`` makes the check skip hallpass's caches; use it for
    destructive tools.
    """

    connection: str
    action: str
    resource: str
    fresh: bool = False


RuleLike = Union[Rule, tuple[str, str, str], tuple[str, str, str, bool], None]


@dataclass(frozen=True)
class Checked:
    """A call hallpass allowed, kept until the tool has run so the write
    can be logged against the check."""

    user: str
    rule: Rule
    resource: str
    decision: Decision
    checked_at: datetime.datetime

    def log(self, outcome: str) -> None:
        """Log that the tool ran (or failed) after the check."""
        _log_write(self.user, outcome, self.rule.connection, self.rule.action, self.resource, self.decision, self.checked_at, self.rule.fresh)


@dataclass(frozen=True)
class Outcome:
    """The answer for one tool call: allowed, or refused with a reason the
    model may read. ``checked`` is set when hallpass was asked and allowed."""

    allowed: bool
    reason: str = ""
    checked: Checked | None = None


def _as_rule(tool: str, r: Any) -> tuple[Rule, tuple[str, ...]] | None:
    """The rule and the input fields its resource uses."""
    if r is None:
        return None
    if isinstance(r, tuple) and len(r) in (3, 4):
        r = Rule(*r)
    if not isinstance(r, Rule) or not all(isinstance(v, str) and v for v in (r.connection, r.action, r.resource)):
        raise TypeError(f"rule for tool {tool!r} must be a Rule or a (connection, action, resource) tuple of strings")
    fields = []
    for _, field, spec, conv in string.Formatter().parse(r.resource):
        if field is None:
            continue
        if not field.isidentifier() or spec or conv:
            raise ValueError(f"resource {r.resource!r} for tool {tool!r}: {{{field}}} must name one input field")
        fields.append(field)
    return r, tuple(fields)


def _fill(template: str, fields: tuple[str, ...], tool_input: Any, schema: Any) -> str:
    """Fill the template from the tool's input; ValueError when it cannot.

    With a JSON schema (what the model saw), each field must be declared as
    a string or an integer without a format, and the value must have exactly
    that JSON type; a field the model left out takes the schema's default.
    Without one (a framework that hands over the bound Python arguments),
    each value must be a str or an int (not a bool)."""
    if not isinstance(tool_input, Mapping):
        raise ValueError("the input is not an object")
    values: dict[str, Any] = {}
    if schema is None:
        for field in fields:
            if field not in tool_input:
                raise ValueError(f"the input has no {field!r}")
            value = tool_input[field]
            if type(value) not in (str, int):
                raise ValueError(f"{field!r} must be a string or an integer, not {type(value).__name__}")
            values[field] = value
        return template.format_map(values)
    props = schema.get("properties") if isinstance(schema, Mapping) else None
    for field in fields:
        prop = props.get(field) if isinstance(props, Mapping) else None
        want = _FIELD_TYPES.get(prop.get("type")) if isinstance(prop, Mapping) else None  # type: ignore[arg-type]
        if want is None or not isinstance(prop, Mapping) or "format" in prop:
            raise ValueError(f"the tool does not declare {field!r} as a string or an integer")
        if field in tool_input:
            value = tool_input[field]
        elif "default" in prop:
            value = prop["default"]  # what the tool runs with when the model leaves it out
        else:
            raise ValueError(f"the input has no {field!r}")
        if type(value) is not want:  # not isinstance: a bool is an int, and frameworks convert it
            raise ValueError(f"{field!r} must be a JSON {prop['type']}, not {type(value).__name__}")
        values[field] = value
    return template.format_map(values)


UserSource = Any  # str, a zero-argument callable, or a ContextVar (see hallpass.current)


class Rules:
    """Rules for a set of tools, and the decision flow every adapter uses."""

    def __init__(self, hp: Hallpass, rules: Mapping[str, RuleLike], *, strict: bool = False) -> None:
        if not isinstance(hp, Hallpass):
            raise TypeError("hp must be a hallpass.Hallpass")
        self.hp = hp
        self.strict = strict
        self.entries = {tool: _as_rule(tool, r) for tool, r in rules.items()}

    def names(self) -> set[str]:
        return set(self.entries)

    def missing(self, tool_names: Any) -> set[str]:
        """Rules that name no tool the agent has: usually a typo that leaves
        the real tool unchecked."""
        return set(self.entries) - set(tool_names)

    def decide(
        self,
        tool: str,
        tool_input: Any,
        *,
        user: Any,
        groups: Any = None,
        schema: Any = None,
        resolve: bool = True,
    ) -> Outcome:
        """Allow or refuse one call. ``user`` and ``groups`` are values, or
        with ``resolve`` sources for ``hallpass.current`` (a callable or a
        ContextVar). Never raises for a refusal; an adapter whose framework
        can surface errors should still treat any exception as a refusal."""
        if tool not in self.entries:
            return Outcome(False, f"no hallpass rule for tool {tool!r}") if self.strict else Outcome(True)
        entry = self.entries[tool]
        if entry is None:
            return Outcome(True)
        rule, fields = entry
        try:
            who = current(user, "user") if resolve else user
        except (RuntimeError, LookupError) as e:
            return Outcome(False, f"no user for this request: {e}")
        if not isinstance(who, str) or not who:
            return Outcome(False, "no user for this request")
        grp = None
        if groups is not None:
            try:
                grp = _group_list(current(groups, "groups") if resolve else groups)
            except (RuntimeError, LookupError, TypeError) as e:
                return Outcome(False, f"no groups for this request: {e}")
        try:
            resource = _fill(rule.resource, fields, tool_input, schema)
        except ValueError as e:
            return Outcome(False, f"cannot build the resource {rule.resource!r} for {tool}: {e}")
        checked_at = datetime.datetime.now(datetime.timezone.utc)
        d = self.hp.check(who, rule.connection, rule.action, resource, grp, fresh=rule.fresh)
        if not d.allowed:
            return Outcome(False, str(PermissionDenied(d, who, rule.connection, rule.action, resource)))
        return Outcome(True, "", Checked(who, rule, resource, d, checked_at))

    async def adecide(self, tool: str, tool_input: Any, **kw: Any) -> Outcome:
        """decide in a worker thread, for async hooks. The user and groups
        are resolved here, in the caller's context, before the thread."""
        user, groups = kw.pop("user"), kw.pop("groups", None)
        try:
            user = current(user, "user")
        except (RuntimeError, LookupError) as e:
            return Outcome(False, f"no user for this request: {e}")
        if groups is not None:
            # Resolved here, validated here: a groups source that yields
            # nothing refuses, as decide does, rather than checking without
            # groups (decide reads groups=None as "none were asked for").
            try:
                groups = _group_list(current(groups, "groups"))
            except (RuntimeError, LookupError, TypeError) as e:
                return Outcome(False, f"no groups for this request: {e}")
        return await asyncio.to_thread(self.decide, tool, tool_input, user=user, groups=groups, resolve=False, **kw)


def refusal(outcome: Outcome) -> str:
    """The text an adapter returns to the model for a refused call."""
    return f"hallpass refused this call: {outcome.reason}"
