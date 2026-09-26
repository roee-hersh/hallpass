"""hallpass as CrewAI tool-call hooks.

    pip install "hallpass[crewai]"

CrewAI runs its ``before_tool_call`` hooks before every tool call an agent
makes (native function calling and the text ReAct loop alike) and its
``after_tool_call`` hooks after it. ``HallpassHooks`` is one pair of them:

    from hallpass import Hallpass
    from hallpass.crewai import HallpassHooks, Rule

    hallpass = HallpassHooks(Hallpass.from_config("hallpass.yaml"), {
        "delete_issue": Rule("jira-main", "DELETE_ISSUES", "issue:{key}", fresh=True),
        "read_issue": ("jira-main", "BROWSE_PROJECTS", "issue:{key}"),
    }).register()
    crew.kickoff(inputs={"user_id": user.email, "topic": topic})  # user_id from your auth

The user comes from the crew's kickoff ``inputs`` (``user_id`` by default,
see ``user_input``), which the application passes and the model cannot
write, or from ``user=``: a string, a zero-argument callable or a
``ContextVar`` the application sets (CrewAI copies context variables into
the threads it runs tools in). Use ``user=`` for an ``Agent.kickoff``
without a crew.

CrewAI hooks are process-wide: once registered, the rules apply to every
crew and agent in the process, until ``unregister()`` (or use the object
as a context manager). ``hallpass.guarded`` also works on the plain
function under CrewAI's ``@tool``, for a per-tool check instead.
"""

from __future__ import annotations

import threading
from collections.abc import Mapping
from typing import Any

try:
    from crewai.hooks import register_after_tool_call_hook, register_before_tool_call_hook, unregister_after_tool_call_hook, unregister_before_tool_call_hook
    from crewai.hooks.tool_hooks import ToolCallHookContext
    from crewai.utilities.string_utils import sanitize_tool_name
except ImportError as e:  # pragma: no cover - exercised only without the extra
    raise ImportError('hallpass.crewai needs crewai 1.10 or later: pip install "hallpass[crewai]"') from e

from hallpass._api import GroupsSource, Hallpass, UserSource
from hallpass._rules import Outcome, Rule, RuleLike, Rules, refusal

__all__ = ["HallpassHooks", "Rule"]

# What CrewAI puts in place of the result of a call a before hook blocked.
_BLOCKED = "Tool execution blocked by hook. Tool: "


class HallpassHooks:
    """Check each CrewAI tool call with hallpass before it runs.

    ``rules`` maps a tool name to a ``Rule`` or a ``(connection, action,
    resource)`` tuple. Names are matched the way CrewAI names tools to the
    model (``"Read Thing"`` and ``read_thing`` are the same tool). A tool
    without a rule runs unchecked, unless ``strict=True``; a rule of
    ``None`` names a tool that may run unchecked even then (CrewAI's own
    delegation tools need one under ``strict``).

    The resource is filled from the model's input, and each field must be
    declared by the tool's ``args_schema`` as a plain ``str`` or ``int``
    with exactly that JSON type, since CrewAI converts ``"01"`` to ``1``
    before the tool runs.

    The user is ``user`` when given, otherwise the crew's kickoff input
    ``user_input``; groups likewise from ``groups`` or the input
    ``groups_input``. No user refuses the call.

    A refused call does not run; the model reads ``hallpass refused this
    call: <reason>`` as the tool's result, and the run goes on. Any error in
    the check refuses too (CrewAI would otherwise ignore a failing hook and
    run the tool). After an allowed tool ran, the ``unconditional write``
    line is logged on the ``hallpass`` logger.

    Register it after any hook that rewrites ``tool_input``: a hook that
    runs after this one changes what runs after hallpass checked it. The
    hook is synchronous, as CrewAI's are, so an async crew waits for the
    check on its event loop.
    """

    def __init__(
        self,
        hp: Hallpass,
        rules: Mapping[str, RuleLike],
        *,
        user: UserSource | None = None,
        groups: GroupsSource | None = None,
        user_input: str = "user_id",
        groups_input: str | None = None,
        strict: bool = False,
    ) -> None:
        named: dict[str, RuleLike] = {}
        for name, rule in rules.items():
            key = sanitize_tool_name(name)
            if key in named:
                raise ValueError(f"rules for {name!r} and another tool both name the CrewAI tool {key!r}")
            named[key] = rule
        self.rules = Rules(hp, named, strict=strict)
        self.user = user
        self.groups = groups
        self.user_input = user_input
        self.groups_input = groups_input
        self._lock = threading.Lock()
        # Calls between the before and the after hook, keyed by the identity
        # of the tool_input dict CrewAI hands to both (kept alive here).
        self._pending: dict[int, tuple[dict[str, Any], Outcome]] = {}
        # CrewAI hands the after hook a fresh {} for a call without input.
        self._pending_empty = threading.local()
        self._registered = False

    # -- registration -----------------------------------------------------

    def register(self) -> HallpassHooks:
        """Register the before and after hooks with CrewAI (process-wide)."""
        if not self._registered:
            register_before_tool_call_hook(self.before_tool_call)
            register_after_tool_call_hook(self.after_tool_call)
            self._registered = True
        return self

    def unregister(self) -> None:
        """Remove the hooks again."""
        unregister_before_tool_call_hook(self.before_tool_call)
        unregister_after_tool_call_hook(self.after_tool_call)
        self._registered = False

    def __enter__(self) -> HallpassHooks:
        return self.register()

    def __exit__(self, *exc: object) -> None:
        self.unregister()

    # -- the hooks --------------------------------------------------------

    def before_tool_call(self, context: ToolCallHookContext) -> bool | None:
        """Return False (block) unless hallpass allowed this call."""
        try:
            outcome = self._decide(context)
        except Exception as e:  # noqa: BLE001 - fail closed: CrewAI ignores a hook that raises and runs the tool
            outcome = Outcome(False, f"the hallpass check failed: {type(e).__name__}: {e}")
        if outcome.allowed and outcome.checked is None:
            return None  # unchecked: nothing to log afterwards
        tool_input = context.tool_input
        with self._lock:
            self._pending[id(tool_input)] = (tool_input, outcome)
        if not tool_input:
            self._pending_empty.entry = (context.tool_name, outcome)
        return None if outcome.allowed else False

    def after_tool_call(self, context: ToolCallHookContext) -> str | None:
        """Give the model the reason for a refusal; log a checked call that ran."""
        with self._lock:
            entry = self._pending.pop(id(context.tool_input), None)
        outcome = entry[1] if entry is not None and entry[0] is context.tool_input else None
        if outcome is None and not context.tool_input:
            empty = getattr(self._pending_empty, "entry", None)
            self._pending_empty.entry = None
            if empty is not None and empty[0] == context.tool_name:
                outcome = empty[1]
        if outcome is None:
            return None
        result = context.tool_result if isinstance(context.tool_result, str) else ""
        if not outcome.allowed:
            return refusal(outcome) if result.startswith(_BLOCKED) else None
        if outcome.checked is None or result.startswith(_BLOCKED):
            return None  # another hook blocked it after hallpass allowed it
        if result.startswith("Error executing tool:"):
            outcome.checked.log("raised an error from")
        elif " has reached its usage limit " in result or "has reached its maximum usage limit" in result:
            pass  # CrewAI did not run it
        else:
            outcome.checked.log("ran")
        return None

    def _decide(self, context: ToolCallHookContext) -> Outcome:
        name = context.tool_name
        if self.rules.entries.get(name) is None:
            return self.rules.decide(name, context.tool_input, user=None, resolve=False)
        inputs = getattr(context.crew, "_inputs", None) if context.crew is not None else None
        inputs = inputs if isinstance(inputs, Mapping) else {}
        user = self.user if self.user is not None else inputs.get(self.user_input)
        if user is None:
            where = "user=" if self.user is not None else f"the crew's kickoff input {self.user_input!r}"
            return Outcome(False, f"no user for this request: {where} is not set")
        groups = self.groups
        if groups is None and self.groups_input is not None:
            groups = inputs.get(self.groups_input)
            if groups is None:
                return Outcome(False, f"no groups for this request: the crew's kickoff input {self.groups_input!r} is not set")
        return self.rules.decide(name, context.tool_input, user=user, groups=groups, schema=_schema(context))


def _schema(context: ToolCallHookContext) -> dict[str, Any]:
    """The JSON schema of the tool's input, as CrewAI validates it; empty
    (so no resource field can be filled) when the tool cannot be found."""
    tools = [context.tool] if context.tool is not None else []
    tools += [t for t in getattr(context.agent, "tools", None) or [] if sanitize_tool_name(getattr(t, "name", "")) == context.tool_name]
    for t in tools:
        args_schema = getattr(t, "args_schema", None)
        if args_schema is not None and hasattr(args_schema, "model_json_schema"):
            schema = args_schema.model_json_schema()
            return schema if isinstance(schema, dict) else {}
    return {}
