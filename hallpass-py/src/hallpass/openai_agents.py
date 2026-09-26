"""hallpass as OpenAI Agents SDK tool guardrails.

    pip install "hallpass[openai-agents]"

Tool input guardrails are the SDK's own hook in front of a function tool:
they run after the model asked for the call and before the body runs, and a
``reject_content`` answer sends text to the model in place of the tool's
result without ending the run. ``HallpassGuardrails`` puts one on every
function tool of an agent, configured once with the rules:

    from agents import Agent, Runner
    from hallpass import Hallpass
    from hallpass.openai_agents import HallpassGuardrails, Rule

    guard = HallpassGuardrails(Hallpass.from_config("hallpass.yaml"), {
        "delete_issue": Rule("jira-main", "DELETE_ISSUES", "issue:{key}", fresh=True),
        "get_issue": None,  # runs unchecked, even with strict=True
    })
    agent = guard.apply(Agent(name="ops", tools=[get_issue, delete_issue]))
    await Runner.run(agent, prompt, context=RequestContext(user_id=user.email))

The user comes from the run context, the object the application passes as
``Runner.run(..., context=...)``: its ``user_id`` attribute (or key, for a
mapping) by default, ``user_key`` to name another. The model cannot write
it. ``user=`` takes a fixed user, a zero-argument callable or a ContextVar
instead, as ``hallpass.guarded`` does.

After an allowed tool ran, a tool output guardrail logs the ``unconditional
write`` line on the ``hallpass`` logger. The SDK turns an exception in the
tool into an error text for the model before output guardrails run, so that
line says "ran" for it too; a tool whose exception fails the run is not
logged.

Only function tools have guardrails. Hosted tools, local shell and computer
tools and MCP servers cannot be checked: a rule naming one raises, and so
does ``strict=True`` on an agent that has one without a ``None`` rule.
Sub-agents reached by a handoff have their own tools: apply the guardrails
to each agent. ``hallpass.guarded`` also works on the plain function under
``@function_tool``.
"""

from __future__ import annotations

import copy
import json
import weakref
from collections.abc import Mapping, Sequence
from typing import Any

try:
    from agents import Agent, FunctionTool
    from agents.tool_context import ToolContext
    from agents.tool_guardrails import (
        ToolGuardrailFunctionOutput,
        ToolInputGuardrail,
        ToolInputGuardrailData,
        ToolOutputGuardrail,
        ToolOutputGuardrailData,
    )
except ImportError as e:  # pragma: no cover - depends on the environment
    raise ImportError('hallpass.openai_agents needs openai-agents 0.22 or later: pip install "hallpass[openai-agents]"') from e

from hallpass._api import Hallpass, log
from hallpass._rules import Checked, Outcome, Rule, RuleLike, Rules, refusal

__all__ = ["HallpassGuardrails", "Rule"]

_UNSET: Any = object()


def _from_context(context: Any, key: str) -> Any:
    """``context[key]`` for a mapping, ``context.key`` otherwise; None when absent."""
    if isinstance(context, Mapping):
        return context.get(key)
    return getattr(context, key, None)


class HallpassGuardrails:
    """Check each function tool call with hallpass before it runs.

    ``rules`` maps a tool name to a ``Rule``, a ``(connection, action,
    resource)`` tuple, or ``None``. A tool without a rule runs unchecked,
    unless ``strict=True``; ``None`` lets a tool run unchecked even then.

    The user is ``context.<user_key>`` (or ``context[user_key]``) of the run
    context, unless ``user`` is given; the groups likewise with
    ``groups_key`` or ``groups``. A missing user refuses the call.

    Any answer other than ``allow`` refuses: the model receives
    ``hallpass refused this call: ...`` as the tool's result, the body never
    runs, and the run goes on. An error inside the check refuses too.
    """

    def __init__(
        self,
        hp: Hallpass,
        rules: Mapping[str, RuleLike],
        *,
        user_key: str = "user_id",
        groups_key: str | None = None,
        user: Any = _UNSET,
        groups: Any = _UNSET,
        strict: bool = False,
    ) -> None:
        self.rules = Rules(hp, rules, strict=strict)
        self._user_key = user_key
        self._groups_key = groups_key
        self._user = user
        self._groups = groups
        self._checked: weakref.WeakKeyDictionary[ToolContext[Any], Checked] = weakref.WeakKeyDictionary()

    # -- configuration --

    def protect(self, tools: Sequence[Any]) -> list[Any]:
        """Copies of the function tools with hallpass's guardrails first in
        their input and output guardrails; other tools are returned as they
        are. Raises for a tool hallpass should check but cannot."""
        out: list[Any] = []
        for t in tools:
            name = getattr(t, "name", type(t).__name__)
            if isinstance(t, FunctionTool):
                g = copy.copy(t)
                g.tool_input_guardrails = [self._input_guardrail(g), *(t.tool_input_guardrails or [])]
                g.tool_output_guardrails = [self._output_guardrail(), *(t.tool_output_guardrails or [])]
                out.append(g)
                continue
            if name in self.rules.entries and self.rules.entries[name] is not None:
                raise TypeError(f"hallpass can check only function tools; {name!r} is a {type(t).__name__}")
            if self.rules.strict and name not in self.rules.entries:
                raise ValueError(f"strict: hallpass cannot check {name!r} ({type(t).__name__}); give it a rule of None to allow it unchecked")
            out.append(t)
        return out

    def apply(self, agent: Agent[Any]) -> Agent[Any]:
        """A clone of the agent whose function tools carry the guardrails.
        Warns about rules that name no tool of the agent."""
        if self.rules.strict and agent.mcp_servers:
            raise ValueError("strict: hallpass cannot check the tools of MCP servers; list them as function tools instead")
        tools = self.protect(agent.tools)
        missing = self.rules.missing(getattr(t, "name", "") for t in agent.tools)
        if missing:
            log.warning("hallpass rules name tools the agent does not have, so they check nothing: %s", ", ".join(sorted(missing)))
        return agent.clone(tools=tools)

    # -- the guardrails --

    def _who(self, context: Any) -> tuple[Any, Any]:
        """The user and groups sources for this run."""
        user = self._user if self._user is not _UNSET else _from_context(context, self._user_key)
        if self._groups is not _UNSET:
            groups = self._groups
        elif self._groups_key is not None:
            groups = _from_context(context, self._groups_key)
            if groups is None:
                raise LookupError(f"the run context has no {self._groups_key!r}")
        else:
            groups = None
        return user, groups

    async def _decide(self, tool: FunctionTool, ctx: ToolContext[Any]) -> Outcome:
        name = tool.name
        if name not in self.rules.entries or self.rules.entries[name] is None:
            return self.rules.decide(name, {}, user=None)  # unchecked, or refused under strict
        try:
            user, groups = self._who(ctx.context)
        except LookupError as e:
            return Outcome(False, f"no groups for this request: {e}")
        if user is None:
            return Outcome(False, f"no user for this request: the run context has no {self._user_key!r}")
        raw = ctx.tool_arguments
        try:
            args = json.loads(raw) if raw and raw.strip() else {}
        except ValueError:
            return Outcome(False, f"the arguments for {name} are not JSON")
        return await self.rules.adecide(name, args, user=user, groups=groups, schema=tool.params_json_schema)

    def _input_guardrail(self, tool: FunctionTool) -> ToolInputGuardrail[Any]:
        async def hallpass_check(data: ToolInputGuardrailData) -> ToolGuardrailFunctionOutput:
            try:
                outcome = await self._decide(tool, data.context)
            except Exception as e:  # noqa: BLE001 - fail closed, and keep the run going
                outcome = Outcome(False, f"the check failed: {type(e).__name__}: {e}")
            if not outcome.allowed:
                return ToolGuardrailFunctionOutput.reject_content(refusal(outcome), output_info=outcome.reason)
            if outcome.checked is not None:
                self._checked[data.context] = outcome.checked
            return ToolGuardrailFunctionOutput.allow()

        return ToolInputGuardrail(guardrail_function=hallpass_check, name="hallpass")

    def _output_guardrail(self) -> ToolOutputGuardrail[Any]:
        def hallpass_log(data: ToolOutputGuardrailData) -> ToolGuardrailFunctionOutput:
            checked = self._checked.pop(data.context, None)
            if checked is not None:
                checked.log("ran")
            return ToolGuardrailFunctionOutput.allow()

        return ToolOutputGuardrail(guardrail_function=hallpass_log, name="hallpass-log")
