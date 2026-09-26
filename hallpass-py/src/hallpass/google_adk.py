"""hallpass as Google ADK tool callbacks.

    pip install "hallpass[google-adk]"

An ``LlmAgent``'s ``before_tool_callback`` is ADK's own check in front of
every tool call: a dict it returns becomes the tool's response, the tool
does not run, and the model reads the dict. ``HallpassCallbacks`` is that
callback, configured once with the rules, plus an ``after_tool_callback`` and
an ``on_tool_error_callback`` that log the write after an allowed tool ran:

    from google.adk.agents import LlmAgent
    from google.adk.runners import InMemoryRunner
    from hallpass import Hallpass
    from hallpass.google_adk import HallpassCallbacks, Rule

    hallpass = HallpassCallbacks(Hallpass.from_config("hallpass.yaml"), {
        "delete_issue": Rule("jira-main", "DELETE_ISSUES", "issue:{key}", fresh=True),
    })
    agent = hallpass.apply(LlmAgent(name="ops", model=..., tools=[get_issue, delete_issue]))
    runner = InMemoryRunner(agent=agent)
    session = await runner.session_service.create_session(app_name=runner.app_name, user_id=user.email)
    async for event in runner.run_async(user_id=user.email, session_id=session.id, new_message=...): ...

The user is the session's ``user_id``, which the application passes to the
runner and the model cannot write (``tool_context.user_id``). ``user=`` takes
a fixed user, a zero-argument callable or a ContextVar instead; ``groups=``
the groups likewise. Session state is not used: tools can write it.

A refused call answers ``{"error": "hallpass refused this call: ..."}`` in
place of the tool's result. ``apply`` puts the check last among the agent's
before-tool callbacks, so a callback that edits the arguments cannot do so
after hallpass checked them, and the logging first among the after-tool and
error callbacks, which the chain would otherwise skip. It applies to the
agent's LLM sub-agents too. ``plugin()`` is the same check as an ``App`` plugin,
for every agent at once; plugins run before an agent's own callbacks, so do
not combine it with agent callbacks that edit tool arguments.

The resource is filled from the tool's declared JSON schema, so a value ADK
would convert before the call ("01" for an int parameter) is refused rather
than checked as something else. ``hallpass.guarded`` also works on the plain
function an ADK ``FunctionTool`` wraps.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

try:
    from google.adk.agents import BaseAgent, LlmAgent
    from google.adk.plugins import BasePlugin
    from google.adk.tools import BaseTool, ToolContext
    from google.adk.tools.base_toolset import BaseToolset
except ImportError as e:  # pragma: no cover - depends on the environment
    raise ImportError('hallpass.google_adk needs google-adk 2.10 or later: pip install "hallpass[google-adk]"') from e

from hallpass._api import log
from hallpass._rules import Checked, Outcome, Rule, RuleLike, Rules, refusal

__all__ = ["HallpassCallbacks", "HallpassPlugin", "Rule"]

_SESSION_USER: Any = object()
_PENDING_MAX = 1024


def _json_schema(tool: BaseTool) -> Mapping[str, Any] | None:
    """The JSON schema of the tool's parameters, as the model saw it; None
    when the tool has no declaration to read one from."""
    decl = tool._get_declaration()
    if decl is None:
        return None
    js = getattr(decl, "parameters_json_schema", None)
    if isinstance(js, Mapping):
        return js
    params = getattr(decl, "parameters", None)
    props: dict[str, Any] = {}
    for name, s in ((params.properties or {}) if params is not None else {}).items():
        p: dict[str, Any] = {}
        if s.type is not None and not s.any_of:  # a union has no plain type, so it is refused
            p["type"] = str(getattr(s.type, "value", s.type)).lower()
        if s.format:
            p["format"] = s.format
        if s.default is not None:
            p["default"] = s.default
        props[name] = p
    return {"properties": props}


class HallpassCallbacks:
    """Check each tool call with hallpass before ADK runs it.

    ``rules`` maps a tool name to a ``Rule``, a ``(connection, action,
    resource)`` tuple, or ``None``. A tool without a rule runs unchecked,
    unless ``strict=True``; ``None`` lets a tool run unchecked even then.

    Any answer other than ``allow`` refuses; so does a missing user and any
    error inside the check. The run goes on and the model reads the reason.
    """

    def __init__(
        self,
        hp: Any,
        rules: Mapping[str, RuleLike],
        *,
        user: Any = _SESSION_USER,
        groups: Any = None,
        strict: bool = False,
    ) -> None:
        self.rules = Rules(hp, rules, strict=strict)
        self._user = user
        self._groups = groups
        self._pending: dict[tuple[str, str], Checked] = {}

    # -- configuration --

    def apply(self, agent: BaseAgent) -> BaseAgent:
        """Add the callbacks to the agent and its LLM sub-agents, in place.
        Warns about rules that name no tool of theirs."""
        names: set[str] = set()
        toolsets = False
        for a in self._llm_agents(agent):
            a.before_tool_callback = [*_as_list(a.before_tool_callback), self.before_tool]
            a.after_tool_callback = [self.after_tool, *_as_list(a.after_tool_callback)]
            a.on_tool_error_callback = [self.on_tool_error, *_as_list(a.on_tool_error_callback)]
            for t in a.tools:
                if isinstance(t, BaseToolset):
                    toolsets = True
                elif isinstance(t, BaseTool):
                    names.add(t.name)
                else:
                    names.add(getattr(t, "__name__", ""))
        missing = self.rules.missing(names)
        if missing and not toolsets:
            log.warning("hallpass rules name tools the agent does not have, so they check nothing: %s", ", ".join(sorted(missing)))
        return agent

    @staticmethod
    def _llm_agents(agent: BaseAgent) -> list[LlmAgent]:
        out: list[LlmAgent] = []
        todo = [agent]
        while todo:
            a = todo.pop()
            if isinstance(a, LlmAgent):
                out.append(a)
            todo.extend(a.sub_agents)
        return out

    def plugin(self, name: str = "hallpass") -> HallpassPlugin:
        """The same check as a plugin, for every agent of an ``App``."""
        return HallpassPlugin(self, name)

    # -- the callbacks --

    def _key(self, tool_context: ToolContext) -> tuple[str, str] | None:
        call_id = tool_context.function_call_id
        return (tool_context.invocation_id, call_id) if call_id else None

    async def _decide(self, tool: BaseTool, args: Any, tool_context: ToolContext) -> Outcome:
        name = tool.name
        entry = self.rules.entries.get(name)
        if entry is None:  # no rule, or a rule of None: no user needed
            return self.rules.decide(name, args, user=None)
        user = tool_context.user_id if self._user is _SESSION_USER else self._user
        return await self.rules.adecide(name, args, user=user, groups=self._groups, schema=_json_schema(tool))

    async def before_tool(self, tool: BaseTool, args: dict[str, Any], tool_context: ToolContext) -> dict[str, Any] | None:
        """Answer the call with the refusal unless hallpass allowed it."""
        try:
            outcome = await self._decide(tool, args, tool_context)
        except Exception as e:  # fail closed, and keep the run going
            outcome = Outcome(False, f"the check failed: {type(e).__name__}: {e}")
        if not outcome.allowed:
            return {"error": refusal(outcome)}
        key = self._key(tool_context)
        if outcome.checked is not None and key is not None:
            self._pending[key] = outcome.checked
            while len(self._pending) > _PENDING_MAX:
                self._pending.pop(next(iter(self._pending)))
        return None

    def _log(self, tool_context: ToolContext, outcome: str) -> None:
        key = self._key(tool_context)
        checked = self._pending.pop(key, None) if key is not None else None
        if checked is not None:
            checked.log(outcome)

    async def after_tool(self, tool: BaseTool, args: dict[str, Any], tool_context: ToolContext, tool_response: Any) -> dict[str, Any] | None:
        """Log that a checked tool ran; the result is left as it is."""
        self._log(tool_context, "ran")
        return None

    async def on_tool_error(self, tool: BaseTool, args: dict[str, Any], tool_context: ToolContext, error: Exception) -> dict[str, Any] | None:
        """Log that a checked tool raised; the error is left to ADK."""
        self._log(tool_context, f"raised {type(error).__name__} from")
        return None


class HallpassPlugin(BasePlugin):
    """``HallpassCallbacks`` as a plugin: ``App(..., plugins=[hallpass.plugin()])``.

    Plugin callbacks run before an agent's own. An agent callback that edits
    the arguments does so after hallpass checked them, and one that answers
    a call hallpass allowed still gets the call logged as having run; use
    ``HallpassCallbacks.apply`` on such agents instead."""

    def __init__(self, callbacks: HallpassCallbacks, name: str = "hallpass") -> None:
        super().__init__(name=name)
        self.callbacks = callbacks

    async def before_tool_callback(self, *, tool: BaseTool, tool_args: dict[str, Any], tool_context: ToolContext) -> dict[str, Any] | None:
        return await self.callbacks.before_tool(tool, tool_args, tool_context)

    async def after_tool_callback(
        self, *, tool: BaseTool, tool_args: dict[str, Any], tool_context: ToolContext, result: dict[str, Any]
    ) -> dict[str, Any] | None:
        return await self.callbacks.after_tool(tool, tool_args, tool_context, result)

    async def on_tool_error_callback(self, *, tool: BaseTool, tool_args: dict[str, Any], tool_context: ToolContext, error: Exception) -> dict[str, Any] | None:
        return await self.callbacks.on_tool_error(tool, tool_args, tool_context, error)


def _as_list(cb: Any) -> list[Any]:
    if cb is None:
        return []
    return list(cb) if isinstance(cb, list) else [cb]
