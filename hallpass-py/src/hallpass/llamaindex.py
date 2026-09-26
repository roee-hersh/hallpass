"""hallpass for LlamaIndex: tools that ask hallpass before they run.

    pip install "hallpass[llamaindex]"

LlamaIndex agents (``FunctionAgent``, ``ReActAgent``, ``AgentWorkflow``)
have no hook that can stop a tool call, so the check sits in the tool: an
agent calls every tool through ``acall`` (or ``call``), and a wrapped tool
checks there before the real one runs. ``wrap`` does it for a list of tools
in one go:

    from hallpass import Hallpass
    from hallpass.llamaindex import HallpassAuthorization, Rule

    hallpass = HallpassAuthorization(Hallpass.from_config("hallpass.yaml"), {
        "delete_issue": Rule("jira-main", "DELETE_ISSUES", "issue:{key}", fresh=True),
        "read_issue": ("jira-main", "BROWSE_PROJECTS", "issue:{key}"),
    }, user=current_user)
    agent = FunctionAgent(tools=hallpass.wrap([delete_issue, read_issue]), llm=llm)

    current_user.set(user.email)  # from your auth, before agent.run
    await agent.run(prompt)

The user comes from ``user=``: a string, a zero-argument callable, or a
``ContextVar`` the application sets before ``agent.run`` (the workflow's
steps run in a copy of the caller's context). The model's input never
names the user. ``hallpass.guarded`` also works on the plain function
before ``FunctionTool.from_defaults``, for a per-tool check instead.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping, Sequence
from typing import Any

try:
    from llama_index.core.tools import BaseTool, FunctionTool, ToolOutput
    from llama_index.core.tools.types import AsyncBaseTool
except ImportError as e:  # pragma: no cover - exercised only without the extra
    raise ImportError('hallpass.llamaindex needs llama-index-core 0.12 or later: pip install "hallpass[llamaindex]"') from e

from hallpass._api import GroupsSource, Hallpass, UserSource, log
from hallpass._rules import Checked, Outcome, Rule, RuleLike, Rules, refusal

__all__ = ["HallpassAuthorization", "HallpassTool", "Rule"]


class HallpassAuthorization:
    """Rules for an agent's tools, and the user they are checked for.

    ``rules`` maps a tool name (``tool.metadata.name``, what the model
    calls) to a ``Rule`` or a ``(connection, action, resource)`` tuple. A
    tool without a rule runs unchecked, unless ``strict=True``; a rule of
    ``None`` names a tool that may run unchecked even then. Each resource
    field must be declared in the tool's schema as a plain ``str`` or
    ``int``, and the model's value must have exactly that JSON type (a
    ``FunctionTool`` passes it to the function unconverted).

    ``user`` (and ``groups``) are a value, a zero-argument callable or a
    ``ContextVar``; no user refuses the call.
    """

    def __init__(
        self,
        hp: Hallpass,
        rules: Mapping[str, RuleLike],
        *,
        user: UserSource,
        groups: GroupsSource | None = None,
        strict: bool = False,
    ) -> None:
        if user is None:
            raise TypeError("HallpassAuthorization needs user=: a string, a zero-argument callable or a ContextVar")
        self.rules = Rules(hp, rules, strict=strict)
        self.user = user
        self.groups = groups

    def wrap(self, tools: Sequence[BaseTool | Callable[..., Any]]) -> list[BaseTool]:
        """The tools to give the agent: each one that needs a check wrapped
        in a ``HallpassTool``, the rest as they are. Plain functions become
        ``FunctionTool``s first, as the agents would make them."""
        out: list[BaseTool] = []
        names: list[str] = []
        for t in tools:
            tool = t if isinstance(t, BaseTool) else FunctionTool.from_defaults(t)
            name = tool.metadata.get_name()
            names.append(name)
            needs_check = self.rules.entries.get(name) is not None or (self.rules.strict and name not in self.rules.entries)
            out.append(HallpassTool(tool, self) if needs_check else tool)
        missing = self.rules.missing(names)
        if missing:
            log.warning("hallpass rules name tools the agent does not have, so they check nothing: %s", ", ".join(sorted(missing)))
        return out

    def decide(self, name: str, tool_input: Mapping[str, Any], schema: Any) -> Outcome:
        """The check for one call, in the caller's thread."""
        if self.rules.entries.get(name) is None:
            return self.rules.decide(name, tool_input, user=None, resolve=False)
        return self.rules.decide(name, tool_input, user=self.user, groups=self.groups, schema=schema)

    async def adecide(self, name: str, tool_input: Mapping[str, Any], schema: Any) -> Outcome:
        """The check for one call, from async code (the lookup runs in a worker thread)."""
        if self.rules.entries.get(name) is None:
            return self.rules.decide(name, tool_input, user=None, resolve=False)
        return await self.rules.adecide(name, tool_input, user=self.user, groups=self.groups, schema=schema)


class HallpassTool(FunctionTool):
    """A tool that asks hallpass before ``tool`` runs.

    It has ``tool``'s name, description and schema, and takes the workflow
    ``Context`` when ``tool`` does. A refused call returns a ``ToolOutput``
    with ``is_error=True`` whose content is ``hallpass refused this call:
    <reason>``, so the model reads it, the tool never runs and the agent
    goes on (a ``return_direct`` tool does not end the run with it). Any
    error in the check refuses too. After a checked call ran, the
    ``unconditional write`` line is logged on the ``hallpass`` logger.
    """

    def __init__(self, tool: BaseTool, auth: HallpassAuthorization) -> None:
        super().__init__(fn=self._sync_entry, async_fn=self._async_entry, metadata=tool.metadata)
        self.tool = tool
        self.auth = auth
        # Let the agent hand over its Context exactly as it would to the tool.
        self.requires_context = bool(getattr(tool, "requires_context", False))
        self.ctx_param_name = getattr(tool, "ctx_param_name", None) if self.requires_context else None

    def _input(self, args: tuple[Any, ...], kwargs: dict[str, Any]) -> dict[str, Any]:
        if args:
            # Agents call tools with keyword arguments; a positional input cannot fill a resource.
            return {"__positional__": args}
        return {k: v for k, v in kwargs.items() if k != self.ctx_param_name}

    def _schema(self) -> Any:
        return self.metadata.get_parameters_dict()

    def _refused(self, outcome: Outcome, tool_input: dict[str, Any]) -> ToolOutput:
        text = refusal(outcome)
        return ToolOutput(content=text, tool_name=self.metadata.get_name(), raw_input={"kwargs": tool_input}, raw_output=text, is_error=True)

    def call(self, *args: Any, **kwargs: Any) -> ToolOutput:
        tool_input = self._input(args, kwargs)
        try:
            outcome = self.auth.decide(self.metadata.get_name(), tool_input, self._schema())
        except Exception as e:  # noqa: BLE001 - fail closed
            outcome = Outcome(False, f"the hallpass check failed: {type(e).__name__}: {e}")
        if not outcome.allowed:
            return self._refused(outcome, tool_input)
        try:
            out: ToolOutput = self.tool.call(*args, **kwargs) if isinstance(self.tool, AsyncBaseTool) else self.tool(*args, **kwargs)
        except BaseException as e:
            _log(outcome.checked, f"raised {type(e).__name__} from")
            raise
        _log(outcome.checked, "got an error result from" if getattr(out, "is_error", False) else "ran")
        return out

    async def acall(self, *args: Any, **kwargs: Any) -> ToolOutput:
        tool_input = self._input(args, kwargs)
        try:
            outcome = await self.auth.adecide(self.metadata.get_name(), tool_input, self._schema())
        except Exception as e:  # noqa: BLE001 - fail closed
            outcome = Outcome(False, f"the hallpass check failed: {type(e).__name__}: {e}")
        if not outcome.allowed:
            return self._refused(outcome, tool_input)
        try:
            if isinstance(self.tool, AsyncBaseTool):
                out: ToolOutput = await self.tool.acall(*args, **kwargs)
            else:  # a plain BaseTool: what LlamaIndex's async adapter does, with the arguments as given
                out = await asyncio.to_thread(self.tool, *args, **kwargs)
        except BaseException as e:
            _log(outcome.checked, f"raised {type(e).__name__} from")
            raise
        _log(outcome.checked, "got an error result from" if getattr(out, "is_error", False) else "ran")
        return out

    # FunctionTool's fn and async_fn (used by to_langchain_tool and the like) go through the check too.
    def _sync_entry(self, *args: Any, **kwargs: Any) -> Any:
        return self.call(*args, **kwargs).raw_output

    async def _async_entry(self, *args: Any, **kwargs: Any) -> Any:
        return (await self.acall(*args, **kwargs)).raw_output


def _log(checked: Checked | None, outcome: str) -> None:
    if checked is not None:
        checked.log(outcome)
