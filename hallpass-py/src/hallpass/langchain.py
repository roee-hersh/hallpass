"""hallpass as LangChain agent middleware, for ``create_agent`` and LangGraph.

    pip install "hallpass[langchain]"

Configured once on the agent, it checks every tool call that has a rule,
before the tool runs (``wrap_tool_call`` / ``awrap_tool_call``):

    from dataclasses import dataclass
    from langchain.agents import create_agent

    from hallpass import Hallpass
    from hallpass.langchain import HallpassMiddleware, Rule

    @dataclass
    class Context:
        user_id: str

    hallpass = HallpassMiddleware(Hallpass.from_config("hallpass.yaml"), {
        "delete_issue": Rule("jira-main", "DELETE_ISSUES", "issue:{key}", fresh=True),
    })
    agent = create_agent(model, tools=tools, middleware=[hallpass], context_schema=Context)
    agent.invoke({"messages": [...]}, context=Context(user_id=user.email))  # from your auth

The user comes from the run's runtime context (``context=``), which the
application passes and the model cannot write: the attribute or key named
``user_key`` (``"user_id"``). When the context has none, the ``user=``
source is used instead: a string, a zero-argument callable or a
``ContextVar`` the application sets for the session.

For a LangGraph graph you assemble yourself, ``hallpass.tool_node(tools)``
is a ``ToolNode`` with the same check. ``hallpass.guarded`` also works on a
plain function under ``@tool``, for a per-tool check instead.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping, Sequence
from typing import Any, Union

try:
    from langchain.agents.middleware import AgentMiddleware
    from langchain_core.messages import ToolMessage
    from langchain_core.tools import BaseTool
    from langgraph.prebuilt import ToolNode
    from langgraph.prebuilt.tool_node import ToolCallRequest
    from langgraph.types import Command
except ImportError as e:  # pragma: no cover - exercised only without the extra
    raise ImportError('hallpass.langchain needs langchain 1.0 or later and langgraph: pip install "hallpass[langchain]"') from e

from hallpass._api import GroupsSource, Hallpass, UserSource, current, log
from hallpass._rules import Checked, Outcome, Rule, RuleLike, Rules, refusal

__all__ = ["HallpassMiddleware", "Rule"]

_MISSING = object()

ToolResult = Union[ToolMessage, Command[Any]]


def _from_context(ctx: Any, key: str) -> Any:
    """``ctx[key]`` for a mapping (a TypedDict context), ``ctx.key`` otherwise
    (a dataclass or a pydantic model)."""
    if ctx is None:
        return _MISSING
    if isinstance(ctx, Mapping):
        return ctx.get(key, _MISSING)
    return getattr(ctx, key, _MISSING)


def _schema(tool: BaseTool) -> Any:
    """The JSON schema of the arguments the model saw for the tool."""
    s = tool.tool_call_schema
    if isinstance(s, Mapping):
        return s
    if hasattr(s, "model_json_schema"):
        return s.model_json_schema()
    return s.schema()  # a pydantic.v1 model


class HallpassMiddleware(AgentMiddleware):
    """Check each tool call with hallpass before it runs.

    ``rules`` maps a tool name to a ``Rule`` or a ``(connection, action,
    resource)`` tuple. A tool without a rule runs unchecked; with
    ``strict=True`` it is refused instead, and a rule of ``None`` names a
    tool that may run unchecked. A rule that names no tool the agent has is
    logged once as a warning, since it is usually a typo that leaves the real
    tool unchecked.

    The user is the runtime context's ``user_key``, or else ``user``; with
    ``groups_key`` or ``groups`` the groups the same way, as a list of
    strings. Neither set refuses the call. Any answer other than ``allow``
    refuses it: the tool does not run, and the model gets a ``ToolMessage``
    with ``status="error"`` naming the user, the action and hallpass's
    reason, so the run goes on. A resource the input cannot fill refuses,
    and so does any error inside the check.

    After a checked tool has run, the ``unconditional write`` line is logged
    on the ``hallpass`` logger, as ``guarded`` does.

    Middleware composes first-outermost: list this one last in
    ``middleware=``, so that no middleware rewrites the call after hallpass
    checked it.
    """

    def __init__(
        self,
        hp: Hallpass,
        rules: Mapping[str, RuleLike],
        *,
        user: UserSource | None = None,
        groups: GroupsSource | None = None,
        user_key: str = "user_id",
        groups_key: str | None = None,
        strict: bool = False,
    ) -> None:
        super().__init__()
        self.rules = Rules(hp, rules, strict=strict)
        self._user, self._groups = user, groups
        self._user_key, self._groups_key = user_key, groups_key
        self._warned: set[str] = set()

    @property
    def name(self) -> str:
        return "HallpassMiddleware"

    def tool_node(self, tools: Sequence[BaseTool | Callable[..., Any]], **kw: Any) -> ToolNode:
        """A LangGraph ``ToolNode`` for ``tools`` whose calls this checks."""
        return ToolNode(tools, wrap_tool_call=self.wrap_tool_call, awrap_tool_call=self.awrap_tool_call, **kw)

    # -- the check --

    def _sources(self, request: ToolCallRequest) -> tuple[Any, Any, str | None]:
        """The user and groups sources for this call, or a refusal reason."""
        ctx = getattr(request.runtime, "context", None)
        user = _from_context(ctx, self._user_key)
        if user is _MISSING:
            if self._user is None:
                return None, None, f"no user for this request: the runtime context has no {self._user_key!r}"
            user = self._user
        elif not isinstance(user, str):
            return None, None, f"no user for this request: the runtime context's {self._user_key!r} is not a string"
        groups: Any = None
        if self._groups_key is not None or self._groups is not None:
            groups = _MISSING if self._groups_key is None else _from_context(ctx, self._groups_key)
            if groups is _MISSING:
                try:
                    # Resolved here, so a source that yields nothing refuses rather than checking without groups.
                    groups = current(self._groups, "groups")
                except (RuntimeError, LookupError) as e:
                    return None, None, f"no groups for this request: {e}"
            if groups is None:
                return None, None, "no groups for this request: neither the runtime context nor groups= has them"
        return user, groups, None

    def _prepare(self, request: ToolCallRequest) -> tuple[Outcome | None, dict[str, Any]]:
        """A refusal before any check, or the decide arguments."""
        call = request.tool_call
        name = call["name"]
        tool = request.tool
        self._warn_missing(request)
        ruled = name in self.rules.entries
        if tool is not None and tool.name != name:
            # A middleware swapped the tool without renaming the call; neither name says what runs.
            if ruled or tool.name in self.rules.entries or self.rules.strict:
                return Outcome(False, f"tool call {name!r} was rerouted to {tool.name!r}"), {}
            return Outcome(True), {}
        if self.rules.entries.get(name) is None:
            return None, {"user": None}  # no rule: decide answers from strict alone
        if tool is None:
            return Outcome(False, f"the agent has no tool {name!r}"), {}
        user, groups, why = self._sources(request)
        if why is not None:
            return Outcome(False, why), {}
        return None, {"user": user, "groups": groups, "schema": _schema(tool)}

    def _warn_missing(self, request: ToolCallRequest) -> None:
        tools = getattr(request.runtime, "tools", None)
        if not tools:
            return
        missing = self.rules.missing(t.name for t in tools) - self._warned
        if missing:
            self._warned |= missing
            log.warning("hallpass rules name tools the agent does not have, so they check nothing: %s", ", ".join(sorted(missing)))

    @staticmethod
    def _refuse(request: ToolCallRequest, outcome: Outcome) -> ToolMessage:
        call = request.tool_call
        return ToolMessage(content=refusal(outcome), name=call["name"], tool_call_id=call["id"], status="error")

    @staticmethod
    def _outcome_of(result: Any) -> str:
        if isinstance(result, ToolMessage) and result.status == "error":
            return "got an error result from"
        return "ran"

    def wrap_tool_call(self, request: ToolCallRequest, handler: Callable[[ToolCallRequest], ToolResult]) -> ToolResult:
        """Ask hallpass whether the run's user may make this call; run it only on allow."""
        try:
            early, kw = self._prepare(request)
            outcome = early or self.rules.decide(request.tool_call["name"], request.tool_call.get("args"), **kw)
        except Exception as e:  # noqa: BLE001 - any failure in the check refuses
            outcome = Outcome(False, f"the hallpass check failed: {type(e).__name__}: {e}")
        if not outcome.allowed:
            return self._refuse(request, outcome)
        return self._run(outcome.checked, lambda: handler(request))

    async def awrap_tool_call(self, request: ToolCallRequest, handler: Callable[[ToolCallRequest], Awaitable[ToolResult]]) -> ToolResult:
        """The async form; the check runs in a worker thread."""
        try:
            early, kw = self._prepare(request)
            outcome = early or await self.rules.adecide(request.tool_call["name"], request.tool_call.get("args"), **kw)
        except Exception as e:  # noqa: BLE001 - any failure in the check refuses
            outcome = Outcome(False, f"the hallpass check failed: {type(e).__name__}: {e}")
        if not outcome.allowed:
            return self._refuse(request, outcome)
        c = outcome.checked
        try:
            result = await handler(request)
        except BaseException as e:
            if c is not None:
                c.log(f"raised {type(e).__name__} from")
            raise
        if c is not None:
            c.log(self._outcome_of(result))
        return result

    def _run(self, c: Checked | None, call: Callable[[], ToolResult]) -> ToolResult:
        try:
            result = call()
        except BaseException as e:
            if c is not None:
                c.log(f"raised {type(e).__name__} from")
            raise
        if c is not None:
            c.log(self._outcome_of(result))
        return result
