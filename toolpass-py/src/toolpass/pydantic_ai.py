"""toolpass for Pydantic AI: a toolset wrapper, and a capability that puts
it around every tool an agent has.

    pip install "toolpass[pydantic-ai]"

Configured once on the agent, it checks every tool call that has a rule,
after Pydantic AI validated the arguments and before the tool runs:

    from dataclasses import dataclass

    from toolpass import Toolpass
    from toolpass.pydantic_ai import ToolpassAuthorization, Rule

    @dataclass
    class Deps:
        user: str  # from your auth, never from the model

    toolpass = ToolpassAuthorization(Toolpass.from_config("toolpass.yaml"), {
        "delete_issue": Rule("jira-main", "DELETE_ISSUES", "issue:{key}", fresh=True),
        "read_issue": ("jira-main", "BROWSE_PROJECTS", "issue:{key}"),
    })
    agent = Agent(model, deps_type=Deps, tools=[delete_issue, read_issue], capabilities=[toolpass])
    agent.run_sync(prompt, deps=Deps(user=user.email))

The user comes from ``RunContext.deps``, which the application passes to
``run`` and the model cannot write: the ``user`` attribute (or key, for a
mapping), and ``groups`` when the deps have one. ``user=`` and ``groups=``
take a string, a zero-argument callable or a ``ContextVar`` instead.

``ToolpassToolset`` is the same check around one toolset, for an agent
that should check only some of its tools:

    agent = Agent(model, toolsets=[ToolpassToolset(FunctionToolset([delete_issue]), tp, rules)])

A refusal reaches the model as a failed tool result (``ToolFailed``) with
toolpass's reason; the tool does not run and the run goes on.
``toolpass.guarded`` also works on a plain function tool, for a per-tool
check with a user source of its own.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

try:
    from pydantic_ai import RunContext
    from pydantic_ai.capabilities import AbstractCapability
    from pydantic_ai.exceptions import ApprovalRequired, CallDeferred, ToolFailed
    from pydantic_ai.toolsets import AbstractToolset, WrapperToolset
    from pydantic_ai.toolsets.abstract import ToolsetTool
except ImportError as e:  # pragma: no cover - exercised only without the extra
    raise ImportError('toolpass.pydantic_ai needs pydantic-ai-slim 2.51 or later: pip install "toolpass[pydantic-ai]"') from e

from toolpass._api import GroupsSource, Toolpass, UserSource, log
from toolpass._rules import Outcome, Rule, RuleLike, Rules, refusal

__all__ = ["Rule", "ToolpassAuthorization", "ToolpassToolset"]


def _from_deps(deps: Any, key: str) -> Any:
    """``deps.<key>``, or ``deps[<key>]`` for a mapping; None when absent."""
    if isinstance(deps, Mapping):
        return deps.get(key)
    return getattr(deps, key, None)


class _Policy:
    """The rules and user sources one agent's toolsets share across runs."""

    def __init__(self, tp: Toolpass, rules: Mapping[str, RuleLike], user: UserSource | None, groups: GroupsSource | None, strict: bool) -> None:
        self.rules = Rules(tp, rules, strict=strict)
        self.user = user
        self.groups = groups
        self.warned: set[str] = set()

    def warn_missing(self, tool_names: Any) -> None:
        missing = self.rules.missing(tool_names) - self.warned
        if missing:
            self.warned |= missing
            log.warning("toolpass rules name tools the agent does not have, so they check nothing: %s", ", ".join(sorted(missing)))

    async def decide(self, name: str, args: Any, ctx: RunContext[Any], schema: Any) -> Outcome:
        if self.rules.entries.get(name) is None:
            # No rule (or a rule of None): no user is needed, and none is resolved.
            return self.rules.decide(name, args, user=None, resolve=False)
        user = self.user if self.user is not None else _from_deps(ctx.deps, "user")
        groups = self.groups if self.groups is not None else _from_deps(ctx.deps, "groups")
        if user is None:
            return Outcome(False, "no user for this request: RunContext.deps has no user")
        return await self.rules.adecide(name, args, user=user, groups=groups, schema=schema)


@dataclass(init=False)
class ToolpassToolset(WrapperToolset[Any]):
    """Check each call to a tool of ``wrapped`` with toolpass before it runs.

    ``rules`` maps a tool name (as the model sees it) to a ``Rule`` or a
    ``(connection, action, resource)`` tuple. A tool without a rule runs
    unchecked, unless ``strict=True``; a rule of ``None`` names a tool that
    may run unchecked even then. The resource is filled from the validated
    arguments, and each field must be declared as a plain ``str`` or
    ``int`` parameter.

    The user is ``user`` when given, otherwise ``RunContext.deps.user``
    (or ``deps["user"]``); groups likewise from ``groups`` or the deps'
    ``groups``, when either exists. No user refuses the call.

    Anything but ``allow`` raises ``ToolFailed`` with the reason, so the
    model reads the refusal and the tool body never runs; an error in the
    check refuses too. After a checked tool ran, the ``unconditional write``
    line is logged on the ``toolpass`` logger.
    """

    policy: _Policy

    def __init__(
        self,
        wrapped: AbstractToolset[Any],
        tp: Toolpass | None = None,
        rules: Mapping[str, RuleLike] | None = None,
        *,
        user: UserSource | None = None,
        groups: GroupsSource | None = None,
        strict: bool = False,
        policy: _Policy | None = None,
    ) -> None:
        if policy is None:
            if tp is None or rules is None:
                raise TypeError("ToolpassToolset needs tp and rules: ToolpassToolset(toolset, tp, rules)")
            policy = _Policy(tp, rules, user, groups, strict)
        self.wrapped = wrapped
        self.policy = policy

    async def get_tools(self, ctx: RunContext[Any]) -> dict[str, ToolsetTool[Any]]:
        tools: dict[str, Any] = await self.wrapped.get_tools(ctx)
        self.policy.warn_missing(tools)
        return tools

    async def call_tool(self, name: str, tool_args: dict[str, Any], ctx: RunContext[Any], tool: ToolsetTool[Any]) -> Any:
        try:
            if tool.tool_def.name != name:
                # Something between the model and this toolset renamed the call; neither name says what runs.
                names = self.policy.rules.names()
                if name in names or tool.tool_def.name in names or self.policy.rules.strict:
                    outcome = Outcome(False, f"tool call {name!r} was rerouted to {tool.tool_def.name!r}")
                else:
                    outcome = Outcome(True)
            else:
                outcome = await self.policy.decide(name, tool_args, ctx, tool.tool_def.parameters_json_schema)
        except Exception as e:  # noqa: BLE001 - fail closed: an error in the check refuses the call
            outcome = Outcome(False, f"the toolpass check failed: {type(e).__name__}: {e}")
        if not outcome.allowed:
            raise ToolFailed(refusal(outcome))
        try:
            result = await self.wrapped.call_tool(name, tool_args, ctx, tool)
        except (CallDeferred, ApprovalRequired):
            raise  # deferred, not run: it is checked again when it does run
        except BaseException as e:
            if outcome.checked is not None:
                outcome.checked.log(f"raised {type(e).__name__} from")
            raise
        if outcome.checked is not None:
            outcome.checked.log("ran")
        return result


@dataclass(init=False)
class ToolpassAuthorization(AbstractCapability[Any]):
    """A capability that wraps every tool the agent has (function tools,
    MCP servers, other toolsets) in a ``ToolpassToolset`` for each run.

    Takes the same arguments as ``ToolpassToolset``, without the toolset:

        Agent(model, tools=tools, capabilities=[ToolpassAuthorization(tp, rules)])

    Output tools are not wrapped: they end the run and do not act.
    """

    policy: _Policy = field(repr=False)

    def __init__(
        self,
        tp: Toolpass,
        rules: Mapping[str, RuleLike],
        *,
        user: UserSource | None = None,
        groups: GroupsSource | None = None,
        strict: bool = False,
    ) -> None:
        self.policy = _Policy(tp, rules, user, groups, strict)
        self.id = None
        self.description = None
        self.defer_loading = False

    @classmethod
    def get_serialization_name(cls) -> str | None:
        return None  # built in code, with a Toolpass object; not from an agent spec

    def get_wrapper_toolset(self, toolset: AbstractToolset[Any]) -> AbstractToolset[Any]:
        return ToolpassToolset(toolset, policy=self.policy)
