"""hallpass as Claude Agent SDK hooks.

    pip install "hallpass[claude-agent-sdk]"

A ``PreToolUse`` hook is Claude Code's own check in front of every tool
call, built-in or MCP: a ``deny`` stops the call before it runs and hands
the reason to Claude as the tool's error result, and the session goes on.
``HallpassHooks`` is that hook, configured once with the rules, plus a
``PostToolUse`` hook that logs the write after an allowed tool ran:

    from claude_agent_sdk import ClaudeAgentOptions, query
    from hallpass import Hallpass
    from hallpass.claude_agent_sdk import HallpassHooks, Rule

    current_user: ContextVar[str] = ContextVar("current_user")
    hallpass = HallpassHooks(Hallpass.from_config("hallpass.yaml"), {
        "mcp__ops__delete_issue": Rule("jira-main", "DELETE_ISSUES", "issue:{key}", fresh=True),
    }, user=current_user)
    options = hallpass.apply(ClaudeAgentOptions(mcp_servers={"ops": server}, allowed_tools=[...]))

    current_user.set(user.email)  # from your auth, before query() or client.connect()
    async for message in query(prompt=prompt, options=options): ...

Rules are keyed by the name Claude Code gives the tool: ``mcp__<server>__<tool>``
for an MCP tool, ``Bash``, ``Write``, ... for a built-in one.

The user comes from ``user``, which the application sets: a fixed string (one
options object per user session), a zero-argument callable, or a ContextVar.
The SDK runs hook callbacks in the task that ``query()`` or
``ClaudeSDKClient.connect()`` started, so a ContextVar must be set before
that call. It is never read from the tool's input.

Claude Code has no JSON schema for a tool in the hook, so each resource
field must be a JSON string or integer in the input as sent; an SDK MCP
server validates the input without converting it, so the handler acts on
the value hallpass checked. Do not add hooks that rewrite tool input
(``updatedInput``): they change the call after hallpass checked it. A hook
returns no decision for an allowed call, so Claude Code's own permission
rules (``allowed_tools``, ``permission_mode``, ``can_use_tool``) still apply
after hallpass. ``can_use_tool`` is offered too, for applications that
already route permissions through it; it runs only for calls Claude Code
would otherwise ask about, so the hook is the one that sees every call.

``hallpass.guarded`` works on an SDK MCP tool's handler as well (the one
dict of arguments shape).
"""

from __future__ import annotations

import dataclasses
from collections import OrderedDict
from collections.abc import Mapping
from typing import Any

try:
    from claude_agent_sdk import ClaudeAgentOptions, HookMatcher, PermissionResultAllow, PermissionResultDeny, ToolPermissionContext
    from claude_agent_sdk.types import HookContext, HookJSONOutput
except ImportError as e:  # pragma: no cover - depends on the environment
    raise ImportError('hallpass.claude_agent_sdk needs claude-agent-sdk 0.2.160 or later: pip install "hallpass[claude-agent-sdk]"') from e

from hallpass._api import log
from hallpass._rules import Checked, Outcome, Rule, RuleLike, Rules, refusal

__all__ = ["HallpassHooks", "Rule"]

# Checks waiting for their PostToolUse, by tool_use_id. A call another hook
# denied never gets one, so the oldest are dropped past this many.
_PENDING_MAX = 1024


class HallpassHooks:
    """Check each tool call with hallpass before Claude Code runs it.

    ``rules`` maps a Claude Code tool name to a ``Rule``, a ``(connection,
    action, resource)`` tuple, or ``None``. A tool without a rule runs
    unchecked, unless ``strict=True``; ``None`` lets a tool run unchecked
    even then. Under ``strict`` that includes Claude Code's built-in tools.

    ``user`` (and ``groups``) are sources the application sets: a value, a
    zero-argument callable or a ContextVar. A missing user refuses.

    Any answer other than ``allow`` denies the call with ``hallpass refused
    this call: ...`` as the reason Claude reads; an error inside the check
    denies too (Claude Code runs the tool when a hook callback raises, so
    the hook never does). ``timeout`` is the hook timeout Claude Code
    applies, in seconds; a check that takes longer stops the call with
    Claude Code's own timeout message instead of hallpass's reason.
    """

    def __init__(
        self,
        hp: Any,
        rules: Mapping[str, RuleLike],
        *,
        user: Any,
        groups: Any = None,
        strict: bool = False,
        timeout: float | None = 60,
    ) -> None:
        self.rules = Rules(hp, rules, strict=strict)
        self._user = user
        self._groups = groups
        self._timeout = timeout
        self._pending: OrderedDict[str, Checked] = OrderedDict()

    # -- configuration --

    def hooks(self) -> dict[str, list[HookMatcher]]:
        """The hooks for ``ClaudeAgentOptions.hooks``."""
        return {
            "PreToolUse": [HookMatcher(matcher=None, hooks=[self.pre_tool_use], timeout=self._timeout)],
            "PostToolUse": [HookMatcher(matcher=None, hooks=[self.post_tool_use])],
            "PostToolUseFailure": [HookMatcher(matcher=None, hooks=[self.post_tool_use_failure])],
        }

    def apply(self, options: ClaudeAgentOptions) -> ClaudeAgentOptions:
        """A copy of ``options`` with hallpass's hooks added to its own.
        Warns about rules for MCP servers the options do not have."""
        merged: dict[Any, list[HookMatcher]] = {k: list(v) for k, v in (options.hooks or {}).items()}
        for event, matchers in self.hooks().items():
            merged.setdefault(event, []).extend(matchers)
        if isinstance(options.mcp_servers, Mapping):
            prefixes = tuple(f"mcp__{name}__" for name in options.mcp_servers)
            odd = sorted(t for t in self.rules.names() if t.startswith("mcp__") and not t.startswith(prefixes))
            if odd:
                log.warning("hallpass rules name MCP servers the options do not have, so they check nothing: %s", ", ".join(odd))
        return dataclasses.replace(options, hooks=merged)

    # -- the checks --

    async def _decide(self, tool: Any, tool_input: Any) -> Outcome:
        if not isinstance(tool, str):
            return Outcome(False, "the call names no tool")
        try:
            return await self.rules.adecide(tool, tool_input, user=self._user, groups=self._groups)
        except Exception as e:  # noqa: BLE001 - fail closed
            return Outcome(False, f"the check failed: {type(e).__name__}: {e}")

    async def pre_tool_use(self, input_data: Any, tool_use_id: str | None, context: HookContext) -> HookJSONOutput:
        """Deny the call unless hallpass allowed it (no decision otherwise,
        so Claude Code's own permission rules still apply)."""
        try:
            data = input_data if isinstance(input_data, Mapping) else {}
            outcome = await self._decide(data.get("tool_name"), data.get("tool_input"))
            if outcome.allowed:
                key = tool_use_id or data.get("tool_use_id")
                if outcome.checked is not None and isinstance(key, str):
                    self._pending[key] = outcome.checked
                    while len(self._pending) > _PENDING_MAX:
                        self._pending.popitem(last=False)
                return {}
            reason = refusal(outcome)
        except Exception as e:  # noqa: BLE001 - fail closed: Claude Code runs the tool when a hook raises
            reason = refusal(Outcome(False, f"the check failed: {type(e).__name__}: {e}"))
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        }

    def _log(self, input_data: Any, tool_use_id: str | None, outcome: str) -> None:
        key = tool_use_id or (input_data.get("tool_use_id") if isinstance(input_data, Mapping) else None)
        checked = self._pending.pop(key, None) if isinstance(key, str) else None
        if checked is not None:
            checked.log(outcome)

    async def post_tool_use(self, input_data: Any, tool_use_id: str | None, context: HookContext) -> HookJSONOutput:
        """Log that a checked tool ran."""
        self._log(input_data, tool_use_id, "ran")
        return {}

    async def post_tool_use_failure(self, input_data: Any, tool_use_id: str | None, context: HookContext) -> HookJSONOutput:
        """Log that a checked tool failed (raised, or returned an error result)."""
        self._log(input_data, tool_use_id, "got an error result from")
        return {}

    async def can_use_tool(self, tool_name: str, tool_input: dict[str, Any], context: ToolPermissionContext) -> PermissionResultAllow | PermissionResultDeny:
        """The same check as a ``can_use_tool`` callback."""
        outcome = await self._decide(tool_name, tool_input)
        if outcome.allowed:
            if outcome.checked is not None and context.tool_use_id:
                self._pending[context.tool_use_id] = outcome.checked
            return PermissionResultAllow()
        return PermissionResultDeny(message=refusal(outcome))
