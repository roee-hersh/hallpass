"""hallpass as a Strands Agents intervention handler.

    pip install "hallpass[strands]"

Configured once on the agent, it checks every tool call that has a rule,
before the tool runs, and composes with Strands' other interventions:

    from hallpass import Hallpass
    from hallpass.strands import HallpassAuthorization, Rule

    hallpass = HallpassAuthorization(Hallpass.from_config("hallpass.yaml"), {
        "open_config_pr": Rule("github-main", "repo.push", "repo:{owner}/{repo}", fresh=True),
        "delete_issue": ("jira-main", "DELETE_ISSUES", "issue:{key}"),
    })
    agent = Agent(tools=tools, interventions=[hallpass])
    agent(prompt, invocation_state={"user_id": user.email})  # from your auth

The user comes from ``invocation_state``, which the application passes and
the model cannot write. ``hallpass.guarded`` also works on a plain function
under Strands' ``@tool``, for a per-tool check instead.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

try:
    from strands.hooks import AfterToolCallEvent, BeforeInvocationEvent, BeforeToolCallEvent
    from strands.interventions import Deny, InterventionHandler, OnError, Proceed
except ImportError as e:  # pragma: no cover - exercised only without the extra
    raise ImportError('hallpass.strands needs strands-agents 1.57.1 or later: pip install "hallpass[strands]"') from e

from hallpass._api import Hallpass, log
from hallpass._rules import Checked, Outcome, Rule, RuleLike, Rules, refusal

__all__ = ["HallpassAuthorization", "Rule"]

# Where a checked call's decision waits in invocation_state for the write log
# line, keyed by toolUseId. Strands keeps its own per-invocation keys there too.
_STATE_KEY = "hallpass_checks"


def _deny(reason: str) -> Deny:
    """A refusal the model reads the same way as under every other adapter."""
    return Deny(reason=refusal(Outcome(False, reason)))


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
        self._rules = Rules(hp, rules, strict=strict)
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
        missing = self._rules.missing(event.agent.tool_names) - self._warned
        if missing:
            self._warned |= missing
            log.warning("hallpass rules name tools the agent does not have, so they check nothing: %s", ", ".join(sorted(missing)))
        return Proceed()

    async def before_tool_call(self, event: BeforeToolCallEvent, **kwargs: Any) -> Proceed | Deny:
        """Ask hallpass whether the invocation's user may make this call."""
        tool = event.tool_use["name"]
        selected = event.selected_tool
        names = self._rules.names()
        if selected is not None and selected.tool_name != tool:
            # A hook swapped the tool without renaming the call; neither name says what runs.
            if tool in names or selected.tool_name in names or self._strict:
                return _deny(f"tool call {tool!r} was rerouted to {selected.tool_name!r}")
            return Proceed()
        state = event.invocation_state
        needs_user = self._rules.entries.get(tool) is not None
        user = state.get(self._user_key)
        groups = None
        if needs_user:
            if not isinstance(user, str) or not user:
                return _deny(f"no user for this request: invocation_state[{self._user_key!r}] is not set")
            if self._groups_key is not None:
                groups = state.get(self._groups_key)
                if isinstance(groups, (str, bytes)) or not isinstance(groups, (list, tuple)) or not all(isinstance(g, str) for g in groups):
                    return _deny(f"no groups for this request: invocation_state[{self._groups_key!r}] is not a list of strings")
                groups = list(groups)
        schema = selected.tool_spec.get("inputSchema", {}).get("json") if selected is not None else None
        outcome = await self._rules.adecide(tool, event.tool_use.get("input"), user=user, groups=groups, schema=schema)
        if not outcome.allowed:
            return _deny(outcome.reason)
        if outcome.checked is not None:
            state.setdefault(_STATE_KEY, {})[event.tool_use.get("toolUseId")] = outcome.checked
        return Proceed()

    def after_tool_call(self, event: AfterToolCallEvent, **kwargs: Any) -> Proceed:
        """Log that a checked tool ran, and that the check did not make it atomic."""
        checks = event.invocation_state.get(_STATE_KEY)
        c = checks.pop(event.tool_use.get("toolUseId"), None) if isinstance(checks, dict) else None
        if not isinstance(c, Checked) or event.cancel_message is not None:
            return Proceed()
        if event.exception is not None:
            outcome = f"raised {type(event.exception).__name__} from"
        elif event.result.get("status") != "success":
            outcome = "got an error result from"
        else:
            outcome = "ran"
        c.log(outcome)
        return Proceed()
