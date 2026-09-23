"""LangChain tools that check with hallpass before they act.

The tools are defined once. The application sets ``current_user`` (and
optionally ``current_groups``) for the session before it runs the agent, so
the acting user is never chosen by the model:

    current_user.set(user.email)  # in the request handler, from your auth
    agent = create_agent(llm, tools)          # any LangChain agent constructor

Needs ``langchain-core`` (pip install -r requirements.txt). The tools do not
depend on any particular LLM provider.
"""

from __future__ import annotations

from contextvars import ContextVar

from langchain_core.tools import tool

from hallpass_client import Hallpass, current, guarded

hp = Hallpass()
current_user: ContextVar[str] = ContextVar("current_user")
current_groups: ContextVar[tuple[str, ...]] = ContextVar("current_groups", default=())


@tool
def check_permission(connection: str, action: str, resource: str) -> str:
    """Ask whether the current user may perform an action in a system.
    connection is a hallpass connection id (e.g. jira-main), action one
    of its actions (e.g. DELETE_ISSUES), resource the target (e.g.
    issue:PAY-123). Only 'allow' permits the action; 'unknown' is a deny."""
    d = hp.check(current(current_user), connection, action, resource, current(current_groups, "groups"))
    return f"{d.decision}: {d.reason}"


# LangChain ends the run on an exception it does not know (handle_tool_error
# covers only its own ToolException), so the refusal is returned as the
# observation instead, and the model learns why. LangGraph's ToolNode runs
# the same tool, so it gets the same behaviour.
@tool
@guarded(hp, "demo", "thing.write", "thing:{thing_id}", user=current_user, groups=current_groups,
         deny=lambda e: f"refused: {e}")
def write_thing(thing_id: str, content: str) -> str:
    """Write content to a thing in the demo system. Refused unless the
    current user holds thing.write on it."""
    # The real action goes here, run with the agent's own credential.
    return f"wrote {len(content)} bytes to thing:{thing_id} as {current(current_user)}"


tools = [check_permission, write_thing]


if __name__ == "__main__":
    # Smoke test without an LLM: call the tools directly.
    import sys

    # Demo only: the command line stands in for the user a real request was
    # authenticated as (see docs/agents.md, "Where the user comes from").
    current_user.set(sys.argv[1] if len(sys.argv) > 1 else "dana@example.com")
    print(check_permission.invoke({"connection": "demo", "action": "thing.write", "resource": "thing:1"}))
    print(write_thing.invoke({"thing_id": "1", "content": "hello"}))
