"""Strands Agents tools that check with hallpass before they act.

The tools are defined once. The application sets ``current_user`` (and
optionally ``current_groups``) for the session before it runs the agent, so
the acting user is never chosen by the model:

    current_user.set("dana@example.com")
    agent = Agent(tools=tools)
    agent("Write 'hello' to thing 1.")

Needs ``strands-agents`` (pip install -r requirements.txt).
"""

from __future__ import annotations

from contextvars import ContextVar

from strands import tool

from hallpass_client import Hallpass, current, guarded

hp = Hallpass()
current_user: ContextVar[str] = ContextVar("current_user")
current_groups: ContextVar[tuple[str, ...]] = ContextVar("current_groups", default=())


@tool
def check_permission(connection: str, action: str, resource: str) -> str:
    """Ask whether the current user may perform an action in a system.

    Only 'allow' permits the action; 'unknown' is a deny.

    Args:
        connection: a hallpass connection id, e.g. jira-main
        action: one of that connection's actions, e.g. DELETE_ISSUES
        resource: the target, e.g. issue:PAY-123
    """
    d = hp.check(current(current_user), connection, action, resource, current(current_groups, "groups"))
    return f"{d.decision}: {d.reason}"


# Strands reports a raised PermissionDenied to the model as a tool error
# carrying its text, so nothing more is needed on a refusal.
@tool
@guarded(hp, "demo", "thing.write", "thing:{thing_id}", user=current_user, groups=current_groups)
def write_thing(thing_id: str, content: str) -> str:
    """Write content to a thing in the demo system.

    Refused unless the current user holds thing.write on it.

    Args:
        thing_id: the thing to write to
        content: what to write
    """
    # The real action goes here, run with the agent's own credential.
    return f"wrote {len(content)} bytes to thing:{thing_id} as {current(current_user)}"


tools = [check_permission, write_thing]


if __name__ == "__main__":
    # Run one prompt through a Strands agent with its default model provider.
    import sys

    from strands import Agent

    current_user.set(sys.argv[1] if len(sys.argv) > 1 else "dana@example.com")
    Agent(tools=tools)("Write 'hello' to thing 1.")
