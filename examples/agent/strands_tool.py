"""Strands Agents tools that check with hallpass before they act.

Build the tools once per user session so the acting user is bound in the
closure and never chosen by the model:

    agent = Agent(tools=make_tools("dana@example.com"))
    agent("Write 'hello' to thing 1.")

Needs ``strands-agents`` (pip install -r requirements-frameworks.txt).
"""

from __future__ import annotations

from strands import tool

from hallpass_client import Hallpass, PermissionDenied, guarded


def make_tools(user: str, groups: list[str] | None = None, hp: Hallpass | None = None) -> list:
    hp = hp or Hallpass()
    groups = groups or []

    @tool
    def check_permission(connection: str, action: str, resource: str) -> str:
        """Ask whether the current user may perform an action in a system.

        Only 'allow' permits the action; 'unknown' is a deny.

        Args:
            connection: a hallpass connection id, e.g. jira-main
            action: one of that connection's actions, e.g. DELETE_ISSUES
            resource: the target, e.g. issue:PAY-123
        """
        d = hp.check(user, connection, action, resource, groups)
        return f"{d.decision}: {d.reason}"

    @guarded(hp, "demo", "thing.write", "thing:{thing_id}", groups)
    def _write_thing(*, user: str, thing_id: str, content: str) -> str:
        # The real action goes here, run with the agent's own credential.
        return f"wrote {len(content)} bytes to thing:{thing_id} as {user}"

    @tool
    def write_thing(thing_id: str, content: str) -> str:
        """Write content to a thing in the demo system.

        Refused unless the current user holds thing.write on it.

        Args:
            thing_id: the thing to write to
            content: what to write
        """
        try:
            return _write_thing(user=user, thing_id=thing_id, content=content)
        except PermissionDenied as e:
            return f"refused: {e}"

    return [check_permission, write_thing]


if __name__ == "__main__":
    # Run one prompt through a Strands agent with its default model provider.
    import sys

    from strands import Agent

    who = sys.argv[1] if len(sys.argv) > 1 else "dana@example.com"
    agent = Agent(tools=make_tools(who))
    agent("Write 'hello' to thing 1.")
