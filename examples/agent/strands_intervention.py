"""Strands Agents with hallpass as an intervention handler.

The handler is configured once on the agent and checks every tool that has a
rule, before the tool runs. The tools themselves carry no decorator. The user
comes from invocation_state, which the application passes on each call and
the model cannot write:

    agent = Agent(tools=tools, interventions=[hallpass])
    agent("Write 'hello' to thing 1.", invocation_state={"user_id": user.email})

This is the recommended way to use hallpass with Strands; strands_tool.py
shows the per-tool ``guarded`` decorator instead.

Needs ``strands-agents`` 1.57.1 or later (pip install -r requirements.txt).
"""

from __future__ import annotations

from strands import Agent, ToolContext, tool

from hallpass_client import Hallpass
from hallpass_client.strands import HallpassAuthorization, Rule

hp = Hallpass()

hallpass = HallpassAuthorization(hp, {
    "write_thing": Rule("demo", "thing.write", "thing:{thing_id}"),
})


@tool(context=True)
def check_permission(connection: str, action: str, resource: str, tool_context: ToolContext) -> str:
    """Ask whether the current user may perform an action in a system.

    Only 'allow' permits the action; 'unknown' is a deny.

    Args:
        connection: a hallpass connection id, e.g. jira-main
        action: one of that connection's actions, e.g. DELETE_ISSUES
        resource: the target, e.g. issue:PAY-123
    """
    d = hp.check(tool_context.invocation_state["user_id"], connection, action, resource)
    return f"{d.decision}: {d.reason}"


@tool(context=True)
def write_thing(thing_id: str, content: str, tool_context: ToolContext) -> str:
    """Write content to a thing in the demo system.

    Refused unless the current user holds thing.write on it.

    Args:
        thing_id: the thing to write to
        content: what to write
    """
    # The real action goes here, run with the agent's own credential.
    return f"wrote {len(content)} bytes to thing:{thing_id} as {tool_context.invocation_state['user_id']}"


tools = [check_permission, write_thing]


if __name__ == "__main__":
    # Run one prompt through a Strands agent with its default model provider.
    import sys

    # Demo only: the command line stands in for the user a real request was
    # authenticated as (see docs/guides/agent-tools.md, "Set the user from your login").
    user = sys.argv[1] if len(sys.argv) > 1 else "dana@example.com"
    Agent(tools=tools, interventions=[hallpass])("Write 'hello' to thing 1.", invocation_state={"user_id": user})
