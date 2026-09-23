"""Claude Agent SDK tools that check with hallpass before they act.

The tools live in an in-process MCP server, defined once. The application
sets ``current_user`` (and optionally ``current_groups``) for the session
before it runs a query, so the acting user is never chosen by the model:

    current_user.set("dana@example.com")
    options = ClaudeAgentOptions(
        mcp_servers={"hallpass": server},
        allowed_tools=["mcp__hallpass__check_permission", "mcp__hallpass__write_thing"],
    )
    async for message in query(prompt="...", options=options): ...

Needs ``claude-agent-sdk`` (pip install -r requirements.txt).
"""

from __future__ import annotations

from contextvars import ContextVar
from typing import Any

from claude_agent_sdk import ToolAnnotations, create_sdk_mcp_server, tool

from hallpass_client import Hallpass, guarded

hp = Hallpass()
current_user: ContextVar[str] = ContextVar("current_user")
current_groups: ContextVar[list[str]] = ContextVar("current_groups", default=[])


def _text(text: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": text}]}


@tool(
    "check_permission",
    "Ask whether the current user may perform an action in a system. "
    "connection is a hallpass connection id (e.g. jira-main), action one of "
    "its actions (e.g. DELETE_ISSUES), resource the target (e.g. issue:PAY-123). "
    "Only 'allow' permits the action; 'unknown' is a deny.",
    {"connection": str, "action": str, "resource": str},
    annotations=ToolAnnotations(readOnlyHint=True),
)
async def check_permission(args: dict[str, Any]) -> dict[str, Any]:
    d = hp.check(current_user.get(), args["connection"], args["action"], args["resource"], current_groups.get())
    return _text(f"{d.decision}: {d.reason}")


# The SDK hands the handler one dict of arguments; guarded formats the
# resource from it. A raised PermissionDenied reaches the model as an error
# result carrying its text, so nothing more is needed on a refusal.
@tool(
    "write_thing",
    "Write content to a thing in the demo system. Refused unless the current "
    "user holds thing.write on it.",
    {"thing_id": str, "content": str},
)
@guarded(hp, "demo", "thing.write", "thing:{thing_id}", user=current_user, groups=current_groups)
async def write_thing(args: dict[str, Any]) -> dict[str, Any]:
    # The real action goes here, run with the agent's own credential.
    return _text(f"wrote {len(args['content'])} bytes to thing:{args['thing_id']} as {current_user.get()}")


server = create_sdk_mcp_server(name="hallpass", version="1.0.0", tools=[check_permission, write_thing])


if __name__ == "__main__":
    # Run one prompt through Claude. Needs the Claude Code CLI the SDK drives.
    import asyncio
    import sys

    from claude_agent_sdk import ClaudeAgentOptions, ResultMessage, query

    current_user.set(sys.argv[1] if len(sys.argv) > 1 else "dana@example.com")

    async def main():
        options = ClaudeAgentOptions(
            mcp_servers={"hallpass": server},
            allowed_tools=["mcp__hallpass__check_permission", "mcp__hallpass__write_thing"],
        )
        async for message in query(prompt="Write 'hello' to thing 1.", options=options):
            if isinstance(message, ResultMessage) and message.subtype == "success":
                print(message.result)

    asyncio.run(main())
