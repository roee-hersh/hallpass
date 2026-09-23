"""Claude Agent SDK tools that check with hallpass before they act.

The tools live in an in-process MCP server. Build the server once per user
session so the acting user is bound in the closure and never chosen by the
model:

    server = make_server("dana@example.com")
    options = ClaudeAgentOptions(
        mcp_servers={"hallpass": server},
        allowed_tools=["mcp__hallpass__check_permission", "mcp__hallpass__write_thing"],
    )
    async for message in query(prompt="...", options=options): ...

Needs ``claude-agent-sdk`` (pip install -r requirements-frameworks.txt).
"""

from __future__ import annotations

from typing import Any

from claude_agent_sdk import ToolAnnotations, create_sdk_mcp_server, tool

from hallpass_client import Hallpass, PermissionDenied, guarded


def _text(text: str, error: bool = False) -> dict[str, Any]:
    out: dict[str, Any] = {"content": [{"type": "text", "text": text}]}
    if error:
        out["is_error"] = True
    return out


def make_tools(user: str, groups: list[str] | None = None, hp: Hallpass | None = None) -> list:
    """The two tools, bound to one user. ``make_server`` wraps them for ``query``."""
    hp = hp or Hallpass()
    groups = groups or []

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
        d = hp.check(user, args["connection"], args["action"], args["resource"], groups)
        return _text(f"{d.decision}: {d.reason}")

    @guarded(hp, "demo", "thing.write", "thing:{thing_id}", groups)
    def _write_thing(*, user: str, thing_id: str, content: str) -> str:
        # The real action goes here, run with the agent's own credential.
        return f"wrote {len(content)} bytes to thing:{thing_id} as {user}"

    @tool(
        "write_thing",
        "Write content to a thing in the demo system. Refused unless the current "
        "user holds thing.write on it.",
        {"thing_id": str, "content": str},
    )
    async def write_thing(args: dict[str, Any]) -> dict[str, Any]:
        try:
            return _text(_write_thing(user=user, thing_id=args["thing_id"], content=args["content"]))
        except PermissionDenied as e:
            # is_error tells the model the action did not happen.
            return _text(f"refused: {e}", error=True)

    return [check_permission, write_thing]


def make_server(user: str, groups: list[str] | None = None, hp: Hallpass | None = None):
    """An in-process MCP server for ``ClaudeAgentOptions.mcp_servers``."""
    return create_sdk_mcp_server(name="hallpass", version="1.0.0", tools=make_tools(user, groups, hp))


if __name__ == "__main__":
    # Run one prompt through Claude. Needs the Claude Code CLI the SDK drives.
    import asyncio
    import sys

    from claude_agent_sdk import ClaudeAgentOptions, ResultMessage, query

    who = sys.argv[1] if len(sys.argv) > 1 else "dana@example.com"

    async def main():
        options = ClaudeAgentOptions(
            mcp_servers={"hallpass": make_server(who)},
            allowed_tools=["mcp__hallpass__check_permission", "mcp__hallpass__write_thing"],
        )
        async for message in query(prompt="Write 'hello' to thing 1.", options=options):
            if isinstance(message, ResultMessage) and message.subtype == "success":
                print(message.result)

    asyncio.run(main())
