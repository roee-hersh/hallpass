"""A Claude Agent SDK session whose tool calls hallpass checks before they run.

``HallpassHooks`` is a ``PreToolUse`` hook, configured once on the options;
the tools carry no decorator, and built-in tools (Bash, Write, ...) can have
rules too. The user comes from ``current_user``, which the application sets
from its login before the session starts; the model cannot write it.

    pip install "hallpass[claude-agent-sdk]"
    export ANTHROPIC_API_KEY=...
    python examples/claude_agent_sdk_agent.py dana@example.com    # refused: not an admin
    python examples/claude_agent_sdk_agent.py admin@example.com   # allowed

The engine runs in this process on the ``fake`` integration, so the example
needs no hallpass server; swap in ``Hallpass.from_config("hallpass.yaml")``.
The SDK drives the Claude Code CLI it bundles.
"""

from __future__ import annotations

import asyncio
import sys
from contextvars import ContextVar
from typing import Any

from claude_agent_sdk import ClaudeAgentOptions, ResultMessage, create_sdk_mcp_server, query, tool

from hallpass import Hallpass
from hallpass.claude_agent_sdk import HallpassHooks, Rule

hp = Hallpass(connections=[{"id": "demo", "integration": "fake", "users": "dana@example.com", "admins": "admin@example.com"}])
current_user: ContextVar[str] = ContextVar("current_user")

hallpass = HallpassHooks(hp, {"mcp__demo__write_thing": Rule("demo", "thing.write", "thing:{thing_id}")}, user=current_user)


@tool("write_thing", "Write content to a thing in the demo system.", {"thing_id": str, "content": str})
async def write_thing(args: dict[str, Any]) -> dict[str, Any]:
    # The real action goes here, run with the agent's own credential.
    text = f"wrote {len(args['content'])} bytes to thing:{args['thing_id']} as {current_user.get()}"
    return {"content": [{"type": "text", "text": text}]}


async def main() -> None:
    # Demo only: the command line stands in for the user your login authenticated.
    current_user.set(sys.argv[1] if len(sys.argv) > 1 else "dana@example.com")
    options = hallpass.apply(
        ClaudeAgentOptions(
            model="claude-haiku-4-5",
            mcp_servers={"demo": create_sdk_mcp_server("demo", tools=[write_thing])},
            allowed_tools=["mcp__demo__write_thing"],
            setting_sources=[],
        )
    )
    async for message in query(prompt="Write 'hello' to thing 1.", options=options):
        if isinstance(message, ResultMessage):
            print(message.result)


if __name__ == "__main__":
    asyncio.run(main())
