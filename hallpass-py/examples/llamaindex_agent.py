"""A LlamaIndex FunctionAgent whose tool calls hallpass checks before they run.

LlamaIndex agents have no hook that can stop a tool call, so
``HallpassAuthorization.wrap`` wraps the tools that have a rule; the tool
functions carry no decorator. The user comes from ``current_user``, which
the application sets from its login before ``agent.run``; the model cannot
write it.

    pip install "hallpass[llamaindex]" llama-index-llms-anthropic
    export ANTHROPIC_API_KEY=...
    python examples/llamaindex_agent.py dana@example.com    # refused: not an admin
    python examples/llamaindex_agent.py admin@example.com   # allowed

The engine runs in this process on the ``fake`` integration, so the example
needs no hallpass server; swap in ``Hallpass.from_config("hallpass.yaml")``.
"""

from __future__ import annotations

import asyncio
import sys
from contextvars import ContextVar

from llama_index.core.agent.workflow import FunctionAgent
from llama_index.llms.anthropic import Anthropic

from hallpass import Hallpass
from hallpass.llamaindex import HallpassAuthorization, Rule

hp = Hallpass(connections=[{"id": "demo", "integration": "fake", "users": "dana@example.com", "admins": "admin@example.com"}])
current_user: ContextVar[str] = ContextVar("current_user")

hallpass = HallpassAuthorization(hp, {"write_thing": Rule("demo", "thing.write", "thing:{thing_id}")}, user=current_user)


def write_thing(thing_id: str, content: str) -> str:
    """Write content to a thing in the demo system."""
    # The real action goes here, run with the agent's own credential.
    return f"wrote {len(content)} bytes to thing:{thing_id} as {current_user.get()}"


async def main() -> None:
    # Demo only: the command line stands in for the user your login authenticated.
    current_user.set(sys.argv[1] if len(sys.argv) > 1 else "dana@example.com")
    agent = FunctionAgent(
        tools=hallpass.wrap([write_thing]),
        llm=Anthropic(model="claude-sonnet-5", max_tokens=1024),
        system_prompt="You write things for the user. If a tool refuses, say why.",
    )
    print(await agent.run("Write 'hello' to thing 1."))


if __name__ == "__main__":
    asyncio.run(main())
