"""A LangChain agent (create_agent, on LangGraph) whose tool calls hallpass
checks before they run.

``HallpassMiddleware`` is configured once on the agent; the tools carry no
decorator. The user comes from the run's runtime context, which the
application passes on each call and the model cannot write.

    pip install "hallpass[langchain]" langchain-anthropic
    export ANTHROPIC_API_KEY=...
    python examples/langchain_agent.py dana@example.com    # refused: not an admin
    python examples/langchain_agent.py admin@example.com   # allowed

The engine runs in this process on the ``fake`` integration, so the example
needs no hallpass server; swap in ``Hallpass.from_config("hallpass.yaml")``.
For a graph you build yourself, ``hallpass.tool_node(tools)`` is the same
check as a LangGraph ``ToolNode``.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Any

from langchain.agents import create_agent
from langchain.tools import ToolRuntime, tool

from hallpass import Hallpass
from hallpass.langchain import HallpassMiddleware, Rule

hp = Hallpass(connections=[{"id": "demo", "integration": "fake", "users": "dana@example.com", "admins": "admin@example.com"}])

hallpass = HallpassMiddleware(hp, {"write_thing": Rule("demo", "thing.write", "thing:{thing_id}")})


@dataclass
class Context:
    user_id: str  # set from your login, never from the model


@tool
def write_thing(thing_id: str, content: str, runtime: ToolRuntime[Any, Any]) -> str:
    """Write content to a thing in the demo system."""
    # The real action goes here, run with the agent's own credential.
    return f"wrote {len(content)} bytes to thing:{thing_id} as {runtime.context.user_id}"


def main() -> None:
    # Demo only: the command line stands in for the user your login authenticated.
    user = sys.argv[1] if len(sys.argv) > 1 else "dana@example.com"
    agent = create_agent("anthropic:claude-haiku-4-5", tools=[write_thing], middleware=[hallpass], context_schema=Context)
    result = agent.invoke({"messages": [("user", "Write 'hello' to thing 1.")]}, context=Context(user_id=user))
    print(result["messages"][-1].content)


if __name__ == "__main__":
    main()
