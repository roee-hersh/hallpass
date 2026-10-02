"""A Strands agent whose tool calls toolpass checks before they run.

The ``ToolpassAuthorization`` intervention handler is configured once on the
agent; the tools carry no decorator. The user comes from ``invocation_state``,
which the application passes on each call and the model cannot write.

    pip install "toolpass[strands]" "strands-agents[anthropic]"
    export ANTHROPIC_API_KEY=...
    python examples/strands_agent.py dana@example.com    # refused: not an admin
    python examples/strands_agent.py admin@example.com   # allowed

The engine runs in this process on the ``fake`` integration, so the example
needs no toolpass server; swap in ``Toolpass.from_config("toolpass.yaml")``.
"""

from __future__ import annotations

import sys

from strands import Agent, ToolContext, tool
from strands.models.anthropic import AnthropicModel

from toolpass import Toolpass
from toolpass.strands import Rule, ToolpassAuthorization

tp = Toolpass(connections=[{"id": "demo", "integration": "fake", "users": "dana@example.com", "admins": "admin@example.com"}])

guard = ToolpassAuthorization(tp, {"write_thing": Rule("demo", "thing.write", "thing:{thing_id}")})


@tool(context=True)
def write_thing(thing_id: str, content: str, tool_context: ToolContext) -> str:
    """Write content to a thing in the demo system.

    Args:
        thing_id: the thing to write to
        content: what to write
    """
    # The real action goes here, run with the agent's own credential.
    return f"wrote {len(content)} bytes to thing:{thing_id} as {tool_context.invocation_state['user_id']}"


def main() -> None:
    # Demo only: the command line stands in for the user your login authenticated.
    user = sys.argv[1] if len(sys.argv) > 1 else "dana@example.com"
    agent = Agent(model=AnthropicModel(model_id="claude-haiku-4-5", max_tokens=1024), tools=[write_thing], interventions=[guard])
    agent("Write 'hello' to thing 1.", invocation_state={"user_id": user})


if __name__ == "__main__":
    main()
