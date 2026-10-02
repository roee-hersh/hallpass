"""A Pydantic AI agent whose tool calls toolpass checks before they run.

``ToolpassAuthorization`` is a capability, configured once on the agent; the
tools carry no decorator. The user comes from the run's ``deps``, which the
application passes to ``run`` and the model cannot write.

    pip install "toolpass[pydantic-ai]" "pydantic-ai-slim[anthropic]"
    export ANTHROPIC_API_KEY=...
    python examples/pydantic_ai_agent.py dana@example.com    # refused: not an admin
    python examples/pydantic_ai_agent.py admin@example.com   # allowed

The engine runs in this process on the ``fake`` integration, so the example
needs no toolpass server; swap in ``Toolpass.from_config("toolpass.yaml")``.
To check only some tools, wrap their toolset in ``ToolpassToolset`` instead.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass

from pydantic_ai import Agent, RunContext

from toolpass import Toolpass
from toolpass.pydantic_ai import Rule, ToolpassAuthorization

tp = Toolpass(connections=[{"id": "demo", "integration": "fake", "users": "dana@example.com", "admins": "admin@example.com"}])


@dataclass
class Deps:
    user: str  # set from your login, never from the model


agent = Agent(
    "anthropic:claude-haiku-4-5",
    deps_type=Deps,
    instructions="You write things for the user. If a tool refuses, say why.",
    capabilities=[ToolpassAuthorization(tp, {"write_thing": Rule("demo", "thing.write", "thing:{thing_id}")})],
)


@agent.tool
def write_thing(ctx: RunContext[Deps], thing_id: str, content: str) -> str:
    """Write content to a thing in the demo system."""
    # The real action goes here, run with the agent's own credential.
    return f"wrote {len(content)} bytes to thing:{thing_id} as {ctx.deps.user}"


def main() -> None:
    # Demo only: the command line stands in for the user your login authenticated.
    user = sys.argv[1] if len(sys.argv) > 1 else "dana@example.com"
    result = agent.run_sync("Write 'hello' to thing 1.", deps=Deps(user=user))
    print(result.output)


if __name__ == "__main__":
    main()
