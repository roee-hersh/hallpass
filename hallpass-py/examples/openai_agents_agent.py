"""An OpenAI Agents SDK agent whose tool calls hallpass checks before they run.

``HallpassGuardrails`` puts a tool input guardrail on each function tool of
the agent, configured once; the tools carry no decorator. The user comes
from the run context, which the application passes to ``Runner.run`` and
the model cannot write. The model here is Claude, through Anthropic's
OpenAI-compatible endpoint.

    pip install "hallpass[openai-agents]"
    export ANTHROPIC_API_KEY=...
    python examples/openai_agents_agent.py dana@example.com    # refused: not an admin
    python examples/openai_agents_agent.py admin@example.com   # allowed

The engine runs in this process on the ``fake`` integration, so the example
needs no hallpass server; swap in ``Hallpass.from_config("hallpass.yaml")``.
"""

from __future__ import annotations

import asyncio
import os
import sys
from dataclasses import dataclass

from agents import Agent, OpenAIChatCompletionsModel, RunContextWrapper, Runner, function_tool, set_tracing_disabled
from openai import AsyncOpenAI

from hallpass import Hallpass
from hallpass.openai_agents import HallpassGuardrails, Rule

hp = Hallpass(connections=[{"id": "demo", "integration": "fake", "users": "dana@example.com", "admins": "admin@example.com"}])

hallpass = HallpassGuardrails(hp, {"write_thing": Rule("demo", "thing.write", "thing:{thing_id}")})


@dataclass
class Context:
    user_id: str  # set from your login, never from the model


@function_tool
def write_thing(ctx: RunContextWrapper[Context], thing_id: str, content: str) -> str:
    """Write content to a thing in the demo system."""
    # The real action goes here, run with the agent's own credential.
    return f"wrote {len(content)} bytes to thing:{thing_id} as {ctx.context.user_id}"


async def main() -> None:
    # Demo only: the command line stands in for the user your login authenticated.
    user = sys.argv[1] if len(sys.argv) > 1 else "dana@example.com"
    set_tracing_disabled(True)  # traces go to OpenAI by default
    claude = AsyncOpenAI(base_url="https://api.anthropic.com/v1/", api_key=os.environ["ANTHROPIC_API_KEY"])
    agent = hallpass.apply(
        Agent(
            name="demo",
            instructions="You write things for the user.",
            model=OpenAIChatCompletionsModel(model="claude-haiku-4-5", openai_client=claude),
            tools=[write_thing],
        )
    )
    result = await Runner.run(agent, "Write 'hello' to thing 1.", context=Context(user_id=user))
    print(result.final_output)


if __name__ == "__main__":
    asyncio.run(main())
