"""A Google ADK agent whose tool calls hallpass checks before they run.

``HallpassCallbacks`` adds a ``before_tool_callback`` (and the audit log's
after and error callbacks) to the agent, configured once; the tools carry
no decorator. The user is the ADK session's ``user_id``, which the
application passes to the runner and the model cannot write. The model here
is Claude, through ADK's Anthropic integration.

    pip install "hallpass[google-adk]" anthropic
    export ANTHROPIC_API_KEY=...
    python examples/google_adk_agent.py dana@example.com    # refused: not an admin
    python examples/google_adk_agent.py admin@example.com   # allowed

The engine runs in this process on the ``fake`` integration, so the example
needs no hallpass server; swap in ``Hallpass.from_config("hallpass.yaml")``.
"""

from __future__ import annotations

import asyncio
import sys

from google.adk.agents import LlmAgent
from google.adk.models.anthropic_llm import AnthropicLlm
from google.adk.runners import InMemoryRunner
from google.adk.tools import ToolContext
from google.genai import types

from hallpass import Hallpass
from hallpass.google_adk import HallpassCallbacks, Rule

hp = Hallpass(connections=[{"id": "demo", "integration": "fake", "users": "dana@example.com", "admins": "admin@example.com"}])

hallpass = HallpassCallbacks(hp, {"write_thing": Rule("demo", "thing.write", "thing:{thing_id}")})


def write_thing(thing_id: str, content: str, tool_context: ToolContext) -> str:
    """Write content to a thing in the demo system."""
    # The real action goes here, run with the agent's own credential.
    return f"wrote {len(content)} bytes to thing:{thing_id} as {tool_context.user_id}"


async def main() -> None:
    # Demo only: the command line stands in for the user your login authenticated.
    user = sys.argv[1] if len(sys.argv) > 1 else "dana@example.com"
    agent = LlmAgent(name="demo", model=AnthropicLlm(model="claude-haiku-4-5"), instruction="You write things for the user.", tools=[write_thing])
    runner = InMemoryRunner(agent=hallpass.apply(agent), app_name="demo")
    session = await runner.session_service.create_session(app_name="demo", user_id=user)
    message = types.Content(role="user", parts=[types.Part(text="Write 'hello' to thing 1.")])
    async for event in runner.run_async(user_id=user, session_id=session.id, new_message=message):
        if event.is_final_response() and event.content and event.content.parts:
            print(event.content.parts[0].text)


if __name__ == "__main__":
    asyncio.run(main())
