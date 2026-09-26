"""A CrewAI crew whose tool calls hallpass checks before they run.

``HallpassHooks`` registers CrewAI ``before_tool_call`` and
``after_tool_call`` hooks, configured once; the tools carry no decorator.
The user comes from the crew's kickoff ``inputs``, which the application
passes and the model cannot write.

    pip install "hallpass[crewai]" "crewai[anthropic]"
    export ANTHROPIC_API_KEY=...
    python examples/crewai_agent.py dana@example.com    # refused: not an admin
    python examples/crewai_agent.py admin@example.com   # allowed

The engine runs in this process on the ``fake`` integration, so the example
needs no hallpass server; swap in ``Hallpass.from_config("hallpass.yaml")``.
"""

from __future__ import annotations

import sys

from crewai import LLM, Agent, Crew, Task
from crewai.tools import tool

from hallpass import Hallpass
from hallpass.crewai import HallpassHooks, Rule

hp = Hallpass(connections=[{"id": "demo", "integration": "fake", "users": "dana@example.com", "admins": "admin@example.com"}])


@tool("write_thing")
def write_thing(thing_id: str, content: str) -> str:
    """Write content to a thing in the demo system."""
    # The real action goes here, run with the agent's own credential.
    return f"wrote {len(content)} bytes to thing:{thing_id}"


def main() -> None:
    # Demo only: the command line stands in for the user your login authenticated.
    user = sys.argv[1] if len(sys.argv) > 1 else "dana@example.com"
    writer = Agent(
        role="writer",
        goal="write things for the user",
        backstory="You write things. If a tool refuses, you say why.",
        llm=LLM(model="anthropic/claude-haiku-4-5", max_tokens=1024),
        tools=[write_thing],
    )
    task = Task(description="Write 'hello' to thing 1.", expected_output="what happened", agent=writer)
    with HallpassHooks(hp, {"write_thing": Rule("demo", "thing.write", "thing:{thing_id}")}):
        result = Crew(agents=[writer], tasks=[task]).kickoff(inputs={"user_id": user})
    print(result.raw)


if __name__ == "__main__":
    main()
