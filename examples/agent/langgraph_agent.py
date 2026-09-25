"""A LangGraph agent whose tools check with hallpass before they act.

The tools are the LangChain ones from ``langchain_tool.py``; LangGraph runs
them unchanged. ``create_agent`` (LangChain 1.x, built on LangGraph) gives a
ready tool-calling loop, and ``tool_node`` is the same tools as a node for a
hand-built graph. Set ``current_user`` for the session before invoking:

    current_user.set(user.email)  # in the request handler, from your auth
    agent = create_agent("anthropic:claude-opus-5", tools=tools)
    agent.invoke({"messages": [("user", "Write 'hello' to thing 1.")]})

Needs ``langgraph`` and ``langchain`` (pip install -r requirements.txt) plus
the provider package for the model you name, e.g. ``langchain-anthropic``.
"""

from __future__ import annotations

from langchain.agents import create_agent
from langgraph.prebuilt import ToolNode

from langchain_tool import current_groups, current_user, tools  # noqa: F401

# For a graph you assemble yourself: add this node and route tool calls to it.
tool_node = ToolNode(tools)


def build_agent(model: str):
    """A tool-calling agent for ``model`` (e.g. ``anthropic:claude-opus-5``)."""
    return create_agent(model, tools=tools)


if __name__ == "__main__":
    import sys

    model = sys.argv[1] if len(sys.argv) > 1 else "anthropic:claude-opus-5"
    # Demo only: the command line stands in for the user a real request was
    # authenticated as (see docs/guides/agent-tools.md, "Set the user from your login").
    current_user.set(sys.argv[2] if len(sys.argv) > 2 else "dana@example.com")
    result = build_agent(model).invoke({"messages": [("user", "Write 'hello' to thing 1.")]})
    print(result["messages"][-1].content)
