# Calling hallpass from an AI agent

Runnable examples for [docs/agents.md](../../docs/agents.md), which explains
the pattern: check with hallpass before acting, treat `unknown` as deny, and
never let the model choose the user. The client they use is the
[`hallpass-client`](../../sdk/python) package (`pip install hallpass-client`).

| File | What it is |
|---|---|
| `langchain_tool.py` | The two tools as LangChain tools. |
| `langgraph_agent.py` | A LangGraph agent (`create_agent`) and a `ToolNode` built from those tools. |
| `strands_tool.py` | The two tools for Strands Agents. |
| `claude_agent_sdk_tool.py` | The two tools as an in-process MCP server for the Claude Agent SDK. |
| `mcp_server.py` | A standalone MCP server over stdio for any MCP host. |
| `test_hallpass_client.py` | Tests against a fake hallpass, through each framework's own invocation path. |

Every example has `check_permission`, so the model can ask first, and a
guarded `write_thing` action against the `demo` connection of
`examples/hallpass.yaml`, where `admin@example.com` may write and
`dana@example.com` may not.

```sh
# hallpass with the demo connection
export HALLPASS_API_KEY=change-me
go run ./cmd/hallpass serve -config examples/hallpass.yaml

# the examples' dependencies and tests
python3 -m venv .venv && . .venv/bin/activate
pip install ./sdk/python -r examples/agent/requirements.txt
python3 -m unittest discover -s examples/agent -v

# a script against the live server, no LLM needed
export HALLPASS_URL=http://localhost:8080
python examples/agent/langchain_tool.py dana@example.com
python examples/agent/langchain_tool.py admin@example.com
```

`langgraph_agent.py`, `strands_tool.py` and `claude_agent_sdk_tool.py` run
one prompt through a model when executed directly and need that provider set
up. `mcp_server.py` is launched by the MCP host; see the guide for the
`claude mcp add` line.
