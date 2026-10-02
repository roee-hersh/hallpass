# Calling toolpass from a Python agent

The Python examples moved to [`toolpass-py/examples`](../../toolpass-py/examples). There is one per
framework adapter (Strands Agents, LangChain and LangGraph, MCP, the OpenAI Agents SDK, the Claude
Agent SDK, Google ADK, CrewAI, Pydantic AI and LlamaIndex), each configured once on the agent,
running the toolpass engine in-process on the `demo` connection, so none needs a toolpass server.
[The agent tools guide](../../docs/guides/agent-tools.md) explains the pattern and how to run them.

The examples that used to be here called a toolpass server through `toolpass_client` (the old
Python client, now replaced by `toolpass`: `Toolpass.remote()` is the same client) and wrapped
each tool with `guarded`, which is `toolpass.guarded`. The adapters' tests in
[`toolpass-py/tests/frameworks`](../../toolpass-py/tests/frameworks) replace these examples' tests.

The TypeScript examples are in [`../agent-ts`](../agent-ts).
