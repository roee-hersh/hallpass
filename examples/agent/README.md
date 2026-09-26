# Calling hallpass from a Python agent

The Python examples moved to [`hallpass-py/examples`](../../hallpass-py/examples). There is one per
framework adapter (Strands Agents, LangChain and LangGraph, MCP, the OpenAI Agents SDK, the Claude
Agent SDK, Google ADK, CrewAI, Pydantic AI and LlamaIndex), each configured once on the agent,
running the hallpass engine in-process on the `demo` connection, so none needs a hallpass server.
[The agent tools guide](../../docs/guides/agent-tools.md) explains the pattern and how to run them.

The examples that used to be here called a hallpass server through `hallpass_client` and wrapped
each tool with `guarded`. That still works: `hallpass_client` is now a compatibility package over
`hallpass`, and `guarded` is `hallpass.guarded`. The adapters' tests in
[`hallpass-py/tests/frameworks`](../../hallpass-py/tests/frameworks) replace these examples' tests.

The TypeScript examples are in [`../agent-ts`](../agent-ts).
