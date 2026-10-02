# Calling toolpass from a TypeScript agent

Runnable examples for [the agent tools guide](../../docs/guides/agent-tools.md), which explains
the pattern: check with toolpass before acting, treat `unknown` as deny, and
never let the model choose the user. The Python examples are in
[`toolpass-py/examples`](../../toolpass-py/examples). The client these use is
the [`toolpass-client`](../../toolpass-ts) package
(`npm install toolpass-client`), which talks to a toolpass server;
here they import its source from `toolpass-ts` directly.

| File | What it is |
|---|---|
| `ai_sdk_tool.ts` | The two tools as Vercel AI SDK `tool()` definitions, for `generateText`, `streamText` and anything built on them. |
| `mcp_server.ts` | A standalone MCP server over stdio for any MCP host. |
| `fake_toolpass.ts` | The fake toolpass the tests run against. |
| `*.test.ts` | Tests, through each framework's own invocation path. |

Every example has `check_permission`, so the model can ask first, and a
guarded `write_thing` action against the `demo` connection of
[`examples/toolpass.yaml`](../toolpass.yaml), where `admin@example.com` may
write and `dana@example.com` may not.

Needs Node 22.18 or later (it runs `.ts` files directly) and npm.

```sh
# toolpass with the demo connection (pip install toolpass, or the Docker command from the quickstart)
export TOOLPASS_API_KEY=change-me
toolpass serve -config examples/toolpass.yaml

# the examples' dependencies and tests
cd examples/agent-ts
npm ci
npm test

# a script against the live server, no LLM needed
export TOOLPASS_URL=http://localhost:8080
node ai_sdk_tool.ts dana@example.com
node ai_sdk_tool.ts admin@example.com
```

`mcp_server.ts` is launched by the MCP host; see the guide for the
`claude mcp add` line.
