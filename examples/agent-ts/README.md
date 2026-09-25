# Calling hallpass from a TypeScript agent

Runnable examples for [docs/agents.md](../../docs/agents.md), which explains
the pattern: check with hallpass before acting, treat `unknown` as deny, and
never let the model choose the user. The Python versions are in
[`../agent`](../agent); these follow the same contract. The client they use is
the [`hallpass-client`](../../sdk/node) package
(`npm install hallpass-client`);
here they import its source from `sdk/node` directly.

| File | What it is |
|---|---|
| `ai_sdk_tool.ts` | The two tools as Vercel AI SDK `tool()` definitions, for `generateText`, `streamText` and anything built on them. |
| `mcp_server.ts` | A standalone MCP server over stdio for any MCP host. |
| `fake_hallpass.ts` | The fake hallpass the tests run against. |
| `*.test.ts` | Tests, through each framework's own invocation path. |

Every example has `check_permission`, so the model can ask first, and a
guarded `write_thing` action against the `demo` connection of
[`examples/hallpass.yaml`](../hallpass.yaml), where `admin@example.com` may
write and `dana@example.com` may not.

Needs Node 22.18 or later (it runs `.ts` files directly) and npm.

```sh
# hallpass with the demo connection
export HALLPASS_API_KEY=change-me
go run ./cmd/hallpass serve -config examples/hallpass.yaml

# the examples' dependencies and tests
cd examples/agent-ts
npm ci
npm test

# a script against the live server, no LLM needed
export HALLPASS_URL=http://localhost:8080
node ai_sdk_tool.ts dana@example.com
node ai_sdk_tool.ts admin@example.com
```

`mcp_server.ts` is launched by the MCP host; see the guide for the
`claude mcp add` line.
