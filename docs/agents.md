# Using hallpass from an AI agent

An agent holds one powerful bot credential. Before it uses that credential on
behalf of a person, it asks hallpass whether that person may do the thing.
This guide shows the pattern and how to wire it into LangChain, LangGraph,
Strands Agents, the Claude Agent SDK and any MCP host, and in TypeScript into
the Vercel AI SDK and the MCP TypeScript SDK. Runnable versions of every
snippet live in [`examples/agent`](../examples/agent) and
[`examples/agent-ts`](../examples/agent-ts).

## The rules

1. **Act only on `allow`.** `deny` and `unknown` are both refusals. hallpass
   answers `unknown` when it could not evaluate: upstream timeout, ambiguous
   user, a resource it cannot see, a bad request.
2. **No answer is a refusal too.** A connection error, a timeout, a malformed
   response, a redirect, or an `allow` with a non-200 status all count as
   `unknown`. Redirects are never followed, because following one would send
   the API key to whatever host the `Location` header names. Plain `http://`
   is accepted only for localhost, for the same reason.
3. **The model does not choose the user.** The person the agent acts for is
   set by your application for the session. It is never a tool argument: a
   tool argument is text the model produces, and a model that can pick the
   user can pick an administrator.
4. **hallpass only checks.** The action itself still runs with the agent's
   own credential, in your code, after the check.

## The client

[`examples/agent/hallpass_client.py`](../examples/agent/hallpass_client.py)
is one file with no dependencies beyond the standard library. Copy it into
your project.

```python
from hallpass_client import Hallpass

hp = Hallpass()  # HALLPASS_URL and HALLPASS_API_KEY from the environment

d = hp.check("dana@example.com", "jira-main", "DELETE_ISSUES", "issue:PAY-123")
d.decision  # "allow", "deny" or "unknown"
d.reason    # "denied: dana@example.com lacks DELETE_ISSUES on PAY"
d.allowed   # True only for allow

hp.require("dana@example.com", "jira-main", "DELETE_ISSUES", "issue:PAY-123")
# raises PermissionDenied unless the answer is allow
```

`check` never raises on transport problems; every failure is an `unknown`
decision with the code `client_error`. Pass `groups=[...]` for systems that
grant by group, such as Kubernetes.

Pass `fresh=True` for an answer straight from the upstream system. hallpass
caches allow and deny answers for 30 seconds by default; a fresh check
skips its caches for that one request and asks now, then stores what it
learned so reads keep using the cache. Make it the default for destructive
actions (delete, merge, scale):

```python
hp.require("dana@example.com", "jira-main", "DELETE_ISSUES", "issue:PAY-123", fresh=True)
jira.delete_issue("PAY-123")
```

A fresh check narrows the window between the check and the action to the
time between the two; it does not close it. Closing it needs a conditional
write in the upstream system (for example `If-Match` with an ETag), which
only some APIs support. A hallpass built before `fresh` existed rejects a
request that carries it, which the clients report as `unknown`: upgrade the
service before turning `fresh` on.

## The `guarded` decorator

`guarded` wraps a function so that its body runs only after hallpass allowed
it. A framework's `@tool` decorator goes directly on top.

```python
from contextvars import ContextVar
from hallpass_client import Hallpass, guarded

hp = Hallpass()
current_user: ContextVar[str] = ContextVar("current_user")

@tool  # LangChain, Strands, MCPServer, ...
@guarded(hp, "jira-main", "DELETE_ISSUES", "issue:{key}", user=current_user, fresh=True)
def delete_issue(key: str) -> str:
    jira.delete_issue(key)  # the agent's own credential
    return f"deleted {key}"
```

`fresh=True` is right for a destructive tool like this one: the check asks
the upstream system now instead of a cached answer.

Your application sets `current_user` for the session before the agent runs:

```python
current_user.set(request.user.email)
```

| Parameter | Meaning |
|---|---|
| `hp` | The `Hallpass` client. |
| `connection`, `action` | The connection id from `hallpass.yaml` and one of its actions (`hallpass catalog jira` lists them). |
| `resource` | A format string over the call's arguments, e.g. `"issue:{key}"`. A call that cannot fill it makes no request and runs nothing. |
| `user` | Where the acting user comes from: a string, a zero-argument callable, or a `ContextVar`. Resolved on every call. Never read from the arguments. |
| `groups` | The user's groups, from the same kinds of source. Must yield a list. |
| `deny` | Optional. Called with the `PermissionDenied`; its return value is returned instead of raising. For frameworks that hide an exception's text from the model. |
| `fresh` | Optional. `True` makes every check skip hallpass's caches and ask the upstream system now. Use it for delete, merge and scale-type actions. |

What the decorator guarantees:

- The decorated function's signature is exactly the original's. There is no
  `user` parameter for a framework to expose in the tool schema. A stray
  `user` keyword argument is a `TypeError` before any request is made; a
  `user` key in a dict of arguments is ignored.
- The check happens before the body, on every call, with the user from the
  application. Any answer other than `allow` raises `PermissionDenied`
  (or returns what `deny` gives) and the body never runs.
- A function with ordinary parameters is called with keyword arguments
  (LangChain, Strands, MCP). A function whose only parameter is a dict, the
  Claude Agent SDK handler shape, receives all the arguments in it. The
  shape is fixed by the signature, so a call in the wrong shape is a
  `TypeError`, not a check on one resource and an action on another.
- `async def` is supported. The check then runs in a worker thread, so the
  event loop is not blocked by the HTTP call.

`current(source)` resolves a user or groups source the same way `guarded`
does, for code outside a guarded function such as a `check_permission` tool;
a `ContextVar` with nothing set for the session gives a clear error naming
it.

## What the model sees on a refusal

Each framework reports a raised exception differently, so the examples pick
per framework whether `guarded` raises or returns:

| Framework | On `PermissionDenied` | The model reads |
|---|---|---|
| Strands Agents | raise | a tool error carrying the text |
| Claude Agent SDK | raise | an `is_error` result carrying the text |
| MCPServer (`mcp` package) | `deny=` returns `refused: ...` | the refusal as the result; the server would otherwise mask the text |
| LangChain / LangGraph | `deny=` returns `refused: ...` | the refusal as the observation; an unknown exception would end the run |

In every case the text names the user, action, resource and hallpass's
reason, so the model can tell the person why.

## Where the user comes from

The user must come from something the model cannot write: your own
authentication. Set `current_user` in the code that handles the incoming
request, from the identity that request was authenticated as, then run the
agent in that same request. Each request runs in its own task, so parallel
requests keep their own user.

A web app, where your auth dependency has already verified the session
(Strands shown; any framework works the same way):

```python
from fastapi import Depends, FastAPI
from strands import Agent
from strands_tool import current_groups, current_user, tools

app = FastAPI()

@app.post("/chat")
async def chat(body: ChatIn, user: User = Depends(authenticated_user)):  # your SSO / session auth
    current_user.set(user.email)
    current_groups.set(tuple(user.groups))
    agent = Agent(tools=tools)               # one agent per request: no history shared between users
    result = await agent.invoke_async(body.message)
    return {"reply": str(result)}
```

A Slack bot, where Slack signs the event and names the user who wrote it
(Claude Agent SDK shown; needs the `users:read.email` scope):

```python
from slack_bolt.async_app import AsyncApp
from claude_agent_sdk import ClaudeAgentOptions, query
from claude_agent_sdk_tool import current_user, server

app = AsyncApp(token=SLACK_BOT_TOKEN, signing_secret=SLACK_SIGNING_SECRET)  # Bolt verifies the signature
options = ClaudeAgentOptions(
    mcp_servers={"hallpass": server},
    allowed_tools=["mcp__hallpass__check_permission", "mcp__hallpass__write_thing"],
)

@app.event("app_mention")
async def on_mention(event, client, say):
    info = await client.users_info(user=event["user"])   # the Slack user who wrote the message
    current_user.set(info["user"]["profile"]["email"])
    async for message in query(prompt=event["text"], options=options):
        ...                                              # post the answer with say(...)
```

Never take the user from the message text, a tool argument or anything else
the model or the requester can type.

With a long-lived `ClaudeSDKClient`, set `current_user` before `connect()`:
its tool calls run in the context it was connected in. Use one client per
user's conversation, never one shared between users.

## Frameworks

Every example below defines two tools: `check_permission`, so the model can
ask before proposing something, and a guarded `write_thing` action against
the `demo` connection of `examples/hallpass.yaml`, where `admin@example.com`
may write and `dana@example.com` may not. Replace `demo`, `thing.write` and
`thing:{thing_id}` with your connection, action and resource.

### LangChain

[`langchain_tool.py`](../examples/agent/langchain_tool.py)

```python
@tool
@guarded(hp, "demo", "thing.write", "thing:{thing_id}", user=current_user, groups=current_groups,
         deny=lambda e: f"refused: {e}")
def write_thing(thing_id: str, content: str) -> str:
    """Write content to a thing in the demo system."""
    ...

tools = [check_permission, write_thing]
```

```python
current_user.set(user.email)  # from your auth, see above
agent = create_agent(model, tools=tools)   # or any LangChain agent constructor
```

### LangGraph

[`langgraph_agent.py`](../examples/agent/langgraph_agent.py) uses the
LangChain tools unchanged. `create_agent` from LangChain 1.x is built on
LangGraph and gives a ready tool-calling loop; `ToolNode(tools)` is the same
tools as a node for a graph you assemble yourself.

```python
from langchain.agents import create_agent
from langgraph.prebuilt import ToolNode
from langchain_tool import current_user, tools

current_user.set(user.email)  # from your auth, see above
agent = create_agent("anthropic:claude-opus-5", tools=tools)
agent.invoke({"messages": [("user", "Write 'hello' to thing 1.")]})

tool_node = ToolNode(tools)  # for a hand-built StateGraph
```

### Strands Agents

[`strands_tool.py`](../examples/agent/strands_tool.py)

```python
from strands import Agent, tool

@tool
@guarded(hp, "demo", "thing.write", "thing:{thing_id}", user=current_user, groups=current_groups)
def write_thing(thing_id: str, content: str) -> str:
    """Write content to a thing in the demo system.

    Args:
        thing_id: the thing to write to
        content: what to write
    """
    ...

current_user.set(user.email)  # from your auth, see above
Agent(tools=[check_permission, write_thing])("Write 'hello' to thing 1.")
```

The tool schema Strands derives has only `thing_id` and `content`. A refusal
is reported to the model as a tool error with hallpass's reason.

### Claude Agent SDK

[`claude_agent_sdk_tool.py`](../examples/agent/claude_agent_sdk_tool.py)

The SDK hands a handler one dict of arguments; `guarded` formats the
resource from it.

```python
from claude_agent_sdk import ClaudeAgentOptions, create_sdk_mcp_server, query, tool

@tool("write_thing", "Write content to a thing in the demo system.", {"thing_id": str, "content": str})
@guarded(hp, "demo", "thing.write", "thing:{thing_id}", user=current_user, groups=current_groups)
async def write_thing(args: dict) -> dict:
    ...
    return {"content": [{"type": "text", "text": f"wrote to thing:{args['thing_id']}"}]}

server = create_sdk_mcp_server(name="hallpass", version="1.0.0", tools=[check_permission, write_thing])

current_user.set(user.email)  # from your auth, see above
options = ClaudeAgentOptions(
    mcp_servers={"hallpass": server},
    allowed_tools=["mcp__hallpass__check_permission", "mcp__hallpass__write_thing"],
)
async for message in query(prompt="Write 'hello' to thing 1.", options=options):
    ...
```

A refusal reaches the model as an `is_error` result with hallpass's reason.

### MCP server, for any host

[`mcp_server.py`](../examples/agent/mcp_server.py) is a standalone server
over stdio for Claude Code, Claude Desktop, Cursor or any other MCP host.
The host launches one process per user session and names the user in
`AGENT_USER`; the tools never take a user argument.

```python
mcp = MCPServer("hallpass")

@mcp.tool()
@guarded(hp, "demo", "thing.write", "thing:{thing_id}", user=AGENT_USER, groups=AGENT_GROUPS,
         deny=lambda e: f"refused: {e}")
def write_thing(thing_id: str, content: str) -> str:
    """Write content to a thing in the demo system."""
    ...
```

```sh
claude mcp add hallpass \
  -e HALLPASS_URL=http://localhost:8080 -e HALLPASS_API_KEY=change-me \
  -e AGENT_USER=dana@example.com \
  -- /path/to/.venv/bin/python /path/to/hallpass/examples/agent/mcp_server.py
```

Or in any host that takes an `mcpServers` JSON block:

```json
{
  "mcpServers": {
    "hallpass": {
      "command": "/path/to/.venv/bin/python",
      "args": ["/path/to/hallpass/examples/agent/mcp_server.py"],
      "env": {
        "HALLPASS_URL": "http://localhost:8080",
        "HALLPASS_API_KEY": "change-me",
        "AGENT_USER": "dana@example.com"
      }
    }
  }
}
```

`AGENT_GROUPS` (comma-separated) passes group memberships.

## TypeScript

[`examples/agent-ts/hallpass_client.ts`](../examples/agent-ts/hallpass_client.ts)
is the same client for Node, on the built-in `fetch` with no dependencies.
Copy it into your project. It follows the rules above to the letter: a
transport failure, a redirect, a non-JSON body or an `allow` with a non-200
status is an `unknown` decision with the code `client_error` (a 400 or 401
keeps hallpass's own reason), and `guarded` never reads the user from the
arguments.

```ts
import { Hallpass, current, guarded } from "./hallpass_client.ts";

const hp = new Hallpass(); // HALLPASS_URL and HALLPASS_API_KEY from the environment

const d = await hp.check("dana@example.com", "jira-main", "DELETE_ISSUES", "issue:PAY-123");
d.decision; // "allow", "deny" or "unknown"
d.allowed;  // true only for allow

await hp.require("dana@example.com", "jira-main", "DELETE_ISSUES", "issue:PAY-123");
// rejects with PermissionDenied unless the answer is allow

await hp.require("dana@example.com", "jira-main", "DELETE_ISSUES", "issue:PAY-123", { fresh: true });
// fresh: skips hallpass's caches and asks Jira now, for a destructive action
```

The fifth argument of `check`, `allowed` and `require` is the user's groups
or an options object, `{ groups, fresh }`, with the meaning described for
the Python client above.

Every Node agent framework calls a tool with one object of arguments, so
`guarded` wraps a function of that shape and returns one with the same
signature. The user comes from a string, a zero-argument function, or an
`AsyncLocalStorage` your request handler enters, the Node counterpart of
the `ContextVar` above. `resource` is the same `"issue:{key}"` template.

```ts
import { AsyncLocalStorage } from "node:async_hooks";

const session = new AsyncLocalStorage<{ user: string; groups?: string[] }>();
const user = () => current(session).user;
const groups = () => current(session).groups ?? [];

const deleteIssue = guarded(hp, "jira-main", "DELETE_ISSUES", "issue:{key}", { user, fresh: true })(
  async ({ key }: { key: string }) => {
    await jira.deleteIssue(key); // the agent's own credential
    return `deleted ${key}`;
  },
);

// In the request handler, from the identity your auth verified:
app.post("/chat", auth, (req, res) =>
  session.run({ user: req.user.email, groups: req.user.groups }, () => runAgent(req, res)));
```

A `user` key the model puts in the arguments is ignored; a call whose
arguments cannot fill the template makes no request and runs nothing.
`fresh: true` in the options makes every check ask the upstream system now,
right for a destructive tool like this one.

### Vercel AI SDK

[`ai_sdk_tool.ts`](../examples/agent-ts/ai_sdk_tool.ts)

```ts
import { generateText, tool } from "ai";
import { z } from "zod";

const writeThing = tool({
  description: "Write content to a thing in the demo system.",
  inputSchema: z.object({ thing_id: z.string(), content: z.string() }),
  execute: guarded(hp, "demo", "thing.write", "thing:{thing_id}", { user, groups, deny: (e) => `refused: ${e.message}` })(
    async ({ thing_id, content }: { thing_id: string; content: string }) => { ... },
  ),
});

const tools = { check_permission: checkPermission, write_thing: writeThing };
session.run({ user: req.user.email }, () => generateText({ model, tools, prompt }));
```

The schema the model sees has only `thing_id` and `content`; a `user` the
model sends anyway is stripped by the schema before `execute` runs. The
refusal is returned as the tool's output rather than thrown, so the model
reads hallpass's reason whatever the SDK does with a thrown error.
Anything that takes AI SDK tools (`streamText`, `ToolLoopAgent`, Mastra)
works the same way.

### MCP server in TypeScript, for any host

[`mcp_server.ts`](../examples/agent-ts/mcp_server.ts) is the TypeScript
version of the server above. The host launches one process per user session
and names the user in `AGENT_USER`; the tools never take a user argument. A
thrown `PermissionDenied` becomes an `isError` result carrying its message,
so the model learns why.

```ts
server.registerTool(
  "write_thing",
  { description: "Write content to a thing in the demo system.", inputSchema: { thing_id: z.string(), content: z.string() } },
  guarded(hp, "demo", "thing.write", "thing:{thing_id}", { user: AGENT_USER, groups: AGENT_GROUPS })(
    async ({ thing_id, content }: { thing_id: string; content: string }) => ({ content: [{ type: "text", text: `wrote to thing:${thing_id}` }] }),
  ),
);
```

```sh
claude mcp add hallpass \
  -e HALLPASS_URL=http://localhost:8080 -e HALLPASS_API_KEY=change-me \
  -e AGENT_USER=dana@example.com \
  -- node /path/to/hallpass/examples/agent-ts/mcp_server.ts
```

Node 22.18 or later runs the `.ts` file directly.

## Running the examples

Start hallpass with the example config:

```sh
export HALLPASS_API_KEY=change-me
go run ./cmd/hallpass serve -config examples/hallpass.yaml
```

Install the frameworks and run the tests, which drive every example through
its framework's own tool-invocation path against a fake hallpass:

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install -r examples/agent/requirements.txt
python3 -m unittest discover -s examples/agent -v
```

The TypeScript examples have their own tests, through `generateText` with a
mock model and through an MCP client over an in-memory transport:

```sh
cd examples/agent-ts && npm ci && npm test
```

Without the Python frameworks installed the client tests still run and the rest
skip. Each example also runs as a script against the live server; the
LangGraph, Strands and Claude Agent SDK ones need a model provider
configured, the others need none:

```sh
export HALLPASS_URL=http://localhost:8080 HALLPASS_API_KEY=change-me
python examples/agent/langchain_tool.py dana@example.com    # tools called directly, no LLM
python examples/agent/langchain_tool.py admin@example.com
node examples/agent-ts/ai_sdk_tool.ts dana@example.com     # same, in TypeScript
```

The tests assert, for each framework, that the tool schema has no `user`
field, that a `user` the model sends anyway does not change who is checked,
that `deny` and `unknown` stop the action, and that `allow` runs it.
