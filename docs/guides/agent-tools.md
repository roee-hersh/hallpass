# Add hallpass to your agent

Your agent acts in other systems with its own credential. This guide adds one check in front of
each tool that changes something, so the tool runs only when the person asking is allowed to do
it themselves.

You need a running hallpass. The [quickstart](../quickstart.md) starts one with a `demo`
connection in which `admin@example.com` may write and `dana@example.com` may not.

## 1. Install the client

```sh
pip install hallpass-client     # Python
npm install hallpass-client     # Node
```

Set `HALLPASS_URL` and `HALLPASS_API_KEY` in the agent's environment.

## 2. Decide which tools to guard

Guard the tools that change state, and only those.

- **Reads stay unguarded.** Give the agent a read-only account for looking at things, and let it
  read freely. A check on every read adds a round trip and nothing else.
- **Each write tool gets one check**, just before it acts.
- **Fewer write tools is better.** If the agent changes production only by opening a pull request,
  there is one tool to guard, and the merge stays with your reviewers.

For example, an ops agent with one read tool and one write tool:

```python
@tool
def service_health(service: str) -> str:
    """Errors, metrics, events and restarts for a service."""
    ...  # read-only account, no check

@tool
@guarded(hp, "github-main", "repo.push", "repo:{owner}/{repo}", user=current_user, fresh=True)
def open_config_pr(owner: str, repo: str, title: str, patch: str) -> str:
    """Push a branch with the change and open a pull request."""
    ...  # runs only if GitHub says this user may push to the repository
```

Ask about what the tool really does. This tool pushes a branch, so it asks for `repo.push`.
`pr.create` would be too weak: GitHub lets a user with read access open a pull request from a fork.

Use `fresh=True` on tools with lasting effect (delete, merge, scale, push). It makes hallpass ask
the system now instead of reusing a cached answer.

## 3. Set the user from your login, not from the model

The user must come from your own authentication: the SSO session, the Slack user who wrote the
message. Never from a tool argument or the message text, because the model writes those and could
be talked into writing an admin's email.

Set it where you handle the request, before the agent runs:

```python
from contextvars import ContextVar

current_user: ContextVar[str] = ContextVar("current_user")

@app.post("/chat")
async def chat(body: ChatIn, user: User = Depends(authenticated_user)):  # your auth
    current_user.set(user.email)
    agent = Agent(tools=tools)          # one agent per request
    return {"reply": str(await agent.invoke_async(body.message))}
```

In a Slack bot, take the user from the event Slack signed:

```python
@app.event("app_mention")
async def on_mention(event, client, say):
    info = await client.users_info(user=event["user"])  # needs the users:read.email scope
    current_user.set(info["user"]["profile"]["email"])
    ...  # run the agent
```

In a shared thread, the user is whoever wrote the message the agent is acting on, not whoever
started the thread.

In Node, use `AsyncLocalStorage` the same way:
`currentUser.run(req.user.email, () => runAgent(...))`.

## 4. Wrap the write tool

Put `guarded` directly under your framework's tool decorator:

```python
from hallpass_client import Hallpass, guarded

hp = Hallpass()

@tool
@guarded(hp, "jira-main", "DELETE_ISSUES", "issue:{key}", user=current_user, fresh=True)
def delete_issue(key: str) -> str:
    """Delete a Jira issue."""
    jira.delete_issue(key)  # the agent's own credential
    return f"deleted {key}"
```

- `"jira-main"` is the connection id in `hallpass.yaml`.
- `"DELETE_ISSUES"` is the action. `hallpass catalog jira` lists them.
- `"issue:{key}"` builds the resource from the tool's arguments.

If the answer is not `allow`, the body never runs and `PermissionDenied` is raised. That includes
`unknown` and hallpass being unreachable. The tool's signature does not change, so the model never
sees a `user` field.

## 5. Tell the model why

The refusal text names the user, the action and hallpass's reason, so the model can explain it to
the person. Some frameworks hide exception text from the model, so for those, return the refusal
instead of raising it, with `deny=`:

```python
@guarded(..., deny=lambda e: f"refused: {e}")
```

| Framework | Use |
|---|---|
| LangChain, LangGraph | `deny=` (an unexpected exception ends the run) |
| MCP server (`mcp` package) | `deny=` (the server hides exception text) |
| Strands Agents | raise (reported as a tool error with the text) |
| Claude Agent SDK | raise (reported as an `is_error` result with the text) |
| Vercel AI SDK | `deny:` (so the model reads the reason whatever the SDK does with errors) |
| MCP TypeScript SDK | raise (becomes an `isError` result with the text) |

## Framework recipes

Each recipe is a complete, tested file. They define two tools against the `demo` connection:
`check_permission`, so the model can ask before proposing something, and a guarded `write_thing`.

| Framework | File | Notes |
|---|---|---|
| LangChain | [`langchain_tool.py`](../../examples/agent/langchain_tool.py) | `@tool` over `guarded`, with `deny=` |
| LangGraph | [`langgraph_agent.py`](../../examples/agent/langgraph_agent.py) | the LangChain tools in `create_agent` or a `ToolNode` |
| Strands Agents | [`strands_tool.py`](../../examples/agent/strands_tool.py) | `@tool` over `guarded` |
| Claude Agent SDK | [`claude_agent_sdk_tool.py`](../../examples/agent/claude_agent_sdk_tool.py) | handler takes `args: dict`; see below |
| MCP server, any host | [`mcp_server.py`](../../examples/agent/mcp_server.py) | user from `AGENT_USER`; see below |
| Vercel AI SDK | [`ai_sdk_tool.ts`](../../examples/agent-ts/ai_sdk_tool.ts) | `guarded(...)` as the tool's `execute` |
| MCP TypeScript SDK | [`mcp_server.ts`](../../examples/agent-ts/mcp_server.ts) | user from `AGENT_USER` |

**Claude Agent SDK.** The handler receives one dict, and `guarded` reads the resource from it.
With a long-lived `ClaudeSDKClient`, set the user before `connect()` and use one client per user.

```python
@tool("write_thing", "Write content to a thing.", {"thing_id": str, "content": str})
@guarded(hp, "demo", "thing.write", "thing:{thing_id}", user=current_user)
async def write_thing(args: dict) -> dict:
    ...
    return {"content": [{"type": "text", "text": f"wrote to thing:{args['thing_id']}"}]}
```

**Vercel AI SDK.**

```ts
const writeThing = tool({
  description: "Write content to a thing.",
  inputSchema: z.object({ thing_id: z.string(), content: z.string() }),
  execute: guarded(hp, "demo", "thing.write", "thing:{thing_id}", { user, deny: (e) => `refused: ${e.message}` })(
    async ({ thing_id, content }) => { ... },
  ),
});
```

**MCP servers** (Claude Code, Claude Desktop, Cursor and other hosts). The host starts one server
process per user and names the user in its environment, so the tools never take a user argument:

```sh
pip install hallpass-client "mcp>=2,<3"
claude mcp add hallpass \
  -e HALLPASS_URL=http://localhost:8080 -e HALLPASS_API_KEY=change-me \
  -e AGENT_USER=dana@example.com \
  -- python /path/to/hallpass/examples/agent/mcp_server.py
```

`AGENT_GROUPS` (comma-separated) passes group memberships. The TypeScript server runs the same way
with `node /path/to/hallpass/examples/agent-ts/mcp_server.ts` (Node 22.18 or later).

## Run the examples

From a clone of the repository, install the examples' dependencies first:

```sh
pip install -e ./sdk/python -r examples/agent/requirements.txt
(cd examples/agent-ts && npm ci)
```

Then start hallpass and call the tools:

```sh
export HALLPASS_API_KEY=change-me
go run ./cmd/hallpass serve -config examples/hallpass.yaml      # or the Docker command from the quickstart

export HALLPASS_URL=http://localhost:8080
python examples/agent/langchain_tool.py dana@example.com        # refused
python examples/agent/langchain_tool.py admin@example.com       # allowed
node examples/agent-ts/ai_sdk_tool.ts dana@example.com
```

These call the tools directly, with no model. The LangGraph, Strands and Claude Agent SDK
examples run a prompt through a model when you run them, so they need a provider configured.

The tests drive every example through its framework's own tool path and check that the schema has
no `user` field, that a `user` sent anyway changes nothing, that `deny` and `unknown` stop the
action, and that `allow` runs it:

```sh
python3 -m unittest discover -s examples/agent -v
cd examples/agent-ts && npm test
```

## Checklist

- [ ] Only write tools are guarded, one check each, with `fresh=True` where the effect lasts.
- [ ] The user comes from your authentication, set per request, never from the model.
- [ ] Anything other than `allow` stops the tool, including hallpass being unreachable.
- [ ] The model gets the refusal text, so it can tell the person why.
- [ ] Only the tool layer holds the hallpass API key.

Every client option, the `guarded` parameters and the write log line are in the
[client reference](../reference/client.md).
