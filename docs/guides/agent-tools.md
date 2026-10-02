# Add toolpass to your agent

Your agent acts in other systems with its own credential. This guide adds one check in front of
each tool that changes something, so the tool runs only when the person asking is allowed to do
it themselves.

The examples use the `demo` connection of [`examples/toolpass.yaml`](../../examples/toolpass.yaml),
in which `admin@example.com` may write and `dana@example.com` may not. The
[quickstart](../quickstart.md) shows it working.

## 1. Install

```sh
pip install "toolpass[strands]"   # or [langchain], [mcp], [openai-agents], [claude-agent-sdk],
                                  # [google-adk], [crewai], [pydantic-ai], [llamaindex]
npm install toolpass-client       # Node, talking to a toolpass server
```

Then make one `Toolpass` for the process:

```python
from toolpass import Toolpass

tp = Toolpass.from_config("toolpass.yaml")     # the engine in this process
tp = Toolpass.remote(url, api_key)             # or a toolpass server (TOOLPASS_URL, TOOLPASS_API_KEY)
```

In-process, the agent's process holds toolpass's lookup credentials; with a server, it holds only
the API key. [Deploy](deploy.md#pick-a-topology) helps you choose. Everything below works the same
with either.

## 2. Decide which tools to guard

Guard the tools that change state, and only those.

- **Reads stay unguarded.** Give the agent a read-only account for looking at things, and let it
  read freely. A check on every read adds a lookup and nothing else.
- **Each write tool gets one check**, just before it acts.
- **Fewer write tools is better.** If the agent changes production only by opening a pull request,
  there is one tool to guard, and the merge stays with your reviewers.

For example, an ops agent with one read tool and one write tool:

```python
from toolpass.strands import ToolpassAuthorization, Rule

toolpass = ToolpassAuthorization(tp, {
    # service_health has no rule: it reads with a read-only account and runs unchecked
    "open_config_pr": Rule("github-main", "repo.push", "repo:{owner}/{repo}", fresh=True),
})
```

Ask about what the tool really does. `open_config_pr` pushes a branch, so it asks for `repo.push`.
`pr.create` would be too weak: GitHub lets a user with read access open a pull request from a fork.

Use `fresh=True` on tools with lasting effect (delete, merge, scale, push). It makes toolpass ask
the system now instead of reusing a cached answer.

## 3. Set the user from your login, not from the model

The user must come from your own authentication: the SSO session, the Slack user who wrote the
message. Never from a tool argument or the message text, because the model writes those and could
be talked into writing an admin's email.

Every adapter reads the user from something your application passes and the model cannot write:
Strands' `invocation_state`, LangChain's runtime context, the OpenAI Agents run context, the ADK
session, CrewAI's kickoff inputs, Pydantic AI's `deps`, an MCP access token. Where the framework
has no such place (the Claude Agent SDK, LlamaIndex, `guarded`), it takes `user=`: a string, a
zero-argument callable, or a `ContextVar` you set where you handle the request, before the agent
runs:

```python
from contextvars import ContextVar

current_user: ContextVar[str] = ContextVar("current_user")

@app.post("/chat")
async def chat(body: ChatIn, user: User = Depends(authenticated_user)):  # your auth
    current_user.set(user.email)
    agent = Agent(tools=tools, interventions=[toolpass])          # one agent per request
    result = await agent.invoke_async(body.message, invocation_state={"user_id": user.email})
    return {"reply": str(result)}
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

## 4. Check the write tools

There are two ways, and both fail closed: anything but `allow` (including `unknown`, and a toolpass
server that cannot be reached) stops the call before the tool runs.

**An adapter**, configured once on the agent. It checks every call to a tool that has a rule, and
the tools need no decorator. This is the usual choice; the recipes below show each framework.

```python
toolpass = ToolpassAuthorization(tp, {
    "delete_issue": Rule("jira-main", "DELETE_ISSUES", "issue:{key}", fresh=True),
    "close_issue": ("jira-main", "TRANSITION_ISSUES", "issue:{key}"),  # a tuple works too
})
```

- `"jira-main"` is the connection id in `toolpass.yaml`.
- `"DELETE_ISSUES"` is the action. `toolpass catalog jira` lists them.
- `"issue:{key}"` builds the resource from the tool's input.

**`guarded`**, on one function, directly under your framework's tool decorator:

```python
from toolpass import guarded

@tool
@guarded(tp, "jira-main", "DELETE_ISSUES", "issue:{key}", user=current_user, fresh=True)
def delete_issue(key: str) -> str:
    """Delete a Jira issue."""
    jira.delete_issue(key)  # the agent's own credential
    return f"deleted {key}"
```

If the answer is not `allow`, the body never runs and `PermissionDenied` is raised. The tool's
signature does not change, so the model never sees a `user` field.

The adapters share these rules:

- A tool without a rule runs unchecked, so reads stay fast. With `strict=True` it is refused
  instead, and a rule of `None` names a tool that may run unchecked. Use `strict=True` when the
  agent loads tools you do not list yourself, such as MCP tools. A rule that names no tool of the
  agent is logged as a warning: it is usually a typo that leaves the real tool unchecked.
- Each field in a resource must be a plain `str` or `int` input of the tool, and the model's value
  must already have exactly that JSON type, so the resource toolpass checks is the one the tool
  gets (frameworks turn `"07"` into the integer 7). A field the model leaves out takes the tool's
  default.
- A missing user, a resource the input cannot fill, any answer but `allow`, and any error inside
  the check all refuse the call.
- Groups, for systems that grant by group: `groups_key=` (read like the user) or `groups=` (a
  source like `user=`), as the adapter's docstring says.
- Add the adapter after anything that rewrites tool calls (list it last among Strands
  interventions and LangChain middleware, call `guard` after other MCP middleware): a rewrite after
  the check changes what runs after toolpass checked it. A call moved to another tool is refused.
- After a checked tool has run, the adapter logs the
  [write log line](../reference/client.md#the-write-log-line) on the `toolpass` logger.

## 5. Tell the model why

The adapters give the model `toolpass refused this call: <reason>`, naming the user, the action and
toolpass's reason, as the tool's result, and the run goes on. The model can explain it to the
person.

With `guarded`, some frameworks hide exception text from the model. For those, return the refusal
instead of raising it, with `deny=`:

```python
@guarded(..., deny=lambda e: f"refused: {e}")
```

| Framework | With `guarded`, use |
|---|---|
| LangChain, LangGraph | `deny=` (an unexpected exception ends the run) |
| MCP server (`mcp` package) | `deny=` (the server hides exception text) |
| Strands Agents | raise (reported as a tool error with the text) |
| Claude Agent SDK | raise (reported as an `is_error` result with the text) |
| Vercel AI SDK | `deny:` (so the model reads the reason whatever the SDK does with errors) |
| MCP TypeScript SDK | raise (becomes an `isError` result with the text) |

## Framework recipes

Each Python recipe has a complete example in [`toolpass-py/examples`](../../toolpass-py/examples)
that runs the engine in-process on the `demo` connection and drives a real model; each adapter's
docstring has every option.

| Framework | Adapter | Example |
|---|---|---|
| Strands Agents | `toolpass.strands.ToolpassAuthorization` | [`strands_agent.py`](../../toolpass-py/examples/strands_agent.py) |
| LangChain, LangGraph | `toolpass.langchain.ToolpassMiddleware` | [`langchain_agent.py`](../../toolpass-py/examples/langchain_agent.py) |
| MCP servers, any host | `toolpass.mcp.guard` | [`mcp_server.py`](../../toolpass-py/examples/mcp_server.py) |
| OpenAI Agents SDK | `toolpass.openai_agents.ToolpassGuardrails` | [`openai_agents_agent.py`](../../toolpass-py/examples/openai_agents_agent.py) |
| Claude Agent SDK | `toolpass.claude_agent_sdk.ToolpassHooks` | [`claude_agent_sdk_agent.py`](../../toolpass-py/examples/claude_agent_sdk_agent.py) |
| Google ADK | `toolpass.google_adk.ToolpassCallbacks` | [`google_adk_agent.py`](../../toolpass-py/examples/google_adk_agent.py) |
| CrewAI | `toolpass.crewai.ToolpassHooks` | [`crewai_agent.py`](../../toolpass-py/examples/crewai_agent.py) |
| Pydantic AI | `toolpass.pydantic_ai.ToolpassAuthorization` | [`pydantic_ai_agent.py`](../../toolpass-py/examples/pydantic_ai_agent.py) |
| LlamaIndex | `toolpass.llamaindex.ToolpassAuthorization` | [`llamaindex_agent.py`](../../toolpass-py/examples/llamaindex_agent.py) |
| Vercel AI SDK (TypeScript) | `guarded` from `toolpass-client` | [`ai_sdk_tool.ts`](../../examples/agent-ts/ai_sdk_tool.ts) |
| MCP TypeScript SDK | `guarded` from `toolpass-client` | [`mcp_server.ts`](../../examples/agent-ts/mcp_server.ts) |

**Strands Agents** (`toolpass[strands]`). An intervention handler; it composes with Strands' other
interventions such as `CedarAuthorization`. The user is `invocation_state["user_id"]` (`user_key=`
names another key):

```python
from toolpass.strands import ToolpassAuthorization, Rule

toolpass = ToolpassAuthorization(tp, {
    "open_config_pr": Rule("github-main", "repo.push", "repo:{owner}/{repo}", fresh=True),
    "delete_issue": ("jira-main", "DELETE_ISSUES", "issue:{key}"),
})
agent = Agent(tools=tools, interventions=[toolpass])
agent(body.message, invocation_state={"user_id": user.email})  # from your auth, per request
```

**LangChain and LangGraph** (`toolpass[langchain]`). Agent middleware for `create_agent`. The user
is the runtime context's `user_id` (an attribute, or a key for a `TypedDict` context), or else
`user=`. A refusal is a `ToolMessage` with `status="error"`:

```python
from dataclasses import dataclass
from toolpass.langchain import ToolpassMiddleware, Rule

@dataclass
class Context:
    user_id: str

toolpass = ToolpassMiddleware(tp, {"delete_issue": Rule("jira-main", "DELETE_ISSUES", "issue:{key}", fresh=True)})
agent = create_agent(model, tools=tools, middleware=[toolpass], context_schema=Context)
agent.invoke({"messages": [...]}, context=Context(user_id=user.email))
```

For a LangGraph graph you assemble yourself, `toolpass.tool_node(tools)` is a `ToolNode` with the
same check.

**MCP servers** (`toolpass[mcp]`, the official `mcp` SDK v2 and its `MCPServer`). Server
middleware, whatever transport the call came over. The user is the authenticated access token's
`email` claim (`user_claim="sub"` for its subject), refused when the token says
`email_verified: false`; a request without a token (stdio, or HTTP without auth) uses `user=`. A refusal is a tool result with `isError: true`:

```python
from toolpass.mcp import Rule, guard

mcp = MCPServer("tools", token_verifier=verifier, auth=AuthSettings(...))

@mcp.tool()
def delete_issue(key: str) -> str: ...

guard(mcp, tp, {"delete_issue": Rule("jira-main", "DELETE_ISSUES", "issue:{key}", fresh=True)})
```

A stdio server serves one user, whom the host names when it starts the server. The example takes
it from `AGENT_USER`:

```sh
pip install "toolpass[mcp]"
claude mcp add toolpass -e AGENT_USER=dana@example.com \
  -- python /path/to/toolpass/toolpass-py/examples/mcp_server.py
```

The example runs the engine in-process on the `demo` connection. With real credentials, do not run
the engine inside a server a coding agent launches: an agent with shell access on your machine
could read toolpass's secrets. Run toolpass as a shared service behind TLS and use
`Toolpass.remote(...)` in the MCP server (see the [deploy guide](deploy.md)). The TypeScript server
runs the same way with `node /path/to/toolpass/examples/agent-ts/mcp_server.ts` (Node 22.18 or
later), with `TOOLPASS_URL`, `TOOLPASS_API_KEY`, `AGENT_USER` and, comma-separated, `AGENT_GROUPS`.

**OpenAI Agents SDK** (`toolpass[openai-agents]`). A tool input guardrail on every function tool;
`apply` returns a clone of the agent. The user is the run context's `user_id` (attribute or key),
or `user=`:

```python
from toolpass.openai_agents import ToolpassGuardrails, Rule

guard = ToolpassGuardrails(tp, {
    "delete_issue": Rule("jira-main", "DELETE_ISSUES", "issue:{key}", fresh=True),
    "get_issue": None,  # runs unchecked, even with strict=True
})
agent = guard.apply(Agent(name="ops", tools=[get_issue, delete_issue]))
await Runner.run(agent, prompt, context=RequestContext(user_id=user.email))
```

Only function tools have guardrails: a rule naming a hosted tool raises, and so does `strict=True`
on an agent with MCP servers. Apply the guardrails to each agent a handoff can reach.

**Claude Agent SDK** (`toolpass[claude-agent-sdk]`). A `PreToolUse` hook, which sees every tool
call, built-in or MCP. Rules use Claude Code's tool names: `mcp__<server>__<tool>`, or `Bash`,
`Write`, ... The user comes from `user=`; the SDK runs hooks in the task `query()` or
`ClaudeSDKClient.connect()` started, so set a `ContextVar` before that call:

```python
from toolpass.claude_agent_sdk import ToolpassHooks, Rule

toolpass = ToolpassHooks(tp, {
    "mcp__ops__delete_issue": Rule("jira-main", "DELETE_ISSUES", "issue:{key}", fresh=True),
}, user=current_user)
options = toolpass.apply(ClaudeAgentOptions(mcp_servers={"ops": server}, allowed_tools=[...]))

current_user.set(user.email)  # before query() or client.connect()
async for message in query(prompt=prompt, options=options): ...
```

An allowed call gets no decision from the hook, so Claude Code's own permission rules still apply
after toolpass. `guarded` also works on an SDK MCP tool's handler, whose one parameter is a dict of
arguments.

**Google ADK** (`toolpass[google-adk]`). A `before_tool_callback`, added last among the agent's own
and to its LLM sub-agents. The user is the session's `user_id`, which you pass to the runner, or
`user=`. A refusal answers `{"error": "toolpass refused this call: ..."}`:

```python
from toolpass.google_adk import ToolpassCallbacks, Rule

toolpass = ToolpassCallbacks(tp, {"delete_issue": Rule("jira-main", "DELETE_ISSUES", "issue:{key}", fresh=True)})
agent = toolpass.apply(LlmAgent(name="ops", model=..., tools=[get_issue, delete_issue]))
runner = InMemoryRunner(agent=agent)
session = await runner.session_service.create_session(app_name=runner.app_name, user_id=user.email)
```

`toolpass.plugin()` is the same check as an `App` plugin, for every agent at once; plugins run
before an agent's own callbacks, so do not combine it with callbacks that edit tool arguments.

**CrewAI** (`toolpass[crewai]`). A pair of `before_tool_call` and `after_tool_call` hooks. CrewAI
hooks are process-wide: registered, the rules apply to every crew until `unregister()`, or for the
`with` block. The user is the crew's kickoff input `user_id` (`user_input=`), or `user=` (use that
for `Agent.kickoff` without a crew):

```python
from toolpass.crewai import ToolpassHooks, Rule

with ToolpassHooks(tp, {"delete_issue": Rule("jira-main", "DELETE_ISSUES", "issue:{key}", fresh=True)}):
    crew.kickoff(inputs={"user_id": user.email, "topic": topic})
```

Rule names match the way CrewAI names tools to the model (`"Read Thing"` and `read_thing` are the
same tool).

**Pydantic AI** (`toolpass[pydantic-ai]`). A capability that wraps every tool the agent has in a
`ToolpassToolset`. The user is `deps.user` (attribute or key), and the groups `deps.groups` when
present, or `user=` and `groups=`. A refusal is a failed tool result (`ToolFailed`):

```python
from dataclasses import dataclass
from toolpass.pydantic_ai import ToolpassAuthorization, Rule

@dataclass
class Deps:
    user: str

toolpass = ToolpassAuthorization(tp, {"delete_issue": Rule("jira-main", "DELETE_ISSUES", "issue:{key}", fresh=True)})
agent = Agent(model, deps_type=Deps, tools=[delete_issue, read_issue], capabilities=[toolpass])
agent.run_sync(prompt, deps=Deps(user=user.email))
```

To check only some tools, wrap their toolset instead:
`Agent(model, toolsets=[ToolpassToolset(FunctionToolset([delete_issue]), tp, rules)])`.

**LlamaIndex** (`toolpass[llamaindex]`). LlamaIndex agents have no hook that can stop a tool call,
so `wrap` puts the check in each tool that has a rule. The user comes from `user=`; the workflow
runs in a copy of the caller's context, so set a `ContextVar` before `agent.run`. A refusal is a
`ToolOutput` with `is_error=True`:

```python
from toolpass.llamaindex import ToolpassAuthorization, Rule

toolpass = ToolpassAuthorization(tp, {"delete_issue": Rule("jira-main", "DELETE_ISSUES", "issue:{key}", fresh=True)},
                                 user=current_user)
agent = FunctionAgent(tools=toolpass.wrap([delete_issue, read_issue]), llm=llm)

current_user.set(user.email)  # before agent.run
await agent.run(prompt)
```

**Vercel AI SDK** (TypeScript, `toolpass-client`, against a toolpass server):

```ts
const writeThing = tool({
  description: "Write content to a thing.",
  inputSchema: z.object({ thing_id: z.string(), content: z.string() }),
  execute: guarded(tp, "demo", "thing.write", "thing:{thing_id}", { user, deny: (e) => `refused: ${e.message}` })(
    async ({ thing_id, content }) => { ... },
  ),
});
```

## Run the examples

From a clone of the repository, install toolpass with the framework's extra and the model provider
the example names in its docstring, then run it as dana (refused) and as the admin (allowed):

```sh
pip install -e "./toolpass-py[strands]" "strands-agents[anthropic]"
export ANTHROPIC_API_KEY=...
python toolpass-py/examples/strands_agent.py dana@example.com
python toolpass-py/examples/strands_agent.py admin@example.com
```

The Python examples need no toolpass server. The TypeScript examples talk to one:

```sh
export TOOLPASS_API_KEY=change-me
toolpass serve -config examples/toolpass.yaml       # or the Docker command from the quickstart

(cd examples/agent-ts && npm ci)
TOOLPASS_URL=http://localhost:8080 node examples/agent-ts/ai_sdk_tool.ts dana@example.com
```

The adapters' tests drive each framework's real agent loop, with a scripted model, against a real
in-process engine: a refused call does not run and the model reads why, an allowed one runs, and
the model cannot choose the user. With `ANTHROPIC_API_KEY` set, a live test per framework runs the same scenario with
Claude. Each file skips when its framework is not installed:

```sh
(cd toolpass-py && python -m pytest tests/frameworks -v)
(cd examples/agent-ts && npm test)
```

## Checklist

- [ ] Only write tools are checked, one check each, with `fresh=True` where the effect lasts.
- [ ] The user comes from your authentication, set per request, never from the model.
- [ ] Anything other than `allow` stops the tool, including a toolpass server that cannot be reached.
- [ ] The model gets the refusal text, so it can tell the person why.
- [ ] The lookup credentials are where you decided they should be: in the agent's process, or only
      in the toolpass server, with the API key held only by the tool layer.

Every `Toolpass` method, the `guarded` parameters and the write log line are in the
[Python API reference](../reference/client.md).
