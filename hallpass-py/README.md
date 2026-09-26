# hallpass

Permission checks for AI agents and bots, answered live by the system they act in.

Before your agent acts for a user (delete a Jira issue, push to a repository, scale a deployment),
ask hallpass whether that user may do it. hallpass asks the system that owns the resource, live,
with its own read-only credential, and answers `allow`, `deny` or `unknown`. It only checks; it
never performs the action. Twenty-one systems are supported: Kubernetes, Argo CD, GitHub, GitLab,
Bitbucket, Jira, Confluence, Slack, Datadog, PagerDuty, AWS, Google Workspace, Google Cloud,
Microsoft 365, Databricks, Salesforce, Snowflake, Vault, Azure, Linear and Zendesk.

```sh
pip install hallpass
```

Python 3.10 or later. The core depends only on PyYAML. The engine runs in your process, so there is
no service to deploy; the same package also runs it as a server (`hallpass serve`).

## In-process

From a hallpass YAML file ([example](https://github.com/roee-hersh/hallpass/blob/main/examples/hallpass.yaml),
[reference](https://github.com/roee-hersh/hallpass/blob/main/docs/reference/configuration.md)):

```python
from hallpass import Hallpass

hp = Hallpass.from_config("hallpass.yaml")

d = hp.check("dana@example.com", "jira-main", "DELETE_ISSUES", "issue:PAY-123")
d.decision  # "allow", "deny" or "unknown"
d.reason    # "denied: Dana Levi does not hold DELETE_ISSUES on issue PAY-123"
d.allowed   # True only for allow

hp.allowed(...)                # True or False
hp.require(..., fresh=True)    # the decision on allow; raises PermissionDenied otherwise
await hp.acheck(...)           # check and require for async code
await hp.arequire(...)
```

Or with the connections in code, as mappings with exactly the keys of the file. A secret key takes
`hallpass.env("NAME")`, `hallpass.file("/path")`, `hallpass.literal(value)`, or the file's
`"env:NAME"` and `"file:/path"` strings:

```python
import hallpass

hp = hallpass.Hallpass(connections=[
    {"id": "jira-main", "integration": "jira", "url": "https://acme.atlassian.net",
     "username": "hallpass-bot@acme.com", "credential": hallpass.env("JIRA_TOKEN")},
])
```

`check` never raises for a failed lookup: a timeout, a rejected credential or anything else hallpass
cannot evaluate is `unknown`. Treat `unknown` exactly like `deny`.

## Remote

To keep the lookup credentials out of the agent's process, run hallpass as a server (the
`ghcr.io/roee-hersh/hallpass` image, the Helm chart, or `hallpass serve -config hallpass.yaml`) and
ask it:

```python
hp = Hallpass.remote("https://hallpass.internal", api_key)  # or HALLPASS_URL and HALLPASS_API_KEY
```

The methods are the same. The URL must be `https://`, or `http://` on localhost; redirects are not
followed; a server that cannot be reached is `unknown`.

## guarded

Puts the check in front of one function, so its body runs only after hallpass said `allow`:

```python
from contextvars import ContextVar
from hallpass import guarded

current_user: ContextVar[str] = ContextVar("current_user")  # set from your login, per request

@tool  # any framework's decorator
@guarded(hp, "jira-main", "DELETE_ISSUES", "issue:{key}", user=current_user, fresh=True)
def delete_issue(key: str) -> str:
    jira.delete_issue(key)  # the agent's own credential, only after allow
    return f"deleted {key}"
```

The user comes from `user=` (a string, a zero-argument callable or a `ContextVar`), never from the
call's arguments, so the model cannot choose who it acts as. Anything but `allow` raises
`PermissionDenied` before the body runs; `deny=` returns a message instead.

## Framework adapters

Each adapter is configured once on the agent with rules, a tool name to `Rule(connection, action,
resource)` or a `(connection, action, resource)` tuple, and checks every call to a tool with a rule
before it runs. A refused call does not run; the model reads `hallpass refused this call: <reason>`
and the run goes on. The user always comes from the application, never from the model. A tool
without a rule runs unchecked, unless `strict=True`.

**Strands Agents**: an intervention handler; the user from `invocation_state`.

```python
from hallpass.strands import HallpassAuthorization, Rule

hallpass = HallpassAuthorization(hp, {"delete_issue": Rule("jira-main", "DELETE_ISSUES", "issue:{key}", fresh=True)})
agent = Agent(tools=tools, interventions=[hallpass])
agent(prompt, invocation_state={"user_id": user.email})
```

**LangChain and LangGraph**: agent middleware; the user from the runtime context.

```python
from hallpass.langchain import HallpassMiddleware, Rule

hallpass = HallpassMiddleware(hp, {"delete_issue": Rule("jira-main", "DELETE_ISSUES", "issue:{key}")})
agent = create_agent(model, tools=tools, middleware=[hallpass], context_schema=Context)
agent.invoke({"messages": [...]}, context=Context(user_id=user.email))
# a graph you build yourself: hallpass.tool_node(tools) is a checked ToolNode
```

**MCP servers** (the `mcp` SDK v2): server middleware; the user from the access token's `email`
claim, or `user=` for stdio.

```python
from hallpass.mcp import Rule, guard

guard(mcp, hp, {"delete_issue": Rule("jira-main", "DELETE_ISSUES", "issue:{key}")})
```

**OpenAI Agents SDK**: tool guardrails; the user from the run context's `user_id`.

```python
from hallpass.openai_agents import HallpassGuardrails, Rule

agent = HallpassGuardrails(hp, {"delete_issue": Rule("jira-main", "DELETE_ISSUES", "issue:{key}")}).apply(agent)
await Runner.run(agent, prompt, context=RequestContext(user_id=user.email))
```

**Claude Agent SDK**: a `PreToolUse` hook; the user from `user=`. Rules use Claude Code's tool names.

```python
from hallpass.claude_agent_sdk import HallpassHooks, Rule

hallpass = HallpassHooks(hp, {"mcp__ops__delete_issue": Rule("jira-main", "DELETE_ISSUES", "issue:{key}")}, user=current_user)
options = hallpass.apply(ClaudeAgentOptions(mcp_servers={"ops": server}))
```

**Google ADK**: tool callbacks (or `.plugin()` for an `App`); the user is the session's `user_id`.

```python
from hallpass.google_adk import HallpassCallbacks, Rule

agent = HallpassCallbacks(hp, {"delete_issue": Rule("jira-main", "DELETE_ISSUES", "issue:{key}")}).apply(agent)
```

**CrewAI**: process-wide tool-call hooks; the user from the crew's kickoff `inputs`.

```python
from hallpass.crewai import HallpassHooks, Rule

with HallpassHooks(hp, {"delete_issue": Rule("jira-main", "DELETE_ISSUES", "issue:{key}")}):
    crew.kickoff(inputs={"user_id": user.email})
```

**Pydantic AI**: a capability (or `HallpassToolset` around one toolset); the user from `deps.user`.

```python
from hallpass.pydantic_ai import HallpassAuthorization, Rule

agent = Agent(model, deps_type=Deps, tools=tools,
              capabilities=[HallpassAuthorization(hp, {"delete_issue": Rule("jira-main", "DELETE_ISSUES", "issue:{key}")})])
agent.run_sync(prompt, deps=Deps(user=user.email))
```

**LlamaIndex**: wrapped tools; the user from `user=`.

```python
from hallpass.llamaindex import HallpassAuthorization, Rule

hallpass = HallpassAuthorization(hp, {"delete_issue": Rule("jira-main", "DELETE_ISSUES", "issue:{key}")}, user=current_user)
agent = FunctionAgent(tools=hallpass.wrap(tools), llm=llm)
```

Complete, runnable examples:
[hallpass-py/examples](https://github.com/roee-hersh/hallpass/tree/main/hallpass-py/examples). Each
adapter's docstring and the
[agent guide](https://github.com/roee-hersh/hallpass/blob/main/docs/guides/agent-tools.md) cover
groups, `strict`, and what each framework does with a refusal.

## Extras

| Extra | Adds |
|---|---|
| `hallpass[crypto]` | `cryptography`, for the integrations that sign with a private key: GitHub App, Google service accounts, Snowflake key pair, Salesforce JWT, Microsoft 365 certificates |
| `hallpass[strands]` | `strands-agents`, for `hallpass.strands` |
| `hallpass[langchain]` | `langchain` and `langgraph`, for `hallpass.langchain` |
| `hallpass[mcp]` | `mcp`, for `hallpass.mcp` |
| `hallpass[openai-agents]` | `openai-agents`, for `hallpass.openai_agents` |
| `hallpass[claude-agent-sdk]` | `claude-agent-sdk`, for `hallpass.claude_agent_sdk` |
| `hallpass[google-adk]` | `google-adk`, for `hallpass.google_adk` |
| `hallpass[pydantic-ai]` | `pydantic-ai-slim`, for `hallpass.pydantic_ai` |
| `hallpass[crewai]` | `crewai`, for `hallpass.crewai` |
| `hallpass[llamaindex]` | `llama-index-core`, for `hallpass.llamaindex` |

## The command

The package installs `hallpass`:

```sh
hallpass validate -config hallpass.yaml      # the file, references, certificates; no network
hallpass probe    -config hallpass.yaml      # each connection's credential, live
hallpass check    -config hallpass.yaml -connection jira-main \
  -user dana@example.com -action DELETE_ISSUES -resource issue:PAY-123
hallpass catalog  jira                       # an integration's keys and actions
hallpass serve    -config hallpass.yaml      # POST /check and GET /healthz on :8080
```

## More

- [Documentation](https://github.com/roee-hersh/hallpass/tree/main/docs), including one page per
  integration with the credential to create.
- [Architecture and trust boundaries](https://github.com/roee-hersh/hallpass/blob/main/docs/concepts/architecture.md).
- `hallpass-client` on PyPI, the old Python client, is replaced by this package and gets no new
  releases; installed versions keep working. To move, depend on `hallpass` and change
  `from hallpass_client import Hallpass` / `Hallpass()` to `from hallpass import Hallpass` /
  `Hallpass.remote()` (and `hallpass_client.strands` to `hallpass.strands`).

Apache-2.0.
