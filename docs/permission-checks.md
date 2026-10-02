# Permission checks

> This page covers toolpass's permission engine (`Toolpass`, `guarded`, `toolpass serve`). It works on
> its own, and inside [toolpass's secure tools](../README.md) as `permission_check`.

[![ci](https://github.com/roee-hersh/toolpass/actions/workflows/ci.yaml/badge.svg)](https://github.com/roee-hersh/toolpass/actions/workflows/ci.yaml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](../LICENSE)

**Permission checks for AI agents and bots, answered live by the system they act in.**

![toolpass demo: an admin is allowed, dana is denied, an unknown user is denied](assets/demo.svg)

toolpass is a small Python package that answers one question, in your agent's process or as a
self-hosted service:

> May user X do action Y on resource Z in system C?

Your AI agent acts with its own permissions, not the user's. It calls Jira, GitHub or Kubernetes
with its own bot credential, which can usually do more than the person asking. When Dana asks it to
do something she isn't allowed to do, the agent can, because its token can. Dana is logged in and
the agent knows who she is; the problem is that the bot's permissions get checked instead of hers.
This is the [confused deputy problem](https://en.wikipedia.org/wiki/Confused_deputy_problem).

The structural fix is to have the agent act with the user's own credentials
([capability-based security](https://en.wikipedia.org/wiki/Capability-based_security)); use it when
every system you touch supports it. When it doesn't, toolpass guards against the problem for every
tool you guard. Before the agent acts, it asks toolpass, and toolpass asks the system itself, live,
with its own read-only credential, whether this user may do this. The answer is `allow`, `deny` or
`unknown`, and the agent acts only on `allow`. toolpass only checks and never performs the action.
A tool you don't guard still runs with the agent's full permissions. See
[toolpass and the structural fix](concepts/architecture.md#toolpass-and-the-structural-fix).

## Why

toolpass came out of an ops agent that runs at work. One tool call gives it a service's health from
every angle (error counts, metrics, Kubernetes events, pod restarts, node status) in a few seconds,
so it reads everything, with a read-only account, and nobody gates the reads. It changes things one
way only: by opening a pull request against the GitOps repository. That single write path raised a
question the agent could not answer on its own: may the *person asking* open that pull request in
that repository? The agent's token could, whoever asked. GitHub already knows the answer, so the
agent asks GitHub. toolpass is that question, pulled out of the agent so every write path can use
it, in every system the agent touches.

The general form: an agent or chat bot holds one credential that covers everything anyone uses it
for. When Dana asks it to delete a Jira issue or scale a deployment, the bot can, even when Dana
could not. Copying every system's permission model into your own policy engine drifts out of date
the day you write it. toolpass asks the source of truth instead: Kubernetes `SubjectAccessReview`,
Jira's permission API, GitHub collaborator roles, AWS IAM policy simulation, and so on. One API,
twenty-one systems, no synced copy of anyone's permissions.

```mermaid
sequenceDiagram
    actor Dana
    participant Agent as Your agent or bot
    participant HP as toolpass
    participant Sys as Jira / K8s / GitHub / ...
    Dana->>Agent: "delete issue PAY-123"
    Agent->>HP: check(dana, jira-main, DELETE_ISSUES, issue:PAY-123)
    HP->>Sys: may dana do this? (read-only credential)
    Sys-->>HP: no
    HP-->>Agent: deny
    Agent-->>Dana: "You don't have permission to do that."
```

- **Read-only.** It only checks and never performs the action.
- **Fails closed.** Anything it cannot evaluate is `unknown`, not `allow`.
- **One Python package, in-process or as a server.** `pip install toolpass` runs the checks inside
  your agent; `toolpass serve` runs the same engine as an HTTP service. The core depends only on
  PyYAML. One YAML file, no database.

## How it differs from OPA, Cedar, OpenFGA and OAuth

| | Where the rules live | What you maintain | Fits |
|---|---|---|---|
| **OPA / Cedar** | Policies you write, over data you feed in | The policy, and a sync of each system's roles into that data | Rules of your own application |
| **OpenFGA / SpiceDB** | A relationship store you write tuples into | The tuples, kept in step with every system | Your own application's object graph |
| **Per-user OAuth** | The system itself, through the user's own token | Every user connecting every system; the agent holding their tokens | Systems that support it, for users who will connect |
| **toolpass** | The system itself, through one lookup credential | One credential per system, nothing to sync | Permissions that already exist in Jira, GitHub, AWS, Kubernetes, ... |

toolpass has no policy language and stores no rules. It asks the system that owns the resource,
at call time, and passes the answer through. Use it next to a policy engine, not instead of one:
OPA or Cedar for the rules of your own product, toolpass for what a person may do in systems you
do not control. Where a system supports acting with the user's own token, prefer that; toolpass
covers the many that do not, and the agents that cannot ask every user to connect every tool.

## Security model

- **The agent is an untrusted deputy.** What its own credential can do never decides anything.
- **The user comes from your session, never from the model.** The tool layer passes the user it
  authenticated; `guarded` binds it when the tool is built.
- **Fails closed.** `deny`, `unknown` and an unreachable toolpass all mean the tool does not run.
- **Read-only, per resource, from the source of truth.** Each check is answered live by the system
  that owns the resource, with a credential that is read-only wherever the product allows it.
- **The lookup credentials can stay out of the agent.** The agent keeps its own credential to act.
  Asking what *another* user may do takes different, more sensitive access: it reveals what anyone
  may do, and in Jira it needs Administer Jira. In-process, the agent's process holds those
  credentials. Run toolpass as a server in its own container or service, with the credentials
  mounted only there, and the agent's process never holds them.
- **Every decision is logged** as a JSON line, with the upstream calls it was based on.

Not goals: approving changes, making check and action atomic, or proving who the user is.
[Architecture](concepts/architecture.md) explains each boundary.

## Quickstart

```sh
pip install toolpass
curl -sO https://raw.githubusercontent.com/roee-hersh/toolpass/main/examples/toolpass.yaml
```

The example config has a `demo` connection that talks to nothing. Ask it, in-process:

```python
from toolpass import Toolpass

tp = Toolpass.from_config("toolpass.yaml")
d = tp.check("dana@example.com", "demo", "thing.write", "thing:1")
print(d.decision, d.reason)  # deny denied: dana@example.com is not an admin
```

Then guard a tool, so it runs only after toolpass said `allow`:

```python
from contextvars import ContextVar
from toolpass import guarded

current_user: ContextVar[str] = ContextVar("current_user")  # your app sets it per session

@tool  # LangChain, Strands, MCPServer, ...
@guarded(tp, "jira-main", "DELETE_ISSUES", "issue:{key}", user=current_user)
def delete_issue(key: str) -> str:
    jira.delete_issue(key)  # the agent's own credential, only after allow
    return f"deleted {key}"
```

To keep the lookup credentials out of the agent, run the same engine as a server:

```sh
docker run --rm -p 8080:8080 -e TOOLPASS_API_KEY=change-me \
  -v "$PWD/toolpass.yaml:/etc/toolpass/toolpass.yaml:ro" ghcr.io/roee-hersh/toolpass
```

```sh
curl -X POST localhost:8080/check -H 'Authorization: Bearer change-me' \
  -d '{"user":"dana@example.com","connection":"demo","action":"thing.write","resource":"thing:1"}'
```

```json
{"decision":"deny","reason":"denied: dana@example.com is not an admin"}
```

Then change one line in the agent, `tp = Toolpass.remote("http://localhost:8080", api_key)`. The
methods and `guarded` stay the same. From Node, `npm install toolpass-client` talks to the server.

The [quickstart](quickstart.md) walks through all of it, including connecting a real system.
Each framework has an adapter that checks every tool call with a rule, configured once on the
agent, and a working example:

| Framework | Adapter | Example |
|---|---|---|
| Strands Agents | `toolpass.strands.ToolpassAuthorization` | [`strands_agent.py`](../toolpass-py/examples/strands_agent.py) |
| LangChain, LangGraph | `toolpass.langchain.ToolpassMiddleware` | [`langchain_agent.py`](../toolpass-py/examples/langchain_agent.py) |
| MCP servers (`mcp` SDK), for any host | `toolpass.mcp.guard` | [`mcp_server.py`](../toolpass-py/examples/mcp_server.py) |
| OpenAI Agents SDK | `toolpass.openai_agents.ToolpassGuardrails` | [`openai_agents_agent.py`](../toolpass-py/examples/openai_agents_agent.py) |
| Claude Agent SDK | `toolpass.claude_agent_sdk.ToolpassHooks` | [`claude_agent_sdk_agent.py`](../toolpass-py/examples/claude_agent_sdk_agent.py) |
| Google ADK | `toolpass.google_adk.ToolpassCallbacks` | [`google_adk_agent.py`](../toolpass-py/examples/google_adk_agent.py) |
| CrewAI | `toolpass.crewai.ToolpassHooks` | [`crewai_agent.py`](../toolpass-py/examples/crewai_agent.py) |
| Pydantic AI | `toolpass.pydantic_ai.ToolpassAuthorization` | [`pydantic_ai_agent.py`](../toolpass-py/examples/pydantic_ai_agent.py) |
| LlamaIndex | `toolpass.llamaindex.ToolpassAuthorization` | [`llamaindex_agent.py`](../toolpass-py/examples/llamaindex_agent.py) |
| Vercel AI SDK (TypeScript) | `guarded` from `toolpass-client` | [`ai_sdk_tool.ts`](../examples/agent-ts/ai_sdk_tool.ts) |
| MCP TypeScript SDK | `guarded` from `toolpass-client` | [`mcp_server.ts`](../examples/agent-ts/mcp_server.ts) |

## Integrations

Kubernetes, Argo CD, GitHub, GitLab, Bitbucket, Jira, Confluence, Slack, Datadog, PagerDuty, AWS,
Google Workspace, Google Cloud, Microsoft 365, Databricks, Salesforce, Snowflake, Vault, Azure,
Linear and Zendesk. Kubernetes and Argo CD are tested against the real thing in CI; the rest
against the vendors' published API descriptions, and six are marked beta.
[The integrations page](integrations/README.md) has the status of each and one page per system.

## Documentation

| | |
|---|---|
| [Quickstart](quickstart.md) | Run it, ask a question, guard a tool |
| [Architecture](concepts/architecture.md) | How a check flows, caching, trust boundaries |
| [Deploy](guides/deploy.md) | In-process or a server: Docker, pip, Kubernetes with Helm, TLS, production checklist |
| [Add toolpass to your agent](guides/agent-tools.md) | Which tools to guard, where the user comes from, per framework |
| [Operating](guides/operating.md) | Decision log, health, what each `unknown` means |
| [Python API](reference/client.md), [HTTP API](reference/api.md), [configuration](reference/configuration.md), [CLI](reference/cli.md) | Reference |
| [All docs](README.md) | The full index |

## License

Apache-2.0.

## Contributing

Issues and pull requests are welcome, especially new integrations. See
[CONTRIBUTING.md](../CONTRIBUTING.md). Report security issues privately as described in
[SECURITY.md](../SECURITY.md).

Much of this code was written with Claude Code, directed and reviewed by the maintainer. That is
why the tests are the bar rather than the author: every integration ships with a fake of its API
that validates each request against the vendor's description, injects failures, and asserts that
no secret reaches a log line; the security model above is enforced by those tests, not by trust.
Contributions written the same way are welcome on the same terms.
