# Python API reference

The `toolpass` package (`pip install toolpass`, Python 3.10 or later), and the Node client
`toolpass-client` at the end. For how to use them in an agent, see the
[agent tools guide](../guides/agent-tools.md).

## Toolpass

Three ways to make one, all with the same methods:

```python
import toolpass
from toolpass import Toolpass

tp = Toolpass.from_config("toolpass.yaml")                   # the engine in this process
tp = Toolpass(connections=[{"id": "demo", "integration": "fake", "users": "dana@example.com"}])
tp = Toolpass.remote("https://toolpass.internal", api_key)   # a toolpass server
```

| Constructor | What it is |
|---|---|
| `Toolpass.from_config(path, *, logger=None)` | The engine in this process, from a toolpass YAML file. The file's `decision_cache_seconds`, `identity_cache_seconds` and `decision_log` apply; `listen` and `api_key` are not needed |
| `Toolpass(connections, *, decision_cache_seconds=30, identity_cache_seconds=900, decision_log="none", logger=None)` | The same, with the connections in code: mappings with exactly the keys of the file ([configuration](configuration.md#connections-in-code)) |
| `Toolpass.remote(url=None, api_key=None, timeout=10.0)` | A client for a running toolpass server. `url` defaults to `$TOOLPASS_URL` or `http://localhost:8080`, `api_key` to `$TOOLPASS_API_KEY`, and a missing key raises `ValueError` |

`logger` takes a `logging.Logger` for the engine's own log lines (the stdlib `toolpass` logger by
default). `Toolpass()` with no connections raises `TypeError`. Build one per process and share it:
each in-process `Toolpass` keeps its own caches.

For `remote`, the URL must be `https://`, or `http://` on `localhost` or a loopback address,
because the API key travels in a header. Redirects are never followed. `timeout` is the seconds to
wait for the connection and then for each read; the server waits up to the connection's `timeout`
(8 s by default) for the upstream, so keep this a little above that.

## check, allowed, require

```python
d = tp.check("dana@example.com", "jira-main", "DELETE_ISSUES", "issue:PAY-123")
d.decision  # "allow", "deny" or "unknown"
d.reason    # "denied: Dana Levi does not hold DELETE_ISSUES on issue PAY-123"
d.code      # "denied"
d.allowed   # True only for allow
d.status    # the HTTP status the server used (in-process: the one it would use); 0 if none arrived

tp.allowed(...)          # True or False
tp.require(...)          # returns the decision on allow, raises PermissionDenied otherwise
await tp.acheck(...)     # check for async code; the lookup runs in a worker thread
await tp.arequire(...)   # require for async code
```

All five take `(user, connection, action, resource, groups=None, *, fresh=False)`:

| Argument | Meaning |
|---|---|
| `groups` | A list of the user's groups, for systems that grant by group, such as Kubernetes |
| `fresh` | Skip toolpass's caches and ask the system now ([fresh checks](api.md#fresh-checks)) |

`check` never raises for a failed lookup: every failure is an `unknown` decision. With `remote`, a
connection error, a timeout, a redirect, a body that is not a decision, or an `allow` with a
non-200 status all become `unknown` with the code `client_error`. `PermissionDenied` carries the
`decision`, `user`, `connection`, `action` and `resource`, and its text names all of them.

In-process only:

| | |
|---|---|
| `tp.probe()` | Verify every connection's credential: a list of `(connection id, ok, summary or error)` |
| `tp.connections()` | The configured connection ids |
| `tp.local` | `True` when the engine runs in this process (also available on `remote`) |

## guarded

Wraps a function so its body runs only after toolpass said `allow`.

```python
from toolpass import guarded

@guarded(tp, "jira-main", "DELETE_ISSUES", "issue:{key}", user=current_user, fresh=True)
def delete_issue(key: str) -> str: ...
```

| Parameter | Meaning |
|---|---|
| `connection`, `action` | The connection id and one of its actions (`toolpass catalog <integration>` lists them) |
| `resource` | A format string over the call's arguments, such as `"issue:{key}"`; a parameter left at its default is available too. A call that cannot fill it checks nothing and runs nothing |
| `user` | A string, a zero-argument callable, or a `ContextVar` your application sets. Read on every call, never from the arguments |
| `groups` | The user's groups, from the same kinds of source; it must yield a list |
| `deny` | Optional. Called with the `PermissionDenied`; its return value is returned instead of raising |
| `fresh` | Optional. Every check skips toolpass's caches |

What it guarantees:

- The wrapped function keeps its exact signature, so no `user` field appears in a tool schema. A
  stray `user` keyword argument is a `TypeError` before any check; a `user` key inside a dict of
  arguments (the Claude Agent SDK shape) is ignored.
- Anything but `allow` stops the call before the body runs.
- A function with ordinary parameters is called with keyword arguments (LangChain, Strands, MCP); a
  function whose one parameter is a dict gets all the arguments in it (the Claude Agent SDK handler
  shape, `async def f(args: dict)`). `async def` works, and the check runs in a worker thread.

`toolpass.current(source)` resolves a user or groups source the same way, for code outside a
guarded function. A `ContextVar` with nothing set raises a `RuntimeError` that names it.

## Framework adapters

Each adapter module needs its extra (`pip install "toolpass[<extra>]"`) and exports `Rule` along
with the adapter. All take `tp`, then `rules`: a mapping of tool name to
`Rule(connection, action, resource, fresh=False)`, a `(connection, action, resource)` tuple, or
`None` (the tool runs unchecked even under `strict`); and `strict=False` (refuse tools that have
no rule).

| Module (extra) | Adapter | User from | Other arguments |
|---|---|---|---|
| `toolpass.strands` (`strands`) | `ToolpassAuthorization`, an intervention handler | `invocation_state[user_key]` | `user_key="user_id"`, `groups_key=None` |
| `toolpass.langchain` (`langchain`) | `ToolpassMiddleware`, agent middleware; `.tool_node(tools)` for LangGraph | the runtime context's `user_key`, else `user` | `user`, `groups`, `user_key="user_id"`, `groups_key=None` |
| `toolpass.mcp` (`mcp`) | `guard(server, tp, rules, ...)`, server middleware | the access token's `user_claim`, else `user` | `user`, `groups`, `user_claim="email"`, `groups_claim=None` |
| `toolpass.openai_agents` (`openai-agents`) | `ToolpassGuardrails`; `.apply(agent)`, `.protect(tools)` | the run context's `user_key`, unless `user` | `user_key="user_id"`, `groups_key=None`, `user`, `groups` |
| `toolpass.claude_agent_sdk` (`claude-agent-sdk`) | `ToolpassHooks`; `.apply(options)`, `.hooks()`, `.can_use_tool` | `user` (required) | `groups`, `timeout=60` |
| `toolpass.google_adk` (`google-adk`) | `ToolpassCallbacks`; `.apply(agent)`, `.plugin()` | the session's `user_id`, unless `user` | `user`, `groups` |
| `toolpass.crewai` (`crewai`) | `ToolpassHooks`; `.register()`, `.unregister()`, or `with` | `user`, else the kickoff input `user_input` | `user`, `groups`, `user_input="user_id"`, `groups_input=None` |
| `toolpass.pydantic_ai` (`pydantic-ai`) | `ToolpassAuthorization`, a capability; `ToolpassToolset(toolset, tp, rules)` | `user`, else `deps.user` | `user`, `groups` (else `deps.groups`) |
| `toolpass.llamaindex` (`llamaindex`) | `ToolpassAuthorization`; `.wrap(tools)` | `user` (required) | `groups` |

Each refuses a call when the user is missing, when a resource field is not exactly the string or
integer the tool declares, when a field is missing with no default, on any answer but `allow`,
and on any error inside the check; the model reads `toolpass refused this call: <reason>` as the
tool's result. The adapter's docstring says how its framework delivers that result and what it
cannot check.

## The write log line

toolpass never sees the write itself, so after a guarded body runs, `guarded` logs one line on the
`toolpass` logger at INFO:

```text
unconditional write: dana@example.com ran DELETE_ISSUES on issue:PAY-123 in jira-main;
toolpass said allow (allowed: dana may delete issues in PAY) at 2026-09-24T10:00:00.412+00:00,
fresh=True; the write was not conditioned on the state toolpass saw (no If-Match),
so check and write were not atomic
```

A refused call logs nothing. A body that raises still logs, since the write may have happened. The
adapters log the same line after a checked tool runs, with `raised <error> from` or `got an error
result from` in place of `ran` when the tool failed.

## Fresh checks and atomicity

A fresh check narrows the gap between the check and the action; it does not close it. Closing it
needs a conditional write in the upstream system, such as `If-Match` with an ETag. A toolpass
server older than the `fresh` field rejects it, which `remote` reports as `unknown`, so upgrade the
server before turning `fresh` on. The [API reference](api.md#fresh-checks) has the details.

## Moving from toolpass-client (Python)

`toolpass-client` on PyPI, the old Python client, is replaced by this package and gets no new
releases; installed versions keep working. To move, depend on `toolpass` and change
`from toolpass_client import Toolpass` / `Toolpass()` to `from toolpass import Toolpass` /
`Toolpass.remote()` (and `toolpass_client.strands` to `toolpass.strands`).

## toolpass-client (Node)

The Node and TypeScript client of a toolpass server (`npm install toolpass-client`, Node 18.17 or
later, no dependencies). It follows the same rules as `Toolpass.remote`.

```ts
import { Toolpass, guarded } from "toolpass-client";

const tp = new Toolpass(); // TOOLPASS_URL and TOOLPASS_API_KEY; or new Toolpass({ url, apiKey, timeoutMs })

const d = await tp.check("dana@example.com", "jira-main", "DELETE_ISSUES", "issue:PAY-123", { groups, fresh: true });
await tp.require(...); // rejects with PermissionDenied unless allow

const deleteIssue = guarded(tp, "jira-main", "DELETE_ISSUES", "issue:{key}", { user, fresh: true })(
  async ({ key }: { key: string }) => { ... },
);
```

`check`, `allowed` and `require` return promises. The wrapped function takes one object of
arguments, which is what every Node agent framework passes; `user` and `groups` are a string, a
zero-argument function or an `AsyncLocalStorage`; `deny` works as in Python. The Node client does
not log the write line.
