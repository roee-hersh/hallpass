# Python API reference

The `hallpass` package (`pip install hallpass`, Python 3.10 or later), and the Node client
`hallpass-client` at the end. For how to use them in an agent, see the
[agent tools guide](../guides/agent-tools.md).

## Hallpass

Three ways to make one, all with the same methods:

```python
import hallpass
from hallpass import Hallpass

hp = Hallpass.from_config("hallpass.yaml")                   # the engine in this process
hp = Hallpass(connections=[{"id": "demo", "integration": "fake", "users": "dana@example.com"}])
hp = Hallpass.remote("https://hallpass.internal", api_key)   # a hallpass server
```

| Constructor | What it is |
|---|---|
| `Hallpass.from_config(path, *, logger=None)` | The engine in this process, from a hallpass YAML file. The file's `decision_cache_seconds`, `identity_cache_seconds` and `decision_log` apply; `listen` and `api_key` are not needed |
| `Hallpass(connections, *, decision_cache_seconds=30, identity_cache_seconds=900, decision_log="none", logger=None)` | The same, with the connections in code: mappings with exactly the keys of the file ([configuration](configuration.md#connections-in-code)) |
| `Hallpass.remote(url=None, api_key=None, timeout=10.0)` | A client for a running hallpass server. `url` defaults to `$HALLPASS_URL` or `http://localhost:8080`, `api_key` to `$HALLPASS_API_KEY`, and a missing key raises `ValueError` |

`logger` takes a `logging.Logger` for the engine's own log lines (the stdlib `hallpass` logger by
default). `Hallpass()` with no connections raises `TypeError`. Build one per process and share it:
each in-process `Hallpass` keeps its own caches.

For `remote`, the URL must be `https://`, or `http://` on `localhost` or a loopback address,
because the API key travels in a header. Redirects are never followed. `timeout` is the seconds to
wait for the connection and then for each read; the server waits up to the connection's `timeout`
(8 s by default) for the upstream, so keep this a little above that.

## check, allowed, require

```python
d = hp.check("dana@example.com", "jira-main", "DELETE_ISSUES", "issue:PAY-123")
d.decision  # "allow", "deny" or "unknown"
d.reason    # "denied: Dana Levi does not hold DELETE_ISSUES on issue PAY-123"
d.code      # "denied"
d.allowed   # True only for allow
d.status    # the HTTP status the server used (in-process: the one it would use); 0 if none arrived

hp.allowed(...)          # True or False
hp.require(...)          # returns the decision on allow, raises PermissionDenied otherwise
await hp.acheck(...)     # check for async code; the lookup runs in a worker thread
await hp.arequire(...)   # require for async code
```

All five take `(user, connection, action, resource, groups=None, *, fresh=False)`:

| Argument | Meaning |
|---|---|
| `groups` | A list of the user's groups, for systems that grant by group, such as Kubernetes |
| `fresh` | Skip hallpass's caches and ask the system now ([fresh checks](api.md#fresh-checks)) |

`check` never raises for a failed lookup: every failure is an `unknown` decision. With `remote`, a
connection error, a timeout, a redirect, a body that is not a decision, or an `allow` with a
non-200 status all become `unknown` with the code `client_error`. `PermissionDenied` carries the
`decision`, `user`, `connection`, `action` and `resource`, and its text names all of them.

In-process only:

| | |
|---|---|
| `hp.probe()` | Verify every connection's credential: a list of `(connection id, ok, summary or error)` |
| `hp.connections()` | The configured connection ids |
| `hp.local` | `True` when the engine runs in this process (also available on `remote`) |

## guarded

Wraps a function so its body runs only after hallpass said `allow`.

```python
from hallpass import guarded

@guarded(hp, "jira-main", "DELETE_ISSUES", "issue:{key}", user=current_user, fresh=True)
def delete_issue(key: str) -> str: ...
```

| Parameter | Meaning |
|---|---|
| `connection`, `action` | The connection id and one of its actions (`hallpass catalog <integration>` lists them) |
| `resource` | A format string over the call's arguments, such as `"issue:{key}"`; a parameter left at its default is available too. A call that cannot fill it checks nothing and runs nothing |
| `user` | A string, a zero-argument callable, or a `ContextVar` your application sets. Read on every call, never from the arguments |
| `groups` | The user's groups, from the same kinds of source; it must yield a list |
| `deny` | Optional. Called with the `PermissionDenied`; its return value is returned instead of raising |
| `fresh` | Optional. Every check skips hallpass's caches |

What it guarantees:

- The wrapped function keeps its exact signature, so no `user` field appears in a tool schema. A
  stray `user` keyword argument is a `TypeError` before any check; a `user` key inside a dict of
  arguments (the Claude Agent SDK shape) is ignored.
- Anything but `allow` stops the call before the body runs.
- A function with ordinary parameters is called with keyword arguments (LangChain, Strands, MCP); a
  function whose one parameter is a dict gets all the arguments in it (the Claude Agent SDK handler
  shape, `async def f(args: dict)`). `async def` works, and the check runs in a worker thread.

`hallpass.current(source)` resolves a user or groups source the same way, for code outside a
guarded function. A `ContextVar` with nothing set raises a `RuntimeError` that names it.

## Framework adapters

Each adapter module needs its extra (`pip install "hallpass[<extra>]"`) and exports `Rule` along
with the adapter. All take `hp`, then `rules`: a mapping of tool name to
`Rule(connection, action, resource, fresh=False)`, a `(connection, action, resource)` tuple, or
`None` (the tool runs unchecked even under `strict`); and `strict=False` (refuse tools that have
no rule).

| Module (extra) | Adapter | User from | Other arguments |
|---|---|---|---|
| `hallpass.strands` (`strands`) | `HallpassAuthorization`, an intervention handler | `invocation_state[user_key]` | `user_key="user_id"`, `groups_key=None` |
| `hallpass.langchain` (`langchain`) | `HallpassMiddleware`, agent middleware; `.tool_node(tools)` for LangGraph | the runtime context's `user_key`, else `user` | `user`, `groups`, `user_key="user_id"`, `groups_key=None` |
| `hallpass.mcp` (`mcp`) | `guard(server, hp, rules, ...)`, server middleware | the access token's `user_claim`, else `user` | `user`, `groups`, `user_claim="email"`, `groups_claim=None` |
| `hallpass.openai_agents` (`openai-agents`) | `HallpassGuardrails`; `.apply(agent)`, `.protect(tools)` | the run context's `user_key`, unless `user` | `user_key="user_id"`, `groups_key=None`, `user`, `groups` |
| `hallpass.claude_agent_sdk` (`claude-agent-sdk`) | `HallpassHooks`; `.apply(options)`, `.hooks()`, `.can_use_tool` | `user` (required) | `groups`, `timeout=60` |
| `hallpass.google_adk` (`google-adk`) | `HallpassCallbacks`; `.apply(agent)`, `.plugin()` | the session's `user_id`, unless `user` | `user`, `groups` |
| `hallpass.crewai` (`crewai`) | `HallpassHooks`; `.register()`, `.unregister()`, or `with` | `user`, else the kickoff input `user_input` | `user`, `groups`, `user_input="user_id"`, `groups_input=None` |
| `hallpass.pydantic_ai` (`pydantic-ai`) | `HallpassAuthorization`, a capability; `HallpassToolset(toolset, hp, rules)` | `user`, else `deps.user` | `user`, `groups` (else `deps.groups`) |
| `hallpass.llamaindex` (`llamaindex`) | `HallpassAuthorization`; `.wrap(tools)` | `user` (required) | `groups` |

Each refuses a call when the user is missing, when a resource field is not exactly the string or
integer the tool declares, when a field is missing with no default, on any answer but `allow`,
and on any error inside the check; the model reads `hallpass refused this call: <reason>` as the
tool's result. The adapter's docstring says how its framework delivers that result and what it
cannot check.

## The write log line

hallpass never sees the write itself, so after a guarded body runs, `guarded` logs one line on the
`hallpass` logger at INFO:

```text
unconditional write: dana@example.com ran DELETE_ISSUES on issue:PAY-123 in jira-main;
hallpass said allow (allowed: dana may delete issues in PAY) at 2026-09-24T10:00:00.412+00:00,
fresh=True; the write was not conditioned on the state hallpass saw (no If-Match),
so check and write were not atomic
```

A refused call logs nothing. A body that raises still logs, since the write may have happened. The
adapters log the same line after a checked tool runs, with `raised <error> from` or `got an error
result from` in place of `ran` when the tool failed.

## Fresh checks and atomicity

A fresh check narrows the gap between the check and the action; it does not close it. Closing it
needs a conditional write in the upstream system, such as `If-Match` with an ETag. A hallpass
server older than the `fresh` field rejects it, which `remote` reports as `unknown`, so upgrade the
server before turning `fresh` on. The [API reference](api.md#fresh-checks) has the details.

## Moving from hallpass-client (Python)

`hallpass-client` on PyPI, the old Python client, is replaced by this package and gets no new
releases; installed versions keep working. To move, depend on `hallpass` and change
`from hallpass_client import Hallpass` / `Hallpass()` to `from hallpass import Hallpass` /
`Hallpass.remote()` (and `hallpass_client.strands` to `hallpass.strands`).

## hallpass-client (Node)

The Node and TypeScript client of a hallpass server (`npm install hallpass-client`, Node 18.17 or
later, no dependencies). It follows the same rules as `Hallpass.remote`.

```ts
import { Hallpass, guarded } from "hallpass-client";

const hp = new Hallpass(); // HALLPASS_URL and HALLPASS_API_KEY; or new Hallpass({ url, apiKey, timeoutMs })

const d = await hp.check("dana@example.com", "jira-main", "DELETE_ISSUES", "issue:PAY-123", { groups, fresh: true });
await hp.require(...); // rejects with PermissionDenied unless allow

const deleteIssue = guarded(hp, "jira-main", "DELETE_ISSUES", "issue:{key}", { user, fresh: true })(
  async ({ key }: { key: string }) => { ... },
);
```

`check`, `allowed` and `require` return promises. The wrapped function takes one object of
arguments, which is what every Node agent framework passes; `user` and `groups` are a string, a
zero-argument function or an `AsyncLocalStorage`; `deny` works as in Python. The Node client does
not log the write line.
