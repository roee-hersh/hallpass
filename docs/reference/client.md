# Client reference

The `hallpass-client` package for Python (`pip install hallpass-client`) and Node
(`npm install hallpass-client`). Both have no runtime dependencies and follow the same rules. For
how to use them in an agent, see the [agent tools guide](../guides/agent-tools.md).

## Hallpass

```python
from hallpass_client import Hallpass

hp = Hallpass()  # HALLPASS_URL (default http://localhost:8080) and HALLPASS_API_KEY
```

```ts
import { Hallpass } from "hallpass-client";

const hp = new Hallpass(); // same variables; or new Hallpass({ url, apiKey, timeoutMs })
```

The URL must be `https://`, or `http://` on localhost or a loopback address, because the API key
travels in a header. Redirects are never followed.

## check, allowed, require

```python
d = hp.check("dana@example.com", "jira-main", "DELETE_ISSUES", "issue:PAY-123")
d.decision  # "allow", "deny" or "unknown"
d.reason    # "denied: dana@example.com lacks DELETE_ISSUES on PAY"
d.code      # "denied"
d.allowed   # True only for allow

hp.allowed(...)   # True or False
hp.require(...)   # returns the decision on allow, raises PermissionDenied otherwise
```

In Node the same three methods return promises, and `require` rejects with `PermissionDenied`.

| Option | Python | Node | Meaning |
|---|---|---|---|
| Groups | `groups=[...]` | `{ groups: [...] }` | For systems that grant by group, such as Kubernetes |
| Fresh | `fresh=True` | `{ fresh: true }` | Skip hallpass's caches and ask the system now |

`check` never raises on a transport problem. A connection error, a timeout, a redirect, a body that
is not JSON, or an `allow` with a non-200 status all become `unknown` with the code `client_error`.

## guarded

Wraps a function so its body runs only after hallpass said `allow`.

```python
@guarded(hp, "jira-main", "DELETE_ISSUES", "issue:{key}", user=current_user, fresh=True)
def delete_issue(key: str) -> str: ...
```

```ts
const deleteIssue = guarded(hp, "jira-main", "DELETE_ISSUES", "issue:{key}", { user, fresh: true })(
  async ({ key }: { key: string }) => { ... },
);
```

| Parameter | Meaning |
|---|---|
| `connection`, `action` | The connection id and one of its actions (`hallpass catalog <integration>` lists them) |
| `resource` | A template over the call's arguments, such as `"issue:{key}"`. A call that cannot fill it makes no request and runs nothing |
| `user` | A string, a zero-argument function, or a `ContextVar` (Python) or `AsyncLocalStorage` (Node) your application sets. Read on every call, never from the arguments |
| `groups` | The user's groups, from the same kinds of source |
| `deny` | Optional. Called with the `PermissionDenied`; its return value is returned instead of raising |
| `fresh` | Optional. Every check skips hallpass's caches |

What it guarantees:

- The wrapped function keeps its exact signature, so no `user` field appears in a tool schema. A
  stray `user` keyword argument is a `TypeError` before any request; a `user` key inside a dict of
  arguments (the Claude Agent SDK shape, or Node) is ignored.
- Anything but `allow` stops the call before the body runs.
- Python: a function with normal parameters is called with keyword arguments (LangChain, Strands,
  MCP); a function whose one parameter is a dict gets all the arguments in it (the Claude Agent SDK
  handler shape). `async def` works, and the check runs in a worker thread.
- Node: the function takes one object of arguments, which is what every Node agent framework passes.

`current(source)` resolves a user or groups source the same way, for code outside a guarded
function. A `ContextVar` or `AsyncLocalStorage` with nothing set gives a clear error.

## HallpassAuthorization (Python, Strands Agents)

A Strands intervention handler, in `hallpass_client.strands` (`pip install "hallpass-client[strands]"`,
Python 3.10 or later, `strands-agents` 1.57.1 or later).

```python
HallpassAuthorization(hp, rules, *, user_key="user_id", groups_key=None, strict=False)
```

| Parameter | Meaning |
|---|---|
| `rules` | Tool name to `Rule(connection, action, resource, fresh=False)` or a `(connection, action, resource)` tuple. `resource` is a template over the tool's input; each field must be one plain `str` or `int` parameter of the tool (not a UUID, URL or path, which Strands converts). A rule naming no tool of the agent is logged as a warning |
| `user_key` | The `invocation_state` key the user is read from |
| `groups_key` | Optional. The `invocation_state` key the user's groups are read from, a list of strings |
| `strict` | Deny tools with no rule. A rule of `None` lets a tool run unchecked |

Each of these denies the call, with the reason as the tool result: no user (or no groups when
`groups_key` is set), a resource field whose value is not exactly the string or integer the tool
declares (Strands would convert it, so the tool would act on another resource), a missing field
with no default, a call a hook moved to another tool, any answer but `allow`, and an exception in
the handler (`on_error` is `deny`). The check
runs in a worker thread, and a checked tool logs the write line below after it runs.

## The write log line (Python)

hallpass never sees the write itself, so after a guarded body runs, the Python client logs one line
on the `hallpass` logger at INFO:

```text
unconditional write: dana@example.com ran DELETE_ISSUES on issue:PAY-123 in jira-main;
hallpass said allow (allowed: dana may delete issues in PAY) at 2026-09-24T10:00:00.412+00:00,
fresh=True; the write was not conditioned on the state hallpass saw (no If-Match),
so check and write were not atomic
```

A refused call logs nothing. A body that raises still logs, since the write may have happened.
`HallpassAuthorization` logs the same line after a checked Strands tool runs, with `raised <error>
from` or `got an error result from` in place of `ran` when the tool failed.

## Fresh checks and atomicity

A fresh check narrows the gap between the check and the action; it does not close it. Closing it
needs a conditional write in the upstream system, such as `If-Match` with an ETag. A hallpass older
than the `fresh` field rejects it, which the clients report as `unknown`, so upgrade the service
before turning `fresh` on. The [API reference](api.md#fresh-checks) has the details.
