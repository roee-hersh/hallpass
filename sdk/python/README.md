# hallpass-client

The Python client for [hallpass](https://github.com/roee-hersh/hallpass): before your AI agent
acts for a user, ask the system that owns the resource whether that user may do it.

```sh
pip install hallpass-client
```

It is on [PyPI](https://pypi.org/project/hallpass-client/), and every hallpass
[release](https://github.com/roee-hersh/hallpass/releases) also carries it as a download. Its version
matches the hallpass release, so pin the one you run, e.g. `hallpass-client==0.4.0`.

It needs a running hallpass service. The client has no dependencies beyond the standard library.

```python
from contextvars import ContextVar
from hallpass_client import Hallpass, guarded

hp = Hallpass()  # HALLPASS_URL and HALLPASS_API_KEY from the environment
current_user: ContextVar[str] = ContextVar("current_user")

@tool  # LangChain, Strands, MCP, the Claude Agent SDK...
@guarded(hp, "jira-main", "DELETE_ISSUES", "issue:{key}", user=current_user, fresh=True)
def delete_issue(key: str) -> str:
    jira.delete_issue(key)  # the agent's own credential, only after hallpass said allow
    return f"deleted {key}"

current_user.set(request.user.email)  # from your auth, per request or session
```

- **The model never picks the user.** It comes from `user=`: a string, a zero-argument
  callable, or a `ContextVar` your application sets. A `user` key in the tool's arguments is ignored.
- **It fails closed.** `deny`, `unknown` and hallpass being unreachable all raise
  `PermissionDenied` before the body runs. Pass `deny=` to return a message to the model instead.
- **One package covers every framework.** `guarded` handles plain functions, `async def`,
  and the Claude Agent SDK's `async def f(args: dict)` handler shape.

For Strands Agents, `pip install "hallpass-client[strands]"` adds an intervention handler that
checks every tool call with a rule, with the user from `invocation_state`:

```python
from hallpass_client.strands import HallpassAuthorization

hallpass = HallpassAuthorization(hp, {"delete_issue": ("jira-main", "DELETE_ISSUES", "issue:{key}")})
agent = Agent(tools=tools, interventions=[hallpass])
agent(prompt, invocation_state={"user_id": request.user.email})
```

Without a decorator:

```python
d = hp.check("dana@example.com", "jira-main", "DELETE_ISSUES", "issue:PAY-123")
d.decision, d.reason        # "deny", "denied: ..."
hp.require(...)             # raises PermissionDenied unless allow
```

Framework examples: [examples/agent](https://github.com/roee-hersh/hallpass/tree/main/examples/agent).
The guide: [docs/guides/agent-tools.md](https://github.com/roee-hersh/hallpass/blob/main/docs/guides/agent-tools.md).
