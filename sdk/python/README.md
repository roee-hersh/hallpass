# hallpass-client

The Python client for [hallpass](https://github.com/roee-hersh/hallpass): before your AI agent
acts for a user, ask the system that owns the resource whether that user may do it.

```sh
pip install https://github.com/roee-hersh/hallpass/releases/latest/download/hallpass-client-python.tar.gz
```

That URL always gives the latest [release](https://github.com/roee-hersh/hallpass/releases). In a
project, pin a version by replacing `latest/download` with `download/v0.4.0`, in `requirements.txt`
too:

```
hallpass-client @ https://github.com/roee-hersh/hallpass/releases/download/v0.4.0/hallpass-client-python.tar.gz
```

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

Without a decorator:

```python
d = hp.check("dana@example.com", "jira-main", "DELETE_ISSUES", "issue:PAY-123")
d.decision, d.reason        # "deny", "denied: ..."
hp.require(...)             # raises PermissionDenied unless allow
```

Framework examples: [examples/agent](https://github.com/roee-hersh/hallpass/tree/main/examples/agent).
The guide: [docs/agents.md](https://github.com/roee-hersh/hallpass/blob/main/docs/agents.md).
