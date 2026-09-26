# hallpass-client

**hallpass-client is now part of [hallpass](https://pypi.org/project/hallpass/).** This package
depends on `hallpass` at the same version and re-exports it, so existing code keeps working. New
projects should install `hallpass` instead:

```sh
pip install hallpass
```

`hallpass` is the whole engine as a Python package: it can check permissions in-process, from a
config file or connections given in code, with no service to deploy
(`Hallpass.from_config("hallpass.yaml")`), and it is also the client of a hallpass server
(`Hallpass.remote(url, api_key)`) and the server itself (`hallpass serve`).

## What stays the same

```python
from contextvars import ContextVar
from hallpass_client import Hallpass, guarded

hp = Hallpass()  # a client of a running hallpass server: HALLPASS_URL and HALLPASS_API_KEY
current_user: ContextVar[str] = ContextVar("current_user")

@tool
@guarded(hp, "jira-main", "DELETE_ISSUES", "issue:{key}", user=current_user, fresh=True)
def delete_issue(key: str) -> str:
    jira.delete_issue(key)  # the agent's own credential, only after hallpass said allow
    return f"deleted {key}"
```

- `hallpass_client.Hallpass(url=None, api_key=None, timeout=10.0)` is
  `hallpass.Hallpass.remote(url, api_key, timeout)`: `check`, `allowed`, `require`, and now
  `acheck` and `arequire`.
- `guarded`, `current`, `Decision`, `PermissionDenied`, `ALLOW`, `DENY` and `UNKNOWN` are
  hallpass's own.
- `hallpass_client.strands` is `hallpass.strands`: `pip install "hallpass-client[strands]"`
  installs `hallpass[strands]`.

It needs Python 3.10 or later. Its version matches the hallpass release; pin the one you run.

## Moving to hallpass

```python
from hallpass import Hallpass, guarded

hp = Hallpass.remote()                      # the same server, the same environment variables
hp = Hallpass.from_config("hallpass.yaml")  # or the engine in this process, no server
```

`hallpass` also has adapters for Strands, LangChain and LangGraph, MCP, the OpenAI Agents SDK, the
Claude Agent SDK, Google ADK, CrewAI, Pydantic AI and LlamaIndex.
[The agent guide](https://github.com/roee-hersh/hallpass/blob/main/docs/guides/agent-tools.md) covers
each one.
