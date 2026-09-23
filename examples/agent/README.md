# Calling hallpass from an AI agent

An agent holds one powerful bot credential. Before it uses that credential on
behalf of a person, it asks hallpass whether that person may do the thing.
This directory shows the pattern in two flavours, with one shared client.

| File | What it is |
|---|---|
| `hallpass_client.py` | `POST /check` wrapper, standard library only. `unknown`, errors and an unreachable hallpass all count as **not allowed**. |
| `mcp_server.py` | An MCP server with a `check_permission` tool and a guarded `write_thing` action. |
| `langchain_tool.py` | The same two tools as LangChain tools, provider-neutral. |
| `claude_agent_sdk_tool.py` | The same two tools as an in-process MCP server for the Claude Agent SDK. |
| `strands_tool.py` | The same two tools for Strands Agents. |
| `test_hallpass_client.py` | Tests against a fake hallpass. `python3 -m unittest discover -s examples/agent` |

## The rules the code follows

1. **Act only on `allow`.** `deny` and `unknown` are both refusals. hallpass
   answers `unknown` when it could not evaluate (upstream timeout, ambiguous
   user, resource it cannot see, bad request). The client's `Decision.allowed`
   is true only for `allow`.
2. **No answer is a refusal too.** A connection error, a timeout, a malformed
   or non-JSON response, a redirect, or an `allow` that arrives with a non-200
   status all become an `unknown` decision with the code `client_error`. The
   client never raises on transport problems, so a guarded action cannot
   accidentally run through an exception handler. Redirects are not followed
   because following one would send the API key to whatever host the
   `Location` header names.
3. **The model does not choose the user.** The person the agent acts for is
   bound when the tools are built (`AGENT_USER` for the MCP server, the
   argument of `make_tools` or `make_server` for the frameworks). A tool
   argument is text the model produces; the identity behind the session is not.
4. **hallpass only checks.** The action itself still runs with the agent's own
   credential. The `write_thing` bodies are where a real call to Jira, GitHub,
   Kubernetes and so on would go.

## Try it against the demo connection

Start hallpass with the example config, which has a `demo` connection where
`admin@example.com` may write and `dana@example.com` may only read:

```sh
export HALLPASS_API_KEY=change-me
go run ./cmd/hallpass serve -config examples/hallpass.yaml
```

Run the tests (no dependencies):

```sh
python3 -m unittest discover -s examples/agent -v
```

Install the optional dependencies. `requirements.txt` covers MCP and
LangChain and is what CI installs; `requirements-frameworks.txt` adds the
Claude Agent SDK and Strands:

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install -r examples/agent/requirements.txt -r examples/agent/requirements-frameworks.txt
```

### LangChain

`langchain_tool.py` calls its tools directly when run as a script, so no LLM
is needed to see the decisions:

```sh
export HALLPASS_URL=http://localhost:8080 HALLPASS_API_KEY=change-me
python examples/agent/langchain_tool.py dana@example.com
# deny: denied: dana@example.com is not an admin
# refused: dana@example.com may not thing.write on thing:1 in demo: deny (...)
python examples/agent/langchain_tool.py admin@example.com
# allow: allowed: admin@example.com is an admin
# wrote 5 bytes to thing:1 as admin@example.com
```

In an agent, build the tools once per session with the signed-in user:

```python
from langchain_tool import make_tools

tools = make_tools(user="dana@example.com", groups=["platform-team"])
# hand `tools` to any LangChain agent constructor
```

### MCP

`mcp_server.py` speaks MCP over stdio. Point an MCP host at it and set the
three environment variables. For Claude Code:

```sh
claude mcp add hallpass \
  -e HALLPASS_URL=http://localhost:8080 -e HALLPASS_API_KEY=change-me \
  -e AGENT_USER=dana@example.com \
  -- /path/to/.venv/bin/python /path/to/hallpass/examples/agent/mcp_server.py
```

Or in any host that takes an `mcpServers` JSON block:

```json
{
  "mcpServers": {
    "hallpass": {
      "command": "/path/to/.venv/bin/python",
      "args": ["/path/to/hallpass/examples/agent/mcp_server.py"],
      "env": {
        "HALLPASS_URL": "http://localhost:8080",
        "HALLPASS_API_KEY": "change-me",
        "AGENT_USER": "dana@example.com"
      }
    }
  }
}
```

The model then sees two tools. `check_permission(connection, action, resource)`
returns `{"decision", "reason", "allowed"}`; `write_thing(thing_id, content)`
answers `refused: ...` for anyone but an admin. With `AGENT_USER` set to
`admin@example.com` the write goes through.

`AGENT_GROUPS` (comma-separated) passes group memberships for systems that
grant by group, such as Kubernetes. Both tools send the same user and groups,
so `check_permission` and the guarded action always agree.

The tests exercise the MCP and LangChain paths when their packages are
installed and skip them otherwise; CI installs both.

### Claude Agent SDK

`claude_agent_sdk_tool.py` puts the two tools in an in-process MCP server.
Build it once per session with the signed-in user and pass it to `query`:

```python
from claude_agent_sdk import ClaudeAgentOptions, query
from claude_agent_sdk_tool import make_server

options = ClaudeAgentOptions(
    mcp_servers={"hallpass": make_server("dana@example.com")},
    allowed_tools=["mcp__hallpass__check_permission", "mcp__hallpass__write_thing"],
)
async for message in query(prompt="Write 'hello' to thing 1.", options=options):
    ...
```

A refused `write_thing` comes back with `is_error` set, so the model knows the
action did not happen. Running the file directly sends that prompt through
Claude, which needs the Claude Code CLI the SDK drives.

### Strands Agents

`strands_tool.py` returns the two tools for `Agent(tools=...)`:

```python
from strands import Agent
from strands_tool import make_tools

agent = Agent(tools=make_tools("dana@example.com"))
agent("Write 'hello' to thing 1.")
```

Running the file directly does exactly that with the Strands default model
provider.

## Adapting to a real system

Replace `demo`, `thing.write` and `thing:{thing_id}` with a connection from
your `hallpass.yaml` and one of its actions (`hallpass catalog jira` lists
them), then put the real call in the function body:

```python
@guarded(hp, "jira-main", "DELETE_ISSUES", "issue:{key}")
def delete_issue(*, user: str, key: str) -> str:
    jira.delete_issue(key)          # the agent's own credential
    return f"deleted {key}"
```

`guarded` formats the resource from the keyword arguments, asks hallpass, and
raises `PermissionDenied` before the body runs unless the answer is `allow`.
