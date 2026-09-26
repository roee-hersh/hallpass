"""An MCP server (the official ``mcp`` SDK, v2) whose tools hallpass checks
before they run.

``guard`` installs the check once, as server middleware; the tools carry no
decorator. The user comes from the request's access token when the server
runs over HTTP with auth, and otherwise from ``AGENT_USER``, fixed by the
host that launches this server (one stdio server process per user session).
Never from a tool argument: the model can make those up.

    pip install "hallpass[mcp]"
    AGENT_USER=dana@example.com python examples/mcp_server.py   # speaks MCP over stdio

The engine runs in this process on the ``fake`` integration, so the example
needs no hallpass server; swap in ``Hallpass.from_config("hallpass.yaml")``.
"""

from __future__ import annotations

import os

from mcp.server.mcpserver import MCPServer

from hallpass import Hallpass
from hallpass.mcp import Rule, guard

hp = Hallpass(connections=[{"id": "demo", "integration": "fake", "users": "dana@example.com", "admins": "admin@example.com"}])

mcp = MCPServer("hallpass-demo", instructions="write_thing is refused unless the user holds thing.write; a refusal says why.")


@mcp.tool()
def write_thing(thing_id: str, content: str) -> str:
    """Write content to a thing in the demo system. Requires thing.write."""
    # The action itself, run with the server's own credential. Replace with a
    # real call (delete a Jira issue, scale a deployment, ...).
    return f"wrote {len(content)} bytes to thing:{thing_id}"


@mcp.tool()
def read_thing(thing_id: str) -> str:
    """Read a thing in the demo system."""
    return f"contents of thing:{thing_id}"


# strict: a tool added later without a rule is refused, not silently unchecked.
guard(
    mcp,
    hp,
    {"write_thing": Rule("demo", "thing.write", "thing:{thing_id}"), "read_thing": None},
    user=os.environ.get("AGENT_USER") or None,
    strict=True,
)


if __name__ == "__main__":
    mcp.run()
