"""An MCP server that checks with hallpass before it acts.

Two tools:

  check_permission   ask hallpass whether the current user may do something
  write_thing        an example action that runs only after an allow

The user the agent acts for is fixed when the server starts (AGENT_USER),
not passed by the model. A tool argument is something the model can make up;
the identity of the person behind the session is not. Set it from the host
that launches this server, one server process per user session.

Run:

    export HALLPASS_URL=http://localhost:8080 HALLPASS_API_KEY=change-me
    export AGENT_USER=dana@example.com
    python mcp_server.py           # speaks MCP over stdio

Needs the ``mcp`` package (pip install -r requirements.txt).
"""

from __future__ import annotations

import os
from typing import TypedDict

from mcp.server.mcpserver import MCPServer

from hallpass_client import Hallpass, guarded

hp = Hallpass()
AGENT_USER = os.environ.get("AGENT_USER", "")
if not AGENT_USER:
    raise ValueError("AGENT_USER missing: set it to the email of the user this server acts for")
# Optional group memberships, for systems that grant by group (e.g. Kubernetes).
AGENT_GROUPS = [g.strip() for g in os.environ.get("AGENT_GROUPS", "").split(",") if g.strip()]


class PermissionDecision(TypedDict):
    decision: str  # allow | deny | unknown
    reason: str  # "<code>: <text>"
    allowed: bool  # true only for allow


mcp = MCPServer(
    "hallpass",
    instructions=(
        f"Tools act on behalf of {AGENT_USER}. Call check_permission before "
        "suggesting an action the user may not be allowed to do. A decision of "
        "'deny' or 'unknown' means the action must not be performed."
    ),
)


@mcp.tool()
def check_permission(connection: str, action: str, resource: str) -> PermissionDecision:
    """Ask hallpass whether the current user may perform an action.

    connection: the hallpass connection id, e.g. "jira-main" or "k8s-prod-eu".
    action:     an action of that integration, e.g. "DELETE_ISSUES".
    resource:   the target, e.g. "issue:PAY-123" or "namespace:payments".

    Returns decision (allow / deny / unknown), reason and allowed. Only
    allowed=true permits the action; unknown means hallpass could not tell
    and must be treated as deny.
    """
    d = hp.check(AGENT_USER, connection, action, resource, AGENT_GROUPS)
    return {"decision": d.decision, "reason": d.reason, "allowed": d.allowed}


# MCPServer replaces an exception's text with "Error executing tool", so the
# refusal is returned as the result instead, and the model learns why.
@mcp.tool()
@guarded(hp, "demo", "thing.write", "thing:{thing_id}", user=AGENT_USER, groups=AGENT_GROUPS,
         deny=lambda e: f"refused: {e}")
def write_thing(thing_id: str, content: str) -> str:
    """Write content to a thing in the demo system. Requires thing.write."""
    # The action itself, with the agent's own credential. Replace with a real
    # call (delete a Jira issue, scale a deployment, ...) and keep the shape:
    # the decorator checks first, the body runs only on allow.
    return f"wrote {len(content)} bytes to thing:{thing_id} as {AGENT_USER}"


if __name__ == "__main__":
    mcp.run()
