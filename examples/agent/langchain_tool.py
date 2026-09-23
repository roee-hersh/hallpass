"""LangChain tools that check with hallpass before they act.

Build the tools once per user session so the acting user is bound in the
closure and never chosen by the model:

    tools = make_tools("dana@example.com")
    agent = create_agent(llm, tools)          # any LangChain agent constructor

Needs ``langchain-core`` (pip install -r requirements.txt). The tools do not
depend on any particular LLM provider.
"""

from __future__ import annotations

from langchain_core.tools import tool

from hallpass_client import Hallpass, PermissionDenied, guarded


def make_tools(user: str, groups: list[str] | None = None, hp: Hallpass | None = None) -> list:
    hp = hp or Hallpass()
    groups = groups or []

    @tool
    def check_permission(connection: str, action: str, resource: str) -> str:
        """Ask whether the current user may perform an action in a system.
        connection is a hallpass connection id (e.g. jira-main), action one
        of its actions (e.g. DELETE_ISSUES), resource the target (e.g.
        issue:PAY-123). Only 'allow' permits the action; 'unknown' is a deny."""
        d = hp.check(user, connection, action, resource, groups)
        return f"{d.decision}: {d.reason}"

    @guarded(hp, "demo", "thing.write", "thing:{thing_id}")
    def _write_thing(*, user: str, thing_id: str, content: str) -> str:
        # The real action goes here, run with the agent's own credential.
        return f"wrote {len(content)} bytes to thing:{thing_id} as {user}"

    @tool
    def write_thing(thing_id: str, content: str) -> str:
        """Write content to a thing in the demo system. Refused unless the
        current user holds thing.write on it."""
        try:
            return _write_thing(user=user, thing_id=thing_id, content=content)
        except PermissionDenied as e:
            return f"refused: {e}"

    return [check_permission, write_thing]


if __name__ == "__main__":
    # Smoke test without an LLM: call the tools directly.
    import sys

    who = sys.argv[1] if len(sys.argv) > 1 else "dana@example.com"
    check, write = make_tools(who)
    print(check.invoke({"connection": "demo", "action": "thing.write", "resource": "thing:1"}))
    print(write.invoke({"thing_id": "1", "content": "hello"}))
