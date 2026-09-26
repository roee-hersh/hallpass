"""hallpass for MCP servers built with the official ``mcp`` SDK (v2, ``MCPServer``).

    pip install "hallpass[mcp]"

``guard`` puts a hallpass check in front of the server's tools, as server
middleware: every ``tools/call`` that names a tool with a rule is checked
before the tool runs, whatever transport the call came over.

    from mcp.server.mcpserver import MCPServer

    from hallpass import Hallpass
    from hallpass.mcp import Rule, guard

    mcp = MCPServer("tools", token_verifier=verifier, auth=AuthSettings(...))

    @mcp.tool()
    def delete_issue(key: str) -> str: ...

    guard(mcp, Hallpass.from_config("hallpass.yaml"), {
        "delete_issue": Rule("jira-main", "DELETE_ISSUES", "issue:{key}", fresh=True),
    })

The user is taken from the request's authenticated access token (the
``user_claim`` claim, ``"email"`` by default; ``"sub"`` for the token's
subject), which the server's token verifier produced and the model cannot
write. When the request carries no token (stdio, or HTTP without auth), the
``user=`` source is used instead: a string, a zero-argument callable or a
``ContextVar``, e.g. the user a stdio server was started for.

A refusal comes back to the client as the tool's result, with
``isError: true`` and the reason as text, so the model can read it.
``hallpass.guarded`` also works on a plain tool function (with ``deny=``
returning the refusal as the result).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

try:
    from mcp.server.auth.middleware.auth_context import get_access_token
    from mcp.server.auth.provider import AccessToken
    from mcp.server.context import CallNext, HandlerResult, ServerRequestContext
    from mcp.server.mcpserver import MCPServer
    from mcp_types import CallToolResult, TextContent
except ImportError as e:  # pragma: no cover - exercised only without the extra
    raise ImportError('hallpass.mcp needs the mcp SDK 2.0 or later: pip install "hallpass[mcp]"') from e

from hallpass._api import GroupsSource, Hallpass, UserSource, current, log
from hallpass._rules import Checked, Outcome, Rule, RuleLike, Rules, refusal

__all__ = ["HallpassMiddleware", "Rule", "guard"]

_MISSING = object()


def _claim(token: AccessToken, claim: str) -> Any:
    """A claim of the access token; ``sub`` is the token's subject."""
    if claim == "sub":
        return token.subject if token.subject is not None else (token.claims or {}).get("sub", _MISSING)
    return (token.claims or {}).get(claim, _MISSING)


class HallpassMiddleware:
    """Server middleware that checks each ``tools/call`` with hallpass.

    Made by ``guard``, which also installs it; it needs the server to read
    the schema of the tool being called.

    ``rules`` maps a tool name to a ``Rule`` or a ``(connection, action,
    resource)`` tuple. A tool without a rule runs unchecked; with
    ``strict=True`` it is refused instead, and a rule of ``None`` names a
    tool that may run unchecked. A rule that names no tool the server has is
    logged once as a warning.

    The user is the access token's ``user_claim``, or else ``user``; with
    ``groups_claim`` or ``groups`` the groups the same way, as a list of
    strings. Neither set refuses the call. Any answer other than ``allow``
    refuses it: the tool does not run and the client gets a tool result with
    ``isError`` naming the user, the action and hallpass's reason. A
    resource the arguments cannot fill refuses, and so does any error inside
    the check.

    After a checked tool has run, the ``unconditional write`` line is logged
    on the ``hallpass`` logger, as ``guarded`` does.
    """

    def __init__(
        self,
        server: MCPServer[Any],
        hp: Hallpass,
        rules: Mapping[str, RuleLike],
        *,
        user: UserSource | None = None,
        groups: GroupsSource | None = None,
        user_claim: str = "email",
        groups_claim: str | None = None,
        strict: bool = False,
    ) -> None:
        if not isinstance(server, MCPServer):
            raise TypeError("server must be an mcp.server.mcpserver.MCPServer")
        self.server = server
        self.rules = Rules(hp, rules, strict=strict)
        self._user, self._groups = user, groups
        self._user_claim, self._groups_claim = user_claim, groups_claim
        self._warned: set[str] = set()

    async def __call__(self, ctx: ServerRequestContext[Any, Any], call_next: CallNext) -> HandlerResult:
        if ctx.method != "tools/call" or ctx.request_id is None:
            return await call_next(ctx)
        try:
            name, outcome = await self._decide(ctx.params)
        except Exception as e:  # noqa: BLE001 - any failure in the check refuses
            name, outcome = None, Outcome(False, f"the hallpass check failed: {type(e).__name__}: {e}")
        if not outcome.allowed:
            return CallToolResult(content=[TextContent(type="text", text=refusal(outcome))], is_error=True)
        c = outcome.checked
        try:
            result = await call_next(ctx)
        except BaseException as e:
            if c is not None:
                c.log(f"raised {type(e).__name__} from")
            raise
        if c is not None:
            self._log(c, result, name)
        return result

    @staticmethod
    def _log(c: Checked, result: HandlerResult, name: str | None) -> None:
        if isinstance(result, Mapping):
            is_error, final = result.get("isError"), "content" in result
        else:
            is_error, final = getattr(result, "is_error", None), isinstance(result, CallToolResult)
        if not final:
            return  # input required: the tool asked the client for more before it ran; the retry is checked again
        c.log("got an error result from" if is_error else "ran")

    async def _decide(self, params: Any) -> tuple[str | None, Outcome]:
        if not isinstance(params, Mapping) or not isinstance(params.get("name"), str):
            return None, Outcome(False, "the tools/call request names no tool")
        name: str = params["name"]
        args = params.get("arguments")
        if args is None:
            args = {}  # what the server runs the tool with
        tools = {t.name: t for t in await self.server.list_tools()}
        self._warn_missing(tools)
        if self.rules.entries.get(name) is None:
            return name, await self.rules.adecide(name, args, user=None)  # no rule: strict alone decides
        tool = tools.get(name)
        if tool is None:
            return name, Outcome(False, f"the server has no tool {name!r}")
        user, groups, why = self._sources()
        if why is not None:
            return name, Outcome(False, why)
        return name, await self.rules.adecide(name, args, user=user, groups=groups, schema=tool.input_schema)

    def _sources(self) -> tuple[Any, Any, str | None]:
        """The user and groups for this request, or a refusal reason."""
        token = get_access_token()
        user = _MISSING if token is None else _claim(token, self._user_claim)
        if user is _MISSING:
            if self._user is None:
                where = "carries no access token" if token is None else f"has an access token without a {self._user_claim!r} claim"
                return None, None, f"no user for this request: the request {where}"
            user = self._user
        elif not isinstance(user, str):
            return None, None, f"no user for this request: the access token's {self._user_claim!r} claim is not a string"
        groups: Any = None
        if self._groups_claim is not None or self._groups is not None:
            groups = _MISSING if token is None or self._groups_claim is None else _claim(token, self._groups_claim)
            if groups is _MISSING:
                try:
                    # Resolved here, so a source that yields nothing refuses rather than checking without groups.
                    groups = current(self._groups, "groups")
                except (RuntimeError, LookupError) as e:
                    return None, None, f"no groups for this request: {e}"
            if groups is None:
                return None, None, "no groups for this request: neither the access token nor groups= has them"
        return user, groups, None

    def _warn_missing(self, tools: Mapping[str, Any]) -> None:
        missing = self.rules.missing(tools) - self._warned
        if missing:
            self._warned |= missing
            log.warning("hallpass rules name tools the server does not have, so they check nothing: %s", ", ".join(sorted(missing)))


def guard(
    server: MCPServer[Any],
    hp: Hallpass,
    rules: Mapping[str, RuleLike],
    *,
    user: UserSource | None = None,
    groups: GroupsSource | None = None,
    user_claim: str = "email",
    groups_claim: str | None = None,
    strict: bool = False,
) -> HallpassMiddleware:
    """Check the server's tool calls with hallpass; see ``HallpassMiddleware``.

    The middleware is appended to ``server.middleware``. Middleware runs
    outermost first, so call ``guard`` after adding any middleware that
    rewrites requests: one added later could change a call hallpass already
    checked. Only calls that arrive over MCP pass through middleware;
    calling ``server.call_tool`` directly in the same process does not.
    """
    mw = HallpassMiddleware(server, hp, rules, user=user, groups=groups, user_claim=user_claim, groups_claim=groups_claim, strict=strict)
    server.middleware.append(mw)
    return mw
