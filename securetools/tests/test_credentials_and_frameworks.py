"""Credential injection, redaction, and what a framework sees."""

from __future__ import annotations

import asyncio
import inspect
import json
import typing

import pytest

from securetools import Session, Toolkit, ToolRefused

TOKEN = "ghp_supersecrettoken1234567890"


def test_credential_is_injected_and_hidden(events, dana):
    tools = Toolkit(audit=events, credentials={"github-bot": TOKEN})
    got = []

    @tools.tool(effect="write", credential="github-bot")
    def open_pr(repo: str, *, credential: str) -> str:
        got.append(credential)
        return f"opened in {repo}"

    assert open_pr("acme/gitops") == "opened in acme/gitops"
    assert got == [TOKEN]
    assert list(inspect.signature(open_pr).parameters) == ["repo"]
    assert "credential" not in typing.get_type_hints(open_pr)
    assert TOKEN not in json.dumps([e.to_dict() for e in events], default=repr)


def test_the_model_cannot_pass_the_credential(dana):
    tools = Toolkit(audit=None, credentials={"bot": TOKEN})

    @tools.tool(effect="write", credential="bot")
    def act(x: str, *, credential: str) -> str:
        return credential

    with pytest.raises(ToolRefused) as e:
        act("a", credential="attacker-token")
    assert e.value.code == "invalid_arguments"


def test_credential_comes_after_every_check(dana):
    asked = []

    def provider(name, call):
        asked.append(name)
        return TOKEN

    tools = Toolkit(audit=None, credentials=provider)

    @tools.tool(effect="write", credential="bot", authorize=lambda call: False)
    def act(*, credential: str) -> str:
        return "ran"

    with pytest.raises(ToolRefused):
        act()
    assert asked == []


def test_provider_failure_refuses_without_leaking(dana):
    def provider(name, call):
        raise KeyError(f"vault path secret/{name} token={TOKEN}")

    tools = Toolkit(audit=None, credentials=provider)

    @tools.tool(effect="write", credential="bot")
    def act(*, credential: str) -> str:
        return "ran"

    with pytest.raises(ToolRefused) as e:
        act()
    assert e.value.code == "credential_error"
    assert TOKEN not in str(e.value)

    tools2 = Toolkit(audit=None, credentials={})

    @tools2.tool(effect="write", credential="missing")
    def act2(*, credential: str) -> str:
        return "ran"

    with pytest.raises(ToolRefused) as e:
        act2()
    assert e.value.code == "credential_error"


def test_output_echoing_the_credential_is_redacted(dana):
    tools = Toolkit(audit=None, credentials={"bot": TOKEN})

    @tools.tool(effect="read", credential="bot")
    def debug(*, credential: str) -> dict:
        return {"headers": {"Authorization": f"Bearer {credential}"}, "items": [credential, 3]}

    out = debug()
    assert TOKEN not in json.dumps(out)
    assert out["headers"]["Authorization"] == "Bearer [REDACTED]"
    assert out["items"] == ["[REDACTED]", 3]


def test_async_credential_provider():
    async def provider(name, call):
        await asyncio.sleep(0)
        return TOKEN

    tools = Toolkit(audit=None, credentials=provider)

    @tools.tool(effect="write", credential="bot")
    async def act(*, credential: str) -> bool:
        return credential == TOKEN

    async def main():
        with Session("d@example.com").active():
            return await act()

    assert asyncio.run(main()) is True


def test_declaration_errors_for_credentials():
    tools = Toolkit(audit=None, credentials={"bot": TOKEN})
    with pytest.raises(TypeError, match="reserved"):

        @tools.tool(effect="write")
        def a(*, credential: str) -> str:
            return ""

    with pytest.raises(TypeError, match="keyword-only"):

        @tools.tool(effect="write", credential="bot")
        def b(credential: str) -> str:
            return ""

    with pytest.raises(TypeError, match="parameter named"):

        @tools.tool(effect="write", credential="bot")
        def c(x: str) -> str:
            return ""

    with pytest.raises(TypeError, match="no credentials source"):

        @Toolkit(audit=None).tool(effect="write", credential="bot")
        def d(*, credential: str) -> str:
            return ""


# Frameworks build the model's schema from the signature; it must not mention the credential.


def test_langchain_schema_hides_the_credential(dana):
    lc = pytest.importorskip("langchain_core.tools")
    tools = Toolkit(audit=None, credentials={"bot": TOKEN})

    @lc.tool
    @tools.tool(effect="write", credential="bot", scope={"repo": "acme/*"})
    def open_pr(repo: str, title: str, *, credential: str) -> str:
        """Open a pull request."""
        return f"{repo}: {title}"

    schema = open_pr.args
    assert set(schema) == {"repo", "title"}
    assert open_pr.invoke({"repo": "acme/web", "title": "bump"}) == "acme/web: bump"
    with pytest.raises(ToolRefused):
        open_pr.invoke({"repo": "evil/web", "title": "bump"})


def test_pydantic_validate_call_sees_the_public_signature(dana):
    pydantic = pytest.importorskip("pydantic")
    tools = Toolkit(audit=None, credentials={"bot": TOKEN})

    @tools.tool(effect="write", credential="bot")
    def act(n: int, *, credential: str) -> int:
        return n

    validated = pydantic.validate_call(act)
    assert validated(n="3") == 3  # pydantic coerces, then securetools checks the int
