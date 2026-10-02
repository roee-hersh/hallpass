"""Sessions, the decorated function's shape, sync and async, refusals as values."""

from __future__ import annotations

import asyncio
import contextvars
import inspect
import typing

import pytest

from toolpass import Session, Toolkit, ToolRefused, current_session, spec_of


def test_no_session_refuses(events):
    tools = Toolkit(audit=events)
    ran = []

    @tools.tool(effect="read")
    def look(x: str) -> str:
        ran.append(x)
        return x

    with pytest.raises(ToolRefused) as e:
        look("a")
    assert e.value.code == "no_session"
    assert ran == []
    assert events.last.outcome == "refused"
    assert events.last.code == "no_session"


def test_runs_with_a_session(events, dana):
    tools = Toolkit(audit=events)

    @tools.tool(effect="read")
    def look(x: str, n: int = 2) -> str:
        return x * n

    assert look("a") == "aa"
    assert look(x="b", n=3) == "bbb"
    assert events.last.outcome == "ran"
    assert events.last.user == "dana@example.com"
    assert events.last.session == dana.id
    assert events.last.arguments == {"x": "b", "n": 3}


def test_session_is_scoped_to_the_with_block():
    s = Session("a@example.com")
    assert current_session() is None
    with s.active():
        assert current_session() is s
        with Session("b@example.com").active() as inner:
            assert current_session() is inner
        assert current_session() is s
    assert current_session() is None


def test_session_rejects_empty_user():
    with pytest.raises(ValueError):
        Session("")
    with pytest.raises(ValueError):
        Session("   ")


def test_session_from_a_contextvar_or_callable(events):
    var: contextvars.ContextVar[Session] = contextvars.ContextVar("s")
    tools = Toolkit(audit=events, session=var)

    @tools.tool(effect="read")
    def who() -> str:
        return "ok"

    with pytest.raises(ToolRefused):
        who()
    var.set(Session("x@example.com"))
    assert who() == "ok"

    fixed = Session("y@example.com")
    tools2 = Toolkit(audit=events, session=lambda: fixed)

    @tools2.tool(effect="read")
    def who2() -> str:
        return "ok"

    assert who2() == "ok"
    assert events.last.user == "y@example.com"


def test_a_non_session_from_the_source_refuses(events):
    tools = Toolkit(audit=events, session=lambda: "dana@example.com")  # type: ignore[arg-type,return-value]

    @tools.tool(effect="read")
    def who() -> str:
        return "ok"

    with pytest.raises(ToolRefused) as e:
        who()
    assert e.value.code == "no_session"


def test_signature_and_metadata_are_kept(dana):
    tools = Toolkit(audit=None)

    @tools.tool(effect="write")
    def open_pr(repo: str, title: str, draft: bool = False) -> str:
        """Open a pull request."""
        return repo

    assert open_pr.__name__ == "open_pr"
    assert open_pr.__doc__ == "Open a pull request."
    assert list(inspect.signature(open_pr).parameters) == ["repo", "title", "draft"]
    assert typing.get_type_hints(open_pr) == {"repo": str, "title": str, "draft": bool, "return": str}
    assert not hasattr(open_pr, "__wrapped__")
    spec = spec_of(open_pr)
    assert spec is not None and spec.effect == "write" and spec.name == "open_pr"
    assert spec_of(print) is None


def test_positional_calls_bind_like_the_original(dana):
    tools = Toolkit(audit=None)

    @tools.tool(effect="read")
    def add(a: int, b: int) -> int:
        return a + b

    assert add(1, 2) == 3
    with pytest.raises(ToolRefused) as e:
        add(1, 2, 3)
    assert e.value.code == "invalid_arguments"
    with pytest.raises(ToolRefused) as e:
        add(1, c=3)
    assert e.value.code == "invalid_arguments"


def test_async_tools(events):
    tools = Toolkit(audit=events)

    @tools.tool(effect="read")
    async def fetch(x: str) -> str:
        await asyncio.sleep(0)
        return x.upper()

    assert inspect.iscoroutinefunction(fetch)

    async def main() -> str:
        with Session("dana@example.com").active():
            return await fetch("hi")

    assert asyncio.run(main()) == "HI"
    assert events.last.outcome == "ran"


def test_body_errors_propagate_and_are_audited(events, dana):
    tools = Toolkit(audit=events)

    @tools.tool(effect="write")
    def boom() -> None:
        raise RuntimeError("upstream down")

    with pytest.raises(RuntimeError):
        boom()
    assert events.last.outcome == "raised"
    assert events.last.reason == "RuntimeError"


def test_a_nested_refusal_from_the_body_is_not_this_calls_refusal(events, dana):
    tools = Toolkit(audit=events, limits={"write": 1})

    @tools.tool(effect="read")
    def inner() -> None:
        raise ToolRefused("inner", "not_authorized", "no")

    @tools.tool(effect="write")
    def outer() -> None:
        inner()

    with pytest.raises(ToolRefused):
        outer()
    assert events.last.tool == "outer" and events.last.outcome == "raised"
    # the write ran, so its slot stays used
    assert dana.count("effect:write") == 1


def test_on_refuse_turns_refusals_into_values(dana):
    tools = Toolkit(audit=None, on_refuse=str)

    @tools.tool(effect="read", scope={"name": "ok-*"})
    def look(name: str) -> str:
        return name

    out = look("nope")
    assert isinstance(out, str) and "out_of_scope" in out


def test_broken_audit_sink_does_not_change_the_outcome(dana, caplog):
    def sink(_):
        raise OSError("disk full")

    tools = Toolkit(audit=sink)

    @tools.tool(effect="read")
    def look() -> str:
        return "ok"

    assert look() == "ok"
    assert "audit sink failed" in caplog.text


def test_default_audit_logs_json(dana, caplog):
    import json
    import logging

    tools = Toolkit()

    @tools.tool(effect="read")
    def look(q: str) -> str:
        return "ok"

    with caplog.at_level(logging.INFO, logger="toolpass"):
        look("x" * 500)
    line = json.loads(caplog.records[-1].getMessage())
    assert line["tool"] == "look" and line["outcome"] == "ran"
    assert len(line["arguments"]["q"]) < 260


@pytest.mark.parametrize(
    "kwargs",
    [
        {"effect": "delete"},
        {"effect": "read", "limit": -1},
        {"effect": "read", "approve": "yes"},
        {"effect": "read", "untrusted_inputs": "maybe"},
    ],
)
def test_bad_declarations_fail_at_import(kwargs):
    tools = Toolkit(audit=None)
    with pytest.raises((ValueError, TypeError)):

        @tools.tool(**kwargs)
        def f(x: str) -> str:
            return x


def test_bad_toolkit_settings():
    with pytest.raises(ValueError):
        Toolkit(limits={"delete": 1})
    with pytest.raises(ValueError):
        Toolkit(limits={"write": -1})
    with pytest.raises(ValueError):
        Toolkit(on_untrusted_input="ignore")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        Toolkit(exfiltration="maybe")  # type: ignore[arg-type]
