"""Port of internal/integrations/fake/fake_test.go."""

from __future__ import annotations

import pytest

from hallpass.core import catalog
from hallpass.core.context import background
from hallpass.core.decision import Code, Decision, Outcome, to_decision
from hallpass.core.integration import CheckRequest, Connection, Deps, Settings, User, find_action
from hallpass.core.log import discard
from hallpass.integrations.fake import Fake


def _no_deps() -> Deps:
    """Go's zero integration.Deps: the fake uses none of it."""

    def no_connection(id: str) -> Connection:
        raise AssertionError("the fake needs no other connection")

    def no_http(s: Settings) -> object:
        raise AssertionError("the fake makes no HTTP calls")

    return Deps(logger=discard(), connection=no_connection, http_client=no_http)  # type: ignore[arg-type]


def conn(fail: str) -> Connection:
    s = Settings("f", "fake", {"users": "u@x.com, U2@x.com", "admins": "a@x.com", "fail": fail})
    return Fake().new(background(), s, _no_deps())


def check(c: Connection, email: str, action: str, resource: str) -> Decision:
    ctx = background()
    try:
        ident = c.resolve_identity(ctx, User(email=email))
    except Exception as e:
        return to_decision(e)
    res = catalog.parse_resource(resource)
    act = find_action(Fake(), action)
    assert act is not None
    try:
        return c.check(ctx, CheckRequest(user=User(email=email), identity=ident, action=act, action_name=action, resource=res))
    except Exception as e:
        return to_decision(e)


def test_action_thing_read_allow() -> None:
    d = check(conn("none"), "u2@x.com", "thing.read", "thing:1")
    assert d.outcome == Outcome.ALLOW, d


def test_action_thing_read_deny() -> None:
    d = check(conn("none"), "nobody@x.com", "thing.read", "thing:1")
    assert d.code == Code.USER_NOT_FOUND and d.outcome == Outcome.DENY, d


def test_action_thing_write_allow() -> None:
    d = check(conn("none"), "a@x.com", "thing.write", "thing:1")
    assert d.outcome == Outcome.ALLOW, d


def test_action_thing_write_deny() -> None:
    d = check(conn("none"), "u@x.com", "thing.write", "thing:1")
    assert d.code == Code.DENIED, d


def test_action_thing_admin_allow() -> None:
    d = check(conn("none"), "a@x.com", "thing.admin", "thing:1")
    assert d.outcome == Outcome.ALLOW, d


def test_action_thing_admin_deny() -> None:
    d = check(conn("none"), "u@x.com", "thing.admin", "thing:1")
    assert d.code == Code.DENIED, d


def test_unknowns() -> None:
    c = conn("none")
    d = check(c, "ambiguous@x.com", "thing.read", "thing:1")
    assert d.code == Code.USER_AMBIGUOUS, d
    d = check(c, "u@x.com", "thing.read", "thing:hidden")
    assert d.code == Code.RESOURCE_NOT_VISIBLE, d
    d = check(c, "u@x.com", "thing.read", "thing:broken")
    assert d.code == Code.UNSUPPORTED, d
    d = check(c, "u@x.com", "thing.read", "other:1")
    assert d.code == Code.INVALID_REQUEST, d
    d = check(conn("upstream_timeout"), "u@x.com", "thing.read", "thing:1")
    assert d.code == Code.UPSTREAM_TIMEOUT, d
    with pytest.raises(Exception):  # noqa: B017 - Go: any error
        conn("credential_rejected").probe(background())
    r = c.probe(background())
    assert r.summary != "", r
