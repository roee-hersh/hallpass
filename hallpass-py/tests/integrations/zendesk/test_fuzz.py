"""Port of internal/integrations/zendesk/fuzz_test.go.

FuzzParseTarget becomes a Hypothesis property with the same invariants; its
seed corpus (the f.Add seeds; the Go package has no testdata/fuzz files) is
replayed as plain cases.
"""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from hallpass.core.catalog import ResourceError, parse_resource
from hallpass.core.decision import HallpassError
from hallpass.integrations.zendesk.actions import ACTION_LIST, id_ok, parse_target

SEEDS = [
    ("ticket.view", "ticket:123"),
    ("organization.edit", "organization:5"),
    ("user.edit", "user:1"),
    ("account.admin", "account"),
    ("ticket.view", "ticket:1/2"),
    ("ticket.view", "ticket:1?x=y"),
    ("ticket.view", "ticket:-1"),
    ("account.admin", "account:1"),
]


def _parse_int64(s: str) -> int | None:
    """Go's strconv.ParseInt(s, 10, 64): None on a syntax or range error."""
    t = s[1:] if s[:1] in "+-" else s
    if not t or not all("0" <= c <= "9" for c in t):
        return None
    n = int(s)
    return n if -(1 << 63) <= n < (1 << 63) else None


def fuzz_parse_target(action: str, resource: str) -> None:
    """An accepted id is a plain decimal Zendesk id, and the resource type
    is the one the action takes."""
    try:
        res = parse_resource(resource)
    except ResourceError:
        return
    try:
        tg = parse_target(action, res)
    except HallpassError:
        return
    assert not res.query, f"query slipped through {res}"
    assert tg.action.resource == res.type, f"type {res.type!r} for action {action!r}"
    if tg.action.resource == "account":
        assert tg.id == "", f"account with id {tg}"
        return
    assert id_ok(tg.id), f"unvalidated id {tg.id!r} from {resource!r}"
    n = _parse_int64(tg.id)
    assert n is not None and n > 0 and str(n) == tg.id, f"id {tg.id!r} is not a canonical positive int64"


@pytest.mark.parametrize(("action", "resource"), SEEDS)
def test_fuzz_parse_target_seeds(action: str, resource: str) -> None:
    fuzz_parse_target(action, resource)


_ACTIONS = st.one_of(st.sampled_from([a.name for a in ACTION_LIST]), st.text())
_TYPES = st.sampled_from([*sorted({a.resource for a in ACTION_LIST}), "other"])
_RESOURCES = st.one_of(st.text(), st.builds(lambda t, i: t + ":" + i, _TYPES, st.text()), _TYPES)


@given(_ACTIONS, _RESOURCES)
def test_fuzz_parse_target(action: str, resource: str) -> None:
    fuzz_parse_target(action, resource)
