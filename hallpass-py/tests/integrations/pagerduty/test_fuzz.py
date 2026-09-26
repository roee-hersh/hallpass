"""Port of internal/integrations/pagerduty/fuzz_test.go.

FuzzParseTarget becomes a Hypothesis property with the same invariant; its
seed corpus (the f.Add seeds; the Go package has no testdata/fuzz files) is
replayed as plain cases.
"""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from hallpass.core.catalog import ResourceError, parse_resource
from hallpass.core.decision import HallpassError
from hallpass.integrations.pagerduty.actions import ACTION_LIST, id_ok, parse_target

SEEDS = [
    ("incident.acknowledge", "incident:PINC1"),
    ("service.edit", "service:psvc1"),
    ("account.admin", "account"),
    ("team.member", "team:PTEAM1/x"),
    ("team.member", "team:P TEAM"),
    ("account.admin", "account:x"),
]


def fuzz_parse_target(action: str, resource: str) -> None:
    """An accepted id is upper-case alphanumeric, so it is safe as a path
    segment."""
    try:
        res = parse_resource(resource)
    except ResourceError:
        return
    try:
        tg = parse_target(action, res)
    except HallpassError:
        return
    assert not res.query, f"query slipped through {res}"
    assert tg.action.name == action, f"action {action!r} became {tg.action.name!r}"
    if tg.action.resource == "account":
        assert tg.id == "", f"account with id {tg.id!r}"
        return
    assert id_ok(tg.id), f"unvalidated id {tg.id!r} from {resource!r}"


@pytest.mark.parametrize(("action", "resource"), SEEDS)
def test_fuzz_parse_target_seeds(action: str, resource: str) -> None:
    fuzz_parse_target(action, resource)


_ACTIONS = st.one_of(st.sampled_from([a.name for a in ACTION_LIST]), st.text())
_TYPES = st.sampled_from(sorted({a.resource for a in ACTION_LIST}) + ["other"])
_RESOURCES = st.one_of(st.text(), st.builds(lambda t, i: t + ":" + i, _TYPES, st.text()), _TYPES)


@given(_ACTIONS, _RESOURCES)
def test_fuzz_parse_target(action: str, resource: str) -> None:
    fuzz_parse_target(action, resource)
