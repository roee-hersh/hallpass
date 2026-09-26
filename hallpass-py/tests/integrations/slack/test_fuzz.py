"""Port of internal/integrations/slack/fuzz_test.go.

FuzzValidateResource becomes a Hypothesis property with the same invariant;
its seed corpus (the f.Add seeds; the Go package has no testdata/fuzz files)
is replayed as plain cases.
"""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from hallpass.core.catalog import ResourceError, parse_resource
from hallpass.integrations.slack.actions import (
    ACTION_LIST,
    CHANNEL_ID_RE,
    RES_CHANNEL,
    RES_USERGROUP,
    RES_WORKSPACE,
    USERGROUP_ID_RE,
    validate_resource,
)

SEEDS = [
    ("channel.read", "channel:C0123456789"),
    ("usergroup.member", "usergroup:S0123456789"),
    ("user.active", "workspace"),
    ("channel.read", "channel:c0123456789"),
    ("channel.read", "channel:C0123456789&x=1"),
    ("user.active", "workspace:x"),
    ("channel.read", "channel:C0123456789?x=1"),
]


def fuzz_validate_resource(action: str, resource: str) -> None:
    """An accepted id is a Slack channel or user group id and never anything
    else that could reach a query string."""
    try:
        res = parse_resource(resource)
    except ResourceError:
        return
    try:
        a = validate_resource(action, res)
    except ValueError:
        return
    assert a.resource == res.type and not res.query, f"type/query slipped through {a} {res}"
    if a.resource == RES_WORKSPACE:
        assert res.id == "", f"workspace with id {res.id!r}"
    elif a.resource == RES_CHANNEL:
        assert CHANNEL_ID_RE.fullmatch(res.id), f"unvalidated channel {res.id!r}"
    elif a.resource == RES_USERGROUP:
        assert USERGROUP_ID_RE.fullmatch(res.id), f"unvalidated usergroup {res.id!r}"
    else:
        raise AssertionError(f"unknown resource type {a.resource!r}")


@pytest.mark.parametrize(("action", "resource"), SEEDS)
def test_fuzz_validate_resource_seeds(action: str, resource: str) -> None:
    fuzz_validate_resource(action, resource)


_ACTIONS = st.one_of(st.sampled_from([a.name for a in ACTION_LIST]), st.text())
_TYPES = st.sampled_from(sorted({a.resource for a in ACTION_LIST}) + ["other"])
_IDS = st.one_of(st.text(), st.from_regex(r"[CGS][A-Z0-9]{8,12}(\n|\?x=1|&x=1)?", fullmatch=True))
_RESOURCES = st.one_of(st.text(), st.builds(lambda t, i: t + ":" + i, _TYPES, _IDS), _TYPES)


@given(_ACTIONS, _RESOURCES)
def test_fuzz_validate_resource(action: str, resource: str) -> None:
    fuzz_validate_resource(action, resource)
