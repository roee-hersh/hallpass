"""Port of internal/integrations/linear/fuzz_test.go.

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
from hallpass.core.errors import go_lower
from hallpass.integrations.linear.actions import ACTION_LIST, ISSUE_KEY_RE, SLUG_RE, TEAM_KEY_RE, UUID_RE, parse_target

SEEDS = [
    ("team.view", "team:ENG"),
    ("issue.view", "issue:ENG-123"),
    ("project.view", "project:abc-def"),
    ("workspace.admin", "workspace"),
    ("team.view", "team:00000000-0000-4000-8000-000000000001"),
    ("issue.view", "issue:eng-1"),
    ("team.view", "team:ENG?x=y"),
    ("team.view", "team:a b"),
]


def fuzz_parse_target(action: str, resource: str) -> None:
    """An accepted id is a Linear uuid, an upper-case team key, an upper-case
    issue identifier or a project slug, with no query."""
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
    if tg.action.resource == "workspace":
        assert tg.id == "", f"workspace with id {tg}"
        return
    if tg.by_id:
        assert UUID_RE.fullmatch(tg.id) and tg.id == go_lower(tg.id), f"by_id with {tg.id!r}"
        return
    ok = False
    if tg.action.resource == "team":
        ok = TEAM_KEY_RE.fullmatch(tg.id) is not None
    elif tg.action.resource == "issue":
        ok = ISSUE_KEY_RE.fullmatch(tg.id) is not None
    elif tg.action.resource == "project":
        ok = SLUG_RE.fullmatch(tg.id) is not None
    assert ok and not any(ch in tg.id for ch in ' /?#"\\'), f"unvalidated id {tg.id!r} from {resource!r}"


@pytest.mark.parametrize(("action", "resource"), SEEDS)
def test_fuzz_parse_target_seeds(action: str, resource: str) -> None:
    fuzz_parse_target(action, resource)


_ACTIONS = st.one_of(st.sampled_from([a.name for a in ACTION_LIST]), st.text())
_TYPES = st.sampled_from([*sorted({a.resource for a in ACTION_LIST}), "other"])
_IDS = st.one_of(
    st.text(),
    st.from_regex(r"[A-Za-z][A-Za-z0-9]{0,10}(-[0-9]{1,10})?(\n| |\?x=1|/x)?", fullmatch=True),
    st.uuids().map(str),
    st.uuids().map(lambda u: str(u).upper()),
)
_RESOURCES = st.one_of(st.text(), st.builds(lambda t, i: t + ":" + i, _TYPES, _IDS), _TYPES)


@given(_ACTIONS, _RESOURCES)
def test_fuzz_parse_target(action: str, resource: str) -> None:
    fuzz_parse_target(action, resource)
