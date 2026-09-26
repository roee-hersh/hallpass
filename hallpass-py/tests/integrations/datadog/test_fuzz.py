"""Port of internal/integrations/datadog/fuzz_test.go.

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
from hallpass.integrations.datadog.actions import ACTION_LIST, ASSET_TYPES, id_ok, parse_target, permission_ok

SEEDS = [
    ("monitor.edit", "monitor:123"),
    ("dashboard.edit", "dashboard:abc-def-ghi"),
    ("logs.read", "org"),
    ("raw:monitors_write", "monitor:1"),
    ("raw:api_keys_read", "org"),
    ("monitor.edit", "monitor:1/2"),
    ("logs.read", "org:1"),
    ("raw:Monitors", "org"),
]


def fuzz_parse_target(action: str, resource: str) -> None:
    """An accepted asset id is alphanumeric with hyphens and underscores,
    and an accepted permission is a lower-case identifier."""
    try:
        res = parse_resource(resource)
    except ResourceError:
        return
    try:
        tg = parse_target(action, res)
    except HallpassError:
        return
    assert not res.query, f"query slipped through {res}"
    assert permission_ok(tg.permission()), f"unvalidated permission {tg.permission()!r} from {action!r}"
    if action.startswith("raw:"):
        assert tg.permission() == action.removeprefix("raw:"), f"raw action {action!r} became {tg.permission()!r}"
    if tg.typ == "org":
        assert tg.id == "" and tg.relation() == "", f"org target with id or relation: {tg}"
        return
    assert tg.typ in ASSET_TYPES and id_ok(tg.id) and tg.id == res.id, f"unvalidated asset {tg} from {resource!r}"
    assert tg.relation() in ("editor", "viewer"), f"asset target without a relation: {tg}"


@pytest.mark.parametrize(("action", "resource"), SEEDS)
def test_fuzz_parse_target_seeds(action: str, resource: str) -> None:
    fuzz_parse_target(action, resource)


_PERMS = sorted({a.permission for a in ACTION_LIST})
_ACTIONS = st.one_of(
    st.sampled_from([a.name for a in ACTION_LIST]),
    st.builds(lambda p: "raw:" + p, st.one_of(st.sampled_from(_PERMS), st.text())),
    st.text(),
)
_TYPES = st.sampled_from([*sorted(ASSET_TYPES), "org", "synthetic"])
_RESOURCES = st.one_of(st.text(), st.builds(lambda t, i: t + ":" + i, _TYPES, st.text()), _TYPES)


@given(_ACTIONS, _RESOURCES)
def test_fuzz_parse_target(action: str, resource: str) -> None:
    fuzz_parse_target(action, resource)
