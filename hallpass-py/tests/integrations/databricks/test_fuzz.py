"""Port of internal/integrations/databricks/fuzz_test.go.

FuzzParseRef becomes a Hypothesis property with the same invariant; its
seed corpus (the f.Add seeds; the Go package has no testdata/fuzz files) is
replayed as plain cases.
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from hallpass.core.catalog import ResourceError, parse_resource
from hallpass.core.decision import HallpassError
from hallpass.integrations.databricks.actions import (
    ACTION_INDEX,
    ACTION_LIST,
    RAW_RE,
    UC_NAME_RE,
    UC_TYPES,
    WS_ID_RE,
    WS_TYPES,
    known_level,
    levels_of,
    parse_ref,
)
from tests.harness import examples as _examples

SEEDS = [
    ("table.read", "table:main.sales.orders"),
    ("catalog.use", "catalog:main"),
    ("uc.manage", "volume:main.sales.files"),
    ("cluster.attach", "cluster:0123-456789-abcde1f2"),
    ("raw:CAN_RESTART", "cluster:0123-456789-abcde1f2"),
    ("raw:SELECT", "table:main.sales.orders"),
    ("table.read", "table:main.sales.`orders`"),
    ("table.read", "table:main.sales.orders?x=1"),
    ("cluster.attach", "cluster:a/b"),
    ("raw:select", "table:main.sales.orders"),
]


def fuzz_parse_ref(action: str, resource: str) -> None:
    """An accepted question carries a Unity Catalog name made only of
    identifier parts, or a workspace object id of the strict shape, and a
    privilege or level in upper case."""
    try:
        res = parse_resource(resource)
    except ResourceError:
        return
    try:
        q = parse_ref(action, res)
    except HallpassError:
        return
    assert not res.query, f"query slipped through {res}"
    if q.uc:
        assert res.type in UC_TYPES and q.full_name == res.id, f"uc question {q} from {resource!r}"
        for part in q.full_name.split("."):
            assert UC_NAME_RE.fullmatch(part), f"unvalidated name part {part!r} from {resource!r}"
        assert q.privileges, f"uc question without privileges from {action!r}"
        for p in q.privileges:
            assert RAW_RE.fullmatch(p), f"unvalidated privilege {p!r}"
    else:
        ws = WS_TYPES.get(res.type)
        assert ws is not None and q.object == ws.object and q.id == res.id and WS_ID_RE.fullmatch(q.id), f"workspace question {q} from {resource!r}"
        assert RAW_RE.fullmatch(q.level), f"unvalidated level {q.level!r}"
    if action.startswith("raw:"):
        want = action.removeprefix("raw:")
        got = q.privileges[0] if q.uc else q.level
        assert got == want, f"raw action {action!r} became {got!r}"
        if not q.uc:
            assert known_level(q.chains, got), f"unknown level {got!r} accepted for {resource!r}"
    else:
        assert action in ACTION_INDEX, f"unknown action {action!r} accepted"


@pytest.mark.parametrize(("action", "resource"), SEEDS)
def test_fuzz_parse_ref_seeds(action: str, resource: str) -> None:
    fuzz_parse_ref(action, resource)


_LEVELS = sorted({lv for ws in WS_TYPES.values() for lv in levels_of(ws.chains)} | {"IS_OWNER", "SELECT", "MODIFY", "CREATE_VOLUME"})
_ACTIONS = st.one_of(
    st.sampled_from([a.name for a in ACTION_LIST]),
    st.builds(lambda s: "raw:" + s, st.one_of(st.sampled_from(_LEVELS), st.text(alphabet="ABCXYZ_019a- ", max_size=12))),
    st.text(max_size=30),
)
_TYPES = st.sampled_from(sorted([*UC_TYPES, *WS_TYPES, "thing", "user"]))
_RESOURCES = st.one_of(
    st.builds(lambda t, i: t + ":" + i, _TYPES, st.text(alphabet="abcXYZ019_-.`/ ?=%", max_size=40)),
    st.text(max_size=60),
)


@settings(max_examples=_examples(1000), deadline=None)
@given(_ACTIONS, _RESOURCES)
def test_fuzz_parse_ref(action: str, resource: str) -> None:
    fuzz_parse_ref(action, resource)
