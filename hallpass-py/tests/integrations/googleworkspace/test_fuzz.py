"""Port of internal/integrations/googleworkspace/fuzz_test.go.

FuzzParseRef becomes a Hypothesis property with the same invariant; its seed
corpus (the f.Add seeds; the Go package has no testdata/fuzz files) is
replayed as plain cases.
"""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from hallpass.core.catalog import ResourceError, parse_resource
from hallpass.core.decision import HallpassError
from hallpass.core.errors import go_lower
from hallpass.integrations.googleworkspace.actions import ACTION_INDEX, ACTION_LIST, CALENDAR_ID_RE, EMAIL_RE, FILE_ID_RE, parse_ref

SEEDS = [
    ("drive.file.read", "file:1AbCdEfGhIjKlMnOpQrStUvWxYz"),
    ("calendar.read", "calendar:primary"),
    ("calendar.read", "calendar:team@example.com"),
    ("group.member", "group:eng@example.com"),
    ("user.active", "user:Dana@Example.com"),
    ("mail.send_as", "mailbox:dana@example.com"),
    ("drive.file.read", "file:../x"),
    ("user.active", "user:dana@example.com/x"),
    ("calendar.read", "calendar:a?b"),
    ("group.member", "group:eng@example.com?x=1"),
]


def fuzz_parse_ref(action: str, resource: str) -> None:
    """An accepted id matches the strict shape of its type, so it is safe as
    a path segment or a query value."""
    i = ACTION_INDEX.get(action)
    if i is None:
        return
    try:
        res = parse_resource(resource)
    except ResourceError:
        return
    try:
        id = parse_ref(action, res)
    except HallpassError:
        return
    assert res.type == ACTION_LIST[i].resource and not res.query, f"type/query slipped through {res}"
    # Ids are path-escaped before use; the regexes must still keep out
    # whitespace and control characters.
    for r in id:
        assert not (ord(r) <= 0x20 or ord(r) == 0x7F), f"whitespace or control character in {id!r}"
    if res.type in ("user", "mailbox", "group"):
        assert EMAIL_RE.fullmatch(id) and id == go_lower(id), f"unvalidated email {id!r}"
    elif res.type == "file":
        assert FILE_ID_RE.fullmatch(id), f"unvalidated file id {id!r}"
    elif res.type == "calendar":
        assert CALENDAR_ID_RE.fullmatch(id), f"unvalidated calendar id {id!r}"
    else:
        raise AssertionError(f"unknown type {res.type!r}")


@pytest.mark.parametrize(("action", "resource"), SEEDS)
def test_fuzz_parse_ref_seeds(action: str, resource: str) -> None:
    fuzz_parse_ref(action, resource)


_ACTIONS = st.one_of(st.sampled_from(sorted(ACTION_INDEX)), st.text())
_TYPES = st.sampled_from(["user", "mailbox", "group", "file", "calendar", "other"])
_IDS = st.one_of(st.text(), st.builds(lambda a, b: a + "@" + b, st.text(), st.text()), st.from_regex(FILE_ID_RE, fullmatch=True))
_RESOURCES = st.one_of(st.text(), st.builds(lambda t, i: t + ":" + i, _TYPES, _IDS))


@given(_ACTIONS, _RESOURCES)
def test_fuzz_parse_ref(action: str, resource: str) -> None:
    fuzz_parse_ref(action, resource)
