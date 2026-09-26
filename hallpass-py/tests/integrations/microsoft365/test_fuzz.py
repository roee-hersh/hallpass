"""Port of internal/integrations/microsoft365/fuzz_test.go.

FuzzParseRef and FuzzODataString become Hypothesis properties with the same
invariants; their seed corpora (the f.Add seeds; the Go package has no
testdata/fuzz files) are replayed as plain cases.
"""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from hallpass.core.catalog import ResourceError, parse_resource
from hallpass.core.decision import HallpassError
from hallpass.integrations.microsoft365.actions import ACTION_RESOURCES, CHANNEL_ID_RE, DRIVE_ID_RE, EMAIL_RE, GUID_RE, parse_ref
from hallpass.integrations.microsoft365.microsoft365 import odata_string

PARSE_REF_SEEDS = [
    ("group.member", "group:11111111-2222-3333-4444-555555555555"),
    ("team.member", "team:11111111-2222-3333-4444-555555555555"),
    ("channel.read", "team:11111111-2222-3333-4444-555555555555/channel/19:abc@thread.tacv2"),
    ("file.read", "drive:b!abc/item/01ABC"),
    ("user.active", "user:dana@example.com"),
    ("mail.send_as_self", "mailbox:dana@example.com"),
    ("channel.read", "team:11111111-2222-3333-4444-555555555555"),
    ("team.member", "team:11111111-2222-3333-4444-555555555555/channel/x"),
    ("file.read", "drive:b!abc/item/../x"),
    ("group.member", "group:not-a-guid"),
    ("user.active", "user:dana@example.com?x=1"),
]


def fuzz_parse_ref(action: str, resource: str) -> None:
    """Every part of an accepted ref matches the strict shape of its type
    (GUIDs where Graph needs GUIDs, no whitespace or control characters
    anywhere), so it is safe as a path segment."""
    if action not in ACTION_RESOURCES:
        return
    try:
        res = parse_resource(resource)
    except ResourceError:
        return
    try:
        ref = parse_ref(action, res)
    except HallpassError:
        return
    assert ref.typ == res.type and not res.query, f"type/query slipped through {res}"
    for part in (ref.id, ref.channel, ref.item):
        for r in part:
            assert not (ord(r) <= 0x20 or ord(r) == 0x7F), f"whitespace or control character in {ref}"
    if ref.typ in ("user", "mailbox"):
        assert EMAIL_RE.fullmatch(ref.id) or GUID_RE.fullmatch(ref.id), f"unvalidated id {ref.id!r}"
    elif ref.typ in ("group", "role"):
        assert GUID_RE.fullmatch(ref.id), f"unvalidated guid {ref.id!r}"
    elif ref.typ == "team":
        assert GUID_RE.fullmatch(ref.id) and (ref.channel == "" or CHANNEL_ID_RE.fullmatch(ref.channel)), f"unvalidated team ref {ref}"
        assert not ((action.startswith("channel.") and ref.channel == "") or (action.startswith("team.") and ref.channel != "")), (
            f"channel presence does not match action {action}: {ref}"
        )
    elif ref.typ == "drive":
        assert DRIVE_ID_RE.fullmatch(ref.id) and DRIVE_ID_RE.fullmatch(ref.item) and "/" not in ref.id + ref.item, f"unvalidated drive ref {ref}"
    else:
        raise AssertionError(f"unknown type {ref.typ!r}")


@pytest.mark.parametrize(("action", "resource"), PARSE_REF_SEEDS)
def test_fuzz_parse_ref_seeds(action: str, resource: str) -> None:
    fuzz_parse_ref(action, resource)


_ACTIONS = st.one_of(st.sampled_from(sorted(ACTION_RESOURCES)), st.text())
_TYPES = st.sampled_from(["user", "mailbox", "group", "role", "team", "drive", "other"])
_GUID = st.from_regex(GUID_RE, fullmatch=True)
_IDS = st.one_of(
    st.text(),
    _GUID,
    st.builds(lambda g, c: g + "/channel/" + c, _GUID, st.text()),
    st.builds(lambda d, i: d + "/item/" + i, st.text(), st.text()),
    st.builds(lambda a, b: a + "@" + b, st.text(), st.text()),
)
_RESOURCES = st.one_of(st.text(), st.builds(lambda t, i: t + ":" + i, _TYPES, _IDS))


@given(_ACTIONS, _RESOURCES)
def test_fuzz_parse_ref(action: str, resource: str) -> None:
    fuzz_parse_ref(action, resource)


ODATA_SEEDS = ["o'neil", "''", "a' or 1 eq 1 or 'b", "plain@example.com"]


def fuzz_odata_string(s: str) -> None:
    """An escaped literal never contains a lone quote, so it cannot end a
    $filter string early."""
    lit = odata_string(s)
    assert len(lit) >= 2 and lit[0] == "'" and lit[-1] == "'", f"literal {lit!r} is not quoted"
    inner = lit[1:-1]
    assert "'" not in inner.replace("''", ""), f"literal {lit!r} has a lone quote"


@pytest.mark.parametrize("s", ODATA_SEEDS)
def test_fuzz_odata_string_seeds(s: str) -> None:
    fuzz_odata_string(s)


@given(st.text(alphabet=st.sampled_from(["'", "a", " ", "é"]) | st.characters()))
def test_fuzz_odata_string(s: str) -> None:
    fuzz_odata_string(s)
