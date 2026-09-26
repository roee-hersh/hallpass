"""Port of internal/integrations/salesforce/fuzz_test.go.

FuzzParseTarget and FuzzSOQLString become Hypothesis properties with the
same invariants; their seed corpora (the f.Add seeds; the Go package has no
testdata/fuzz files) are replayed as plain cases.
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from hallpass.core.catalog import ResourceError, parse_resource
from hallpass.integrations.salesforce.actions import ACTION_LIST, ACTIONS, parse_target
from hallpass.integrations.salesforce.soql import API_NAME_RE, ID_RE, PERM_NAME_RE, soql_string, validate_email
from tests.harness import examples as _examples

PARSE_TARGET_SEEDS = [
    ("record.read", "record:001000000000001AAA"),
    ("object.create", "object:Invoice__c"),
    ("field.edit", "field:Account.Rating"),
    ("system.permission", "permission:PermissionsApiEnabled"),
    ("permset.assigned", "permset:acme__Sales_Ops"),
    ("user.active", "user:dana@example.com"),
    ("user.active", "user:o'neil@example.com"),
    ("user.active", "user:Dana <dana@example.com>"),
    ("object.read", "object:Account' OR 1=1"),
    ("record.read", "record:001000000000001AAA?x=1"),
    ("permset.assigned", "permset:a__b__c"),
]


def fuzz_parse_target(action: str, resource: str) -> None:
    """Every part of an accepted target matches the strict identifier
    shapes, so nothing that could break out of a SOQL statement is ever
    interpolated. Emails are the one free-text value; they must round-trip
    through net/mail and carry no control characters."""
    a = ACTIONS.get(action)
    if a is None:
        return
    try:
        res = parse_resource(resource)
    except ResourceError:
        return
    try:
        tg = parse_target(a, res)
    except ValueError:
        return
    assert tg.record_id == "" or ID_RE.fullmatch(tg.record_id), f"unvalidated id {tg.record_id!r}"
    for n in (tg.object, tg.field, tg.perm_set, tg.perm_set_ns):
        assert n == "" or API_NAME_RE.fullmatch(n), f"unvalidated api name {n!r}"
    assert tg.perm == "" or PERM_NAME_RE.fullmatch(tg.perm), f"unvalidated permission {tg.perm!r}"
    assert "__" not in tg.perm_set and "__" not in tg.perm_set_ns, f"namespace separator left in {tg}"
    if tg.email != "":
        validate_email(tg.email)  # raises for an unvalidated email
        lit = soql_string(tg.email)
        # An escaped literal never holds a bare quote or a control byte.
        assert not any(c in lit for c in "\n\r\t") and "'" not in lit.replace("\\'", ""), f"literal {lit!r} not inert"


@pytest.mark.parametrize(("action", "resource"), PARSE_TARGET_SEEDS)
def test_fuzz_parse_target_seeds(action: str, resource: str) -> None:
    fuzz_parse_target(action, resource)


_ACTIONS = st.one_of(st.sampled_from([a.name for a in ACTION_LIST]), st.text())
_TYPES = st.sampled_from(["record", "object", "field", "permission", "permset", "user"])
_ID_TEXT = st.one_of(
    st.text(),
    st.from_regex(r"[A-Za-z0-9_.'@<> \"\\-]{0,40}", fullmatch=True),
    st.from_regex(r"[a-zA-Z0-9]{15}([a-zA-Z0-9]{3})?", fullmatch=True),
    st.from_regex(r"[A-Za-z][A-Za-z0-9_]{0,20}(__[A-Za-z0-9_]{0,10}){0,2}(\.[A-Za-z0-9_]{0,10})?", fullmatch=True),
    st.from_regex(r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]{1,20}@[A-Za-z0-9.\[\]:-]{1,20}", fullmatch=True),
)
_RESOURCES = st.one_of(st.text(), st.builds(lambda t, i: t + ":" + i, _TYPES, _ID_TEXT))


@settings(max_examples=_examples(500), deadline=None)
@given(_ACTIONS, _RESOURCES)
def test_fuzz_parse_target(action: str, resource: str) -> None:
    fuzz_parse_target(action, resource)


SOQL_STRING_SEEDS = ["a'b", "a\\'b", "\\", "a\nb", '"', "\\\\'", "plain@example.com"]


def fuzz_soql_string(s: str) -> None:
    """The escaped literal never contains an unescaped quote, and every
    backslash is part of an escape sequence."""
    lit = soql_string(s)
    i = 0
    while i < len(lit):
        c = lit[i]
        if c == "\\":
            assert i + 1 < len(lit) and lit[i + 1] in "\\'\"nrt", f"dangling backslash in {lit!r}"
            i += 1
        else:
            assert c not in "'\"\n\r\t", f"unescaped {c!r} in {lit!r}"
        i += 1


@pytest.mark.parametrize("s", SOQL_STRING_SEEDS)
def test_fuzz_soql_string_seeds(s: str) -> None:
    fuzz_soql_string(s)


@settings(max_examples=_examples(1000), deadline=None)
@given(st.one_of(st.text(), st.from_regex(r"[\\'\"\n\r\ta-z]*", fullmatch=True)))
def test_fuzz_soql_string(s: str) -> None:
    fuzz_soql_string(s)
