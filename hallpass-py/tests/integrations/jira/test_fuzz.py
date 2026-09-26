"""Port of internal/integrations/jira/fuzz_test.go.

FuzzParseResource becomes a Hypothesis property with the same invariant; its
seed corpus (the f.Add seeds; the Go package has no testdata/fuzz files) is
replayed as plain cases.
"""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from hallpass.core.catalog import ResourceError
from hallpass.core.catalog import parse_resource as catalog_parse_resource
from hallpass.integrations.jira.actions import ISSUE_KEY_RE, PROJECT_KEY_RE, ResKind, parse_resource

SEEDS = ["project:OPS", "issue:OPS-123", "global", "project:ops", "issue:OPS-0", "project:OPS/x", "global:x", "project:OPS?x=1"]


def fuzz_parse_resource(resource: str) -> None:
    """An accepted key always matches the strict project or issue key shape,
    so it is safe in a URL path."""
    try:
        res = catalog_parse_resource(resource)
    except ResourceError:
        return
    try:
        r = parse_resource(res)
    except ValueError:
        return
    if r.kind == ResKind.GLOBAL:
        assert r.key == "", f"global with key {r.key!r}"
    elif r.kind == ResKind.PROJECT:
        assert PROJECT_KEY_RE.fullmatch(r.key), f"unvalidated project key {r.key!r}"
    elif r.kind == ResKind.ISSUE:
        assert ISSUE_KEY_RE.fullmatch(r.key), f"unvalidated issue key {r.key!r}"
    else:
        raise AssertionError(f"unknown kind {r.kind}")


@pytest.mark.parametrize("resource", SEEDS)
def test_fuzz_parse_resource_seeds(resource: str) -> None:
    fuzz_parse_resource(resource)


_TYPES = st.sampled_from(["project", "issue", "global", "board"])
_KEYS = st.one_of(st.text(), st.from_regex(r"[A-Z][A-Z0-9_]{1,9}(-[0-9]{1,4})?[\n/?x]?", fullmatch=True))
_RESOURCES = st.one_of(st.text(), st.builds(lambda t, k: t + ":" + k, _TYPES, _KEYS), _TYPES)


@given(_RESOURCES)
def test_fuzz_parse_resource(resource: str) -> None:
    fuzz_parse_resource(resource)
