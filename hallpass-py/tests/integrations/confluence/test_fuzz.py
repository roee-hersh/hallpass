"""Port of internal/integrations/confluence/fuzz_test.go.

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
from hallpass.integrations.confluence.actions import CONTENT_ID_RE, SPACE_KEY_RE, ResKind, parse_resource

SEEDS = ["page:123", "blogpost:9", "space:OPS", "page:0", "page:12a", "space:O S", "space:OPS/x", "page:1?x=1", "attachment:1"]


def fuzz_parse_resource(resource: str) -> None:
    """An accepted id is a numeric content id or a strict space key, safe in
    a URL path or query."""
    try:
        res = catalog_parse_resource(resource)
    except ResourceError:
        return
    try:
        r = parse_resource(res)
    except ValueError:
        return
    if r.kind in (ResKind.PAGE, ResKind.BLOGPOST):
        assert CONTENT_ID_RE.fullmatch(r.id), f"unvalidated content id {r.id!r}"
    elif r.kind == ResKind.SPACE:
        assert SPACE_KEY_RE.fullmatch(r.id), f"unvalidated space key {r.id!r}"
    else:
        raise AssertionError(f"unknown kind {r.kind!r}")


@pytest.mark.parametrize("resource", SEEDS)
def test_fuzz_parse_resource_seeds(resource: str) -> None:
    fuzz_parse_resource(resource)


_TYPES = st.sampled_from(["page", "blogpost", "space", "attachment"])
_IDS = st.one_of(st.text(), st.from_regex(r"[0-9A-Za-z~_-]{1,20}[\n/? ]?", fullmatch=True))
_RESOURCES = st.one_of(st.text(), st.builds(lambda t, i: t + ":" + i, _TYPES, _IDS), _TYPES)


@given(_RESOURCES)
def test_fuzz_parse_resource(resource: str) -> None:
    fuzz_parse_resource(resource)
