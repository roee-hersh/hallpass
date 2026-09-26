"""Port of internal/integrations/kubernetes/fuzz_test.go (FuzzBuildAttributes)
as a Hypothesis property test plus its seed corpus. The Go package has no
testdata/fuzz directory, so the f.Add seeds are the whole corpus."""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from hallpass.core.catalog import ResourceError, parse_resource
from hallpass.integrations.kubernetes.actions import (
    ALIASES,
    GROUP_RE,
    NAME_RE,
    NAMESPACE_RE,
    PATH_RE,
    RESOURCE_RE,
    VERB_RE,
    build_attributes,
)

SEEDS = [
    ("raw:get:pods", "namespace:payments?name=api-0"),
    ("raw:get", "nonresource:/version"),
    ("scale", "namespace:payments?resource=deployments.apps&name=api"),
    ("impersonate", "cluster?name=admin"),
    ("raw:create:deployments.apps/scale", "namespace:x"),
    ("pods.exec", "namespace:payments?name=a b"),
    ("raw:get:pods", "namespace:payments?namespace=other"),
]


def build_attributes_invariants(action: str, resource: str) -> None:
    """Whatever the caller sends, the attributes that reach the
    SubjectAccessReview are made only of validated pieces."""
    try:
        res = parse_resource(resource)
    except ResourceError:
        return
    if not action.startswith("raw:") and action not in ALIASES:
        return
    try:
        a = build_attributes(action, res)
    except ValueError:
        return
    if a.non_resource_path != "":
        assert PATH_RE.fullmatch(a.non_resource_path) and a.resource == "", f"bad nonresource {a}"
        return
    assert VERB_RE.fullmatch(a.verb) and RESOURCE_RE.fullmatch(a.resource), f"unvalidated verb/resource {a}"
    assert a.group == "" or GROUP_RE.fullmatch(a.group), f"unvalidated group {a}"
    assert a.subresource == "" or RESOURCE_RE.fullmatch(a.subresource), f"unvalidated subresource {a}"
    assert a.name == "" or NAME_RE.fullmatch(a.name), f"unvalidated name {a}"
    assert a.namespace == "" or NAMESPACE_RE.fullmatch(a.namespace), f"unvalidated namespace {a}"


@pytest.mark.parametrize(("action", "resource"), SEEDS)
def test_fuzz_build_attributes_seeds(action: str, resource: str) -> None:
    build_attributes_invariants(action, resource)


_ACTIONS = st.one_of(
    st.sampled_from(sorted(ALIASES)),
    st.builds(lambda s: "raw:" + s, st.text(alphabet="abcdefgxyzABZ019.:/-_ \n", max_size=40)),
    st.text(max_size=40),
)
_RESOURCES = st.one_of(
    st.builds(
        lambda t, i, q: t + i + q,
        st.sampled_from(["namespace:", "cluster", "cluster:", "nonresource:", "pod:"]),
        st.text(alphabet="abcxyzABC019-_./*~ :\n", max_size=30),
        st.sampled_from(["", "?name=", "?resource=", "?subresource=", "?namespace=", "?name=a&resource="]).flatmap(
            lambda p: st.text(alphabet="abcxyzABC019-_./:%20 \n", max_size=30).map(lambda v: p + v if p else "")
        ),
    ),
    st.text(max_size=60),
)


@settings(max_examples=500, deadline=None)
@given(_ACTIONS, _RESOURCES)
def test_fuzz_build_attributes(action: str, resource: str) -> None:
    build_attributes_invariants(action, resource)
