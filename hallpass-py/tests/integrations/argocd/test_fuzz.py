"""Port of internal/integrations/argocd/fuzz_test.go (FuzzBuildRequest,
FuzzGlob) and fuzz_glob_test.go as Hypothesis property tests plus their
seeds. The Go package has no testdata/fuzz directory, so the f.Add seeds
are the whole corpus. The Go test hooks (CompileGlobForTest,
GlobMatchForTest) are the glob module's parse_glob and glob_match."""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from hallpass.core.catalog import ResourceError, parse_resource
from hallpass.integrations.argocd.actions import ACTIONS, OBJ_RE, build_request
from hallpass.integrations.argocd.rbac.glob import GlobError, glob_match, parse_glob
from tests.harness import examples as _examples

BUILD_REQUEST_SEEDS = [
    ("app.get", "applications:dev/web"),
    ("app.action/apps/Deployment/restart", "applications:dev/web"),
    ("app.update/apps/Deployment/ns/x", "applications:p/a"),
    ("project.get", "projects:dev"),
    ("cluster.get", "clusters:https://k"),
    ("app.get", "applications:x y"),
]

GLOB_SEEDS = [("*/*", "a/b"), ("{a,b}", "a"), ("[!a-c]x", "dx"), ("\\*", "*"), ("[", "["), ("{", "{")]


def build_request_invariants(action: str, resource: str) -> None:
    """The object handed to the policy evaluator is always the validated
    resource id, and actions are always known shapes."""
    try:
        res = parse_resource(resource)
    except ResourceError:
        return
    try:
        req = build_request(action, res)
    except ValueError:
        return
    assert req.obj == res.id and OBJ_RE.fullmatch(req.obj), f"obj {req.obj!r} not the validated id {res.id!r}"
    assert req.res != "" and req.act != "", f"empty res/act for {action!r}"


def glob_invariants(pattern: str, text: str) -> None:
    """The matcher never crashes and an invalid pattern never matches."""
    try:
        parse_glob(pattern)
    except GlobError:
        assert not glob_match(pattern, text), f"invalid pattern {pattern!r} matched"
        return
    glob_match(pattern, text)


@pytest.mark.parametrize(("action", "resource"), BUILD_REQUEST_SEEDS)
def test_fuzz_build_request_seeds(action: str, resource: str) -> None:
    build_request_invariants(action, resource)


@pytest.mark.parametrize(("pattern", "text"), GLOB_SEEDS)
def test_fuzz_glob_seeds(pattern: str, text: str) -> None:
    glob_invariants(pattern, text)


_SEG = st.text(alphabet="abAZ09._- /", max_size=12)
_ACTIONS = st.one_of(
    st.sampled_from(sorted(ACTIONS)),
    st.builds(lambda p, parts: p + "/" + "/".join(parts), st.sampled_from(["app.action", "app.update", "app.delete", "app.get"]), st.lists(_SEG, max_size=5)),
    st.text(max_size=40),
)
_RESOURCES = st.one_of(
    st.builds(
        lambda t, i: t + ":" + i,
        st.sampled_from(["applications", "applicationsets", "logs", "exec", "projects", "clusters", "repositories", "write_repositories", "things"]),
        st.text(alphabet="abc/:.-_ \t\x00\x7f日", max_size=30),
    ),
    st.text(max_size=60),
)


@settings(max_examples=_examples(500), deadline=None)
@given(_ACTIONS, _RESOURCES)
def test_fuzz_build_request(action: str, resource: str) -> None:
    build_request_invariants(action, resource)


_GLOB_CHARS = "ab/*?[]!-{},\\日"


@settings(max_examples=_examples(1000), deadline=None)
@given(st.text(alphabet=_GLOB_CHARS, max_size=20), st.text(alphabet=_GLOB_CHARS, max_size=20))
def test_fuzz_glob(pattern: str, text: str) -> None:
    glob_invariants(pattern, text)
