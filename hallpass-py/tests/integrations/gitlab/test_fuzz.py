"""Port of internal/integrations/gitlab/fuzz_test.go: FuzzParseTarget as a
Hypothesis property plus a replay of its seed corpus. The Go package has no
testdata/fuzz directory, so the seeds are the f.Add calls."""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from hallpass.core.catalog import ResourceError, parse_resource
from hallpass.integrations.gitlab.actions import ACTIONS, BRANCH_RE, NUMERIC_RE, PATH_RE, SCOPE_PROJECT, parse_target
from tests.harness import examples as _examples

SEEDS = [
    ("project.read", "project:acme/webapp"),
    ("repo.push", "project:acme/webapp@main"),
    ("repo.push", "project:42@release/1.0"),
    ("member.manage", "group:acme"),
    ("repo.push", "project:acme/../admin@x"),
    ("repo.push", "project:acme/webapp@"),
    ("repo.push", "project:acme/webapp@a b"),
    ("project.read", "project:acme/webapp?x=1"),
]


def fuzz_parse_target(action: str, resource: str) -> None:
    """Whatever the caller sends, an accepted target is a numeric id or a
    clean path, and a branch is a plausible git ref with nothing that
    changes the meaning of a URL."""
    spec = ACTIONS.get(action)
    if spec is None:
        return
    try:
        res = parse_resource(resource)
    except ResourceError:
        return
    try:
        tg = parse_target(spec, res)
    except ValueError:
        return
    assert tg.scope == spec.scope and tg.id != "", f"scope/id {tg}"
    assert NUMERIC_RE.fullmatch(tg.id) or PATH_RE.fullmatch(tg.id), f"unvalidated id {tg.id!r}"
    for seg in tg.id.split("/"):
        assert seg not in (".", ".."), f"dot segment in {tg.id!r}"
    if tg.branch != "":
        assert BRANCH_RE.fullmatch(tg.branch) and ".." not in tg.branch and not tg.branch.startswith("-"), f"unvalidated branch {tg.branch!r}"
    assert not (spec.scope != SCOPE_PROJECT and tg.branch != ""), f"branch on a {spec.scope} resource"


@pytest.mark.parametrize(("action", "resource"), SEEDS)
def test_fuzz_parse_target_seeds(action: str, resource: str) -> None:
    fuzz_parse_target(action, resource)


# Resources shaped like the real ones, with the characters that matter to
# the validators (separators, dots, @, ?, spaces, controls, non-ASCII).
_PIECE = st.text(alphabet=st.sampled_from(list("aZ09_.-/@?=&~^:*[\\ \t\x00\x7f%é.")), max_size=24)
_RESOURCE = st.one_of(
    st.text(max_size=40),
    st.builds(lambda t, p: t + ":" + p, st.sampled_from(["project", "group", "repo", "Project", ""]), _PIECE),
    st.builds(lambda p, b: "project:" + p + "@" + b, _PIECE, _PIECE),
)
_ACTION = st.one_of(st.sampled_from(sorted(ACTIONS)), st.text(max_size=20))


@settings(max_examples=_examples(500), deadline=None)
@given(_ACTION, _RESOURCE)
def test_fuzz_parse_target(action: str, resource: str) -> None:
    fuzz_parse_target(action, resource)
