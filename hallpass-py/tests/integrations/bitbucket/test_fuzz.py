"""Port of internal/integrations/bitbucket/fuzz_test.go: FuzzParseTarget as
a Hypothesis property plus a replay of its seed corpus. The Go package has
no testdata/fuzz directory, so the seeds are the f.Add calls."""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from hallpass.core.catalog import ResourceError, parse_resource
from hallpass.core.decision import HallpassError
from hallpass.integrations.bitbucket.actions import ACTIONS, parse_target, valid_branch, valid_slug

SEEDS = [
    ("repo.read", "repo:api"),
    ("repo.push", "repo:api@release/1.2"),
    ("repo.push", "repo:APP/api@main"),
    ("project.read", "project:APP"),
    ("workspace.member", "workspace"),
    ("repo.read", "repo:api@main"),
    ("repo.push", "repo:api@a..b"),
    ("repo.read", "repo:a/b/c"),
    ("repo.read", "repo:api?x=1"),
    ("project.read", "project:~dana"),
]


def fuzz_parse_target(action: str, resource: str) -> None:
    """An accepted target is made of validated slugs and, if present, a
    validated branch name, so every piece is safe in a URL path."""
    try:
        res = parse_resource(resource)
    except ResourceError:
        return
    for dc in (False, True):
        try:
            tg = parse_target(action, res, dc)
        except HallpassError:
            continue
        assert not res.query, f"query slipped through {res}"
        assert tg.action.name == action, f"action {action!r} became {tg.action.name!r}"
        assert tg.project == "" or valid_slug(tg.project), f"unvalidated project {tg.project!r} from {resource!r}"
        assert tg.repo == "" or valid_slug(tg.repo), f"unvalidated repo {tg.repo!r} from {resource!r}"
        assert tg.branch == "" or (valid_branch(tg.branch) and tg.action.branch != ""), f"unvalidated branch {tg.branch!r} from {resource!r}"
        assert not any(ch in tg.project + tg.repo for ch in "/?#\\ "), f"path characters in {tg}"
        assert not (dc and tg.repo != "" and tg.project == ""), f"data center repo without project from {resource!r}"
        assert not (not dc and tg.repo != "" and tg.project != ""), f"cloud repo with project from {resource!r}"


@pytest.mark.parametrize(("action", "resource"), SEEDS)
def test_fuzz_parse_target_seeds(action: str, resource: str) -> None:
    fuzz_parse_target(action, resource)


# Resources shaped like the real ones, with the characters that matter to
# the validators.
_PIECE = st.text(alphabet=st.sampled_from(list("aZ09_.-/@?=&~^:*[\\{} \t\x00\x7f%é")), max_size=24)
_RESOURCE = st.one_of(
    st.text(max_size=40),
    st.builds(lambda t, p: t + ":" + p, st.sampled_from(["repo", "project", "workspace", "Repo", ""]), _PIECE),
    st.builds(lambda p, r, b: "repo:" + p + "/" + r + "@" + b, _PIECE, _PIECE, _PIECE),
    st.just("workspace"),
)
_ACTION = st.one_of(st.sampled_from(sorted(ACTIONS)), st.text(max_size=20))


@settings(max_examples=500, deadline=None)
@given(_ACTION, _RESOURCE)
def test_fuzz_parse_target(action: str, resource: str) -> None:
    fuzz_parse_target(action, resource)
