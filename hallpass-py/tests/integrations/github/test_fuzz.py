"""Port of internal/integrations/github/fuzz_test.go.

FuzzParseTarget becomes a Hypothesis property with the same invariants; its
seed corpus (the f.Add seeds; the Go package has no testdata/fuzz files) is
replayed as plain cases.
"""

from __future__ import annotations

import re

import pytest
from hypothesis import given
from hypothesis import strategies as st

from hallpass.core.catalog import ResourceError, go_bytes, parse_resource
from hallpass.integrations.github.actions import ACTIONS, parse_target, valid_branch, valid_repo_name

SEEDS = [
    ("repo.read", "repo:acme/webapp"),
    ("repo.push", "repo:acme/webapp@main"),
    ("org.member", "org:acme"),
    ("team.member", "team:acme/platform"),
    ("repo.read", "repo:other/webapp"),
    ("repo.push", "repo:acme/webapp@../x"),
    ("repo.push", "repo:acme/..@main"),
    ("team.member", "team:acme/Platform Team"),
    ("repo.read", "repo:acme/webapp?x=1"),
]

_SLUG_RE = re.compile(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?")


def fuzz_parse_target(action: str, resource: str) -> None:
    """Every part of an accepted target is a validated login, repository
    name, team slug or branch, and always inside the configured
    organization."""
    a = ACTIONS.get(action)
    if a is None:
        return
    try:
        res = parse_resource(resource)
    except ResourceError:
        return
    try:
        tg = parse_target(a, "acme", res)
    except ValueError:
        return
    assert tg.owner == "acme", f"owner {tg.owner!r} escaped the organization"
    if tg.kind == "repo":
        assert valid_repo_name(tg.repo), f"unvalidated repo {tg.repo!r}"
        assert tg.branch == "" or valid_branch(tg.branch), f"unvalidated branch {tg.branch!r}"
        assert not any(c in tg.repo for c in "/?#%") and ".." not in tg.branch and not any(c in tg.branch for c in "?@"), f"url-significant character in {tg!r}"
    elif tg.kind == "team":
        assert _SLUG_RE.fullmatch(tg.team) is not None and len(go_bytes(tg.team)) <= 255, f"unvalidated team {tg.team!r}"
    elif tg.kind == "org":
        assert tg.repo == "" and tg.team == "" and tg.branch == "", f"org target carries extra parts {tg!r}"
    else:
        raise AssertionError(f"unknown kind {tg.kind!r}")


@pytest.mark.parametrize(("action", "resource"), SEEDS)
def test_fuzz_parse_target_seeds(action: str, resource: str) -> None:
    fuzz_parse_target(action, resource)


_ACTIONS = st.one_of(st.sampled_from(sorted(ACTIONS)), st.text())
_TYPES = st.sampled_from(["repo", "org", "team", "other"])
_OWNERS = st.one_of(st.sampled_from(["acme", "Acme", "ACME", "other"]), st.text())
_PARTS = st.one_of(st.text(), st.from_regex(r"[A-Za-z0-9._@/?#%-]{0,20}", fullmatch=True))
_RESOURCES = st.one_of(
    st.text(),
    st.builds(lambda t, i: t + ":" + i, _TYPES, st.text()),
    st.builds(lambda t, o, rest: t + ":" + o + "/" + rest, _TYPES, _OWNERS, _PARTS),
    st.builds(lambda o: "org:" + o, _OWNERS),
)


@given(_ACTIONS, _RESOURCES)
def test_fuzz_parse_target(action: str, resource: str) -> None:
    fuzz_parse_target(action, resource)
