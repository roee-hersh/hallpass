"""Port of internal/integrations/argocd/rbac/glob_test.go."""

from __future__ import annotations

import time

import pytest

from hallpass.integrations.argocd.rbac.glob import GlobError, glob_match, parse_glob


@pytest.mark.parametrize(
    ("pattern", "text", "want"),
    [
        ("*", "", True),
        ("*", "anything/with/slashes", True),
        ("*/*", "foo/bar", True),
        ("*/*", "foo", False),
        ("*/*", "foo/bar/baz", True),  # no separators: * crosses /
        ("foo/*", "foo/bar", True),
        ("foo/*", "foo/", True),
        ("foo/*", "bar/foo", False),
        ("**", "a/b/c", True),
        ("a**b", "a/x/b", True),
        ("?", "a", True),
        ("?", "ab", False),
        ("?", "", False),
        ("a?c", "abc", True),
        ("a?c", "a/c", True),
        ("[abc]", "b", True),
        ("[abc]", "d", False),
        ("[!abc]", "d", True),
        ("[!abc]", "a", False),
        ("[a-z]x", "qx", True),
        ("[a-z]x", "Qx", False),
        ("{foo,bar}/*", "foo/x", True),
        ("{foo,bar}/*", "bar/x", True),
        ("{foo,bar}/*", "baz/x", False),
        ("{*.go,*.md}", "main.go", True),
        ("{*.go,*.md}", "README.md", True),
        ("{*.go,*.md}", "main.rs", False),
        ("{a,{b,c}}", "c", True),
        ("{a,{b,c}}", "d", False),
        ("\\*", "*", True),
        ("\\*", "x", False),
        ("a\\,b", "a,b", True),
        ("https://github.com/*/*.git", "https://github.com/argoproj/argo-cd.git", True),
        ("https://github.com/*/*.git", "https://github.com/argo-cd.git", False),
        ("action/*", "action/argoproj.io/Rollout/resume", True),
        ("action/argoproj.io/Rollout/*", "action/argoproj.io/Rollout/resume", True),
        ("action/argoproj.io/Rollout/*", "action/argoproj.io/NewCrd/abort", False),
        ("update", "update/apps/Deployment/ns/name", False),
        ("update/*", "update/apps/Deployment/ns/name", True),
        ("proj:*:admin", "proj:foo:admin", True),
        ("", "", True),
        ("", "a", False),
        ("a,b", "a,b", True),
        ("a}b", "a}b", True),
        ("日本*", "日本語", True),
        ("[日-語]", "本", True),
    ],
)
def test_glob(pattern: str, text: str, want: bool) -> None:
    assert glob_match(pattern, text) == want, f"glob({pattern!r}, {text!r}) = {not want}, want {want}"


@pytest.mark.parametrize("bad", ["[abc", "{a,b", "a\\", "[]", "[z-a]"])
def test_glob_invalid(bad: str) -> None:
    with pytest.raises(GlobError):
        parse_glob(bad)
    assert not glob_match(bad, bad), f"invalid pattern {bad!r} matched"


def test_glob_no_blowup() -> None:
    pattern = "*a*a*a*a*a*a*a*a*a*a*a*a*b"
    text = "a" * 89 + "c"
    start = time.monotonic()
    assert not glob_match(pattern, text), "should not match"
    assert time.monotonic() - start < 5
