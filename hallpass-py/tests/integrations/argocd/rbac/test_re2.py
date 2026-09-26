"""The RE2 translation behind Argo CD's regex match mode (not in the Go
tests, which run Go's regexp itself). Every expectation was recorded from
the argocd v3.5.3 CLI (`argocd admin settings rbac can` with
policy.matchMode: regex), so a pattern must match exactly the objects Go's
regexp matches; patterns RE2 rejects match nothing."""

from __future__ import annotations

import pytest

from hallpass.integrations.argocd.rbac import REGEX_MATCH_MODE, Enforcer, Options

OBJECTS = ["日本", "Éa", "a b", "dev/web", "my-dev-1", "DEV/WEB", "prod/x", "x{,5}", "ab", "c", "web", "a1", "{2}"]

CASES = [
    ("\\pL", ["日本", "Éa", "a b", "dev/web", "my-dev-1", "DEV/WEB", "prod/x", "x{,5}", "ab", "c", "web", "a1"]),
    ("^\\p{Lu}", ["Éa", "DEV/WEB"]),
    ("\\PL", ["a b", "dev/web", "my-dev-1", "DEV/WEB", "prod/x", "x{,5}", "a1", "{2}"]),
    ("\\p{^L}", ["a b", "dev/web", "my-dev-1", "DEV/WEB", "prod/x", "x{,5}", "a1", "{2}"]),
    ("[\\p{Nd}x]", ["my-dev-1", "prod/x", "x{,5}", "a1", "{2}"]),
    ("\\p{Greek}", []),
    ("\\pZ", ["a b"]),
    ("[^\\pL]", ["a b", "dev/web", "my-dev-1", "DEV/WEB", "prod/x", "x{,5}", "a1", "{2}"]),
    ("\\p{Any}", ["日本", "Éa", "a b", "dev/web", "my-dev-1", "DEV/WEB", "prod/x", "x{,5}", "ab", "c", "web", "a1", "{2}"]),
    ("é\\p{Ll}", []),
    ("\\d+", ["my-dev-1", "x{,5}", "a1", "{2}"]),
    ("^dev\\b", ["dev/web"]),
    ("(?i)DEV/", ["dev/web", "DEV/WEB"]),
    ("a(?i)b|c", ["ab", "c"]),
    ("x{,5}", ["x{,5}"]),
    ("[[:alpha:]]+-1", ["my-dev-1"]),
    ("\\x{64}ev", ["dev/web", "my-dev-1"]),
    ("web$", ["dev/web", "web"]),
    ("web\\z", ["dev/web", "web"]),
    ("\\Qdev/w\\E", ["dev/web"]),
    ("(?=dev)", []),
    ("dev/w{1,2}eb", ["dev/web"]),
    ("[\\d]", ["my-dev-1", "x{,5}", "a1", "{2}"]),
    ("\\w-\\w", ["my-dev-1"]),
    ("(?s:.)", ["日本", "Éa", "a b", "dev/web", "my-dev-1", "DEV/WEB", "prod/x", "x{,5}", "ab", "c", "web", "a1", "{2}"]),
    ("[^[:digit:]]", ["日本", "Éa", "a b", "dev/web", "my-dev-1", "DEV/WEB", "prod/x", "x{,5}", "ab", "c", "web", "a1", "{2}"]),
    ("a**", []),
    ("\\1", []),
    ("(?P<n>dev)", ["dev/web", "my-dev-1"]),
    ("(?<n>dev)", ["dev/web", "my-dev-1"]),
    ("de(?i:V)", ["dev/web", "my-dev-1"]),
    ("\\101", []),
    ("[a-\\x{7a}]eb", ["dev/web", "web"]),
    ("{2}", []),
    ("x{2,1}", []),
    ("dev|(?i)PROD", ["dev/web", "my-dev-1", "prod/x"]),
    ("[&&]", []),
    ("\\S+/\\S+", ["dev/web", "DEV/WEB", "prod/x"]),
    ("é", []),
    ("(?m)web$", ["dev/web", "web"]),
    ("a++", []),
    ("\\bweb", ["dev/web", "web"]),
    ("\\Bev", ["dev/web", "my-dev-1"]),
]


@pytest.mark.parametrize(("pattern", "matches"), CASES)
def test_regex_mode_matches_go(pattern: str, matches: list[str]) -> None:
    q = pattern.replace('"', '""')
    e = Enforcer(Options(user=f'p, u, applications, get, "{q}", allow', match_mode=REGEX_MATCH_MODE))
    got = [o for o in OBJECTS if e.enforce("u", "applications", "get", o)]
    assert got == matches
