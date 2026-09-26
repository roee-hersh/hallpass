"""Port of internal/integrations/argocd/rbac/rbac_test.go.

These tests are ported from argo-cd/util/rbac/rbac_test.go and
argo-cd/server/rbacpolicy/rbacpolicy_test.go. Names are kept so a reader
can compare them with upstream.
"""

from __future__ import annotations

import pytest

from hallpass.integrations.argocd.rbac import (
    BUILTIN_POLICY_CSV,
    POLICY_CSV_KEY,
    REGEX_MATCH_MODE,
    Enforcer,
    Options,
    PolicyError,
    Project,
    ProjectRole,
    parse_policy,
    parse_scopes,
    policy_csv,
    project_from_request,
)


def must_enforcer(o: Options) -> Enforcer:
    return Enforcer(o)


def test_policy_csv() -> None:
    assert policy_csv({}) == "", "empty"
    data = {POLICY_CSV_KEY: "policy1\npolicy2", "UnrelatedKey": "unrelated value"}
    assert policy_csv(data) == "policy1\npolicy2", "default key only"
    data = {POLICY_CSV_KEY: "policy1", "UnrelatedKey": "x", "policy.overlay1.csv": "policy2", "policy.overlay2.csv": "policy3"}
    p = policy_csv(data)
    assert p.startswith("policy1") and "policy2" in p and "policy3" in p, p
    data = {"UnrelatedKey": "x", "policy.B.csv": "policyb", "policy.A.csv": "policya", "policy.C.csv": "policyc", POLICY_CSV_KEY: "policy1"}
    got = policy_csv(data).split("\n")
    assert got == ["policy1", "policya", "policyb", "policyc"], got


def test_builtin_policy_enforcer() -> None:
    # Without the builtin policy nothing is allowed.
    e = must_enforcer(Options())
    assert not e.enforce("admin", "applications", "get", "foo/bar"), "no policy should deny"
    e = must_enforcer(Options(builtin=BUILTIN_POLICY_CSV))
    allowed = [
        ("admin", "applications", "get", "foo/bar"),
        ("admin", "applications", "delete", "foo/bar"),
        ("role:readonly", "applications", "get", "foo/bar"),
        ("role:admin", "applications", "get", "foo/bar"),
        ("role:admin", "applications", "delete", "foo/bar"),
        ("role:admin", "applications", "sync", "foo/bar"),
    ]
    for a in allowed:
        assert e.enforce(*a), f"{a}: expected true"
    disallowed = [
        ("role:readonly", "applications", "create", "foo/bar"),
        ("role:readonly", "applications", "delete", "foo/bar"),
        ("role:readonly", "applications", "rollback", "foo/bar"),
        # v3.5.3's builtin policy has no rollback line; unreleased master adds one.
        ("role:admin", "applications", "rollback", "foo/bar"),
    ]
    for a in disallowed:
        assert not e.enforce(*a), f"{a}: expected false"


def test_project_isolation_enforcement() -> None:
    e = must_enforcer(
        Options(
            builtin="""
p, role:foo-admin, *, *, foo/*, allow
p, role:bar-admin, *, *, bar/*, allow
g, alice, role:foo-admin
g, bob, role:bar-admin
"""
        )
    )
    assert e.enforce("bob", "applications", "delete", "bar/obj") and not e.enforce("bob", "applications", "delete", "foo/obj"), "bob"
    assert e.enforce("alice", "applications", "delete", "foo/obj") and not e.enforce("alice", "applications", "delete", "bar/obj"), "alice"


def test_project_read_only() -> None:
    e = must_enforcer(Options(builtin="p, role:foo-readonly, *, get, foo/*, allow\ng, alice, role:foo-readonly\n"))
    assert e.enforce("alice", "applications", "get", "foo/obj"), "alice get"
    assert not (
        e.enforce("alice", "applications", "delete", "bar/obj")
        or e.enforce("alice", "applications", "get", "bar/obj")
        or e.enforce("bob", "applications", "get", "foo/obj")
    ), "denies"


def test_default_role() -> None:
    e = must_enforcer(Options(builtin=BUILTIN_POLICY_CSV))
    assert not e.enforce("bob", "applications", "get", "foo/bar"), "bob without default role"
    e = must_enforcer(Options(builtin=BUILTIN_POLICY_CSV, default_role="role:readonly"))
    assert e.enforce("bob", "applications", "get", "foo/bar"), "bob with default role"
    # A user-level deny cannot block the default role: it is checked first.
    e = must_enforcer(Options(builtin=BUILTIN_POLICY_CSV, user="p, bob, applications, get, foo/bar, deny", default_role="role:readonly"))
    assert e.enforce("bob", "applications", "get", "foo/bar"), "default role is checked before the subject"


def test_url_as_object_name() -> None:
    e = must_enforcer(
        Options(
            user="""
p, alice, repositories, *, foo/*, allow
p, bob, repositories, *, foo/https://github.com/argoproj/argo-cd.git, allow
p, cathy, repositories, *, foo/*, allow
"""
        )
    )
    assert e.enforce("alice", "repositories", "delete", "foo/https://github.com/argoproj/argo-cd.git") and e.enforce(
        "alice", "repositories", "delete", "foo/https://github.com/golang/go.git"
    ), "alice"
    assert e.enforce("bob", "repositories", "delete", "foo/https://github.com/argoproj/argo-cd.git") and not e.enforce(
        "bob", "repositories", "delete", "foo/https://github.com/golang/go.git"
    ), "bob"


def test_deny_overrides_allow() -> None:
    e = must_enforcer(Options(user="p, alice, *, get, foo/obj, allow\np, mike, *, get, foo/obj, deny\n"))
    assert e.enforce("alice", "applications", "get", "foo/obj") and not e.enforce("alice", "applications/resources", "delete", "foo/obj"), "alice"
    assert not e.enforce("mike", "applications", "get", "foo/obj"), "mike deny"
    assert not e.enforce("", "applications/resources", "delete", "foo/obj"), "empty subject"
    e = must_enforcer(Options(builtin=BUILTIN_POLICY_CSV, user="p, admin, applications, delete, prod/*, deny"))
    assert not e.enforce("admin", "applications", "delete", "prod/db") and e.enforce("admin", "applications", "delete", "dev/db"), (
        "explicit deny on builtin admin"
    )


@pytest.mark.parametrize(
    "good",
    [
        "p, role:admin, projects, delete, *, allow",
        "",
        "#",
        'p, "role,admin", projects, delete, *, allow',
        " p, role:admin, projects, delete, *, allow ",
        "g, your-github-org:your-team, role:org-admin",
        "# Some comment",
    ],
)
def test_validate_policy_good(good: str) -> None:
    parse_policy(good)


@pytest.mark.parametrize(
    "bad",
    [
        "this, is, not, a, good, policy",
        "this\ttoo",
        "p",
        "Some comment",
        "agh, foo, bar",
        "p, role:Myrole, applications, *, myproj/* allow",
        ", role:Myrole, applications, *, myproj/*, allow",
        "g, only-two",
    ],
)
def test_validate_policy_bad(bad: str) -> None:
    with pytest.raises(PolicyError):
        parse_policy(bad)


def test_validate_policy() -> None:
    p = parse_policy('p, "role,admin", projects, delete, *, allow')
    assert p.rules[0].sub == "role,admin", f"quoted field: {p}"
    p = parse_policy("p, a, b, c, d, maybe")
    assert len(p.rules) == 0, "unknown effect must not become a rule"


def test_validate_policy_csv_errors() -> None:
    # Not in the Go test: pins encoding/csv's ParseError texts, which reach
    # decision reasons and probe warnings (checked against Go 1.24).
    cases = {
        'p, a"b, c': 'error parsing policy line "p, a\\"b, c": parse error on line 1, column 5: bare " in non-quoted-field',
        'p, "ab"c, d': 'error parsing policy line "p, \\"ab\\"c, d": parse error on line 1, column 7: extraneous or missing " in quoted-field',
        'p, "abc': 'error parsing policy line "p, \\"abc": parse error on line 1, column 8: extraneous or missing " in quoted-field',
        'p, "a""b", c, d, e, allow': None,
        # Columns are byte offsets.
        'p, é"x': 'error parsing policy line "p, é\\"x": parse error on line 1, column 6: bare " in non-quoted-field',
        'p, "é': 'error parsing policy line "p, \\"é": parse error on line 1, column 7: extraneous or missing " in quoted-field',
    }
    for line, want in cases.items():
        if want is None:
            assert parse_policy(line).rules[0].sub == 'a"b'
            continue
        with pytest.raises(PolicyError) as ei:
            parse_policy(line)
        assert str(ei.value) == want


def test_glob_match_mode_and_regex_match_mode() -> None:
    e = must_enforcer(Options(user='p, alice, clusters, get, "https://github.com/*/*.git", allow'))
    assert e.enforce("alice", "clusters", "get", "https://github.com/argoproj/argo-cd.git"), "glob match"
    assert not e.enforce("alice", "repositories", "get", "https://github.com/argoproj/argo-cd.git"), "wrong resource"
    assert not e.enforce("alice", "clusters", "get", "https://github.com/argo-cd.git"), "glob needs two segments"
    e = must_enforcer(Options(match_mode=REGEX_MATCH_MODE, user='p, alice, clusters, get, "https://github.com/argo[a-z]{4}/argo-[a-z]+.git", allow'))
    assert e.enforce("alice", "clusters", "get", "https://github.com/argoproj/argo-cd.git"), "regex match"
    assert not e.enforce("alice", "clusters", "get", "https://github.com/argoproj/1argo-cd.git"), "regex mismatch"
    # Regex is unanchored, and an invalid regex never matches.
    e = must_enforcer(Options(match_mode=REGEX_MATCH_MODE, user="p, alice, clusters, get, proj, allow\np, bob, clusters, get, (, allow"))
    assert e.enforce("alice", "clusters", "get", "my-proj-1"), "unanchored"
    assert not e.enforce("bob", "clusters", "get", "("), "invalid regex matched"


def test_role_depth() -> None:
    lines = ["p, role:leaf, applications, get, */*, allow"]
    for i in range(12):
        lines.append(f"g, role:l{i}, role:l{i + 1}")
    lines.append("g, role:l12, role:leaf")
    lines.append("g, deep, role:l0\ng, shallow, role:l5")
    e = must_enforcer(Options(user="\n".join(lines) + "\n"))
    assert not e.enforce("deep", "applications", "get", "a/b"), "13 hops should exceed the Casbin depth of 10"
    assert e.enforce("shallow", "applications", "get", "a/b"), "8 hops should work"
    # Cycles must not loop forever.
    e = must_enforcer(Options(user="g, a, b\ng, b, a\np, c, x, y, z, allow"))
    assert not e.enforce("a", "x", "y", "z"), "cycle"


def new_fake_proj() -> Project:
    return Project(
        name="my-proj",
        roles=[
            ProjectRole(
                name="my-role",
                policies=[
                    "p, proj:my-proj:my-role, applications, create, my-proj/*, allow",
                    "p, proj:my-proj:my-role, logs, get, my-proj/*, allow",
                    "p, proj:my-proj:my-role, exec, create, my-proj/*, allow",
                ],
                groups=["my-org:my-team"],
            )
        ],
    )


def test_project_policies_string() -> None:
    got = new_fake_proj().policies_string()
    want = (
        "p, proj:my-proj:my-role, projects, get, my-proj, allow\n"
        "p, proj:my-proj:my-role, applications, create, my-proj/*, allow\n"
        "p, proj:my-proj:my-role, logs, get, my-proj/*, allow\n"
        "p, proj:my-proj:my-role, exec, create, my-proj/*, allow\n"
        "g, my-org:my-team, proj:my-proj:my-role"
    )
    assert got == want, f"got\n{got}\nwant\n{want}"


def claims(e: Enforcer, sub: str, groups: list[str] | None, res: str, act: str, obj: str) -> bool:
    """Mirrors the upstream test: enforce with a subject and group claims
    against builtin + user + the project's runtime policy."""
    return e.enforce_claims(sub, groups or [], res, act, obj)


def test_enforce_all_policies() -> None:
    proj = new_fake_proj()
    e = must_enforcer(
        Options(
            builtin="p, alice, applications, create, my-proj/*, allow\np, alice, logs, get, my-proj/*, allow\np, alice, exec, create, my-proj/*, allow",
            user="p, bob, applications, create, my-proj/*, allow\np, bob, logs, get, my-proj/*, allow\np, bob, exec, create, my-proj/*, allow",
            runtime=proj.policies_string(),
        )
    )
    for sub in ("alice", "bob", "proj:my-proj:my-role"):
        assert (
            claims(e, sub, None, "applications", "create", "my-proj/my-app")
            and claims(e, sub, None, "logs", "get", "my-proj/my-app")
            and claims(e, sub, None, "exec", "create", "my-proj/my-app")
        ), f"{sub} should be allowed"
    assert claims(e, "", ["my-org:my-team"], "applications", "create", "my-proj/my-app"), "group via project role"
    assert claims(e, "", ["my-org:my-team"], "projects", "get", "my-proj"), "project roles get the project"
    assert not claims(e, "cathy", None, "applications", "create", "my-proj/my-app"), "cathy"
    # A group not named in any g line is ignored even if a p line names it.
    e2 = must_enforcer(Options(user="p, some-group, applications, get, */*, allow"))
    assert not claims(e2, "", ["some-group"], "applications", "get", "a/b"), "groups without a g line must be ignored (upstream prefilter)"
    assert e2.enforce("some-group", "applications", "get", "a/b"), "but as a plain subject it matches"


def test_enforce_action_actions() -> None:
    e = must_enforcer(
        Options(
            builtin="""p, alice, applications, action/*, my-proj/*, allow
p, bob, applications, action/argoproj.io/Rollout/*, my-proj/*, allow
p, cam, applications, action/argoproj.io/Rollout/resume, my-proj/*, allow
"""
        )
    )
    assert e.enforce("alice", "applications", "action/argoproj.io/Rollout/resume", "my-proj/my-app") and e.enforce(
        "alice", "applications", "action/argoproj.io/NewCrd/abort", "my-proj/my-app"
    ), "alice"
    assert e.enforce("bob", "applications", "action/argoproj.io/Rollout/resume", "my-proj/my-app") and not e.enforce(
        "bob", "applications", "action/argoproj.io/NewCrd/abort", "my-proj/my-app"
    ), "bob"
    assert e.enforce("cam", "applications", "action/argoproj.io/Rollout/resume", "my-proj/my-app") and not e.enforce(
        "cam", "applications", "action/argoproj.io/Rollout/abort", "my-proj/my-app"
    ), "cam"
    assert not e.enforce("eve", "applications", "action/argoproj.io/Rollout/resume", "my-proj/my-app"), "eve"


def test_fine_grained_not_inherited() -> None:
    e = must_enforcer(Options(user="p, alice, applications, update, my-proj/*, allow"))
    assert e.enforce("alice", "applications", "update", "my-proj/app"), "update"
    assert not e.enforce("alice", "applications", "update/apps/Deployment/ns/name", "my-proj/app"), (
        "update must not match update/* on its own; the integration decides inheritance"
    )


@pytest.mark.parametrize(
    ("res", "obj", "want"),
    [
        ("repositories", "my-proj/https://github.com/argoproj/argocd-example-apps", "my-proj"),
        ("applicationsets", "my-proj/x", "my-proj"),
        ("applications", "my-proj/ns/x", "my-proj"),
        ("applications", "noslash", ""),
        ("projects", "my-proj", "my-proj"),
        ("accounts", "a/b", ""),
    ],
)
def test_project_from_request(res: str, obj: str, want: str) -> None:
    assert project_from_request(res, obj) == want, f"{res} {obj}"


def test_parse_scopes() -> None:
    assert parse_scopes("[groups, email]") == ["groups", "email"]
    assert parse_scopes('["cognito:groups"]') == ["cognito:groups"]
    assert parse_scopes("") is None, "empty"
    with pytest.raises(ValueError):
        parse_scopes("groups")
