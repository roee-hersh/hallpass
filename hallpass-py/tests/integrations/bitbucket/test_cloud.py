"""Port of internal/integrations/bitbucket/cloud_test.go."""

from __future__ import annotations

import threading
from typing import Any

import pytest

from hallpass.core.context import background
from hallpass.core.decision import Code, to_decision
from hallpass.core.integration import User, validate_fields
from hallpass.core.secret import literal as secret_literal
from hallpass.integrations.bitbucket import INTEGRATION, BitbucketConnection
from hallpass.integrations.bitbucket.actions import ACTION_LIST, Level, ref_match
from hallpass.net import httpx
from tests import harness as itest
from tests.harness.spec import SpecOptions, spec_from_env
from tests.integrations.bitbucket.common import Tracker, bob, check, cr, dana, expect, left, ola, write


class CloudMember:
    def __init__(self, account_id: str, uuid: str, nickname: str, email: str) -> None:
        self.account_id, self.uuid, self.nickname, self.email = account_id, uuid, nickname, email


def cloud_err(w: itest.ResponseWriter, status: int, msg: str) -> None:
    w.header().set("Content-Type", "application/json")
    w.write_header(status)
    w.write('{"type":"error","error":{"message":"' + itest.CANARY + " " + msg + '"}}')


def _atoi(s: str, default: int) -> int:
    try:
        return int(s)
    except ValueError:
        return default


class CloudFake:
    def __init__(self) -> None:
        self.mu = threading.Lock()
        self.errors: list[str] = []  # Go's t.Errorf from inside the handler
        self.token = itest.CANARY + "wstoken"
        self.members: dict[str, CloudMember] = {  # email -> member
            "dana@example.com": CloudMember("557058:dana", "{11111111-1111-1111-1111-111111111111}", "dana", "dana@example.com"),
            "bob@example.com": CloudMember("557058:bob", "{22222222-2222-2222-2222-222222222222}", "bobby", "bob@example.com"),
            "ola@example.com": CloudMember("557058:ola", "{33333333-3333-3333-3333-333333333333}", "ola", "ola@example.com"),
            "cr@example.com": CloudMember("557058:cr", "{44444444-4444-4444-4444-444444444444}", "cr", "cr@example.com"),
            "left@example.com": CloudMember("557058:left", "{55555555-5555-5555-5555-555555555555}", "left", "left@example.com"),
        }
        self.owners = ["557058:ola"]  # account ids
        self.repos = {"api": True, "site": False}  # slug -> is_private
        self.repo_perms: dict[str, dict[str, str]] = {  # slug -> account id -> permission
            "api": {"557058:dana": "write", "557058:bob": "read", "557058:ola": "admin"},
            "site": {},
        }
        self.restrictions: dict[str, list[dict[str, Any]]] = {  # slug -> restrictions
            "api": [
                {
                    "id": 1,
                    "kind": "push",
                    "branch_match_kind": "glob",
                    "pattern": "main",
                    "users": [{"account_id": "557058:ola", "uuid": "{33333333-3333-3333-3333-333333333333}", "display_name": itest.CANARY}],
                    "groups": [],
                },
                {
                    "id": 2,
                    "kind": "push",
                    "branch_match_kind": "glob",
                    "pattern": "release/*",
                    "users": [],
                    "groups": [{"slug": "developers", "name": itest.CANARY}],
                },
                {
                    "id": 3,
                    "kind": "restrict_merges",
                    "branch_match_kind": "glob",
                    "pattern": "refs/heads/main",
                    "users": [{"account_id": "557058:dana", "uuid": "{11111111-1111-1111-1111-111111111111}"}],
                    "groups": [],
                },
                {"id": 4, "kind": "require_approvals_to_merge", "branch_match_kind": "glob", "pattern": "main", "value": 2},
                {"id": 5, "kind": "delete", "branch_match_kind": "glob", "pattern": "*", "users": [], "groups": []},
            ],
        }
        self.projects = {"APP": True, "DOCS": True}  # key -> exists
        self.project_users: dict[str, dict[str, str]] = {  # key -> account id -> permission
            "APP": {"557058:dana": "write", "557058:bob": "read", "557058:cr": "create-repo"},
            "DOCS": {"557058:bob": "read", "557058:dana": "write"},
        }
        self.project_groups: dict[str, dict[str, str]] = {"APP": {"developers": "admin"}, "DOCS": {}}  # key -> group slug -> permission
        self.public_projects: dict[str, bool] = {}  # key -> is_private false
        self.reject_filter = False  # 400 on q=user.account_id
        self.status = 0  # when set, every API call fails with it
        self.filtered = 0  # repository permission calls that carried a user filter

    def user(self, m: CloudMember, with_email: bool) -> dict[str, Any]:
        u: dict[str, Any] = {"type": "user", "account_id": m.account_id, "uuid": m.uuid, "nickname": m.nickname, "display_name": itest.CANARY + "name"}
        if with_email:
            u["email"] = m.email
        return u

    def paged(self, w: itest.ResponseWriter, r: itest.Request, values: list[dict[str, Any]]) -> None:
        """A one-page list, or two pages when the caller asks for pagelen=1
        on a list longer than one."""
        page = _atoi(r.q("page"), 1)
        if r.q("pagelen") == "1" and len(values) > 1:
            body: dict[str, Any] = {"pagelen": 1, "page": page, "values": values[page - 1 : page]}
            if page < len(values):
                q = {k: list(v) for k, v in r.query.items()}
                q["page"] = [str(page + 1)]
                body["next"] = "https://" + r.host + r.path + "?" + httpx.encode_query(q)
            write(w, body)
            return
        write(w, {"pagelen": 100, "page": 1, "values": values})

    def api(self, w: itest.ResponseWriter, r: itest.Request) -> None:
        with self.mu:
            self._api(w, r)

    def _api(self, w: itest.ResponseWriter, r: itest.Request) -> None:
        if r.header.get("Authorization") != "Bearer " + self.token:
            w.write_header(401)
            return
        if self.status != 0:
            cloud_err(w, self.status, "injected")
            return
        p, q = r.path, r.q
        ws = "/2.0/workspaces/acme"
        if p == ws:
            write(w, {"slug": "acme", "name": "Acme " + itest.CANARY, "uuid": "{aaaa}"})
        elif p == ws + "/members":
            flt = q("q")
            if not flt.startswith('user.email IN ("') or not flt.endswith('")'):
                cloud_err(w, 400, "bad filter")
                return
            if "values.user.email" not in q("fields"):
                self.errors.append("member lookup without the email field")
            email = flt.removeprefix('user.email IN ("').removesuffix('")')
            values = [{"type": "workspace_membership", "user": self.user(m, True)} for e, m in self.members.items() if e.lower() == email.lower()]
            if email == "dup@example.com":
                values += [{"user": {"account_id": "1", "email": "dup@example.com"}}, {"user": {"account_id": "2", "email": "Dup@example.com"}}]
            write(w, {"pagelen": 100, "page": 1, "values": values})
        elif p.startswith(ws + "/members/"):
            uid = p.removeprefix(ws + "/members/")
            for m in self.members.values():
                if m.account_id == uid and uid != "557058:left":
                    write(w, {"user": self.user(m, False)})
                    return
            cloud_err(w, 404, "not a member")
        elif p == ws + "/permissions":
            if q("q") != 'permission="owner"':
                self.errors.append(f"owner listing filter {q('q')!r}")
            values = []
            for oid in self.owners:
                for m in self.members.values():
                    if m.account_id == oid:
                        values.append({"permission": "owner", "user": self.user(m, False)})
            # A member entry that must not count as owner even if the filter
            # were ignored.
            values.append({"permission": "member", "user": self.user(self.members["dana@example.com"], False)})
            self.paged(w, r, values)
        elif p.startswith(ws + "/permissions/repositories/"):
            slug = p.removeprefix(ws + "/permissions/repositories/")
            perms = self.repo_perms.get(slug)
            if perms is None:
                cloud_err(w, 404, "no repo")
                return
            only = ""
            flt = q("q")
            if flt != "":
                if self.reject_filter:
                    cloud_err(w, 400, "bad query")
                    return
                if not flt.startswith('user.account_id="'):
                    self.errors.append(f"repository permission filter {flt!r}")
                only = flt.removeprefix('user.account_id="').removesuffix('"')
                self.filtered += 1
            values = []
            for m in self.members.values():
                perm = perms.get(m.account_id)
                if perm is None or (only != "" and only != m.account_id):
                    continue
                values.append({"type": "repository_permission", "permission": perm, "user": self.user(m, False), "repository": {"name": slug}})
            self.paged(w, r, values)
        elif p.startswith("/2.0/repositories/acme/"):
            rest = p.removeprefix("/2.0/repositories/acme/")
            slug, _, sub = rest.partition("/")
            private = self.repos.get(slug)
            if private is None:
                cloud_err(w, 404, "You may not have access to this repository or it no longer exists")
                return
            if sub == "":
                write(w, {"slug": slug, "is_private": private, "project": {"key": "APP"}, "description": itest.CANARY})
            elif sub == "branch-restrictions":
                k = q("kind")
                self.paged(w, r, [rs for rs in self.restrictions.get(slug, []) if k == "" or k == rs["kind"]])
            else:
                cloud_err(w, 404, "no route")
        elif p.startswith(ws + "/projects/"):
            rest = p.removeprefix(ws + "/projects/")
            key, _, sub = rest.partition("/")
            if not self.projects.get(key):
                cloud_err(w, 404, "no project")
                return
            if sub == "":
                write(w, {"key": key, "name": itest.CANARY, "is_private": not self.public_projects.get(key, False)})
            elif sub.startswith("permissions-config/users/"):
                uid = sub.removeprefix("permissions-config/users/")
                perm = self.project_users.get(key, {}).get(uid, "none")
                write(w, {"type": "project_user_permission", "permission": perm})
            elif sub == "permissions-config/groups":
                values = [
                    {"type": "project_group_permission", "permission": perm, "group": {"slug": g, "name": itest.CANARY}}
                    for g, perm in self.project_groups.get(key, {}).items()
                ]
                self.paged(w, r, values)
            else:
                cloud_err(w, 404, "no route")
        else:
            self.errors.append(f"cloud fake: no route for {r.method} {p}")
            cloud_err(w, 404, "no route")


def cloud_spec() -> tuple[Any, SpecOptions]:
    # The description declares neither pagination nor the q/fields filters
    # on the members list.
    return spec_from_env("bitbucket-cloud"), SpecOptions(allow_query=["q", "fields", "pagelen", "page", "kind"])


def setup_cloud(tracker: Tracker, values: dict[str, str] | None = None) -> tuple[itest.Server, CloudFake, BitbucketConnection]:
    srv = tracker.server()
    spec, opts = cloud_spec()
    srv.use_spec(spec, opts)
    f = CloudFake()
    tracker.fakes.append(f)
    srv.handle("GET", "/2.0/*", f.api)
    deps, _ = itest.deps(srv)
    v = {"url": srv.url, "workspace": "acme"}
    v.update(values or {})
    s = itest.settings("bb", "bitbucket", v, {"credential": secret_literal(f.token)})
    c = INTEGRATION.new(background(), s, deps)
    assert isinstance(c, BitbucketConnection)
    return srv, f, c


# -- the action table (Cloud) --


def test_action_repo_read_allow(tracker: Tracker) -> None:
    _, _, c = setup_cloud(tracker)
    expect(check(c, bob, "repo.read", "repo:api"), Code.ALLOWED, "has read (needs read)")
    expect(check(c, cr, "repo.read", "repo:site"), Code.ALLOWED, "public repository")


def test_action_repo_read_deny(tracker: Tracker) -> None:
    _, _, c = setup_cloud(tracker)
    expect(check(c, cr, "repo.read", "repo:api"), Code.DENIED, "has none, needs read")


def test_action_repo_push_allow(tracker: Tracker) -> None:
    _, _, c = setup_cloud(tracker)
    expect(check(c, dana, "repo.push", "repo:api"), Code.ALLOWED, "")
    expect(check(c, dana, "repo.push", "repo:api@feature/x"), Code.ALLOWED, "no push restriction stops feature/x")
    expect(check(c, ola, "repo.push", "repo:api@main"), Code.ALLOWED, "")


def test_action_repo_push_deny(tracker: Tracker) -> None:
    _, _, c = setup_cloud(tracker)
    expect(check(c, bob, "repo.push", "repo:api"), Code.DENIED, "has read, needs write")
    expect(check(c, dana, "repo.push", "repo:api@main"), Code.DENIED, "push restriction")
    # Write is checked before the branch: no restriction call for a reader.
    expect(check(c, bob, "repo.push", "repo:api@main"), Code.DENIED, "needs write")


def test_action_pr_merge_allow(tracker: Tracker) -> None:
    _, _, c = setup_cloud(tracker)
    expect(check(c, dana, "pr.merge", "repo:api@main"), Code.ALLOWED, "")
    expect(check(c, dana, "pr.merge", "repo:api"), Code.ALLOWED, "")


def test_action_pr_merge_deny(tracker: Tracker) -> None:
    _, _, c = setup_cloud(tracker)
    expect(check(c, bob, "pr.merge", "repo:api"), Code.DENIED, "")
    # The owner has admin but the merge restriction lists only dana.
    expect(check(c, ola, "pr.merge", "repo:api@main"), Code.DENIED, "restrict_merges restriction")


def test_action_repo_admin_allow(tracker: Tracker) -> None:
    _, _, c = setup_cloud(tracker)
    expect(check(c, ola, "repo.admin", "repo:api"), Code.ALLOWED, "")
    # Owners administer every repository, listed or not.
    expect(check(c, ola, "repo.admin", "repo:site"), Code.ALLOWED, "workspace owner")


def test_action_repo_admin_deny(tracker: Tracker) -> None:
    _, _, c = setup_cloud(tracker)
    expect(check(c, dana, "repo.admin", "repo:api"), Code.DENIED, "has write, needs admin")


def test_action_project_read_allow(tracker: Tracker) -> None:
    _, _, c = setup_cloud(tracker)
    expect(check(c, bob, "project.read", "project:APP"), Code.ALLOWED, "has read on project APP directly")


def test_action_project_read_deny(tracker: Tracker) -> None:
    _, f, c = setup_cloud(tracker)
    expect(check(c, cr, "project.read", "project:DOCS"), Code.DENIED, "has none on project DOCS, needs read")
    # A public project is readable by everyone, but only readable.
    with f.mu:
        f.public_projects = {"DOCS": True}
    expect(check(c, cr, "project.read", "project:DOCS"), Code.ALLOWED, "public")
    expect(check(c, cr, "project.write", "project:DOCS"), Code.DENIED, "")


def test_action_project_write_allow(tracker: Tracker) -> None:
    _, _, c = setup_cloud(tracker)
    expect(check(c, dana, "project.write", "project:APP"), Code.ALLOWED, "")
    # create-repo carries write.
    expect(check(c, cr, "project.write", "project:APP"), Code.ALLOWED, "create-repo")


def test_action_project_write_deny(tracker: Tracker) -> None:
    _, _, c = setup_cloud(tracker)
    expect(check(c, bob, "project.write", "project:DOCS"), Code.DENIED, "has read on project DOCS, needs write")


def test_action_repo_create_allow(tracker: Tracker) -> None:
    _, _, c = setup_cloud(tracker)
    expect(check(c, cr, "repo.create", "project:APP"), Code.ALLOWED, "create-repo")
    expect(check(c, ola, "repo.create", "project:DOCS"), Code.ALLOWED, "owner")


def test_action_repo_create_deny(tracker: Tracker) -> None:
    _, _, c = setup_cloud(tracker)
    expect(check(c, dana, "repo.create", "project:DOCS"), Code.DENIED, "has write on project DOCS, needs create-repo")


def test_action_project_admin_allow(tracker: Tracker) -> None:
    _, _, c = setup_cloud(tracker)
    expect(check(c, ola, "project.admin", "project:APP"), Code.ALLOWED, "owner of workspace acme")


def test_action_project_admin_deny(tracker: Tracker) -> None:
    _, _, c = setup_cloud(tracker)
    expect(check(c, bob, "project.admin", "project:DOCS"), Code.DENIED, "needs admin")
    # A group that would suffice makes the answer unknown, not deny.
    expect(check(c, bob, "project.admin", "project:APP"), Code.UNSUPPORTED, "group developers grants admin")


def test_action_workspace_member_allow(tracker: Tracker) -> None:
    _, _, c = setup_cloud(tracker)
    expect(check(c, dana, "workspace.member", "workspace"), Code.ALLOWED, "member of workspace acme")


def test_action_workspace_member_deny(tracker: Tracker) -> None:
    _, _, c = setup_cloud(tracker)
    expect(check(c, left, "workspace.member", "workspace"), Code.DENIED, "not a member")


def test_action_workspace_admin_allow(tracker: Tracker) -> None:
    _, _, c = setup_cloud(tracker)
    expect(check(c, ola, "workspace.admin", "workspace"), Code.ALLOWED, "owner")


def test_action_workspace_admin_deny(tracker: Tracker) -> None:
    _, _, c = setup_cloud(tracker)
    expect(check(c, dana, "workspace.admin", "workspace"), Code.DENIED, "not an owner")


# -- Cloud semantics --


def test_cloud_branch_restrictions_unknowns(tracker: Tracker) -> None:
    _, f, c = setup_cloud(tracker)
    # A restriction exempting a group: Cloud does not say who is in it.
    expect(check(c, dana, "repo.push", "repo:api@release/1.2"), Code.UNSUPPORTED, "exempts group developers")
    # "release/*" against a nested branch: Cloud's glob semantics are
    # undocumented, so the answer is unknown rather than a guess.
    expect(check(c, dana, "repo.push", "repo:api@release/1/hotfix"), Code.UNSUPPORTED, 'pattern "release/*"')
    # Branching model and character classes cannot be evaluated.
    with f.mu:
        f.restrictions["api"] += [
            {"id": 6, "kind": "push", "branch_match_kind": "branching_model", "branch_type": "production", "pattern": "", "users": [], "groups": []},
            {"id": 7, "kind": "push", "branch_match_kind": "glob", "pattern": "hotfix/[0-9]*", "users": [], "groups": []},
        ]
    d = check(c, dana, "repo.push", "repo:api@feature/x")
    expect(d, Code.UNSUPPORTED, "branching model production")
    assert 'pattern "hotfix/[0-9]*"' in d.text, d.text
    # A matching restriction still denies before the unknowns are reported.
    expect(check(c, dana, "repo.push", "repo:api@main"), Code.DENIED, "")


def test_cloud_repo_permission_filter_fallback(tracker: Tracker) -> None:
    srv, f, c = setup_cloud(tracker)
    with f.mu:
        f.reject_filter = True
    expect(check(c, dana, "repo.push", "repo:api"), Code.ALLOWED, "")
    expect(check(c, bob, "repo.push", "repo:api"), Code.DENIED, "")
    unfiltered = sum(1 for call in srv.calls() if "/permissions/repositories/api" in call.path and call.q("q") == "")
    assert unfiltered == 2, f"{unfiltered} unfiltered reads, want 2"


def test_cloud_pagination(tracker: Tracker) -> None:
    srv, _, conn = setup_cloud(tracker)
    # Force one-entry pages on the owner listing by asking for pagelen=1.
    ident = conn.resolve_identity(background(), ola)
    # The owner list has two entries (ola owner, dana member); with the
    # fake's two-page mode the second page must be followed on the same host.
    other = CloudFake()
    tracker.fakes.append(other)

    def one_per_page(w: itest.ResponseWriter, r: itest.Request) -> None:
        r.query["pagelen"] = ["1"]
        other.api(w, r)

    srv.handle("GET", "/2.0/workspaces/acme/permissions", one_per_page)
    owner = conn.cloud_is_owner(background(), ident)
    assert owner, f"owner = {owner}"
    pages = sum(1 for call in srv.calls() if call.path == "/2.0/workspaces/acme/permissions")
    assert pages == 2, f"read {pages} pages, want 2"

    # A next link on another host is refused.
    def foreign(w: itest.ResponseWriter, r: itest.Request) -> None:
        write(w, {"values": [], "next": "https://evil.example/2.0/workspaces/acme/permissions?page=2"})

    srv.handle("GET", "/2.0/workspaces/acme/permissions", foreign)
    with pytest.raises(Exception, match="outside its API"):
        conn.cloud_is_owner(background(), ident)


def test_cloud_missing_objects(tracker: Tracker) -> None:
    _, f, c = setup_cloud(tracker)
    expect(check(c, dana, "repo.read", "repo:hidden"), Code.RESOURCE_NOT_VISIBLE, "does not exist in workspace acme or hallpass cannot see it")
    expect(check(c, dana, "project.read", "project:NOPE"), Code.RESOURCE_NOT_VISIBLE, "")
    with f.mu:
        f.status = 403
    expect(check(c, dana, "repo.read", "repo:api"), Code.CREDENTIAL_REJECTED, "")


def test_cloud_identity(tracker: Tracker) -> None:
    srv, _, c = setup_cloud(tracker)
    expect(check(c, User(email=" Dana@Example.com "), "workspace.member", "workspace"), Code.ALLOWED, "")
    lookup = None
    for call in srv.calls():
        if call.path == "/2.0/workspaces/acme/members":
            lookup = call
    assert lookup is not None and lookup.q("q") == 'user.email IN ("dana@example.com")', f"lookup {lookup}"
    expect(check(c, User(email="nobody@example.com"), "workspace.member", "workspace"), Code.USER_NOT_FOUND, "no member of workspace acme")
    expect(check(c, User(email="dup@example.com"), "workspace.member", "workspace"), Code.USER_AMBIGUOUS, "")
    expect(check(c, User(email='a"b@example.com'), "workspace.member", "workspace"), Code.INVALID_REQUEST, "")


def test_rejects_bad_resources(tracker: Tracker) -> None:
    srv, _, c = setup_cloud(tracker)
    expect(check(c, dana, "repo.read", "repo:api"), Code.ALLOWED, "")
    n = len(srv.calls())
    cases = [
        ("repo.read", "repo:APP/api"),  # Data Center shape on Cloud
        ("repo.read", "repo:api@main"),  # read takes no branch
        ("repo.admin", "repo:api@main"),  # admin takes no branch
        ("repo.push", "repo:api@"),  # empty branch
        ("repo.push", "repo:api@-x"),  # bad branch
        ("repo.push", "repo:api@a..b"),  # bad branch
        ("repo.push", "repo:api@a/"),  # bad branch
        ("repo.push", "repo:api@x?y"),  # query, not a branch
        ("repo.read", "repo:a b"),  # bad slug
        ("repo.read", "repo:"),  # empty
        ("repo.read", "project:APP"),  # wrong type
        ("project.read", "repo:api"),  # wrong type
        ("project.read", "project:A/B"),  # bad key
        ("workspace.member", "workspace:acme"),
        ("workspace.member", "repo:api"),
        ("repo.read", "repo:api?x=1"),
    ]
    bad = []
    for action, resource in cases:
        d = check(c, dana, action, resource)
        if d.code != Code.INVALID_REQUEST:
            bad.append(f"{action} {resource}: {d.code} ({d.text}), want invalid_request")
    assert not bad, "\n".join(bad)
    # Only the identity lookups reached the upstream.
    extra = sum(1 for call in srv.calls()[n:] if call.path != "/2.0/workspaces/acme/members")
    assert extra == 0, f"{extra} calls reached the upstream for rejected resources"


@pytest.mark.parametrize(
    ("pattern", "branch", "dc", "cloud", "dc_ok", "cloud_ok"),
    [
        ("main", "main", True, True, True, True),
        ("main", "main2", False, False, True, True),
        # A slash-less pattern against a nested branch: ambiguous on both.
        ("main", "release/main", False, False, False, False),
        ("**/main", "release/main", True, True, True, True),
        ("release/*", "release/1.2", True, True, True, True),
        # "*" across "/": Data Center says no; Cloud is undocumented, so unknown.
        ("release/*", "release/a/b", False, False, True, False),
        ("release/*", "releases", False, False, True, True),
        ("*", "main", True, True, True, True),
        ("*", "a/b", False, False, False, False),
        ("**", "anything/at/all", True, True, True, True),
        ("**/hotfix", "a/b/hotfix", True, True, True, True),
        ("**/hotfix", "hotfix", True, True, True, True),
        ("release/**", "release/a/b", True, True, True, True),
        ("feature/?", "feature/a", True, True, True, True),
        ("feature/?", "feature/ab", False, False, True, True),
        ("feature/?", "feature//", False, False, True, False),
        ("refs/heads/main", "main", True, True, True, True),
        ("release/[0-9]", "release/1", False, False, False, False),
        ("{a,b}", "a", False, False, False, False),
    ],
)
def test_glob(pattern: str, branch: str, dc: bool, cloud: bool, dc_ok: bool, cloud_ok: bool) -> None:
    assert ref_match(pattern, branch, True) == (dc, dc_ok), f"data center ref_match({pattern!r}, {branch!r})"
    assert ref_match(pattern, branch, False) == (cloud, cloud_ok), f"cloud ref_match({pattern!r}, {branch!r})"


def test_cloud_failures(tracker: Tracker) -> None:
    srv, _, c = setup_cloud(tracker)
    expect(check(c, dana, "repo.read", "repo:api"), Code.ALLOWED, "")
    itest.failure_cases(srv, lambda: check(c, dana, "repo.read", "repo:api"))


def test_cloud_basic_auth(tracker: Tracker) -> None:
    srv = tracker.server()
    f = CloudFake()
    tracker.fakes.append(f)

    def h(w: itest.ResponseWriter, r: itest.Request) -> None:
        ba = r.basic_auth()
        if ba is None or ba[0] != "bot@example.com" or ba[1] != f.token:
            w.write_header(401)
            return
        r.header.set("Authorization", "Bearer " + f.token)
        f.api(w, r)

    srv.handle("GET", "/2.0/*", h)
    deps, _ = itest.deps(srv)
    s = itest.settings(
        "bb",
        "bitbucket",
        {"url": srv.url, "workspace": "acme", "auth_mode": "basic", "username": "bot@example.com"},
        {"credential": secret_literal(f.token)},
    )
    c = INTEGRATION.new(background(), s, deps)
    expect(check(c, dana, "repo.read", "repo:api"), Code.ALLOWED, "")


def test_cloud_probe(tracker: Tracker) -> None:
    _, f, c = setup_cloud(tracker)
    r = c.probe(background())
    assert "workspace acme" in r.summary and "looked up by email" in r.summary, r.summary
    itest.assert_no_canary(r.summary)
    assert "no group membership" in "\n".join(r.warnings), f"warnings {r.warnings}"
    with f.mu:
        f.status = 403
    with pytest.raises(Exception) as ei:  # Go: err == nil fails
        c.probe(background())
    itest.assert_no_canary(str(ei.value))
    with f.mu:
        f.status = 503
    with pytest.raises(Exception) as ei:
        c.probe(background())
    d = to_decision(ei.value)
    assert d.code == Code.UPSTREAM_ERROR, f"probe on 503: {d.code} ({d.text})"


def test_new_rejects_bad_settings(tracker: Tracker) -> None:
    srv = tracker.server()
    deps, _ = itest.deps(srv)
    cases: list[dict[str, str]] = [
        {},  # cloud without workspace
        {"workspace": "acme", "edition": "x"},  # bad edition
        {"workspace": "a b"},  # bad slug
        {"edition": "datacenter"},  # no url
        {"edition": "datacenter", "url": srv.url, "workspace": "acme"},
        {"workspace": "acme", "auth_mode": "basic"},  # no username
        {"workspace": "acme", "auth_mode": "digest"},
    ]
    for v in cases:
        s = itest.settings("bb", "bitbucket", v, {"credential": itest.literal("x")})
        with pytest.raises(Exception):  # noqa: B017 - Go: err == nil fails
            INTEGRATION.new(background(), s, deps)
    s = itest.settings("bb", "bitbucket", {"workspace": "acme"}, None)
    with pytest.raises(Exception):  # noqa: B017 - Go: err == nil fails
        INTEGRATION.new(background(), s, deps)
    validate_fields(INTEGRATION.fields())
    for fl in INTEGRATION.fields():
        if fl.validate is not None:
            fl.validate("")  # the empty value is always accepted


def test_catalog() -> None:
    seen: set[str] = set()
    for a in INTEGRATION.actions():
        assert a.name not in seen and a.description != "", f"action {a.name} duplicated or undescribed"
        seen.add(a.name)
    for b in ACTION_LIST:
        incomplete = (b.resource == "workspace" and b.role == "") or (b.resource != "workspace" and b.level == Level.NONE)
        assert not incomplete, f"action {b.name} is incompletely defined"
