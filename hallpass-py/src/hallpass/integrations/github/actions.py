"""The github action table, name rules and resource parsing."""

from __future__ import annotations

import re
from dataclasses import dataclass

from hallpass.core.catalog import Resource, go_bytes, split_branch
from hallpass.core.errors import go_quote

__all__ = [
    "ACTIONS",
    "ACTION_LIST",
    "GHAction",
    "Permissions",
    "Target",
    "equal_fold",
    "from_string",
    "parse_target",
    "slug_ok",
    "valid_branch",
    "valid_login",
    "valid_repo_name",
]

# One rung of GitHub's repository permission ladder, lowest first.
LEVEL_PULL = "pull"
LEVEL_TRIAGE = "triage"
LEVEL_PUSH = "push"
LEVEL_MAINTAIN = "maintain"
LEVEL_ADMIN = "admin"


@dataclass(frozen=True)
class GHAction:
    """One entry of the fixed action table."""

    name: str
    desc: str
    # The resource type the action applies to: repo, org or team.
    resource: str
    # The repository permission the action needs (repo actions only).
    level: str = ""


ACTION_LIST: tuple[GHAction, ...] = (
    GHAction("repo.read", "read the repository (clone, view code and issues); needs pull", "repo", LEVEL_PULL),
    GHAction("repo.triage", "manage issues and pull requests without write access; needs triage", "repo", LEVEL_TRIAGE),
    GHAction("repo.push", "push to the repository (or to @branch, checked against its rules); needs push", "repo", LEVEL_PUSH),
    GHAction("repo.maintain", "manage the repository without destructive actions; needs maintain", "repo", LEVEL_MAINTAIN),
    GHAction("repo.admin", "administer the repository; needs admin", "repo", LEVEL_ADMIN),
    GHAction("issue.create", "open an issue; needs pull and the repository must have issues enabled", "repo", LEVEL_PULL),
    GHAction("pr.create", "open a pull request (via a fork with pull; a branch in the repository itself needs push)", "repo", LEVEL_PULL),
    GHAction("pr.merge", "merge a pull request (into @branch, checked against its rules); needs push", "repo", LEVEL_PUSH),
    GHAction("org.member", "be an active member of the organization", "org"),
    GHAction("org.admin", "be an owner (admin) of the organization", "org"),
    GHAction("org.repo.create", "create a repository in the organization: owner, or member when members may create repositories", "org"),
    GHAction("team.member", "be an active member of the team", "team"),
    GHAction("team.maintainer", "be a maintainer of the team", "team"),
)

ACTIONS: dict[str, GHAction] = {a.name: a for a in ACTION_LIST}

# GitHub's name rules; a repository name may contain dots, an owner (login)
# may not. Go's RE2 classes are ASCII; fullmatch stands in for ^...$.
_REPO_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}")
_LOGIN_RE = re.compile(r"[A-Za-z0-9]([A-Za-z0-9-]{0,37}[A-Za-z0-9])?")
_SLUG_RE = re.compile(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?")


def valid_login(s: str) -> bool:
    """Whether s is a GitHub login: alphanumerics and single hyphens, at
    most 39 characters."""
    return _LOGIN_RE.fullmatch(s) is not None and "--" not in s


def valid_repo_name(s: str) -> bool:
    return _REPO_RE.fullmatch(s) is not None and s not in (".", "..")


def slug_ok(s: str) -> bool:
    """A team slug hallpass can put into a URL (Go: slugRe plus the length cap)."""
    return _SLUG_RE.fullmatch(s) is not None and len(go_bytes(s)) <= 255


def slug_re_match(s: str) -> bool:
    return _SLUG_RE.fullmatch(s) is not None


_BRANCH_BAD = frozenset("\\~^:?*[@")


def valid_branch(s: str) -> bool:
    """Reject branch names that could not be git refs or that would change
    the meaning of a URL."""
    if s == "" or len(go_bytes(s)) > 255 or s.startswith("-") or ".." in s:
        return False
    return all(not (ord(c) < 0x21 or c == "\x7f" or c in _BRANCH_BAD) for c in s)


def _fold(c: str) -> str:
    """The simple case folding of one rune."""
    f = c.casefold()
    if len(f) == 1:
        return f
    lo = c.lower()
    return lo if len(lo) == 1 else c


def equal_fold(a: str, b: str) -> bool:
    """Go's strings.EqualFold: equal under simple Unicode case folding."""
    if len(a) != len(b):
        return False
    return all(x == y or _fold(x) == _fold(y) for x, y in zip(a, b, strict=True))


@dataclass(frozen=True)
class Target:
    """A parsed and validated resource."""

    kind: str  # repo, org or team
    owner: str  # organization login, as configured
    repo: str = ""
    branch: str = ""
    team: str = ""

    def __str__(self) -> str:
        if self.kind == "repo":
            s = self.owner + "/" + self.repo
            if self.branch:
                s += "@" + self.branch
            return s
        if self.kind == "team":
            return self.owner + "/" + self.team
        return self.owner


def parse_target(a: GHAction, org: str, r: Resource) -> Target:
    """Validate the resource against the action's resource type and the
    configured organization; raise ValueError. Every part goes into a URL
    path later, so the rules are strict."""
    if r.type != a.resource:
        raise ValueError(f"action {a.name} needs a {a.resource}: resource, not {r.type}:")
    if r.query:
        raise ValueError("github resources take no query parameters")
    if r.type == "repo":
        rid, branch = split_branch(r.id)
        owner, sep, name = rid.partition("/")
        if not sep or not valid_login(owner) or not valid_repo_name(name):
            raise ValueError(f"repo resource must be repo:<owner>/<name>[@branch], got {go_quote(r.id)}")
        if not equal_fold(owner, org):
            raise ValueError(f"repository owner {go_quote(owner)} must be the configured organization {go_quote(org)}: the app installation is per organization")
        if "@" in r.id and not valid_branch(branch):
            raise ValueError(f"branch {go_quote(branch)} is not a valid branch name")
        return Target(kind="repo", owner=org, repo=name, branch=branch)
    if r.type == "org":
        if not valid_login(r.id):
            raise ValueError(f"org resource must be org:<login>, got {go_quote(r.id)}")
        if not equal_fold(r.id, org):
            raise ValueError(f"organization {go_quote(r.id)} must be the configured organization {go_quote(org)}: the app installation is per organization")
        return Target(kind="org", owner=org)
    if r.type == "team":
        owner, sep, slug = r.id.partition("/")
        if not sep or not valid_login(owner) or not slug_ok(slug):
            raise ValueError(f"team resource must be team:<org>/<slug>, got {go_quote(r.id)}")
        if not equal_fold(owner, org):
            raise ValueError(f"team organization {go_quote(owner)} must be the configured organization {go_quote(org)}: the app installation is per organization")
        return Target(kind="team", owner=org, team=slug)
    raise ValueError(f"unknown resource type {go_quote(r.type)}")


@dataclass(frozen=True)
class Permissions:
    """The booleans GitHub reports for a collaborator."""

    pull: bool = False
    triage: bool = False
    push: bool = False
    maintain: bool = False
    admin: bool = False

    def has(self, level: str) -> bool:
        """Whether the permissions include the level."""
        return {
            LEVEL_PULL: self.pull,
            LEVEL_TRIAGE: self.triage,
            LEVEL_PUSH: self.push,
            LEVEL_MAINTAIN: self.maintain,
            LEVEL_ADMIN: self.admin,
        }.get(level, False)


def from_string(s: str) -> Permissions:
    """Expand the lossy top-level permission string, for responses that
    carry no user.permissions object."""
    if s == "admin":
        return Permissions(True, True, True, True, True)
    if s == "maintain":
        return Permissions(True, True, True, True)
    if s in ("write", "push"):
        return Permissions(True, True, True)
    if s == "triage":
        return Permissions(True, True)
    if s in ("read", "pull"):
        return Permissions(True)
    return Permissions()
