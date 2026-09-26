"""The bitbucket action table, resource parsing and branch pattern matching
(Go: internal/integrations/bitbucket/actions.go)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import IntEnum

from hallpass.core.catalog import Action, Resource, go_bytes, split_branch
from hallpass.core.decision import Code, HallpassError, errorf
from hallpass.core.errors import go_quote


class Level(IntEnum):
    """An effective permission on a repository or project, ordered."""

    NONE = 0
    READ = 1
    WRITE = 2
    ADMIN = 3

    def __str__(self) -> str:
        if self == Level.READ:
            return "read"
        if self == Level.WRITE:
            return "write"
        if self == Level.ADMIN:
            return "admin"
        return "none"


@dataclass(frozen=True)
class BBAction:
    """One named question."""

    name: str
    desc: str
    # The type the action takes: repo, project or workspace.
    resource: str
    # The repository or project permission needed.
    level: Level = Level.NONE
    # The branch-restriction kind consulted when the repo resource names a
    # branch: "push" or "merge".
    branch: str = ""
    # Project-level repository creation, which Cloud grants separately from
    # write.
    create_repo: bool = False
    # The workspace role needed: "member" or "admin".
    role: str = ""


ACTION_LIST: tuple[BBAction, ...] = (
    BBAction("repo.read", "read and clone the repository; needs read", "repo", Level.READ),
    BBAction(
        "repo.push",
        "push to the repository (or to @branch, checked against its branch restrictions); needs write",
        "repo",
        Level.WRITE,
        branch="push",
    ),
    BBAction(
        "pr.merge",
        "merge a pull request (into @branch, checked against its branch restrictions); needs write",
        "repo",
        Level.WRITE,
        branch="merge",
    ),
    BBAction("repo.admin", "administer the repository: settings, permissions, deletion; needs admin", "repo", Level.ADMIN),
    BBAction("project.read", "see the project and read its repositories; needs read", "project", Level.READ),
    BBAction("project.write", "push to the project's repositories; needs write", "project", Level.WRITE),
    BBAction(
        "repo.create",
        "create a repository in the project; needs create-repo (Cloud) or project admin (Data Center, see the doc)",
        "project",
        Level.WRITE,
        create_repo=True,
    ),
    BBAction("project.admin", "administer the project; needs admin", "project", Level.ADMIN),
    BBAction("workspace.member", "is a member of the workspace (Cloud) or a licensed user (Data Center)", "workspace", role="member"),
    BBAction("workspace.admin", "is a workspace owner (Cloud) or a global administrator (Data Center)", "workspace", role="admin"),
)

ACTIONS: dict[str, BBAction] = {a.name: a for a in ACTION_LIST}


def catalog_actions() -> list[Action]:
    return [Action(a.name, a.desc + " (" + a.resource + ")") for a in ACTION_LIST]


# SLUG_RE is a workspace slug, repository slug or project key. Cloud slugs
# are lowercase with dots, hyphens and underscores; Data Center project keys
# are upper case and personal projects start with "~".
SLUG_RE = re.compile(r"~?[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
# UUID_RE is a Cloud UUID in braces, also accepted where a slug is.
UUID_RE = re.compile(r"\{[0-9a-fA-F-]{36}\}")
BRANCH_RE = re.compile(r"[^\x00-\x20\x7f~^:?*\[\\]{1,255}")


def valid_slug(s: str) -> bool:
    return SLUG_RE.fullmatch(s) is not None or UUID_RE.fullmatch(s) is not None


def valid_branch(s: str) -> bool:
    return (
        BRANCH_RE.fullmatch(s) is not None
        and not s.startswith("-")
        and not s.startswith("/")
        and not s.endswith("/")
        and not s.endswith(".")
        and not s.endswith(".lock")
        and ".." not in s
        and "//" not in s
        and "@{" not in s
    )


@dataclass(frozen=True)
class Target:
    """A parsed resource."""

    action: BBAction
    # The project key (Data Center, and Cloud projects).
    project: str = ""
    # The repository slug; empty for project and workspace targets.
    repo: str = ""
    # The branch named with @, if any.
    branch: str = ""

    def __str__(self) -> str:
        """Names the target for decision texts."""
        if self.action.resource == "workspace":
            return "the workspace"
        if self.action.resource == "project":
            return "project " + self.project
        s = "repository " + self.repo
        if self.project != "":
            s = "repository " + self.project + "/" + self.repo
        if self.branch != "":
            s += "@" + self.branch
        return s


def invalid(text: str) -> HallpassError:
    return errorf(Code.INVALID_REQUEST, text)


def parse_target(action_name: str, r: Resource, data_center: bool) -> Target:
    """Validate the resource for the action; raises an invalid_request
    HallpassError.

        repo:<slug>[@branch]                Cloud, the workspace is the connection's
        repo:<PROJECT>/<slug>[@branch]      Data Center
        project:<key>
        workspace                           the connection's workspace or instance
    """
    a = ACTIONS.get(action_name)
    if a is None:
        raise invalid(f"unknown action {go_quote(action_name)}")
    if r.query:
        raise invalid(f"resource {go_quote(r.raw)} must not carry a query")
    if r.type != a.resource:
        raise invalid(f"action {a.name} takes a {a.resource}: resource, not {r.type}:")
    project = repo = branch = ""
    if r.type == "workspace":
        if r.id != "":
            raise invalid("workspace takes no id: the connection names the workspace")
    elif r.type == "project":
        if not valid_slug(r.id):
            raise invalid("project: id must be a project key")
        project = r.id
    elif r.type == "repo":
        rid, branch = split_branch(r.id)
        if "@" in r.id and branch == "":
            raise invalid("repo: a branch after @ must not be empty")
        if branch != "" and not valid_branch(branch):
            raise invalid(f"branch {go_quote(branch)} is not a valid branch name")
        if branch != "" and a.branch == "":
            raise invalid(f"action {a.name} does not take a branch")
        if data_center:
            p, sep, rp = rid.partition("/")
            if not sep or not valid_slug(p) or not valid_slug(rp):
                raise invalid("repo: id must be <PROJECT>/<slug>[@branch] on Data Center")
            project, repo = p, rp
        else:
            if "/" in rid or not valid_slug(rid):
                raise invalid("repo: id must be <slug>[@branch]; the workspace is the connection's")
            repo = rid
    return Target(a, project, repo, branch)


def glob(p: str, s: str, crossing: bool) -> bool:
    """An Ant-style pattern match: "*" and "?" stay within one path segment,
    "**" crosses segments. With crossing set, "*" and "?" match "/" too.
    Patterns with character classes or alternations are not handled.
    Byte-wise, as Go indexes strings."""
    return _glob(go_bytes(p), go_bytes(s), crossing)


def _glob(p: bytes, s: bytes, crossing: bool) -> bool:
    slash = 0x2F
    while p:
        if p.startswith(b"**"):
            p = p.lstrip(b"*")
            if p.startswith(b"/"):
                p = p[1:]
            if not p:
                return True
            return any((i == 0 or s[i - 1] == slash) and _glob(p, s[i:], crossing) for i in range(len(s) + 1))
        if p[0] == 0x2A:  # '*'
            p = p[1:]
            for i in range(len(s) + 1):
                if _glob(p, s[i:], crossing):
                    return True
                if i < len(s) and s[i] == slash and not crossing:
                    return False
            return False
        if p[0] == 0x3F:  # '?'
            if not s or (s[0] == slash and not crossing):
                return False
            p, s = p[1:], s[1:]
            continue
        if not s or p[0] != s[0]:
            return False
        p, s = p[1:], s[1:]
    return s == b""


def ref_match(pattern: str, branch: str, data_center: bool) -> tuple[bool, bool]:
    """Match a branch restriction pattern against a branch name: (matched,
    supported). A refs/heads/ prefix is stripped, as Bitbucket does. Data
    Center patterns are Ant-style. Bitbucket Cloud does not document whether
    "*" crosses "/"; when the two readings disagree for this branch the match
    is reported unsupported, so hallpass never guesses. Character classes and
    alternations are unsupported on both."""
    pattern = pattern.removeprefix("refs/heads/")
    if any(c in pattern for c in "[]{}"):
        return False, False
    segment = glob(pattern, branch, False)
    # UNVERIFIED: whether a pattern without "/" also matches a branch of
    # that name inside a folder (main against release/main). When the two
    # readings differ, the match is unsupported.
    if "/" not in pattern and "/" in branch:
        any_dir = glob("**/" + pattern, branch, False)
        if any_dir != segment:
            return False, False
    if data_center:
        return segment, True
    # UNVERIFIED: whether Cloud's "*" matches across "/".
    crossing = glob(pattern, branch, True)
    if crossing != segment:
        return False, False
    return segment, True


def describe_level(have: Level, needed: Level) -> str:
    if have >= needed:
        return f"has {have} (needs {needed})"
    return f"has {have}, needs {needed}"
