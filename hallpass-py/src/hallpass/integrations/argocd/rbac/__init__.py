"""Evaluates Argo CD RBAC policy the way Argo CD's API server does, without
Casbin. A port of argo-cd/util/rbac and argo-cd/server/rbacpolicy (v3):

    request  r = sub, res, act, obj
    policy   p = sub, res, act, obj, eft
    roles    g = _, _
    effect   some allow && !some deny
    matcher  g(r.sub, p.sub) && m(r.res, p.res) && m(r.act, p.act) && m(r.obj, p.obj)

where m is a gobwas glob with no separators (default) or an unanchored Go
regexp when policy.matchMode is "regex".
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field

from hallpass.core.catalog import go_bytes
from hallpass.core.errors import go_quote, go_trim_space

from .builtin import BUILTIN_POLICY_CSV
from .glob import glob_match
from .re2 import RE2Error, compile_re2

__all__ = [
    "ACTION_ACTION",
    "ACTION_CREATE",
    "ACTION_DELETE",
    "ACTION_GET",
    "ACTION_INVOKE",
    "ACTION_OVERRIDE",
    "ACTION_ROLLBACK",
    "ACTION_SYNC",
    "ACTION_UPDATE",
    "BUILTIN_POLICY_CSV",
    "DEFAULT_SCOPES",
    "GLOB_MATCH_MODE",
    "MATCH_MODE_KEY",
    "MAX_ROLE_DEPTH",
    "POLICY_CSV_KEY",
    "POLICY_DEFAULT_KEY",
    "PROJECT_SCOPED",
    "REGEX_MATCH_MODE",
    "RESOURCE_ACCOUNTS",
    "RESOURCE_APPLICATIONS",
    "RESOURCE_APPLICATION_SETS",
    "RESOURCE_CERTIFICATES",
    "RESOURCE_CLUSTERS",
    "RESOURCE_EXEC",
    "RESOURCE_EXTENSIONS",
    "RESOURCE_GPG_KEYS",
    "RESOURCE_LOGS",
    "RESOURCE_PROJECTS",
    "RESOURCE_REPOSITORIES",
    "RESOURCE_WRITE_REPOSITORIES",
    "SCOPES_KEY",
    "Enforcer",
    "Link",
    "Options",
    "Policy",
    "PolicyError",
    "Project",
    "ProjectRole",
    "Rule",
    "parse_policy",
    "parse_scopes",
    "policy_csv",
    "project_from_request",
]

# Config map keys, as in argo-cd/util/rbac.
POLICY_CSV_KEY = "policy.csv"
POLICY_DEFAULT_KEY = "policy.default"
SCOPES_KEY = "scopes"
MATCH_MODE_KEY = "policy.matchMode"
GLOB_MATCH_MODE = "glob"
REGEX_MATCH_MODE = "regex"

# Resources and actions Argo CD knows.
RESOURCE_CLUSTERS = "clusters"
RESOURCE_PROJECTS = "projects"
RESOURCE_APPLICATIONS = "applications"
RESOURCE_APPLICATION_SETS = "applicationsets"
RESOURCE_REPOSITORIES = "repositories"
RESOURCE_WRITE_REPOSITORIES = "write-repositories"
RESOURCE_CERTIFICATES = "certificates"
RESOURCE_ACCOUNTS = "accounts"
RESOURCE_GPG_KEYS = "gpgkeys"
RESOURCE_LOGS = "logs"
RESOURCE_EXEC = "exec"
RESOURCE_EXTENSIONS = "extensions"

ACTION_GET = "get"
ACTION_CREATE = "create"
ACTION_UPDATE = "update"
ACTION_DELETE = "delete"
ACTION_SYNC = "sync"
ACTION_OVERRIDE = "override"
ACTION_ACTION = "action"
ACTION_INVOKE = "invoke"
ACTION_ROLLBACK = "rollback"

# The claim Argo CD reads groups from when "scopes" is unset.
DEFAULT_SCOPES = ("groups",)

# Casbin's default role hierarchy limit.
MAX_ROLE_DEPTH = 10


class PolicyError(ValueError):
    """A policy Argo CD would refuse to load."""


@dataclass(frozen=True)
class Rule:
    """One p line."""

    sub: str
    res: str
    act: str
    obj: str
    deny: bool = False


@dataclass(frozen=True)
class Link:
    """One g line: sub has role role."""

    sub: str
    role: str


@dataclass
class Policy:
    """A parsed set of p and g lines."""

    rules: list[Rule] = field(default_factory=list)
    links: list[Link] = field(default_factory=list)


# unicode.IsSpace, which encoding/csv's TrimLeadingSpace uses.
_GO_SPACE = "\t\n\v\f\r \x85\xa0                　"

_ERR_BARE_QUOTE = 'bare " in non-quoted-field'
_ERR_QUOTE = 'extraneous or missing " in quoted-field'


class _CSVError(ValueError):
    """encoding/csv's *ParseError for a one-line input."""

    def __init__(self, column: int, err: str) -> None:
        super().__init__(f"parse error on line 1, column {column}: {err}")


def _blen(s: str) -> int:
    return len(go_bytes(s))


def _csv_record(line: str) -> list[str]:
    """The first record of line as Go's csv.Reader with TrimLeadingSpace
    reads it (line holds no newline and is not blank). Column numbers in
    errors are 1-based byte offsets, as Go reports them."""
    fields: list[str] = []
    col = 1
    while True:
        stripped = line.lstrip(_GO_SPACE)
        col += _blen(line) - _blen(stripped)
        line = stripped
        if not line.startswith('"'):
            i = line.find(",")
            fld = line if i < 0 else line[:i]
            j = fld.find('"')
            if j >= 0:
                raise _CSVError(col + _blen(fld[:j]), _ERR_BARE_QUOTE)
            fields.append(fld)
            if i < 0:
                return fields
            col += _blen(line[: i + 1])
            line = line[i + 1 :]
            continue
        line = line[1:]
        col += 1
        buf: list[str] = []
        while True:
            i = line.find('"')
            if i < 0:
                # Abrupt end of input inside a quoted field.
                col += _blen(line)
                raise _CSVError(col, _ERR_QUOTE)
            buf.append(line[:i])
            col += _blen(line[: i + 1])
            line = line[i + 1 :]
            if line.startswith('"'):
                buf.append('"')
                line = line[1:]
                col += 1
            elif line.startswith(","):
                line = line[1:]
                col += 1
                fields.append("".join(buf))
                break
            elif line == "":
                fields.append("".join(buf))
                return fields
            else:
                raise _CSVError(col - 1, _ERR_QUOTE)


def parse_policy(text: str) -> Policy:
    """Parse CSV policy text exactly as Argo CD's loadPolicyLine does: blank
    lines and # comments are skipped, fields are CSV with leading space
    trimmed, p lines have 6 fields and g lines 3, anything else is an
    error (PolicyError)."""
    p = Policy()
    for raw in text.split("\n"):
        line = go_trim_space(raw)
        if line == "" or line.startswith("#"):
            continue
        try:
            tokens = _csv_record(line)
        except _CSVError as e:
            raise PolicyError(f"error parsing policy line {go_quote(line)}: {e}") from None
        if len(tokens) == 6 and tokens[0] == "p":
            eft = tokens[5]
            if eft not in ("allow", "deny"):
                # Casbin treats any other effect as neither allow nor deny;
                # such a line can never match. Keep it out.
                continue
            p.rules.append(Rule(sub=tokens[1], res=tokens[2], act=tokens[3], obj=tokens[4], deny=eft == "deny"))
        elif len(tokens) == 3 and tokens[0] == "g":
            p.links.append(Link(sub=tokens[1], role=tokens[2]))
        else:
            raise PolicyError(f"invalid RBAC policy: {line}")
    return p


def policy_csv(data: dict[str, str]) -> str:
    """Assemble the user policy from an argocd-rbac-cm data map: policy.csv
    first, then every policy.*.csv key in sorted order."""
    out: list[str] = []
    if POLICY_CSV_KEY in data:
        out.append(data[POLICY_CSV_KEY])
    for k in sorted(data):
        if k.startswith("policy.") and k.endswith(".csv") and k != POLICY_CSV_KEY:
            out.append("\n")
            out.append(data[k])
    return "".join(out)


@dataclass
class ProjectRole:
    """One spec.roles entry."""

    name: str
    policies: list[str] = field(default_factory=list)
    groups: list[str] = field(default_factory=list)


@dataclass
class Project:
    """The part of an AppProject that affects RBAC."""

    name: str
    roles: list[ProjectRole] = field(default_factory=list)

    def policies_string(self) -> str:
        """The project's runtime policy exactly as
        AppProject.ProjectPoliciesString renders it."""
        lines: list[str] = []
        for role in self.roles:
            lines.append(f"p, proj:{self.name}:{role.name}, projects, get, {self.name}, allow")
            lines.extend(role.policies)
            for g in role.groups:
                lines.append(f"g, {g}, proj:{self.name}:{role.name}")
        return "\n".join(lines)


@dataclass(frozen=True)
class Options:
    """Options for Enforcer."""

    # Argo CD's built-in policy (BUILTIN_POLICY_CSV).
    builtin: str = ""
    # The policy from argocd-rbac-cm (policy_csv).
    user: str = ""
    # A project's policies_string, or "".
    runtime: str = ""
    # "glob" (default) or "regex".
    match_mode: str = ""
    # policy.default, or "".
    default_role: str = ""


class Enforcer:
    """Evaluates requests against builtin + user (+ runtime) policy.

    The constructor parses the three policies. A parse error in any of
    them raises PolicyError; Argo CD would refuse to load the policy too.
    """

    def __init__(self, o: Options) -> None:
        self.rules: list[Rule] = []
        self.links: dict[str, list[str]] = {}
        self.link_subs: set[str] = set()
        self.match_mode = REGEX_MATCH_MODE if o.match_mode == REGEX_MATCH_MODE else GLOB_MATCH_MODE
        self.default_role = o.default_role
        self._regexes: dict[str, re.Pattern[str] | None] = {}
        self._regex_lock = threading.Lock()
        for text in (o.builtin, o.user, o.runtime):
            p = parse_policy(text)
            self.rules.extend(p.rules)
            for lk in p.links:
                self.links.setdefault(lk.sub, []).append(lk.role)
                self.link_subs.add(lk.sub)

    def has_grouping_subject(self, sub: str) -> bool:
        """Whether a g line starts with sub. Argo CD only considers a user's
        group when the policy names it in a g line."""
        return sub in self.link_subs

    def _has_link(self, sub: str, role: str) -> bool:
        """Casbin's role manager: sub == role, or sub reaches role through g
        links within MAX_ROLE_DEPTH steps."""
        if sub == role:
            return True
        seen = {sub}
        frontier = [sub]
        depth = 0
        while depth < MAX_ROLE_DEPTH and frontier:
            nxt: list[str] = []
            for s in frontier:
                for r in self.links.get(s, ()):
                    if r == role:
                        return True
                    if r not in seen:
                        seen.add(r)
                        nxt.append(r)
            frontier = nxt
            depth += 1
        return False

    def _match(self, val: str, pattern: str) -> bool:
        if self.match_mode == REGEX_MATCH_MODE:
            return self._regex_match(val, pattern)
        return glob_match(pattern, val)

    def _regex_match(self, val: str, pattern: str) -> bool:
        """Casbin's RegexMatch: regexp.MatchString(pattern, val), unanchored,
        in Go's RE2 syntax. An invalid pattern never matches (Casbin panics,
        and Argo CD's enforce treats the resulting error as false)."""
        with self._regex_lock:
            if pattern in self._regexes:
                rx = self._regexes[pattern]
            else:
                try:
                    rx = compile_re2(pattern)
                except RE2Error:
                    rx = None
                self._regexes[pattern] = rx
        return rx is not None and rx.search(val) is not None

    def _enforce_raw(self, sub: str, res: str, act: str, obj: str) -> bool:
        """Casbin's Enforce: some allow and no deny among matching rules."""
        allow = False
        for r in self.rules:
            if not self._has_link(sub, r.sub) or not self._match(res, r.res) or not self._match(act, r.act) or not self._match(obj, r.obj):
                continue
            if r.deny:
                return False
            allow = True
        return allow

    def enforce(self, sub: str, res: str, act: str, obj: str) -> bool:
        """Argo CD's enforce for a string subject: the default role is
        checked first, then the subject."""
        if self.default_role != "" and self._enforce_raw(self.default_role, res, act, obj):
            return True
        return self._enforce_raw(sub, res, act, obj)

    def enforce_claims(self, subject: str, groups: list[str] | tuple[str, ...], res: str, act: str, obj: str) -> bool:
        """RBACPolicyEnforcer.EnforceClaims for a resolved subject and its
        group values: default role, then the subject, then each group that
        appears as the first element of a g line. The Enforcer must already
        include the project's runtime policy when the request is project
        scoped."""
        if self.enforce(subject, res, act, obj):
            return True
        for g in groups:
            if g not in self.link_subs:
                continue
            if self.enforce(g, res, act, obj):
                return True
        return False


# The resources whose object is "<project>/<name>".
PROJECT_SCOPED = frozenset(
    {
        RESOURCE_APPLICATIONS,
        RESOURCE_APPLICATION_SETS,
        RESOURCE_LOGS,
        RESOURCE_EXEC,
        RESOURCE_CLUSTERS,
        RESOURCE_REPOSITORIES,
    }
)


def project_from_request(res: str, obj: str) -> str:
    """The project name a request refers to, as getProjectFromRequest finds
    it: the first path segment of the object for project-scoped resources
    (when there is a "/"), the object itself for projects, "" otherwise."""
    if res in PROJECT_SCOPED:
        parts = obj.split("/")
        if len(parts) >= 2:
            return parts[0]
    elif res == RESOURCE_PROJECTS:
        return obj
    return ""


def parse_scopes(v: str) -> list[str] | None:
    """Parse the "scopes" config map value, a YAML/JSON flow list such as
    "[groups, email]". Argo CD uses a YAML parser; the flow form is the only
    one documented and the only one accepted here. Raises ValueError."""
    v = go_trim_space(v)
    if v == "":
        return None
    if not v.startswith("[") or not v.endswith("]"):
        raise ValueError("scopes must be a list such as [groups, email]")
    out: list[str] = []
    for s in v[1:-1].split(","):
        s = go_trim_space(s).strip("\"'")
        if s != "":
            out.append(s)
    return out or None
