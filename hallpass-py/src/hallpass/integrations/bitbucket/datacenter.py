"""Bitbucket Data Center (and Server): /rest/api/latest and the
branch-permissions plugin. Permissions are listed per grant, so hallpass
combines the direct, group, project, default, public and global grants
itself into the user's effective level.
(Go: internal/integrations/bitbucket/datacenter.go.)"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from hallpass.core import jsonx
from hallpass.core.cache import is_panic_type
from hallpass.core.context import Context
from hallpass.core.decision import (
    Code,
    Decision,
    allowed,
    denied,
    errorf,
    unknown_decision,
    unsupported,
    user_ambiguous,
    user_not_found,
    wrap_error,
)
from hallpass.core.errors import go_quote
from hallpass.core.integration import Identity, ProbeResult
from hallpass.integrations.bitbucket.actions import Level, Target, describe_level, ref_match
from hallpass.integrations.bitbucket.common import Base, classify, equal_fold, i64, opt_bool, opt_i64
from hallpass.net import httpx

DC_API = "/rest/api/latest"


@dataclass(frozen=True)
class DCUser:
    """A Data Center user."""

    name: str = ""
    slug: str = ""
    display_name: str = ""
    email_address: str = ""
    active: bool | None = None


def dc_user(v: Any) -> DCUser:
    d = jsonx.obj(v, "dcUser")
    return DCUser(jsonx.s(d, "name"), jsonx.s(d, "slug"), jsonx.s(d, "displayName"), jsonx.s(d, "emailAddress"), opt_bool(d, "active"))


def dc_level(p: str) -> Level:
    """REPO_*, PROJECT_* and global permission names."""
    if p in ("REPO_ADMIN", "PROJECT_ADMIN", "ADMIN", "SYS_ADMIN"):
        return Level.ADMIN
    if p in ("REPO_WRITE", "PROJECT_WRITE"):
        return Level.WRITE
    if p in ("REPO_READ", "PROJECT_READ"):
        return Level.READ
    return Level.NONE


@dataclass
class GrantSet:
    """What the grant listings of one scope say about the user."""

    level: Level = Level.NONE
    how: str = ""
    # Grants hallpass could not evaluate that might raise the level: a group
    # grant while the user's groups are unavailable, or the global
    # permissions while they are unreadable.
    unresolved: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class _DCRestriction:
    """One ref restriction of the branch-permissions plugin."""

    id: int
    type: str
    matcher_id: str
    matcher_display_id: str
    matcher_type: str
    users: tuple[DCUser, ...]
    groups: tuple[str, ...]


def _dc_restriction(v: Any) -> _DCRestriction:
    d = jsonx.obj(v, "dcRestriction")
    m = jsonx.o(d, "matcher")
    return _DCRestriction(
        i64(d, "id"),
        jsonx.s(d, "type"),
        jsonx.s(m, "id"),
        jsonx.s(m, "displayId"),
        jsonx.s(jsonx.o(m, "type"), "id"),
        tuple(dc_user(u) for u in jsonx.arr(d, "users")),
        tuple(jsonx.strs(d, "groups")),
    )


# UNVERIFIED: repository creation in a Data Center project is taken to need
# PROJECT_ADMIN; if Bitbucket lets PROJECT_WRITE create repositories, users
# with write are denied repo.create although they could.
DC_REPO_CREATE_LEVEL = Level.ADMIN


def dc_decide(g: GrantSet, need: Level, ident: Identity, t: Target) -> Decision:
    """A grant set as a decision."""
    if g.level >= need:
        return allowed(f"{ident.display} {describe_level(g.level, need)} on {t}: {g.how}")
    if g.unresolved:
        return unsupported(f"{ident.display} {describe_level(g.level, need)} on {t} as far as hallpass can read, and {', '.join(g.unresolved)} could add more")
    return denied(f"{ident.display} {describe_level(g.level, need)} on {t}")


class DataCenterMixin(Base):
    """The Data Center half of the connection."""

    def dc_list(self, ctx: Context, path: str, q: dict[str, str] | None, each: Callable[[list[Any]], None]) -> None:
        """Read every page of a Data Center list (start/limit paging)."""
        if q is None:
            q = {}
        q["limit"] = "100"

        def page(resp: httpx.Response) -> httpx.Request | None:
            try:
                d = jsonx.obj(resp.json(), "page")
                values = jsonx.arr(d, "values")
                is_last = opt_bool(d, "isLastPage")
                next_start = opt_i64(d, "nextPageStart")
            except ValueError as e:
                raise wrap_error(Code.UPSTREAM_ERROR, e, "Bitbucket returned an unreadable page")
            each(values)
            if is_last is None or is_last or next_start is None:
                return None
            nxt = dict(q)
            nxt["start"] = str(next_start)
            return httpx.Request(path=path, query=nxt)

        self.api.paginate(ctx, httpx.Request(path=path, query=q), page)

    # -- identity --

    def dc_identity(self, ctx: Context, email: str) -> Identity:
        """Find the user whose email address is the email. The filter is a
        substring match on name and email, so the address is compared
        exactly."""
        matches: list[DCUser] = []

        def users(values: list[Any]) -> None:
            for raw in values:
                try:
                    u = dc_user(raw)
                except ValueError as e:
                    raise wrap_error(Code.UPSTREAM_ERROR, e, "Bitbucket returned an unreadable user")
                if equal_fold(u.email_address, email):
                    matches.append(u)

        try:
            self.dc_list(ctx, DC_API + "/users", {"filter": email}, users)
        except Exception as e:  # noqa: BLE001 - classified or re-raised
            raise classify(e, "search users")
        if not matches:
            raise user_not_found(f"no user has email {email}")
        if len(matches) > 1:
            raise user_ambiguous(f"{len(matches)} users have email {email}")
        u = matches[0]
        if u.name == "":
            raise errorf(Code.UPSTREAM_ERROR, f"the user record for {email} carries no name")
        attrs = {"slug": u.slug, "active": "unknown", "groups": "known"}
        if u.active is not None:
            attrs["active"] = "true" if u.active else "false"
        # The groups the user belongs to. Reading them needs LICENSED_USER;
        # without them group grants cannot be resolved and answer unknown.
        groups: list[str] = []

        def group_page(values: list[Any]) -> None:
            for raw in values:
                try:
                    name = jsonx.s(jsonx.obj(raw, "group"), "name")
                except ValueError as e:
                    raise wrap_error(Code.UPSTREAM_ERROR, e, "Bitbucket returned an unreadable group")
                if name != "":
                    groups.append(name)

        try:
            self.dc_list(ctx, DC_API + "/admin/users/more-members", {"context": u.name}, group_page)
        except Exception as e:  # noqa: BLE001 - classified or re-raised
            if httpx.status(e) in (403, 404):
                attrs["groups"] = "unavailable"
            else:
                raise classify(e, "list the user's groups")
        return Identity(id=u.name, display=u.name, attrs=attrs, groups=tuple(groups))

    # -- permission grants --

    def dc_grants(self, ctx: Context, base: str, ident: Identity) -> GrantSet:
        """Read the user and group permission listings under base (a
        repository, a project, or /admin) and return the user's highest
        level there."""
        out = GrantSet()

        def user_grants(values: list[Any]) -> None:
            for raw in values:
                try:
                    d = jsonx.obj(raw, "grant")
                    perm, user = jsonx.s(d, "permission"), dc_user(d.get("user"))
                except ValueError as e:
                    raise wrap_error(Code.UPSTREAM_ERROR, e, "Bitbucket returned an unreadable grant")
                # The filter is a substring match; only the exact name counts.
                if user.name == ident.id:
                    lv = dc_level(perm)
                    if lv > out.level:
                        out.level, out.how = lv, perm + " granted directly"

        self.dc_list(ctx, base + "/permissions/users", {"filter": ident.id}, user_grants)

        def group_grants(values: list[Any]) -> None:
            for raw in values:
                try:
                    d = jsonx.obj(raw, "grant")
                    perm, group = jsonx.s(d, "permission"), jsonx.s(jsonx.o(d, "group"), "name")
                except ValueError as e:
                    raise wrap_error(Code.UPSTREAM_ERROR, e, "Bitbucket returned an unreadable grant")
                lv = dc_level(perm)
                if lv <= out.level:
                    continue
                if ident.attr("groups") == "unavailable":
                    out.unresolved.append(perm + " of group " + group)
                    continue
                for g in ident.groups:
                    if g == group:
                        out.level, out.how = lv, perm + " via group " + group

        self.dc_list(ctx, base + "/permissions/groups", None, group_grants)
        return out

    def dc_global(self, ctx: Context, ident: Identity) -> tuple[GrantSet, bool]:
        """The user's global level: ADMIN or SYS_ADMIN carry admin
        everywhere. Reading it needs ADMIN; a refusal is reported (False) so
        the caller can answer unknown when it would have mattered."""
        try:
            g = self.dc_grants(ctx, DC_API + "/admin", ident)
        except Exception as e:  # noqa: BLE001 - classified or re-raised
            if httpx.status(e) in (403, 401):
                return GrantSet(), False
            raise classify(e, "read the global permissions")
        if g.level < Level.ADMIN:
            g.level = Level.NONE
        return g, True

    def dc_project_level(self, ctx: Context, key: str, ident: Identity, need: Level) -> tuple[GrantSet, bool, BaseException | None]:
        """The user's effective level on a project: direct and group grants,
        the project's default permission, its public flag and the global
        permissions. Returns (grants, exists, error) as the Go code does:
        exists is False when the project record itself could not be read."""

        def project_rec(v: Any) -> bool:
            d = jsonx.obj(v, "project")
            jsonx.s(d, "key")
            return jsonx.b(d, "public")

        base = DC_API + "/projects/" + httpx.path_escape(key)
        try:
            public = self.get_json(ctx, base, None, project_rec)
        except Exception as e:
            if is_panic_type(e):
                raise
            return GrantSet(), False, e
        try:
            g = self.dc_grants(ctx, base, ident)
        except Exception as e:
            if is_panic_type(e):
                raise
            return GrantSet(), True, e
        if public and g.level < Level.READ:
            g.level, g.how = Level.READ, "public project"
        # Default permissions: granted to every licensed user.
        for name, lv in (("PROJECT_ADMIN", Level.ADMIN), ("PROJECT_WRITE", Level.WRITE), ("PROJECT_READ", Level.READ)):
            if lv <= g.level or lv < need:
                continue
            try:
                permitted = self.get_json(ctx, base + "/permissions/" + name + "/all", None, lambda v: jsonx.b(jsonx.obj(v), "permitted"))
            except Exception as e:
                if is_panic_type(e):
                    raise
                return GrantSet(), True, e
            if permitted:
                g.level, g.how = lv, name + " is the project default"
                break
        if g.level < Level.ADMIN:
            try:
                glob_, seen = self.dc_global(ctx, ident)
            except Exception as e:
                if is_panic_type(e):
                    raise
                return GrantSet(), True, e
            if glob_.level == Level.ADMIN:
                g.level, g.how = Level.ADMIN, glob_.how + " globally"
            elif not seen and g.level < need:
                g.unresolved.append("the global permissions (not readable without ADMIN)")
            else:
                g.unresolved.extend(glob_.unresolved)
        return g, True, None

    # -- checks --

    def dc_check(self, ctx: Context, t: Target, ident: Identity) -> Decision:
        if t.action.resource == "workspace":
            return self._dc_instance(ctx, t, ident)
        if t.action.resource == "project":
            return self._dc_project(ctx, t, ident)
        return self._dc_repo(ctx, t, ident)

    def _dc_instance(self, ctx: Context, t: Target, ident: Identity) -> Decision:
        if t.action.role == "member":
            if ident.attr("active") != "true":
                return unsupported(f"Bitbucket did not report whether {ident.display} is active")
            return allowed(f"{ident.display} is an active user of the instance")
        glob_, seen = self.dc_global(ctx, ident)
        if not seen:
            raise errorf(Code.CREDENTIAL_REJECTED, "reading the global permissions needs ADMIN, which hallpass's token lacks")
        if glob_.level == Level.ADMIN:
            return allowed(f"{ident.display} is a global administrator ({glob_.how})")
        if glob_.unresolved:
            return unsupported(
                f"{ident.display} holds no global administrator permission directly, and hallpass could not resolve {', '.join(glob_.unresolved)} "
                "(listing the groups of a user needs LICENSED_USER)"
            )
        return denied(f"{ident.display} holds no global administrator permission")

    def _dc_project(self, ctx: Context, t: Target, ident: Identity) -> Decision:
        need = t.action.level
        if t.action.create_repo:
            need = DC_REPO_CREATE_LEVEL
        g, exists, err = self.dc_project_level(ctx, t.project, ident, need)
        if err is not None:
            if not exists and httpx.status(err) == 404:
                return unknown_decision(Code.RESOURCE_NOT_VISIBLE, f"project {t.project} does not exist or hallpass cannot see it")
            raise classify(err, "read the permissions of project " + t.project)
        return dc_decide(g, need, ident, t)

    def _dc_repo(self, ctx: Context, t: Target, ident: Identity) -> Decision:
        def repo_rec(v: Any) -> bool:
            d = jsonx.obj(v, "repository")
            jsonx.s(d, "slug")
            return jsonx.b(d, "public")

        base = DC_API + "/projects/" + httpx.path_escape(t.project) + "/repos/" + httpx.path_escape(t.repo)
        try:
            public = self.get_json(ctx, base, None, repo_rec)
        except Exception as e:  # noqa: BLE001 - classified or re-raised
            if httpx.status(e) == 404:
                return unknown_decision(Code.RESOURCE_NOT_VISIBLE, f"{t} does not exist or hallpass cannot see it")
            raise classify(e, "read " + str(t))
        need = t.action.level
        try:
            g = self.dc_grants(ctx, base, ident)
        except Exception as e:  # noqa: BLE001 - classified or re-raised
            raise classify(e, "read the permissions of " + str(t))
        if public and g.level < Level.READ:
            g.level, g.how = Level.READ, "public repository"
        if g.level < need:
            p, _, err = self.dc_project_level(ctx, t.project, ident, need)
            if err is not None:
                raise classify(err, "read the permissions of project " + t.project)
            if p.level > g.level:
                g.level, g.how = p.level, p.how + " on project " + t.project
            g.unresolved.extend(p.unresolved)
        d = dc_decide(g, need, ident, t)
        if d.code != Code.ALLOWED or t.branch == "":
            return d
        return self._dc_branch(ctx, t, ident, g)

    def _dc_branch(self, ctx: Context, t: Target, ident: Identity, g: GrantSet) -> Decision:
        """Evaluate the ref restrictions on the branch for a user who has
        write. read-only stops pushes and merges, pull-request-only stops
        direct pushes; the listed users and groups are exempt."""
        blocking = {"read-only"}
        if t.action.branch == "push":
            blocking.add("pull-request-only")
        matching: list[_DCRestriction] = []
        unsup: list[str] = []
        seen: set[int] = set()
        # Restrictions set on the project apply to every repository in it,
        # so both levels are read; a restriction listed twice counts once.
        project = "/rest/branch-permissions/2.0/projects/" + httpx.path_escape(t.project)

        def collect(values: list[Any]) -> None:
            for raw in values:
                try:
                    r = _dc_restriction(raw)
                except ValueError as e:
                    raise wrap_error(Code.UPSTREAM_ERROR, e, "Bitbucket returned an unreadable restriction")
                if r.type not in blocking or (r.id != 0 and r.id in seen):
                    continue
                seen.add(r.id)
                if r.matcher_type == "ANY_REF":
                    matching.append(r)
                elif r.matcher_type == "BRANCH":
                    if r.matcher_display_id == t.branch or r.matcher_id == "refs/heads/" + t.branch:
                        matching.append(r)
                elif r.matcher_type == "PATTERN":
                    matched, ok = ref_match(r.matcher_id, t.branch, True)
                    if not ok:
                        unsup.append("pattern " + go_quote(r.matcher_id))
                    elif matched:
                        matching.append(r)
                else:
                    # MODEL_BRANCH and MODEL_CATEGORY name branches through
                    # the branching model, which hallpass does not read.
                    unsup.append("branching model matcher " + r.matcher_type)

        try:
            self.dc_list(ctx, project + "/repos/" + httpx.path_escape(t.repo) + "/restrictions", None, collect)
            self.dc_list(ctx, project + "/restrictions", None, collect)
        except Exception as e:  # noqa: BLE001 - classified or re-raised
            if httpx.status(e) == 404:
                return unknown_decision(Code.RESOURCE_NOT_VISIBLE, f"the branch permissions of {t} are not visible to hallpass")
            raise classify(e, "read the branch permissions")
        verb = "merge into" if t.action.branch == "merge" else "push to"
        for r in matching:
            exempt = any(u.name == ident.id for u in r.users) or any(grp in ident.groups for grp in r.groups)
            if exempt:
                continue
            if r.groups and ident.attr("groups") == "unavailable":
                return unsupported(
                    f"a {r.type} restriction on {r.matcher_display_id} exempts group {', '.join(r.groups)} "
                    f"and hallpass could not list the groups of {ident.display}"
                )
            return denied(f"a {r.type} restriction on {r.matcher_display_id} stops {ident.display} from {verb} {t.branch}")
        if unsup:
            return unsupported(f"branch permissions on {t.project + '/' + t.repo} use {', '.join(unsup)}, which hallpass cannot evaluate for branch {t.branch}")
        return allowed(f"{ident.display} {describe_level(g.level, t.action.level)} on {t}: {g.how}, and no branch permission stops {t.branch}")

    # -- probe --

    def dc_probe(self, ctx: Context) -> ProbeResult:
        def props(v: Any) -> tuple[str, str]:
            d = jsonx.obj(v, "properties")
            return jsonx.s(d, "version"), jsonx.s(d, "displayName")

        try:
            version, display = self.get_json(ctx, DC_API + "/application-properties", None, props)
        except Exception as e:  # noqa: BLE001 - classified or re-raised
            raise classify(e, "read the application properties")
        try:
            self.get_json(ctx, DC_API + "/users", {"limit": "1"}, None)
        except Exception as e:  # noqa: BLE001 - classified or re-raised
            raise classify(e, "list users")
        warnings: list[str] = []
        try:
            self.get_json(ctx, DC_API + "/admin/permissions/users", {"limit": "1"}, None)
        except Exception as e:  # noqa: BLE001 - classified or re-raised
            if httpx.status(e) in (403, 401):
                warnings.append("the token lacks ADMIN: global administrators cannot be recognised and workspace.admin answers unknown")
            else:
                raise classify(e, "read the global permissions")
        warnings.append(
            "repository and project permission listings need REPO_ADMIN or PROJECT_ADMIN on each object, or a global ADMIN token; "
            "objects the token lacks it on answer unknown"
        )
        return ProbeResult(summary=f"{display} {version} at {self.api.base}: the token authenticates", warnings=tuple(warnings))
