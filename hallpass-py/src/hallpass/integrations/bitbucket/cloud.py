"""Bitbucket Cloud (api.bitbucket.org/2.0). Every resource belongs to the
connection's workspace. (Go: internal/integrations/bitbucket/cloud.go.)"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, TypeVar

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
from hallpass.integrations.bitbucket.actions import BBAction, Level, Target, describe_level, ref_match
from hallpass.integrations.bitbucket.common import Base, classify, empty_struct, equal_fold
from hallpass.net import httpx

T = TypeVar("T")


@dataclass(frozen=True)
class CloudUser:
    """The user object as the workspace endpoints return it."""

    account_id: str = ""
    uuid: str = ""
    nickname: str = ""
    display_name: str = ""
    email: str = ""


def cloud_user(v: Any) -> CloudUser:
    d = jsonx.obj(v, "cloudUser")
    return CloudUser(jsonx.s(d, "account_id"), jsonx.s(d, "uuid"), jsonx.s(d, "nickname"), jsonx.s(d, "display_name"), jsonx.s(d, "email"))


def _cloud_page(v: Any, decode: Callable[[Any], T]) -> tuple[list[T], str]:
    """The pagination envelope of every Cloud list: values and next."""
    d = jsonx.obj(v, "cloudPage")
    return [decode(x) for x in jsonx.arr(d, "values")], jsonx.s(d, "next")


def decode_each(values: list[Any], decode: Callable[[Any], T], fn: Callable[[T], None]) -> None:
    """Decode every raw value and call fn."""
    for raw in values:
        try:
            v = decode(raw)
        except ValueError as e:
            raise wrap_error(Code.UPSTREAM_ERROR, e, "Bitbucket returned an unreadable entry")
        fn(v)


def same_user(u: CloudUser, ident: Identity) -> bool:
    """A Cloud user object against the identity, by account id or UUID."""
    return u.account_id == ident.id or (u.uuid != "" and u.uuid == ident.attr("uuid"))


@dataclass(frozen=True)
class _CloudProjectLevel:
    """An explicit project permission."""

    level: Level = Level.NONE
    create_repo: bool = False

    def satisfies(self, a: BBAction) -> bool:
        if a.create_repo:
            return self.create_repo
        return self.level >= a.level


def parse_cloud_project_permission(p: str) -> _CloudProjectLevel:
    if p == "admin":
        return _CloudProjectLevel(Level.ADMIN, True)
    if p == "create-repo":
        return _CloudProjectLevel(Level.WRITE, True)
    if p == "write":
        return _CloudProjectLevel(Level.WRITE, False)
    if p == "read":
        return _CloudProjectLevel(Level.READ, False)
    return _CloudProjectLevel()


def none_or(p: str) -> str:
    return "none" if p == "" else p


def parse_cloud_level(p: str) -> Level:
    if p == "admin":
        return Level.ADMIN
    if p == "write":
        return Level.WRITE
    if p == "read":
        return Level.READ
    return Level.NONE


@dataclass(frozen=True)
class _CloudRestriction:
    """One branch restriction."""

    kind: str
    branch_match_kind: str
    branch_type: str
    pattern: str
    users: tuple[CloudUser, ...]
    groups: tuple[str, ...]  # slugs


def _cloud_restriction(v: Any) -> _CloudRestriction:
    d = jsonx.obj(v, "cloudRestriction")
    return _CloudRestriction(
        jsonx.s(d, "kind"),
        jsonx.s(d, "branch_match_kind"),
        jsonx.s(d, "branch_type"),
        jsonx.s(d, "pattern"),
        tuple(cloud_user(u) for u in jsonx.arr(d, "users")),
        tuple(jsonx.s(jsonx.obj(g, "group"), "slug") for g in jsonx.arr(d, "groups")),
    )


def _permission_user(v: Any) -> tuple[str, CloudUser]:
    """{permission, user}: a workspace membership or a repository grant."""
    d = jsonx.obj(v, "grant")
    return jsonx.s(d, "permission"), cloud_user(d.get("user"))


class CloudMixin(Base):
    """The Cloud half of the connection."""

    def cloud_list(self, ctx: Context, path: str, q: dict[str, str] | None, each: Callable[[list[Any]], None]) -> None:
        """Read every page of a Cloud list and hand each page's values to
        each. Pages are followed through the body's next URL, which must
        stay under the API base."""

        def page(resp: httpx.Response) -> httpx.Request | None:
            try:
                values, nxt = _cloud_page(resp.json(), lambda x: x)
            except ValueError as e:
                raise wrap_error(Code.UPSTREAM_ERROR, e, "Bitbucket returned an unreadable page")
            each(values)
            if nxt == "":
                return None
            if not self.api.within(nxt):
                raise errorf(Code.UPSTREAM_ERROR, "Bitbucket sent a next page outside its API")
            return httpx.Request(path=nxt)

        self.api.paginate(ctx, httpx.Request(path=path, query=q), page)

    # -- identity --

    def cloud_identity(self, ctx: Context, email: str) -> Identity:
        """Find the workspace member with the email. Only a workspace
        administrator, an integration or a workspace access token may filter
        members by email."""
        # is_email admits no quote, so the address cannot escape the IN list.
        q = {
            "q": 'user.email IN ("' + email + '")',
            "fields": "values.user.email,values.user.account_id,values.user.uuid,values.user.nickname,values.user.display_name,next",
        }
        try:
            members, _ = self.get_json(
                ctx,
                "/2.0/workspaces/" + httpx.path_escape(self.workspace) + "/members",
                q,
                lambda v: _cloud_page(v, lambda x: cloud_user(jsonx.obj(x, "member").get("user"))),
            )
        except Exception as e:  # noqa: BLE001 - classified or re-raised
            if httpx.status(e) == 404:
                raise wrap_error(Code.CREDENTIAL_REJECTED, e, f"workspace {self.workspace} is not visible to hallpass's token")
            raise classify(e, "list the workspace members")
        matches = [u for u in members if equal_fold(u.email, email)]
        if not matches:
            raise user_not_found(f"no member of workspace {self.workspace} has email {email}")
        if len(matches) > 1:
            raise user_ambiguous(f"{len(matches)} members of workspace {self.workspace} have email {email}")
        u = matches[0]
        if u.account_id == "":
            raise errorf(Code.UPSTREAM_ERROR, f"the member record for {email} carries no account id")
        display = u.nickname or email
        return Identity(id=u.account_id, display=display, attrs={"uuid": u.uuid, "email": email})

    # -- checks --

    def cloud_check(self, ctx: Context, t: Target, ident: Identity) -> Decision:
        if t.action.resource == "workspace":
            return self._cloud_workspace(ctx, t, ident)
        if t.action.resource == "project":
            return self._cloud_project(ctx, t, ident)
        return self._cloud_repo(ctx, t, ident)

    def cloud_is_owner(self, ctx: Context, ident: Identity) -> bool:
        """Whether the user is a workspace owner."""
        owner = False

        def seen(m: tuple[str, CloudUser]) -> None:
            nonlocal owner
            if m[0] == "owner" and same_user(m[1], ident):
                owner = True

        try:
            self.cloud_list(
                ctx,
                "/2.0/workspaces/" + httpx.path_escape(self.workspace) + "/permissions",
                {"q": 'permission="owner"', "pagelen": "100"},
                lambda values: decode_each(values, _permission_user, seen),
            )
        except Exception as e:  # noqa: BLE001 - classified or re-raised
            raise classify(e, "list the workspace owners")
        return owner

    def _cloud_workspace(self, ctx: Context, t: Target, ident: Identity) -> Decision:
        if t.action.role == "member":
            try:
                self.get_json(ctx, "/2.0/workspaces/" + httpx.path_escape(self.workspace) + "/members/" + httpx.path_escape(ident.id), None, None)
            except Exception as e:  # noqa: BLE001 - classified or re-raised
                if httpx.status(e) == 404:
                    return denied(f"{ident.display} is not a member of workspace {self.workspace}")
                raise classify(e, "read the membership")
            return allowed(f"{ident.display} is a member of workspace {self.workspace}")
        if self.cloud_is_owner(ctx, ident):
            return allowed(f"{ident.display} is an owner of workspace {self.workspace}")
        return denied(f"{ident.display} is not an owner of workspace {self.workspace}")

    def _cloud_project(self, ctx: Context, t: Target, ident: Identity) -> Decision:
        base = "/2.0/workspaces/" + httpx.path_escape(self.workspace) + "/projects/" + httpx.path_escape(t.project)
        try:
            is_private = self.get_json(ctx, base, None, lambda v: _opt_bool_field(v, "is_private"))
        except Exception as e:  # noqa: BLE001 - classified or re-raised
            if httpx.status(e) == 404:
                return unknown_decision(
                    Code.RESOURCE_NOT_VISIBLE, f"project {t.project} does not exist in workspace {self.workspace} or hallpass cannot see it"
                )
            raise classify(e, "read project " + t.project)
        direct = ""
        try:
            direct = self.get_json(ctx, base + "/permissions-config/users/" + httpx.path_escape(ident.id), None, lambda v: jsonx.s(jsonx.obj(v), "permission"))
        except Exception as e:  # noqa: BLE001 - classified or re-raised
            if httpx.status(e) != 404:
                raise classify(e, "read the project permissions")
        need = str(t.action.level)
        if t.action.create_repo:
            need = "create-repo"
        if parse_cloud_project_permission(direct).satisfies(t.action):
            return allowed(f"{ident.display} has {direct} on project {t.project} directly (needs {need})")
        if t.action.level == Level.READ and not t.action.create_repo and is_private is not None and not is_private:
            return allowed(f"project {t.project} is public, so {ident.display} can read it")
        if self.cloud_is_owner(ctx, ident):
            return allowed(f"{ident.display} is an owner of workspace {self.workspace}, which carries admin on project {t.project}")
        # Group grants: Cloud's API exposes no group membership, so a group
        # that would suffice makes the answer unknown rather than deny.
        groups: list[str] = []

        def grant(g: tuple[str, str]) -> None:
            if parse_cloud_project_permission(g[0]).satisfies(t.action):
                groups.append(g[1])

        def group_grant(v: Any) -> tuple[str, str]:
            d = jsonx.obj(v, "groupGrant")
            return jsonx.s(d, "permission"), jsonx.s(jsonx.o(d, "group"), "slug")

        try:
            self.cloud_list(ctx, base + "/permissions-config/groups", {"pagelen": "100"}, lambda values: decode_each(values, group_grant, grant))
        except Exception as e:  # noqa: BLE001 - classified or re-raised
            raise classify(e, "read the project group permissions")
        if groups:
            return unsupported(
                f"group {', '.join(groups)} grants {need} on project {t.project} and Bitbucket Cloud does not tell hallpass who is in it; "
                f"{ident.display} has {none_or(direct)} directly"
            )
        return denied(f"{ident.display} has {none_or(direct)} on project {t.project}, needs {need}")

    def cloud_repo_level(self, ctx: Context, slug: str, ident: Identity) -> Level:
        """The user's effective permission on the repository: the highest of
        direct, group and project grants, as Bitbucket computes it. The list
        is filtered by account id; a Bitbucket that rejects the filter is
        read whole."""
        path = "/2.0/workspaces/" + httpx.path_escape(self.workspace) + "/permissions/repositories/" + httpx.path_escape(slug)
        found = Level.NONE

        def seen(g: tuple[str, CloudUser]) -> None:
            nonlocal found
            if same_user(g[1], ident):
                lv = parse_cloud_level(g[0])
                if lv > found:
                    found = lv

        def read(q: dict[str, str]) -> None:
            self.cloud_list(ctx, path, q, lambda values: decode_each(values, _permission_user, seen))

        # UNVERIFIED: the filter grammar for a single user; the spec says the
        # list "may be filtered by user" and documents q=permission>"read".
        try:
            read({"q": 'user.account_id="' + ident.id + '"', "pagelen": "100"})
        except Exception as e:
            if httpx.status(e) != 400:
                raise
            read({"pagelen": "100"})
        return found

    def _cloud_repo(self, ctx: Context, t: Target, ident: Identity) -> Decision:
        """Answer a repository question."""

        def repo_rec(v: Any) -> bool | None:
            d = jsonx.obj(v, "repository")
            jsonx.s(jsonx.o(d, "project"), "key")
            return _opt_bool_field(d, "is_private")

        repo_path = "/2.0/repositories/" + httpx.path_escape(self.workspace) + "/" + httpx.path_escape(t.repo)
        try:
            is_private = self.get_json(ctx, repo_path, None, repo_rec)
        except Exception as e:  # noqa: BLE001 - classified or re-raised
            if httpx.status(e) == 404:
                return unknown_decision(
                    Code.RESOURCE_NOT_VISIBLE, f"repository {t.repo} does not exist in workspace {self.workspace} or hallpass cannot see it"
                )
            raise classify(e, "read repository " + t.repo)
        try:
            have = self.cloud_repo_level(ctx, t.repo, ident)
        except Exception as e:  # noqa: BLE001 - classified or re-raised
            if httpx.status(e) == 404:
                return unknown_decision(Code.RESOURCE_NOT_VISIBLE, f"the permissions of repository {t.repo} are not visible to hallpass")
            raise classify(e, "read the repository permissions")
        how = "effective permission"
        if have == Level.NONE:
            if self.cloud_is_owner(ctx, ident):
                have, how = Level.ADMIN, "workspace owner"
            elif is_private is not None and not is_private:
                have, how = Level.READ, "public repository"
        need = t.action.level
        if have < need:
            return denied(f"{ident.display} {describe_level(have, need)} on {t} ({how})")
        if t.branch == "":
            return allowed(f"{ident.display} {describe_level(have, need)} on {t} ({how})")
        return self._cloud_branch(ctx, t, ident, have, how)

    def _cloud_branch(self, ctx: Context, t: Target, ident: Identity, have: Level, how: str) -> Decision:
        """Evaluate the push or merge restrictions on the branch for a user
        who already has write."""
        kind = "restrict_merges" if t.action.branch == "merge" else "push"
        matching: list[_CloudRestriction] = []
        unsup: list[str] = []

        def seen(r: _CloudRestriction) -> None:
            if r.kind != kind:
                return
            if r.branch_match_kind == "branching_model":
                # Which branches are "production" or "release" is the
                # repository's branching model, which hallpass does not read.
                unsup.append("branching model " + r.branch_type)
                return
            matched, ok = ref_match(r.pattern, t.branch, False)
            if not ok:
                unsup.append("pattern " + go_quote(r.pattern))
            elif matched:
                matching.append(r)

        path = "/2.0/repositories/" + httpx.path_escape(self.workspace) + "/" + httpx.path_escape(t.repo) + "/branch-restrictions"
        try:
            self.cloud_list(ctx, path, {"kind": kind, "pagelen": "100"}, lambda values: decode_each(values, _cloud_restriction, seen))
        except Exception as e:
            if is_panic_type(e):
                raise
            if httpx.status(e) == 404:
                return unknown_decision(Code.RESOURCE_NOT_VISIBLE, f"the branch restrictions of repository {t.repo} are not visible to hallpass")
            raise classify(e, "read the branch restrictions")
        verb = "push to" if kind == "push" else "merge into"
        for r in matching:
            if any(same_user(u, ident) for u in r.users):
                continue
            if r.groups:
                return unsupported(
                    f"a {kind} restriction on {go_quote(r.pattern)} matches {t.branch} and exempts group {', '.join(r.groups)}, "
                    f"whose members Bitbucket Cloud does not tell hallpass; {ident.display} is not exempted by name"
                )
            return denied(f"a {kind} restriction on {go_quote(r.pattern)} stops {ident.display} from {verb} {t.branch} (only the listed users may)")
        if unsup:
            return unsupported(f"{kind} restrictions on {t.repo} use {', '.join(unsup)}, which hallpass cannot evaluate for branch {t.branch}")
        return allowed(f"{ident.display} {describe_level(have, t.action.level)} on {t} ({how}) and no {kind} restriction stops {t.branch}")

    # -- probe --

    def cloud_probe(self, ctx: Context) -> ProbeResult:
        try:
            slug = self.get_json(ctx, "/2.0/workspaces/" + httpx.path_escape(self.workspace), None, lambda v: jsonx.s(jsonx.obj(v), "slug"))
        except Exception as e:  # noqa: BLE001 - classified or re-raised
            if httpx.status(e) == 404:
                raise wrap_error(Code.CREDENTIAL_REJECTED, e, f"workspace {self.workspace} is not visible to hallpass's token")
            raise classify(e, "read the workspace")
        q = {"q": 'user.email IN ("probe@example.invalid")', "fields": "values.user.email,values.user.account_id"}
        try:
            self.get_json(ctx, "/2.0/workspaces/" + httpx.path_escape(self.workspace) + "/members", q, lambda v: _cloud_page(v, empty_struct))
        except Exception as e:  # noqa: BLE001 - classified or re-raised
            st = httpx.status(e)
            if st in (401, 403, 400):
                raise wrap_error(
                    Code.CREDENTIAL_REJECTED,
                    e,
                    f"the token cannot filter workspace members by email (HTTP {st}); "
                    "it must be a workspace access token or belong to a workspace administrator",
                )
            raise classify(e, "filter members by email")
        return ProbeResult(
            summary=f"workspace {slug}: members can be looked up by email",
            warnings=(
                "repository permissions and branch restrictions are readable only with admin on the repository (repository:admin scope); "
                "repositories the token lacks it on answer unknown",
                "Bitbucket Cloud exposes no group membership: a project or branch grant that comes only through a group answers unknown",
            ),
        )


def _opt_bool_field(v: Any, key: str) -> bool | None:
    d = jsonx.obj(v)
    if d.get(key) is None:
        return None
    return jsonx.b(d, key)
