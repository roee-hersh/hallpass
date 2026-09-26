"""Checks GitLab project and group permissions.

hallpass resolves the caller's email to a GitLab account (four identity
modes, see fields), reads the account's effective membership of the project
or group with the members/all endpoint, and maps the access level to the
asked action with an exact level set per action. For repo.push and mr.merge
it also reads the project's protected-branch rules: on a named branch it
evaluates them, without one it answers unknown when any exist.
The token is read-only (read_api) and nothing is written.

A port of internal/integrations/gitlab.
"""

from __future__ import annotations

import dataclasses
import datetime
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from hallpass.core import jsonx
from hallpass.core.cache import is_panic_type
from hallpass.core.catalog import Action
from hallpass.core.context import Context
from hallpass.core.decision import (
    Code,
    Decision,
    HallpassError,
    allowed,
    denied,
    errorf,
    to_decision,
    unsupported,
    user_ambiguous,
    user_not_found,
    wrap_error,
)
from hallpass.core.errors import go_quote, go_trim_space
from hallpass.core.integration import (
    CheckRequest,
    Connection,
    Deps,
    Field,
    Identity,
    Integration,
    ProbeResult,
    Settings,
    User,
    credential_field,
    url_field,
)
from hallpass.core.template import Template, email_domain, parse_email_domains, parse_template, validate_email_domains, validate_template
from hallpass.integrations.gitlab.actions import (
    ACTIONS,
    BRANCH_MERGE,
    BRANCH_PUSH,
    LEVEL_ADMIN,
    LEVEL_DEVELOPER,
    LEVEL_NONE,
    ActionSpec,
    Target,
    catalog_actions,
    level_name,
    level_names,
    match_wildcard,
    parse_target,
    validate_path,
)
from hallpass.net import httpx

__all__ = ["INTEGRATION", "GitLab", "GitLabConnection"]

DEFAULT_URL = "https://gitlab.com"
DEFAULT_TEMPLATE = "{local}"

MODE_ADMIN_SEARCH = "admin_search"
MODE_ENTERPRISE_USERS = "enterprise_users"
MODE_SAML = "saml"
MODE_TEMPLATE = "template"

# SEARCH_PER_PAGE and SEARCH_MAX_PAGES bound the admin_search listing: a
# search that fills SEARCH_MAX_PAGES pages without an exact match answers
# unknown rather than user_not_found.
SEARCH_PER_PAGE = 100
SEARCH_MAX_PAGES = 5

# The account states GitLab uses for accounts that may not sign in. Any
# other non-active state is not evaluable.
INACTIVE_STATES = frozenset({"blocked", "deactivated", "ldap_blocked", "banned", "blocked_pending_approval"})


# -- Go semantics helpers ------------------------------------------------------


def _equal_fold(a: str, b: str) -> bool:
    """Go's strings.EqualFold: rune by rune under simple case folding."""
    if a == b:
        return True
    if len(a) != len(b):
        return False
    for x, y in zip(a, b, strict=True):
        if x == y:
            continue
        xl, yl, xu, yu = x.lower(), y.lower(), x.upper(), y.upper()
        if len(xl) == 1 and xl == yl:
            continue
        if len(xu) == 1 and xu == yu:
            continue
        return False
    return True


_INT64_MIN, _INT64_MAX = -(1 << 63), (1 << 63) - 1


def _i64(d: dict[str, Any], key: str) -> int:
    """An int64 struct field: out of range is a decode error."""
    v = jsonx.i(d, key)
    if not _INT64_MIN <= v <= _INT64_MAX:
        raise jsonx.DecodeError(f"json: cannot unmarshal number {v} into field {key} of type int64")
    return v


def _opt_bool(d: dict[str, Any], key: str) -> bool | None:
    """A *bool struct field: null or missing is None."""
    if d.get(key) is None:
        return None
    return jsonx.b(d, key)


def _list(v: Any, what: str) -> list[Any]:
    """A top-level JSON array decoded into a Go slice: null is empty."""
    if v is None:
        return []
    if not isinstance(v, list):
        raise jsonx.DecodeError(f"json: cannot unmarshal {type(v).__name__} into Go value of type []{what}")
    return v


_PARSE_INT = re.compile(r"[+-]?[0-9]+")


def _parse_int64(s: str) -> int:
    """strconv.ParseInt(s, 10, 64) with the error ignored: 0 for a syntax
    error, the value of largest magnitude for a range error."""
    if not _PARSE_INT.fullmatch(s):
        return 0
    v = int(s)
    return max(_INT64_MIN, min(_INT64_MAX, v))


def _fmt_bool(b: bool) -> str:
    return "true" if b else "false"


# -- decoded records -----------------------------------------------------------


@dataclass(frozen=True)
class _SecondaryEmail:
    """One entry of a user's emails array. confirmed reports whether the
    entry may be trusted: true when confirmed_at is absent or non-null,
    false when it is present and null."""

    email: str
    confirmed: bool


def _secondary_email(v: Any) -> _SecondaryEmail:
    # UNVERIFIED: that a user record of the search listing carries an
    # "emails" array, and its shape; both a bare string and an object with
    # "email" and "confirmed_at" are accepted.
    if v is None or isinstance(v, str):
        # Go: json.Unmarshal into a string accepts a string or null.
        return _SecondaryEmail(v or "", True)
    if not isinstance(v, dict):
        raise jsonx.DecodeError(f"json: cannot unmarshal {type(v).__name__} into Go value of type map[string]json.RawMessage")
    email = ""
    if "email" in v:
        raw = v["email"]
        if raw is not None and not isinstance(raw, str):
            raise jsonx.DecodeError(f"emails[].email: json: cannot unmarshal {type(raw).__name__} into Go value of type string")
        email = raw or ""
    confirmed = not ("confirmed_at" in v and v["confirmed_at"] is None)
    return _SecondaryEmail(email, confirmed)


@dataclass(frozen=True)
class _User:
    """The subset of a GitLab user record hallpass reads. email, is_admin,
    external and emails are present only for administrators' tokens."""

    id: int = 0
    username: str = ""
    state: str = ""
    email: str = ""
    public_email: str = ""
    bot: bool = False
    is_admin: bool | None = None
    external: bool | None = None
    # The account's secondary emails.
    emails: tuple[_SecondaryEmail, ...] = ()

    def identity(self) -> Identity:
        attrs = {"state": self.state, "username": self.username, "bot": _fmt_bool(self.bot)}
        if self.is_admin is not None:
            attrs["is_admin"] = _fmt_bool(self.is_admin)
        if self.external is not None:
            attrs["external"] = _fmt_bool(self.external)
        return Identity(id=str(self.id), display=self.username, attrs=attrs)


def _user(v: Any) -> _User:
    d = jsonx.obj(v, "user")
    return _User(
        id=_i64(d, "id"),
        username=jsonx.s(d, "username"),
        state=jsonx.s(d, "state"),
        email=jsonx.s(d, "email"),
        public_email=jsonx.s(d, "public_email"),
        bot=jsonx.b(d, "bot"),
        is_admin=_opt_bool(d, "is_admin"),
        external=_opt_bool(d, "external"),
        emails=tuple(_secondary_email(e) for e in jsonx.arr(d, "emails")),
    )


def _users(v: Any) -> list[_User]:
    return [_user(u) for u in _list(v, "gitlab.user")]


@dataclass
class _Membership:
    """The effective membership of a user in a project or group."""

    found: bool = False
    level: int = 0
    state: str = ""
    # The custom role name when the membership has one.
    custom_role: str = ""
    custom_role_id: int = 0


@dataclass(frozen=True)
class _MemberRecord:
    access_level: int
    state: str
    member_role: tuple[int, str] | None


def _member_record(v: Any) -> _MemberRecord:
    d = jsonx.obj(v, "memberRecord")
    mr: tuple[int, str] | None = None
    if d.get("member_role") is not None:
        r = jsonx.o(d, "member_role")
        mr = (_i64(r, "id"), jsonx.s(r, "name"))
    return _MemberRecord(_i64(d, "access_level"), jsonx.s(d, "state"), mr)


@dataclass(frozen=True)
class _Resource:
    """What hallpass reads of a project or group record."""

    visibility: str = ""
    # "disabled", "private" or "enabled" on projects.
    issues_access_level: str = ""
    # The older boolean form of the same setting.
    issues_enabled: bool | None = None

    def issues_disabled(self) -> bool:
        """Whether the project has the issues feature off."""
        return self.issues_access_level == "disabled" or (self.issues_enabled is not None and not self.issues_enabled)


def _resource(v: Any) -> _Resource:
    d = jsonx.obj(v, "resource")
    return _Resource(jsonx.s(d, "visibility"), jsonx.s(d, "issues_access_level"), _opt_bool(d, "issues_enabled"))


@dataclass(frozen=True)
class _AccessEntry:
    """One "allowed to push/merge" entry of a protected branch."""

    access_level: int = 0
    user_id: int = 0
    group_id: int = 0
    member_role_id: int = 0
    deploy_key_id: int = 0


def _access_entry(v: Any) -> _AccessEntry:
    d = jsonx.obj(v, "accessEntry")
    return _AccessEntry(_i64(d, "access_level"), _i64(d, "user_id"), _i64(d, "group_id"), _i64(d, "member_role_id"), _i64(d, "deploy_key_id"))


@dataclass(frozen=True)
class _ProtectedBranch:
    name: str = ""
    push_access_levels: tuple[_AccessEntry, ...] = ()
    merge_access_levels: tuple[_AccessEntry, ...] = ()


def _protected_branch(v: Any) -> _ProtectedBranch:
    d = jsonx.obj(v, "protectedBranch")
    return _ProtectedBranch(
        jsonx.s(d, "name"),
        tuple(_access_entry(e) for e in jsonx.arr(d, "push_access_levels")),
        tuple(_access_entry(e) for e in jsonx.arr(d, "merge_access_levels")),
    )


# -- the integration -------------------------------------------------------------


def validate_group(v: str) -> None:
    if v == "":
        return
    validate_path(v)


class GitLab(Integration):
    """The gitlab product."""

    def name(self) -> str:
        return "gitlab"

    def fields(self) -> list[Field]:
        u = dataclasses.replace(url_field(False, "GitLab URL, default https://gitlab.com; the API is used at {url}/api/v4"), default=DEFAULT_URL)
        return [
            u,
            credential_field(
                True, "personal access token with the read_api scope: an administrator's on self-managed, a top-level group Owner's on GitLab.com"
            ),
            Field(
                name="identity_mode",
                default=MODE_ADMIN_SEARCH,
                enum=(MODE_ADMIN_SEARCH, MODE_ENTERPRISE_USERS, MODE_SAML, MODE_TEMPLATE),
                description="how the email is mapped to an account: admin_search (GET /users?search, needs an administrator's token), enterprise_users "
                "(GitLab.com enterprise users of the group), saml (the group's SAML identities, NameID must be the email), "
                "template (username derived with username_template)",
            ),
            Field(name="group", validate=validate_group, description="top-level group path; required for identity_mode enterprise_users and saml"),
            Field(
                name="username_template",
                default=DEFAULT_TEMPLATE,
                validate=validate_template,
                description="username derivation for identity_mode template: placeholders {email}, {local}, {domain}, default {local}",
            ),
            Field(
                name="email_domains",
                validate=validate_email_domains,
                description="comma-separated email domains (acme.com,acme.io) whose users may be mapped by identity_mode template; required in that "
                "mode, any other domain answers unknown",
            ),
        ]

    def actions(self) -> list[Action]:
        return catalog_actions()

    def new(self, ctx: Context, s: Settings, d: Deps) -> Connection:
        """Build a connection. It does not touch the network."""
        hc = d.http_client(s)
        cred = s.secret("credential")
        if cred.is_zero():
            raise ValueError("credential is required")
        mode = s.get("identity_mode") or MODE_ADMIN_SEARCH
        if mode not in (MODE_ADMIN_SEARCH, MODE_ENTERPRISE_USERS, MODE_SAML, MODE_TEMPLATE):
            raise ValueError(f"identity_mode {go_quote(mode)} is not one of admin_search, enterprise_users, saml, template")
        group = s.get("group")
        if mode in (MODE_ENTERPRISE_USERS, MODE_SAML) and group == "":
            raise ValueError(f"group is required when identity_mode is {mode}")
        try:
            validate_group(group)
        except ValueError as e:
            raise ValueError(f"group: {e}")
        tpl_text = s.get("username_template") or DEFAULT_TEMPLATE
        try:
            tpl = parse_template(tpl_text)
        except ValueError as e:
            raise ValueError(f"username_template: {e}")
        domains: frozenset[str] = frozenset()
        raw = s.get("email_domains")
        if raw != "":
            try:
                domains = frozenset(parse_email_domains(raw))
            except ValueError as e:
                raise ValueError(f"email_domains: {e}")
        if mode == MODE_TEMPLATE and not domains:
            raise ValueError(
                "email_domains is required when identity_mode is template: the template maps any email's local part to an account, so the domains that "
                "may be mapped must be listed"
            )
        base = s.get("url") or DEFAULT_URL
        client = httpx.Client(
            http=hc,
            base=base.rstrip("/") + "/api/v4",
            logger=d.logger,
            auth=httpx.header_auth("PRIVATE-TOKEN", lambda _ctx: cred.get_string()),
        )
        return GitLabConnection(client, mode, group, tpl, domains, d.now or time.time)


@dataclass
class GitLabConnection(Connection):
    """One GitLab instance (gitlab.com or self-managed)."""

    client: httpx.Client
    mode: str
    group: str
    template: Template
    # The email_domains allow-list (template mode), lowercase.
    domains: frozenset[str] = field(default_factory=frozenset)
    now: Callable[[], float] = time.time

    def _domain_allowed(self, email: str) -> bool:
        """Whether the email's domain is in email_domains."""
        d = email_domain(email)
        return d != "" and d in self.domains

    def username(self, email: str) -> str:
        """The template applied to an email (identity_mode template)."""
        return self.template.render(email)

    def _get(self, ctx: Context, path: str, q: dict[str, str] | None, decode: Callable[[Any], Any]) -> Any:
        """GetJSON into a typed value: a decode failure is an error of the
        call, as it is in Go."""
        _, v = self.client.get_json(ctx, path, q)
        try:
            return decode(v)
        except ValueError as e:
            raise ValueError(f"decode {path}: {e}") from e

    # -- identity --

    def resolve_identity(self, ctx: Context, u: User) -> Identity:
        """Map the email to a GitLab account by the configured mode."""
        email = go_trim_space(u.email)
        if email == "" or any(c in email for c in " \t\r\n"):
            raise errorf(Code.INVALID_REQUEST, "email is empty or contains whitespace")
        if self.mode == MODE_ADMIN_SEARCH:
            found = self._admin_search(ctx, email)
        elif self.mode == MODE_ENTERPRISE_USERS:
            found = self._enterprise_user(ctx, email)
        elif self.mode == MODE_SAML:
            found = self._saml_identity(ctx, email)
        elif self.mode == MODE_TEMPLATE:
            if not self._domain_allowed(email):
                raise errorf(Code.UNSUPPORTED, f"domain not allowed for template identities: {email} is not in email_domains")
            found = self._by_username(ctx, self.username(email))
            # The template only guesses a username; when the account's email
            # is visible it must be the caller's, else the guess is wrong.
            if found.email != "" and not _equal_fold(found.email, email):
                raise user_not_found(f"the account {found.username} derived from {email} has a different email")
        else:
            raise RuntimeError(f"unreachable: identity_mode {go_quote(self.mode)}")
        return found.identity()

    def _admin_search(self, ctx: Context, email: str) -> _User:
        """List GET /users?search=<email> page by page (SEARCH_PER_PAGE per
        page, at most SEARCH_MAX_PAGES pages) and pick the exact match. The
        search is fuzzy on GitLab's side, so a common local part can return
        more candidates than hallpass will read; then the answer is unknown."""
        users: list[_User] = []
        full = True
        page = 1
        while page <= SEARCH_MAX_PAGES and full:
            q = {"search": email, "per_page": str(SEARCH_PER_PAGE), "page": str(page)}
            try:
                batch = self._get(ctx, "/users", q, _users)
            except Exception as e:  # noqa: BLE001
                raise self._classify(e, "search users")
            users.extend(batch)
            full = len(batch) >= SEARCH_PER_PAGE
            page += 1
        try:
            return _match_email(
                users,
                email,
                "the token's user is not an administrator, so private emails are not searchable; use an administrator's token or another identity_mode",
            )
        except HallpassError as e:
            if full and to_decision(e).code == Code.USER_NOT_FOUND:
                raise errorf(
                    Code.UNSUPPORTED,
                    f"too many candidates: the search for {email} filled {SEARCH_MAX_PAGES} pages of {SEARCH_PER_PAGE} users without an exact match",
                )
            raise

    def _enterprise_user(self, ctx: Context, email: str) -> _User:
        path = "/groups/" + httpx.path_escape(self.group) + "/enterprise_users"
        try:
            users = self._get(ctx, path, {"search": email, "per_page": "100"}, _users)
        except Exception as e:  # noqa: BLE001
            raise self._classify_group(e, "list enterprise users of")
        return _match_email(users, email, "the enterprise users of group " + self.group + " carry no email; the token must belong to an Owner of the group")

    def _saml_identity(self, ctx: Context, email: str) -> _User:
        matches: list[int] = []
        req = httpx.Request(method="GET", path="/groups/" + httpx.path_escape(self.group) + "/saml/identities", query={"per_page": "100"})

        def page(resp: httpx.Response) -> httpx.Request | None:
            try:
                items = [jsonx.obj(x, "samlIdentity") for x in _list(resp.json(), "gitlab.samlIdentity")]
                ids = [(jsonx.s(x, "extern_uid"), _i64(x, "user_id")) for x in items]
            except ValueError as e:
                raise ValueError(f"decode saml identities: {e}") from e
            for extern_uid, user_id in ids:
                if _equal_fold(extern_uid, email):
                    matches.append(user_id)
            try:
                nxt = self.client.next_link(resp.header)
            except ValueError as e:
                raise wrap_error(Code.UPSTREAM_ERROR, e, "GitLab returned a next page link outside the connection's url")
            if nxt != "":
                return httpx.Request(method="GET", path=nxt)
            return None

        try:
            self.client.paginate(ctx, req, page)
        except Exception as e:  # noqa: BLE001
            raise self._classify_group(e, "list SAML identities of")
        if not matches:
            raise user_not_found(f"no SAML identity in group {self.group} has the NameID {email}")
        if len(matches) > 1:
            raise user_ambiguous(f"{len(matches)} SAML identities in group {self.group} have the NameID {email}")
        try:
            return self._get(ctx, "/users/" + str(matches[0]), None, _user)
        except Exception as e:  # noqa: BLE001
            if httpx.status(e) == 404:
                raise user_not_found(f"SAML identity {email} points at user {matches[0]}, which no longer exists")
            raise self._classify(e, "read user")

    def _by_username(self, ctx: Context, username: str) -> _User:
        try:
            users = self._get(ctx, "/users", {"username": username}, _users)
        except Exception as e:  # noqa: BLE001
            raise self._classify(e, "look up username")
        if not users:
            raise user_not_found(f"no GitLab account has the username {username}")
        if len(users) > 1:
            raise user_ambiguous(f"{len(users)} GitLab accounts have the username {username}")
        return users[0]

    def _classify(self, err: BaseException, what: str) -> BaseException:
        """Map an error from a call the token should always be allowed to
        make. 403 means the token lacks the right."""
        if is_panic_type(err):
            return err
        if httpx.status(err) == 403:
            return wrap_error(Code.CREDENTIAL_REJECTED, err, f"the token may not {what} (HTTP 403)")
        return httpx.classify(err) or err

    def _classify_group(self, err: BaseException, what: str) -> BaseException:
        """Map an error from a group-scoped identity call."""
        if is_panic_type(err):
            return err
        st = httpx.status(err)
        if st == 403:
            return wrap_error(Code.CREDENTIAL_REJECTED, err, f"the token may not {what} group {self.group} (HTTP 403); it must belong to an Owner of the group")
        if st == 404:
            return wrap_error(Code.RESOURCE_NOT_VISIBLE, err, f"group {self.group} is not visible to the token (HTTP 404)")
        return httpx.classify(err) or err

    # -- reads --

    def _member(self, ctx: Context, scope: str, rid: str, user_id: str) -> _Membership:
        """GET /<projects|groups>/:id/members/all/:user_id. 404 means "not
        a member", or that the project or group is not visible; the caller
        tells the two apart by reading the record (see _read)."""
        path = "/" + scope + "s/" + httpx.path_escape(rid) + "/members/all/" + httpx.path_escape(user_id)
        try:
            rec = self._get(ctx, path, None, _member_record)
        except Exception as e:
            if is_panic_type(e):
                raise
            st = httpx.status(e)
            if st == 404:
                return _Membership()
            if st == 403:
                raise wrap_error(Code.CREDENTIAL_REJECTED, e, f"the token may not read the members of {scope} {rid} (HTTP 403)")
            raise (httpx.classify(e) or e)
        m = _Membership(found=True, level=rec.access_level, state=rec.state)
        if rec.member_role is not None:
            m.custom_role_id, m.custom_role = rec.member_role
            if m.custom_role == "":
                m.custom_role = "id " + str(m.custom_role_id)
        return m

    def _read(self, ctx: Context, t: Target) -> _Resource:
        """The project or group record. A 404 means the token cannot see it."""
        try:
            return self._get(ctx, "/" + t.scope + "s/" + httpx.path_escape(t.id), None, _resource)
        except Exception as e:
            if is_panic_type(e):
                raise
            st = httpx.status(e)
            if st == 404:
                raise wrap_error(Code.RESOURCE_NOT_VISIBLE, e, f"{t.scope} {t.id} is not visible to the token (HTTP 404)")
            if st == 403:
                raise wrap_error(Code.CREDENTIAL_REJECTED, e, f"the token may not read {t.scope} {t.id} (HTTP 403)")
            raise (httpx.classify(e) or e)

    # -- check --

    def check(self, ctx: Context, r: CheckRequest) -> Decision:
        """Evaluate one action against the user's effective access level."""
        spec = ACTIONS.get(r.action.name)
        if spec is None:
            raise errorf(Code.UNKNOWN_ACTION, f"gitlab has no action {go_quote(r.action.name)}")
        try:
            t = parse_target(spec, r.resource)
        except ValueError as e:
            raise errorf(Code.INVALID_REQUEST, str(e))
        who = r.identity.display
        if who == "":
            who = "user " + r.identity.id
        state = r.identity.attr("state")
        if state == "active":
            pass
        elif state == "":
            return unsupported(f"GitLab account {who} has no state in the record the token can see")
        elif state in INACTIVE_STATES:
            return denied(f"GitLab account {who} is {state}")
        else:
            return unsupported(f"GitLab account {who} is in state {go_quote(state)}, which hallpass does not know")
        if r.identity.attr("bot") == "true":
            return denied(f"GitLab account {who} is a bot account")

        m = self._member(ctx, t.scope, t.id, r.identity.id)
        if not m.found:
            return self._check_non_member(ctx, spec, t, r.identity, who)
        if m.state not in ("active", ""):
            return denied(f"the membership of {who} in {t.scope} {t.id} is {m.state}")
        role = level_name(m.level)
        if m.custom_role != "":
            role = f"custom role {go_quote(m.custom_role)} (base {level_name(m.level)})"

        if spec.branch != "":
            rules = self._protected_branches(ctx, t)
            if t.branch == "" and rules:
                # The level alone cannot answer: a protected branch may
                # restrict (Maintainers only) or widen (a named user) what
                # the level says.
                return unsupported(f"project {t.id} has {len(rules)} protected-branch rules, which decide {spec.name} per branch; add @branch to the resource")
            matched = [pb for pb in rules if match_wildcard(pb.name, t.branch)]
            if matched:
                return self._check_protected(ctx, r, spec, t, m, matched, who, role)

        if spec.grants(m.level):
            return allowed(f"{who} has {role} access to {t.scope} {t.id}, which grants {spec.name}")
        if spec.is_conditional(m.level):
            return unsupported(f"{who} has {role} access to {t.scope} {t.id}; at that level {spec.name} depends on approval rules hallpass does not evaluate")
        if m.custom_role != "":
            return unsupported(
                f"{who} has {role} on {t.scope} {t.id}; the base level does not grant {spec.name} but a custom role can add abilities hallpass cannot see"
            )
        return denied(f"{who} has {role} access to {t.scope} {t.id}; {spec.name} needs {level_names(spec.levels)}")

    def _check_non_member(self, ctx: Context, spec: ActionSpec, t: Target, ident: Identity, who: str) -> Decision:
        """Answer for an account with no membership of the project or group:
        administrators, the project's visibility and its issue settings
        decide."""
        res = self._read(ctx, t)
        vis = res.visibility
        if spec.name == "issue.create" and res.issues_disabled():
            return denied(f"issues are disabled on project {t.id}, so no one can create one")
        if ident.attr("is_admin") == "true":
            return allowed(f"{who} is an instance administrator, which grants {spec.name} on every {t.scope}")
        if spec.name == "issue.create" and res.issues_access_level == "private":
            return denied(f"{who} is not a member of project {t.id} and its issues are restricted to project members")
        if spec.grants_non_member(vis):
            if vis == "internal":
                # External users cannot see internal projects.
                ext = ident.attr("external")
                if ext == "true":
                    return denied(f"{who} is not a member of {t.scope} {t.id}, and as an external user cannot see {vis} projects")
                if ext != "false":
                    return unsupported(
                        f"{who} is not a member of {t.scope} {t.id}; the {t.scope} is {vis}, which external users cannot see, and the token cannot tell "
                        "whether the account is external"
                    )
            return allowed(f"{who} is not a member of {t.scope} {t.id}, but the {t.scope} is {vis} and {spec.name} is open to every signed-in user")
        return denied(f"{who} is not a member of {t.scope} {t.id} ({vis}); {spec.name} needs {level_names(spec.levels)}")

    def _protected_branches(self, ctx: Context, t: Target) -> list[_ProtectedBranch]:
        """The project's protected-branch rules."""
        out: list[_ProtectedBranch] = []
        req = httpx.Request(method="GET", path="/projects/" + httpx.path_escape(t.id) + "/protected_branches", query={"per_page": "100"})

        def page(resp: httpx.Response) -> httpx.Request | None:
            try:
                items = [_protected_branch(x) for x in _list(resp.json(), "gitlab.protectedBranch")]
            except ValueError as e:
                raise ValueError(f"decode protected branches: {e}") from e
            out.extend(items)
            try:
                nxt = self.client.next_link(resp.header)
            except ValueError as e:
                raise wrap_error(Code.UPSTREAM_ERROR, e, "GitLab returned a next page link outside the connection's url")
            if nxt != "":
                return httpx.Request(method="GET", path=nxt)
            return None

        try:
            self.client.paginate(ctx, req, page)
        except Exception as e:
            if is_panic_type(e):
                raise
            st = httpx.status(e)
            if st == 403:
                # UNVERIFIED: the minimum role needed to list protected branches.
                raise wrap_error(Code.CREDENTIAL_REJECTED, e, f"the token may not list the protected branches of project {t.id} (HTTP 403)")
            if st == 404:
                raise wrap_error(Code.RESOURCE_NOT_VISIBLE, e, f"project {t.id} is not visible to the token (HTTP 404)")
            raise (httpx.classify(e) or e)
        return out

    def _check_protected(
        self,
        ctx: Context,
        r: CheckRequest,
        spec: ActionSpec,
        t: Target,
        m: _Membership,
        rules: list[_ProtectedBranch],
        who: str,
        role: str,
    ) -> Decision:
        """Evaluate the matching protected-branch rules. An entry allows the
        user when it names the user, a group the user belongs to, a role
        level the user's level reaches, or Admins for a known administrator.
        The most permissive entry wins across every matching rule.
        UNVERIFIED: how GitLab combines several rules matching one branch;
        every matching rule's entries are pooled here."""
        user_id = _parse_int64(r.identity.id)
        entries: list[_AccessEntry] = []
        names: list[str] = []
        for pb in rules:
            names.append(pb.name)
            if spec.branch == BRANCH_PUSH:
                entries.extend(pb.push_access_levels)
            else:
                entries.extend(pb.merge_access_levels)
        rule = f"protected branch rule {', '.join(names)} of project {t.id}"
        verb = "merge into" if spec.branch == BRANCH_MERGE else "push to"
        anyone = False
        unresolved: list[str] = []
        for e in entries:
            if e.deploy_key_id != 0:
                # A deploy key may push, but it is never the user; the
                # entry's access_level describes the key, not a role.
                anyone = True
            elif e.user_id != 0:
                anyone = True
                if e.user_id == user_id:
                    return allowed(f"{who} may {verb} branch {t.branch}: {rule} names the user")
            elif e.group_id != 0:
                anyone = True
                try:
                    inside = self._group_has(ctx, e.group_id, r.identity.id)
                except Exception as err:
                    if is_panic_type(err):
                        raise
                    unresolved.append(f"group {e.group_id} could not be resolved")
                    continue
                if inside:
                    return allowed(f"{who} may {verb} branch {t.branch}: {rule} names group {e.group_id}, which the user belongs to")
            elif e.member_role_id != 0:
                # UNVERIFIED: an entry naming a custom role is taken to match
                # a member holding that exact custom role.
                anyone = True
                if m.custom_role_id == e.member_role_id:
                    return allowed(f"{who} may {verb} branch {t.branch}: {rule} names the user's custom role")
                unresolved.append(f"custom role {e.member_role_id} is not the user's")
            elif e.access_level == LEVEL_NONE:
                pass  # "No one".
            elif e.access_level == LEVEL_ADMIN:
                anyone = True
                adm = r.identity.attr("is_admin")
                if adm == "true":
                    return allowed(f"{who} may {verb} branch {t.branch}: {rule} allows administrators")
                if adm != "false":
                    unresolved.append("the rule allows administrators and the user's administrator status is unknown")
            else:
                anyone = True
                if m.level >= e.access_level and m.level >= LEVEL_DEVELOPER:
                    return allowed(f"{who} may {verb} branch {t.branch}: {rule} allows {level_name(e.access_level)} and up, and the user has {role} access")
        if not anyone:
            return denied(f"no one may {verb} branch {t.branch}: {rule} allows no one")
        if unresolved:
            return unsupported(f"{who} is not clearly allowed to {verb} branch {t.branch} by {rule}: {'; '.join(unresolved)}")
        if m.custom_role != "":
            return unsupported(
                f"{who} has {role} on project {t.id}; no entry of {rule} matches the base level but a custom role can add abilities hallpass cannot see"
            )
        return denied(f"{who} has {role} access to project {t.id}, and no entry of {rule} allows that user to {verb} branch {t.branch}")

    def _group_has(self, ctx: Context, group_id: int, user_id: str) -> bool:
        """Whether the user is a member of the group (200), is not (404);
        raises when it could not be resolved (any other failure)."""
        path = "/groups/" + str(group_id) + "/members/all/" + httpx.path_escape(user_id)
        try:
            rec = self._get(ctx, path, None, _member_record)
        except Exception as e:
            if httpx.status(e) == 404:
                return False
            raise
        return rec.state in ("", "active")

    # -- probe --

    def probe(self, ctx: Context) -> ProbeResult:
        """Verify the token, report whose it is and warn about scopes."""
        try:
            me = self._get(ctx, "/user", None, _user)
        except Exception as e:  # noqa: BLE001
            raise self._classify(e, "read its own user")
        warnings: list[str] = []
        summary = "authenticated as " + me.username
        is_admin = me.is_admin is True
        if is_admin:
            summary += " (administrator)"
        if me.bot:
            summary += " (bot)"
        if self.mode == MODE_ADMIN_SEARCH and not is_admin:
            warnings.append(
                "identity_mode admin_search needs an administrator's token: this token's user is not an administrator, so private emails are not "
                "searchable and most users will answer user_not_found"
            )

        # UNVERIFIED: the path /personal_access_tokens/self.
        def token(v: Any) -> tuple[list[str], str]:
            d = jsonx.obj(v, "token")
            _opt_bool(d, "active")
            return jsonx.strs(d, "scopes"), jsonx.s(d, "expires_at")

        try:
            scope_list, expires_at = self._get(ctx, "/personal_access_tokens/self", None, token)
        except Exception as e:  # noqa: BLE001
            st = httpx.status(e)
            if st in (403, 404):
                warnings.append(f"could not verify the token's scopes (the token endpoint answered HTTP {st}); make sure it has read_api and nothing broader")
            else:
                raise self._classify(e, "read its own token")
        else:
            scopes = set(scope_list)
            if "read_api" not in scopes and "api" not in scopes:
                warnings.append("the token lacks the read_api scope; API calls will be refused")
            broad = [s for s in ("api", "write_repository", "sudo", "admin_mode", "write_registry", "create_runner", "manage_runner") if s in scopes]
            if broad:
                warnings.append("the token has scopes broader than read_api (" + ", ".join(broad) + "); hallpass only reads")
            if expires_at != "":
                exp = _parse_date(expires_at)
                if exp is not None and exp - self.now() < 14 * 24 * 3600:
                    warnings.append("the token expires on " + expires_at)

        if self.group != "":
            try:
                self._get(ctx, "/groups/" + httpx.path_escape(self.group), None, lambda v: jsonx.s(jsonx.obj(v, "group"), "full_path"))
            except Exception as e:  # noqa: BLE001
                raise self._classify_group(e, "read")
            summary += ", group " + self.group + " visible"
        return ProbeResult(summary=summary, warnings=tuple(warnings))


_DATE_RE = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})")


def _parse_date(s: str) -> float | None:
    """time.Parse("2006-01-02", s) as epoch seconds (UTC midnight), or None
    when it does not parse."""
    m = _DATE_RE.fullmatch(s)
    if m is None:
        return None
    try:
        d = datetime.datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)), tzinfo=datetime.timezone.utc)
    except ValueError:
        return None
    return d.timestamp()


def _match_email(users: list[_User], email: str, no_email_hint: str) -> _User:
    """The one user whose email (or, absent that, public_email) or one of
    whose confirmed secondary emails equals the searched email, ignoring
    case. Never a substring match."""
    matches: list[_User] = []
    comparable = False
    for u in users:
        e = u.email or u.public_email
        matched = False
        if e != "":
            comparable = True
            matched = _equal_fold(e, email)
        for sec in u.emails:
            if sec.email == "":
                continue
            comparable = True
            if sec.confirmed and _equal_fold(sec.email, email):
                matched = True
        if matched:
            matches.append(u)
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        raise user_ambiguous(f"{len(matches)} GitLab accounts have the email {email}")
    if users and not comparable:
        raise errorf(Code.UNSUPPORTED, no_email_hint)
    raise user_not_found(f"no GitLab account has the email {email}")


INTEGRATION = GitLab()
