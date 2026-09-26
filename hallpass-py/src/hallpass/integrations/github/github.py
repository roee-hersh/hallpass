"""The github integration: repository, organization and team permissions
through the GitHub REST and GraphQL APIs.

hallpass authenticates as a GitHub App installed in one organization: it
signs a short-lived JWT with the App's private key, exchanges it for an
installation token (cached, refreshed before expiry) and reads with that.
The App needs only read permissions. The user's email is mapped to a
GitHub login through the organization's SAML identities, a login template
or a mapping file, and the effective repository permission (the highest of
direct, team, organization and enterprise grants, as GitHub computes it)
is read from the collaborator permission endpoint. Nothing is written.
"""

from __future__ import annotations

import json
import math
import os
import re
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from hallpass.authx import jwt as authx_jwt
from hallpass.authx.token import Token, TokenSource
from hallpass.authx.util import parse_rfc3339
from hallpass.core import jsonx
from hallpass.core.cache import TTL
from hallpass.core.catalog import Action
from hallpass.core.context import Context
from hallpass.core.decision import (
    Code,
    Decision,
    HallpassError,
    allowed,
    denied,
    errorf,
    unknown_decision,
    unsupported,
    wrap_error,
)
from hallpass.core.errors import as_error, go_quote, go_trim_space, path_error_text
from hallpass.core.integration import (
    CheckRequest,
    Connection,
    Deps,
    Field,
    Integration,
    ProbeResult,
    Settings,
    credential_field,
    url_field,
)
from hallpass.core.log import Logger
from hallpass.core.template import Template, parse_email_domains, parse_template, validate_email_domains, validate_template
from hallpass.integrations.github.actions import (
    ACTION_LIST,
    ACTIONS,
    GHAction,
    Permissions,
    Target,
    equal_fold,
    from_string,
    parse_target,
    slug_ok,
    valid_login,
)
from hallpass.integrations.github.identity import (
    MODE_MAP_FILE,
    MODE_SAML,
    MODE_TEMPLATE,
    IdentityMixin,
    SamlData,
    SamlIndex,
    decode_saml_data,
    member,
)
from hallpass.net import httpx

__all__ = [
    "API_VERSION",
    "DEFAULT_TEMPLATE",
    "GitHub",
    "GitHubConnection",
    "err_text",
]

_APP_ID_RE = re.compile(r"[A-Za-z0-9._-]{1,100}")
_INSTALLATION_ID_RE = re.compile(r"[0-9]{1,20}")

# Applies when login_template is unset.
DEFAULT_TEMPLATE = "{local}"

API_VERSION = "2022-11-28"
ACCEPT_JSON = "application/vnd.github+json"
PUBLIC_REST = "https://api.github.com"
PUBLIC_GRAPHQL = "https://api.github.com/graphql"
JWT_BACKDATE = 60.0
JWT_LIFETIME = 9 * 60.0
TOKEN_LIFETIME = 3600.0
MINT_IDEMPOTENT = True


def validate_login(v: str) -> None:
    if not valid_login(v):
        raise ValueError(f"{go_quote(v)} is not a GitHub login")


def validate_app_id(v: str) -> None:
    if _APP_ID_RE.fullmatch(v) is None:
        raise ValueError(f"{go_quote(v)} is not an App client id or App id")


def validate_installation_id(v: str) -> None:
    if _INSTALLATION_ID_RE.fullmatch(v) is None:
        raise ValueError(f"{go_quote(v)} is not a numeric installation id")


class GitHub(Integration):
    """The github product."""

    def name(self) -> str:
        return "github"

    def fields(self) -> list[Field]:
        return [
            url_field(False, "GitHub Enterprise Server URL, e.g. https://github.example.com; omit for github.com"),
            Field(
                name="organization",
                required=True,
                validate=validate_login,
                description="the organization the App is installed in; every resource must belong to it",
            ),
            Field(
                name="app_id",
                required=True,
                validate=validate_app_id,
                description="the App's client id (preferred) or numeric App id, used as the JWT issuer",
            ),
            Field(
                name="installation_id",
                validate=validate_installation_id,
                description="the App's installation id in the organization; discovered when omitted",
            ),
            credential_field(True, "the App's private key, PEM (PKCS#1 or PKCS#8)"),
            Field(
                name="identity_mode",
                default=MODE_SAML,
                enum=(MODE_SAML, MODE_TEMPLATE, MODE_MAP_FILE),
                description="how an email becomes a login: saml (organization SAML identities), template (login_template) or map_file (user_map_file)",
            ),
            Field(
                name="login_template",
                default=DEFAULT_TEMPLATE,
                validate=validate_template,
                description="template mode: placeholders {email}, {local}, {domain}, e.g. {local}-acme",
            ),
            Field(
                name="email_domains",
                validate=validate_email_domains,
                description="template mode (required): comma-separated email domains the template applies to; other domains are unknown",
            ),
            Field(
                name="user_map_file",
                description='map_file mode: path to a file of "email login" or "email=login" lines, # comments; re-read every 60 s',
            ),
        ]

    def actions(self) -> list[Action]:
        return [Action(a.name, a.desc) for a in ACTION_LIST]

    def new(self, ctx: Context, s: Settings, d: Deps) -> Connection:
        """Build a connection. It touches no network; the private key is
        read and parsed when a JWT is needed, so a rotated key file takes
        effect."""
        hc = d.http_client(s)
        if s.secret("credential").is_zero():
            raise ValueError("credential is required")
        if s.get("organization") == "":
            raise ValueError("organization is required")
        if s.get("app_id") == "":
            raise ValueError("app_id is required")
        c = GitHubConnection(
            settings=s,
            org=s.get("organization"),
            app_id=s.get("app_id"),
            installation_id=s.get("installation_id"),
            mode=s.get("identity_mode"),
            template=Template(s.get("login_template")),
            map_file=s.get("user_map_file"),
            logger=d.logger if d.logger is not None else Logger(),
            now=d.now,
        )
        c.saml.set_clock(c.now)
        c.saml.set_fresh_max_age(_saml_cache_ttl())
        if c.mode == "":
            c.mode = MODE_SAML
        if c.template == "":
            c.template = Template(DEFAULT_TEMPLATE)
        if c.mode == MODE_SAML:
            pass
        elif c.mode == MODE_TEMPLATE:
            try:
                parse_template(str(c.template))
            except ValueError as e:
                raise ValueError(f"login_template: {e}") from e
            if s.get("email_domains") == "":
                raise ValueError("identity_mode template requires email_domains: the template would otherwise map any domain's local part to a login")
            try:
                domains = parse_email_domains(s.get("email_domains"))
            except ValueError as e:
                raise ValueError(f"email_domains: {e}") from e
            c.email_domains = frozenset(domains)
        elif c.mode == MODE_MAP_FILE:
            if c.map_file == "":
                raise ValueError("identity_mode map_file requires user_map_file")
            try:
                is_dir = os.path.isdir(c.map_file) if os.stat(c.map_file) else False
            except (OSError, ValueError) as e:
                raise ValueError(f"user_map_file: {path_error_text('stat', c.map_file, e)}") from e
            if is_dir:
                raise ValueError(f"user_map_file {c.map_file} is a directory")
        else:
            raise ValueError(f"identity_mode {go_quote(c.mode)} must be one of saml, template, map_file")
        rest_base, graphql_url = PUBLIC_REST, PUBLIC_GRAPHQL
        u = s.get("url").rstrip("/")
        if u != "":
            rest_base, graphql_url = u + "/api/v3", u + "/api/graphql"
        c.graphql_url = graphql_url
        c.app = httpx.Client(http=hc, base=rest_base, logger=d.logger, auth=c._jwt_auth)
        c.rest = httpx.Client(http=hc, base=rest_base, logger=d.logger, auth=c._token_auth)
        c.tokens = TokenSource(fetch=c._mint_token, default_ttl=TOKEN_LIFETIME, now=c.now)
        return c


def _saml_cache_ttl() -> float:
    from hallpass.integrations.github import identity

    return identity.SAML_CACHE_TTL


# -- decoding ----------------------------------------------------------------
#
# Each decoder reads the fields of the Go struct the response was decoded
# into, all of them, so a value of the wrong type is an error there too.


def _decode_str_map(v: Any, key: str) -> dict[str, str]:
    """A map[string]string field."""
    out: dict[str, str] = {}
    for k, x in jsonx.obj(v, key).items():
        if x is None:
            out[k] = ""
        elif isinstance(x, str):
            out[k] = x
        else:
            raise jsonx.DecodeError(f"json: cannot unmarshal {type(x).__name__} into field {key} of type string")
    return out


def _opt_bool(d: dict[str, Any], key: str) -> bool | None:
    """A *bool field: None when absent or null."""
    if member(d, key) is None:
        return None
    return jsonx.b(d, key)


class _Num:
    """A JSON number kept as its literal text (json.Number)."""

    __slots__ = ("text",)

    def __init__(self, text: str) -> None:
        self.text = text


_JSON_NUMBER_RE = re.compile(r"-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?")


def _json_number(d: dict[str, Any], key: str) -> str:
    """A json.Number field: a number's literal text, or a string holding a
    valid number."""
    v = member(d, key)
    if v is None:
        return ""
    if isinstance(v, _Num):
        return v.text
    if isinstance(v, str):
        if v != "" and _JSON_NUMBER_RE.fullmatch(v) is None:
            raise jsonx.DecodeError(f"json: invalid number literal, trying to unmarshal {go_quote(json.dumps(v))} into Number")
        return v
    raise jsonx.DecodeError(f"json: cannot unmarshal into field {key} of type json.Number")


def _decode_with_numbers(resp: httpx.Response) -> Any:
    """resp.json() with number literals kept as _Num."""
    text = resp.body.decode("utf-8", "replace").lstrip(" \t\r\n")
    if not text:
        raise ValueError("empty body")
    v, _ = json.JSONDecoder(parse_int=_Num, parse_float=_Num).raw_decode(text)
    return v


@dataclass(frozen=True)
class _Installation:
    id: str
    permissions: dict[str, str]
    account_login: str


def _decode_installation(resp: httpx.Response) -> _Installation:
    d = jsonx.obj(_decode_with_numbers(resp))
    perms_raw = member(d, "permissions")
    perms = _decode_str_map(perms_raw, "permissions") if perms_raw is not None else {}
    account = member(d, "account")
    login = ""
    if account is not None:
        a = jsonx.obj(account, "account")
        if isinstance(member(a, "login"), _Num):
            raise jsonx.DecodeError("json: cannot unmarshal number into field login of type string")
        login = jsonx.s(a, "login")
    for k in perms_raw.values() if isinstance(perms_raw, dict) else ():
        if isinstance(k, _Num):
            raise jsonx.DecodeError("json: cannot unmarshal number into field permissions of type string")
    return _Installation(_json_number(d, "id"), perms, login)


@dataclass(frozen=True)
class _PermissionRecord:
    permission: str
    role_name: str
    has_user: bool
    perms: Permissions | None  # None: no user.permissions object


def _decode_permissions(v: Any) -> Permissions:
    p = jsonx.obj(v, "permissions")
    return Permissions(jsonx.b(p, "pull"), jsonx.b(p, "triage"), jsonx.b(p, "push"), jsonx.b(p, "maintain"), jsonx.b(p, "admin"))


def _decode_permission_record(v: Any) -> _PermissionRecord:
    d = jsonx.obj(v)
    permission, role = jsonx.s(d, "permission"), jsonx.s(d, "role_name")
    u = member(d, "user")
    if u is None:
        return _PermissionRecord(permission, role, False, None)
    u = jsonx.obj(u, "user")
    jsonx.s(u, "login")
    p = member(u, "permissions")
    return _PermissionRecord(permission, role, True, _decode_permissions(p) if p is not None else None)


@dataclass(frozen=True)
class _RepoMeta:
    has_issues: bool | None
    allow_forking: bool | None
    visibility: str


def _decode_repo_meta(v: Any) -> _RepoMeta:
    d = jsonx.obj(v)
    return _RepoMeta(_opt_bool(d, "has_issues"), _opt_bool(d, "allow_forking"), jsonx.s(d, "visibility"))


@dataclass(frozen=True)
class _Membership:
    state: str
    role: str


def _decode_membership(v: Any) -> _Membership:
    d = jsonx.obj(v)
    return _Membership(jsonx.s(d, "state"), jsonx.s(d, "role"))


def _decode_rules(v: Any) -> list[str]:
    """[]branchRule: the type of each rule."""
    if v is None:
        return []
    if not isinstance(v, list):
        raise jsonx.DecodeError("json: cannot unmarshal object into Go value of type []github.branchRule")
    return [jsonx.s(jsonx.obj(r), "type") for r in v]


@dataclass
class _Protection:
    """The part of the classic branch protection record hallpass evaluates.
    Every object is optional: absent means the setting is off.

    UNVERIFIED: the field shapes follow GitHub's OpenAPI description
    (restrictions.users[].login, restrictions.teams[].slug,
    required_pull_request_reviews present, enforce_admins.enabled); no live
    response was captured."""

    enforce_admins: bool | None = None  # None: not reported
    required_reviews: bool = False
    has_restrictions: bool = False
    users: list[str] = field(default_factory=list)
    teams: list[str] = field(default_factory=list)


def _decode_protection(v: Any) -> _Protection:
    d = jsonx.obj(v)
    p = _Protection()
    ea = member(d, "enforce_admins")
    if ea is not None:
        p.enforce_admins = jsonx.b(jsonx.obj(ea, "enforce_admins"), "enabled")
    rr = member(d, "required_pull_request_reviews")
    if rr is not None:
        jsonx.i(jsonx.obj(rr, "required_pull_request_reviews"), "required_approving_review_count")
        p.required_reviews = True
    rs = member(d, "restrictions")
    if rs is not None:
        rs = jsonx.obj(rs, "restrictions")
        p.has_restrictions = True
        p.users = [jsonx.s(jsonx.obj(u), "login") for u in jsonx.arr(rs, "users")]
        p.teams = [jsonx.s(jsonx.obj(t), "slug") for t in jsonx.arr(rs, "teams")]
        for a in jsonx.arr(rs, "apps"):
            jsonx.s(jsonx.obj(a), "slug")
    return p


# The ruleset rule types under which a direct push to an existing branch is
# only possible for bypass actors, with what each means. creation and
# deletion do not affect a push to an existing branch.
PUSH_BLOCKING_RULES = (
    ("pull_request", "requires pull requests"),
    ("update", "restricts updates to bypass actors"),
    ("merge_queue", "requires the merge queue"),
)


def _builtin_role(name: str) -> bool:
    """Whether a role_name is one of GitHub's five base roles (or "none").
    Anything else is a custom repository role, whose extra abilities the
    five permission booleans do not describe."""
    return name in ("", "none", "read", "pull", "triage", "write", "push", "maintain", "admin")


def _or_empty(s: str, default: str) -> str:
    return s if s != "" else default


def _unauthorized(err: BaseException) -> bool:
    """A 401 answered by the API itself, as opposed to a failure inside the
    token exchange (which has no response)."""
    resp = getattr(err, "response", None)
    return resp is not None and resp.status == 401


def api_status(err: BaseException) -> int:
    """The HTTP status of a failed API call, or 0 when the failure was
    already classified (for example a 404 from the token exchange, which
    must not read as "user not found")."""
    if as_error(err, HallpassError) is not None:
        return 0
    return httpx.status(err)


def err_text(err: BaseException) -> str:
    """The code and text of an integration error, never its cause."""
    he = as_error(err, HallpassError)
    if he is not None:
        return he.code.value + ": " + he.text
    return "upstream call failed"


_PROBE_QUERY = "query($org:String!){ organization(login:$org){ samlIdentityProvider { externalIdentities(first:1){ nodes { user { login } } } } } }"


class GitHubConnection(IdentityMixin, Connection):
    """One organization on one GitHub."""

    def __init__(
        self,
        settings: Settings,
        org: str,
        app_id: str,
        installation_id: str,
        mode: str,
        template: Template,
        map_file: str,
        logger: Logger,
        now: Callable[[], float],
    ) -> None:
        self.settings = settings
        self.org = org
        self.app_id = app_id
        self.installation_id = installation_id
        self.mode = mode
        self.template = template
        # Template mode: lowercase domains the template applies to.
        self.email_domains: frozenset[str] = frozenset()
        self.map_file = map_file
        self.graphql_url = ""
        self.logger = logger
        self.now = now
        # app authenticates as the App (JWT); rest as the installation (token).
        self.app: httpx.Client = httpx.Client()
        self.rest: httpx.Client = httpx.Client()
        self.tokens: TokenSource = TokenSource(None)
        self._inst_lock = threading.Lock()
        self._discovered_inst = ""
        # The external-identity index under the empty key.
        self.saml: TTL[tuple[()], SamlIndex] = TTL(1)
        self._map_lock = threading.Lock()
        self._map_entries: dict[str, str] | None = None
        self._map_read = 0.0

    # -- authentication --------------------------------------------------

    def _app_jwt(self) -> str:
        """A fresh App JWT. GitHub allows at most 10 minutes of lifetime and
        rejects clocks ahead of its own, hence the backdated iat."""
        try:
            pem_text = self.settings.secret("credential").get_string()
        except Exception as e:  # noqa: BLE001 - any failure to read the secret
            raise wrap_error(Code.CREDENTIAL_REJECTED, e, "the App private key could not be read") from e
        try:
            key = authx_jwt.parse_rsa_private_key(pem_text.encode("utf-8", "surrogateescape"))
        except Exception as e:  # noqa: BLE001 - ValueError, or the crypto package missing
            raise wrap_error(Code.CREDENTIAL_REJECTED, e, "the App private key is not a PEM RSA key") from e
        now = self.now()
        claims = authx_jwt.standard_claims(iss=self.app_id, iat=math.floor(now - JWT_BACKDATE), exp=math.floor(now + JWT_LIFETIME))
        return authx_jwt.sign_jwt(key, authx_jwt.Header(alg=authx_jwt.RS256), claims)

    @staticmethod
    def _set_github_headers(r: httpx.PreparedRequest) -> None:
        r.headers.set("Accept", ACCEPT_JSON)
        r.headers.set("X-GitHub-Api-Version", API_VERSION)

    def _jwt_auth(self, ctx: Context, r: httpx.PreparedRequest) -> None:
        tok = self._app_jwt()
        self._set_github_headers(r)
        r.headers.set("Authorization", "Bearer " + tok)

    def _token_auth(self, ctx: Context, r: httpx.PreparedRequest) -> None:
        tok = self.tokens.get(ctx)
        self._set_github_headers(r)
        r.headers.set("Authorization", "Bearer " + tok)

    def _installation(self, ctx: Context) -> _Installation:
        """The App's installation in the organization, read with the JWT."""
        try:
            resp, _ = self.app.get_json(ctx, "/orgs/" + httpx.path_escape(self.org) + "/installation", decode=False)
            return _decode_installation(resp)
        except Exception as e:  # noqa: BLE001 - classified below
            if httpx.status(e) == 404:
                raise wrap_error(Code.CREDENTIAL_REJECTED, e, f"the App is not installed in organization {self.org} (or app_id is wrong)") from e
            raise self.classify(e, "read its installation in " + self.org) from e

    def _installation_id_for(self, ctx: Context) -> str:
        """The configured or discovered installation id."""
        if self.installation_id != "":
            return self.installation_id
        with self._inst_lock:
            iid = self._discovered_inst
        if iid != "":
            return iid
        inst = self._installation(ctx)
        iid = inst.id
        if _INSTALLATION_ID_RE.fullmatch(iid) is None:
            raise errorf(Code.UPSTREAM_ERROR, f"the installation record for {self.org} carries no id")
        with self._inst_lock:
            self._discovered_inst = iid
        return iid

    def _mint_token(self, ctx: Context) -> Token:
        """Exchange the App JWT for an installation token."""
        iid = self._installation_id_for(ctx)
        try:
            _, v = self.app.post_json(ctx, "/app/installations/" + httpx.path_escape(iid) + "/access_tokens", {}, idempotent=MINT_IDEMPOTENT)
            d = jsonx.obj(v)
            token, expires_at = jsonx.s(d, "token"), jsonx.s(d, "expires_at")
        except Exception as e:  # noqa: BLE001 - classified below
            if httpx.status(e) == 404:
                raise wrap_error(Code.CREDENTIAL_REJECTED, e, f"installation {iid} was not found for this App") from e
            raise self.classify(e, "create an installation token") from e
        if token == "":
            raise errorf(Code.UPSTREAM_ERROR, "the installation token response carried no token")
        expiry: float | None = None
        try:
            expiry = parse_rfc3339(expires_at)
        except ValueError:
            pass
        return Token(value=token, expiry=expiry)

    # -- transport helpers -----------------------------------------------

    def _get(self, ctx: Context, path: str, decode: bool = True) -> Any:
        """One REST GET with the installation token. On a 401 the token is
        dropped and the call is retried once with a fresh one."""
        try:
            return self.rest.get_json(ctx, path, decode=decode)[1]
        except Exception as e:
            if not _unauthorized(e):
                raise
        self.tokens.invalidate()
        return self.rest.get_json(ctx, path, decode=decode)[1]

    def classify(self, err: BaseException, what: str) -> HallpassError:
        """A failed call as an integration error. 401 and 403 mean the App's
        credential or permissions are insufficient, except a 403 that GitHub
        uses for an exhausted rate limit."""
        he = as_error(err, HallpassError)
        if he is not None:
            return he
        st = httpx.status(err)
        if st == 403:
            se = as_error(err, httpx.StatusError)
            if se is not None and se.header is not None:
                if go_trim_space(se.header.get("X-RateLimit-Remaining")) == "0" or se.header.get("Retry-After") != "":
                    return wrap_error(Code.UPSTREAM_RATE_LIMIT, err, "GitHub rate limit exhausted for the App installation")
            return wrap_error(Code.CREDENTIAL_REJECTED, err, f"the App may not {what} (HTTP 403); check its permissions")
        if st == 401:
            return wrap_error(Code.CREDENTIAL_REJECTED, err, "the App's credential was rejected (HTTP 401)")
        out = httpx.classify(err)
        assert out is not None
        return out

    def graphql(self, ctx: Context, query: str, variables: dict[str, Any]) -> Any:
        """Run one query with the installation token and return data.
        GraphQL reports most failures as HTTP 200 with an errors array."""
        body = {"query": query, "variables": dict(sorted(variables.items()))}

        def do() -> httpx.Response:
            return self.rest.do(ctx, httpx.Request(method="POST", path=self.graphql_url, json=body, idempotent=True))

        try:
            try:
                resp = do()
            except Exception as e:
                if not _unauthorized(e):
                    raise
                self.tokens.invalidate()
                resp = do()
        except Exception as e:  # noqa: BLE001 - classified below
            raise self.classify(e, "query GraphQL") from e
        try:
            env = jsonx.obj(resp.json())
            errors = []
            for x in jsonx.arr(env, "errors"):
                x = jsonx.obj(x)
                errors.append((jsonx.s(x, "type"), jsonx.s(x, "message")))
        except Exception as e:  # noqa: BLE001 - any decode failure
            raise wrap_error(Code.UPSTREAM_ERROR, e, "GraphQL response was not JSON") from e
        for typ, _ in errors:
            if typ.upper() in ("INSUFFICIENT_SCOPES", "FORBIDDEN"):
                raise errorf(
                    Code.CREDENTIAL_REJECTED,
                    f"the App may not read organization SAML identities (GraphQL {typ}); it needs Organization members: read",
                )
            if typ.upper() == "RATE_LIMITED":
                raise errorf(Code.UPSTREAM_RATE_LIMIT, "GraphQL rate limit exhausted")
        if errors:
            t = errors[0][0] or "error"
            raise errorf(Code.UPSTREAM_ERROR, f"GraphQL query failed ({t})")
        data = member(env, "data")
        if data is None:
            raise errorf(Code.UPSTREAM_ERROR, "GraphQL response carried no data")
        return data

    def graphql_saml(self, ctx: Context, query: str, variables: dict[str, Any]) -> SamlData:
        data = self.graphql(ctx, query, variables)
        try:
            return decode_saml_data(data)
        except Exception as e:  # noqa: BLE001 - any decode failure
            raise wrap_error(Code.UPSTREAM_ERROR, e, "GraphQL data could not be decoded") from e

    # -- check -----------------------------------------------------------

    def check(self, ctx: Context, r: CheckRequest) -> Decision:
        a = ACTIONS.get(r.action_name)
        if a is None:
            raise errorf(Code.UNKNOWN_ACTION, f"unknown action {go_quote(r.action_name)}")
        try:
            t = parse_target(a, self.org, r.resource)
        except ValueError as e:
            raise errorf(Code.INVALID_REQUEST, str(e)) from None
        login = r.identity.id
        if not valid_login(login):
            raise errorf(Code.INVALID_REQUEST, f"identity {go_quote(login)} is not a GitHub login")
        if t.kind == "repo":
            return self._check_repo(ctx, a, t, login)
        if t.kind == "org":
            return self._check_org(ctx, a, t, login)
        return self._check_team(ctx, a, t, login)

    def _repo_meta(self, ctx: Context, repo_path: str, repo: str) -> _RepoMeta:
        try:
            return _decode_repo_meta(self._get(ctx, repo_path))
        except Exception as e:  # noqa: BLE001 - classified below
            if api_status(e) == 404:
                raise errorf(Code.RESOURCE_NOT_VISIBLE, f"repository {repo} is not visible to the App") from e
            raise self.classify(e, "read repository " + repo) from e

    def _check_repo(self, ctx: Context, a: GHAction, t: Target, login: str) -> Decision:
        repo_path = "/repos/" + httpx.path_escape(t.owner) + "/" + httpx.path_escape(t.repo)
        try:
            rec = _decode_permission_record(self._get(ctx, repo_path + "/collaborators/" + httpx.path_escape(login) + "/permission"))
        except Exception as e:  # noqa: BLE001 - classified below
            if api_status(e) == 404:
                return unknown_decision(
                    Code.RESOURCE_NOT_VISIBLE,
                    f"repository {t.owner}/{t.repo} is not visible to the App, or {login} is not a collaborator on a private repository",
                )
            raise self.classify(e, "read collaborator permissions on " + t.owner + "/" + t.repo) from e
        repo = t.owner + "/" + t.repo
        if rec.has_user and rec.perms is not None:
            perms = rec.perms
        elif rec.permission != "":
            if not _builtin_role(rec.permission):
                return unsupported(f"GitHub reported permission {go_quote(rec.permission)} for {login} on {repo}, which hallpass does not model")
            perms = from_string(rec.permission)
        else:
            return unsupported(f"GitHub reported no permissions for {login} on {repo}")
        role = rec.role_name or rec.permission or "none"
        if not perms.has(a.level):
            if not _builtin_role(rec.role_name):
                return unsupported(f"{login} has custom repository role {role} on {repo}; extra abilities not modeled, so {a.level} cannot be evaluated")
            return denied(f"{login} has {role} on {repo}, which does not include {a.level}")
        text = f"{login} has {role} on {repo}, which includes {a.level}"

        if a.name == "issue.create":
            meta = self._repo_meta(ctx, repo_path, repo)
            if meta.has_issues is None:
                return unsupported(f"{text}; GitHub did not report whether issues are enabled on {repo}")
            if not meta.has_issues:
                return denied(f"issues are disabled on {repo}")
            text += "; issues are enabled"
        elif a.name == "pr.create":
            if not perms.push:
                # Without push the branch must come from a fork, so forking
                # must be possible on this repository.
                meta = self._repo_meta(ctx, repo_path, repo)
                if meta.allow_forking is None:
                    return unsupported(f"{text} but not push; GitHub did not report whether {repo} may be forked")
                if not meta.allow_forking:
                    return denied(f"forking disabled on {repo}; pull request needs push access, and {login} has only {role}")
                # UNVERIFIED: allow_forking on a private or internal
                # repository is assumed to reflect the organization's
                # "members can fork" policy; the visibility is quoted so a
                # reader can tell.
                text += " (via fork; pushing a branch to the repository itself needs push"
                if meta.visibility != "":
                    text += "; the repository is " + meta.visibility
                text += ")"
        elif a.name in ("repo.push", "pr.merge"):
            if t.branch != "":
                return self._annotate_branch(ctx, a, t, repo_path, login, perms, text)
        return allowed(text)

    # -- branch rules and protection -------------------------------------

    def _forbidden(self, err: BaseException, text: str) -> HallpassError:
        """A 403 on a read that needs an extra App permission: a rate-limit
        403 keeps its meaning, anything else is unknown (unsupported) with a
        hint at the permission to grant."""
        ie = self.classify(err, "")
        if ie.code == Code.UPSTREAM_RATE_LIMIT:
            return ie
        return wrap_error(Code.UNSUPPORTED, err, text)

    def _branch_rules(self, ctx: Context, t: Target, repo_path: str) -> list[str]:
        """The types of the ruleset rules that apply to the branch. The
        endpoint answers 200 with an empty list when no rule applies, so a
        404 means the repository or branch is not visible."""
        try:
            return _decode_rules(self._get(ctx, repo_path + "/rules/branches/" + httpx.path_escape(t.branch)))
        except Exception as e:  # noqa: BLE001 - classified below
            st = api_status(e)
            if st == 403:
                raise self._forbidden(e, f"branch rules of {t} not readable; grant the App Repository Administration: read") from e
            if st == 404:
                raise errorf(Code.RESOURCE_NOT_VISIBLE, f"branch {t} does not exist or is not visible to the App") from e
            raise self.classify(e, "read branch rules of " + t.owner + "/" + t.repo) from e

    def _branch_protection(self, ctx: Context, t: Target, repo_path: str) -> _Protection | None:
        """The classic protection of the branch; None when the branch has
        none (GitHub answers 404 "Branch not protected")."""
        try:
            return _decode_protection(self._get(ctx, repo_path + "/branches/" + httpx.path_escape(t.branch) + "/protection"))
        except Exception as e:  # noqa: BLE001 - classified below
            st = api_status(e)
            if st == 404:
                return None
            if st == 403:
                raise self._forbidden(e, f"branch protection of {t} not readable; grant the App Repository Administration: read") from e
            raise self.classify(e, "read branch protection of " + t.owner + "/" + t.repo) from e

    def _in_restrictions(self, ctx: Context, t: Target, prot: _Protection, login: str) -> bool:
        """Whether the login may push under the branch's push restrictions:
        listed directly, or an active member of a listed team. Apps are not
        people and are skipped."""
        for u in prot.users:
            if equal_fold(u, login):
                return True
        for slug in prot.teams:
            if not slug_ok(slug):
                raise errorf(Code.UNSUPPORTED, f"branch {t} restricts pushes to a team whose slug hallpass cannot look up")
            try:
                m = _decode_membership(
                    self._get(ctx, "/orgs/" + httpx.path_escape(t.owner) + "/teams/" + httpx.path_escape(slug) + "/memberships/" + httpx.path_escape(login))
                )
            except Exception as e:  # noqa: BLE001 - classified below
                st = api_status(e)
                if st == 404:
                    continue
                if st == 403:
                    raise self._forbidden(e, f"branch {t} restricts pushes to team {slug}, whose members the App may not read") from e
                raise self.classify(e, "read memberships of team " + t.owner + "/" + slug) from e
            if m.state == "active":
                return True
            if m.state == "":
                raise errorf(Code.UNSUPPORTED, f"GitHub reported no membership state for {login} in team {t.owner}/{slug}")
        return False

    def _annotate_branch(self, ctx: Context, a: GHAction, t: Target, repo_path: str, login: str, perms: Permissions, text: str) -> Decision:
        """Evaluate the branch's ruleset rules and classic protection on top
        of an allowed push or merge. A push restriction that excludes the
        login is a deny; a rule that routes changes through pull requests
        turns an allowed direct push into unknown."""
        rules = self._branch_rules(ctx, t, repo_path)
        prot = self._branch_protection(ctx, t, repo_path)
        branch = t.branch

        # Classic protection. UNVERIFIED: the restrictions of a classic rule
        # are assumed not to apply to repository admins unless
        # enforce_admins is enabled ("Do not allow bypassing the above
        # settings"); when GitHub does not report enforce_admins for an
        # admin the answer is unknown.
        admin_bypass = False
        if prot is not None and perms.admin:
            if prot.enforce_admins is None:
                return unsupported(f"{text}, but branch {branch} is protected and GitHub did not report whether admins are exempt")
            admin_bypass = not prot.enforce_admins
        if prot is not None and prot.has_restrictions and not admin_bypass:
            listed = self._in_restrictions(ctx, t, prot, login)
            if not listed:
                if a.name == "repo.push":
                    return denied(f"branch {branch} restricts pushes to listed users, teams and apps, and {login} is not among them")
                # UNVERIFIED: whether a push restriction also blocks merging a
                # pull request into the branch; treated as unknown.
                return unsupported(f"{text}, but branch {branch} restricts pushes and {login} is not among the listed users and teams; merging may be rejected")
            text += f"; {login} is among those allowed to push to branch {branch}"

        # Ruleset rules.
        seen: set[str] = set()
        for typ in rules:
            if typ != "":
                seen.add(typ)
        types = sorted(seen)
        if a.name == "repo.push":
            for typ, means in PUSH_BLOCKING_RULES:
                if typ in seen:
                    # UNVERIFIED: bypass actors of the ruleset may still push
                    # directly; hallpass does not evaluate bypass lists.
                    return unsupported(f"{text}, but branch {branch} {means} ({typ} rule); direct push not allowed by rules")
            if prot is not None and prot.required_reviews and not admin_bypass:
                return unsupported(f"{text}, but branch {branch} requires pull request reviews; direct push not allowed by its protection")
        if admin_bypass:
            text += f"; {login} is an admin and branch {branch} does not enforce its protection for admins"
        if not rules and prot is None:
            return allowed(f"{text}; branch {branch} has no rules and no classic protection")
        if not rules:
            return allowed(f"{text}; branch {branch} has classic protection: a direct push may still be rejected")
        return allowed(f"{text}; branch {branch} has {len(rules)} rules (types {', '.join(types)}): a direct push may still be rejected")

    # -- organization and team -------------------------------------------

    def _org_membership(self, ctx: Context, t: Target, login: str) -> _Membership | None:
        try:
            return _decode_membership(self._get(ctx, "/orgs/" + httpx.path_escape(t.owner) + "/memberships/" + httpx.path_escape(login)))
        except Exception as e:  # noqa: BLE001 - classified below
            if api_status(e) == 404:
                return None
            raise self.classify(e, "read organization memberships of " + t.owner) from e

    def _check_org(self, ctx: Context, a: GHAction, t: Target, login: str) -> Decision:
        m = self._org_membership(ctx, t, login)
        if m is None:
            return denied(f"{login} is not a member of organization {t.owner}")
        if m.state == "":
            return unsupported(f"GitHub reported no membership state for {login} in organization {t.owner}")
        if m.state != "active":
            return denied(f"{login}'s membership in organization {t.owner} is {m.state}, not active")
        if a.name == "org.member":
            return allowed(f"{login} is an active {_or_empty(m.role, 'member')} of organization {t.owner}")
        if a.name == "org.admin":
            if m.role == "admin":
                return allowed(f"{login} is an owner of organization {t.owner}")
            return denied(f"{login} is a {_or_empty(m.role, 'member')} of organization {t.owner}, not an owner")
        # org.repo.create
        if m.role == "admin":
            return allowed(f"{login} is an owner of organization {t.owner} and may create repositories")
        try:
            # UNVERIFIED: whether an installation token sees these fields;
            # absent means unknown.
            org = jsonx.obj(self._get(ctx, "/orgs/" + httpx.path_escape(t.owner)))
            can_create = _opt_bool(org, "members_can_create_repositories")
            kinds_raw = [
                ("public", _opt_bool(org, "members_can_create_public_repositories")),
                ("private", _opt_bool(org, "members_can_create_private_repositories")),
                ("internal", _opt_bool(org, "members_can_create_internal_repositories")),
            ]
        except Exception as e:  # noqa: BLE001 - classified below
            raise self.classify(e, "read organization " + t.owner) from e
        if can_create is None:
            return unsupported(f"GitHub did not report whether members of {t.owner} may create repositories; the App may need Organization administration: read")
        if not can_create:
            return denied(f"{login} is a member of organization {t.owner}, whose members may not create repositories")
        kinds = [name for name, v in kinds_raw if v]
        text = f"{login} is a member of organization {t.owner}, whose members may create repositories"
        if kinds:
            text += " (" + ", ".join(kinds) + ")"
        return allowed(text)

    def _check_team(self, ctx: Context, a: GHAction, t: Target, login: str) -> Decision:
        team_path = "/orgs/" + httpx.path_escape(t.owner) + "/teams/" + httpx.path_escape(t.team)
        try:
            m = _decode_membership(self._get(ctx, team_path + "/memberships/" + httpx.path_escape(login)))
        except Exception as e:  # noqa: BLE001 - classified below
            if api_status(e) != 404:
                raise self.classify(e, "read memberships of team " + str(t)) from e
            # 404 is both "not a member" and "no such team"; tell them apart
            # so a typo in the slug is not reported as a deny.
            try:
                self._get(ctx, team_path, decode=False)
            except Exception as e2:  # noqa: BLE001 - classified below
                if api_status(e2) == 404:
                    return unknown_decision(Code.RESOURCE_NOT_VISIBLE, f"team {t} does not exist or is not visible to the App")
                raise self.classify(e2, "read team " + str(t)) from e2
            return denied(f"{login} is not a member of team {t}")
        if m.state == "":
            return unsupported(f"GitHub reported no membership state for {login} in team {t}")
        if m.state != "active":
            return denied(f"{login}'s membership in team {t} is {m.state}, not active")
        if a.name == "team.maintainer":
            if m.role == "maintainer":
                return allowed(f"{login} is a maintainer of team {t}")
            return denied(f"{login} is a {_or_empty(m.role, 'member')} of team {t}, not a maintainer")
        return allowed(f"{login} is an active {_or_empty(m.role, 'member')} of team {t}")

    # -- probe -----------------------------------------------------------

    def probe(self, ctx: Context) -> ProbeResult:
        """Read the App and its installation with the JWT, then check the
        installation's permissions: metadata and members must be readable,
        and anything writable is reported as over-privileged."""
        try:
            _, v = self.app.get_json(ctx, "/app")
            d = jsonx.obj(v)
            slug, app_name = jsonx.s(d, "slug"), jsonx.s(d, "name")
        except Exception as e:  # noqa: BLE001 - classified below
            raise self.classify(e, "read the App (GET /app)") from e
        inst = self._installation(ctx)
        name = slug or _or_empty(app_name, self.app_id)
        summary = f"app {name} installed in {self.org}"
        warnings: list[str] = []
        if self.installation_id != "" and inst.id != self.installation_id:
            warnings.append(
                f"installation_id {self.installation_id} does not match the installation GitHub reports for {self.org} ({inst.id})"
            )
        if inst.permissions.get("metadata", "") == "":
            warnings.append("the installation lacks Repository metadata: read; repository permission checks will fail")
        if inst.permissions.get("members", "") == "":
            warnings.append("the installation lacks Organization members: read; organization, team and SAML identity lookups will fail")
        for k in sorted(inst.permissions):
            v = inst.permissions[k]
            if v in ("write", "admin"):
                warnings.append(f"over-privileged: the installation has {k}: {v}; hallpass only reads")
        if self.mode == MODE_SAML:
            try:
                data = self.graphql_saml(ctx, _PROBE_QUERY, {"org": self.org})
            except Exception as e:  # noqa: BLE001 - reported as a warning
                warnings.append("SAML identity lookup failed: " + go_quote(err_text(e)))
            else:
                if not data.has_org or not data.has_provider:
                    warnings.append(
                        "organization " + self.org + " has no SAML identity provider; identity_mode saml will not resolve anyone (use template or map_file)"
                    )
        return ProbeResult(summary=summary, warnings=tuple(warnings))
