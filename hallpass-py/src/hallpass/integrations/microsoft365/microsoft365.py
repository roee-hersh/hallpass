"""Checks Entra ID, Teams, OneDrive/SharePoint and Exchange facts through
Microsoft Graph.

hallpass authenticates as an app registration with read-only application
permissions (client credentials, with a client secret or a certificate),
resolves the caller's email to an Entra user and asks Graph about group
membership, directory roles, team and channel membership and drive item
permissions. Exchange delegation (Send As, Send on Behalf, Full Access)
has no Graph API and is always unknown. Nothing is persisted.
"""

from __future__ import annotations

import math
import re
import time
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from hallpass.authx.jwt import PS256, Header, cert_thumbprint_sha256, new_jti, parse_certificate, parse_rsa_private_key, sign_jwt, standard_claims
from hallpass.authx.oauth2 import TokenError, classify_token_error, client_assertion, client_credentials
from hallpass.authx.token import Token, TokenSource
from hallpass.authx.util import go_json_loads, go_sprint
from hallpass.core import jsonx
from hallpass.core.catalog import Action
from hallpass.core.context import Context
from hallpass.core.decision import (
    Code,
    Decision,
    HallpassError,
    allowed,
    denied,
    errorf,
    unsupported,
    user_ambiguous,
    user_not_found,
    wrap_error,
)
from hallpass.core.errors import as_error, go_lower, go_quote, go_trim_space, is_error
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
    validate_https_url,
)
from hallpass.core.secret import SecretError
from hallpass.integrations.microsoft365.actions import EMAIL_RE, GUID_RE, Ref, catalog_actions, parse_ref
from hallpass.net import httpx

__all__ = [
    "ASSERTION_TTL",
    "CHECK_BATCH",
    "DEFAULT_AUTHORITY",
    "DEFAULT_GRAPH",
    "USER_SELECT",
    "GraphUser",
    "Microsoft365",
    "Microsoft365Connection",
    "error_code",
    "odata_string",
    "query_escape",
]

DEFAULT_AUTHORITY = "https://login.microsoftonline.com"
DEFAULT_GRAPH = "https://graph.microsoft.com"
ASSERTION_TTL = 5 * 60.0
# The maximum number of ids checkMemberGroups accepts.
CHECK_BATCH = 20
USER_SELECT = "id,userPrincipalName,mail,accountEnabled,userType,displayName"

_DOMAIN_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?)+")


def validate_tenant(v: str) -> None:
    if GUID_RE.fullmatch(v) or _DOMAIN_RE.fullmatch(v):
        return
    raise ValueError("must be a GUID or a domain name")


def validate_guid(v: str) -> None:
    if GUID_RE.fullmatch(v):
        return
    raise ValueError("must be a GUID")


# -- Go string helpers ---------------------------------------------------------


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


def query_escape(s: str) -> str:
    """Encode an OData literal for a query string. Spaces become %20 rather
    than '+', which OData parsers do not always decode."""
    return urllib.parse.quote_plus(s, safe="-_.~").replace("+", "%20")


def odata_string(s: str) -> str:
    """Quote a string literal for $filter: ' is doubled."""
    return "'" + s.replace("'", "''") + "'"


def _opt(d: dict[str, Any], key: str) -> Any:
    """The member for key as Go's decoder finds it, or None."""
    return jsonx.get(d, key)


def _opt_bool(d: dict[str, Any], key: str) -> bool | None:
    """A *bool field: None when absent or null."""
    if _opt(d, key) is None:
        return None
    return jsonx.b(d, key)


# -- the integration -----------------------------------------------------------


class Microsoft365(Integration):
    """The microsoft365 product."""

    def name(self) -> str:
        return "microsoft365"

    def fields(self) -> list[Field]:
        return [
            Field(
                name="tenant_id",
                required=True,
                validate=validate_tenant,
                description="Entra tenant: a GUID or a verified domain such as contoso.onmicrosoft.com",
            ),
            Field(name="client_id", required=True, validate=validate_guid, description="application (client) id of the app registration"),
            credential_field(True, "client secret, or the PEM private key when certificate_file is set"),
            Field(
                name="certificate_file",
                description="path to the PEM public certificate; when set hallpass authenticates with a certificate assertion",
            ),
            Field(
                name="authority_url",
                default=DEFAULT_AUTHORITY,
                validate=validate_https_url,
                description="Entra authority; national clouds use login.microsoftonline.us or login.chinacloudapi.cn",
            ),
            Field(
                name="url",
                default=DEFAULT_GRAPH,
                validate=validate_https_url,
                description="Microsoft Graph endpoint; national clouds use graph.microsoft.us, dod-graph.microsoft.us or microsoftgraph.chinacloudapi.cn",
            ),
        ]

    def actions(self) -> list[Action]:
        return catalog_actions()

    def new(self, ctx: Context, s: Settings, d: Deps) -> Connection:
        """Build a connection. It touches no network."""
        hc = d.http_client(s)
        if s.secret("credential").is_zero():
            raise ValueError("credential is required")
        tenant = s.get("tenant_id")
        client_id = s.get("client_id")
        if tenant == "":
            raise ValueError("tenant_id is required")
        try:
            validate_tenant(tenant)
        except ValueError as e:
            raise ValueError(f"tenant_id: {e}") from e
        try:
            validate_guid(client_id)
        except ValueError as e:
            raise ValueError(f"client_id: {e}") from e
        now = d.now if d.now is not None else time.time
        authority = s.get("authority_url").rstrip("/")
        if authority == "":
            authority = DEFAULT_AUTHORITY
        graph = s.get("url").rstrip("/")
        if graph == "":
            graph = DEFAULT_GRAPH
        return Microsoft365Connection(
            settings=s,
            tenant=tenant,
            client_id=client_id,
            cert_file=s.get("certificate_file"),
            token_url=authority + "/" + httpx.path_escape(tenant) + "/oauth2/v2.0/token",
            scope=graph + "/.default",
            now=now,
            hc=hc,
            logger=d.logger,
            graph_base=graph,
        )


# -- Graph records -------------------------------------------------------------


@dataclass(frozen=True)
class GraphUser:
    """The subset of microsoft.graph.user hallpass reads."""

    id: str = ""
    user_principal_name: str = ""
    mail: str = ""
    account_enabled: bool | None = None
    user_type: str = ""
    display_name: str = ""


def _graph_user(v: Any) -> GraphUser:
    d = jsonx.obj(v)
    return GraphUser(
        id=jsonx.s(d, "id"),
        user_principal_name=jsonx.s(d, "userPrincipalName"),
        mail=jsonx.s(d, "mail"),
        account_enabled=_opt_bool(d, "accountEnabled"),
        user_type=jsonx.s(d, "userType"),
        display_name=jsonx.s(d, "displayName"),
    )


@dataclass(frozen=True)
class _ConversationMember:
    user_id: str
    roles: list[str]


@dataclass
class _IdentitySet:
    # Each is the principal's id, or None when the set has no such principal.
    user: str | None = None
    group: str | None = None
    site_group: str | None = None
    site_user: str | None = None


def _id_ref(d: dict[str, Any], key: str) -> str | None:
    v = _opt(d, key)
    if v is None:
        return None
    return jsonx.s(jsonx.obj(v), "id")


def _identity_set(v: Any) -> _IdentitySet:
    d = jsonx.obj(v)
    return _IdentitySet(_id_ref(d, "user"), _id_ref(d, "group"), _id_ref(d, "siteGroup"), _id_ref(d, "siteUser"))


@dataclass
class _DrivePermission:
    roles: list[str]
    granted_to_v2: _IdentitySet | None
    granted_to_identities_v2: list[_IdentitySet] = field(default_factory=list)
    # The sharing link's scope, or None without a link.
    link: str | None = None


def _drive_permission(v: Any) -> _DrivePermission:
    d = jsonx.obj(v)
    g = _opt(d, "grantedToV2")
    link = _opt(d, "link")
    return _DrivePermission(
        roles=jsonx.strs(d, "roles"),
        granted_to_v2=None if g is None else _identity_set(g),
        granted_to_identities_v2=[_identity_set(x) for x in jsonx.arr(d, "grantedToIdentitiesV2")],
        link=None if link is None else jsonx.s(jsonx.obj(link), "scope"),
    )


LEVEL_NONE, LEVEL_READ, LEVEL_WRITE, LEVEL_OWNER = 0, 1, 2, 3


def level(roles: list[str]) -> tuple[int, bool]:
    """Collapse Graph roles to read/write/owner. SharePoint custom permission
    levels appear as other strings ("sp.full control", "sp.views"); they add
    nothing to the level but are reported as unknown, since they may grant
    more than the recognised roles say."""
    best, unknown = LEVEL_NONE, False
    for r in roles:
        lr = go_lower(r)
        if lr == "owner":
            lv = LEVEL_OWNER
        elif lr == "write":
            lv = LEVEL_WRITE
        elif lr == "read":
            lv = LEVEL_READ
        else:
            lv = LEVEL_NONE
            unknown = True
        best = max(best, lv)
    return best, unknown


def needed(action: str) -> int:
    if action == "file.read":
        return LEVEL_READ
    if action == "file.edit":
        return LEVEL_WRITE
    if action == "file.delete":
        # UNVERIFIED: write on the item is assumed to include delete;
        # SharePoint "contribute without delete" levels are not
        # distinguishable.
        return LEVEL_WRITE
    return LEVEL_OWNER  # file.share


def verb(action: str) -> str:
    return action.removeprefix("file.")


def level_name(lv: int) -> str:
    return {LEVEL_OWNER: "owner", LEVEL_WRITE: "write", LEVEL_READ: "read"}.get(lv, "no")


def _has_owner(ms: list[_ConversationMember]) -> bool:
    return any(equal_fold(r, "owner") for m in ms for r in m.roles)


def error_code(err: BaseException | None) -> str:
    """error.code from a Graph error body snippet. The message is never used."""
    se = as_error(err, httpx.StatusError)
    if se is None:
        return ""
    try:
        return jsonx.s(jsonx.o(jsonx.obj(go_json_loads(se.snippet)), "error"), "code")
    except (ValueError, RecursionError):
        # The snippet may be cut; try the code alone.
        i = se.snippet.find('"code"')
        if i < 0:
            return ""
        rest = se.snippet[i + len('"code"') :].lstrip(" :")
        if not rest.startswith('"'):
            return ""
        rest = rest[1:]
        j = rest.find('"')
        return rest[:j] if j >= 0 else ""


def classify_token(err: BaseException) -> HallpassError:
    """Map a token endpoint failure. A 429 or 5xx from the endpoint is
    transient, not a credential problem."""
    te = as_error(err, TokenError)
    if te is not None:
        if te.status == 429:
            return wrap_error(Code.UPSTREAM_RATE_LIMIT, err, "the token endpoint rate limited hallpass")
        if te.status >= 500:
            return wrap_error(Code.UPSTREAM_ERROR, err, f"the token endpoint failed (HTTP {te.status})")
    return classify_token_error(err)


def _resource_not_visible(what: str) -> Callable[[], BaseException]:
    return lambda: errorf(Code.RESOURCE_NOT_VISIBLE, f"{what} was not found or is not visible to hallpass")


class _UserNotFound(Exception):
    """The direct user lookup answered 404."""


class _DriveNotFound(Exception):
    """A 404 on the drive-owner lookup, which is ignored."""


# The application permissions the checks need.
REQUIRED_ROLES = ("User.Read.All", "GroupMember.Read.All", "TeamMember.Read.All", "ChannelMember.Read.All", "Files.Read.All")


def identity_of(u: GraphUser) -> Identity:
    """The identity. account_enabled is "true", "false" or, when Graph did
    not report accountEnabled at all, "unknown": a missing value is never
    taken as enabled."""
    enabled = "unknown" if u.account_enabled is None else go_sprint(u.account_enabled)
    return Identity(
        id=u.id,
        display=u.user_principal_name or u.id,
        attrs={
            "upn": u.user_principal_name,
            "mail": u.mail,
            "account_enabled": enabled,
            "user_type": u.user_type,
            "guest": go_sprint(equal_fold(u.user_type, "Guest")),
        },
        native=u,
    )


class Microsoft365Connection(Connection):
    """One Entra tenant reached through one app registration."""

    def __init__(
        self,
        *,
        settings: Settings,
        tenant: str,
        client_id: str,
        cert_file: str,
        token_url: str,
        scope: str,
        now: Callable[[], float],
        hc: httpx.Transport,
        logger: Any,
        graph_base: str,
    ) -> None:
        self.settings = settings
        self.tenant = tenant
        self.client_id = client_id
        self.cert_file = cert_file
        self.token_url = token_url
        self.scope = scope
        self.now = now
        # The token endpoint.
        self.plain = httpx.Client(http=hc, logger=logger)
        self.tokens = TokenSource(fetch=self._fetch_token, now=now)
        # Graph, bearer.
        self.graph = httpx.Client(http=hc, base=graph_base, logger=logger, auth=httpx.bearer_auth(self.tokens.get))

    # -- authentication --

    def _fetch_token(self, ctx: Context) -> Token:
        """The client credentials grant, with the secret or with a PS256
        certificate assertion when certificate_file is set."""
        cred = self.settings.secret("credential")
        if self.cert_file == "":
            return client_credentials(self.plain, self.token_url, self.client_id, lambda _ctx: cred.get_string(), self.scope)(ctx)
        return client_assertion(self.plain, self.token_url, self.client_id, self._assertion, self.scope)(ctx)

    def _assertion(self, ctx: Context) -> str:
        """Sign the certificate credential JWT: PS256 with the x5t#S256
        thumbprint of the certificate, audience = the token endpoint."""
        try:
            with open(self.cert_file, "rb") as f:
                cert_pem = f.read()
        except (OSError, ValueError) as e:
            raise wrap_error(Code.CREDENTIAL_REJECTED, e, "certificate_file could not be read") from e
        try:
            cert = parse_certificate(cert_pem)
        except ValueError as e:
            raise wrap_error(Code.CREDENTIAL_REJECTED, e, "certificate_file is not a PEM certificate") from e
        try:
            key_pem = self.settings.secret("credential").get_string()
        except SecretError as e:
            raise wrap_error(Code.CREDENTIAL_REJECTED, e, "the private key could not be read") from e
        try:
            key = parse_rsa_private_key(key_pem.encode("utf-8", "surrogateescape"))
        except ValueError as e:
            raise wrap_error(Code.CREDENTIAL_REJECTED, e, "credential is not a PEM RSA private key") from e
        jti = new_jti()
        now = self.now()
        # UNVERIFIED: whether Entra still accepts RS256 with the legacy x5t
        # header; only PS256 + x5t#S256 is implemented.
        claims = standard_claims(
            aud=self.token_url,
            iss=self.client_id,
            sub=self.client_id,
            jti=jti,
            nbf=math.floor(now),
            iat=math.floor(now),
            exp=math.floor(now + ASSERTION_TTL),
        )
        return sign_jwt(key, Header(alg=PS256, x5t_s256=cert_thumbprint_sha256(cert)), claims)

    # -- Graph transport --

    def _do(self, ctx: Context, req: httpx.Request, not_found: Callable[[], BaseException] | None) -> httpx.Response:
        """One Graph call. A 401 invalidates the cached token and the call is
        retried once. 403 means hallpass lacks an application permission.
        not_found builds the error for a 404, which depends on context."""
        try:
            try:
                return self.graph.do(ctx, req)
            except Exception as e:
                if httpx.status(e) != 401:
                    raise
                self.tokens.invalidate()
                return self.graph.do(ctx, req)
        except Exception as err:
            if is_error(err, TokenError):
                raise classify_token(err)
            st = httpx.status(err)
            if st == 404 and not_found is not None:
                raise not_found()
            if st == 403:
                if error_code(err) == "Authorization_RequestDenied":
                    raise wrap_error(
                        Code.CREDENTIAL_REJECTED,
                        err,
                        "the app registration lacks an application permission for this call (Authorization_RequestDenied)",
                    )
                raise wrap_error(Code.CREDENTIAL_REJECTED, err, "Graph refused the call (HTTP 403)")
            he = httpx.classify(err)
            assert he is not None
            if he is err:
                raise
            raise he

    def _get_json(self, ctx: Context, path: str, header: dict[str, str] | None, not_found: Callable[[], BaseException] | None) -> Any:
        resp = self._do(ctx, httpx.Request(method="GET", path=path, header=header), not_found)
        try:
            return resp.json()
        except ValueError as e:
            raise wrap_error(Code.UPSTREAM_ERROR, e, "Graph returned an unreadable response") from e

    def _get_typed(
        self, ctx: Context, path: str, header: dict[str, str] | None, decode: Callable[[Any], Any], not_found: Callable[[], BaseException] | None
    ) -> Any:
        """GET and decode the body the way json.Unmarshal into a struct would."""
        v = self._get_json(ctx, path, header, not_found)
        try:
            return decode(v)
        except (ValueError, RecursionError) as e:
            raise wrap_error(Code.UPSTREAM_ERROR, e, "Graph returned an unreadable response") from e

    def _list(self, ctx: Context, path: str, header: dict[str, str] | None, not_found: Callable[[], BaseException] | None) -> list[Any]:
        """Every page of a collection. Graph's nextLink is absolute."""

        def page(v: Any) -> tuple[list[Any], str]:
            d = jsonx.obj(v)
            return jsonx.arr(d, "value"), jsonx.s(d, "@odata.nextLink")

        out: list[Any] = []
        n = 0
        while path != "":
            if n >= httpx.MAX_PAGES:
                raise wrap_error(Code.UPSTREAM_ERROR, httpx.TooManyPages(), "the Graph collection has too many pages")
            values, path = self._get_typed(ctx, path, header, page, not_found)
            out.extend(values)
            if path != "" and not path.startswith(self.graph.base + "/"):
                raise errorf(Code.UPSTREAM_ERROR, "Graph returned a nextLink outside the connection's url")
            n += 1
        return out

    # -- identity --

    def resolve_identity(self, ctx: Context, u: User) -> Identity:
        """Find the Entra user: by UPN or id, then by mail, then by proxy
        address."""
        email = go_trim_space(u.email)
        if not EMAIL_RE.fullmatch(email):
            raise errorf(Code.INVALID_REQUEST, f"user email {go_quote(email)} is not an address")

        def nf() -> BaseException:
            return _UserNotFound()

        try:
            user = self._get_typed(ctx, "/v1.0/users/" + httpx.path_escape(email) + "?$select=" + USER_SELECT, None, _graph_user, nf)
            return identity_of(user)
        except _UserNotFound:
            pass
        users = self._find_users(ctx, "mail eq " + odata_string(email), None)
        if not users:
            # UNVERIFIED: the proxyAddresses/any filter with ConsistencyLevel
            # eventual and $count=true is documented as an advanced query;
            # whether the smtp: prefix match needs lower-casing is not verified.
            users = self._find_users(ctx, "proxyAddresses/any(p:p eq " + odata_string("smtp:" + email) + ")", {"ConsistencyLevel": "eventual"})
        if len(users) == 0:
            raise user_not_found(f"no Entra user has {email} as UPN, mail or proxy address")
        if len(users) == 1:
            return identity_of(users[0])
        raise user_ambiguous(f"{len(users)} Entra users match {email}")

    def _find_users(self, ctx: Context, flt: str, header: dict[str, str] | None) -> list[GraphUser]:
        path = "/v1.0/users?$filter=" + query_escape(flt) + "&$select=" + USER_SELECT
        if header is not None:
            path += "&$count=true"
        raw = self._list(ctx, path, header, None)
        users = []
        for r in raw:
            try:
                users.append(_graph_user(r))
            except ValueError as e:
                raise wrap_error(Code.UPSTREAM_ERROR, e, "Graph returned an unreadable user") from e
        return users

    # -- checks --

    def check(self, ctx: Context, r: CheckRequest) -> Decision:
        t = parse_ref(r.action_name, r.resource)
        if not GUID_RE.fullmatch(r.identity.id):
            raise errorf(Code.INVALID_REQUEST, "identity id is not an Entra object id")
        who = r.identity.display
        if r.identity.attr("guest") == "true":
            who += " (guest account)"
        state = r.identity.attr("account_enabled")
        if state == "false":
            return denied(f"{who}: account disabled")
        if state != "true":
            return unsupported(f"{who}: Graph did not report whether the account is enabled")
        a = r.action_name
        if a == "user.active":
            if not self._is_self(r.identity, t.id):
                return unsupported(f"user.active is evaluated for the caller's own account only; {t.id} is another account")
            return allowed(f"{who}: account enabled")
        if a == "group.member":
            return self._check_group(ctx, r.identity, who, t.id)
        if a == "role.member":
            return self._check_role(ctx, r.identity, who, t.id)
        if a in ("team.member", "team.owner"):
            return self._check_team(ctx, a, r.identity, who, t)
        if a in ("channel.read", "channel.owner", "channel.message.post"):
            return self._check_channel(ctx, a, r.identity, who, t)
        if a in ("file.read", "file.edit", "file.share", "file.delete"):
            return self._check_file(ctx, a, r.identity, who, t)
        if a == "mail.send_as_self":
            if not self._is_self(r.identity, t.id):
                return unsupported(f"mailbox {t.id} is not {who}'s own; Send As, Send on Behalf and Full Access have no Graph API")
            if r.identity.attr("mail") == "":
                # An empty mail attribute does not prove there is no mailbox
                # (unlicensed users, on-premises mailboxes, sync lag).
                return unsupported(f"{who} has no mail attribute in Entra; whether a mailbox exists is unknown")
            return allowed(f"{who} may send from their own mailbox")
        if a in ("mail.send_as", "mail.send_on_behalf", "mailbox.full_access"):
            return unsupported(
                f"Send As, Send on Behalf and Full Access are Exchange delegations with no Graph API; hallpass cannot evaluate {a} on mailbox {t.id}"
            )
        if a in ("calendar.read", "calendar.write"):
            return unsupported(
                f"calendar delegation and folder permissions have no application-permission Graph API; hallpass cannot evaluate {a} on mailbox {t.id}"
            )
        raise errorf(Code.INVALID_REQUEST, f"unknown action {go_quote(a)}")

    def _is_self(self, ident: Identity, res: str) -> bool:
        """Whether the resource id names the resolved identity."""
        return any(v != "" and equal_fold(v, res) for v in (ident.id, ident.attr("upn"), ident.attr("mail")))

    def _check_member_groups(self, ctx: Context, user_id: str, group_ids: list[str]) -> set[str]:
        """Which of the given groups the user belongs to, transitively, in
        batches of 20. The matching ids come back lower-cased."""
        matched: set[str] = set()
        for start in range(0, len(group_ids), CHECK_BATCH):
            body = {"groupIds": group_ids[start : start + CHECK_BATCH]}
            resp = self._do(
                ctx,
                httpx.Request(method="POST", path="/v1.0/users/" + httpx.path_escape(user_id) + "/checkMemberGroups", json=body, idempotent=True),
                _resource_not_visible("user " + user_id),
            )
            try:
                values = jsonx.strs(jsonx.obj(resp.json()), "value")
            except (ValueError, RecursionError) as e:
                raise wrap_error(Code.UPSTREAM_ERROR, e, "Graph returned an unreadable checkMemberGroups response") from e
            matched.update(go_lower(g) for g in values)
        return matched

    def _group_visibility(self, ctx: Context, group_id: str) -> str:
        """The group's visibility. A 404 is resource_not_visible:
        checkMemberGroups alone cannot tell a group the user is not in from
        a group that does not exist."""

        def decode(v: Any) -> str:
            d = jsonx.obj(v)
            jsonx.s(d, "id")
            return jsonx.s(d, "visibility")

        # UNVERIFIED: GroupMember.Read.All is documented as sufficient for
        # GET /groups/{id}; visibility is null for security groups and
        # HiddenMembership only for Microsoft 365 groups created that way.
        return str(
            self._get_typed(
                ctx, "/v1.0/groups/" + httpx.path_escape(group_id) + "?$select=id,visibility", None, decode, _resource_not_visible("group " + group_id)
            )
        )

    def _check_group(self, ctx: Context, ident: Identity, who: str, group_id: str) -> Decision:
        visibility = self._group_visibility(ctx, group_id)
        matched = self._check_member_groups(ctx, ident.id, [group_id])
        if go_lower(group_id) in matched:
            return allowed(f"{who} is a transitive member of group {group_id}")
        if equal_fold(visibility, "HiddenMembership"):
            # UNVERIFIED: without Member.Read.Hidden, checkMemberGroups omits
            # hidden-membership groups rather than failing, so a miss proves
            # nothing.
            return unsupported(
                f"group {group_id} has hidden membership; checkMemberGroups omits it without Member.Read.Hidden, so {who}'s membership is unknown"
            )
        return denied(f"{who} is not a member of group {group_id}")

    def _check_role(self, ctx: Context, ident: Identity, who: str, template_id: str) -> Decision:
        # UNVERIFIED: the OData cast path transitiveMemberOf/microsoft.graph.directoryRole
        # with $select=roleTemplateId; role-assignable groups are covered by
        # the transitive expansion.
        try:
            raw = self._list(
                ctx,
                "/v1.0/users/" + httpx.path_escape(ident.id) + "/transitiveMemberOf/microsoft.graph.directoryRole?$select=roleTemplateId",
                None,
                _resource_not_visible("user " + ident.id),
            )
        except Exception as err:
            he = as_error(err, HallpassError)
            if he is not None and he.code == Code.CREDENTIAL_REJECTED:
                raise wrap_error(Code.CREDENTIAL_REJECTED, err, "reading directory roles needs RoleManagement.Read.Directory")
            raise
        for r in raw:
            try:
                rt = jsonx.s(jsonx.obj(r), "roleTemplateId")
            except ValueError:
                continue
            if equal_fold(rt, template_id):
                return allowed(f"{who} holds directory role template {template_id}")
        return denied(f"{who} does not hold directory role template {template_id} (eligible PIM assignments are not activated)")

    def _membership(self, ctx: Context, collection: str, user_id: str, not_found: Callable[[], BaseException]) -> list[_ConversationMember]:
        """The caller's membership records under a members collection. The
        filter is the documented userId filter, but the result is never
        trusted: only records whose userId is the caller's are kept, so an
        ignored or unsupported filter cannot turn the whole roster into a
        membership."""
        flt = "(microsoft.graph.aadUserConversationMember/userId eq " + odata_string(user_id) + ")"
        raw = self._list(ctx, collection + "?$filter=" + query_escape(flt), None, not_found)
        out = []
        for r in raw:
            try:
                d = jsonx.obj(r)
                m = _ConversationMember(jsonx.s(d, "userId"), jsonx.strs(d, "roles"))
            except ValueError as e:
                raise wrap_error(Code.UPSTREAM_ERROR, e, "Graph returned an unreadable member") from e
            if not equal_fold(m.user_id, user_id):
                continue
            out.append(m)
        return out

    def _check_team(self, ctx: Context, action: str, ident: Identity, who: str, t: Ref) -> Decision:
        ms = self._membership(ctx, "/v1.0/teams/" + httpx.path_escape(t.id) + "/members", ident.id, _resource_not_visible("team " + t.id))
        if not ms:
            return denied(f"{who} is not a member of team {t.id}")
        if action == "team.owner":
            if _has_owner(ms):
                return allowed(f"{who} owns team {t.id}")
            return denied(f"{who} is a member but not an owner of team {t.id}")
        return allowed(f"{who} is a member of team {t.id}")

    def _check_channel(self, ctx: Context, action: str, ident: Identity, who: str, t: Ref) -> Decision:
        base = "/v1.0/teams/" + httpx.path_escape(t.id) + "/channels/" + httpx.path_escape(t.channel)
        not_found = _resource_not_visible(t.describe())

        def decode(v: Any) -> tuple[str, str | None]:
            d = jsonx.obj(v)
            mod = _opt(d, "moderationSettings")
            restr = None if mod is None else jsonx.s(jsonx.obj(mod), "userNewMessageRestriction")
            return jsonx.s(d, "membershipType"), restr

        membership_type, restriction = self._get_typed(ctx, base, None, decode, not_found)
        kind = go_lower(membership_type)
        if kind == "standard":
            ms = self._membership(ctx, "/v1.0/teams/" + httpx.path_escape(t.id) + "/members", ident.id, _resource_not_visible("team " + t.id))
        elif kind == "private":
            ms = self._membership(ctx, base + "/members", ident.id, not_found)
        elif kind == "shared":
            # UNVERIFIED: /allMembers lists direct and team-shared members of
            # a shared channel; the userId filter is assumed to apply there too.
            ms = self._membership(ctx, base + "/allMembers", ident.id, not_found)
        elif kind == "":
            # A missing membershipType is not assumed to be standard: the team
            # roster would be the wrong answer for a private or shared channel.
            return unsupported(f"channel {t.channel} reports no membership type; hallpass cannot tell which roster applies")
        else:
            return unsupported(f"channel {t.channel} has membership type {go_quote(membership_type)}, which hallpass does not model")
        what = t.describe()
        if not ms:
            return denied(f"{who} is not a member of {what} ({kind} channel)")
        if action == "channel.owner":
            if _has_owner(ms):
                return allowed(f"{who} owns {what} ({kind} channel)")
            return denied(f"{who} is a member but not an owner of {what} ({kind} channel)")
        if action == "channel.message.post":
            if restriction is not None and restriction != "" and not equal_fold(restriction, "everyone"):
                return unsupported(f"{what} restricts new messages to {restriction}; hallpass does not evaluate channel moderation")
            return allowed(f"{who} is a member of {what} ({kind} channel); channel moderation settings are not evaluated")
        return allowed(f"{who} is a member of {what} ({kind} channel)")

    # -- files --

    def _check_file(self, ctx: Context, action: str, ident: Identity, who: str, t: Ref) -> Decision:
        what = t.describe()
        not_found = _resource_not_visible(what)
        item_path = "/v1.0/drives/" + httpx.path_escape(t.id) + "/items/" + httpx.path_escape(t.item)
        raw = self._list(ctx, item_path + "/permissions", None, not_found)
        perms = []
        for r in raw:
            try:
                perms.append(_drive_permission(r))
            except ValueError as e:
                raise wrap_error(Code.UPSTREAM_ERROR, e, "Graph returned an unreadable permission") from e
        need = needed(action)
        guest = ident.attr("guest") == "true"
        direct = LEVEL_NONE
        org_link = LEVEL_NONE
        group_levels: dict[str, int] = {}
        # group_unknown marks groups whose grant carries an unrecognised role.
        group_unknown: dict[str, bool] = {}
        # unknown_role is set when a grant that reaches the caller (directly,
        # via a group they are in, or via a usable organization link) carries
        # a role hallpass does not model; the answer is then unknown, not deny.
        unknown_role = False
        unknown_scope = ""
        site_group = anonymous = guest_org_link = False
        for p in perms:
            lv, unk = level(p.roles)
            sets = list(p.granted_to_identities_v2)
            if p.granted_to_v2 is not None:
                sets.append(p.granted_to_v2)
            for s in sets:
                if s.user is not None and equal_fold(s.user, ident.id):
                    direct = max(direct, lv)
                    unknown_role = unknown_role or unk
                elif s.group is not None and GUID_RE.fullmatch(s.group):
                    g = go_lower(s.group)
                    group_levels[g] = max(group_levels.get(g, LEVEL_NONE), lv)
                    group_unknown[g] = group_unknown.get(g, False) or unk
                elif s.site_group is not None:
                    site_group = True
                elif s.site_user is not None and s.user is None:
                    # A SharePoint-only principal (for example a claims login)
                    # that Graph could not map to an Entra user.
                    site_group = True
            if p.link is not None:
                scope = go_lower(p.link)
                if scope == "organization":
                    if guest:
                        # UNVERIFIED: "people in your organization" links cannot
                        # be redeemed by guest (B2B) accounts, as Microsoft's
                        # sharing documentation states; the link is not
                        # credited to a guest.
                        guest_org_link = True
                        continue
                    org_link = max(org_link, lv)
                    unknown_role = unknown_role or unk
                elif scope == "anonymous":
                    anonymous = True
                elif scope == "users":
                    # The people the link was sent to are listed in
                    # grantedToIdentitiesV2 and handled above.
                    pass
                else:
                    unknown_scope = p.link
        v = verb(action)
        if direct >= need:
            return allowed(f"{who} may {v} {what}: granted directly")

        # UNVERIFIED: drives/{id}?$select=owner exposes owner.user.id for
        # OneDrive; SharePoint document libraries report the site (group)
        # instead.
        def owner_of(val: Any) -> _IdentitySet | None:
            o = _opt(jsonx.obj(val), "owner")
            return None if o is None else _identity_set(o)

        def drive_nf() -> BaseException:
            return _DriveNotFound()

        try:
            owner = self._get_typed(ctx, "/v1.0/drives/" + httpx.path_escape(t.id) + "?$select=owner", None, owner_of, drive_nf)
        except _DriveNotFound:
            # The item's permissions were readable, so a 404 on the drive
            # itself only means the owner rule cannot apply; the group and
            # link rules still can.
            pass
        else:
            if owner is not None and owner.user is not None and equal_fold(owner.user, ident.id):
                return allowed(f"{who} may {v} {what}: owner of the drive")
        if group_levels:
            matched = self._check_member_groups(ctx, ident.id, list(group_levels))
            via_group = LEVEL_NONE
            for g in matched:
                via_group = max(via_group, group_levels.get(g, LEVEL_NONE))
                unknown_role = unknown_role or group_unknown.get(g, False)
            if via_group >= need:
                return allowed(f"{who} may {v} {what}: granted to a group they belong to")
            direct = max(direct, via_group)
        if org_link >= need:
            return allowed(f"{who} may {v} {what} via an organization-wide sharing link")
        direct = max(direct, org_link)
        if unknown_role:
            return unsupported(
                f"{who} is granted a role on {what} that hallpass does not model (a custom SharePoint permission level); their access is unknown"
            )
        if unknown_scope != "":
            return unsupported(f"{what} has a sharing link with scope {go_quote(unknown_scope)}, which hallpass does not model; {who}'s access is unknown")
        if action == "file.share" and direct >= LEVEL_READ:
            return unsupported(f"{who} has {level_name(direct)} access to {what} but is not an owner; sharing rights depend on site settings")
        if site_group:
            return unsupported(f"{what} is granted to SharePoint site groups, which Graph cannot expand; {who}'s access is unknown")
        if anonymous:
            return unsupported(f"{what} has an anonymous sharing link; {who}'s own access is unknown")
        if direct >= LEVEL_READ:
            return denied(f"{who} has {level_name(direct)} access to {what}, which does not include {v}")
        if guest_org_link:
            return denied(
                f"no permission on {what} is granted to {who} or a group they belong to; its organization-wide sharing link is not usable by guest accounts"
            )
        return denied(f"no permission on {what} is granted to {who} or a group they belong to")

    # -- probe --

    def probe(self, ctx: Context) -> ProbeResult:
        """Fetch a token, read the organization and report the granted
        application permissions."""

        def page_values(v: Any) -> list[Any]:
            d = jsonx.obj(v)
            jsonx.s(d, "@odata.nextLink")
            return jsonx.arr(d, "value")

        org = self._get_typed(ctx, "/v1.0/organization?$select=id,displayName", None, page_values, None)
        summary = "authenticated as application " + self.client_id
        if org:
            try:
                o = jsonx.obj(org[0])
                oid, name = jsonx.s(o, "id"), jsonx.s(o, "displayName")
            except ValueError:
                pass
            else:
                summary += f" in Microsoft 365 tenant {go_quote(name)} ({oid})"
        warnings: list[str] = []
        try:
            roles = self._granted_roles(ctx)
        except Exception:  # noqa: BLE001 - any failure is reported as a warning
            warnings.append("could not verify permissions: reading the app's own appRoleAssignments failed")
            return ProbeResult(summary=summary, warnings=tuple(warnings))
        have: set[str] = set()
        for r in roles:
            have.add(r)
            if ".ReadWrite." in r or r.endswith(".ReadWrite") or ".Read" not in r:
                warnings.append("application permission " + r + " allows writes; hallpass only needs read permissions")
        for r in REQUIRED_ROLES:
            if r not in have:
                warnings.append("application permission " + r + " is not granted; checks that need it will be unknown (credential_rejected)")
        if "Files.Read.All" in have:
            warnings.append("Files.Read.All lets this credential read every file in the tenant; keep the secret tightly held")
        if "Member.Read.Hidden" not in have:
            warnings.append("Member.Read.Hidden is not granted; hidden-membership groups are omitted, which can produce a false deny")
        return ProbeResult(summary=summary, warnings=tuple(warnings))

    def _granted_roles(self, ctx: Context) -> list[str]:
        """The application permission values granted to the app."""
        # UNVERIFIED: whether an app may read its own service principal and
        # appRoleAssignments with only the permissions listed in the doc;
        # Application.Read.All may be needed, in which case the probe warns.
        raw = self._list(ctx, "/v1.0/servicePrincipals?$filter=" + query_escape("appId eq " + odata_string(self.client_id)) + "&$select=id", None, None)
        if len(raw) != 1:
            raise ValueError(f"expected one service principal, got {len(raw)}")
        try:
            sp_id = jsonx.s(jsonx.obj(raw[0]), "id")
        except ValueError:
            sp_id = None
        if sp_id is None or not GUID_RE.fullmatch(sp_id):
            raise ValueError("service principal without an id")
        raw = self._list(ctx, "/v1.0/servicePrincipals/" + httpx.path_escape(sp_id) + "/appRoleAssignments", None, None)
        # Assignments carry role ids; the names live on the resource service
        # principal's appRoles.
        by_resource: dict[str, list[str]] = {}
        for r in raw:
            try:
                d = jsonx.obj(r)
                role_id, res_id = jsonx.s(d, "appRoleId"), jsonx.s(d, "resourceId")
            except ValueError:
                continue
            if GUID_RE.fullmatch(res_id):
                by_resource.setdefault(res_id, []).append(go_lower(role_id))
        out: list[str] = []
        for res_id, role_ids in by_resource.items():

            def decode(v: Any) -> dict[str, str]:
                names: dict[str, str] = {}
                for ar in jsonx.arr(jsonx.obj(v), "appRoles"):
                    ar = jsonx.obj(ar)
                    names[go_lower(jsonx.s(ar, "id"))] = jsonx.s(ar, "value")
                return names

            names = self._get_typed(ctx, "/v1.0/servicePrincipals/" + httpx.path_escape(res_id) + "?$select=appRoles", None, decode, None)
            for rid in role_ids:
                v = names.get(rid, "")
                if v != "":
                    out.append(v)
        return out
