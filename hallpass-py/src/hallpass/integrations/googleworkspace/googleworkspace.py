"""Checks Directory, Drive, Calendar, Gmail and Groups facts through the
Google Workspace APIs.

hallpass authenticates as a service account with domain-wide delegation.
Directory calls impersonate an admin (admin_email) with read-only scopes;
Drive, Calendar and Gmail calls impersonate the user being asked about, so
Google itself evaluates the user's access. One token is minted per
(impersonated user, scope) and cached. Nothing is persisted.
"""

from __future__ import annotations

import dataclasses
import math
import re
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from hallpass.authx.google import GoogleServiceAccountKey, google_error_reason, google_metadata_token, parse_google_service_account_key
from hallpass.authx.jwt import RS256, Header, sign_jwt
from hallpass.authx.oauth2 import TokenError, classify_token_error, jwt_bearer
from hallpass.authx.token import Token, TokenSource
from hallpass.authx.util import StructDict, go_json_marshal, go_sprint
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
    unknown_decision,
    unsupported,
    user_not_found,
    wrap_error,
)
from hallpass.core.errors import as_error, go_lower, go_quote, go_trim_space
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
from hallpass.integrations.googleworkspace.actions import ACTION_INDEX, ACTION_LIST, EMAIL_RE, catalog_actions, parse_ref
from hallpass.net import httpx

__all__ = [
    "ASSERTION_TTL",
    "DEFAULT_API",
    "DEFAULT_IAM_CREDS",
    "DEFAULT_METADATA",
    "DEFAULT_TOKEN_URL",
    "MAX_SOURCES",
    "MODE_KEY",
    "MODE_KEYLESS",
    "SCOPE_CALENDAR",
    "SCOPE_DIRECTORY_GROUP",
    "SCOPE_DIRECTORY_USER",
    "SCOPE_DRIVE",
    "SCOPE_GMAIL_SETTINGS",
    "GoogleWorkspace",
    "GoogleWorkspaceConnection",
    "validate_http_url",
]

DEFAULT_TOKEN_URL = "https://oauth2.googleapis.com/token"
DEFAULT_API = "https://www.googleapis.com"
DEFAULT_METADATA = "http://metadata.google.internal"
DEFAULT_IAM_CREDS = "https://iamcredentials.googleapis.com"

SCOPE_DIRECTORY_USER = "https://www.googleapis.com/auth/admin.directory.user.readonly"
SCOPE_DIRECTORY_GROUP = "https://www.googleapis.com/auth/admin.directory.group.member.readonly"
SCOPE_DRIVE = "https://www.googleapis.com/auth/drive.metadata.readonly"
SCOPE_CALENDAR = "https://www.googleapis.com/auth/calendar.calendarlist.readonly"
SCOPE_GMAIL_SETTINGS = "https://www.googleapis.com/auth/gmail.settings.basic"

MODE_KEY = "key"
MODE_KEYLESS = "keyless"

ASSERTION_TTL = 3600.0
# Bounds the per-(sub, scope) token cache.
MAX_SOURCES = 500

_CUSTOMER_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")


def validate_email(v: str) -> None:
    if v == "" or EMAIL_RE.fullmatch(v):
        return
    raise ValueError("must be an email address")


def validate_customer(v: str) -> None:
    if v == "" or _CUSTOMER_RE.fullmatch(v):
        return
    raise ValueError("must be a customer id or my_customer")


def validate_http_url(v: str) -> None:
    """validate_https_url that also accepts plain http://, for the
    link-local metadata server."""
    if v.startswith("http://") and not any(c in v for c in " \t\r\n#?"):
        return
    validate_https_url(v)


# -- Go helpers ----------------------------------------------------------------


def _fold(c: str) -> str:
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


def _opt_bool(d: dict[str, Any], key: str) -> bool | None:
    """A *bool field: None when absent or null."""
    if jsonx.get(d, key) is None:
        return None
    return jsonx.b(d, key)


def bool_attr(b: bool | None) -> str:
    """An optional boolean as an identity attribute: "true", "false" or
    "unknown" when the Directory did not send the field."""
    return "unknown" if b is None else go_sprint(b)


# -- the integration -----------------------------------------------------------


class GoogleWorkspace(Integration):
    """The googleworkspace product."""

    def name(self) -> str:
        return "googleworkspace"

    def fields(self) -> list[Field]:
        return [
            credential_field(False, "service-account key JSON (file:); required in auth_mode key"),
            Field(
                name="admin_email",
                required=True,
                validate=validate_email,
                description="Workspace admin impersonated for Directory calls; give it a custom role with Users > Read and Groups > Read only",
            ),
            Field(
                name="customer_id",
                default="my_customer",
                validate=validate_customer,
                description="Workspace customer id; my_customer means the service account's own",
            ),
            Field(
                name="auth_mode",
                default=MODE_KEY,
                enum=(MODE_KEY, MODE_KEYLESS),
                description="key: sign with the key JSON; keyless: sign with the IAM Credentials API from a GCE/GKE identity",
            ),
            Field(name="service_account_email", validate=validate_email, description="service account to sign as in auth_mode keyless"),
            Field(
                name="enable_gmail_settings",
                default="false",
                enum=("true", "false"),
                description="evaluate mail.send_as and mail.delegate_access with the gmail.settings.basic scope, which can also write settings",
            ),
            Field(name="token_url", default=DEFAULT_TOKEN_URL, validate=validate_https_url, description="OAuth token endpoint"),
            Field(
                name="api_url",
                default=DEFAULT_API,
                validate=validate_https_url,
                description="Google APIs endpoint; the Admin SDK is addressed under it as /admin/directory/v1",
            ),
            Field(name="metadata_url", default=DEFAULT_METADATA, validate=validate_http_url, description="GCE metadata server, auth_mode keyless only"),
            Field(
                name="iamcredentials_url",
                default=DEFAULT_IAM_CREDS,
                validate=validate_https_url,
                description="IAM Credentials API endpoint, auth_mode keyless only",
            ),
        ]

    def actions(self) -> list[Action]:
        return catalog_actions()

    def new(self, ctx: Context, s: Settings, d: Deps) -> Connection:
        """Build a connection. It touches no network; the key is read when a
        token is minted, so a rotated key file takes effect."""
        hc = d.http_client(s)
        return GoogleWorkspaceConnection(s, d, hc)


@dataclass(frozen=True)
class DirectoryUser:
    """The subset of the Directory user resource hallpass reads."""

    id: str = ""
    primary_email: str = ""
    # None when absent, so an absent field is not mistaken for an active
    # account.
    suspended: bool | None = None
    archived: bool | None = None
    full_name: str = ""


def _directory_user(v: Any) -> DirectoryUser:
    d = jsonx.obj(v)
    return DirectoryUser(
        id=jsonx.s(d, "id"),
        primary_email=jsonx.s(d, "primaryEmail"),
        suspended=_opt_bool(d, "suspended"),
        archived=_opt_bool(d, "archived"),
        full_name=jsonx.s(jsonx.o(d, "name"), "fullName"),
    )


# The 403 reasons that mean "slow down".
RATE_LIMIT_REASONS = frozenset({"rateLimitExceeded", "userRateLimitExceeded", "quotaExceeded", "dailyLimitExceeded", "sharingRateLimitExceeded"})

# The 403 reasons that are about the impersonated user or the resource (a
# Drive or Workspace policy, a file's sharing settings), not about
# hallpass's credential. They are not a deny: Google blocked the metadata
# call, it did not evaluate the action asked about.
USER_LEVEL_REASONS = frozenset(
    {
        "insufficientFilePermissions",
        "domainPolicy",
        "appNotAuthorizedToFile",
        "cannotDownloadAbusiveFile",
        "fileOwnerNotMemberOfSharedDrive",
        "fileOwnerNotMemberOfTeamDrive",
        "sharedDriveMembershipRequired",
        "teamDriveMembershipRequired",
        "cannotModifyInheritedTeamDrivePermission",
        "failedPrecondition",
        "storageQuotaExceeded",
    }
)

# The 403 reasons that mean hallpass's own setup is wrong: the scope is not
# delegated, the API is not enabled in the project, or the admin role lacks
# the privilege.
CREDENTIAL_REASONS = frozenset({"insufficientPermissions", "accessNotConfigured", "forbidden"})


def reason(err: BaseException | None) -> str:
    """errors[].reason from a Google error body snippet. The message is
    never used."""
    return google_error_reason(err)


def classify(err: BaseException) -> HallpassError:
    """Map an API error to an integration error. A 403 is split by
    errors[].reason: rate limits, user-level refusals (unsupported) and
    everything else, which is taken to be hallpass's credential or scope
    (credential_rejected), including a 403 without a reason."""
    if httpx.status(err) == 403:
        r = reason(err)
        if r in RATE_LIMIT_REASONS:
            return wrap_error(Code.UPSTREAM_RATE_LIMIT, err, "rate limited by Google")
        if r in USER_LEVEL_REASONS:
            return wrap_error(
                Code.UNSUPPORTED,
                err,
                f"Google refused the call for this user ({r}): a Drive or Workspace policy blocks it, so hallpass cannot evaluate the action",
            )
        if r in CREDENTIAL_REASONS:
            return wrap_error(
                Code.CREDENTIAL_REJECTED,
                err,
                f"Google refused the call: the scope is not delegated, the API is not enabled, or the admin role lacks the privilege ({r})",
            )
        if r == "":
            return wrap_error(Code.CREDENTIAL_REJECTED, err, "Google refused the call (HTTP 403)")
        return wrap_error(Code.CREDENTIAL_REJECTED, err, f"Google refused the call (HTTP 403, {r})")
    he = httpx.classify(err)
    assert he is not None
    return he


# The calendarList accessRole values, ordered.
ACCESS_RANK = {"freeBusyReader": 1, "reader": 2, "writerWithoutPrivateAccess": 3, "writer": 4, "owner": 5}

CAPABILITY_FIELDS = "capabilities(canDownload,canEdit,canComment,canShare,canTrash,canDelete,canRename,canCopy,canAddChildren,canListChildren),trashed"


def _reason_or(r: str, fallback: str) -> str:
    return fallback if r == "" else r


def gmail_refused(err: BaseException, sub: str) -> Decision:
    """Map a failed Gmail settings call made as sub. Gmail is asked as the
    account itself, so a refusal is about that account (no Gmail licence,
    mailbox not set up, a Workspace policy) unless the reason names
    hallpass's credential; none of it is a deny of the action."""
    he = as_error(err, HallpassError)
    if he is not None and he.code == Code.UNSUPPORTED:
        return unsupported(f"could not act as {sub} to read its Gmail settings: not a Workspace account, suspended, or the scope is missing")
    r = reason(err)
    st = httpx.status(err)
    if st == 404:
        return unsupported(f"Gmail answered 404 for {sub}: the account may have no Gmail mailbox")
    if st == 400 and r == "failedPrecondition":
        # UNVERIFIED: an account without a Gmail licence is assumed to answer
        # 400 failedPrecondition ("Mail service not enabled").
        return unsupported(f"Gmail is not enabled for {sub}")
    # UNVERIFIED: a Gmail 403 forbidden or without a reason as the user
    # ("Delegation denied for <user>") is assumed to be about that account,
    # not hallpass's credential; only insufficientPermissions and
    # accessNotConfigured are.
    if st == 403 and r not in RATE_LIMIT_REASONS and r != "insufficientPermissions" and r != "accessNotConfigured":
        return unsupported(f"Gmail refused the call as {sub} ({_reason_or(r, 'no reason')}): the account may have no Gmail licence or a policy blocks it")
    raise classify(err)


class GoogleWorkspaceConnection(Connection):
    """One Workspace customer reached through one service account."""

    def __init__(self, s: Settings, d: Deps, hc: httpx.Transport) -> None:
        self.settings = s
        self.admin = go_lower(s.get("admin_email"))
        self.customer = s.get("customer_id")
        self.mode = s.get("auth_mode")
        self.sa_email = go_lower(s.get("service_account_email"))
        self.gmail = s.bool("enable_gmail_settings", False)
        self.token_url = s.get("token_url").rstrip("/")
        self.metadata_url = s.get("metadata_url").rstrip("/")
        self.iam_creds_url = s.get("iamcredentials_url").rstrip("/")
        self.now: Callable[[], float] = d.now if d.now is not None else time.time
        # "config" or "key" (use the key's token_uri).
        self.token_url_from = "config"
        self._mu = threading.Lock()
        self.sources: dict[tuple[str, str], TokenSource] = {}
        self.order: list[tuple[str, str]] = []
        if self.admin == "" or not EMAIL_RE.fullmatch(self.admin):
            raise ValueError("admin_email is required and must be an email address")
        if self.customer == "":
            self.customer = "my_customer"
        if not _CUSTOMER_RE.fullmatch(self.customer):
            raise ValueError("customer_id must be a customer id or my_customer")
        if self.mode == "":
            self.mode = MODE_KEY
        if self.mode == MODE_KEY:
            if s.secret("credential").is_zero():
                raise ValueError("credential is required in auth_mode key")
        elif self.mode == MODE_KEYLESS:
            if self.sa_email == "" or not EMAIL_RE.fullmatch(self.sa_email):
                raise ValueError("service_account_email is required in auth_mode keyless")
        else:
            raise ValueError(f"auth_mode {go_quote(self.mode)} must be key or keyless")
        if self.token_url == "":
            self.token_url_from = "key"
        if self.metadata_url == "":
            self.metadata_url = DEFAULT_METADATA
        if self.iam_creds_url == "":
            self.iam_creds_url = DEFAULT_IAM_CREDS
        api = s.get("api_url").rstrip("/")
        if api == "":
            api = DEFAULT_API
        # Token, metadata and IAM Credentials endpoints.
        self.plain = httpx.Client(http=hc, logger=d.logger)
        # Google APIs, per-call bearer.
        self.api = httpx.Client(http=hc, base=api, logger=d.logger)
        self.meta_tokens = TokenSource(fetch=self._fetch_metadata_token, now=self.now)

    # -- authentication --

    def source(self, sub: str, scope: str) -> TokenSource:
        """The cached token source for one (sub, scope)."""
        k = (go_lower(sub), scope)
        with self._mu:
            ts = self.sources.get(k)
            if ts is not None:
                return ts
            ts = TokenSource(now=self.now, fetch=lambda ctx: self._mint(ctx, k[0], k[1]))
            self.sources[k] = ts
            self.order.append(k)
            while len(self.order) > MAX_SOURCES:
                del self.sources[self.order[0]]
                self.order = self.order[1:]
            return ts

    def load_key(self) -> GoogleServiceAccountKey:
        try:
            raw = self.settings.secret("credential").get_string()
        except SecretError as e:
            raise wrap_error(Code.CREDENTIAL_REJECTED, e, "the service-account key could not be read") from e
        return parse_google_service_account_key(raw)

    def _mint(self, ctx: Context, sub: str, scope: str) -> Token:
        """An access token for (sub, scope)."""
        sign: Callable[[Context, bytes], str]
        if self.mode == MODE_KEYLESS:
            iss, token_url = self.sa_email, self.token_url
            if token_url == "":
                token_url = DEFAULT_TOKEN_URL
            sign = self._sign_with_iam
        else:
            k = self.load_key()
            iss, token_url = k.client_email, self.token_url
            if self.token_url_from == "key" and k.token_uri != "":
                try:
                    validate_https_url(k.token_uri)
                except ValueError as e:
                    raise wrap_error(Code.CREDENTIAL_REJECTED, e, "the key's token_uri is not an https URL") from e
                token_url = k.token_uri
            if token_url == "":
                token_url = DEFAULT_TOKEN_URL

            def sign(_ctx: Context, payload: bytes) -> str:
                return sign_jwt(k.key, Header(alg=RS256, kid=k.private_key_id), payload)

        now = self.now()
        # The claims of the JWT bearer assertion: exactly one scope,
        # impersonating sub.
        payload = go_json_marshal(StructDict(iss=iss, scope=scope, aud=token_url, iat=math.floor(now), exp=math.floor(now + ASSERTION_TTL), sub=sub))
        return jwt_bearer(self.plain, token_url, lambda c: sign(c, payload), None)(ctx)

    def _fetch_metadata_token(self, ctx: Context) -> Token:
        """The attached service account's token from the GCE metadata server."""
        return google_metadata_token(ctx, self.plain, self.metadata_url, self.now)

    def _sign_with_iam(self, ctx: Context, payload: bytes) -> str:
        """Sign the assertion with the IAM Credentials API."""
        meta = self.meta_tokens.get(ctx)
        # UNVERIFIED: signJwt takes {"payload": "<claims JSON>"} and answers
        # {"keyId", "signedJwt"}; the metadata token needs
        # roles/iam.serviceAccountTokenCreator on the signing service account.
        try:
            resp = self.plain.do(
                ctx,
                httpx.Request(
                    method="POST",
                    path=self.iam_creds_url + "/v1/projects/-/serviceAccounts/" + httpx.path_escape(self.sa_email) + ":signJwt",
                    json={"payload": payload.decode("utf-8", "surrogateescape")},
                    header={"Authorization": "Bearer " + meta},
                    idempotent=True,
                ),
            )
        except Exception as err:
            st = httpx.status(err)
            if st == 401:
                self.meta_tokens.invalidate()
                raise wrap_error(Code.CREDENTIAL_REJECTED, err, "the IAM Credentials API rejected the metadata token")
            if st in (403, 404):
                raise wrap_error(
                    Code.CREDENTIAL_REJECTED,
                    err,
                    f"the IAM Credentials API refused signJwt; the runtime identity needs roles/iam.serviceAccountTokenCreator on {self.sa_email}",
                )
            he = httpx.classify(err)
            assert he is not None
            if he is err:
                raise
            raise he
        try:
            signed = jsonx.s(jsonx.obj(resp.json()), "signedJwt")
        except (ValueError, RecursionError):
            signed = ""
        if signed == "":
            raise errorf(Code.UPSTREAM_ERROR, "signJwt returned no signedJwt")
        return signed

    def token_error(self, err: BaseException, sub: str) -> HallpassError:
        """Classify a minting failure. invalid_grant for the admin means
        delegation is misconfigured; for a user it means Google would not
        let hallpass act as that user, which is not a decision about the
        action."""
        te = as_error(err, TokenError)
        if te is not None:
            if te.status == 429:
                return wrap_error(Code.UPSTREAM_RATE_LIMIT, err, "the token endpoint rate limited hallpass")
            if te.status >= 500:
                return wrap_error(Code.UPSTREAM_ERROR, err, f"the token endpoint failed (HTTP {te.status})")
            if te.code in ("invalid_grant", "unauthorized_client"):
                if equal_fold(sub, self.admin):
                    return wrap_error(
                        Code.CREDENTIAL_REJECTED,
                        err,
                        f"could not act as admin_email: domain-wide delegation is missing the scope or admin_email is invalid ({te.code})",
                    )
                return wrap_error(Code.UNSUPPORTED, err, f"could not act as the user: suspended, or the delegation scope is missing ({te.code})")
        return classify_token_error(err)

    # -- API transport --

    def _call(self, ctx: Context, sub: str, scope: str, req: httpx.Request) -> httpx.Response:
        """One API request as sub with one scope. A 401 invalidates the
        token and retries once. The raised error is the raw httpx error so
        callers can branch on 404/400; classify maps everything else."""
        ts = self.source(sub, scope)

        def attempt() -> httpx.Response:
            try:
                tok = ts.get(ctx)
            except Exception as e:  # noqa: BLE001 - Go: the error is decided on or classified
                raise self.token_error(e, sub)
            h = req.header.clone() if isinstance(req.header, httpx.Headers) else httpx.Headers(req.header or {})
            h.set("Authorization", "Bearer " + tok)
            return self.api.do(ctx, dataclasses.replace(req, header=h))

        try:
            return attempt()
        except Exception as e:
            if httpx.status(e) != 401:
                raise
            ts.invalidate()
            return attempt()

    def _get_json(self, ctx: Context, sub: str, scope: str, path: str, q: Mapping[str, str] | None, decode: Callable[[Any], Any]) -> Any:
        resp = self._call(ctx, sub, scope, httpx.Request(method="GET", path=path, query=q))
        try:
            return decode(resp.json())
        except (ValueError, RecursionError) as e:
            raise wrap_error(Code.UPSTREAM_ERROR, e, "Google returned an unreadable response") from e

    # -- identity --

    def resolve_identity(self, ctx: Context, u: User) -> Identity:
        """Look the email up in the Directory as the admin. The primary
        email becomes the identity, and the sub for user-scoped calls."""
        email = go_lower(go_trim_space(u.email))
        if not EMAIL_RE.fullmatch(email):
            raise errorf(Code.INVALID_REQUEST, f"user email {go_quote(email)} is not an address")
        q = {"projection": "basic", "viewType": "admin_view"}
        try:
            du = self._get_json(ctx, self.admin, SCOPE_DIRECTORY_USER, "/admin/directory/v1/users/" + httpx.path_escape(email), q, _directory_user)
        except Exception as err:  # noqa: BLE001 - Go: the error is decided on or classified
            if httpx.status(err) == 404:
                raise user_not_found(f"no Workspace account for {email} (aliases resolve; external accounts do not)")
            raise classify(err)
        primary = go_lower(du.primary_email)
        if not EMAIL_RE.fullmatch(primary):
            raise errorf(Code.UPSTREAM_ERROR, "the Directory returned a user without a primary email")
        return Identity(
            id=primary,
            display=primary,
            attrs={
                "id": du.id,
                # UNVERIFIED: the Directory is assumed to send suspended and
                # archived explicitly (false included) in the basic
                # projection; if it omitted a false value every check would
                # be unsupported.
                "suspended": bool_attr(du.suspended),
                "archived": bool_attr(du.archived),
            },
            native=du,
        )

    # -- checks --

    def check(self, ctx: Context, r: CheckRequest) -> Decision:
        id = parse_ref(r.action_name, r.resource)
        user = go_lower(r.identity.id)
        if not EMAIL_RE.fullmatch(user):
            raise errorf(Code.INVALID_REQUEST, "identity is not a Workspace primary email")
        for state in ("suspended", "archived"):
            v = r.identity.attr(state)
            if v == "true":
                return denied(f"{user} is {state}")
            if v != "false":
                return unsupported(f"the Directory did not report whether {user} is {state}")
        a = r.action_name
        if a == "user.active":
            if id != user and id != go_lower(r.user.email):
                return unsupported(f"user.active is evaluated for the caller's own account only; {id} is another account")
            return allowed(f"{user} is active")
        if a.startswith("drive."):
            return self._check_drive(ctx, a, user, id)
        if a.startswith("calendar."):
            return self._check_calendar(ctx, a, user, id)
        if a == "mail.send_as":
            return self._check_send_as(ctx, user, id)
        if a == "mail.delegate_access":
            return self._check_delegate(ctx, user, id)
        if a == "group.member":
            return self._check_group(ctx, user, id)
        raise errorf(Code.INVALID_REQUEST, f"unknown action {go_quote(a)}")

    def _check_drive(self, ctx: Context, action: str, user: str, file_id: str) -> Decision:
        def decode(v: Any) -> tuple[dict[str, bool | None], bool | None]:
            d = jsonx.obj(v)
            caps: dict[str, bool | None] = {}
            for k, x in jsonx.o(d, "capabilities").items():
                if x is not None and not isinstance(x, bool):
                    raise jsonx.DecodeError("json: cannot unmarshal into Go struct field driveFile.capabilities of type bool")
                caps[k] = x
            return caps, _opt_bool(d, "trashed")

        q = {"supportsAllDrives": "true", "fields": CAPABILITY_FIELDS}
        try:
            caps, trashed = self._get_json(ctx, user, SCOPE_DRIVE, "/drive/v3/files/" + httpx.path_escape(file_id), q, decode)
        except Exception as err:  # noqa: BLE001 - Go: the error is decided on or classified
            if httpx.status(err) == 404:
                if reason(err) == "notFound":
                    return denied(f"{user} has no access to file {file_id}, or the file does not exist: Drive does not distinguish")
                return unknown_decision(
                    Code.RESOURCE_NOT_VISIBLE,
                    f"Drive answered 404 for file {file_id} without reason notFound, so it is not visible as {user} for a reason hallpass does not model",
                )
            raise classify(err)
        suffix = " (the file is in the trash)" if trashed else ""
        cap_name = ACTION_LIST[ACTION_INDEX[action]].capability
        if cap_name == "":
            return allowed(f"{user} can see file {file_id}{suffix}")
        v = caps.get(cap_name)
        if v is None:
            return unsupported(f"Drive did not report {cap_name} for file {file_id}")
        if v:
            return allowed(f"{user} has {cap_name} on file {file_id}{suffix}")
        return denied(f"{user} lacks {cap_name} on file {file_id}{suffix}")

    def _check_calendar(self, ctx: Context, action: str, user: str, cal_id: str) -> Decision:
        role = "owner"
        if cal_id != "primary" and not equal_fold(cal_id, user):
            try:
                role = self._get_json(
                    ctx,
                    user,
                    SCOPE_CALENDAR,
                    "/calendar/v3/users/me/calendarList/" + httpx.path_escape(cal_id),
                    None,
                    lambda v: jsonx.s(jsonx.obj(v), "accessRole"),
                )
            except Exception as err:  # noqa: BLE001 - Go: the error is decided on or classified
                if httpx.status(err) == 404:
                    return unsupported(f"calendar {cal_id} is not in {user}'s calendar list; ACL access may still exist")
                raise classify(err)
        rank = ACCESS_RANK.get(role)
        if rank is None:
            return unsupported(f"calendar {cal_id} reports access role {go_quote(role)}, which hallpass does not model")
        if action == "calendar.read":
            need = ACCESS_RANK["reader"]
        elif action == "calendar.event.write":
            # UNVERIFIED: writerWithoutPrivateAccess is assumed to allow
            # creating and changing non-private events.
            need = ACCESS_RANK["writerWithoutPrivateAccess"]
        else:  # calendar.share
            need = ACCESS_RANK["owner"]
        if rank >= need:
            return allowed(f"{user} has role {role} on calendar {cal_id}")
        return denied(f"{user} has role {role} on calendar {cal_id}, which does not allow {action.removeprefix('calendar.')}")

    def _check_send_as(self, ctx: Context, user: str, mailbox: str) -> Decision:
        if not self.gmail:
            return unsupported(
                f"send-as addresses are read with the gmail.settings.basic scope; set enable_gmail_settings to evaluate mail.send_as for {mailbox}"
            )

        def decode(v: Any) -> list[tuple[str, str, bool]]:
            out = []
            for e in jsonx.arr(jsonx.obj(v), "sendAs"):
                e = jsonx.obj(e)
                out.append((jsonx.s(e, "sendAsEmail"), jsonx.s(e, "verificationStatus"), jsonx.b(e, "isPrimary")))
            return out

        # Read as the user: the list "includes the primary send-as address
        # associated with the account", so the own mailbox is answered by the
        # same call and an account without Gmail is not a false allow.
        try:
            entries = self._get_json(ctx, user, SCOPE_GMAIL_SETTINGS, "/gmail/v1/users/me/settings/sendAs", None, decode)
        except Exception as err:  # noqa: BLE001 - Go: the error is decided on or classified
            return gmail_refused(err, user)
        for email, status, is_primary in entries:
            if not equal_fold(email, mailbox):
                continue
            if status == "accepted":
                return allowed(f"{user} has {mailbox} as a verified send-as address")
            if status == "pending":
                return denied(f"{user} has {mailbox} as a send-as address but it is awaiting verification by the owner")
            if is_primary:
                # The API defines isPrimary as "the primary address used to
                # login to the account", which every Gmail account has and
                # cannot delete, and verificationStatus "only applies to
                # custom from aliases".
                # UNVERIFIED: the primary entry is assumed to come without a
                # verificationStatus, which is why isPrimary is consulted.
                return allowed(f"{mailbox} is the primary address of {user}'s own mailbox")
            # "" and verificationStatusUnspecified: Gmail did not say whether
            # the alias is usable. treatAsAlias and a shared domain are not
            # taken as verification; the API description does not say so.
            return unsupported(f"Gmail lists {mailbox} as a send-as address of {user} without a verification status")
        if mailbox == user:
            return unsupported(f"Gmail did not list {user}'s own primary address among the send-as addresses")
        return denied(f"{user} has no send-as address {mailbox}")

    def _check_delegate(self, ctx: Context, user: str, mailbox: str) -> Decision:
        if not self.gmail:
            return unsupported(
                f"delegates are read with the gmail.settings.basic scope; set enable_gmail_settings to evaluate mail.delegate_access for {mailbox}"
            )

        def decode(v: Any) -> list[tuple[str, str]]:
            out = []
            for e in jsonx.arr(jsonx.obj(v), "delegates"):
                e = jsonx.obj(e)
                out.append((jsonx.s(e, "delegateEmail"), jsonx.s(e, "verificationStatus")))
            return out

        # The list is read as the mailbox owner, so the mailbox must be a
        # Workspace account hallpass may impersonate. For the own mailbox the
        # owner is the user: a 200 proves the mailbox is set up and reachable.
        try:
            delegates = self._get_json(ctx, mailbox, SCOPE_GMAIL_SETTINGS, "/gmail/v1/users/me/settings/delegates", None, decode)
        except Exception as err:  # noqa: BLE001 - Go: the error is decided on or classified
            return gmail_refused(err, mailbox)
        if mailbox == user:
            return allowed(f"{user} owns mailbox {mailbox} and its Gmail settings are readable")
        for email, status in delegates:
            if equal_fold(email, user):
                if status == "accepted":
                    return allowed(f"{user} is an accepted delegate of mailbox {mailbox}")
                if status in ("pending", "rejected", "expired"):
                    return denied(f"{user} is a delegate of mailbox {mailbox} but the delegation is {status}")
                return unsupported(f"Gmail lists {user} as a delegate of mailbox {mailbox} without a verification status")
        return denied(f"{user} is not a delegate of mailbox {mailbox}")

    def _check_group(self, ctx: Context, user: str, group: str) -> Decision:
        path = "/admin/directory/v1/groups/" + httpx.path_escape(group) + "/hasMember/" + httpx.path_escape(user)
        try:
            is_member = self._get_json(ctx, self.admin, SCOPE_DIRECTORY_GROUP, path, None, lambda v: _opt_bool(jsonx.obj(v), "isMember"))
        except Exception as err:  # noqa: BLE001 - Go: the error is decided on or classified
            if httpx.status(err) in (400, 404):
                return unsupported(f"group {group} is unknown or outside the domain, so membership of {user} cannot be checked")
            raise classify(err)
        if is_member is None:
            return unsupported(f"the Directory did not report membership of {user} in {group}")
        if is_member:
            return allowed(f"{user} is a member of group {group} (directly or through nested groups)")
        return denied(f"{user} is not a member of group {group}")

    # -- probe --

    def probe(self, ctx: Context) -> ProbeResult:
        """Mint the admin Directory token, list one user, and mint a token
        per user scope as the admin to prove each scope is delegated."""
        q = {"customer": self.customer, "maxResults": "1"}
        try:
            users = self._get_json(
                ctx, self.admin, SCOPE_DIRECTORY_USER, "/admin/directory/v1/users", q, lambda v: [_directory_user(x) for x in jsonx.arr(jsonx.obj(v), "users")]
            )
        except Exception as err:  # noqa: BLE001 - Go: the error is decided on or classified
            if httpx.status(err) in (404, 400):
                raise wrap_error(Code.INVALID_REQUEST, err, f"the Directory rejected customer_id {self.customer}")
            raise classify(err)
        who = self.sa_email
        if self.mode == MODE_KEY:
            try:
                who = self.load_key().client_email
            except HallpassError:
                pass
        warnings: list[str] = []
        summary = f"service account {who} reads the directory as {self.admin} (customer {self.customer})"
        if not users:
            warnings.append("the Directory listed no users; check customer_id and the admin's role")
        scopes = [SCOPE_DIRECTORY_GROUP, SCOPE_DRIVE, SCOPE_CALENDAR]
        if self.gmail:
            scopes.append(SCOPE_GMAIL_SETTINGS)
            warnings.append("enable_gmail_settings is on: gmail.settings.basic has no read-only variant and can change users' Gmail settings")
        for sc in scopes:
            try:
                self.source(self.admin, sc).get(ctx)
            except Exception as e:  # noqa: BLE001 - reported as a warning
                warnings.append(
                    f"scope {sc} could not be minted as {self.admin}: add it to the domain-wide delegation "
                    f"allowlist ({self.token_error(e, self.admin).code.value})"
                )
        warnings.append("domain-wide delegation lets this credential act as any user within the allowlisted scopes; keep the key tightly held")
        return ProbeResult(summary=summary, warnings=tuple(warnings))
