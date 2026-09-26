"""Checks Google Cloud IAM permissions with the Policy Troubleshooter API.

One connection is one credential. hallpass authenticates as a service
account (a key, or the runtime identity on GCE/GKE) and asks
policytroubleshooter.googleapis.com whether a principal holds a permission
on a full resource name. Google evaluates the allow and deny policies of the
resource and every ancestor, including group membership, and answers
CAN_ACCESS, CANNOT_ACCESS, UNKNOWN_CONDITIONAL or UNKNOWN_INFO. Nothing is
written and no user credential is ever used.
"""

from __future__ import annotations

import dataclasses
import math
import re
import time
from collections.abc import Callable

from hallpass.authx.google import GoogleServiceAccountKey, google_metadata_token, google_reason_in, parse_google_service_account_key
from hallpass.authx.jwt import RS256, Header, sign_jwt
from hallpass.authx.oauth2 import TokenError, TokenRequest, classify_token_error, fetch_token
from hallpass.authx.token import Token, TokenSource
from hallpass.authx.util import StructDict, go_json_loads, go_json_marshal
from hallpass.core import jsonx
from hallpass.core.catalog import Action, parse_resource
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
    connection_ref_field,
    credential_field,
    validate_https_url,
)
from hallpass.core.secret import SecretError
from hallpass.integrations.googlecloud.actions import catalog_actions, full_resource_name, is_project, match_action, parse_ref
from hallpass.net import httpx

__all__ = [
    "ASSERTION_TTL",
    "DEFAULT_API",
    "DEFAULT_METADATA",
    "DEFAULT_TOKEN_URL",
    "MODE_KEY",
    "MODE_KEYLESS",
    "SCOPE_CLOUD_PLATFORM",
    "STATE_CANNOT_ACCESS",
    "STATE_CAN_ACCESS",
    "STATE_UNKNOWN_CONDITIONAL",
    "STATE_UNKNOWN_INFO",
    "GoogleCloud",
    "GoogleCloudConnection",
    "parse_scope",
    "validate_http_url",
]

DEFAULT_TOKEN_URL = "https://oauth2.googleapis.com/token"
DEFAULT_API = "https://policytroubleshooter.googleapis.com"
DEFAULT_METADATA = "http://metadata.google.internal"

SCOPE_CLOUD_PLATFORM = "https://www.googleapis.com/auth/cloud-platform"

MODE_KEY = "key"
MODE_KEYLESS = "keyless"

ASSERTION_TTL = 3600.0

EMAIL_RE = re.compile(r"[A-Za-z0-9!#$%&'*+/=?^_{|}~.-]{1,64}@[A-Za-z0-9.-]{1,255}")

# The v3 states.
STATE_CAN_ACCESS = "CAN_ACCESS"
STATE_CANNOT_ACCESS = "CANNOT_ACCESS"
STATE_UNKNOWN_INFO = "UNKNOWN_INFO"
STATE_UNKNOWN_CONDITIONAL = "UNKNOWN_CONDITIONAL"

DENY_DENIED = "DENY_ACCESS_STATE_DENIED"


def validate_project(v: str) -> None:
    if v == "" or is_project(v):
        return
    raise ValueError("must be a project id or number")


def validate_scope(v: str) -> None:
    if v == "":
        return
    parse_scope(v)


def parse_scope(v: str) -> str:
    """Validate organization:<n>, folder:<n> or project:<id> and return the
    full resource name."""
    r = parse_resource(v)
    if r.type not in ("organization", "folder", "project"):
        raise ValueError(f"scope {go_quote(v)} must be organization:<number>, folder:<number> or project:<id>")
    if r.query:
        raise ValueError(f"scope {go_quote(v)} must not carry a query")
    try:
        return full_resource_name(r)
    except HallpassError as e:
        raise ValueError(f"scope {go_quote(v)}: {e}") from None


def validate_http_url(v: str) -> None:
    """validate_https_url that also accepts plain http://, for the
    link-local metadata server."""
    if v.startswith("http://") and not any(c in v for c in " \t\r\n#?"):
        return
    validate_https_url(v)


class GoogleCloud(Integration):
    """The googlecloud product."""

    def name(self) -> str:
        return "googlecloud"

    def fields(self) -> list[Field]:
        return [
            credential_field(False, "service-account key JSON (file:); required in auth_mode key"),
            Field(
                name="scope",
                required=True,
                validate=validate_scope,
                description=(
                    "organization:<number>, folder:<number> or project:<id> under which hallpass's credential can read IAM policies; the probe checks it"
                ),
            ),
            Field(
                name="auth_mode",
                default=MODE_KEY,
                enum=(MODE_KEY, MODE_KEYLESS),
                description="key: sign a JWT with the key JSON; keyless: use the GCE/GKE runtime identity from the metadata server",
            ),
            Field(
                name="quota_project",
                validate=validate_project,
                description="project billed for the API calls (X-Goog-User-Project); needed when the credential's own project has the API disabled",
            ),
            connection_ref_field(
                "googleworkspace_connection",
                "googleworkspace",
                False,
                "optional: resolve the user in this Workspace first, so an unknown email is user_not_found and a suspended account is denied",
            ),
            Field(name="token_url", default=DEFAULT_TOKEN_URL, validate=validate_https_url, description="OAuth token endpoint"),
            Field(name="api_url", default=DEFAULT_API, validate=validate_https_url, description="Policy Troubleshooter API endpoint"),
            Field(name="metadata_url", default=DEFAULT_METADATA, validate=validate_http_url, description="GCE metadata server, auth_mode keyless only"),
        ]

    def actions(self) -> list[Action]:
        return catalog_actions()

    def match_action(self, name: str) -> Action | None:
        """Accept raw:<permission>."""
        return match_action(name)

    def new(self, ctx: Context, s: Settings, d: Deps) -> Connection:
        """Build a connection. It touches no network; the key is read when a
        token is minted, so a rotated key file takes effect. The config
        loader has already run every Field's validate and enum; the checks
        repeated here cover connections built from raw settings, as tests do."""
        hc = d.http_client(s)
        return GoogleCloudConnection(s, d, hc)


def token_error(err: BaseException) -> HallpassError:
    """Classify a minting failure."""
    te = as_error(err, TokenError)
    if te is not None:
        if te.status == 429:
            return wrap_error(Code.UPSTREAM_RATE_LIMIT, err, "the token endpoint rate limited hallpass")
        if te.status >= 500:
            return wrap_error(Code.UPSTREAM_ERROR, err, f"the token endpoint failed (HTTP {te.status})")
        if te.code in ("invalid_grant", "unauthorized_client", "invalid_client"):
            return wrap_error(
                Code.CREDENTIAL_REJECTED,
                err,
                f"the token endpoint refused the service-account assertion ({te.code}): the key is revoked, the account is disabled or the clock is off",
            )
    return classify_token_error(err)


# The 403 markers that mean "slow down" rather than "not allowed".
RATE_LIMIT_REASONS = frozenset({"rateLimitExceeded", "userRateLimitExceeded", "quotaExceeded", "dailyLimitExceeded", "RATE_LIMIT_EXCEEDED"})
RATE_LIMIT_STATUSES = frozenset({"RESOURCE_EXHAUSTED"})


class APIError(Exception):
    """The cause of an API error: the status only, never the body."""


def _google_error(body: bytes) -> tuple[str, list[str]]:
    """error.status and error.details[].reason of a Google API error body,
    decoded as json.Unmarshal into the envelope struct does with its error
    ignored: nothing on a syntax error, members of the wrong type skipped
    while the rest still decode. Only the status and the reason tokens are
    read; the message is never used."""
    try:
        v = go_json_loads(body)
    except (ValueError, RecursionError):
        return "", []
    if not isinstance(v, dict):
        return "", []
    e = jsonx.get(v, "error")
    if not isinstance(e, dict):
        return "", []
    status = jsonx.get(e, "status")
    details = jsonx.get(e, "details")
    reasons: list[str] = []
    if isinstance(details, list):
        for d in details:
            r = jsonx.get(d, "reason") if isinstance(d, dict) else None
            reasons.append(r if isinstance(r, str) else "")
    return status if isinstance(status, str) else "", reasons


def api_error(resp: httpx.Response) -> HallpassError:
    """Map a 4xx response to an integration error. A 403 is hallpass's own
    setup (the API is not enabled, the service account lacks the role, the
    quota project is refused) unless its reason is a rate limit."""
    status, details = _google_error(resp.body)
    reason = google_reason_in(resp.body.decode("utf-8", "replace"))
    if reason == "":
        reason = next((d for d in details if d != ""), "")
    cause = APIError(f"policy troubleshooter: HTTP {resp.status}")
    if resp.status == 429:
        return wrap_error(Code.UPSTREAM_RATE_LIMIT, cause, "rate limited by Google")
    if resp.status == 403:
        if reason in RATE_LIMIT_REASONS or status in RATE_LIMIT_STATUSES:
            return wrap_error(Code.UPSTREAM_RATE_LIMIT, cause, "rate limited by Google")
        if reason == "":
            return wrap_error(
                Code.CREDENTIAL_REJECTED,
                cause,
                "the Policy Troubleshooter refused the call (HTTP 403): enable the API, grant the service "
                "account roles/iam.securityReviewer, or set quota_project",
            )
        return wrap_error(
            Code.CREDENTIAL_REJECTED,
            cause,
            f"the Policy Troubleshooter refused the call (HTTP 403, {reason}): enable the API, grant the "
            "service account roles/iam.securityReviewer, or set quota_project",
        )
    if resp.status == 401:
        return wrap_error(Code.CREDENTIAL_REJECTED, cause, "the Policy Troubleshooter rejected the access token twice")
    if resp.status == 400:
        return wrap_error(
            Code.INVALID_REQUEST,
            cause,
            "the Policy Troubleshooter rejected the request: check the permission name, the resource and "
            "that the principal is a Google Account or service account",
        )
    if resp.status == 404:
        return wrap_error(Code.RESOURCE_NOT_VISIBLE, cause, "the Policy Troubleshooter found no such resource")
    return wrap_error(Code.UPSTREAM_ERROR, cause, f"the Policy Troubleshooter answered HTTP {resp.status}")


def _attr_or(id: Identity, k: str, default: str) -> str:
    v = id.attr(k)
    return v if v != "" else default


class GoogleCloudConnection(Connection):
    """One credential asking the Policy Troubleshooter."""

    def __init__(self, s: Settings, d: Deps, hc: httpx.Transport) -> None:
        self.settings = s
        self.mode = s.get("auth_mode")
        self.quota_project = s.get("quota_project")
        self.token_url = s.get("token_url").rstrip("/")
        self.metadata_url = s.get("metadata_url").rstrip("/")
        # An optional identity source.
        self.workspace: Connection | None = None
        # The full resource name of the configured scope.
        self.scope = parse_scope(s.get("scope"))
        if self.mode == "":
            self.mode = MODE_KEY
        if self.mode == MODE_KEY:
            if s.secret("credential").is_zero():
                raise ValueError("credential is required in auth_mode key")
        elif self.mode != MODE_KEYLESS:
            raise ValueError(f"auth_mode {go_quote(self.mode)} must be key or keyless")
        try:
            validate_project(self.quota_project)
        except ValueError as e:
            raise ValueError(f"quota_project: {e}") from e
        ws = s.get("googleworkspace_connection")
        if ws != "":
            self.workspace = d.connection(ws)
        self.now: Callable[[], float] = d.now or time.time
        if self.token_url == "":
            self.token_url = DEFAULT_TOKEN_URL
        if self.metadata_url == "":
            self.metadata_url = DEFAULT_METADATA
        api = s.get("api_url").rstrip("/")
        if api == "":
            api = DEFAULT_API
        # Token and metadata endpoints.
        self.plain = httpx.Client(http=hc, logger=d.logger)
        # The troubleshooter, per-call bearer.
        self.api = httpx.Client(http=hc, base=api, logger=d.logger)
        self.tokens = TokenSource(now=self.now, fetch=self._mint)

    # -- authentication --

    def load_key(self) -> GoogleServiceAccountKey:
        try:
            raw = self.settings.secret("credential").get_string()
        except SecretError as e:
            raise wrap_error(Code.CREDENTIAL_REJECTED, e, "the service-account key could not be read") from e
        return parse_google_service_account_key(raw)

    def _mint(self, ctx: Context) -> Token:
        """An access token for the service account: a JWT bearer exchange in
        key mode, the metadata server's token in keyless mode."""
        if self.mode == MODE_KEYLESS:
            return google_metadata_token(ctx, self.plain, self.metadata_url, self.now)
        k = self.load_key()
        now = self.now()
        # The claims of the JWT bearer assertion: the service account
        # itself, one scope.
        payload = go_json_marshal(
            StructDict(iss=k.client_email, scope=SCOPE_CLOUD_PLATFORM, aud=self.token_url, iat=math.floor(now), exp=math.floor(now + ASSERTION_TTL))
        )
        assertion = sign_jwt(k.key, Header(alg=RS256, kid=k.private_key_id), payload)
        form = {"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": assertion}
        return fetch_token(ctx, self.plain, TokenRequest(url=self.token_url, form=form, now=self.now))

    def _whoami(self, ctx: Context) -> str:
        """The service account's email, for the probe: the key's
        client_email, or in keyless mode the metadata server's answer."""
        if self.mode == MODE_KEY:
            return self.load_key().client_email
        try:
            resp = self.plain.do(
                ctx,
                httpx.Request(
                    method="GET",
                    path=self.metadata_url + "/computeMetadata/v1/instance/service-accounts/default/email",
                    header={"Metadata-Flavor": "Google"},
                ),
            )
        except Exception as err:
            raise wrap_error(
                Code.CREDENTIAL_REJECTED,
                err,
                "the metadata server did not report the service account's email; auth_mode keyless needs a GCE or GKE Workload Identity",
            ) from err
        email = go_trim_space(resp.body.decode("utf-8", "replace"))
        if not EMAIL_RE.fullmatch(email):
            raise errorf(Code.CREDENTIAL_REJECTED, "the metadata server returned no service account email")
        return email

    # -- API transport --

    def _call(self, ctx: Context, req: httpx.Request) -> httpx.Response:
        """One API request with the bearer token. 4xx responses are returned
        whole so their status and reason can be read from the full body; a
        401 invalidates the token and retries once. Transport errors,
        timeouts and 5xx come back as httpx errors."""

        def attempt() -> httpx.Response:
            try:
                tok = self.tokens.get(ctx)
            except Exception as e:  # noqa: BLE001 - Go: the error is decided on or classified
                raise token_error(e)
            h = req.header.clone() if isinstance(req.header, httpx.Headers) else httpx.Headers(req.header or {})
            h.set("Authorization", "Bearer " + tok)
            if self.quota_project != "":
                h.set("X-Goog-User-Project", self.quota_project)
            return self.api.do(ctx, dataclasses.replace(req, header=h, accept_4xx=True))

        try:
            resp = attempt()
            if resp.status == 401:
                self.tokens.invalidate()
                resp = attempt()
        except Exception as err:
            he = httpx.classify(err)
            assert he is not None
            if he is err:
                raise
            raise he
        if resp.status >= 400:
            raise api_error(resp)
        return resp

    # -- identity --

    def resolve_identity(self, ctx: Context, u: User) -> Identity:
        """Take the email as the principal. With a googleworkspace_connection
        the Workspace Directory decides whether the account exists (aliases
        become the primary address) and whether it is suspended or archived;
        without one the troubleshooter is asked about the address as given."""
        email = go_lower(go_trim_space(u.email))
        if not EMAIL_RE.fullmatch(email):
            raise errorf(Code.INVALID_REQUEST, f"user email {go_quote(email)} is not an address")
        if self.workspace is None:
            return Identity(id=email, display=email, attrs={"source": "email"})
        ws = self.workspace.resolve_identity(ctx, u)
        primary = go_lower(ws.id)
        if not EMAIL_RE.fullmatch(primary):
            raise errorf(Code.UPSTREAM_ERROR, "the Workspace connection returned an identity that is not an email")
        return Identity(
            id=primary,
            display=primary,
            attrs={
                "source": "googleworkspace",
                "suspended": _attr_or(ws, "suspended", "unknown"),
                "archived": _attr_or(ws, "archived", "unknown"),
            },
        )

    # -- checks --

    def _troubleshoot(self, ctx: Context, principal: str, permission: str, resource: str) -> tuple[str, str]:
        """Ask one question: (overallAccessState, denyAccessState)."""
        # The call reads policies and is safe to retry.
        resp = self._call(
            ctx,
            httpx.Request(
                method="POST",
                path="/v3/iam:troubleshoot",
                json={"accessTuple": {"principal": principal, "fullResourceName": resource, "permission": permission}},
                idempotent=True,
            ),
        )
        try:
            d = jsonx.obj(resp.json())
            return jsonx.s(d, "overallAccessState"), jsonx.s(jsonx.o(d, "denyPolicyExplanation"), "denyAccessState")
        except (ValueError, RecursionError) as e:
            raise wrap_error(Code.UPSTREAM_ERROR, e, "the Policy Troubleshooter returned an unreadable response") from e

    def check(self, ctx: Context, r: CheckRequest) -> Decision:
        q = parse_ref(r.action_name, r.resource)
        principal = go_lower(r.identity.id)
        if not EMAIL_RE.fullmatch(principal):
            raise errorf(Code.INVALID_REQUEST, "identity is not an email address")
        if r.identity.attr("source") == "googleworkspace":
            for state in ("suspended", "archived"):
                v = r.identity.attr(state)
                if v == "true":
                    return denied(f"{principal} is {state} in Google Workspace")
                if v != "false":
                    return unsupported(f"the Workspace Directory did not report whether {principal} is {state}")
        overall, deny = self._troubleshoot(ctx, principal, q.permission, q.resource)
        what = q.permission + " on " + r.resource.raw
        if overall == STATE_CAN_ACCESS:
            return allowed(f"{principal} holds {what}")
        if overall == STATE_CANNOT_ACCESS:
            # UNVERIFIED: a principal that is not a Google Account or a
            # service account (a Workforce Identity user, a typo) is assumed
            # to come back CANNOT_ACCESS or HTTP 400, never some other state.
            if deny == DENY_DENIED:
                return denied(f"a deny policy denies {principal} {what}")
            return denied(f"no allow policy grants {principal} {what}")
        if overall == STATE_UNKNOWN_CONDITIONAL:
            return unsupported(f"whether {principal} holds {what} depends on a policy condition the troubleshooter could not evaluate")
        if overall == STATE_UNKNOWN_INFO:
            # UNVERIFIED: UNKNOWN_INFO is also what the troubleshooter answers
            # when it cannot read the membership of a Google Group in a
            # binding; hallpass cannot tell that apart from an unreadable
            # policy.
            return unknown_decision(
                Code.RESOURCE_NOT_VISIBLE,
                f"hallpass cannot read every policy that applies to {r.resource.raw}, or the resource does not exist; "
                "the service account needs roles/iam.securityReviewer above it",
            )
        raise errorf(Code.UPSTREAM_ERROR, "the Policy Troubleshooter returned an unknown access state")

    # -- probe --

    def probe(self, ctx: Context) -> ProbeResult:
        """Mint a token and ask the troubleshooter whether the service
        account itself may get the configured scope. CAN_ACCESS or
        CANNOT_ACCESS proves the API is enabled and the policies under scope
        are readable; UNKNOWN_INFO means the securityReviewer role is
        missing there."""
        who = self._whoami(ctx)
        permission = "resourcemanager.projects.get"
        if "/folders/" in self.scope:
            permission = "resourcemanager.folders.get"
        elif "/organizations/" in self.scope:
            permission = "resourcemanager.organizations.get"
        overall, _ = self._troubleshoot(ctx, who, permission, self.scope)
        scope = self.settings.get("scope")
        summary = f"service account {who} asks the Policy Troubleshooter about {scope} ({overall})"
        warnings: list[str] = []
        if overall in (STATE_CAN_ACCESS, STATE_CANNOT_ACCESS, STATE_UNKNOWN_CONDITIONAL):
            pass
        elif overall == STATE_UNKNOWN_INFO:
            # UNVERIFIED: roles/iam.securityReviewer is assumed to be enough
            # for the troubleshooter to read every allow and deny policy
            # under scope.
            warnings.append(
                f"the troubleshooter could not read every policy under {scope}: grant {who} roles/iam.securityReviewer there, or every check will be unknown"
            )
        else:
            warnings.append("the troubleshooter returned an unknown access state")
        if self.workspace is None:
            warnings.append(
                "no googleworkspace_connection: an email with no Google Account is answered by the troubleshooter as if it existed (deny), never user_not_found"
            )
        warnings.append("the Policy Troubleshooter discloses which permissions other principals hold; this is inherent to how hallpass checks")
        return ProbeResult(summary=summary, warnings=tuple(warnings))
