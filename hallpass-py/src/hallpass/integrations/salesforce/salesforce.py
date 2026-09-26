"""Checks record, object, field and system permissions through the
Salesforce REST API.

hallpass authenticates as an External Client App with the OAuth 2.0 JWT
bearer flow (or client credentials), acting as a read-only integration user.
It maps the caller's email to a User row, then asks Salesforce's own
permission objects: UserRecordAccess for one record, ObjectPermissions and
FieldPermissions across the user's profile and permission sets,
PermissionSet for system permissions and PermissionSetAssignment for
permission set membership. Every query is SOQL over GET; nothing is written.

Every Salesforce behaviour this package relies on was designed from
secondary sources and is marked "UNVERIFIED:" until confirmed in a
Developer Edition org. See docs/integrations/salesforce.md.
"""

from __future__ import annotations

import json
import math
import re
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, TypeVar

from hallpass.authx.jwt import RS256, Header, parse_rsa_private_key, sign_jwt, standard_claims
from hallpass.authx.oauth2 import TokenError, classify_token_error
from hallpass.authx.token import Token, TokenSource
from hallpass.authx.util import STR, go_unmarshal
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
    user_ambiguous,
    user_not_found,
    wrap_error,
)
from hallpass.core.duration import parse_duration_ns
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
    _go_url_parse,
    _hostname,
    credential_field,
    url_field,
    validate_https_url,
)
from hallpass.core.log import Logger, discard
from hallpass.core.secret import SecretError
from hallpass.integrations.salesforce.actions import ACTION_LIST, ACTIONS, Kind, SFAction, Target, parse_target
from hallpass.integrations.salesforce.soql import (
    PERM_NAME_RE,
    soql_id_list,
    soql_string,
    validate_email,
    validate_id,
    validate_text,
)
from hallpass.net import httpx

__all__ = ["ApiError", "Salesforce", "SalesforceConnection", "decode_api_error"]

FLOW_JWT_BEARER = "jwt_bearer"
FLOW_CLIENT_CREDENTIALS = "client_credentials"

MATCH_EMAIL = "Email"
MATCH_USERNAME = "Username"
MATCH_FEDERATION_ID = "FederationIdentifier"

DEFAULT_AUDIENCE = "https://login.salesforce.com"
DEFAULT_TOKEN_TTL = "15m"
TOKEN_PATH = "/services/oauth2/token"

# The assertion's validity. UNVERIFIED: Salesforce is reported to reject
# assertions whose exp is more than 3 minutes ahead.
JWT_LIFETIME = 180.0
# How long the PermissionSet describe and each sObject existence check are
# cached.
DESCRIBE_TTL = 3600.0
# Bounds nextRecordsUrl following.
MAX_QUERY_PAGES = 5
# The daily API allocation below which the probe warns.
LOW_LIMIT_PERCENT = 10

_API_VERSION_RE = re.compile(r"v[0-9]{2,3}\.[0-9]")

_MINUTE_NS = 60 * 10**9
_DAY_NS = 24 * 3600 * 10**9


def _fold(c: str) -> str:
    f = c.casefold()
    if len(f) == 1:
        return f
    lo = c.lower()
    return lo if len(lo) == 1 else c


def equal_fold(a: str, b: str) -> bool:
    """Go's strings.EqualFold: equal under simple Unicode case folding."""
    return len(a) == len(b) and all(x == y or _fold(x) == _fold(y) for x, y in zip(a, b, strict=True))


# -- settings validation --------------------------------------------------------


def validate_client_id(v: str) -> None:
    if v == "":
        return
    try:
        validate_text(v)
    except ValueError as e:
        raise ValueError(f"client_id: {e}") from None
    if any(c in v for c in " \t\r\n"):
        raise ValueError("client_id must not contain whitespace")


def validate_username(v: str) -> None:
    if v == "":
        return
    try:
        validate_text(v)
    except ValueError as e:
        raise ValueError(f"username: {e}") from None
    if any(c in v for c in " \t\r\n'\\"):
        raise ValueError("username must not contain whitespace, quotes or backslashes")


def validate_api_version(v: str) -> None:
    if not _API_VERSION_RE.fullmatch(v):
        raise ValueError(f"api_version {go_quote(v)} must look like v66.0")


def validate_token_ttl(v: str) -> None:
    try:
        d = parse_duration_ns(v)
    except ValueError:
        raise ValueError(f"token_ttl {go_quote(v)} is not a duration such as 15m") from None
    if d < _MINUTE_NS or d > _DAY_NS:
        raise ValueError(f"token_ttl {go_quote(v)} must be between 1m and 24h")


def _value_or(s: Settings, key: str, default: str) -> str:
    v = s.get(key)
    return v if v != "" else default


class Salesforce(Integration):
    """The salesforce product."""

    def name(self) -> str:
        return "salesforce"

    def fields(self) -> list[Field]:
        return [
            url_field(True, "My Domain URL, e.g. https://acme.my.salesforce.com; the token endpoint is {url}/services/oauth2/token"),
            Field(name="client_id", required=True, validate=validate_client_id, description="consumer key of the External Client App"),
            Field(
                name="auth_flow",
                default=FLOW_JWT_BEARER,
                enum=(FLOW_JWT_BEARER, FLOW_CLIENT_CREDENTIALS),
                description="jwt_bearer (a private key, the integration user as JWT subject) or client_credentials (consumer secret, the app's Run As user)",
            ),
            Field(
                name="username",
                validate=validate_username,
                description="the integration user's Username; the JWT sub claim, required for jwt_bearer",
            ),
            credential_field(True, "PEM RSA private key for jwt_bearer, or the consumer secret for client_credentials"),
            Field(
                name="audience",
                default=DEFAULT_AUDIENCE,
                validate=validate_https_url,
                description="the JWT aud claim: https://login.salesforce.com, or https://test.salesforce.com for sandboxes",
            ),
            Field(
                name="api_version",
                required=True,
                validate=validate_api_version,
                description="REST API version to pin, e.g. v66.0; never discovered automatically",
            ),
            Field(
                name="match_field",
                default=MATCH_EMAIL,
                enum=(MATCH_EMAIL, MATCH_USERNAME, MATCH_FEDERATION_ID),
                description="the User field the caller's email is matched against",
            ),
            Field(
                name="token_ttl",
                default=DEFAULT_TOKEN_TTL,
                validate=validate_token_ttl,
                description="how long a minted access token is reused; the token response carries no expiry",
            ),
        ]

    def actions(self) -> list[Action]:
        return [Action(name=a.name, description=a.desc) for a in ACTION_LIST]

    def new(self, ctx: Context, s: Settings, d: Deps) -> Connection:
        """Build a connection. It touches no network; the credential is read
        each time a token is minted, so a rotated key file takes effect."""
        hc = d.http_client(s)
        if s.secret("credential").is_zero():
            raise ValueError("credential is required")
        c = SalesforceConnection(
            settings=s,
            url=s.get("url").rstrip("/"),
            client_id=s.get("client_id"),
            flow=_value_or(s, "auth_flow", FLOW_JWT_BEARER),
            username=s.get("username"),
            audience=_value_or(s, "audience", DEFAULT_AUDIENCE),
            version=s.get("api_version"),
            match_field=_value_or(s, "match_field", MATCH_EMAIL),
            logger=d.logger if d.logger is not None else discard(),
            now=d.now if d.now is not None else time.time,
        )
        if c.url == "":
            raise ValueError("url is required")
        if c.client_id == "":
            raise ValueError("client_id is required")
        validate_api_version(c.version)
        if c.flow == FLOW_JWT_BEARER:
            if c.username == "":
                raise ValueError("username is required for auth_flow jwt_bearer")
        elif c.flow != FLOW_CLIENT_CREDENTIALS:
            raise ValueError(f"auth_flow {go_quote(c.flow)} must be jwt_bearer or client_credentials")
        if c.match_field not in (MATCH_EMAIL, MATCH_USERNAME, MATCH_FEDERATION_ID):
            raise ValueError(f"match_field {go_quote(c.match_field)} must be Email, Username or FederationIdentifier")
        ttl_text = _value_or(s, "token_ttl", DEFAULT_TOKEN_TTL)
        validate_token_ttl(ttl_text)
        ttl = parse_duration_ns(ttl_text) / 1e9
        c.plain = httpx.Client(http=hc, logger=d.logger)
        c.api = httpx.Client(http=hc, logger=d.logger, auth=c._bearer_auth)
        c.tokens = TokenSource(fetch=c._fetch_token, default_ttl=ttl, now=c.now)
        return c


# -- transport -------------------------------------------------------------------


class ApiError(Exception):
    """A 4xx answered by the REST API itself, decoded from the JSON array
    Salesforce returns: [{"message": "...", "errorCode": "..."}]. The
    messages are dropped: they can echo the query."""

    def __init__(self, status: int, codes: list[str] | None = None) -> None:
        self.status = status
        self.codes = list(codes or [])
        super().__init__(str(self))

    def __str__(self) -> str:
        return f"salesforce: HTTP {self.status} {','.join(self.codes)}"

    def has(self, code: str) -> bool:
        return code in self.codes


# The shape of a Salesforce errorCode (INVALID_FIELD, REQUEST_LIMIT_EXCEEDED).
# Anything else in that slot is not trusted into a decision text or a log
# line and is rendered as UNKNOWN_ERROR_CODE.
_ERROR_CODE_RE = re.compile(r"[A-Z_]{1,64}")
UNKNOWN_ERROR_CODE = "unknown error"


def _reject_constant(name: str) -> Any:
    raise ValueError(f"invalid character '{name[0]}' looking for beginning of value")


def _go_unmarshal_any(body: bytes) -> Any:
    """json.Unmarshal into an any: one value and nothing after it, no NaN
    or Infinity."""
    return json.loads(body.decode("utf-8", "replace"), parse_constant=_reject_constant)


def _go_decode_first(body: bytes) -> Any:
    """httpx.Response.JSON: the first value of the body (trailing data is
    not read), no NaN or Infinity."""
    text = body.decode("utf-8", "replace")
    stripped = text.lstrip(" \t\r\n")
    if not stripped:
        raise ValueError("empty body")
    v, _ = json.JSONDecoder(parse_constant=_reject_constant).raw_decode(stripped)
    return v


def decode_api_error(resp: httpx.Response) -> ApiError:
    e = ApiError(resp.status)
    codes: list[str] = []
    try:
        body = _go_unmarshal_any(resp.body)
        # []struct{ErrorCode string}: any element of the wrong shape fails
        # the whole decode.
        items = [] if body is None else body
        if not isinstance(items, list):
            raise jsonx.DecodeError("not an array")
        decoded = [jsonx.s(jsonx.obj(b), "errorCode") for b in items]
    except (ValueError, RecursionError):
        decoded = []
    for code in decoded:
        if code == "":
            continue
        if _ERROR_CODE_RE.fullmatch(code):
            codes.append(code)
        elif UNKNOWN_ERROR_CODE not in codes:
            codes.append(UNKNOWN_ERROR_CODE)
    e.codes = codes
    return e


def classify(err: BaseException, subject: str) -> HallpassError:
    """Map a failed call to an integration error. subject names the object
    or field the call was about, for the unsupported text."""
    he = as_error(err, HallpassError)
    if he is not None:
        return he
    ae = as_error(err, ApiError)
    if ae is not None:
        if ae.status == 401:
            return wrap_error(Code.CREDENTIAL_REJECTED, err, "the access token was rejected twice (HTTP 401)")
        if ae.status == 403:
            if ae.has("REQUEST_LIMIT_EXCEEDED"):
                return wrap_error(Code.UPSTREAM_RATE_LIMIT, err, "the org's API request allocation is exhausted")
            if ae.has("API_DISABLED_FOR_ORG"):
                return wrap_error(Code.CREDENTIAL_REJECTED, err, "the API is disabled for the org or the integration user lacks API Enabled")
            return wrap_error(Code.CREDENTIAL_REJECTED, err, f"the integration user may not query {subject} (HTTP 403)")
        if ae.status == 404:
            return wrap_error(Code.RESOURCE_NOT_VISIBLE, err, f"{subject} was not found or is not visible to the integration user (HTTP 404)")
        if ae.status == 429:
            return wrap_error(Code.UPSTREAM_RATE_LIMIT, err, "rate limited by Salesforce")
        if ae.status == 400 and (ae.has("INVALID_TYPE") or ae.has("INVALID_FIELD") or ae.has("MALFORMED_QUERY")):
            return wrap_error(Code.UNSUPPORTED, err, f"{subject} cannot be queried in this org ({','.join(ae.codes)})")
        return wrap_error(Code.UPSTREAM_ERROR, err, f"Salesforce returned HTTP {ae.status} for {subject}")
    out = httpx.classify(err)
    assert out is not None
    return out


def api_status(err: BaseException) -> int:
    """The HTTP status of an ApiError, or 0 for any other error."""
    ae = as_error(err, ApiError)
    return ae.status if ae is not None else 0


def is_query_shape_error(err: BaseException) -> bool:
    """A 400 that means the object or field does not exist in this org."""
    ae = as_error(err, ApiError)
    return ae is not None and ae.status == 400 and (ae.has("INVALID_TYPE") or ae.has("INVALID_FIELD"))


# -- decoding (Go decodes into typed structs) --------------------------------------

_NUMBER_RE = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")


def _number(d: dict[str, Any], key: str) -> Any:
    """A json.Number field: a JSON number, or a string that is a valid
    number literal; null is empty."""
    v = jsonx._get(d, key)
    if v is None:
        return ""
    if isinstance(v, bool):
        raise jsonx.DecodeError(f"json: cannot unmarshal bool into field {key} of type json.Number")
    if isinstance(v, (int, float)):
        return v
    if isinstance(v, str):
        if not _NUMBER_RE.fullmatch(v):
            raise jsonx.DecodeError(f"json: invalid number literal, trying to unmarshal {go_quote(v)} into Number")
        return v
    raise jsonx.DecodeError(f"json: cannot unmarshal {type(v).__name__} into field {key} of type json.Number")


def _int64(n: Any) -> int:
    """json.Number.Int64 with its error ignored: the integer, or 0."""
    if isinstance(n, bool):
        return 0
    if isinstance(n, int):
        v = n
    elif isinstance(n, str) and re.fullmatch(r"[+-]?[0-9]+", n):
        v = int(n)
    else:
        return 0
    return v if -(2**63) <= v < 2**63 else 0


@dataclass
class _QueryResponse:
    """The envelope of /query."""

    done: bool
    next_records_url: str
    records: list[Any]


def _decode_query_response(v: Any) -> _QueryResponse:
    d = jsonx.obj(v)
    _number(d, "totalSize")
    return _QueryResponse(done=jsonx.b(d, "done"), next_records_url=jsonx.s(d, "nextRecordsUrl"), records=jsonx.arr(d, "records"))


@dataclass
class UserRow:
    id: str = ""
    is_active: bool = False
    username: str = ""
    email: str = ""
    federation_identifier: str = ""
    user_type: str = ""
    name: str = ""


def _decode_user_row(v: Any) -> UserRow:
    d = jsonx.obj(v)
    return UserRow(
        id=jsonx.s(d, "Id"),
        is_active=jsonx.b(d, "IsActive"),
        username=jsonx.s(d, "Username"),
        email=jsonx.s(d, "Email"),
        federation_identifier=jsonx.s(d, "FederationIdentifier"),
        user_type=jsonx.s(d, "UserType"),
        name=jsonx.s(d, "Name"),
    )


def _decode_frozen(v: Any) -> bool:
    return jsonx.b(jsonx.obj(v), "IsFrozen")


_RECORD_COLUMNS = ("HasReadAccess", "HasEditAccess", "HasDeleteAccess", "HasTransferAccess", "HasAllAccess")


@dataclass
class RecordAccessRow:
    record_id: str
    columns: dict[str, bool]
    max_access_level: str

    def column(self, name: str) -> bool:
        return self.columns.get(name, False)


def _decode_record_access(v: Any) -> RecordAccessRow:
    d = jsonx.obj(v)
    rid = jsonx.s(d, "RecordId")
    cols = {c: jsonx.b(d, c) for c in _RECORD_COLUMNS}
    return RecordAccessRow(record_id=rid, columns=cols, max_access_level=jsonx.s(d, "MaxAccessLevel"))


@dataclass
class ParentRef:
    """The Parent relationship of a permission row."""

    is_owned_by_profile: bool = False
    name: str = ""

    def label(self) -> str:
        kind_name = "profile" if self.is_owned_by_profile else "permission set"
        if self.name == "":
            return kind_name
        return kind_name + " " + self.name


def _decode_parent(d: dict[str, Any]) -> ParentRef:
    p = jsonx.o(d, "Parent")
    return ParentRef(is_owned_by_profile=jsonx.b(p, "IsOwnedByProfile"), name=jsonx.s(p, "Name"))


_OBJECT_COLUMNS = (
    "PermissionsRead",
    "PermissionsCreate",
    "PermissionsEdit",
    "PermissionsDelete",
    "PermissionsViewAllRecords",
    "PermissionsModifyAllRecords",
)


@dataclass
class PermRow:
    """An ObjectPermissions or FieldPermissions row."""

    columns: dict[str, bool]
    parent: ParentRef

    def column(self, name: str) -> bool:
        return self.columns.get(name, False)


def _decode_object_perm(v: Any) -> PermRow:
    d = jsonx.obj(v)
    cols = {c: jsonx.b(d, c) for c in _OBJECT_COLUMNS}
    return PermRow(columns=cols, parent=_decode_parent(d))


def _decode_field_perm(v: Any) -> PermRow:
    d = jsonx.obj(v)
    cols = {c: jsonx.b(d, c) for c in ("PermissionsRead", "PermissionsEdit")}
    return PermRow(columns=cols, parent=_decode_parent(d))


def _decode_perm_set(v: Any) -> ParentRef:
    d = jsonx.obj(v)
    name = jsonx.s(d, "Name")
    return ParentRef(is_owned_by_profile=jsonx.b(d, "IsOwnedByProfile"), name=name)


def _decode_group_assignment(v: Any) -> str:
    return jsonx.s(jsonx.obj(v), "PermissionSetGroupId")


def _decode_group(v: Any) -> tuple[str, str, str]:
    d = jsonx.obj(v)
    return jsonx.s(d, "Id"), jsonx.s(d, "DeveloperName"), jsonx.s(d, "Status")


def _decode_describe(v: Any) -> list[str]:
    d = jsonx.obj(v)
    return [jsonx.s(jsonx.obj(f), "name") for f in jsonx.arr(d, "fields")]


def _decode_limits(v: Any) -> dict[str, tuple[Any, Any]]:
    m = jsonx.obj(v)
    out = {}
    for k, x in m.items():
        e = jsonx.obj(x)
        out[k] = (_number(e, "Max"), _number(e, "Remaining"))
    return out


# -- identity ------------------------------------------------------------------------

ATTR_ACTIVE = "active"
ATTR_FROZEN = "frozen"
ATTR_USERNAME = "username"
ATTR_USER_TYPE = "user_type"

# Bounds a lookup by Username. UNVERIFIED: Salesforce keeps Username unique
# per org, so a second row means the org is not what hallpass assumes and
# the lookup is ambiguous.
EXACT_USER_LIMIT = 2
# Bounds the match_field lookup. Reaching it means the rows are a subset of
# the matches, so no rule may pick from them.
MATCH_USER_LIMIT = 4

# Values of the frozen identity attribute.
FROZEN_TRUE = "true"
FROZEN_FALSE = "false"
FROZEN_UNKNOWN = "unknown"  # UserLogin is not queryable in this org

# The probe warning and the reason recorded when UserLogin cannot be queried.
FROZEN_NOT_DETECTED = "frozen users are not detected: UserLogin not queryable"


def pick_user(rows: list[UserRow], value: str, match_field: str, limit: int) -> UserRow:
    """Choose one row of a match_field lookup. Email is not unique in
    Salesforce: several users (a person plus their community or
    sandbox-cloned accounts) can share one address, so a single active
    Standard user wins among two or three rows; when the rows hit the query
    limit they are only a subset of the matches and nothing may be picked
    from them. Any other multiplicity is ambiguous."""
    if len(rows) == 0:
        raise user_not_found(f"no Salesforce user has {match_field} {go_quote(value)}")
    if len(rows) == 1:
        return rows[0]
    if len(rows) >= limit:
        raise user_ambiguous(
            f"at least {len(rows)} Salesforce users have {match_field} {go_quote(value)}; set match_field: FederationIdentifier (or Username) to disambiguate"
        )
    if match_field == MATCH_EMAIL:
        # UNVERIFIED: UserType "Standard" is the value for full licence users,
        # as opposed to portal, guest and community types.
        std = [r for r in rows if r.is_active and r.user_type == "Standard"]
        if len(std) == 1:
            return std[0]
    raise user_ambiguous(
        f"{len(rows)} Salesforce users have {match_field} {go_quote(value)}; set match_field: FederationIdentifier (or Username) to disambiguate"
    )


# -- checks ----------------------------------------------------------------------------

# The values UserRecordAccess.MaxAccessLevel can take. UNVERIFIED: the
# picklist is None, Read, Edit, Delete, Transfer, All.
_ACCESS_LEVELS = frozenset({"None", "Read", "Edit", "Delete", "Transfer", "All"})


def access_level(v: str) -> str:
    """MaxAccessLevel for a decision text: only a known picklist value is
    copied; anything else (an upstream surprise) is "unknown"."""
    return v if v in _ACCESS_LEVELS else "unknown"


def soql_datetime(t: float) -> str:
    """t as a SOQL datetime literal (unquoted, YYYY-MM-DDThh:mm:ssZ)."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(math.floor(t)))


def assigned_sets(uid: str, now: float) -> str:
    """The sub-select of every permission set in force for the user right
    now. Profiles appear as permission sets with IsOwnedByProfile = true and
    permission set groups as their aggregate set. Session-based permission
    sets (HasActivationRequired) only apply during an activated session and
    time-bound assignments end at ExpirationDate, so both are excluded. uid
    is regex-validated; now is rendered by hallpass.

    UNVERIFIED: PermissionSet.HasActivationRequired and
    PermissionSetAssignment.ExpirationDate are filterable through the
    assignment sub-select; orgs on API versions before ExpirationDate
    existed answer INVALID_FIELD, which assigned_sets_loose handles.
    """
    return (
        "(SELECT PermissionSetId FROM PermissionSetAssignment WHERE AssigneeId = '"
        + uid
        + "'"
        + " AND PermissionSet.HasActivationRequired = false"
        + " AND (ExpirationDate = null OR ExpirationDate > "
        + soql_datetime(now)
        + "))"
    )


def assigned_sets_loose(uid: str) -> str:
    """assigned_sets without the activation and expiry filter: every
    assignment, including ones not in force. An allow derived from it is
    not trustworthy."""
    return "(SELECT PermissionSetId FROM PermissionSetAssignment WHERE AssigneeId = '" + uid + "')"


# The unknown answer for an allow that only the unfiltered sub-select
# produced.
LOOSE_TEXT = "could not exclude session-based or expired assignments"

# The domain suffixes an instance_url host may carry besides the configured
# url's own host. UNVERIFIED: every org's REST host is under one of these; a
# host elsewhere is treated as untrusted.
INSTANCE_DOMAINS = (".salesforce.com", ".force.com", ".salesforce.mil")

T = TypeVar("T")


@dataclass
class _ParsedURL:
    scheme: str
    has_user: bool
    host: str  # with port
    hostname: str
    query: str
    fragment: str


def _parse_url(raw: str) -> _ParsedURL | None:
    """The parts of Go's url.Parse this package reads, or None where
    url.Parse fails."""
    rest, _, frag = raw.partition("#")
    rest, _, query = rest.partition("?")
    try:
        scheme, has_user, host = _go_url_parse(rest)
    except ValueError:
        return None
    return _ParsedURL(scheme, has_user, host.decode("utf-8", "surrogateescape"), _hostname(host), query, frag)


class SalesforceConnection(Connection):
    """One Salesforce org reached through one External Client App."""

    def __init__(
        self,
        settings: Settings,
        url: str,
        client_id: str,
        flow: str,
        username: str,
        audience: str,
        version: str,
        match_field: str,
        logger: Logger,
        now: Callable[[], float],
    ) -> None:
        self.settings = settings
        self.url = url
        self.client_id = client_id
        self.flow = flow
        self.username = username
        self.audience = audience
        self.version = version
        self.match_field = match_field
        self.logger = logger
        self.now = now
        self.plain: httpx.Client = httpx.Client()  # the token endpoint, unauthenticated
        self.api: httpx.Client = httpx.Client()  # REST calls with the bearer token
        self.tokens: TokenSource = TokenSource(fetch=None)
        self._inst_lock = threading.Lock()
        self._instance_url = ""
        # desc is the PermissionSet describe's PermissionsXxx field names,
        # under the empty key; objects is whether each sObject exists, by API
        # name. Both are kept for DESCRIBE_TTL. Describes are schema, not
        # permission state: a fresh check does not re-read them.
        self.desc: TTL[tuple[()], frozenset[str]] = TTL(1)
        self.desc.set_clock(now)
        self.objects: TTL[str, bool] = TTL(0)
        self.objects.set_clock(now)
        self.desc.set_fresh_max_age(DESCRIBE_TTL)
        self.objects.set_fresh_max_age(DESCRIBE_TTL)

    # -- authentication --

    def _assertion(self) -> str:
        """Sign the JWT bearer assertion: RS256, iss = consumer key, sub =
        integration user, aud = login host, exp = now + 3 minutes."""
        try:
            pem_text = self.settings.secret("credential").get_string()
        except SecretError as e:
            raise wrap_error(Code.CREDENTIAL_REJECTED, e, "the private key could not be read") from e
        try:
            key = parse_rsa_private_key(pem_text.encode("utf-8", "surrogateescape"))
        except ValueError as e:
            raise wrap_error(Code.CREDENTIAL_REJECTED, e, "the credential is not a PEM RSA private key") from e
        claims = standard_claims(iss=self.client_id, sub=self.username, aud=self.audience, exp=math.floor(self.now() + JWT_LIFETIME))
        return sign_jwt(key, Header(alg=RS256), claims)

    def _token_form(self) -> dict[str, str]:
        """The token request for the configured flow, in the same shape
        authx's jwt_bearer and client_credentials would send."""
        if self.flow == FLOW_CLIENT_CREDENTIALS:
            try:
                sec = self.settings.secret("credential").get_string()
            except SecretError as e:
                raise wrap_error(Code.CREDENTIAL_REJECTED, e, "the consumer secret could not be read") from e
            # UNVERIFIED: the client credentials flow needs a "Run As" user on
            # the External Client App; the token then acts as that user.
            return {"grant_type": "client_credentials", "client_id": self.client_id, "client_secret": sec}
        return {"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": self._assertion()}

    def _fetch_token(self, ctx: Context) -> Token:
        """Post to {url}/services/oauth2/token. The response has no
        expires_in, so the TokenSource's default TTL (token_ttl) applies. It
        is posted here rather than through authx's post_token because the
        instance_url field of the response is needed."""
        form = self._token_form()
        resp = self.plain.do(ctx, httpx.Request(method="POST", path=self.url + TOKEN_PATH, form=form, idempotent=False, accept_4xx=True))
        tr, _ = go_unmarshal(resp.body, (("access_token", STR), ("instance_url", STR), ("token_type", STR), ("error", STR)))
        if resp.status == 429:
            raise errorf(Code.UPSTREAM_RATE_LIMIT, "the token endpoint is rate limiting hallpass")
        if resp.status >= 400 or tr["error"] != "":
            # error_description is deliberately not kept: it can echo the request.
            raise TokenError(resp.status, tr["error"])
        if tr["access_token"] == "":
            raise ValueError("token endpoint returned no access_token")
        # UNVERIFIED: the token response's instance_url is the host that
        # serves the org's REST API and may differ from the My Domain URL. It
        # is used as the API base when it is an https URL without query or
        # userinfo whose host is the configured url's host or a
        # Salesforce-owned domain; otherwise url is used.
        self.set_instance_url(tr["instance_url"])
        return Token(tr["access_token"])

    def set_instance_url(self, s: str) -> None:
        """Record the token response's instance_url as the API base when it
        is trustworthy: https, no userinfo, query or fragment, and a host
        that either equals the configured url's host or is under a
        Salesforce domain. Anything else is ignored, so a token endpoint (or
        a proxy in front of it) cannot redirect the bearer token to a host
        of its choosing."""
        s = go_trim_space(s).rstrip("/")
        inst = ""
        u = _parse_url(s)
        if u is not None and u.scheme == "https" and u.host != "" and not u.has_user and u.query == "" and u.fragment == "":
            if self._trusted_instance_host(u):
                inst = s
            else:
                self.logger.debug("salesforce: ignoring token response instance_url with an untrusted host; using url", host=u.host)
        with self._inst_lock:
            self._instance_url = inst

    def _trusted_instance_host(self, u: _ParsedURL) -> bool:
        cfg = _parse_url(self.url)
        if cfg is not None and cfg.host != "" and equal_fold(cfg.host, u.host):
            return True
        host = go_lower(u.hostname)
        return any(host.endswith(d) and len(host) > len(d) for d in INSTANCE_DOMAINS)

    def api_base(self) -> str:
        """The instance URL learned from the token response, or url."""
        with self._inst_lock:
            return self._instance_url if self._instance_url != "" else self.url

    def _bearer_auth(self, ctx: Context, r: httpx.PreparedRequest) -> None:
        try:
            tok = self.tokens.get(ctx)
        except Exception as e:
            raise classify_token_error(e) from e
        r.headers.set("Authorization", "Bearer " + tok)

    # -- transport --

    def _get(self, ctx: Context, path: str, q: dict[str, str] | None, decode: Callable[[Any], T] | None) -> T | None:
        """One authenticated GET. A 401 drops the cached token and the call
        is retried once with a fresh one; a second 401 is an ApiError."""
        resp = self._get_once(ctx, path, q)
        if resp.status == 401:
            # UNVERIFIED: an expired or revoked session answers 401 with
            # errorCode INVALID_SESSION_ID. Any 401 is treated that way: the
            # token is dropped and minted again once.
            self.tokens.invalidate()
            resp = self._get_once(ctx, path, q)
        if resp.status >= 400:
            raise decode_api_error(resp)
        if decode is None:
            return None
        try:
            return decode(_go_decode_first(resp.body))
        except (ValueError, RecursionError) as e:
            raise wrap_error(Code.UPSTREAM_ERROR, e, "the Salesforce response was not JSON") from e

    def _get_once(self, ctx: Context, path: str, q: dict[str, str] | None) -> httpx.Response:
        # The token is fetched before the URL is built so the instance URL it
        # carries is the base of this very call.
        try:
            self.tokens.get(ctx)
        except Exception as e:
            raise classify_token_error(e) from e
        return self.api.do(ctx, httpx.Request(method="GET", path=self.api_base() + path, query=q, accept_4xx=True))

    def query(self, ctx: Context, soql: str) -> list[Any]:
        """Run one SOQL statement as GET /services/data/{v}/query?q=... and
        return every record, following nextRecordsUrl a bounded number of
        times. The statement must have been assembled only from validated
        parts."""
        records: list[Any] = []
        path = "/services/data/" + self.version + "/query"
        q: dict[str, str] | None = {"q": soql}
        page = 0
        while True:
            if page >= MAX_QUERY_PAGES:
                raise errorf(Code.UPSTREAM_ERROR, f"query returned more than {MAX_QUERY_PAGES} pages")
            qr = self._get(ctx, path, q, _decode_query_response)
            assert qr is not None
            records.extend(qr.records)
            if qr.done or qr.next_records_url == "":
                return records
            # UNVERIFIED: nextRecordsUrl is a path such as
            # /services/data/v66.0/query/01gxx-2000 on the same instance.
            if not qr.next_records_url.startswith("/services/data/"):
                raise errorf(Code.UPSTREAM_ERROR, "unexpected nextRecordsUrl shape")
            path, q = qr.next_records_url, None
            page += 1

    def query_into(self, ctx: Context, soql: str, decode: Callable[[Any], T]) -> list[T]:
        """query with the records decoded."""
        raw = self.query(ctx, soql)
        out = []
        for r in raw:
            try:
                out.append(decode(r))
            except (ValueError, RecursionError) as e:
                raise wrap_error(Code.UPSTREAM_ERROR, e, "a query record could not be decoded") from e
        return out

    def permission_fields(self, ctx: Context) -> frozenset[str]:
        """The PermissionsXxx field names of PermissionSet from its
        describe, cached for an hour."""

        def fill(ctx: Context) -> tuple[frozenset[str], float]:
            # UNVERIFIED: the describe lists one boolean field per system or
            # app permission, named PermissionsXxx.
            try:
                names = self._get(ctx, "/services/data/" + self.version + "/sobjects/PermissionSet/describe", None, _decode_describe)
            except Exception as e:
                raise classify(e, "the PermissionSet describe")
            fields = frozenset(n for n in names or [] if PERM_NAME_RE.fullmatch(n))
            if len(fields) == 0:
                raise errorf(Code.UPSTREAM_ERROR, "the PermissionSet describe listed no PermissionsXxx fields")
            return fields, DESCRIBE_TTL

        return self.desc.do(ctx, (), fill)

    # -- identity --

    def resolve_identity(self, ctx: Context, u: User) -> Identity:
        """Find the User row whose match_field equals the email."""
        try:
            if self.match_field == MATCH_FEDERATION_ID:
                validate_text(u.email)
            else:
                validate_email(u.email)
        except ValueError as e:
            raise errorf(Code.INVALID_REQUEST, f"user: {e}") from None
        row = self._lookup_user(ctx, u.email)
        try:
            validate_id(row.id)
        except ValueError:
            raise errorf(Code.UPSTREAM_ERROR, "the User row carries no valid Id") from None
        frozen = self._frozen_state(ctx, row.id)
        return Identity(
            id=row.id,
            display=row.username,
            attrs={
                ATTR_ACTIVE: "true" if row.is_active else "false",
                ATTR_FROZEN: frozen,
                ATTR_USERNAME: row.username,
                ATTR_USER_TYPE: row.user_type,
            },
        )

    def _query_users(self, ctx: Context, field: str, value: str, limit: int) -> list[UserRow]:
        """One User lookup by field, which is one of the match_field
        constants; the literal is escaped."""
        soql = (
            "SELECT Id, IsActive, Username, Email, FederationIdentifier, UserType, Name FROM User WHERE "
            + field
            + " = '"
            + soql_string(value)
            + "' LIMIT "
            + str(limit)
        )
        try:
            return self.query_into(ctx, soql, _decode_user_row)
        except Exception as e:
            raise classify(e, "User")

    def _lookup_user(self, ctx: Context, value: str) -> UserRow:
        """The one User row for the value. Under match_field Email an exact
        Username lookup runs first (Username is unique, and a person's
        primary account usually carries the address as its Username); only
        when that finds nothing is the Email match tried. Username is
        matched exactly; FederationIdentifier is matched with the same bound
        and must be unique."""
        if self.match_field in (MATCH_EMAIL, MATCH_USERNAME):
            rows = self._query_users(ctx, MATCH_USERNAME, value, EXACT_USER_LIMIT)
            if len(rows) == 1:
                return rows[0]
            if len(rows) > 1:
                raise user_ambiguous(f"{len(rows)} Salesforce users have Username {go_quote(value)}")
            if self.match_field == MATCH_USERNAME:
                raise user_not_found(f"no Salesforce user has Username {go_quote(value)}")
        rows = self._query_users(ctx, self.match_field, value, MATCH_USER_LIMIT)
        return pick_user(rows, value, self.match_field, MATCH_USER_LIMIT)

    def _frozen_state(self, ctx: Context, user_id: str) -> str:
        """UserLogin.IsFrozen as FROZEN_TRUE, FROZEN_FALSE or, where the org
        or the integration user cannot query UserLogin, FROZEN_UNKNOWN. A
        user whose frozen state is unknown is still allowed; the probe
        reports the gap."""
        # UNVERIFIED: UserLogin exposes IsFrozen per user and is queryable by
        # the integration user; where the object or field is missing the
        # query fails with INVALID_TYPE or INVALID_FIELD and freezing is not
        # modelled.
        try:
            rows = self.query_into(ctx, "SELECT IsFrozen FROM UserLogin WHERE UserId = '" + user_id + "'", _decode_frozen)
        except Exception as e:
            if is_query_shape_error(e):
                self.logger.debug("salesforce: " + FROZEN_NOT_DETECTED)
                return FROZEN_UNKNOWN
            raise classify(e, "UserLogin")
        return FROZEN_TRUE if any(rows) else FROZEN_FALSE

    # -- checks --

    def check(self, ctx: Context, r: CheckRequest) -> Decision:
        """Answer one question with one to three SOQL queries."""
        act = ACTIONS.get(r.action_name)
        if act is None:
            if r.action_name == "record.create":
                raise errorf(Code.INVALID_REQUEST, "records are created per object: use object.create with object:<ApiName>")
            raise errorf(Code.INVALID_REQUEST, f"unknown action {go_quote(r.action_name)}")
        try:
            t = parse_target(act, r.resource)
        except ValueError as e:
            raise errorf(Code.INVALID_REQUEST, str(e)) from None
        uid = r.identity.id
        try:
            validate_id(uid)
        except ValueError:
            raise errorf(Code.UPSTREAM_ERROR, "the resolved identity is not a Salesforce Id") from None
        who = r.identity.display or uid
        if r.identity.attr(ATTR_ACTIVE) != "true":
            return denied(f"user {who} is inactive")
        if r.identity.attr(ATTR_FROZEN) == FROZEN_TRUE:
            return denied(f"user {who} is frozen")
        if act.kind == Kind.RECORD:
            return self._check_record(ctx, act, uid, who, t)
        if act.kind == Kind.OBJECT:
            return self._check_object(ctx, act, uid, who, t)
        if act.kind == Kind.FIELD:
            return self._check_field(ctx, act, uid, who, t)
        if act.kind == Kind.SYSTEM:
            return self._check_system(ctx, uid, who, t)
        if act.kind == Kind.PERM_SET:
            return self._check_perm_set(ctx, uid, who, t)
        return self._check_user(r, uid, who, t)

    def _check_record(self, ctx: Context, act: SFAction, uid: str, who: str, t: Target) -> Decision:
        """Ask UserRecordAccess, which must be filtered by exactly one
        UserId and one RecordId."""
        soql = (
            "SELECT RecordId, HasReadAccess, HasEditAccess, HasDeleteAccess, HasTransferAccess, HasAllAccess, MaxAccessLevel "
            + "FROM UserRecordAccess WHERE UserId = '"
            + uid
            + "' AND RecordId = '"
            + t.record_id
            + "'"
        )
        try:
            rows = self.query_into(ctx, soql, _decode_record_access)
        except Exception as e:
            raise classify(e, "UserRecordAccess for record " + t.record_id)
        if len(rows) == 0:
            # UNVERIFIED: UserRecordAccess reportedly returns no row for a
            # record the running (integration) user cannot see, and for
            # objects without sharing settings.
            return unknown_decision(
                Code.RESOURCE_NOT_VISIBLE, f"record {t.record_id} is not visible to the integration user, or its object has no sharing settings"
            )
        row = rows[0]
        level = access_level(row.max_access_level)
        if row.column(act.column):
            return allowed(f"{who} has {act.column} on record {t.record_id} (max access level {level})")
        return denied(f"{who} lacks {act.column} on record {t.record_id} (max access level {level})")

    def _query_assigned(self, ctx: Context, uid: str, build: Callable[[str], str], decode: Callable[[Any], T]) -> tuple[list[T], bool]:
        """Run build(sub) with the filtered assignment sub-select. When the
        org rejects the filter fields (INVALID_FIELD), run once more with the
        loose sub-select and report loose = True, in which case the caller
        may still deny (the loose set is a superset) but must not allow."""
        try:
            return self.query_into(ctx, build(assigned_sets(uid, self.now())), decode), False
        except Exception as e:
            ae = as_error(e, ApiError)
            if api_status(e) != 400 or ae is None or not ae.has("INVALID_FIELD"):
                raise
        self.logger.debug("salesforce: the assignment filter was rejected (INVALID_FIELD); retrying without it, allows become unknown")
        return self.query_into(ctx, build(assigned_sets_loose(uid)), decode), True

    def _object_exists(self, ctx: Context, name: str) -> Decision | None:
        """Confirm the sObject through its describe, cached for an hour. A
        404 is returned as an unknown decision (None means it exists); any
        other failure is raised."""

        def fill(ctx: Context) -> tuple[bool, float]:
            # UNVERIFIED: the describe of an object that does not exist, or
            # that the integration user cannot see at all, is a 404 NOT_FOUND.
            try:
                self._get(ctx, "/services/data/" + self.version + "/sobjects/" + httpx.path_escape(name) + "/describe", None, None)
            except Exception as e:
                if api_status(e) == 404:
                    return False, DESCRIBE_TTL
                raise classify(e, "the describe of " + name)
            return True, DESCRIBE_TTL

        if not self.objects.do(ctx, name, fill):
            return unknown_decision(Code.RESOURCE_NOT_VISIBLE, f"object {name} does not exist or is not visible to the integration user")
        return None

    def _check_object(self, ctx: Context, act: SFAction, uid: str, who: str, t: Target) -> Decision:
        """OR ObjectPermissions across the user's profile and permission
        sets. Zero rows is a deny once the object is known to exist: nothing
        grants it."""
        stale = self._groups_recalculated(ctx, uid)
        if stale is not None:
            return stale
        # UNVERIFIED: profile object permissions are rows whose Parent is the
        # profile's owned permission set, and a permission set group's rows
        # reflect its muting sets through the aggregate permission set.

        def build(sub: str) -> str:
            return (
                "SELECT PermissionsRead, PermissionsCreate, PermissionsEdit, PermissionsDelete, PermissionsViewAllRecords, "
                + "PermissionsModifyAllRecords, Parent.IsOwnedByProfile, Parent.Name "
                + "FROM ObjectPermissions WHERE SobjectType = '"
                + t.object
                + "' AND ParentId IN "
                + sub
            )

        try:
            rows, loose = self._query_assigned(ctx, uid, build, _decode_object_perm)
        except Exception as e:
            raise classify(e, "ObjectPermissions for " + t.object)
        for row in rows:
            if row.column(act.column):
                if loose:
                    return unsupported(f"{who} may have {act.column} on {t.object} through {row.parent.label()}, but hallpass {LOOSE_TEXT}")
                return allowed(f"{who} has {act.column} on {t.object} through {row.parent.label()}")
        if len(rows) == 0:
            missing = self._object_exists(ctx, t.object)
            if missing is not None:
                return missing
            return denied(f"no profile or permission set assigned to {who} grants any access to {t.object}")
        return denied(f"{who} lacks {act.column} on {t.object} across {len(rows)} assigned profile and permission sets")

    def _check_field(self, ctx: Context, act: SFAction, uid: str, who: str, t: Target) -> Decision:
        """OR FieldPermissions. Zero rows is unknown: required and system
        fields have no FieldPermissions rows at all."""
        stale = self._groups_recalculated(ctx, uid)
        if stale is not None:
            return stale
        full = t.object + "." + t.field

        def build(sub: str) -> str:
            return (
                "SELECT PermissionsRead, PermissionsEdit, Parent.IsOwnedByProfile, Parent.Name FROM FieldPermissions "
                + "WHERE SobjectType = '"
                + t.object
                + "' AND Field = '"
                + full
                + "' AND ParentId IN "
                + sub
            )

        try:
            rows, loose = self._query_assigned(ctx, uid, build, _decode_field_perm)
        except Exception as e:
            raise classify(e, "FieldPermissions for " + full)
        for row in rows:
            granted = row.column("PermissionsEdit") if act.column == "PermissionsEdit" else row.column("PermissionsRead")
            if granted:
                if loose:
                    return unsupported(f"{who} may have {act.column} on {full} through {row.parent.label()}, but hallpass {LOOSE_TEXT}")
                return allowed(f"{who} has {act.column} on {full} through {row.parent.label()}")
        if len(rows) == 0:
            # UNVERIFIED: required, system and some standard fields have no
            # FieldPermissions rows; the absence is not a refusal.
            return unsupported(f"no FieldPermissions rows for {full}: required or system fields carry none, so field-level security cannot be read")
        return denied(f"{who} lacks {act.column} on {full} across {len(rows)} assigned profile and permission sets")

    def _check_system(self, ctx: Context, uid: str, who: str, t: Target) -> Decision:
        """Whether any assigned permission set (profile included) has the
        PermissionsXxx boolean set. The field name reaches the query only
        after the describe confirms it exists."""
        fields = self.permission_fields(ctx)
        if t.perm not in fields:
            raise errorf(Code.INVALID_REQUEST, f"{t.perm} is not a permission field of PermissionSet in this org")
        stale = self._groups_recalculated(ctx, uid)
        if stale is not None:
            return stale

        def build(sub: str) -> str:
            return "SELECT Id, Name, IsOwnedByProfile FROM PermissionSet WHERE " + t.perm + " = true AND Id IN " + sub

        try:
            rows, loose = self._query_assigned(ctx, uid, build, _decode_perm_set)
        except Exception as e:
            raise classify(e, "PermissionSet." + t.perm)
        if rows:
            p = rows[0]
            if loose:
                return unsupported(f"{who} may hold {t.perm} through {p.label()}, but hallpass {LOOSE_TEXT}")
            return allowed(f"{who} holds {t.perm} through {p.label()}")
        return denied(f"no profile or permission set assigned to {who} has {t.perm}")

    def _check_perm_set(self, ctx: Context, uid: str, who: str, t: Target) -> Decision:
        """Whether the user is assigned the permission set by API name. A
        managed package's set is permset:<ns>__<Name> and is matched on
        NamespacePrefix too; an unprefixed name matches only sets without
        one."""
        # UNVERIFIED: PermissionSet.NamespacePrefix is null for local sets and
        # filterable through the PermissionSet relationship of the assignment.
        ns = "PermissionSet.NamespacePrefix = null"
        if t.perm_set_ns != "":
            ns = "PermissionSet.NamespacePrefix = '" + t.perm_set_ns + "'"
        soql = "SELECT Id FROM PermissionSetAssignment WHERE AssigneeId = '" + uid + "' AND PermissionSet.Name = '" + t.perm_set + "' AND " + ns
        try:
            rows = self.query(ctx, soql)
        except Exception as e:
            raise classify(e, "PermissionSetAssignment for " + t.perm_set_full())
        if rows:
            return allowed(f"{who} is assigned permission set {t.perm_set_full()}")
        return denied(f"{who} is not assigned permission set {t.perm_set_full()}")

    def _check_user(self, r: CheckRequest, uid: str, who: str, t: Target) -> Decision:
        """user.active from the resolved identity; an inactive or frozen
        user was already denied before dispatch."""
        if t.record_id != "" and not equal_fold(t.record_id, uid):
            raise errorf(Code.INVALID_REQUEST, f"record:{t.record_id} is not the user's own Id {uid}; user.active answers about the requesting user")
        if t.email != "" and not equal_fold(t.email, r.user.email):
            raise errorf(Code.INVALID_REQUEST, f"user:{t.email} is not the requesting user; user.active answers about the requesting user")
        if r.identity.attr(ATTR_FROZEN) == FROZEN_UNKNOWN:
            return allowed(f"user {who} is active ({FROZEN_NOT_DETECTED})")
        return allowed(f"user {who} is active and not frozen")

    def _groups_recalculated(self, ctx: Context, uid: str) -> Decision | None:
        """Check that every permission set group assigned to the user has
        Status Updated. A group mid-recalculation would make the aggregate
        permission set stale, so the answer is unknown (returned) until it
        is; None means none is stale."""
        # UNVERIFIED: PermissionSetAssignment.PermissionSetGroupId is set on
        # assignments made through a group, and PermissionSetGroup.Status is
        # "Updated" once the aggregate set reflects its members and mutings.
        try:
            asg = self.query_into(
                ctx,
                "SELECT PermissionSetGroupId FROM PermissionSetAssignment WHERE AssigneeId = '" + uid + "' AND PermissionSetGroupId != null",
                _decode_group_assignment,
            )
        except Exception as e:
            if is_query_shape_error(e):
                self.logger.debug("salesforce: PermissionSetGroup not queryable; group status is not checked")
                return None
            raise classify(e, "PermissionSetAssignment")
        ids: list[str] = []
        seen: set[str] = set()
        for gid in asg:
            if gid == "" or gid in seen:
                continue
            try:
                validate_id(gid)
            except ValueError:
                raise errorf(Code.UPSTREAM_ERROR, "a PermissionSetGroupId is not a Salesforce Id") from None
            seen.add(gid)
            ids.append(gid)
        if not ids:
            return None
        try:
            groups = self.query_into(ctx, "SELECT Id, DeveloperName, Status FROM PermissionSetGroup WHERE Id IN (" + soql_id_list(ids) + ")", _decode_group)
        except Exception as e:
            raise classify(e, "PermissionSetGroup")
        stale = [dev or gid for gid, dev, status in groups if status != "Updated"]
        if stale:
            return unsupported(f"permission set group {', '.join(stale)} not yet recalculated; retry once its status is Updated")
        return None

    # -- probe --

    def probe(self, ctx: Context) -> ProbeResult:
        """Mint a token, read the org's API limits, confirm the integration
        user exists and fetch the PermissionSet describe."""
        try:
            self.tokens.get(ctx)
        except Exception as e:
            raise classify_token_error(e) from e
        warnings: list[str] = []
        # UNVERIFIED: /limits reports DailyApiRequests with Max and Remaining.
        try:
            limits = self._get(ctx, "/services/data/" + self.version + "/limits", None, _decode_limits)
        except Exception as e:
            raise classify(e, "/limits")
        assert limits is not None
        summary = "authenticated against " + self.api_base() + " with API " + self.version
        if "DailyApiRequests" in limits:
            mx_n, rem_n = limits["DailyApiRequests"]
            mx, rem = _int64(mx_n), _int64(rem_n)
            summary += f"; {rem} of {mx} daily API requests remaining"
            if mx > 0 and rem * 100 < mx * LOW_LIMIT_PERCENT:
                warnings.append(
                    f"under {LOW_LIMIT_PERCENT}% of the daily API request allocation remains ({rem} of {mx}); every check costs one to three requests"
                )
        self_id = ""
        if self.username != "":
            try:
                rows = self.query_into(ctx, "SELECT Id, Username, IsActive FROM User WHERE Username = '" + soql_string(self.username) + "'", _decode_user_row)
            except Exception as e:
                raise classify(e, "User")
            if len(rows) == 0:
                warnings.append("no User row has Username " + self.username + "; the integration user cannot be confirmed")
            elif not rows[0].is_active:
                warnings.append("the integration user " + self.username + " is inactive")
            else:
                summary += " as " + rows[0].username
            if rows:
                try:
                    validate_id(rows[0].id)
                    self_id = rows[0].id
                except ValueError:
                    pass
        # The frozen check is tried on the integration user itself, so an org
        # where UserLogin is not queryable is reported here rather than
        # silently answering allow for frozen users.
        if self_id != "":
            if self._frozen_state(ctx, self_id) == FROZEN_UNKNOWN:
                warnings.append(FROZEN_NOT_DETECTED)
        else:
            # UNVERIFIED: without a known user Id (client_credentials, or the
            # integration user not found) UserLogin is probed unfiltered.
            try:
                self.query(ctx, "SELECT IsFrozen FROM UserLogin LIMIT 1")
            except Exception as e:
                if not is_query_shape_error(e):
                    raise classify(e, "UserLogin")
                warnings.append(FROZEN_NOT_DETECTED)
        fields = self.permission_fields(ctx)
        summary += f"; {len(fields)} permission fields known"
        warnings.append(
            "UserRecordAccess reportedly omits records the integration user cannot see: record.* answers are unknown for those unless the user has "
            "View All on the object (or View All Data); confirm in a Developer Edition org before relying on record checks"
        )
        return ProbeResult(summary=summary, warnings=tuple(warnings))
