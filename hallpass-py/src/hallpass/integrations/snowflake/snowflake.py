"""Checks what a user may do in a Snowflake account.

hallpass authenticates as a service user with a key pair through the SQL
REST API, finds the user with SHOW USERS, lists the roles granted to the
user with SHOW GRANTS TO USER and walks the role hierarchy with SHOW GRANTS
TO ROLE, then looks for the privilege the question needs on the object
(OWNERSHIP counts), and for USAGE on the object's database and schema. Only
SHOW commands run, which need no warehouse. Nothing is written.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import threading
import time
from collections import deque
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from hallpass.authx.jwt import RS256, Header, parse_rsa_private_key, sign_jwt, standard_claims
from hallpass.authx.token import Token, TokenSource
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
    to_decision,
    unsupported,
    user_ambiguous,
    user_not_found,
    wrap_error,
)
from hallpass.core.errors import go_lower, go_quote, go_trim_space, is_error
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
    validate_https_url,
)
from hallpass.core.secret import Secret, SecretError
from hallpass.core.template import is_email
from hallpass.integrations.snowflake.actions import KINDS, Target, catalog_actions, match_action, parse_target
from hallpass.integrations.snowflake.sql import like_literal, parse_identifier, quote, quote_name, same_name, split_name, string_literal
from hallpass.net import httpx

__all__ = ["NotVisible", "Snowflake", "SnowflakeConnection", "classify_sql", "fingerprint"]

# The key-pair token's validity; Snowflake accepts up to an hour.
JWT_LIFETIME = 50 * 60.0
# The seconds a SHOW command may take.
STATEMENT_TIMEOUT = 30
# How long a role's grants are kept.
GRANTS_TTL = 120.0
# Bounds the role hierarchy walk.
MAX_ROLES = 500
# The SHOW USERS page size.
USER_PAGE = 10000
# Bounds the SHOW USERS scan.
MAX_USER_PAGES = 20

_ACCOUNT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,254}")
_HANDLE_RE = re.compile(r"[0-9a-fA-F-]{36}")


def _fold(c: str) -> str:
    f = c.casefold()
    if len(f) == 1:
        return f
    lo = c.lower()
    return lo if len(lo) == 1 else c


def equal_fold(a: str, b: str) -> bool:
    """Go's strings.EqualFold: equal under simple Unicode case folding."""
    return len(a) == len(b) and all(x == y or _fold(x) == _fold(y) for x, y in zip(a, b, strict=True))


def go_upper(s: str) -> str:
    """Go's strings.ToUpper: the simple, one-rune-for-one mapping (str.upper
    turns "ß" into "SS"; Go leaves it)."""
    if s.isascii():
        return s.upper()
    out = []
    for c in s:
        u = c.upper()
        out.append(u if len(u) == 1 else c)
    return "".join(out)


def _or_empty(s: str, default: str) -> str:
    return default if s == "" else s


def fingerprint(pub: Any) -> str:
    """SHA256:<base64 of the SHA-256 of the public key's DER>."""
    from cryptography.hazmat.primitives import serialization

    der = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return "SHA256:" + base64.b64encode(hashlib.sha256(der).digest()).decode("ascii")


class Snowflake(Integration):
    """The snowflake product."""

    def name(self) -> str:
        return "snowflake"

    def fields(self) -> list[Field]:
        return [
            Field(name="account", required=True, description="the account identifier, e.g. myorg-myaccount (or the legacy locator xy12345.us-east-1)"),
            Field(name="user", required=True, description="the service user hallpass authenticates as"),
            credential_field(True, "the user's RSA private key (PEM, unencrypted) for key-pair authentication"),
            Field(name="role", description="the role to run as; it needs MANAGE GRANTS (or SECURITYADMIN) to see other users' grants"),
            url_field(False, "the account URL, default https://<account>.snowflakecomputing.com"),
        ]

    def actions(self) -> list[Action]:
        return catalog_actions()

    def match_action(self, name: str) -> Action | None:
        """Accept raw:<PRIVILEGE>."""
        return match_action(name)

    def new(self, ctx: Context, s: Settings, d: Deps) -> Connection:
        """Build a connection. It touches no network."""
        hc = d.http_client(s)
        account = go_trim_space(s.get("account"))
        if not _ACCOUNT_RE.fullmatch(account):
            raise ValueError("account is required and must be an account identifier")
        try:
            user = parse_identifier(go_trim_space(s.get("user")))
        except ValueError as e:
            raise ValueError(f"user: {e}") from None
        if s.secret("credential").is_zero():
            raise ValueError("credential (the private key) is required")
        role = ""
        r = go_trim_space(s.get("role"))
        if r != "":
            try:
                role = parse_identifier(r)
            except ValueError as e:
                raise ValueError(f"role: {e}") from None
        base = go_trim_space(s.get("url")).rstrip("/")
        if base == "":
            # Underscores in an account identifier are hyphens in its host name.
            base = "https://" + account.lower().replace("_", "-") + ".snowflakecomputing.com"
        try:
            validate_https_url(base)
        except ValueError as e:
            raise ValueError(f"url: {e}") from None
        # The iss and sub claims name the account and user the way the
        # official drivers do: upper case, the legacy locator cut at its first
        # dot (a .global locator at its first dash).
        acct = account.partition("-")[0] if ".global" in account else account.partition(".")[0]
        subject = go_upper(acct) + "." + go_upper(user)
        c = SnowflakeConnection(user=user, role=role, now=d.now if d.now is not None else time.time)
        c.tokens = TokenSource(fetch=_key_pair_fetch(s.secret("credential"), subject, c.now), now=c.now)

        def auth(ctx: Context, req: httpx.PreparedRequest) -> None:
            tok = c.tokens.get(ctx)
            req.headers.set("Authorization", "Bearer " + tok)
            req.headers.set("X-Snowflake-Authorization-Token-Type", "KEYPAIR_JWT")

        c.api = httpx.Client(http=hc, base=base, logger=d.logger, auth=auth)
        return c


def _key_pair_fetch(cred: Secret, subject: str, now_fn: Callable[[], float]) -> Callable[[Context], Token]:
    def fetch(ctx: Context) -> Token:
        try:
            pem = cred.get_string()
        except SecretError as e:
            raise wrap_error(Code.CREDENTIAL_REJECTED, e, "the private key could not be read") from e
        try:
            key = parse_rsa_private_key(pem.encode("utf-8", "surrogateescape"))
        except ValueError as e:
            raise wrap_error(Code.CREDENTIAL_REJECTED, e, "the credential is not an unencrypted RSA private key in PEM") from e
        now = now_fn()
        claims = standard_claims(
            iss=subject + "." + fingerprint(key.public_key()),
            sub=subject,
            iat=math.floor(now),
            exp=math.floor(now + JWT_LIFETIME),
        )
        try:
            jwt = sign_jwt(key, Header(alg=RS256), claims)
        except ValueError as e:
            raise wrap_error(Code.CREDENTIAL_REJECTED, e, "the key-pair token could not be signed") from e
        return Token(jwt, now + JWT_LIFETIME)

    return fetch


# -- SQL API ------------------------------------------------------------------------


class NotVisible(Exception):
    """A statement Snowflake refused because the object does not exist or
    hallpass's role may not see it."""

    def __init__(self) -> None:
        super().__init__("object not visible")


class Row(dict):  # type: ignore[type-arg]
    """One result row by lower-cased column name."""

    def get_col(self, k: str) -> str:
        return str(self.get(go_lower(k), ""))


@dataclass
class _ResultSet:
    """The SQL API's response to a completed statement."""

    statement_handle: str
    data: list[list[str]]
    row_type: list[str]
    partitions: int

    def rows(self) -> list[Row]:
        """The positional data as rows keyed by column name."""
        cols = [go_lower(c) for c in self.row_type]
        out = []
        for d in self.data:
            if len(d) != len(cols):
                raise errorf(Code.UPSTREAM_ERROR, f"a result row has {len(d)} cells for {len(cols)} columns")
            out.append(Row(zip(cols, d, strict=True)))
        return out


def _reject_constant(name: str) -> Any:
    raise ValueError(f"invalid character '{name[0]}' looking for beginning of value")


def _decode_first(body: bytes) -> Any:
    """httpx.Response.JSON: the first value of the body, no NaN or
    Infinity."""
    text = body.decode("utf-8", "replace")
    stripped = text.lstrip(" \t\r\n")
    if not stripped:
        raise ValueError("empty body")
    v, _ = json.JSONDecoder(parse_constant=_reject_constant).raw_decode(stripped)
    return v


def _cells(v: Any) -> list[str]:
    """A []string: null is empty, a null cell is ""."""
    if v is None:
        return []
    if not isinstance(v, list):
        raise jsonx.DecodeError("json: cannot unmarshal into Go struct field data of type []string")
    out = []
    for x in v:
        if x is None:
            out.append("")
        elif isinstance(x, str):
            out.append(x)
        else:
            raise jsonx.DecodeError("json: cannot unmarshal into Go struct field data of type string")
    return out


def _decode_result_set(v: Any) -> _ResultSet:
    d = jsonx.obj(v)
    for k in ("code", "sqlState", "message"):
        jsonx.s(d, k)
    handle = jsonx.s(d, "statementHandle")
    data = [_cells(x) for x in jsonx.arr(d, "data")]
    meta = jsonx.o(d, "resultSetMetaData")
    jsonx.i(meta, "numRows")
    row_type = [jsonx.s(jsonx.obj(x), "name") for x in jsonx.arr(meta, "rowType")]
    parts = [jsonx.i(jsonx.obj(x), "rowCount") for x in jsonx.arr(meta, "partitionInfo")]
    return _ResultSet(statement_handle=handle, data=data, row_type=row_type, partitions=len(parts))


def classify_sql(code: str, sql_state: str) -> BaseException:
    """A statement failure by its Snowflake error code. The message may
    echo identifiers, so only the code reaches the text."""
    if code in ("002003", "002043", "090105"):
        # Object does not exist or not authorized; not authorized to view.
        return NotVisible()
    if code == "003001":
        return errorf(Code.CREDENTIAL_REJECTED, f"hallpass's role lacks the privilege for the command (Snowflake error {code}); it needs MANAGE GRANTS")
    if code in ("390144", "390142", "390143", "390318"):
        return errorf(Code.CREDENTIAL_REJECTED, f"Snowflake rejected the key-pair token (error {code})")
    if code in ("000630", "000604"):
        return errorf(Code.UPSTREAM_TIMEOUT, f"the statement was cancelled or timed out (error {code})")
    return errorf(Code.UPSTREAM_ERROR, f"the statement failed (Snowflake error {_or_empty(code, 'unknown')}, SQL state {_or_empty(sql_state, 'unknown')})")


def _classify(err: BaseException) -> HallpassError:
    out = httpx.classify(err)
    assert out is not None
    return out


@dataclass(frozen=True)
class Grant:
    """One SHOW GRANTS TO ROLE row, its object name parsed into resolved
    parts."""

    privilege: str
    granted_on: str
    name: tuple[str, ...]
    granted_by: str


@dataclass(frozen=True)
class Holding:
    """A privilege found on an object: which role holds it and by which
    chain of roles the user reaches it."""

    grant: Grant
    role: str
    chain: tuple[str, ...]

    @property
    def privilege(self) -> str:
        return self.grant.privilege


def find(holdings: Sequence[Holding], granted_on: Sequence[str], name: Sequence[str], privileges: Sequence[str]) -> Holding | None:
    """The first holding of one of the privileges (or OWNERSHIP) on an
    object of one of the kinds with the name; the returned holding's
    privilege is the one that answered."""
    for h in holdings:
        if h.grant.granted_on not in granted_on:
            continue
        if name and not same_name(h.grant.name, name):
            continue
        if h.grant.privilege == "OWNERSHIP":
            return h
        if h.grant.privilege in privileges:
            return h
    return None


def via(chain: Sequence[str]) -> str:
    """A role chain of quoted names in words."""
    if len(chain) <= 1:
        return "directly"
    return "through " + " -> ".join(chain)


class SnowflakeConnection(Connection):
    """One Snowflake account."""

    def __init__(self, user: str, role: str, now: Callable[[], float]) -> None:
        self.api = httpx.Client()
        self.tokens = TokenSource(fetch=None)
        self.user = user
        self.role = role
        self.now = now
        # SHOW GRANTS TO ROLE per role.
        self.grants: TTL[str, list[Grant]] = TTL(0)
        self.grants.set_clock(now)

    def _sleep(self, ctx: Context, seconds: float) -> None:
        """Wait, or raise when the context ends first."""
        done = threading.Event()
        timer = threading.Timer(seconds, done.set)
        timer.daemon = True
        timer.start()
        try:
            if not ctx.wait(done):
                raise wrap_error(Code.UPSTREAM_TIMEOUT, ctx.err(), "the SHOW command did not finish in time")
        finally:
            timer.cancel()

    def run(self, ctx: Context, statement: str) -> list[Row]:
        """Execute one statement and return its rows. Statements here are
        SHOW commands built from validated identifiers."""
        body: dict[str, Any] = {}
        if self.role != "":
            body["role"] = self.role
        body["statement"] = statement
        body["timeout"] = STATEMENT_TIMEOUT
        try:
            resp = self.api.do(ctx, httpx.Request(method="POST", path="/api/v2/statements", json=body, idempotent=True, accept_4xx=True))
        except Exception as e:  # noqa: BLE001 - classified and re-raised
            raise _classify(e)
        attempt = 0
        while resp.status == 202:
            # The statement is still running: poll its handle.
            try:
                handle = jsonx.s(jsonx.obj(_decode_first(resp.body)), "statementHandle")
            except (ValueError, RecursionError):
                handle = ""
            if not _HANDLE_RE.fullmatch(handle):
                raise errorf(Code.UPSTREAM_ERROR, "Snowflake accepted the statement without a usable handle")
            if attempt >= 10:
                raise errorf(Code.UPSTREAM_TIMEOUT, "the SHOW command did not finish in time")
            self._sleep(ctx, 0.2 * (attempt + 1))
            try:
                resp = self.api.do(ctx, httpx.Request(path="/api/v2/statements/" + handle, accept_4xx=True))
            except Exception as e:  # noqa: BLE001 - classified and re-raised
                raise _classify(e)
            attempt += 1
        if resp.status == 401:
            # A rotated key: the next call signs a fresh token from the
            # credential as it is now.
            self.tokens.invalidate()
            raise errorf(
                Code.CREDENTIAL_REJECTED,
                "Snowflake rejected the key-pair token (HTTP 401): check account, user and the public key registered on the user",
            )
        if resp.status == 403:
            raise errorf(Code.CREDENTIAL_REJECTED, "Snowflake refused the request (HTTP 403)")
        if resp.status == 429:
            raise errorf(Code.UPSTREAM_RATE_LIMIT, "Snowflake throttled the request (HTTP 429)")
        if resp.status == 408:
            raise errorf(Code.UPSTREAM_TIMEOUT, "the SHOW command exceeded Snowflake's timeout")
        if resp.status == 422:
            try:
                f = jsonx.obj(_decode_first(resp.body))
                code, sql_state = jsonx.s(f, "code"), jsonx.s(f, "sqlState")
                jsonx.s(f, "message")
            except (ValueError, RecursionError):
                raise errorf(Code.UPSTREAM_ERROR, "the statement failed (HTTP 422)") from None
            raise classify_sql(code, sql_state)
        if resp.status != 200:
            raise errorf(Code.UPSTREAM_ERROR, f"Snowflake answered HTTP {resp.status}")
        try:
            rs = _decode_result_set(_decode_first(resp.body))
        except (ValueError, RecursionError) as e:
            raise wrap_error(Code.UPSTREAM_ERROR, e, "the result set was not JSON") from e
        rows = rs.rows()
        for part in range(1, rs.partitions):
            if not _HANDLE_RE.fullmatch(rs.statement_handle):
                raise errorf(Code.UPSTREAM_ERROR, "the result set has partitions but no usable handle")
            if part > httpx.MAX_PAGES:
                raise errorf(Code.UPSTREAM_ERROR, "the result set has more partitions than hallpass reads")
            try:
                _, v = self.api.get_json(ctx, "/api/v2/statements/" + rs.statement_handle, {"partition": str(part)})
                more = _decode_result_set(v)
            except Exception as e:  # noqa: BLE001 - classified and re-raised
                raise _classify(e)
            more.row_type = rs.row_type
            rows.extend(more.rows())
        return rows

    # -- identity --

    def resolve_identity(self, ctx: Context, u: User) -> Identity:
        """Find the user by email: first SHOW USERS LIKE the address
        (SCIM-provisioned users are named by their address), then a scan of
        SHOW USERS matching login_name and email. A match on name or
        login_name, which only the user's owner can set, outranks a match on
        email, which users may set on themselves. The identity's groups are
        the roles granted directly to the user."""
        email = go_lower(go_trim_space(u.email))
        if not is_email(email):
            raise errorf(Code.INVALID_REQUEST, f"user email {go_quote(email)} is not an address")

        def strong(r: Row) -> bool:
            return equal_fold(r.get_col("name"), email) or equal_fold(r.get_col("login_name"), email)

        def match(r: Row) -> bool:
            return strong(r) or equal_fold(r.get_col("email"), email)

        try:
            rows = self.run(ctx, "SHOW USERS LIKE " + like_literal(email))
        except Exception as e:  # noqa: BLE001 - classified and re-raised
            raise self._identity_err(e, "list users")
        found = [r for r in rows if match(r)]
        if not found:
            # Users named otherwise: scan by email and login name, page by page.
            after = ""
            for _ in range(MAX_USER_PAGES):
                stmt = f"SHOW USERS LIMIT {USER_PAGE}"
                if after != "":
                    stmt += " FROM " + string_literal(after)
                try:
                    rows = self.run(ctx, stmt)
                except Exception as e:  # noqa: BLE001 - classified and re-raised
                    raise self._identity_err(e, "list users")
                found.extend(r for r in rows if match(r))
                if len(rows) < USER_PAGE:
                    break
                after = rows[-1].get_col("name")
                if after == "":
                    break
        # Owner-set identifiers outrank the self-service email column.
        strong_matches = [r for r in found if strong(r)]
        if strong_matches:
            found = strong_matches
        if len(found) == 0:
            raise user_not_found(f"no Snowflake user is named {email} or has it as login name or email")
        if len(found) > 1:
            raise user_ambiguous(f"{len(found)} Snowflake users have {email} as name, login name or email")
        usr = found[0]
        name = usr.get_col("name")
        if name == "":
            raise errorf(Code.UPSTREAM_ERROR, "SHOW USERS returned a user without a name")
        attrs = {
            "login_name": usr.get_col("login_name"),
            "disabled": go_lower(_or_empty(usr.get_col("disabled"), "unknown")),
            "default_role": usr.get_col("default_role"),
            "default_secondary_roles": usr.get_col("default_secondary_roles"),
            "type": usr.get_col("type"),
        }
        roles = self.user_roles(ctx, name)
        return Identity(id=name, display=email, attrs=attrs, groups=tuple(roles))

    def _identity_err(self, err: BaseException, what: str) -> BaseException:
        """A failure of the user listing."""
        if is_error(err, NotVisible):
            return errorf(Code.CREDENTIAL_REJECTED, f"hallpass's role may not {what}; it needs MANAGE GRANTS")
        return err

    def user_roles(self, ctx: Context, name: str) -> list[str]:
        """The roles granted directly to the user. SHOW GRANTS TO USER
        historically has a role column; since the 2025_01 change bundle it
        is shaped like SHOW GRANTS TO ROLE (privilege USAGE, granted_on
        ROLE, name). UNVERIFIED: the exact columns of the new shape; both
        are read."""
        try:
            rows = self.run(ctx, "SHOW GRANTS TO USER " + quote(name))
        except Exception as e:
            if is_error(e, NotVisible):
                raise errorf(Code.CREDENTIAL_REJECTED, f"hallpass's role may not read the grants of user {quote(name)}; it needs MANAGE GRANTS") from None
            raise
        seen: set[str] = set()
        roles: list[str] = []
        for r in rows:
            role = r.get_col("role")
            if role == "" and equal_fold(r.get_col("granted_on"), "ROLE"):
                role = r.get_col("name")
            if role == "":
                continue
            # The output spells names unquoted (upper case) or quoted.
            try:
                resolved = parse_identifier(role)
            except ValueError:
                raise errorf(Code.UPSTREAM_ERROR, "SHOW GRANTS TO USER returned a role name of an unexpected shape") from None
            if resolved in seen:
                continue
            seen.add(resolved)
            roles.append(resolved)
        roles.sort(key=lambda s: s.encode("utf-8", "surrogatepass"))
        return roles

    # -- grants --

    def role_grants(self, ctx: Context, role: Sequence[str]) -> list[Grant]:
        """SHOW GRANTS TO ROLE (or DATABASE ROLE) for a role given as
        resolved name parts, cached."""
        key = quote_name(role)
        stmt = "SHOW GRANTS TO ROLE " + key
        if len(role) == 2:
            # UNVERIFIED: the name column spells database roles as
            # <database>.<role>, each part unquoted or quoted.
            stmt = "SHOW GRANTS TO DATABASE ROLE " + key

        def fill(ctx: Context) -> tuple[list[Grant], float]:
            try:
                rows = self.run(ctx, stmt)
            except Exception as e:
                if is_error(e, NotVisible):
                    raise errorf(
                        Code.RESOURCE_NOT_VISIBLE, f"role {key} is granted but hallpass's role may not read its grants; it needs MANAGE GRANTS"
                    ) from None
                raise
            out = []
            for r in rows:
                # Names the output spells in a shape hallpass cannot parse
                # are kept unnamed: they match nothing, which fails closed.
                name: tuple[str, ...] = ()
                try:
                    name = tuple(parse_identifier(p) for p in split_name(r.get_col("name")))
                except ValueError:
                    name = ()
                out.append(Grant(go_upper(r.get_col("privilege")), go_upper(r.get_col("granted_on")), name, r.get_col("granted_by")))
            return out, GRANTS_TTL

        return self.grants.do(ctx, key, fill)

    def walk(self, ctx: Context, roles: Sequence[str]) -> tuple[list[Holding], dict[str, tuple[str, ...]]]:
        """The grants reachable from the user's roles through the role
        hierarchy, and the chain of quoted role names each role is reached
        by (keyed by the role's quoted name)."""
        queue: deque[tuple[tuple[str, ...], tuple[str, ...]]] = deque(((r,), (quote(r),)) for r in roles)
        # Every user holds PUBLIC, which SHOW GRANTS TO USER does not list.
        queue.append((("PUBLIC",), (quote("PUBLIC"),)))
        visited: set[str] = set()
        reach: dict[str, tuple[str, ...]] = {}
        holdings: list[Holding] = []
        while queue:
            role, chain = queue.popleft()
            key = quote_name(role)
            if key in visited:
                continue
            if len(visited) >= MAX_ROLES:
                raise errorf(Code.UNSUPPORTED, f"the role hierarchy has more than {MAX_ROLES} roles; hallpass stops walking it")
            visited.add(key)
            reach[key] = chain
            for g in self.role_grants(ctx, role):
                if g.granted_on == "ROLE" and g.privilege == "USAGE" and len(g.name) == 1:
                    queue.append((g.name, (*chain, quote(g.name[0]))))
                elif g.granted_on == "DATABASE_ROLE" and g.privilege == "USAGE" and len(g.name) == 2:
                    queue.append((g.name, (*chain, quote_name(g.name))))
                else:
                    holdings.append(Holding(g, key, chain))
        return holdings, reach

    # -- checks --

    def check(self, ctx: Context, r: CheckRequest) -> Decision:
        """Answer one question."""
        t: Target = parse_target(r.action_name, r.resource)
        ident = r.identity
        who = ident.display
        disabled = ident.attr("disabled")
        if disabled == "true":
            return denied(f"user {quote(ident.id)} ({who}) is disabled")
        if disabled != "false":
            return unsupported(f"SHOW USERS did not report whether {quote(ident.id)} is disabled")
        try:
            holdings, reach = self.walk(ctx, ident.groups)
        except Exception as e:  # noqa: BLE001 - classified and re-raised
            return to_decision(e)
        if t.action.name == "role.use":
            chain = reach.get(quote_name(t.name))
            if chain is not None:
                return allowed(f"role {quote(t.name[0])} is granted to {who} {via(chain)}")
            return denied(f"role {quote(t.name[0])} is not granted to {who}, directly or through the {len(reach)} role(s) they hold")
        kind = KINDS[t.kind]
        # The privilege on the object itself.
        found = find(holdings, kind.granted_on, t.name, t.action.privileges)
        if found is None:
            return denied(f"none of the {len(reach)} role(s) {who} holds carries {' or '.join(t.action.privileges)} on {t} (or the object does not exist)")
        # USAGE on the parents: the database, and the schema for objects in
        # one. UNVERIFIED: standard Snowflake behaviour, not quoted from the
        # docs.
        if kind.parts >= 2 and find(holdings, ("DATABASE",), t.name[:1], ("USAGE",)) is None:
            return denied(f"{who} holds {found.privilege} on {t} but no role holds USAGE on database {quote(t.name[0])}")
        if kind.parts >= 3 and find(holdings, ("SCHEMA",), t.name[:2], ("USAGE",)) is None:
            return denied(f"{who} holds {found.privilege} on {t} but no role holds USAGE on schema {quote_name(t.name[:2])}")
        return allowed(f"role {found.role} holds {found.privilege} on {t}; {who} has it {via(found.chain)}")

    # -- probe --

    def probe(self, ctx: Context) -> ProbeResult:
        """List hallpass's own grants and warn when MANAGE GRANTS is absent."""
        roles = self.user_roles(ctx, self.user)
        summary = f"authenticated as {quote(self.user)} with roles {', '.join(roles)}"
        if not roles:
            summary = f"authenticated as {quote(self.user)} with no role but PUBLIC"
        holdings, _ = self.walk(ctx, roles)
        warnings = []
        if find(holdings, ("ACCOUNT",), (), ("MANAGE GRANTS",)) is None:
            warnings.append(
                "none of hallpass's roles holds MANAGE GRANTS: SHOW GRANTS on other users and roles answers only for objects hallpass's role can see"
            )
        warnings.append("the answer is the union of every role granted to the user; a session activates one primary role plus secondary roles")
        return ProbeResult(summary=summary, warnings=tuple(warnings))
