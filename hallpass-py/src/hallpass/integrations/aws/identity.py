"""How an email becomes IAM principals: IAM Identity Center (the
AWSReservedSSO roles of the user's permission sets), an IAM user, or a
static email/group -> role map file."""

from __future__ import annotations

import re
import threading
import xml.etree.ElementTree as ET
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from hallpass.authx import xmlutil
from hallpass.authx.awsquery import AWSClient, AWSError, classify_aws_error
from hallpass.authx.sts import validate_role_arn
from hallpass.core import jsonx
from hallpass.core.cache import TTL, is_panic_type
from hallpass.core.context import Context
from hallpass.core.decision import Code, HallpassError, errorf, user_not_found, wrap_error
from hallpass.core.errors import as_error, go_lower, go_quote, go_trim_space, path_error_text
from hallpass.core.integration import Identity, User

__all__ = [
    "MAX_PAGES",
    "ROLE_LIST_TTL",
    "ROLE_MAP_REREAD",
    "SSO_PATH_PREFIX",
    "IdentityResolver",
    "Native",
    "Principal",
    "RoleMap",
    "SSORole",
    "aws_code",
    "classified",
    "classify",
    "match_sso_role",
    "xml_bools",
    "xml_texts",
]

SSO_PATH_PREFIX = "/aws-reserved/sso.amazonaws.com/"
ROLE_LIST_TTL = 600.0  # 10 minutes
ROLE_MAP_REREAD = 60.0
MAX_PAGES = 50

_IAM_USER_NAME_RE = re.compile(r"[\w+=,.@-]{1,64}", re.ASCII)

IAM_VERSION = "2010-05-08"


@dataclass(frozen=True)
class Principal:
    """One IAM principal the user may act as. kind and name are for
    decision texts: "permission set AdminAccess", "role Deployer", "user dana"."""

    arn: str
    kind: str
    name: str

    def __str__(self) -> str:
        return self.kind + " " + self.name


@dataclass
class Native:
    """Identity.native: the candidate principals and, for Identity Center,
    the permission set names and the ones with no provisioned role."""

    principals: list[Principal] = field(default_factory=list)
    permission_sets: list[str] = field(default_factory=list)
    # Assigned permission sets whose AWSReservedSSO role was not found in
    # the account (not yet provisioned, or recreated).
    missing: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class SSORole:
    """One AWSReservedSSO_* role in the account."""

    name: str = ""
    arn: str = ""
    path: str = ""


# -- XML the way encoding/xml decodes it into struct fields -------------------


def _frontier(e: ET.Element | None, *path: str) -> list[ET.Element]:
    """Every element at path under e, in document order (Go merges repeated
    elements of a non-slice field and appends those of a slice field)."""
    frontier = [e] if e is not None else []
    for p in path:
        frontier = [c for x in frontier for c in xmlutil.children(x, p)]
    return frontier


def _own_text(e: ET.Element) -> str:
    """The element's own character data, as Go saves it for a string."""
    return (e.text or "") + "".join(c.tail or "" for c in e)


def xml_texts(e: ET.Element | None, *path: str) -> list[str]:
    """A []string field: one entry per element at path."""
    return [_own_text(x) for x in _frontier(e, *path)]


def _parse_bool(src: str) -> bool:
    """encoding/xml's copyValue for a bool: empty is false, otherwise
    strconv.ParseBool of the trimmed text."""
    if len(src) == 0:
        return False
    s = go_trim_space(src)
    if s in ("1", "t", "T", "TRUE", "true", "True"):
        return True
    if s in ("0", "f", "F", "FALSE", "false", "False"):
        return False
    raise ValueError(f'strconv.ParseBool: parsing {go_quote(s)}: invalid syntax')


def xml_bools(e: ET.Element | None, *path: str) -> bool | None:
    """A *bool field: None when no element is at path, else the last one's
    value. Every occurrence is decoded, so a malformed one is an error even
    when a later one would win."""
    out: bool | None = None
    for x in _frontier(e, *path):
        out = _parse_bool(_own_text(x))
    return out


# -- errors -----------------------------------------------------------------------


def aws_code(err: BaseException) -> str:
    """The AWS error code carried by err, or ""."""
    ae = as_error(err, AWSError)
    return ae.code if ae is not None else ""


def classify(err: BaseException, op: str) -> HallpassError:
    """A failed AWS call as a HallpassError, naming the call."""
    ie = classify_aws_error(err)
    return HallpassError(ie.code, op + ": " + ie.text, ie.cause)


def classified(e: Exception, op: str) -> HallpassError:
    """classify for an exception caught around a call; a crash (the
    Python form of a Go panic) propagates as itself."""
    if is_panic_type(e):
        raise e
    return classify(e, op)


def match_sso_role(roles: Iterable[SSORole], permission_set: str) -> tuple[str, bool]:
    """The role provisioned for a permission set. The match is anchored:
    AWSReservedSSO_<name>_<16 hex>, nothing else."""
    rx = re.compile("AWSReservedSSO_" + re.escape(permission_set) + "_[0-9a-f]{16}")
    for r in roles:
        if rx.fullmatch(r.name) and r.arn != "":
            return r.arn, True
    return "", False


# -- static map ---------------------------------------------------------------------

_GO_SPACE = "\t\n\v\f\r \x85\xa0                　"
_FIELDS_RE = re.compile("[" + re.escape(_GO_SPACE) + "]+")

# bufio.Scanner's largest token as the map reader configures it.
_MAX_LINE = 1 << 20


def _go_fields(s: str) -> list[str]:
    """strings.Fields: split around runs of unicode.IsSpace."""
    return [f for f in _FIELDS_RE.split(s) if f]


def _append_unique(xs: list[str], x: str) -> list[str]:
    if x not in xs:
        xs.append(x)
    return xs


class RoleMap:
    """The static_map file: "<email-or-group> <role-arn>" per line, "#"
    comments, matched case-insensitively. It is re-read at most every 60
    seconds; a re-read failure keeps the last good map."""

    def __init__(self, path: str, now: Callable[[], float], logf: Callable[..., None]) -> None:
        self.path = path
        self.now = now
        self.logf = logf
        self._lock = threading.Lock()
        self.items: dict[str, list[str]] | None = self._read()
        self.loaded = now()

    def _read(self) -> dict[str, list[str]]:
        try:
            with open(self.path, "rb") as f:
                data = f.read()
        except OSError as e:
            raise ValueError(f"role_map_file: {path_error_text('open', self.path, e)}") from e
        items: dict[str, list[str]] = {}
        lines = data.split(b"\n")
        if lines and lines[-1] == b"":
            lines.pop()
        for n, raw in enumerate(lines, start=1):
            if len(raw) >= _MAX_LINE:
                raise ValueError(f"role_map_file {self.path}: bufio.Scanner: token too long")
            if raw.endswith(b"\r"):
                raw = raw[:-1]
            line = go_trim_space(raw.decode("utf-8", "surrogateescape"))
            if line == "" or line.startswith("#"):
                continue
            fields = _go_fields(line)
            if len(fields) != 2:
                raise ValueError(f'role_map_file {self.path} line {n}: want "<email-or-group> <role-arn>"')
            try:
                validate_role_arn(fields[1])
            except ValueError as e:
                raise ValueError(f"role_map_file {self.path} line {n}: {e}") from None
            key = go_lower(fields[0])
            items[key] = _append_unique(items.get(key, []), fields[1])
        return items

    def lookup(self, email: str, groups: Iterable[str]) -> list[str]:
        """The union of the role ARNs mapped to the email and to any of the
        groups, in file order of first appearance."""
        with self._lock:
            if self.now() - self.loaded >= ROLE_MAP_REREAD:
                try:
                    items = self._read()
                except ValueError as e:
                    if self.items is None:
                        raise wrap_error(Code.UPSTREAM_ERROR, e, "role_map_file could not be read") from e
                    self.logf("role_map_file re-read failed; keeping the previous map", "path", self.path, "error", str(e))
                else:
                    self.items = items
                self.loaded = self.now()
            m = self.items or {}
            out = list(m.get(go_lower(email), []))
            for g in groups:
                for arn in m.get(go_lower(g), []):
                    _append_unique(out, arn)
            return out


# -- resolution ------------------------------------------------------------------------


class IdentityResolver:
    """resolve_identity and what it is built from; mixed into the
    connection, which sets these attributes."""

    mode: str
    account_id: str
    identity_store_id: str
    sso_instance_arn: str
    role_map: RoleMap | None
    iam: AWSClient
    identity_store: AWSClient | None
    sso_admin: AWSClient | None
    roles: TTL[str, list[SSORole]]
    ps_names: TTL[str, str]

    def resolve_identity(self, ctx: Context, u: User) -> Identity:
        """Map the email to IAM principals by the configured mode. The
        result is cached by the engine (identity_cache_seconds, keyed by
        email and groups), not here."""
        email = go_trim_space(u.email)
        if email == "" or "@" not in email:
            raise user_not_found(f"{go_quote(u.email)} is not an email address")
        if self.mode == "static_map":
            # The map is re-read every 60 s, so the roles are looked up
            # again in check from the request's groups rather than carried
            # in the identity.
            assert self.role_map is not None
            arns = self.role_map.lookup(email, u.groups)
            if not arns:
                raise user_not_found(f"{email} and its groups are not in role_map_file")
            return Identity(id=go_lower(email), display=email)
        if self.mode == "iam_user":
            return self._resolve_iam_user(ctx, email)
        return self._resolve_identity_center(ctx, email)

    # Identity Center

    def _json11(self, client: AWSClient | None, ctx: Context, target: str, body: Any) -> dict[str, Any]:
        assert client is not None
        return jsonx.obj(client.json11(ctx, target, body))

    def _resolve_identity_center(self, ctx: Context, email: str) -> Identity:
        user_id = self._get_user_id(ctx, email)
        try:
            out = self._json11(self.identity_store, ctx, "AWSIdentityStore.DescribeUser", {"IdentityStoreId": self.identity_store_id, "UserId": user_id})
            # UNVERIFIED: DescribeUser is not documented to return a status
            # field; when a UserStatus of "DISABLED" is present the user is
            # denied everything.
            jsonx.s(out, "UserId")
            jsonx.s(out, "DisplayName")
            user_name, user_status = jsonx.s(out, "UserName"), jsonx.s(out, "UserStatus")
        except Exception as e:
            raise classified(e, "DescribeUser") from e
        groups = self._list_groups(ctx, user_id)
        # Assignments for the user and for each group are unioned.
        # UNVERIFIED: whether ListAccountAssignmentsForPrincipal for a USER
        # already includes assignments inherited through groups.
        ps_arns: list[str] = []
        seen: set[str] = set()

        def add(arns: list[str]) -> None:
            for a in arns:
                if a not in seen:
                    seen.add(a)
                    ps_arns.append(a)

        add(self._list_assignments(ctx, user_id, "USER"))
        for g in groups:
            add(self._list_assignments(ctx, g, "GROUP"))
        ps_arns.sort()
        nat = Native()
        principals: list[Principal] = []
        if ps_arns:
            roles = self._sso_roles(ctx)
            for arn in ps_arns:
                name = self._permission_set_name(ctx, arn)
                nat.permission_sets.append(name)
                role_arn, ok = match_sso_role(roles, name)
                if not ok:
                    nat.missing.append(name)
                    continue
                principals.append(Principal(arn=role_arn, kind="permission set", name=name))
        nat.principals = principals
        display = user_name or email
        attrs = {"user_name": user_name}
        if user_status != "":
            attrs["user_status"] = user_status
        return Identity(id=user_id, display=display, attrs=attrs, groups=tuple(groups), native=nat)

    def _get_user_id(self, ctx: Context, email: str) -> str:
        """Look the email up as emails.value, then as userName."""
        for path in ("emails.value", "userName"):
            body = {
                "IdentityStoreId": self.identity_store_id,
                "AlternateIdentifier": {"UniqueAttribute": {"AttributePath": path, "AttributeValue": email}},
            }
            try:
                user_id = jsonx.s(self._json11(self.identity_store, ctx, "AWSIdentityStore.GetUserId", body), "UserId")
            except Exception as e:
                if aws_code(e) == "ResourceNotFoundException":
                    continue
                raise classified(e, "GetUserId") from e
            if user_id == "":
                raise errorf(Code.UPSTREAM_ERROR, "GetUserId returned no UserId")
            return user_id
        raise user_not_found(f"no Identity Center user has email or username {email}")

    def _list_groups(self, ctx: Context, user_id: str) -> list[str]:
        groups: list[str] = []
        token = ""
        page = 0
        while True:
            if page >= MAX_PAGES:
                raise errorf(Code.UPSTREAM_ERROR, "ListGroupMembershipsForMember: too many pages")
            body: dict[str, Any] = {"IdentityStoreId": self.identity_store_id, "MemberId": {"UserId": user_id}}
            if token != "":
                body["NextToken"] = token
            try:
                out = self._json11(self.identity_store, ctx, "AWSIdentityStore.ListGroupMembershipsForMember", body)
                ids = [jsonx.s(jsonx.obj(m), "GroupId") for m in jsonx.arr(out, "GroupMemberships")]
                next_token = jsonx.s(out, "NextToken")
            except Exception as e:
                raise classified(e, "ListGroupMembershipsForMember") from e
            groups.extend(g for g in ids if g != "")
            if next_token == "":
                break
            token = next_token
            page += 1
        groups.sort()
        return groups

    def _list_assignments(self, ctx: Context, principal_id: str, principal_type: str) -> list[str]:
        arns: list[str] = []
        token = ""
        page = 0
        while True:
            if page >= MAX_PAGES:
                raise errorf(Code.UPSTREAM_ERROR, "ListAccountAssignmentsForPrincipal: too many pages")
            body: dict[str, Any] = {
                "InstanceArn": self.sso_instance_arn,
                "PrincipalId": principal_id,
                "PrincipalType": principal_type,
                "Filter": {"AccountId": self.account_id},
            }
            if token != "":
                body["NextToken"] = token
            try:
                out = self._json11(self.sso_admin, ctx, "SWBExternalService.ListAccountAssignmentsForPrincipal", body)
                rows = [jsonx.obj(a) for a in jsonx.arr(out, "AccountAssignments")]
                rows_decoded = [(jsonx.s(a, "AccountId"), jsonx.s(a, "PermissionSetArn")) for a in rows]
                next_token = jsonx.s(out, "NextToken")
            except Exception as e:
                raise classified(e, "ListAccountAssignmentsForPrincipal") from e
            for account, ps in rows_decoded:
                # The filter should already restrict to the account; check
                # anyway. A row must name this account exactly: rows for
                # other accounts or with no AccountId are not assignments here.
                if ps != "" and account == self.account_id:
                    arns.append(ps)
            if next_token == "":
                break
            token = next_token
            page += 1
        return arns

    def _permission_set_name(self, ctx: Context, arn: str) -> str:
        def fill(ctx: Context) -> tuple[str, float]:
            body = {"InstanceArn": self.sso_instance_arn, "PermissionSetArn": arn}
            try:
                out = self._json11(self.sso_admin, ctx, "SWBExternalService.DescribePermissionSet", body)
                name = jsonx.s(jsonx.o(out, "PermissionSet"), "Name")
            except Exception as e:
                raise classified(e, "DescribePermissionSet") from e
            if name == "":
                raise errorf(Code.UPSTREAM_ERROR, "DescribePermissionSet returned no name")
            return name, ROLE_LIST_TTL

        return self.ps_names.do(ctx, arn, fill)

    def _sso_roles(self, ctx: Context) -> list[SSORole]:
        """The account's Identity Center roles, cached for 10 minutes."""
        return self.roles.do(ctx, "sso", lambda ctx: (self._list_sso_roles(ctx), ROLE_LIST_TTL))

    def _list_sso_roles(self, ctx: Context) -> list[SSORole]:
        """iam:ListRoles under the SSO path prefix, every page.
        UNVERIFIED: roles may sit under /aws-reserved/sso.amazonaws.com/<region>/
        as well; PathPrefix matching is a prefix match so both are returned."""
        roles: list[SSORole] = []
        marker = ""
        page = 0
        while True:
            if page >= MAX_PAGES:
                raise errorf(Code.UPSTREAM_ERROR, "ListRoles: too many pages")
            params: dict[str, Any] = {"PathPrefix": SSO_PATH_PREFIX, "MaxItems": 1000}
            if marker != "":
                params["Marker"] = marker
            try:
                root = self.iam.query(ctx, "ListRoles", IAM_VERSION, params)
                page_roles = [
                    SSORole(name=xmlutil.text(m, "RoleName"), arn=xmlutil.text(m, "Arn"), path=xmlutil.text(m, "Path"))
                    for m in _frontier(root, "ListRolesResult", "Roles", "member")
                ]
                truncated = bool(xml_bools(root, "ListRolesResult", "IsTruncated"))
                next_marker = xmlutil.text(root, "ListRolesResult", "Marker")
            except Exception as e:
                raise classified(e, "ListRoles") from e
            roles.extend(page_roles)
            if not truncated or next_marker == "":
                break
            marker = next_marker
            page += 1
        return roles

    # IAM user

    def _resolve_iam_user(self, ctx: Context, email: str) -> Identity:
        local = email.partition("@")[0]
        candidates = [n for n in (local, email) if _IAM_USER_NAME_RE.fullmatch(n)]
        for name in candidates:
            try:
                root = self.iam.query(ctx, "GetUser", IAM_VERSION, {"UserName": name})
            except Exception as e:
                if aws_code(e) == "NoSuchEntity":
                    continue
                raise classified(e, "GetUser") from e
            arn = xmlutil.text(root, "GetUserResult", "User", "Arn")
            user_name = xmlutil.text(root, "GetUserResult", "User", "UserName")
            user_id = xmlutil.text(root, "GetUserResult", "User", "UserId")
            if arn == "":
                raise errorf(Code.UPSTREAM_ERROR, "GetUser returned no ARN")
            nat = Native(principals=[Principal(arn=arn, kind="user", name=user_name)])
            return Identity(id=user_id or user_name, display=user_name, attrs={"arn": arn}, native=nat)
        raise user_not_found(f"no IAM user named {local} or {email} in account {self.account_id}")
