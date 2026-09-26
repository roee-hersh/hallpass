"""Checks permissions with iam:SimulatePrincipalPolicy.

One connection is one AWS account. hallpass assumes a read-only role in
that account, maps the caller's email to the IAM principals the user can
act as (the AWSReservedSSO roles of their Identity Center permission sets,
a static email/group -> role map, or an IAM user) and asks IAM to simulate
the requested action on the requested ARN for each principal. IAM
evaluates identity policies, permissions boundaries and SCPs; nothing is
written.
"""

from __future__ import annotations

import os
import re
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from hallpass.authx import xmlutil
from hallpass.authx.awscreds import OS_ENV, ambient_provider, static_from_json
from hallpass.authx.awsquery import AWSClient, CredentialProvider, iam_endpoint, regional_endpoint
from hallpass.authx.sigv4 import AWSCredentials
from hallpass.authx.sts import CachedProvider, STSClient, assume_role_provider, validate_role_arn
from hallpass.core import jsonx
from hallpass.core.cache import TTL
from hallpass.core.catalog import Action
from hallpass.core.context import Context
from hallpass.core.decision import Code, Decision, allowed, denied, errorf, unknown_decision, unsupported, user_not_found
from hallpass.core.errors import go_lower, go_quote, go_trim_space, path_error_text
from hallpass.core.integration import CheckRequest, Connection, Deps, Field, Integration, ProbeResult, Settings, credential_field
from hallpass.core.log import Logger
from hallpass.core.secret import Secret
from hallpass.integrations.aws.actions import arn_field, catalog_actions, match_action, parse_resource, resolve_action
from hallpass.integrations.aws.identity import (
    IAM_VERSION,
    MAX_PAGES,
    ROLE_LIST_TTL,
    IdentityResolver,
    Native,
    Principal,
    RoleMap,
    SSORole,
    aws_code,
    classified,
    xml_bools,
    xml_elements,
    xml_texts,
)
from hallpass.net import httpx

__all__ = ["AWS", "TEST_ENDPOINTS", "AWSConnection", "ContextEntry", "SimResult", "decision_rank", "more_restrictive", "parse_context_entries"]

STS_VERSION = "2011-06-15"

_ACCOUNT_ID_RE = re.compile(r"[0-9]{12}")
_REGION_RE = re.compile(r"[a-z]{2}(-gov)?-[a-z]+-[0-9]")
_IDENTITY_STORE_ID_RE = re.compile(r"d-[0-9a-f]{10}")
_SSO_INSTANCE_ARN_RE = re.compile(r"arn:aws[a-z-]*:sso:::instance/(sso)?ins-[0-9a-f]{16}")
_SESSION_NAME_RE = re.compile(r"[\w+=,.@-]{2,64}", re.ASCII)
_CONTEXT_KEY_RE = re.compile(r"[A-Za-z0-9:_/.@-]{1,256}")

# When not None, replaces the AWS endpoints. Keys: sts, iam, identitystore,
# sso, imds. Tests set it so one fake server serves them all. Read at new().
TEST_ENDPOINTS: dict[str, str] | None = None


def _endpoint(name: str, default: str) -> str:
    if TEST_ENDPOINTS is not None and name in TEST_ENDPOINTS:
        return TEST_ENDPOINTS[name]
    return default


def _match_re(rx: re.Pattern[str], want: str) -> Callable[[str], None]:
    def validate(v: str) -> None:
        if not rx.fullmatch(v):
            raise ValueError(f"{go_quote(v)} must be {want}")

    return validate


def _validate_context_entries(v: str) -> None:
    parse_context_entries(v)


@dataclass(frozen=True)
class ContextEntry:
    """One condition key for the simulation."""

    key: str
    type: str
    values: tuple[str, ...]


_CONTEXT_TYPES = {
    "string": "string",
    "stringlist": "stringList",
    "numeric": "numeric",
    "boolean": "boolean",
    "ip": "ip",
    "binary": "binary",
    "date": "date",
}


def parse_context_entries(v: str) -> list[ContextEntry]:
    """key=type:value;key=type:value. stringList values are comma separated."""
    v = go_trim_space(v)
    if v == "":
        return []
    out: list[ContextEntry] = []
    seen: set[str] = set()
    for part in v.split(";"):
        part = go_trim_space(part)
        if part == "":
            continue
        key, sep, rest = part.partition("=")
        if not sep:
            raise ValueError(f"context entry {go_quote(part)} must be key=type:value")
        key = go_trim_space(key)
        if not _CONTEXT_KEY_RE.fullmatch(key):
            raise ValueError(f"context key {go_quote(key)} is not a valid condition key")
        if key in seen:
            raise ValueError(f"context key {go_quote(key)} given twice")
        seen.add(key)
        typ, sep, val = rest.partition(":")
        if not sep:
            raise ValueError(
                f"context entry {go_quote(part)} must be key=type:value with type one of string, stringList, numeric, boolean, ip, binary, date"
            )
        canon = _CONTEXT_TYPES.get(go_lower(go_trim_space(typ)))
        if canon is None:
            raise ValueError(f"context type {go_quote(typ)} must be one of string, stringList, numeric, boolean, ip, binary, date")
        if canon == "stringList":
            values = tuple(go_trim_space(s) for s in val.split(","))
        else:
            values = (go_trim_space(val),)
        out.append(ContextEntry(key=key, type=canon, values=values))
    return out


class AWS(Integration):
    """The aws product."""

    def name(self) -> str:
        return "aws"

    def fields(self) -> list[Field]:
        return [
            Field(
                name="account_id",
                required=True,
                validate=_match_re(_ACCOUNT_ID_RE, "a 12-digit account id"),
                description="the AWS account this connection answers for",
            ),
            Field(
                name="role_arn",
                required=True,
                validate=validate_role_arn,
                description="hallpass's read-only role in that account (iam:SimulatePrincipalPolicy, iam:ListRoles)",
            ),
            Field(name="external_id", description="ExternalId sent with every AssumeRole"),
            Field(name="partition", default="aws", enum=("aws", "aws-us-gov", "aws-cn"), description="AWS partition"),
            Field(
                name="region",
                required=True,
                validate=_match_re(_REGION_RE, "a region such as eu-west-1"),
                description="region for the STS endpoint, e.g. eu-west-1",
            ),
            credential_field(True, "JSON {access_key_id, secret_access_key, session_token?} or the value ambient:auto|container|web_identity|imds"),
            Field(
                name="identity_mode",
                default="identity_center",
                enum=("identity_center", "static_map", "iam_user"),
                description="how an email becomes IAM principals",
            ),
            Field(
                name="identity_center_role_arn",
                validate=validate_role_arn,
                description="identity_center: hallpass's read role in the Identity Center management or delegated account",
            ),
            Field(
                name="identity_center_region",
                validate=_match_re(_REGION_RE, "a region such as eu-west-1"),
                description="identity_center: the region Identity Center is enabled in",
            ),
            Field(
                name="identity_store_id",
                validate=_match_re(_IDENTITY_STORE_ID_RE, "d-<10 hex digits>"),
                description="identity_center: the identity store id",
            ),
            Field(
                name="sso_instance_arn",
                validate=_match_re(_SSO_INSTANCE_ARN_RE, "arn:aws:sso:::instance/ssoins-<16 hex digits>"),
                description="identity_center: the Identity Center instance ARN",
            ),
            Field(name="role_map_file", description='static_map: file of "<email-or-group> <role-arn>" lines, # comments; re-read every 60 s'),
            Field(
                name="context_entries",
                validate=_validate_context_entries,
                description="condition context for the simulation: key=type:value;..., e.g. aws:MultiFactorAuthPresent=boolean:true;aws:SourceIp=ip:10.0.0.1",
            ),
            Field(
                name="implicit_deny_as",
                default="deny",
                enum=("deny", "unknown"),
                description="what an implicitDeny (no matching statement) answers",
            ),
            Field(
                name="session_name",
                default="hallpass",
                validate=_match_re(_SESSION_NAME_RE, "2-64 characters of [A-Za-z0-9+=,.@_-]"),
                description="RoleSessionName for AssumeRole",
            ),
        ]

    def actions(self) -> list[Action]:
        return catalog_actions()

    def match_action(self, name: str) -> Action | None:
        return match_action(name)

    def new(self, ctx: Context, s: Settings, d: Deps) -> Connection:
        """Build a connection. It reads role_map_file (static_map) but never
        the network."""
        hc = d.http_client(s)
        cred = s.secret("credential")
        if cred.is_zero():
            raise ValueError("credential is required")
        now = d.now
        logger = d.logger if d.logger is not None else Logger()
        c = AWSConnection(
            logger=logger,
            account_id=s.get("account_id"),
            partition=s.get("partition") or "aws",
            region=s.get("region"),
            mode=s.get("identity_mode") or "identity_center",
            implicit_deny_as=s.get("implicit_deny_as") or "deny",
            session_name=s.get("session_name") or "hallpass",
        )
        if not _ACCOUNT_ID_RE.fullmatch(c.account_id):
            raise ValueError("account_id must be 12 digits")
        if not _REGION_RE.fullmatch(c.region):
            raise ValueError("region is required")
        role_arn = s.get("role_arn")
        try:
            validate_role_arn(role_arn)
        except ValueError as e:
            raise ValueError(f"role_arn: {e}") from e
        a = arn_field(role_arn, 4)
        if a != c.account_id:
            raise ValueError(f"role_arn is in account {a} but account_id is {c.account_id}; IAM simulation only works inside the account")
        p = arn_field(role_arn, 1)
        if p != c.partition:
            raise ValueError(f"role_arn is in partition {p} but partition is {c.partition}")
        c.context_entries = parse_context_entries(s.get("context_entries"))
        external_id = s.get("external_id")

        c.plain = httpx.Client(http=hc, logger=logger)
        sts_endpoint = _endpoint("sts", regional_endpoint(c.partition, "sts", c.region))
        base = BaseProvider(
            secret=cred,
            plain=c.plain,
            sts=STSClient(c.plain, sts_endpoint, c.region),
            imds_base=_endpoint("imds", ""),
        )
        sts_client = STSClient(c.plain, sts_endpoint, c.region, creds=base)
        c.account_creds = assume_role_provider(sts_client, role_arn, c.session_name, external_id)
        c.account_creds.now = now
        iam_ep, iam_region = iam_endpoint(c.partition)
        c.iam = AWSClient(c.plain, _endpoint("iam", iam_ep), iam_region, "iam", c.account_creds)
        c.sts = AWSClient(c.plain, sts_endpoint, c.region, "sts", c.account_creds)

        if c.mode == "identity_center":
            ic_role = s.get("identity_center_role_arn")
            ic_region = s.get("identity_center_region")
            c.identity_store_id = s.get("identity_store_id")
            c.sso_instance_arn = s.get("sso_instance_arn")
            if ic_role == "":
                raise ValueError("identity_center_role_arn is required for identity_mode identity_center")
            if not _REGION_RE.fullmatch(ic_region):
                raise ValueError("identity_center_region is required for identity_mode identity_center")
            if not _IDENTITY_STORE_ID_RE.fullmatch(c.identity_store_id):
                raise ValueError("identity_store_id is required for identity_mode identity_center")
            if not _SSO_INSTANCE_ARN_RE.fullmatch(c.sso_instance_arn):
                raise ValueError("sso_instance_arn is required for identity_mode identity_center")
            try:
                validate_role_arn(ic_role)
            except ValueError as e:
                raise ValueError(f"identity_center_role_arn: {e}") from e
            c.ic_creds = assume_role_provider(sts_client, ic_role, c.session_name, external_id)
            c.ic_creds.now = now
            c.identity_store = AWSClient(
                c.plain,
                _endpoint("identitystore", regional_endpoint(c.partition, "identitystore", ic_region)),
                ic_region,
                "identitystore",
                c.ic_creds,
            )
            c.sso_admin = AWSClient(c.plain, _endpoint("sso", regional_endpoint(c.partition, "sso", ic_region)), ic_region, "sso", c.ic_creds)
        elif c.mode == "static_map":
            path = s.get("role_map_file")
            if path == "":
                raise ValueError("role_map_file is required for identity_mode static_map")
            try:
                os.stat(path)
            except (OSError, ValueError) as e:
                raise ValueError(f"role_map_file: {path_error_text('stat', path, e)}") from e
            c.role_map = RoleMap(path, now, logger.warn)
        elif c.mode == "iam_user":
            pass
        else:
            raise ValueError(f"identity_mode {go_quote(c.mode)} is not one of identity_center, static_map, iam_user")
        c.roles = TTL(1)
        c.roles.set_clock(now)
        c.ps_names = TTL(0)
        c.ps_names.set_clock(now)
        # The account's role inventory and permission set names are not the
        # assignment a fresh check is about: a fresh check reuses them.
        c.roles.set_fresh_max_age(ROLE_LIST_TTL)
        c.ps_names.set_fresh_max_age(ROLE_LIST_TTL)
        return c


class BaseProvider:
    """The credential the connection starts from: either static keys from
    the secret's JSON or an ambient source named by an "ambient:<mode>"
    secret value. The secret is read on every refresh."""

    def __init__(self, secret: Secret, plain: httpx.Client, sts: STSClient, imds_base: str) -> None:
        self.secret = secret
        self.plain = plain
        self.sts = sts
        self.imds_base = imds_base
        self._lock = threading.Lock()
        self._mode = ""
        self._ambient: CredentialProvider | None = None

    def credentials(self, ctx: Context) -> AWSCredentials:
        raw = self.secret.get()
        v = go_trim_space(raw.decode("utf-8", "replace"))
        if v.startswith("ambient:"):
            mode = v[len("ambient:") :]
            with self._lock:
                if self._ambient is None or self._mode != mode:
                    self._ambient = ambient_provider(mode, OS_ENV, self.plain, self.sts, self.imds_base)
                    self._mode = mode
                p = self._ambient
            return p.credentials(ctx)
        try:
            return static_from_json(raw)
        except ValueError:
            # The cause could echo part of the secret; keep it out.
            raise ValueError("credential must be JSON with access_key_id and secret_access_key, or ambient:<mode>") from None


@dataclass
class SimResult:
    """The outcome of one SimulatePrincipalPolicy for one principal."""

    principal: Principal
    decision: str = "implicitDeny"  # allowed, implicitDeny, explicitDeny
    missing: list[str] = field(default_factory=list)
    scp_denied: bool = False
    boundary_denied: bool = False


@dataclass
class _EvalResource:
    name: str
    decision: str
    missing: list[str]


@dataclass
class _EvalResult:
    action_name: str
    decision: str
    resource_name: str
    missing: list[str]
    org_allowed: bool | None
    boundary_allowed: bool | None
    resources: list[_EvalResource]


def _decode_simulate(root: Any) -> tuple[list[_EvalResult], bool, str]:
    """SimulatePrincipalPolicyResult: the evaluation results, IsTruncated
    and Marker, decoded the way encoding/xml fills simulateResponse."""
    res = "SimulatePrincipalPolicyResult"
    results = []
    for m in xml_elements(root, res, "EvaluationResults", "member"):
        resources = [
            _EvalResource(
                name=xmlutil.text(rr, "EvalResourceName"),
                decision=xmlutil.text(rr, "EvalResourceDecision"),
                missing=xml_texts(rr, "MissingContextValues", "member"),
            )
            for rr in xml_elements(m, "ResourceSpecificResults", "member")
        ]
        results.append(
            _EvalResult(
                action_name=xmlutil.text(m, "EvalActionName"),
                decision=xmlutil.text(m, "EvalDecision"),
                resource_name=xmlutil.text(m, "EvalResourceName"),
                missing=xml_texts(m, "MissingContextValues", "member"),
                org_allowed=xml_bools(m, "OrganizationsDecisionDetail", "AllowedByOrganizations"),
                boundary_allowed=xml_bools(m, "PermissionsBoundaryDecisionDetail", "AllowedByPermissionsBoundary"),
                resources=resources,
            )
        )
    truncated = bool(xml_bools(root, res, "IsTruncated"))
    return results, truncated, xmlutil.text(root, res, "Marker")


def decision_rank(d: str) -> int:
    """IAM decisions from least to most restrictive. An unknown string
    ranks above every known one so it is never masked."""
    return {"allowed": 0, "implicitDeny": 1, "explicitDeny": 2}.get(d, 3)


def more_restrictive(a: str, b: str) -> str:
    """Whichever of a and b denies harder: explicitDeny > implicitDeny > allowed."""
    if decision_rank(b) > decision_rank(a):
        return b
    return a


def _role_name(arn: str) -> str:
    res = arn_field(arn, 5)
    i = res.rfind("/")
    if i >= 0:
        return res[i + 1 :]
    return res


class AWSConnection(IdentityResolver, Connection):
    """One AWS account."""

    def __init__(
        self,
        logger: Logger,
        account_id: str,
        partition: str,
        region: str,
        mode: str,
        implicit_deny_as: str,
        session_name: str,
    ) -> None:
        self.logger = logger
        self.account_id = account_id
        self.partition = partition
        self.region = region
        self.mode = mode
        self.implicit_deny_as = implicit_deny_as
        self.session_name = session_name
        self.context_entries: list[ContextEntry] = []
        self.plain: httpx.Client
        self.account_creds: CachedProvider  # the role in the account
        self.ic_creds: CachedProvider | None = None  # the Identity Center role
        self.iam: AWSClient
        self.sts: AWSClient
        self.identity_store: AWSClient | None = None
        self.sso_admin: AWSClient | None = None
        self.identity_store_id = ""
        self.sso_instance_arn = ""
        self.role_map: RoleMap | None = None
        # The engine caches resolved identities (identity_cache_seconds); the
        # connection only caches what identities are built from.
        self.roles: TTL[str, list[SSORole]]
        self.ps_names: TTL[str, str]

    def check(self, ctx: Context, r: CheckRequest) -> Decision:
        """Simulate the action for every candidate principal."""
        try:
            action = resolve_action(r.action_name)
            resource = parse_resource(r.resource, self.partition)
        except ValueError as e:
            raise errorf(Code.INVALID_REQUEST, str(e)) from None
        what = action + " on " + resource
        acct = arn_field(resource, 4)
        if resource != "*" and acct != "" and acct != self.account_id:
            return unsupported(
                f"{resource} is in account {acct}, not {self.account_id}; cross-account access depends on the resource policy, which hallpass cannot see"
            )
        if r.identity.attr("user_status") == "DISABLED":
            return denied(f"{r.identity.display} is disabled in IAM Identity Center")

        principals: list[Principal] = []
        missing: list[str] = []
        if self.mode == "static_map":
            assert self.role_map is not None
            arns = self.role_map.lookup(r.user.email, r.user.groups)
            if not arns:
                raise user_not_found(f"{r.user.email} and its groups are not in role_map_file")
            principals = [Principal(arn=arn, kind="role", name=_role_name(arn)) for arn in arns]
        else:
            nat = r.identity.native if isinstance(r.identity.native, Native) else None
            if nat is None:
                raise errorf(Code.UPSTREAM_ERROR, "identity carries no principals")
            principals, missing = nat.principals, nat.missing
            if self.mode == "identity_center" and not nat.permission_sets:
                # No assignment is an implicit deny: IAM was never asked, so
                # implicit_deny_as decides whether that is deny or unknown.
                text = f"{r.identity.display} has no permission set assigned in account {self.account_id}"
                if self.implicit_deny_as == "unknown":
                    return unsupported(text)
                return denied(text)
        if not principals:
            if missing:
                return unknown_decision(
                    Code.RESOURCE_NOT_VISIBLE,
                    f"permission set {', '.join(missing)} is assigned but its role is not provisioned in account {self.account_id}",
                )
            raise errorf(Code.UPSTREAM_ERROR, "no principal to simulate")

        results: list[SimResult] = []
        for p in principals:
            try:
                res = self._simulate(ctx, p, action, resource)
            except Exception as e:
                code = aws_code(e)
                if code == "NoSuchEntity":
                    # The role list is refreshed on the next resolve, but
                    # the engine keeps the resolved identity (and so this
                    # principal) until identity_cache_seconds expires; there
                    # is no way to evict it from here.
                    self.roles.delete("sso")
                    return unknown_decision(
                        Code.RESOURCE_NOT_VISIBLE,
                        f"{p} ({p.arn}) no longer exists; the role vanished and the identity is re-resolved after identity_cache_seconds expires",
                    )
                if code == "PolicyEvaluation":
                    return unsupported(f"IAM could not evaluate the policies of {p}")
                raise classified(e, "SimulatePrincipalPolicy") from e
            # An "allowed" that IAM evaluated with condition keys missing is
            # not trustworthy: a Deny statement conditioned on such a key was
            # skipped. Only an allow with no missing context settles it.
            if res.decision == "allowed" and not res.missing:
                return allowed(f"{p} allows {what}")
            results.append(res)

        # Nothing allowed outright. Missing context first: the answer depends on it.
        keys: list[str] = []
        seen: set[str] = set()
        for res in results:
            for k in res.missing:
                if k not in seen:
                    seen.add(k)
                    keys.append(k)
        if keys:
            keys.sort()
            return unsupported(f"the answer for {what} depends on condition keys {', '.join(keys)}; set context_entries on the connection")
        if missing:
            return unknown_decision(
                Code.RESOURCE_NOT_VISIBLE,
                f"permission set {', '.join(missing)} is assigned but its role is not provisioned in account {self.account_id}",
            )
        names: list[str] = []
        explicit = True
        notes: list[str] = []
        for res in results:
            names.append(str(res.principal))
            if res.decision != "explicitDeny":
                explicit = False
            if res.scp_denied and "denied by SCP" not in notes:
                notes.append("denied by SCP")
            if res.boundary_denied and "blocked by the permissions boundary" not in notes:
                notes.append("blocked by the permissions boundary")
        suffix = ""
        if notes:
            suffix = " (" + "; ".join(notes) + ")"
        if not explicit and self.implicit_deny_as == "unknown":
            return unsupported(f"no policy of {', '.join(names)} allows {what} (implicit deny){suffix}")
        if explicit:
            return denied(f"{', '.join(names)} explicitly deny {what}{suffix}")
        return denied(f"no policy of {', '.join(names)} allows {what}{suffix}")

    def _simulate(self, ctx: Context, p: Principal, action: str, resource: str) -> SimResult:
        """iam:SimulatePrincipalPolicy for one principal, all pages."""
        out = SimResult(principal=p)
        marker = ""
        results: list[_EvalResult] = []
        page = 0
        while True:
            if page >= MAX_PAGES:
                raise errorf(Code.UPSTREAM_ERROR, "SimulatePrincipalPolicy: too many pages")
            params: dict[str, Any] = {
                "PolicySourceArn": p.arn,
                "ActionNames": [action],
                "MaxItems": 100,
            }
            # UNVERIFIED: for "*" ResourceArns is omitted and IAM's documented
            # default ("*") relied on, rather than sending "*" as an ARN.
            if resource != "*":
                params["ResourceArns"] = [resource]
            for i, e in enumerate(self.context_entries):
                pfx = f"ContextEntries.member.{i + 1}"
                params[pfx + ".ContextKeyName"] = e.key
                params[pfx + ".ContextKeyType"] = e.type
                for j, v in enumerate(e.values):
                    params[f"{pfx}.ContextKeyValues.member.{j + 1}"] = v
            if marker != "":
                params["Marker"] = marker
            root = self.iam.query(ctx, "SimulatePrincipalPolicy", IAM_VERSION, params)
            try:
                page_results, truncated, next_marker = _decode_simulate(root)
            except ValueError as e:
                raise ValueError(f"decode SimulatePrincipalPolicy response: {e}") from e
            results.extend(page_results)
            if not truncated or next_marker == "":
                break
            marker = next_marker
            page += 1
        found = False
        for r in results:
            if r.action_name != "" and r.action_name != action:
                continue
            found = True
            out.decision = r.decision
            out.missing.extend(r.missing)
            if r.org_allowed is not None and not r.org_allowed:
                out.scp_denied = True
            if r.boundary_allowed is not None and not r.boundary_allowed:
                out.boundary_denied = True
            # Merge the per-resource verdict for the requested resource with
            # the action-level one: allowed only when both agree, otherwise
            # the more restrictive decision wins.
            for rr in r.resources:
                if rr.name == resource or (resource == "*" and len(r.resources) == 1):
                    if rr.decision != "":
                        out.decision = more_restrictive(out.decision, rr.decision)
                    out.missing.extend(rr.missing)
        if not found:
            raise errorf(Code.UPSTREAM_ERROR, f"SimulatePrincipalPolicy returned no result for {action}")
        if out.decision not in ("allowed", "explicitDeny", "implicitDeny"):
            raise errorf(Code.UPSTREAM_ERROR, "SimulatePrincipalPolicy returned an unknown decision")
        return out

    def probe(self, ctx: Context) -> ProbeResult:
        """Verify the assumed role, list the account's Identity Center roles
        and, in identity_center mode, check the instance against the config."""
        try:
            root = self.sts.query(ctx, "GetCallerIdentity", STS_VERSION, {})
        except Exception as e:
            raise classified(e, "GetCallerIdentity") from e
        arn = xmlutil.text(root, "GetCallerIdentityResult", "Arn")
        account = xmlutil.text(root, "GetCallerIdentityResult", "Account")
        warnings: list[str] = []
        if account != "" and account != self.account_id:
            warnings.append(f"the assumed role is in account {account}, not account_id {self.account_id}")
        roles = self._list_sso_roles(ctx)
        summary = f"authenticated as {arn}; {len(roles)} AWSReservedSSO roles in account {self.account_id}"
        if self.mode == "identity_center":
            try:
                out = self._json11(self.sso_admin, ctx, "SWBExternalService.ListInstances", {})
                instances = [jsonx.obj(i) for i in jsonx.arr(out, "Instances")]
                pairs = [(jsonx.s(i, "InstanceArn"), jsonx.s(i, "IdentityStoreId")) for i in instances]
            except Exception as e:
                raise classified(e, "ListInstances") from e
            matched = False
            for instance_arn, store_id in pairs:
                if instance_arn != self.sso_instance_arn:
                    continue
                matched = True
                if store_id != self.identity_store_id:
                    warnings.append(f"sso_instance_arn has identity store {store_id} but identity_store_id is {self.identity_store_id}")
            if not matched:
                warnings.append(f"sso:ListInstances did not list sso_instance_arn {self.sso_instance_arn} ({len(pairs)} instances visible)")
            if not roles:
                warnings.append("no AWSReservedSSO roles in the account; every user will be denied until a permission set is provisioned")
        warnings.append("iam:SimulatePrincipalPolicy discloses information about the permissions granted to other users; this is inherent to how hallpass checks")
        return ProbeResult(summary=summary, warnings=tuple(warnings))
