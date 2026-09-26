"""Port of internal/integrations/aws/aws_test.go."""

from __future__ import annotations

import datetime
import json
import os
import threading
import urllib.parse
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

import pytest

from hallpass.authx import xmlutil
from hallpass.core.context import background
from hallpass.core.decision import Code, Decision, HallpassError, Outcome
from hallpass.core.integration import Connection, Field, User, find_action, validate_fields
from hallpass.core.secret import Secret, literal
from hallpass.integrations.aws import AWS, AWSConnection
from hallpass.integrations.aws import aws as aws_mod
from hallpass.integrations.aws.actions import ALIAS_LIST, ALIASES, RAW_ACTION_RE
from hallpass.integrations.aws.aws import _decode_simulate, more_restrictive, parse_context_entries
from hallpass.integrations.aws.identity import SSO_PATH_PREFIX, Native, SSORole, match_sso_role
from tests import harness as itest
from tests.harness.spec import SpecOptions, any_spec, spec_from_env

ACCT = "123456789012"
ROLE_ARN = "arn:aws:iam::123456789012:role/hallpass-read"
IC_ROLE_ARN = "arn:aws:iam::999999999999:role/hallpass-ic-read"
STORE_ID = "d-1234567890"
INSTANCE_ARN = "arn:aws:sso:::instance/ssoins-0123456789abcdef"

BASE_KEY = "AKIA" + itest.CANARY + "base"
TARGET_KEY = "ASIA" + itest.CANARY + "target"
IC_KEY = "ASIA" + itest.CANARY + "ic"
IMDS_KEY = "ASIA" + itest.CANARY + "imds"

PS_RO = "arn:aws:sso:::permissionSet/ssoins-0123456789abcdef/ps-aaaaaaaaaaaaaaaa"
PS_DEV = "arn:aws:sso:::permissionSet/ssoins-0123456789abcdef/ps-bbbbbbbbbbbbbbbb"
PS_ADM = "arn:aws:sso:::permissionSet/ssoins-0123456789abcdef/ps-cccccccccccccccc"

ROLE_RO = "arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_ReadOnly_0123456789abcdef"
ROLE_DEV = "arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/eu-west-1/AWSReservedSSO_Developer_fedcba9876543210"
ROLE_ADMIN = "arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Admin_00000000000000ff"

BUCKET_KEY = "arn:aws:s3:::bucket/key"

_STATIC_JSON = '{"access_key_id":"' + BASE_KEY + '","secret_access_key":"' + itest.CANARY + 'secret"}'


def static_cred() -> Secret:
    return literal(_STATIC_JSON)


secret_lit = literal


@dataclass
class ICUserRec:
    id: str
    user_name: str
    display: str
    status: str = ""


@dataclass
class FakeRole:
    name: str
    path: str
    arn: str


def _rfc3339(ts: float) -> str:
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def credential_scope(auth: str) -> tuple[str, str, str]:
    """The access key id, region and signing service of a SigV4 header."""
    _, sep, rest = auth.partition("Credential=")
    if not sep:
        return "", "", ""
    cred = rest.partition(",")[0]
    parts = cred.split("/")
    if len(parts) != 5:
        return "", "", ""
    return parts[0], parts[2], parts[3]


def xml_error(w: Any, status: int, code: str, msg: str) -> None:
    w.header().set("Content-Type", "text/xml")
    w.write_header(status)
    w.write(f"<ErrorResponse><Error><Type>Sender</Type><Code>{code}</Code><Message>{msg}</Message></Error><RequestId>r</RequestId></ErrorResponse>")


def json_error(w: Any, status: int, code: str, msg: str) -> None:
    w.header().set("Content-Type", "application/x-amz-json-1.1")
    w.write_header(status)
    w.write(f'{{"__type":"com.amazonaws.identitystore#{code}","Message":"{msg}"}}')


def _encode(w: Any, v: Any) -> None:
    w.write(json.dumps(v) + "\n")


class FakeAWS:
    """Serves STS, IAM, Identity Store, SSO Admin and IMDS on one server."""

    def __init__(self) -> None:
        self.mu = threading.RLock()
        self.base_key = BASE_KEY
        self.external_id = ""
        self.sts_calls = self.list_roles_calls = self.simulate_calls = self.get_user_id_calls = 0
        self.users: dict[str, ICUserRec] = {
            "dana@example.com": ICUserRec("u-dana", "dana", "Dana D"),
            "bob@example.com": ICUserRec("u-bob", "bob", "Bob B"),
            "off@example.com": ICUserRec("u-off", "off", "Off", "DISABLED"),
            "adm@example.com": ICUserRec("u-adm", "adm", "Adm"),
        }
        self.user_names = {"lee@example.com": "lee@example.com"}  # userName -> email
        self.groups = {"u-dana": ["g-platform", "g-empty"]}
        self.assignments = {"u-dana": [PS_RO], "g-platform": [PS_DEV], "u-off": [PS_RO], "u-adm": [PS_ADM], "u-lee": [PS_RO]}
        self.row_account: dict[str, str] = {}  # permission set ARN -> AccountId to emit instead of ACCT
        self.permission_sets = {PS_RO: "ReadOnly", PS_DEV: "Developer", PS_ADM: "Adm"}
        self.roles = [
            FakeRole("AWSReservedSSO_ReadOnly_0123456789abcdef", SSO_PATH_PREFIX, ROLE_RO),
            FakeRole("AWSReservedSSO_Admin_00000000000000ff", SSO_PATH_PREFIX, ROLE_ADMIN),
            FakeRole("AWSReservedSSO_Developer_fedcba9876543210", SSO_PATH_PREFIX + "eu-west-1/", ROLE_DEV),
            FakeRole(
                "AWSReservedSSO_Other_1111111111111111",
                SSO_PATH_PREFIX,
                "arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Other_1111111111111111",
            ),
            FakeRole(
                "AWSReservedSSO_ReadOnlyExtra_2222222222222222",
                SSO_PATH_PREFIX,
                "arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_ReadOnlyExtra_2222222222222222",
            ),
        ]
        self.roles_per_page = 3
        self.iam_users = {
            "dana": "arn:aws:iam::123456789012:user/dana",
            "lee@example.com": "arn:aws:iam::123456789012:user/lee@example.com",
        }
        self.instances: list[dict[str, str]] | None = [{"InstanceArn": INSTANCE_ARN, "IdentityStoreId": STORE_ID}]
        self.policy = {
            ROLE_RO + "|s3:GetObject|" + BUCKET_KEY: "allowed",
            ROLE_DEV + "|s3:PutObject|" + BUCKET_KEY: "allowed",
            ROLE_RO + "|ec2:TerminateInstances|*": "explicitDeny",
            ROLE_DEV + "|ec2:TerminateInstances|*": "explicitDeny",
            ROLE_DEV + "|ec2:StopInstances|*": "explicitDeny",
            "arn:aws:iam::123456789012:user/dana|s3:GetObject|" + BUCKET_KEY: "allowed",
            "arn:aws:iam::123456789012:role/Deployer|s3:GetObject|*": "allowed",
            "arn:aws:iam::123456789012:role/PlatformAdmin|s3:GetObject|*": "allowed",
        }
        self.missing: list[str] = []
        self.org_denied = False
        self.boundary_denied = False
        self.eval_only = False
        self.eval_decision = ""  # overrides EvalDecision when resource-specific results are present
        self.page_split = False
        self.sim_err = ""  # IAM error code returned by SimulatePrincipalPolicy
        self.fail = ""  # "throttle" or "denied": every signed call fails

    def user(self, email: str) -> ICUserRec | None:
        u = self.users.get(email)
        if u is not None:
            return u
        for e, name in self.user_names.items():
            if name == email:
                return ICUserRec("u-" + e.split("@")[0], name, name)
        return None

    def handler(self, w: Any, r: Any) -> None:
        with self.mu:
            self._handle(w, r)

    def _handle(self, w: Any, r: Any) -> None:
        # IMDSv2 (unsigned).
        if r.method == "PUT" and r.path == "/latest/api/token":
            if r.header.get("X-aws-ec2-metadata-token-ttl-seconds") == "":
                w.write_header(400)
                return
            w.write(b"imds-token")
            return
        if r.path.startswith("/latest/meta-data/"):
            if r.header.get("X-aws-ec2-metadata-token") != "imds-token":
                w.write_header(401)
                return
            if r.path == "/latest/meta-data/iam/security-credentials/":
                w.write(b"instance-role\n")
                return
            if r.path == "/latest/meta-data/iam/security-credentials/instance-role":
                import time

                _encode(
                    w,
                    {
                        "AccessKeyId": IMDS_KEY,
                        "SecretAccessKey": itest.CANARY + "imds",
                        "Token": itest.CANARY + "imdstok",
                        "Expiration": _rfc3339(time.time() + 3600),
                    },
                )
                return
            w.write_header(404)
            return
        auth = r.header.get("Authorization")
        if not auth.startswith("AWS4-HMAC-SHA256 ") or r.header.get("X-Amz-Date") == "":
            xml_error(w, 403, "MissingAuthenticationToken", "unsigned")
            return
        akid, region, service = credential_scope(auth)
        target = r.header.get("X-Amz-Target")
        if target != "":
            if self.fail == "throttle":
                json_error(w, 400, "ThrottlingException", "slow down")
                return
            if self.fail == "denied":
                json_error(w, 403, "AccessDeniedException", "no")
                return
            if r.header.get("Content-Type") != "application/x-amz-json-1.1":
                json_error(w, 400, "ValidationException", "content type")
                return
            if akid != IC_KEY or r.header.get("X-Amz-Security-Token") == "" or region != "eu-west-1":
                json_error(w, 403, "AccessDeniedException", "wrong credential for identity center")
                return
            try:
                body = json.loads(r.body)
            except ValueError:
                body = None
            if not isinstance(body, dict):
                json_error(w, 400, "ValidationException", "body")
                return
            self.serve_json(w, target, service, body)
            return
        if self.fail == "throttle":
            xml_error(w, 400, "Throttling", "Rate exceeded")
            return
        if self.fail == "denied":
            xml_error(w, 403, "AccessDenied", "not authorized")
            return
        form = urllib.parse.parse_qs(r.raw_query, keep_blank_values=True)
        for k, vs in urllib.parse.parse_qs(r.body.decode(), keep_blank_values=True).items():
            form.setdefault(k, []).extend(vs)
        self.serve_query(w, form, akid, region, service, r.header.get("X-Amz-Security-Token") != "")

    def serve_query(self, w: Any, form: dict[str, list[str]], akid: str, region: str, service: str, has_token: bool) -> None:
        def get(k: str) -> str:
            vs = form.get(k)
            return vs[0] if vs else ""

        action = get("Action")
        w.header().set("Content-Type", "text/xml")
        if action == "AssumeRole":
            self.sts_calls += 1
            if service != "sts" or region != "eu-west-1" or get("Version") != "2011-06-15":
                xml_error(w, 400, "InvalidAction", "bad sts call")
                return
            if akid != self.base_key:
                xml_error(w, 403, "InvalidClientTokenId", "unknown key")
                return
            if get("ExternalId") != self.external_id or get("RoleSessionName") == "":
                xml_error(w, 403, "AccessDenied", "external id or session name")
                return
            if get("RoleArn") == ROLE_ARN:
                key = TARGET_KEY
            elif get("RoleArn") == IC_ROLE_ARN:
                key = IC_KEY
            else:
                xml_error(w, 403, "AccessDenied", "cannot assume")
                return
            import time

            w.write(
                "<AssumeRoleResponse><AssumeRoleResult><Credentials>"
                f"<AccessKeyId>{key}</AccessKeyId><SecretAccessKey>{itest.CANARY}assumed</SecretAccessKey>"
                f"<SessionToken>{itest.CANARY}token</SessionToken><Expiration>{_rfc3339(time.time() + 3600)}</Expiration>"
                f"</Credentials><AssumedRoleUser><Arn>arn:aws:sts::{ACCT}:assumed-role/x/s</Arn></AssumedRoleUser></AssumeRoleResult></AssumeRoleResponse>"
            )
            return
        if action == "GetCallerIdentity":
            if service != "sts" or akid != TARGET_KEY or not has_token:
                xml_error(w, 403, "AccessDenied", "wrong credential")
                return
            w.write(
                "<GetCallerIdentityResponse><GetCallerIdentityResult>"
                f"<Arn>arn:aws:sts::{ACCT}:assumed-role/hallpass-read/hallpass</Arn><Account>{ACCT}</Account>"
                "</GetCallerIdentityResult></GetCallerIdentityResponse>"
            )
            return
        # IAM
        if service != "iam" or region != "us-east-1" or akid != TARGET_KEY or not has_token:
            xml_error(w, 403, "AccessDenied", "wrong credential for iam")
            return
        if get("Version") != "2010-05-08":
            xml_error(w, 400, "InvalidAction", "version")
            return
        if action == "ListRoles":
            self.list_roles_calls += 1
            if get("PathPrefix") != SSO_PATH_PREFIX:
                xml_error(w, 400, "ValidationError", "prefix")
                return
            start = 0
            if get("Marker") != "":
                try:
                    start = int(get("Marker"))
                except ValueError:
                    start = 0
            end = min(start + self.roles_per_page, len(self.roles))
            b = ["<ListRolesResponse><ListRolesResult><Roles>"]
            for ro in self.roles[start:end]:
                b.append(f"<member><Path>{ro.path}</Path><RoleName>{ro.name}</RoleName><Arn>{ro.arn}</Arn></member>")
            b.append("</Roles>")
            if end < len(self.roles):
                b.append(f"<IsTruncated>true</IsTruncated><Marker>{end}</Marker>")
            else:
                b.append("<IsTruncated>false</IsTruncated>")
            b.append("</ListRolesResult></ListRolesResponse>")
            w.write("".join(b))
        elif action == "GetUser":
            arn = self.iam_users.get(get("UserName"))
            if arn is None:
                xml_error(w, 404, "NoSuchEntity", "no user")
                return
            name = get("UserName")
            w.write(
                f"<GetUserResponse><GetUserResult><User><Path>/</Path><UserName>{name}</UserName>"
                f"<UserId>AIDA{name.upper()}</UserId><Arn>{arn}</Arn></User></GetUserResult></GetUserResponse>"
            )
        elif action == "SimulatePrincipalPolicy":
            self.simulate_calls += 1
            if self.sim_err != "":
                xml_error(w, 400, self.sim_err, "simulate failed")
                return
            principal = get("PolicySourceArn")
            act = get("ActionNames.member.1")
            res = get("ResourceArns.member.1") or "*"
            if get("MaxItems") != "100" or get("ActionNames.member.2") != "":
                xml_error(w, 400, "ValidationError", "params")
                return
            dec = self.policy.get(principal + "|" + act + "|" + res)
            if dec is None:
                dec = self.policy.get(principal + "|" + act + "|*", "")
            if dec == "":
                dec = "implicitDeny"
            b = ["<SimulatePrincipalPolicyResponse><SimulatePrincipalPolicyResult><EvaluationResults>"]
            if self.page_split and get("Marker") == "":
                b.append(
                    "<member><EvalActionName>s3:ListAllMyBuckets</EvalActionName><EvalDecision>allowed</EvalDecision>"
                    "<EvalResourceName>*</EvalResourceName></member>"
                )
                b.append(
                    "</EvaluationResults><IsTruncated>true</IsTruncated><Marker>page2</Marker></SimulatePrincipalPolicyResult></SimulatePrincipalPolicyResponse>"
                )
                w.write("".join(b))
                return
            eval_dec = dec
            if self.eval_decision != "" and not self.eval_only:
                eval_dec = self.eval_decision
            b.append(f"<member><EvalActionName>{act}</EvalActionName><EvalDecision>{eval_dec}</EvalDecision><EvalResourceName>{res}</EvalResourceName>")
            if self.org_denied:
                b.append("<OrganizationsDecisionDetail><AllowedByOrganizations>false</AllowedByOrganizations></OrganizationsDecisionDetail>")
            else:
                b.append("<OrganizationsDecisionDetail><AllowedByOrganizations>true</AllowedByOrganizations></OrganizationsDecisionDetail>")
            if self.boundary_denied:
                b.append(
                    "<PermissionsBoundaryDecisionDetail><AllowedByPermissionsBoundary>false</AllowedByPermissionsBoundary></PermissionsBoundaryDecisionDetail>"
                )
            missing = "".join(f"<member>{m}</member>" for m in self.missing)
            if self.eval_only:
                if self.missing:
                    b.append(f"<MissingContextValues>{missing}</MissingContextValues>")
            else:
                b.append(f"<ResourceSpecificResults><member><EvalResourceName>{res}</EvalResourceName><EvalResourceDecision>{dec}</EvalResourceDecision>")
                if self.missing:
                    b.append(f"<MissingContextValues>{missing}</MissingContextValues>")
                b.append("</member></ResourceSpecificResults>")
            b.append("</member></EvaluationResults><IsTruncated>false</IsTruncated></SimulatePrincipalPolicyResult></SimulatePrincipalPolicyResponse>")
            w.write("".join(b))
        else:
            xml_error(w, 400, "InvalidAction", action)

    def serve_json(self, w: Any, target: str, service: str, body: dict[str, Any]) -> None:
        w.header().set("Content-Type", "application/x-amz-json-1.1")

        def s(m: Any, k: str) -> str:
            v = m.get(k) if isinstance(m, dict) else None
            return v if isinstance(v, str) else ""

        def sub(m: Any, k: str) -> dict[str, Any]:
            v = m.get(k) if isinstance(m, dict) else None
            return v if isinstance(v, dict) else {}

        def page(items: list[str], token: str) -> tuple[list[str], str]:
            start = 0
            if token != "":
                try:
                    start = int(token)
                except ValueError:
                    start = 0
            if start >= len(items):
                return [], ""
            end = start + 1
            nxt = str(end) if end < len(items) else ""
            return items[start:end], nxt

        svc, _, op = target.partition(".")
        if (svc == "AWSIdentityStore" and service != "identitystore") or (svc == "SWBExternalService" and service != "sso"):
            json_error(w, 403, "AccessDeniedException", "signing name")
            return
        if svc == "AWSIdentityStore" and s(body, "IdentityStoreId") != STORE_ID:
            json_error(w, 400, "ValidationException", "store")
            return
        if svc == "SWBExternalService" and op != "ListInstances" and s(body, "InstanceArn") != INSTANCE_ARN:
            json_error(w, 400, "ValidationException", "instance")
            return
        if target == "AWSIdentityStore.GetUserId":
            self.get_user_id_calls += 1
            ua = sub(sub(body, "AlternateIdentifier"), "UniqueAttribute")
            path, val = s(ua, "AttributePath"), s(ua, "AttributeValue")
            u: ICUserRec | None = None
            if path == "emails.value":
                u = self.users.get(val)
            elif path == "userName":
                e = self.user_names.get(val)
                if e is not None:
                    u = self.user(e)
                for rec in self.users.values():
                    if rec.user_name == val:
                        u = rec
            else:
                json_error(w, 400, "ValidationException", "path")
                return
            if u is None:
                json_error(w, 400, "ResourceNotFoundException", "no user")
                return
            _encode(w, {"IdentityStoreId": STORE_ID, "UserId": u.id})
        elif target == "AWSIdentityStore.DescribeUser":
            uid = s(body, "UserId")
            for e, u in self.users.items():
                if u.id == uid:
                    out: dict[str, Any] = {
                        "UserId": uid,
                        "UserName": u.user_name,
                        "DisplayName": u.display,
                        "IdentityStoreId": STORE_ID,
                        "Emails": [{"Value": e, "Primary": True}],
                    }
                    if u.status != "":
                        out["UserStatus"] = u.status
                    _encode(w, out)
                    return
            for e, name in self.user_names.items():
                rec = self.user(name)
                if rec is not None and rec.id == uid:
                    _encode(w, {"UserId": uid, "UserName": name, "DisplayName": e})
                    return
            json_error(w, 400, "ResourceNotFoundException", "no user")
        elif target == "AWSIdentityStore.ListGroupMembershipsForMember":
            uid = s(sub(body, "MemberId"), "UserId")
            items, nxt = page(self.groups.get(uid, []), s(body, "NextToken"))
            out = {"GroupMemberships": [{"GroupId": g, "MemberId": uid, "MembershipId": "m-" + g} for g in items]}
            if nxt != "":
                out["NextToken"] = nxt
            _encode(w, out)
        elif target == "SWBExternalService.ListAccountAssignmentsForPrincipal":
            if s(sub(body, "Filter"), "AccountId") != ACCT:
                json_error(w, 400, "ValidationException", "filter")
                return
            typ = s(body, "PrincipalType")
            pid = s(body, "PrincipalId")
            if (typ == "USER") != pid.startswith("u-") or (typ == "GROUP") != pid.startswith("g-"):
                json_error(w, 400, "ValidationException", "principal type")
                return
            items, nxt = page(self.assignments.get(pid, []), s(body, "NextToken"))
            rows = []
            for ps in items:
                row_acct = self.row_account.get(ps, ACCT)
                rows.append({"AccountId": row_acct, "PermissionSetArn": ps, "PrincipalId": pid, "PrincipalType": typ})
            out = {"AccountAssignments": rows}
            if nxt != "":
                out["NextToken"] = nxt
            _encode(w, out)
        elif target == "SWBExternalService.DescribePermissionSet":
            name = self.permission_sets.get(s(body, "PermissionSetArn"))
            if name is None:
                json_error(w, 400, "ResourceNotFoundException", "no ps")
                return
            _encode(w, {"PermissionSet": {"Name": name, "PermissionSetArn": s(body, "PermissionSetArn")}})
        elif target == "SWBExternalService.ListInstances":
            _encode(w, {"Instances": self.instances})
        else:
            json_error(w, 400, "UnknownOperationException", target)


def aws_spec_options() -> SpecOptions:
    return SpecOptions(ignore_paths=[r"^/latest/"])


def aws_spec() -> Any:
    return any_spec(spec_from_env("aws-sts"), spec_from_env("aws-iam"), spec_from_env("aws-identitystore"), spec_from_env("aws-sso-admin"))


class Env:
    def __init__(self, srv: itest.Server, f: FakeAWS) -> None:
        self.srv = srv
        self.f = f
        self.now = 1_700_000_000.0
        self.conn: Connection
        self.c: AWSConnection

    def clock(self) -> float:
        with self.f.mu:
            return self.now

    def advance(self, d: float) -> None:
        with self.f.mu:
            self.now += d


Setup = Callable[..., Env]


@pytest.fixture
def servers() -> Iterator[list[itest.Server]]:
    out: list[itest.Server] = []
    yield out
    errors: list[str] = []
    for s in out:
        s.close()
        errors.extend(s.spec_errors)
    assert not errors, "requests did not match the API description:\n" + "\n".join(errors)


@pytest.fixture
def setup(servers: list[itest.Server], monkeypatch: pytest.MonkeyPatch) -> Setup:
    def make(values: dict[str, str] | None = None, cred: Secret | None = None) -> Env:
        srv = itest.Server()
        servers.append(srv)
        srv.use_spec(aws_spec(), aws_spec_options())
        f = FakeAWS()
        srv.handle("", "/*", f.handler)
        e = Env(srv, f)
        deps, _ = itest.deps(srv, now=e.clock)
        monkeypatch.setattr(aws_mod, "TEST_ENDPOINTS", {"sts": srv.url, "iam": srv.url, "identitystore": srv.url, "sso": srv.url, "imds": srv.url})
        v = {
            "account_id": ACCT,
            "role_arn": ROLE_ARN,
            "partition": "aws",
            "region": "eu-west-1",
            "identity_mode": "identity_center",
            "identity_center_role_arn": IC_ROLE_ARN,
            "identity_center_region": "eu-west-1",
            "identity_store_id": STORE_ID,
            "sso_instance_arn": INSTANCE_ARN,
            "implicit_deny_as": "deny",
            "session_name": "hallpass",
        }
        for k, val in (values or {}).items():
            if val == "":
                v.pop(k, None)
                continue
            v[k] = val
        if cred is None or cred.is_zero():
            cred = static_cred()
        s = itest.settings("aws-prod", "aws", v, {"credential": cred})
        conn = AWS().new(background(), s, deps)
        e.conn = conn
        assert isinstance(conn, AWSConnection)
        e.c = conn
        e.c.plain.sleep_fn = lambda ctx, d: None
        return e

    return make


dana = User(email="dana@example.com", groups=("platform-team",))
bob = User(email="bob@example.com")
lee = User(email="lee@example.com")
off = User(email="off@example.com")
adm = User(email="adm@example.com")


def check(e: Env, u: User, action: str, resource: str) -> Decision:
    return itest.check(e.conn, AWS(), u, action, resource)


def last_form(e: Env, action: str) -> dict[str, list[str]]:
    for c in reversed(e.srv.calls()):
        try:
            form = urllib.parse.parse_qs(c.body.decode(), keep_blank_values=True, strict_parsing=True)
        except (ValueError, UnicodeDecodeError):
            continue
        if form.get("Action", [""])[0] == action:
            return form
    pytest.fail(f"no {action} call recorded")


def fget(form: dict[str, list[str]], k: str) -> str:
    vs = form.get(k)
    return vs[0] if vs else ""


def test_static_credential_and_assume_role_caching(setup: Setup) -> None:
    e = setup()
    d = check(e, dana, "s3.read", BUCKET_KEY)
    itest.expect_code(d, Code.ALLOWED)
    assert "permission set ReadOnly" in d.text, f"text {d.text!r} should name the permission set"
    for _ in range(5):
        itest.expect_code(check(e, dana, "s3.read", BUCKET_KEY), Code.ALLOWED)
        itest.expect_code(check(e, bob, "s3.read", BUCKET_KEY), Code.DENIED)
    with e.f.mu:
        sts = e.f.sts_calls
    assert sts == 2, f"AssumeRole called {sts} times, want 2 (account role and Identity Center role)"
    form = last_form(e, "AssumeRole")
    assert fget(form, "RoleSessionName") == "hallpass"
    # The connection keeps no identity cache of its own: the engine's
    # identity cache (identity_cache_seconds) is the only one, so every
    # resolve_identity call reaches Identity Store. Eleven checks, two of
    # them for bob with one GetUserId each, and dana's ten with one each.
    with e.f.mu:
        n = e.f.get_user_id_calls
    assert n == 11, f"GetUserId called {n} times for eleven checks, want 11 (identity cached in the connection)"
    # A credential that is neither JSON nor ambient: the error never carries it.
    bad = setup(cred=secret_lit(itest.CANARY + "raw-key"))
    d = check(bad, dana, "s3.read", BUCKET_KEY)
    assert d.outcome == Outcome.UNKNOWN and itest.CANARY not in d.text, f"bad credential: {d.code} {d.text}"
    with pytest.raises(ValueError) as ei:
        bad.c.account_creds.credentials(background())
    assert itest.CANARY not in str(ei.value), f"credential error leaks: {ei.value}"


def test_external_id(setup: Setup) -> None:
    e = setup({"external_id": "ext-1"})
    e.f.external_id = "ext-1"
    itest.expect_code(check(e, dana, "s3.read", BUCKET_KEY), Code.ALLOWED)
    assert fget(last_form(e, "AssumeRole"), "ExternalId") == "ext-1", "ExternalId not sent"


def test_ambient_imds(setup: Setup) -> None:
    e = setup(cred=secret_lit("ambient:imds"))
    e.f.base_key = IMDS_KEY
    itest.expect_code(check(e, dana, "s3.read", BUCKET_KEY), Code.ALLOWED)
    token = creds = False
    for c in e.srv.calls():
        if c.method == "PUT" and c.path == "/latest/api/token":
            token = True
        if c.path == "/latest/meta-data/iam/security-credentials/instance-role":
            creds = True
    assert token and creds, "IMDSv2 token and credential calls not made"
    itest.expect_code(check(e, dana, "s3.read", BUCKET_KEY), Code.ALLOWED)
    with e.f.mu:
        assert e.f.sts_calls == 2, f"AssumeRole called {e.f.sts_calls} times"
    bogus = setup(cred=secret_lit("ambient:bogus"))
    d = check(bogus, dana, "s3.read", BUCKET_KEY)
    assert d.outcome == Outcome.UNKNOWN, d


def test_identity_center(setup: Setup) -> None:
    e = setup()
    ident = e.conn.resolve_identity(background(), dana)
    nat = ident.native
    assert isinstance(nat, Native)
    assert ident.id == "u-dana" and ident.display == "dana" and len(ident.groups) == 2 and len(nat.principals) == 2 and not nat.missing, f"{ident} {nat}"
    assert nat.principals[0].arn == ROLE_RO and nat.principals[1].arn == ROLE_DEV, f"principals {nat.principals}"
    assert ",".join(nat.permission_sets) == "ReadOnly,Developer", f"permission sets {nat.permission_sets}"
    # Role list: paginated (5 roles, 3 per page = 2 requests).
    form = last_form(e, "ListRoles")
    assert fget(form, "Marker") == "3" and fget(form, "PathPrefix") == SSO_PATH_PREFIX, f"ListRoles form {form}"
    # Group-inherited permission set allows what the user's own does not.
    d = check(e, dana, "s3.write", BUCKET_KEY)
    itest.expect_code(d, Code.ALLOWED)
    assert "permission set Developer" in d.text, d.text
    # No assignments at all.
    d = check(e, bob, "s3.read", BUCKET_KEY)
    itest.expect_code(d, Code.DENIED)
    assert "no permission set assigned in account " + ACCT in d.text, d.text
    # userName fallback.
    e.srv.reset()
    ident = e.conn.resolve_identity(background(), lee)
    assert ident.id == "u-lee", ident
    paths = []
    for c in e.srv.calls():
        if c.header.get("X-Amz-Target") == "AWSIdentityStore.GetUserId":
            ua = c.json()["AlternateIdentifier"]["UniqueAttribute"]
            paths.append(ua["AttributePath"] + "=" + ua["AttributeValue"])
    assert " ".join(paths) == "emails.value=lee@example.com userName=lee@example.com", f"GetUserId lookups: {paths}"
    # Unknown user.
    itest.expect_code(check(e, User(email="nobody@example.com"), "s3.read", BUCKET_KEY), Code.USER_NOT_FOUND)
    # DISABLED user is denied even though the permission set allows.
    d = check(e, off, "s3.read", BUCKET_KEY)
    itest.expect_code(d, Code.DENIED)
    assert "disabled" in d.text, d.text
    # Anchored matching: permission set "Adm" must not match AWSReservedSSO_Admin_*.
    d = check(e, adm, "s3.read", BUCKET_KEY)
    itest.expect_code(d, Code.RESOURCE_NOT_VISIBLE)
    assert "Adm " in d.text and "Admin" not in d.text, d.text
    assert not match_sso_role([SSORole(name="AWSReservedSSO_Admin_00000000000000ff", arn=ROLE_ADMIN)], "Adm")[1], "prefix match accepted"
    assert match_sso_role([SSORole(name="AWSReservedSSO_Adm_00000000000000ff", arn="x")], "Adm")[1], "exact match rejected"
    assert not match_sso_role([SSORole(name="AWSReservedSSO_Read.Only_00000000000000ff", arn="x")], "Read-Only")[1], "regexp metacharacters not quoted"
    # The role list is cached across users.
    with e.f.mu:
        lr = e.f.list_roles_calls
    assert lr == 2, f"ListRoles requests = {lr}, want 2 (one paginated listing)"
    # After the cache TTL the list is fetched again.
    e.advance(11 * 60)
    itest.expect_code(check(e, dana, "s3.read", BUCKET_KEY), Code.ALLOWED)
    with e.f.mu:
        lr = e.f.list_roles_calls
    assert lr == 4, f"ListRoles requests after TTL = {lr}, want 4"


def test_static_map(setup: Setup, servers: list[itest.Server], tmp_path: Any) -> None:
    path = os.path.join(tmp_path, "roles.txt")
    with open(path, "w") as fh:
        fh.write("# comment\n\nDana@example.com arn:aws:iam::123456789012:role/Deployer\nplatform-team arn:aws:iam::123456789012:role/PlatformAdmin\n")
    e = setup(
        {
            "identity_mode": "static_map",
            "role_map_file": path,
            "identity_center_role_arn": "",
            "identity_center_region": "",
            "identity_store_id": "",
            "sso_instance_arn": "",
        }
    )
    d = check(e, User(email="dana@example.com"), "s3.read", "all")
    itest.expect_code(d, Code.ALLOWED)
    assert "role Deployer" in d.text, d.text
    assert fget(last_form(e, "SimulatePrincipalPolicy"), "ResourceArns.member.1") == "", "ResourceArns sent for *"
    d = check(e, User(email="bob@example.com", groups=("Platform-Team",)), "s3.read", "all")
    itest.expect_code(d, Code.ALLOWED)
    assert "role PlatformAdmin" in d.text, d.text
    itest.expect_code(check(e, bob, "s3.read", "all"), Code.USER_NOT_FOUND)
    # A miss for one set of groups says nothing about another: the same
    # email arriving with a mapped group resolves (the engine keys its
    # negative identity cache by groups for this reason).
    itest.expect_code(check(e, User(email="bob@example.com", groups=("platform-team",)), "s3.read", "all"), Code.ALLOWED)
    itest.expect_code(check(e, User(email="dana@example.com"), "ec2.stop", "all"), Code.DENIED)
    with e.f.mu:
        sts = e.f.sts_calls
    assert sts == 1, f"AssumeRole called {sts} times, want 1"
    # Re-read after 60 s.
    with open(path, "w") as fh:
        fh.write("bob@example.com arn:aws:iam::123456789012:role/Deployer\n")
    itest.expect_code(check(e, bob, "s3.read", "all"), Code.USER_NOT_FOUND)
    e.advance(61)
    itest.expect_code(check(e, bob, "s3.read", "all"), Code.ALLOWED)
    # A broken re-read keeps the previous map.
    with open(path, "w") as fh:
        fh.write("bob@example.com not-an-arn\n")
    e.advance(61)
    itest.expect_code(check(e, bob, "s3.read", "all"), Code.ALLOWED)

    # new rejects a missing or malformed file.
    for bad_path in (os.path.join(tmp_path, "missing"), path):
        s = itest.settings(
            "x",
            "aws",
            {"account_id": ACCT, "role_arn": ROLE_ARN, "region": "eu-west-1", "identity_mode": "static_map", "role_map_file": bad_path},
            {"credential": static_cred()},
        )
        deps, _ = itest.deps(e.srv)
        with pytest.raises(ValueError):
            AWS().new(background(), s, deps)


def test_iam_user(setup: Setup) -> None:
    e = setup({"identity_mode": "iam_user"})
    d = check(e, User(email="dana@example.com"), "s3.read", BUCKET_KEY)
    itest.expect_code(d, Code.ALLOWED)
    assert "user dana" in d.text, d.text
    assert fget(last_form(e, "SimulatePrincipalPolicy"), "PolicySourceArn") == "arn:aws:iam::123456789012:user/dana", "principal is not the user ARN"
    ident = e.conn.resolve_identity(background(), lee)
    assert ident.display == "lee@example.com" and ident.attr("arn") == "arn:aws:iam::123456789012:user/lee@example.com", ident
    itest.expect_code(check(e, User(email="nobody@example.com"), "s3.read", BUCKET_KEY), Code.USER_NOT_FOUND)
    itest.expect_code(check(e, lee, "s3.read", BUCKET_KEY), Code.DENIED)
    with e.f.mu:
        sts = e.f.sts_calls
    assert sts == 1, f"AssumeRole called {sts} times, want 1"


def test_simulate_decisions(setup: Setup) -> None:
    e = setup()
    # explicitDeny on every principal.
    d = check(e, dana, "ec2.terminate", "all")
    itest.expect_code(d, Code.DENIED)
    assert "explicitly deny" in d.text, d.text
    # implicitDeny (one explicit, one implicit) -> deny by default.
    d = check(e, dana, "ec2.stop", "all")
    itest.expect_code(d, Code.DENIED)
    assert "explicitly" not in d.text, d.text
    # implicit_deny_as: unknown.
    u = setup({"implicit_deny_as": "unknown"})
    itest.expect_code(check(u, dana, "ec2.stop", "all"), Code.UNSUPPORTED)
    itest.expect_code(check(u, dana, "ec2.terminate", "all"), Code.DENIED)
    itest.expect_code(check(u, dana, "s3.read", BUCKET_KEY), Code.ALLOWED)

    # The resource-specific result and EvalDecision must agree on allowed;
    # otherwise the more restrictive of the two wins.
    with e.f.mu:
        e.f.eval_decision = "implicitDeny"  # resource says allowed
    d = check(e, dana, "s3.read", BUCKET_KEY)
    itest.expect_code(d, Code.DENIED)
    assert "explicitly" not in d.text, d.text
    with e.f.mu:
        e.f.eval_decision = "explicitDeny"  # resource says allowed
    d = check(e, dana, "s3.read", BUCKET_KEY)
    itest.expect_code(d, Code.DENIED)
    assert "explicitly deny" in d.text, d.text
    with e.f.mu:
        e.f.eval_decision = "allowed"  # resource says explicitDeny
    d = check(e, dana, "ec2.terminate", "all")
    itest.expect_code(d, Code.DENIED)
    assert "explicitly deny" in d.text, d.text
    with e.f.mu:
        e.f.eval_decision = "allowed"  # resource says allowed: both agree
    itest.expect_code(check(e, dana, "s3.read", BUCKET_KEY), Code.ALLOWED)
    # Without resource-specific results EvalDecision is used.
    with e.f.mu:
        e.f.eval_decision, e.f.eval_only = "", True
    itest.expect_code(check(e, dana, "s3.read", BUCKET_KEY), Code.ALLOWED)
    itest.expect_code(check(e, dana, "ec2.terminate", "all"), Code.DENIED)

    # Missing context values -> unknown naming the keys.
    with e.f.mu:
        e.f.eval_only, e.f.missing = False, ["aws:MultiFactorAuthPresent", "aws:SourceIp"]
    d = check(e, dana, "ec2.stop", "all")
    itest.expect_code(d, Code.UNSUPPORTED)
    assert "aws:MultiFactorAuthPresent, aws:SourceIp" in d.text and "context_entries" in d.text, d.text
    with e.f.mu:
        e.f.eval_only = True
    itest.expect_code(check(e, dana, "ec2.stop", "all"), Code.UNSUPPORTED)
    with e.f.mu:
        e.f.eval_only, e.f.missing = False, []

    # SCP and permissions boundary are named in the deny text.
    with e.f.mu:
        e.f.org_denied = True
    d = check(e, dana, "ec2.terminate", "all")
    itest.expect_code(d, Code.DENIED)
    assert "denied by SCP" in d.text, d.text
    with e.f.mu:
        e.f.org_denied, e.f.boundary_denied = False, True
    d = check(e, dana, "ec2.stop", "all")
    itest.expect_code(d, Code.DENIED)
    assert "permissions boundary" in d.text, d.text
    with e.f.mu:
        e.f.boundary_denied = False

    # Cross-account resource -> unknown, no simulation.
    e.srv.reset()
    d = check(e, dana, "raw:sqs:SendMessage", "arn:aws:sqs:eu-west-1:210987654321:queue")
    itest.expect_code(d, Code.UNSUPPORTED)
    assert "210987654321" in d.text, d.text
    for c in e.srv.calls():
        assert b"SimulatePrincipalPolicy" not in c.body, "cross-account resource was simulated"
    # Same-account ARN is fine.
    with e.f.mu:
        e.f.policy[ROLE_RO + "|sqs:SendMessage|arn:aws:sqs:eu-west-1:123456789012:queue"] = "allowed"
    itest.expect_code(check(e, dana, "raw:sqs:SendMessage", "arn:aws:sqs:eu-west-1:123456789012:queue"), Code.ALLOWED)

    # Simulation errors.
    with e.f.mu:
        e.f.sim_err = "PolicyEvaluation"
    itest.expect_code(check(e, dana, "s3.read", BUCKET_KEY), Code.UNSUPPORTED)
    with e.f.mu:
        e.f.sim_err = "NoSuchEntity"
        before = e.f.list_roles_calls
    d = check(e, dana, "s3.read", BUCKET_KEY)
    itest.expect_code(d, Code.RESOURCE_NOT_VISIBLE)
    # The text is honest about what refreshes: the engine holds the identity
    # (and so the vanished principal) until identity_cache_seconds expires.
    assert "vanished" in d.text and "identity_cache_seconds" in d.text and "cache will refresh" not in d.text, d.text
    with e.f.mu:
        e.f.sim_err = ""
    # The role list was dropped: the next resolve lists roles again.
    itest.expect_code(check(e, dana, "s3.read", BUCKET_KEY), Code.ALLOWED)
    with e.f.mu:
        after = e.f.list_roles_calls
    assert after == before + 2, f"ListRoles requests after NoSuchEntity = {after}, want {before + 2} (role list not dropped)"


def test_no_connection_identity_cache(setup: Setup) -> None:
    """The connection has no identity cache: the engine's
    identity_cache_seconds cache is the only one, keyed by email and
    groups, so nothing here can hold a stale identity beyond it."""
    e = setup()
    for _ in range(3):
        e.conn.resolve_identity(background(), dana)
    with e.f.mu:
        n = e.f.get_user_id_calls
    assert n == 3, f"GetUserId called {n} times for three resolves, want 3"
    iam = setup({"identity_mode": "iam_user"})
    iam.srv.reset()
    for _ in range(2):
        iam.conn.resolve_identity(background(), dana)
    get_user = sum(1 for c in iam.srv.calls() if b"Action=GetUser" in c.body)
    assert get_user == 2, f"GetUser called {get_user} times for two resolves, want 2"


def test_simulate_request_shape(setup: Setup) -> None:
    e = setup({"context_entries": "aws:MultiFactorAuthPresent=boolean:true; aws:SourceIp=ip:10.0.0.1;aws:PrincipalTag/team=stringList:a, b"})
    itest.expect_code(check(e, dana, "s3.read", BUCKET_KEY), Code.ALLOWED)
    form = last_form(e, "SimulatePrincipalPolicy")
    want = {
        "Version": "2010-05-08",
        "PolicySourceArn": ROLE_RO,
        "ActionNames.member.1": "s3:GetObject",
        "ResourceArns.member.1": BUCKET_KEY,
        "MaxItems": "100",
        "ContextEntries.member.1.ContextKeyName": "aws:MultiFactorAuthPresent",
        "ContextEntries.member.1.ContextKeyType": "boolean",
        "ContextEntries.member.1.ContextKeyValues.member.1": "true",
        "ContextEntries.member.2.ContextKeyName": "aws:SourceIp",
        "ContextEntries.member.2.ContextKeyType": "ip",
        "ContextEntries.member.2.ContextKeyValues.member.1": "10.0.0.1",
        "ContextEntries.member.3.ContextKeyName": "aws:PrincipalTag/team",
        "ContextEntries.member.3.ContextKeyType": "stringList",
        "ContextEntries.member.3.ContextKeyValues.member.1": "a",
        "ContextEntries.member.3.ContextKeyValues.member.2": "b",
    }
    errors = [f"{k} = {fget(form, k)!r}, want {v!r}" for k, v in want.items() if fget(form, k) != v]
    assert not errors, errors
    assert fget(form, "ContextEntries.member.4.ContextKeyName") == "", "extra context entry"
    # ReadOnly allowed, so it was the last (and only) principal simulated.
    assert fget(form, "PolicySourceArn") == ROLE_RO, "last simulate was not for ReadOnly"
    for bad in ("x", "k=string", "k=blob:1", "a=string:1;a=string:2", "bad key=string:1"):
        with pytest.raises(ValueError):
            parse_context_entries(bad)
    # Pagination of EvaluationResults.
    with e.f.mu:
        e.f.page_split = True
    e.srv.reset()
    itest.expect_code(check(e, dana, "ec2.terminate", "all"), Code.DENIED)
    markers = []
    for c in e.srv.calls():
        f = urllib.parse.parse_qs(c.body.decode(), keep_blank_values=True)
        if fget(f, "Action") == "SimulatePrincipalPolicy":
            markers.append(fget(f, "Marker"))
    assert ",".join(markers) == ",page2,,page2", f"markers {markers}"


def test_raw_actions_and_resources(setup: Setup) -> None:
    for ok in ("raw:s3:GetObject", "raw:iam:*", "raw:ec2:Describe*", "raw:secretsmanager:GetSecretValue", "raw:execute-api:Invoke"):
        assert AWS().match_action(ok) is not None, f"match_action({ok!r}) rejected"
    for bad in ("raw:S3:GetObject", "raw:s3", "raw:s3:", "raw:s3:Get-Object", "s3:GetObject", "raw:s3:GetObject:x", "raw::GetObject", "raw:s3:Get/Object"):
        assert AWS().match_action(bad) is None, f"match_action({bad!r}) accepted"
    assert find_action(AWS(), "raw:<service>:<Action>") is None, "the pattern's own name must not match"
    e = setup()
    with e.f.mu:
        e.f.policy[ROLE_RO + "|iam:*|*"] = "allowed"
    itest.expect_code(check(e, dana, "raw:iam:*", "all"), Code.ALLOWED)
    itest.expect_code(check(e, dana, "raw:kms:Decrypt", "arn:aws:kms:eu-west-1:123456789012:key/abc"), Code.DENIED)
    errors = []
    for bad in (
        "bucket:x",
        "arn:aws:s3:::b?x=1",
        "arn:aws-cn:s3:::b",
        "all:x",
        "arn:aws:s3",
        "arn:aws:s3:::",
        "arn:aws:s3:us-east-1:12345:b",
        "arn:foo:s3:::b",
        "arn",
    ):
        d = check(e, dana, "s3.read", bad)
        if d.code != Code.INVALID_REQUEST:
            errors.append(f"resource {bad!r} -> {d.code}: {d.text}")
    assert not errors, errors
    validate_fields(AWS().fields())


def test_field_validation(servers: list[itest.Server]) -> None:
    fields: dict[str, Field] = {f.name: f for f in AWS().fields()}
    good = {
        "account_id": ACCT,
        "role_arn": ROLE_ARN,
        "region": "us-gov-west-1",
        "identity_store_id": STORE_ID,
        "sso_instance_arn": "arn:aws-us-gov:sso:::instance/ins-0123456789abcdef",
        "context_entries": "aws:SourceIp=ip:10.0.0.1",
        "session_name": "hallpass-prod",
        "identity_center_region": "cn-north-1",
    }
    for k, v in good.items():
        validate = fields[k].validate
        assert validate is not None
        validate(v)
    bad = {
        "account_id": "12345678901",
        "role_arn": "arn:aws:iam::123456789012:user/x",
        "region": "eu-west",
        "identity_store_id": "d-123",
        "sso_instance_arn": "arn:aws:sso:::instance/x",
        "context_entries": "k",
        "session_name": "a",
        "identity_center_region": "EU-WEST-1",
    }
    for k, v in bad.items():
        validate = fields[k].validate
        assert validate is not None
        with pytest.raises(ValueError):
            validate(v)
    srv = itest.Server()
    servers.append(srv)
    srv.use_spec(aws_spec(), aws_spec_options())
    deps, _ = itest.deps(srv)
    base = {
        "account_id": ACCT,
        "role_arn": ROLE_ARN,
        "region": "eu-west-1",
        "identity_mode": "identity_center",
        "identity_center_role_arn": IC_ROLE_ARN,
        "identity_center_region": "eu-west-1",
        "identity_store_id": STORE_ID,
        "sso_instance_arn": INSTANCE_ARN,
    }

    def attempt(over: dict[str, str] | None) -> None:
        v = dict(base)
        for k, val in (over or {}).items():
            if val == "":
                v.pop(k, None)
            else:
                v[k] = val
        AWS().new(background(), itest.settings("x", "aws", v, {"credential": static_cred()}), deps)

    attempt(None)
    for name, over in {
        "role in other account": {"role_arn": IC_ROLE_ARN},
        "role in other partition": {"role_arn": "arn:aws-us-gov:iam::123456789012:role/x"},
        "no ic role": {"identity_center_role_arn": ""},
        "no ic region": {"identity_center_region": ""},
        "no store": {"identity_store_id": ""},
        "no instance": {"sso_instance_arn": ""},
        "no map file": {"identity_mode": "static_map"},
        "bad context": {"context_entries": "x"},
    }.items():
        with pytest.raises(ValueError):
            attempt(over)
            pytest.fail(f"{name}: new accepted")
    attempt({"identity_mode": "iam_user", "identity_center_role_arn": "", "identity_center_region": "", "identity_store_id": "", "sso_instance_arn": ""})
    with pytest.raises(ValueError):
        AWS().new(background(), itest.settings("x", "aws", base, None), deps)


def test_failures(setup: Setup) -> None:
    e = setup()
    itest.expect_code(check(e, dana, "s3.read", BUCKET_KEY), Code.ALLOWED)
    itest.failure_cases(e.srv, lambda: check(e, dana, "s3.read", BUCKET_KEY))
    # Fresh connection: the failure hits AssumeRole itself.
    fresh = setup()
    itest.failure_cases(fresh.srv, lambda: check(fresh, dana, "s3.read", BUCKET_KEY))


@pytest.mark.parametrize(("fail", "code"), [("throttle", Code.UPSTREAM_RATE_LIMIT), ("denied", Code.CREDENTIAL_REJECTED)])
def test_aws_error_bodies(setup: Setup, fail: str, code: Code) -> None:
    # On a fresh connection the error comes from AssumeRole (XML).
    e = setup()
    with e.f.mu:
        e.f.fail = fail
    itest.expect_code(check(e, dana, "s3.read", BUCKET_KEY), code)
    # With credentials in hand the error comes from Identity Store (JSON).
    e2 = setup()
    assert e2.c.ic_creds is not None
    e2.c.ic_creds.credentials(background())
    with e2.f.mu:
        e2.f.fail = fail
    itest.expect_code(check(e2, dana, "s3.read", BUCKET_KEY), code)
    # And from IAM (XML) once the identity is cached.
    e3 = setup()
    itest.expect_code(check(e3, dana, "s3.read", BUCKET_KEY), Code.ALLOWED)
    with e3.f.mu:
        e3.f.fail = fail
    itest.expect_code(check(e3, dana, "s3.read", BUCKET_KEY), code)


def test_probe(setup: Setup) -> None:
    e = setup()
    r = e.conn.probe(background())
    assert "assumed-role/hallpass-read" in r.summary and "5 AWSReservedSSO roles" in r.summary, r.summary
    assert len(r.warnings) == 1 and "discloses" in r.warnings[0], f"warnings {r.warnings}"
    with e.f.mu:
        e.f.instances = [{"InstanceArn": INSTANCE_ARN, "IdentityStoreId": "d-0000000000"}]
    r = e.conn.probe(background())
    assert len(r.warnings) == 2 and "d-0000000000" in r.warnings[0], f"warnings {r.warnings}"
    with e.f.mu:
        e.f.instances = None
    r = e.conn.probe(background())
    assert len(r.warnings) == 2 and "did not list" in r.warnings[0], f"warnings {r.warnings}"
    with e.f.mu:
        e.f.fail = "denied"
    with pytest.raises(HallpassError):
        e.conn.probe(background())
    # iam_user mode skips the Identity Center check.
    u = setup({"identity_mode": "iam_user"})
    r = u.conn.probe(background())
    assert len(r.warnings) == 1, r


@pytest.mark.parametrize(
    ("a", "b", "want"),
    [
        ("allowed", "allowed", "allowed"),
        ("allowed", "implicitDeny", "implicitDeny"),
        ("implicitDeny", "allowed", "implicitDeny"),
        ("allowed", "explicitDeny", "explicitDeny"),
        ("explicitDeny", "allowed", "explicitDeny"),
        ("implicitDeny", "explicitDeny", "explicitDeny"),
        ("explicitDeny", "implicitDeny", "explicitDeny"),
        ("allowed", "bogus", "bogus"),
    ],
)
def test_more_restrictive(a: str, b: str, want: str) -> None:
    assert more_restrictive(a, b) == want, f"more_restrictive({a}, {b}) = {more_restrictive(a, b)}, want {want}"


def test_allowed_with_missing_context_is_unknown(setup: Setup) -> None:
    """An "allowed" evaluated with condition keys missing is not an allow:
    IAM skipped every statement conditioned on those keys, including denies."""
    e = setup()
    itest.expect_code(check(e, dana, "s3.read", BUCKET_KEY), Code.ALLOWED)
    with e.f.mu:
        e.f.missing = ["aws:MultiFactorAuthPresent"]
    # Resource-specific result carries the missing keys.
    d = check(e, dana, "s3.read", BUCKET_KEY)
    itest.expect_code(d, Code.UNSUPPORTED)
    assert "aws:MultiFactorAuthPresent" in d.text and "context_entries" in d.text, d.text
    # Action-level result carries them.
    with e.f.mu:
        e.f.eval_only = True
    d = check(e, dana, "s3.read", BUCKET_KEY)
    itest.expect_code(d, Code.UNSUPPORTED)
    assert "aws:MultiFactorAuthPresent" in d.text, d.text
    # Every principal is still simulated: an allow without missing keys on
    # a later principal settles the check.
    e.srv.reset()
    with e.f.mu:
        e.f.eval_only, e.f.missing = False, []
    itest.expect_code(check(e, dana, "s3.write", BUCKET_KEY), Code.ALLOWED)
    n = sum(1 for c in e.srv.calls() if b"Action=SimulatePrincipalPolicy" in c.body)
    assert n == 2, f"SimulatePrincipalPolicy calls = {n}, want 2"
    # Once the keys are supplied the allow stands (the fake reports no
    # missing keys then).
    itest.expect_code(check(e, dana, "s3.read", BUCKET_KEY), Code.ALLOWED)


def test_no_permission_set_honours_implicit_deny_as(setup: Setup) -> None:
    """A user with no permission set in the account is an implicit deny, so
    implicit_deny_as decides between deny and unknown."""
    e = setup()
    d = check(e, bob, "s3.read", BUCKET_KEY)
    itest.expect_code(d, Code.DENIED)
    assert "no permission set assigned in account " + ACCT in d.text, d.text
    u = setup({"implicit_deny_as": "unknown"})
    d = check(u, bob, "s3.read", BUCKET_KEY)
    itest.expect_code(d, Code.UNSUPPORTED)
    assert "no permission set assigned in account " + ACCT in d.text, d.text


def test_assignment_rows_require_exact_account(setup: Setup) -> None:
    """An assignment row counts only when its AccountId is exactly this
    account: rows for another account or with no AccountId are skipped."""
    for row_acct in ("", "210987654321"):
        e = setup()
        with e.f.mu:
            e.f.assignments["u-bob"] = [PS_RO]
            e.f.row_account = {PS_RO: row_acct}
        ident = e.conn.resolve_identity(background(), bob)
        nat = ident.native
        assert isinstance(nat, Native)
        assert not nat.permission_sets and not nat.principals, (
            f"AccountId {row_acct!r}: permission sets {nat.permission_sets} principals {nat.principals}, want none"
        )
        d = check(e, bob, "s3.read", BUCKET_KEY)
        itest.expect_code(d, Code.DENIED)
        assert "no permission set assigned" in d.text, d.text
    # The exact account still counts.
    e = setup()
    with e.f.mu:
        e.f.assignments["u-bob"] = [PS_RO]
        e.f.row_account = {PS_RO: ACCT}
    itest.expect_code(check(e, bob, "s3.read", BUCKET_KEY), Code.ALLOWED)


def test_simulate_xml_decoding() -> None:
    body = b"""<SimulatePrincipalPolicyResponse><SimulatePrincipalPolicyResult><EvaluationResults><member>
<EvalActionName>s3:GetObject</EvalActionName><EvalDecision>implicitDeny</EvalDecision><EvalResourceName>arn:aws:s3:::b/k</EvalResourceName>
<MissingContextValues><member>aws:SourceIp</member></MissingContextValues>
<OrganizationsDecisionDetail><AllowedByOrganizations>false</AllowedByOrganizations></OrganizationsDecisionDetail>
<PermissionsBoundaryDecisionDetail><AllowedByPermissionsBoundary>false</AllowedByPermissionsBoundary></PermissionsBoundaryDecisionDetail>
<ResourceSpecificResults><member><EvalResourceName>arn:aws:s3:::b/k</EvalResourceName><EvalResourceDecision>explicitDeny</EvalResourceDecision>
<MissingContextValues><member>aws:MultiFactorAuthPresent</member></MissingContextValues></member></ResourceSpecificResults>
</member></EvaluationResults><IsTruncated>true</IsTruncated><Marker>abc</Marker></SimulatePrincipalPolicyResult></SimulatePrincipalPolicyResponse>"""
    results, truncated, marker = _decode_simulate(xmlutil.parse(body))
    assert truncated and marker == "abc" and len(results) == 1, (results, truncated, marker)
    ev = results[0]
    assert (
        ev.decision == "implicitDeny"
        and ev.missing[0] == "aws:SourceIp"
        and ev.org_allowed is not None
        and not ev.org_allowed
        and ev.boundary_allowed is not None
        and not ev.boundary_allowed
    ), ev
    assert len(ev.resources) == 1 and ev.resources[0].decision == "explicitDeny" and ev.resources[0].missing[0] == "aws:MultiFactorAuthPresent", ev.resources


# Allow/deny tests per alias action (coverage gate).


def alias_allow(setup: Setup, name: str) -> None:
    e = setup()
    act = ALIASES[name].action
    with e.f.mu:
        e.f.policy[ROLE_RO + "|" + act + "|*"] = "allowed"
    d = check(e, dana, name, "all")
    itest.expect_code(d, Code.ALLOWED)
    assert fget(last_form(e, "SimulatePrincipalPolicy"), "ActionNames.member.1") == act, f"{name} did not simulate {act}"


def alias_deny(setup: Setup, name: str) -> None:
    e = setup()
    act = ALIASES[name].action
    with e.f.mu:
        e.f.policy[ROLE_RO + "|" + act + "|*"] = "explicitDeny"
        e.f.policy[ROLE_DEV + "|" + act + "|*"] = "explicitDeny"
    itest.expect_code(check(e, dana, name, "all"), Code.DENIED)


def test_action_s3_read_allow(setup: Setup) -> None:
    alias_allow(setup, "s3.read")


def test_action_s3_read_deny(setup: Setup) -> None:
    alias_deny(setup, "s3.read")


def test_action_s3_write_allow(setup: Setup) -> None:
    alias_allow(setup, "s3.write")


def test_action_s3_write_deny(setup: Setup) -> None:
    alias_deny(setup, "s3.write")


def test_action_s3_list_allow(setup: Setup) -> None:
    alias_allow(setup, "s3.list")


def test_action_s3_list_deny(setup: Setup) -> None:
    alias_deny(setup, "s3.list")


def test_action_ec2_stop_allow(setup: Setup) -> None:
    alias_allow(setup, "ec2.stop")


def test_action_ec2_stop_deny(setup: Setup) -> None:
    alias_deny(setup, "ec2.stop")


def test_action_ec2_start_allow(setup: Setup) -> None:
    alias_allow(setup, "ec2.start")


def test_action_ec2_start_deny(setup: Setup) -> None:
    alias_deny(setup, "ec2.start")


def test_action_ec2_terminate_allow(setup: Setup) -> None:
    alias_allow(setup, "ec2.terminate")


def test_action_ec2_terminate_deny(setup: Setup) -> None:
    alias_deny(setup, "ec2.terminate")


def test_action_lambda_invoke_allow(setup: Setup) -> None:
    alias_allow(setup, "lambda.invoke")


def test_action_lambda_invoke_deny(setup: Setup) -> None:
    alias_deny(setup, "lambda.invoke")


def test_action_iam_passrole_allow(setup: Setup) -> None:
    alias_allow(setup, "iam.passrole")


def test_action_iam_passrole_deny(setup: Setup) -> None:
    alias_deny(setup, "iam.passrole")


def test_action_secretsmanager_read_allow(setup: Setup) -> None:
    alias_allow(setup, "secretsmanager.read")


def test_action_secretsmanager_read_deny(setup: Setup) -> None:
    alias_deny(setup, "secretsmanager.read")


def test_action_ssm_session_allow(setup: Setup) -> None:
    alias_allow(setup, "ssm.session")


def test_action_ssm_session_deny(setup: Setup) -> None:
    alias_deny(setup, "ssm.session")


def test_action_sts_assume_allow(setup: Setup) -> None:
    alias_allow(setup, "sts.assume")


def test_action_sts_assume_deny(setup: Setup) -> None:
    alias_deny(setup, "sts.assume")


def test_action_rds_delete_allow(setup: Setup) -> None:
    alias_allow(setup, "rds.delete")


def test_action_rds_delete_deny(setup: Setup) -> None:
    alias_deny(setup, "rds.delete")


def test_action_eks_describe_allow(setup: Setup) -> None:
    alias_allow(setup, "eks.describe")


def test_action_eks_describe_deny(setup: Setup) -> None:
    alias_deny(setup, "eks.describe")


def test_aliases_listed() -> None:
    for a in ALIAS_LIST:
        assert find_action(AWS(), a.name) is not None, f"alias {a.name} not listed"
        assert RAW_ACTION_RE.fullmatch(a.action), f"alias {a.name} expands to {a.action!r}, not an IAM action"
