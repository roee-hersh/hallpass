"""Port of internal/integrations/googlecloud/googlecloud_test.go."""

from __future__ import annotations

import base64
import functools
import json
import threading
import time
from collections.abc import Iterator
from typing import Any

import pytest

from hallpass.authx.jwt import RS256, decode_jwt_claims, verify
from hallpass.core.catalog import parse_resource
from hallpass.core.context import Context, background
from hallpass.core.decision import Code, Decision, to_decision, user_not_found
from hallpass.core.integration import CheckRequest, Connection, Identity, ProbeResult, User, find_action, validate_fields
from hallpass.core.secret import Secret
from hallpass.core.secret import literal as secret_literal
from hallpass.integrations.googlecloud import GoogleCloud
from hallpass.integrations.googlecloud.actions import ACTION_LIST, RAW_PATTERN, SET_IAM_POLICY_PERMISSIONS, full_resource_name
from hallpass.integrations.googlecloud.googlecloud import (
    MODE_KEYLESS,
    SCOPE_CLOUD_PLATFORM,
    STATE_CAN_ACCESS,
    STATE_CANNOT_ACCESS,
    STATE_UNKNOWN_CONDITIONAL,
    STATE_UNKNOWN_INFO,
)
from tests import harness as itest
from tests.harness.spec import SpecOptions, spec_from_env

SA_EMAIL = "hallpass@proj.iam.gserviceaccount.com"
PROJECT_RN = "//cloudresourcemanager.googleapis.com/projects/acme-prod"

dana = User(email="dana@example.com")
bob = User(email="bob@example.com")

# The allow and deny states of the v3 response, as the fake emits them.
ALLOW_GRANTED = "ALLOW_ACCESS_STATE_GRANTED"
ALLOW_NOT_GRANTED = "ALLOW_ACCESS_STATE_NOT_GRANTED"
ALLOW_UNKNOWN_CON = "ALLOW_ACCESS_STATE_UNKNOWN_CONDITIONAL"
ALLOW_UNKNOWN_INF = "ALLOW_ACCESS_STATE_UNKNOWN_INFO"
DENY_NOT_DENIED = "DENY_ACCESS_STATE_NOT_DENIED"
DENY_UNKNOWN_INF = "DENY_ACCESS_STATE_UNKNOWN_INFO"
DENY_DENIED = "DENY_ACCESS_STATE_DENIED"

# (overall, allow, deny): the fake's response to one question.
Answer = tuple[str, str, str]
GRANT: Answer = (STATE_CAN_ACCESS, ALLOW_GRANTED, DENY_NOT_DENIED)
NOGRANT: Answer = (STATE_CANNOT_ACCESS, ALLOW_NOT_GRANTED, DENY_NOT_DENIED)

# One resource per type, and sample() its full resource name.
SAMPLES = {
    "project": "project:acme-prod",
    "folder": "folder:123456789",
    "organization": "organization:987654321",
    "bucket": "bucket:acme-data",
    "object": "object:acme-data/reports/2026/q1.csv",
    "dataset": "dataset:acme-prod/analytics",
    "table": "table:acme-prod/analytics/events",
    "secret": "secret:acme-prod/db-password",
    "serviceaccount": "serviceaccount:deployer@acme-prod.iam.gserviceaccount.com",
    "instance": "instance:acme-prod/europe-west1-b/web-1",
    "service": "service:acme-prod/europe-west1/api",
    "cluster": "cluster:acme-prod/europe-west1/main",
    "name": "name://pubsub.googleapis.com/projects/acme-prod/topics/events",
}


def sample(typ: str) -> str:
    return full_resource_name(parse_resource(SAMPLES[typ]))


@functools.cache
def signing_key() -> Any:
    """Generated once per module."""
    from cryptography.hazmat.primitives.asymmetric import rsa

    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def api_err(w: itest.ResponseWriter, status: int, reason: str) -> None:
    """A Google error body the way the real API writes it: a long message
    first, then status and details, so the reason sits well past the
    256-byte snippet httpx keeps and can only be read from the whole body."""
    w.header().set("Content-Type", "application/json")
    w.write_header(status)
    msg = (
        itest.CANARY
        + " Quota exceeded for quota metric 'Troubleshoot requests' and limit 'Troubleshoot requests per minute' of service"
        + " 'policytroubleshooter.googleapis.com' for consumer 'project_number:123456789012'. "
        + "padding " * 20
    )
    details = "[]"
    if reason != "":
        details = f'[{{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"{reason}","domain":"googleapis.com"}}]'
    w.write(f'{{"error":{{"code":{status},"message":"{msg}","status":"PERMISSION_DENIED","details":{details}}}}}')


class FakeTroubleshooter:
    """An in-memory token endpoint, metadata server and Policy Troubleshooter."""

    def __init__(self) -> None:
        self.key = signing_key()
        self.kid = itest.CANARY + "kid"
        self.mu = threading.Lock()
        self.errors: list[str] = []
        self.tokens: dict[str, bool] = {}  # minted access tokens
        self.minted = 0
        self.expire401 = 0  # next n API calls answer 401
        self.meta_calls = 0
        self.answers: dict[tuple[str, str, str], Answer] = {}
        # When non-zero, the troubleshooter answers that HTTP status with reason.
        self.status = 0
        self.reason = ""
        # The X-Goog-User-Project every call must carry ("" for none).
        self.want_quota = ""
        # When set, returned verbatim with status 200.
        self.raw_body = ""
        # dana holds everything on acme-prod and its resources, bob nothing.
        for a in ACTION_LIST:
            for typ in a.types:
                p = SET_IAM_POLICY_PERMISSIONS[typ] if a.name == "iam.set" else a.permission
                self.answers[("dana@example.com", p, sample(typ))] = GRANT
                self.answers[("bob@example.com", p, sample(typ))] = NOGRANT
        self.answers[("dana@example.com", "storage.objects.delete", PROJECT_RN)] = GRANT
        self.answers[("dana@example.com", "compute.instances.setMetadata", PROJECT_RN)] = GRANT
        self.answers[("dana@example.com", "iam.googleapis.com/roles.create", PROJECT_RN)] = GRANT
        # A deny policy takes dana's bucket deletion away.
        self.answers[("dana@example.com", "storage.buckets.delete", "//storage.googleapis.com/projects/_/buckets/denied")] = (
            STATE_CANNOT_ACCESS,
            ALLOW_GRANTED,
            DENY_DENIED,
        )
        # A conditional binding, and a policy hallpass cannot read.
        self.answers[("dana@example.com", "storage.objects.get", "//storage.googleapis.com/projects/_/buckets/conditional")] = (
            STATE_UNKNOWN_CONDITIONAL,
            ALLOW_UNKNOWN_CON,
            DENY_NOT_DENIED,
        )
        self.answers[("dana@example.com", "storage.objects.get", "//storage.googleapis.com/projects/_/buckets/hidden")] = (
            STATE_UNKNOWN_INFO,
            ALLOW_UNKNOWN_INF,
            DENY_UNKNOWN_INF,
        )
        # The probe: the service account may get the scope project.
        self.answers[(SA_EMAIL, "resourcemanager.projects.get", PROJECT_RN)] = GRANT

    def token_url(self, srv: itest.Server) -> str:
        return srv.url + "/token"

    def token(self, srv: itest.Server) -> itest.Handler:
        """The OAuth token endpoint: it verifies the JWT bearer assertion."""

        def h(w: itest.ResponseWriter, r: itest.Request) -> None:
            form = r.form()

            def fv(k: str) -> str:
                return (form.get(k) or [""])[0]

            with self.mu:

                def fail(code: str) -> None:
                    w.header().set("Content-Type", "application/json")
                    w.write_header(400)
                    w.write('{"error":"' + code + '","error_description":"' + itest.CANARY + 'desc"}')

                if fv("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer":
                    fail("unsupported_grant_type")
                    return
                a = fv("assertion")
                parts = a.split(".")
                if len(parts) != 3:
                    fail("invalid_request")
                    return
                try:
                    hdr = json.loads(_b64url_decode(parts[0]))
                except ValueError:
                    hdr = {}
                if hdr.get("alg") != "RS256" or hdr.get("typ") != "JWT" or hdr.get("kid") != self.kid:
                    self.errors.append(f"assertion header {hdr}")
                    fail("invalid_request")
                    return
                try:
                    verify(self.key.public_key(), RS256, (parts[0] + "." + parts[1]).encode(), _b64url_decode(parts[2]))
                except ValueError as e:
                    self.errors.append(f"assertion signature: {e}")
                    fail("invalid_grant")
                    return
                cl = decode_jwt_claims(a)
                now = int(time.time())
                if (
                    cl.get("iss") != SA_EMAIL
                    or cl.get("aud") != self.token_url(srv)
                    or cl.get("sub", "") != ""
                    or cl.get("scope") != SCOPE_CLOUD_PLATFORM
                    or cl.get("iat", 0) > now + 5
                    or cl.get("exp") != cl.get("iat", 0) + 3600
                ):
                    self.errors.append(f"assertion claims {cl}")
                    fail("invalid_grant")
                    return
                self.minted += 1
                tok = f"{itest.CANARY}token{self.minted}"
                self.tokens[tok] = True
                w.header().set("Content-Type", "application/json")
                w.write(json.dumps({"access_token": tok, "expires_in": 3599, "token_type": "Bearer"}) + "\n")

        return h

    def metadata(self, w: itest.ResponseWriter, r: itest.Request) -> None:
        """The GCE metadata server."""
        with self.mu:
            if r.header.get("Metadata-Flavor") != "Google":
                w.write_header(403)
                return
            if r.path == "/computeMetadata/v1/instance/service-accounts/default/token":
                self.meta_calls += 1
                tok = f"{itest.CANARY}meta{self.meta_calls}"
                self.tokens[tok] = True
                w.header().set("Content-Type", "application/json")
                w.write(json.dumps({"access_token": tok, "expires_in": 3599, "token_type": "Bearer"}) + "\n")
            elif r.path == "/computeMetadata/v1/instance/service-accounts/default/email":
                w.write(SA_EMAIL)
            else:
                w.write_header(404)

    def troubleshoot(self, w: itest.ResponseWriter, r: itest.Request) -> None:
        """POST /v3/iam:troubleshoot."""
        with self.mu:
            if self.expire401 > 0:
                self.expire401 -= 1
                api_err(w, 401, "ACCESS_TOKEN_EXPIRED")
                return
            if not self.tokens.get(r.header.get("Authorization").removeprefix("Bearer ")):
                api_err(w, 401, "ACCESS_TOKEN_TYPE_UNSUPPORTED")
                return
            got = r.header.get("X-Goog-User-Project")
            if got != self.want_quota:
                self.errors.append(f"X-Goog-User-Project = {got!r}, want {self.want_quota!r}")
            if r.header.get("Content-Type") != "application/json":
                self.errors.append(f"content type {r.header.get('Content-Type')!r}")
            if self.status != 0:
                api_err(w, self.status, self.reason)
                return
            try:
                tp = json.loads(r.body).get("accessTuple") or {}
            except (ValueError, AttributeError):
                api_err(w, 400, "INVALID_ARGUMENT")
                return
            principal, permission, resource = tp.get("principal", ""), tp.get("permission", ""), tp.get("fullResourceName", "")
            if principal == "" or permission == "" or not resource.startswith("//"):
                self.errors.append(f"bad access tuple {tp}")
                api_err(w, 400, "INVALID_ARGUMENT")
                return
            w.header().set("Content-Type", "application/json")
            if self.raw_body != "":
                w.write(self.raw_body)
                return
            overall, allow, deny = self.answers.get((principal, permission, resource), NOGRANT)
            w.write(
                json.dumps(
                    {
                        "overallAccessState": overall,
                        "accessTuple": {
                            "principal": principal,
                            "permission": permission,
                            "fullResourceName": resource,
                            "permissionFqdn": itest.CANARY + "fqdn",
                        },
                        "allowPolicyExplanation": {
                            "allowAccessState": allow,
                            "relevance": "HEURISTIC_RELEVANCE_HIGH",
                            "explainedPolicies": [
                                {"fullResourceName": resource, "policy": {"bindings": [{"role": "roles/" + itest.CANARY, "members": ["user:" + principal]}]}}
                            ],
                        },
                        "denyPolicyExplanation": {"denyAccessState": deny, "permissionDeniable": True, "relevance": "HEURISTIC_RELEVANCE_NORMAL"},
                    }
                )
                + "\n"
            )

    def key_json(self, srv: itest.Server) -> Secret:
        from cryptography.hazmat.primitives import serialization

        pem_key = self.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
        return secret_literal(
            json.dumps(
                {
                    "type": "service_account",
                    "project_id": "proj",
                    "private_key_id": self.kid,
                    "private_key": pem_key,
                    "client_email": SA_EMAIL,
                    "client_id": "123",
                    "token_uri": self.token_url(srv),
                }
            )
        )


def spec_options() -> SpecOptions:
    return SpecOptions(ignore_paths=(r"^/token$", "/computeMetadata/"))


class StubWorkspace(Connection):
    """Stands in for a googleworkspace connection."""

    def __init__(self, users: dict[str, Identity]) -> None:
        self.users = users

    def resolve_identity(self, ctx: Context, u: User) -> Identity:
        id = self.users.get(u.email.lower())
        if id is None:
            raise user_not_found(f"no Workspace account for {u.email}")
        return id

    def check(self, ctx: Context, r: CheckRequest) -> Decision:
        return Decision()

    def probe(self, ctx: Context) -> ProbeResult:
        return ProbeResult()


def _connection(id: str) -> Connection:
    if id != "gws":
        raise ValueError(f'no connection "{id}"')
    return StubWorkspace(
        {
            "dana@example.com": Identity(id="dana@example.com", attrs={"suspended": "false", "archived": "false"}),
            "d.alias@example.com": Identity(id="dana@example.com", attrs={"suspended": "false", "archived": "false"}),
            "sus@example.com": Identity(id="sus@example.com", attrs={"suspended": "true", "archived": "false"}),
            "nostatus@example.com": Identity(id="nostatus@example.com"),
        }
    )


class Env:
    """Servers and fakes made by one test, checked when it ends."""

    def __init__(self) -> None:
        self.servers: list[itest.Server] = []
        self.fakes: list[FakeTroubleshooter] = []

    def server(self, spec: bool = True) -> itest.Server:
        srv = itest.Server()
        if spec:
            srv.use_spec(spec_from_env("google-policytroubleshooter"), spec_options())
        self.servers.append(srv)
        return srv

    def setup(self, values: dict[str, str] | None = None) -> tuple[itest.Server, FakeTroubleshooter, Connection]:
        srv = self.server()
        f = FakeTroubleshooter()
        self.fakes.append(f)
        srv.handle("POST", "/token", f.token(srv))
        srv.handle("POST", "/v3/iam:troubleshoot", f.troubleshoot)
        srv.handle("GET", "/computeMetadata/*", f.metadata)
        deps, _ = itest.deps(srv, connection=_connection)
        v = {"scope": "project:acme-prod", "token_url": f.token_url(srv), "api_url": srv.url, "metadata_url": srv.url}
        v.update(values or {})
        f.want_quota = v.get("quota_project", "")
        secrets: dict[str, Secret] = {}
        if v.get("auth_mode") != MODE_KEYLESS:
            secrets["credential"] = f.key_json(srv)
        s = itest.settings("gcp", "googlecloud", v, secrets)
        c = GoogleCloud().new(background(), s, deps)
        return srv, f, c

    def close(self) -> None:
        for srv in self.servers:
            srv.close()
        for srv in self.servers:
            assert not srv.spec_errors, "requests did not match the API description:\n" + "\n".join(srv.spec_errors)
        for f in self.fakes:
            assert not f.errors, "\n".join(f.errors)


@pytest.fixture
def env() -> Iterator[Env]:
    e = Env()
    yield e
    e.close()


def check(c: Connection, u: User, action: str, resource: str) -> Decision:
    return itest.check(c, GoogleCloud(), u, action, resource)


def last_tuple(srv: itest.Server) -> dict[str, Any]:
    return srv.last_call().json()["accessTuple"]


# -- the action table -------------------------------------------------------


def allow_deny(env: Env, action: str, resource: str, permission: str, want: bool) -> None:
    """Run one action on the resource for dana (allowed) and bob (not
    granted) and check the permission that reached the fake."""
    srv, _, c = env.setup()
    u, code = (dana, Code.ALLOWED) if want else (bob, Code.DENIED)
    d = check(c, u, action, resource)
    itest.expect_code(d, code)
    last = srv.last_call()
    assert last.path == "/v3/iam:troubleshoot", f"last call {last.method} {last.path}"
    tp = last.json()["accessTuple"]
    assert tp["permission"] == permission and tp["principal"] == u.email, f"sent {tp}, want permission {permission} for {u.email}"
    assert permission in d.text, f"text {d.text!r} does not name the permission"


def test_action_project_view_allow(env: Env) -> None:
    allow_deny(env, "project.view", SAMPLES["project"], "resourcemanager.projects.get", True)


def test_action_project_view_deny(env: Env) -> None:
    allow_deny(env, "project.view", SAMPLES["project"], "resourcemanager.projects.get", False)


def test_action_iam_set_allow(env: Env) -> None:
    allow_deny(env, "iam.set", SAMPLES["bucket"], "storage.buckets.setIamPolicy", True)


def test_action_iam_set_deny(env: Env) -> None:
    allow_deny(env, "iam.set", SAMPLES["project"], "resourcemanager.projects.setIamPolicy", False)


def test_action_storage_read_allow(env: Env) -> None:
    allow_deny(env, "storage.read", SAMPLES["object"], "storage.objects.get", True)


def test_action_storage_read_deny(env: Env) -> None:
    allow_deny(env, "storage.read", SAMPLES["bucket"], "storage.objects.get", False)


def test_action_storage_write_allow(env: Env) -> None:
    allow_deny(env, "storage.write", SAMPLES["bucket"], "storage.objects.create", True)


def test_action_storage_write_deny(env: Env) -> None:
    allow_deny(env, "storage.write", SAMPLES["object"], "storage.objects.create", False)


def test_action_storage_delete_allow(env: Env) -> None:
    allow_deny(env, "storage.delete", SAMPLES["object"], "storage.objects.delete", True)


def test_action_storage_delete_deny(env: Env) -> None:
    allow_deny(env, "storage.delete", SAMPLES["bucket"], "storage.objects.delete", False)


def test_action_storage_list_allow(env: Env) -> None:
    allow_deny(env, "storage.list", SAMPLES["bucket"], "storage.objects.list", True)


def test_action_storage_list_deny(env: Env) -> None:
    allow_deny(env, "storage.list", SAMPLES["bucket"], "storage.objects.list", False)


def test_action_bucket_delete_allow(env: Env) -> None:
    allow_deny(env, "bucket.delete", SAMPLES["bucket"], "storage.buckets.delete", True)


def test_action_bucket_delete_deny(env: Env) -> None:
    allow_deny(env, "bucket.delete", SAMPLES["bucket"], "storage.buckets.delete", False)


def test_action_bigquery_read_allow(env: Env) -> None:
    allow_deny(env, "bigquery.read", SAMPLES["table"], "bigquery.tables.getData", True)


def test_action_bigquery_read_deny(env: Env) -> None:
    allow_deny(env, "bigquery.read", SAMPLES["dataset"], "bigquery.tables.getData", False)


def test_action_bigquery_write_allow(env: Env) -> None:
    allow_deny(env, "bigquery.write", SAMPLES["dataset"], "bigquery.tables.updateData", True)


def test_action_bigquery_write_deny(env: Env) -> None:
    allow_deny(env, "bigquery.write", SAMPLES["table"], "bigquery.tables.updateData", False)


def test_action_bigquery_delete_allow(env: Env) -> None:
    allow_deny(env, "bigquery.delete", SAMPLES["table"], "bigquery.tables.delete", True)


def test_action_bigquery_delete_deny(env: Env) -> None:
    allow_deny(env, "bigquery.delete", SAMPLES["table"], "bigquery.tables.delete", False)


def test_action_secret_read_allow(env: Env) -> None:
    allow_deny(env, "secret.read", SAMPLES["secret"], "secretmanager.versions.access", True)


def test_action_secret_read_deny(env: Env) -> None:
    allow_deny(env, "secret.read", SAMPLES["secret"], "secretmanager.versions.access", False)


def test_action_serviceaccount_actas_allow(env: Env) -> None:
    allow_deny(env, "serviceaccount.actas", SAMPLES["serviceaccount"], "iam.serviceAccounts.actAs", True)


def test_action_serviceaccount_actas_deny(env: Env) -> None:
    allow_deny(env, "serviceaccount.actas", SAMPLES["serviceaccount"], "iam.serviceAccounts.actAs", False)


def test_action_compute_start_allow(env: Env) -> None:
    allow_deny(env, "compute.start", SAMPLES["instance"], "compute.instances.start", True)


def test_action_compute_start_deny(env: Env) -> None:
    allow_deny(env, "compute.start", SAMPLES["instance"], "compute.instances.start", False)


def test_action_compute_stop_allow(env: Env) -> None:
    allow_deny(env, "compute.stop", SAMPLES["instance"], "compute.instances.stop", True)


def test_action_compute_stop_deny(env: Env) -> None:
    allow_deny(env, "compute.stop", SAMPLES["instance"], "compute.instances.stop", False)


def test_action_compute_delete_allow(env: Env) -> None:
    allow_deny(env, "compute.delete", SAMPLES["instance"], "compute.instances.delete", True)


def test_action_compute_delete_deny(env: Env) -> None:
    allow_deny(env, "compute.delete", SAMPLES["instance"], "compute.instances.delete", False)


def test_action_run_deploy_allow(env: Env) -> None:
    allow_deny(env, "run.deploy", SAMPLES["service"], "run.services.update", True)


def test_action_run_deploy_deny(env: Env) -> None:
    allow_deny(env, "run.deploy", SAMPLES["service"], "run.services.update", False)


def test_action_gke_access_allow(env: Env) -> None:
    allow_deny(env, "gke.access", SAMPLES["cluster"], "container.clusters.get", True)


def test_action_gke_access_deny(env: Env) -> None:
    allow_deny(env, "gke.access", SAMPLES["cluster"], "container.clusters.get", False)


# -- resources and actions --------------------------------------------------


def test_full_resource_names(env: Env) -> None:
    want = {
        "project": PROJECT_RN,
        "folder": "//cloudresourcemanager.googleapis.com/folders/123456789",
        "organization": "//cloudresourcemanager.googleapis.com/organizations/987654321",
        "bucket": "//storage.googleapis.com/projects/_/buckets/acme-data",
        "object": "//storage.googleapis.com/projects/_/buckets/acme-data/objects/reports/2026/q1.csv",
        "dataset": "//bigquery.googleapis.com/projects/acme-prod/datasets/analytics",
        "table": "//bigquery.googleapis.com/projects/acme-prod/datasets/analytics/tables/events",
        "secret": "//secretmanager.googleapis.com/projects/acme-prod/secrets/db-password",
        "serviceaccount": "//iam.googleapis.com/projects/acme-prod/serviceAccounts/deployer@acme-prod.iam.gserviceaccount.com",
        "instance": "//compute.googleapis.com/projects/acme-prod/zones/europe-west1-b/instances/web-1",
        "service": "//run.googleapis.com/projects/acme-prod/locations/europe-west1/services/api",
        "cluster": "//container.googleapis.com/projects/acme-prod/locations/europe-west1/clusters/main",
        "name": "//pubsub.googleapis.com/projects/acme-prod/topics/events",
    }
    for typ, full in want.items():
        assert sample(typ) == full, f"{typ}: {sample(typ)}, want {full}"
    _, _, c = env.setup()
    for typ in SAMPLES:
        d = check(c, dana, "raw:storage.objects.delete", SAMPLES[typ])
        assert d.code in (Code.ALLOWED, Code.DENIED), f"raw on {typ}: {d.code} ({d.text})"


def test_project_numbers_and_object_names(env: Env) -> None:
    srv, f, c = env.setup()
    with f.mu:
        f.answers[("dana@example.com", "secretmanager.versions.access", "//secretmanager.googleapis.com/projects/123456789012/secrets/db-password")] = GRANT
        f.answers[("dana@example.com", "storage.objects.get", "//storage.googleapis.com/projects/_/buckets/acme-data/objects/reports/Q1 2026 (final).pdf")] = (
            GRANT
        )
    itest.expect_code(check(c, dana, "secret.read", "secret:123456789012/db-password"), Code.ALLOWED)
    itest.expect_code(check(c, dana, "project.view", "project:123456789012"), Code.DENIED)
    itest.expect_code(check(c, dana, "storage.read", "object:acme-data/reports/Q1 2026 (final).pdf"), Code.ALLOWED)
    got = last_tuple(srv)["fullResourceName"]
    assert got == "//storage.googleapis.com/projects/_/buckets/acme-data/objects/reports/Q1 2026 (final).pdf", f"object name changed: {got!r}"


def test_raw_actions(env: Env) -> None:
    srv, _, c = env.setup()
    itest.expect_code(check(c, dana, "raw:storage.objects.delete", "project:acme-prod"), Code.ALLOWED)
    itest.expect_code(check(c, dana, "raw:compute.instances.setMetadata", "project:acme-prod"), Code.ALLOWED)
    itest.expect_code(check(c, dana, "raw:iam.googleapis.com/roles.create", "project:acme-prod"), Code.ALLOWED)
    itest.expect_code(check(c, bob, "raw:storage.objects.delete", "project:acme-prod"), Code.DENIED)
    itest.expect_code(check(c, dana, "raw:storage.objects.delete", "name://storage.googleapis.com/projects/_/buckets/x"), Code.DENIED)
    n = len(srv.calls())
    for bad in ("raw:", "raw:storage", "raw:Storage.objects.get", "raw:storage.objects.get x", "raw:storage..get", "raw:a.b.c.d.e.f.g", "storage.objects.get"):
        assert GoogleCloud().match_action(bad) is None, f"{bad!r} matched"
    assert len(srv.calls()) == n, "a rejected action reached the upstream"


def test_rejects_bad_resources(env: Env) -> None:
    srv, _, c = env.setup()
    itest.expect_code(check(c, dana, "project.view", "project:acme-prod"), Code.ALLOWED)
    n = len(srv.calls())
    cases = [
        ("project.view", "project:Acme"),
        ("project.view", "project:ab"),
        ("project.view", "project:acme-prod?x=1"),
        ("project.view", "bucket:acme-data"),
        ("project.view", "user:dana@example.com"),
        ("iam.set", "object:acme-data/x"),
        ("iam.set", "name://storage.googleapis.com/projects/_/buckets/x"),
        ("storage.read", "instance:acme-prod/z/web-1"),
        ("storage.read", "bucket:AB"),
        ("storage.read", "object:acme-data"),
        ("storage.read", "object:acme-data/../etc"),
        ("storage.read", "object:acme-data/a/../etc"),
        ("storage.read", "object:acme-data/a/.."),
        ("storage.read", "object:acme-data/./a"),
        ("bigquery.read", "table:acme-prod/analytics"),
        ("bigquery.read", "dataset:acme-prod/a b"),
        ("secret.read", "secret:acme-prod/x/y"),
        ("serviceaccount.actas", "serviceaccount:123-compute@developer.gserviceaccount.com"),
        ("serviceaccount.actas", "serviceaccount:dana@example.com"),
        ("compute.stop", "instance:acme-prod/web-1"),
        ("compute.stop", "instance:acme-prod/europe-west1-b/Web_1"),
        ("run.deploy", "service:acme-prod/europe-west1/api/x"),
        ("gke.access", "cluster:acme-prod/europe-west1/"),
        ("storage.read", "name:https://storage.googleapis.com/x"),
        ("storage.read", "name://storage.googleapis.com/projects/../x"),
        ("storage.read", "name://evil.example.com/projects/x"),
        ("storage.read", "name://storage.googleapis.com/x y"),
        ("storage.read", "name://storage.googleapis.com/"),
        ("storage.read", "name://storage.googleapis.com/a/./b"),
    ]
    for action, resource in cases:
        d = check(c, dana, action, resource)
        assert d.code == Code.INVALID_REQUEST, f"{action} {resource}: {d.code} ({d.text}), want invalid_request"
    assert len(srv.calls()) == n, "a rejected resource reached the upstream"


# -- decisions --------------------------------------------------------------


def test_deny_policy(env: Env) -> None:
    _, _, c = env.setup()
    d = check(c, dana, "bucket.delete", "bucket:denied")
    itest.expect_code(d, Code.DENIED)
    assert "deny policy" in d.text, d.text
    d = check(c, bob, "bucket.delete", "bucket:acme-data")
    itest.expect_code(d, Code.DENIED)
    assert "no allow policy" in d.text, d.text


def test_unknown_states(env: Env) -> None:
    _, f, c = env.setup()
    d = check(c, dana, "storage.read", "bucket:conditional")
    itest.expect_code(d, Code.UNSUPPORTED)
    assert "condition" in d.text, d.text
    d = check(c, dana, "storage.read", "bucket:hidden")
    itest.expect_code(d, Code.RESOURCE_NOT_VISIBLE)
    assert "securityReviewer" in d.text, d.text
    with f.mu:
        f.raw_body = '{"overallAccessState":"OVERALL_ACCESS_STATE_UNSPECIFIED"}'
    itest.expect_code(check(c, dana, "storage.read", "bucket:acme-data"), Code.UPSTREAM_ERROR)
    with f.mu:
        f.raw_body = '{"overallAccessState":"' + itest.CANARY + '"}'
    itest.expect_code(check(c, dana, "storage.read", "bucket:acme-data"), Code.UPSTREAM_ERROR)
    with f.mu:
        f.raw_body = "not json"
    itest.expect_code(check(c, dana, "storage.read", "bucket:acme-data"), Code.UPSTREAM_ERROR)


def test_api_errors(env: Env) -> None:
    _, f, c = env.setup()

    def set_(status: int, reason: str) -> None:
        with f.mu:
            f.status, f.reason = status, reason

    set_(403, "SERVICE_DISABLED")
    itest.expect_code(check(c, dana, "project.view", "project:acme-prod"), Code.CREDENTIAL_REJECTED)
    set_(403, "")
    itest.expect_code(check(c, dana, "project.view", "project:acme-prod"), Code.CREDENTIAL_REJECTED)
    set_(403, "RATE_LIMIT_EXCEEDED")
    itest.expect_code(check(c, dana, "project.view", "project:acme-prod"), Code.UPSTREAM_RATE_LIMIT)
    set_(429, "")
    itest.expect_code(check(c, dana, "project.view", "project:acme-prod"), Code.UPSTREAM_RATE_LIMIT)
    set_(418, "")
    itest.expect_code(check(c, dana, "project.view", "project:acme-prod"), Code.UPSTREAM_ERROR)
    set_(400, "INVALID_ARGUMENT")
    itest.expect_code(check(c, dana, "project.view", "project:acme-prod"), Code.INVALID_REQUEST)
    set_(404, "NOT_FOUND")
    itest.expect_code(check(c, dana, "project.view", "project:acme-prod"), Code.RESOURCE_NOT_VISIBLE)
    set_(0, "")
    itest.expect_code(check(c, dana, "project.view", "project:acme-prod"), Code.ALLOWED)


def test_failures(env: Env) -> None:
    srv, _, c = env.setup()
    itest.expect_code(check(c, dana, "project.view", "project:acme-prod"), Code.ALLOWED)
    itest.failure_cases(srv, lambda: check(c, dana, "project.view", "project:acme-prod"))


def test_failures_at_token_endpoint(env: Env) -> None:
    srv, _, c = env.setup()
    itest.failure_cases(srv, lambda: check(c, dana, "project.view", "project:acme-prod"))


# -- authentication -----------------------------------------------------------


def test_token_cached_and_refreshed_on401(env: Env) -> None:
    srv, f, c = env.setup()
    itest.expect_code(check(c, dana, "project.view", "project:acme-prod"), Code.ALLOWED)
    itest.expect_code(check(c, bob, "project.view", "project:acme-prod"), Code.DENIED)
    with f.mu:
        assert f.minted == 1, f"minted {f.minted} tokens, want 1"
        f.expire401 = 1
    itest.expect_code(check(c, dana, "project.view", "project:acme-prod"), Code.ALLOWED)
    with f.mu:
        assert f.minted == 2, f"minted {f.minted} tokens after a 401, want 2"
        f.expire401 = 2
    itest.expect_code(check(c, dana, "project.view", "project:acme-prod"), Code.CREDENTIAL_REJECTED)
    for call in srv.calls():
        if call.path == "/v3/iam:troubleshoot":
            assert call.header.get("Authorization").startswith("Bearer " + itest.CANARY), (
                f"call without the minted bearer: {call.header.get('Authorization')!r}"
            )


def test_keyless(env: Env) -> None:
    srv, f, c = env.setup({"auth_mode": MODE_KEYLESS})
    itest.expect_code(check(c, dana, "project.view", "project:acme-prod"), Code.ALLOWED)
    itest.expect_code(check(c, bob, "project.view", "project:acme-prod"), Code.DENIED)
    with f.mu:
        assert f.meta_calls == 1 and f.minted == 0, f"metadata token fetched {f.meta_calls} times (want 1), key tokens {f.minted} (want 0)"
    r = c.probe(background())
    assert SA_EMAIL in r.summary, r.summary
    for call in srv.calls():
        if call.path.startswith("/computeMetadata/"):
            assert call.header.get("Metadata-Flavor") == "Google", "metadata call without Metadata-Flavor"


def test_quota_project(env: Env) -> None:
    _, _, c = env.setup({"quota_project": "acme-billing"})
    itest.expect_code(check(c, dana, "project.view", "project:acme-prod"), Code.ALLOWED)


def test_bad_key(env: Env) -> None:
    srv = env.server()
    deps, _ = itest.deps(srv)
    for cred in ("not json", '{"client_email":"x@y.z"}', '{"client_email":"x@y.z","private_key":"nope"}'):
        s = itest.settings(
            "gcp",
            "googlecloud",
            {"scope": "project:acme-prod", "token_url": srv.url + "/token", "api_url": srv.url},
            {"credential": secret_literal(itest.CANARY + cred)},
        )
        c = GoogleCloud().new(background(), s, deps)
        d = check(c, dana, "project.view", "project:acme-prod")
        itest.expect_code(d, Code.CREDENTIAL_REJECTED)
        itest.assert_no_canary(d.text)
    assert len(srv.calls()) == 0, "a bad key reached the network"


def test_new_rejects_bad_settings(env: Env) -> None:
    srv = env.server(spec=False)

    def no_connection(id: str) -> Connection:
        raise ValueError(f'no connection "{id}"')

    deps, _ = itest.deps(srv, connection=no_connection)
    cases: list[dict[str, str]] = [
        {},  # no scope
        {"scope": "bucket:x"},  # wrong type
        {"scope": "project:Acme"},  # bad id
        {"scope": "project:acme?x=1"},  # query
        {"scope": "project:acme-prod", "auth_mode": "magic"},
        {"scope": "project:acme-prod", "quota_project": "Bad Project"},
        {"scope": "project:acme-prod", "googleworkspace_connection": "nope"},
    ]
    for v in cases:
        s = itest.settings("gcp", "googlecloud", v, {"credential": secret_literal("{}")})
        with pytest.raises(Exception):  # noqa: B017 - Go only checks err != nil
            GoogleCloud().new(background(), s, deps)
    s = itest.settings("gcp", "googlecloud", {"scope": "project:acme-prod"})
    with pytest.raises(Exception):  # noqa: B017
        GoogleCloud().new(background(), s, deps)
    validate_fields(GoogleCloud().fields())
    for f in GoogleCloud().fields():
        if f.validate is None:
            continue
        f.validate("")  # no field rejects the empty value


# -- identity -----------------------------------------------------------------


def test_identity_without_workspace(env: Env) -> None:
    srv, _, c = env.setup()
    # Any address is passed through; the troubleshooter answers for it.
    d = check(c, User(email=" Nobody@Example.com "), "project.view", "project:acme-prod")
    itest.expect_code(d, Code.DENIED)
    assert last_tuple(srv)["principal"] == "nobody@example.com", f"principal {last_tuple(srv)['principal']!r}"
    itest.expect_code(check(c, User(email="not an email"), "project.view", "project:acme-prod"), Code.INVALID_REQUEST)


def test_identity_with_workspace(env: Env) -> None:
    srv, _, c = env.setup({"googleworkspace_connection": "gws"})
    itest.expect_code(check(c, dana, "project.view", "project:acme-prod"), Code.ALLOWED)
    # An alias resolves to the primary address, which is the principal.
    d = check(c, User(email="d.alias@example.com"), "project.view", "project:acme-prod")
    itest.expect_code(d, Code.ALLOWED)
    assert last_tuple(srv)["principal"] == "dana@example.com", f"principal {last_tuple(srv)['principal']!r}, want the primary address"
    n = len(srv.calls())
    itest.expect_code(check(c, bob, "project.view", "project:acme-prod"), Code.USER_NOT_FOUND)
    d = check(c, User(email="sus@example.com"), "project.view", "project:acme-prod")
    itest.expect_code(d, Code.DENIED)
    assert "suspended" in d.text, d.text
    itest.expect_code(check(c, User(email="nostatus@example.com"), "project.view", "project:acme-prod"), Code.UNSUPPORTED)
    assert len(srv.calls()) == n, "an unknown, suspended or status-less user reached the troubleshooter"


# -- probe --------------------------------------------------------------------


def test_probe(env: Env) -> None:
    srv, f, c = env.setup()
    r = c.probe(background())
    assert SA_EMAIL in r.summary and "project:acme-prod" in r.summary and STATE_CAN_ACCESS in r.summary, r.summary
    joined = "\n".join(r.warnings)
    assert "securityReviewer" not in joined and "googleworkspace_connection" in joined and "discloses" in joined, f"warnings: {joined!r}"
    tp = last_tuple(srv)
    assert tp["principal"] == SA_EMAIL and tp["permission"] == "resourcemanager.projects.get" and tp["fullResourceName"] == PROJECT_RN, f"probe asked {tp}"

    # The role is missing under the scope.
    with f.mu:
        f.answers[(SA_EMAIL, "resourcemanager.projects.get", PROJECT_RN)] = (STATE_UNKNOWN_INFO, ALLOW_UNKNOWN_INF, DENY_UNKNOWN_INF)
    r = c.probe(background())
    assert "securityReviewer" in "\n".join(r.warnings), f"warnings: {r.warnings!r}"

    # The API is disabled.
    with f.mu:
        f.status, f.reason = 403, "SERVICE_DISABLED"
    with pytest.raises(Exception) as ei:
        c.probe(background())
    itest.assert_no_canary(str(ei.value))


def test_probe_reports_key_errors(env: Env) -> None:
    srv = env.server(spec=False)
    deps, _ = itest.deps(srv)
    s = itest.settings(
        "gcp",
        "googlecloud",
        {"scope": "project:acme-prod", "token_url": srv.url + "/token", "api_url": srv.url},
        {"credential": secret_literal('{"client_email":"x@y.z","private_key":"' + itest.CANARY + '"}')},
    )
    c = GoogleCloud().new(background(), s, deps)
    with pytest.raises(Exception) as ei:
        c.probe(background())
    assert "PEM RSA key" in str(ei.value), f"probe error {ei.value}, want the key parsing cause"
    itest.assert_no_canary(to_decision(ei.value).text)


def test_probe_scopes(env: Env) -> None:
    for scope, permission, full in (
        ("folder:123456789", "resourcemanager.folders.get", "//cloudresourcemanager.googleapis.com/folders/123456789"),
        ("organization:987654321", "resourcemanager.organizations.get", "//cloudresourcemanager.googleapis.com/organizations/987654321"),
    ):
        srv, f, c = env.setup({"scope": scope})
        with f.mu:
            f.answers[(SA_EMAIL, permission, full)] = NOGRANT
        r = c.probe(background())
        assert STATE_CANNOT_ACCESS in r.summary, r.summary
        tp = last_tuple(srv)
        assert tp["permission"] == permission and tp["fullResourceName"] == full, f"probe asked {tp}"


def test_probe_with_workspace(env: Env) -> None:
    _, _, c = env.setup({"googleworkspace_connection": "gws"})
    r = c.probe(background())
    assert "googleworkspace_connection" not in "\n".join(r.warnings), f"warnings: {r.warnings!r}"


def test_catalog() -> None:
    seen: set[str] = set()
    for a in GoogleCloud().actions():
        assert a.name not in seen, f"action {a.name} listed twice"
        seen.add(a.name)
        assert a.description != "", f"action {a.name} has no description"
    assert RAW_PATTERN in seen, "raw pattern not listed"
    assert find_action(GoogleCloud(), "raw:storage.objects.get") is not None, "raw:storage.objects.get not matched"
