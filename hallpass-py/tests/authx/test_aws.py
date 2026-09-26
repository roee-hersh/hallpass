"""Port of internal/authx/aws_test.go."""

from __future__ import annotations

import datetime
import json
import queue
import threading
from collections.abc import Iterator

import pytest

from hallpass.authx import xmlutil
from hallpass.authx.awscreds import ContainerProvider, OSEnv, _container_relative_endpoint, _validate_container_uri, ambient_provider, static_from_json
from hallpass.authx.awsquery import AWSClient, AWSError, classify_aws_error, decode_json_error, decode_xml_error, query_form
from hallpass.authx.sigv4 import AWSCredentials
from hallpass.authx.sts import _STS_VERSION, CachedProvider, StaticProvider, STSClient, assume_role_provider
from hallpass.core.context import Cancelled, Context, DeadlineExceeded, background, with_cancel
from hallpass.core.decision import Code
from hallpass.core.errors import is_error
from hallpass.net import httpx
from tests import harness as itest


def plain_client(srv: itest.Server) -> httpx.Client:
    deps, _ = itest.deps(srv)
    hc = deps.http_client(itest.settings("aws", "aws"))
    return httpx.Client(http=hc, logger=deps.logger, sleep=lambda ctx, d: None)


def _rfc3339_in_an_hour() -> str:
    """time.Now().Add(time.Hour).UTC().Format(time.RFC3339)."""
    t = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture
def plain_srv() -> Iterator[itest.Server]:
    """httptest.NewServer: a plain HTTP server."""
    s = itest.Server(tls=False)
    yield s
    s.close()


def test_query_params_form() -> None:
    f = query_form({"RoleArn": "arn", "ActionNames": ["s3:GetObject", "s3:PutObject"], "DurationSeconds": 900, "Flag": True}, "AssumeRole", "2011-06-15")
    want = {
        "Action": ["AssumeRole"],
        "Version": ["2011-06-15"],
        "RoleArn": ["arn"],
        "ActionNames.member.1": ["s3:GetObject"],
        "ActionNames.member.2": ["s3:PutObject"],
        "DurationSeconds": ["900"],
        "Flag": ["true"],
    }
    assert httpx.encode_query(f) == httpx.encode_query(want), f"got {httpx.encode_query(f)}"


def test_error_decoding() -> None:
    e = decode_xml_error(
        403,
        b"<ErrorResponse><Error><Type>Sender</Type><Code>AccessDenied</Code><Message>User is not authorized</Message></Error><RequestId>x</RequestId></ErrorResponse>",
    )
    assert e.code == "AccessDenied" and e.access_denied() and not e.throttled(), vars(e)
    e = decode_xml_error(400, b"<ErrorResponse><Error><Code>Throttling</Code><Message>Rate exceeded</Message></Error></ErrorResponse>")
    assert e.throttled(), "throttling"
    e = decode_xml_error(503, b"garbage")
    assert e.code == "HTTP503", e.code
    h = httpx.Headers()
    h.set("x-amzn-ErrorType", "ThrottlingException:http://internal.amazon.com/coral/com.amazon.coral.availability/")
    e = decode_json_error(400, h, b'{"__type":"com.amazonaws.identitystore#ThrottlingException","message":"slow down","RetryAfterSeconds":2}')
    assert e.code == "ThrottlingException" and e.throttled() and e.retry_after_seconds == 2 and e.message == "slow down", vars(e)
    e = decode_json_error(400, httpx.Headers(), b'{"__type":"AccessDeniedException","Message":"nope"}')
    assert e.code == "AccessDeniedException" and e.access_denied() and e.message == "nope", vars(e)
    # The upstream message stays in the field but never in the error
    # string: SignatureDoesNotMatch messages can carry the canonical request.
    e = decode_xml_error(
        403,
        (
            "<ErrorResponse><Error><Code>SignatureDoesNotMatch</Code><Message>The request signature we calculated does not match. Canonical request: "
            + itest.CANARY
            + "</Message></Error></ErrorResponse>"
        ).encode(),
    )
    assert e.message != "" and itest.CANARY in e.message, f"message field dropped: {vars(e)}"
    got = str(e)
    assert got == "aws: HTTP 403 SignatureDoesNotMatch" and itest.CANARY not in got, f"Error() = {got!r}"
    got = str(classify_aws_error(e))
    assert itest.CANARY not in got, f"classified error leaks the message: {got!r}"
    c = classify_aws_error(AWSError(400, "Throttling"))
    assert c.code == Code.UPSTREAM_RATE_LIMIT, c
    c = classify_aws_error(AWSError(403, "AccessDenied"))
    assert c.code == Code.CREDENTIAL_REJECTED, c
    c = classify_aws_error(AWSError(400, "MalformedPolicyDocument"))
    assert c.code == Code.UPSTREAM_ERROR, c
    c = classify_aws_error(DeadlineExceeded())
    assert c.code == Code.UPSTREAM_TIMEOUT, c


def test_sts_assume_role_and_query_client(srv: itest.Server) -> None:
    calls = [0]
    lock = threading.Lock()

    def handler(w: itest.ResponseWriter, r: itest.Request) -> None:
        with lock:
            calls[0] += 1
        form = {k: v[0] for k, v in r.form().items() if v}
        g = form.get
        auth = r.header.get("Authorization")
        action = g("Action", "")
        if action == "AssumeRole":
            if (
                not auth.startswith("AWS4-HMAC-SHA256 Credential=AKIA" + itest.CANARY + "/")
                or "/us-east-1/sts/aws4_request" not in auth
                or r.header.get("X-Amz-Date") == ""
            ):
                w.write_header(403)
                w.write(b"<ErrorResponse><Error><Code>SignatureDoesNotMatch</Code><Message>bad</Message></Error></ErrorResponse>")
                return
            if g("RoleArn") != "arn:aws:iam::123456789012:role/hallpass" or g("ExternalId") != "ext" or g("RoleSessionName", "") == "":
                w.write_header(400)
                w.write(b"<ErrorResponse><Error><Code>ValidationError</Code><Message>bad params</Message></Error></ErrorResponse>")
                return
            w.write(
                "<AssumeRoleResponse><AssumeRoleResult><Credentials><AccessKeyId>ASIA"
                + itest.CANARY
                + "</AccessKeyId><SecretAccessKey>"
                + itest.CANARY
                + "secret</SecretAccessKey><SessionToken>"
                + itest.CANARY
                + "tok</SessionToken><Expiration>"
                + _rfc3339_in_an_hour()
                + "</Expiration></Credentials><AssumedRoleUser><Arn>arn:aws:sts::123456789012:assumed-role/hallpass/s</Arn></AssumedRoleUser></AssumeRoleResult></AssumeRoleResponse>"
            )
        elif action == "AssumeRoleWithWebIdentity":
            if auth != "" or g("WebIdentityToken") != "oidc-" + itest.CANARY:
                w.write_header(400)
                w.write(b"<ErrorResponse><Error><Code>InvalidIdentityToken</Code><Message>bad</Message></Error></ErrorResponse>")
                return
            w.write(
                "<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>ASIAWEB</AccessKeyId><SecretAccessKey>s</SecretAccessKey><SessionToken>t</SessionToken><Expiration>"
                + _rfc3339_in_an_hour()
                + "</Expiration></Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>"
            )
        elif action == "GetCallerIdentity":
            if not auth.startswith("AWS4-HMAC-SHA256 Credential=ASIA") or r.header.get("X-Amz-Security-Token") == "":
                w.write_header(403)
                w.write(b"<ErrorResponse><Error><Code>AccessDenied</Code><Message>no</Message></Error></ErrorResponse>")
                return
            w.write(
                b"<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>arn:aws:sts::123456789012:assumed-role/hallpass/s</Arn></GetCallerIdentityResult></GetCallerIdentityResponse>"
            )
        else:
            w.write_header(400)

    srv.handle("POST", "/", handler)
    c = plain_client(srv)
    base = StaticProvider(AWSCredentials(access_key_id="AKIA" + itest.CANARY, secret_access_key=itest.CANARY + "base"))
    sts = STSClient(http=c, endpoint=srv.url, region="us-east-1", creds=base)
    ctx = background()

    with pytest.raises(Exception):  # noqa: B017 - bad arn accepted
        sts.assume_role(ctx, "not-an-arn", "s", "", 0)
    prov = assume_role_provider(sts, "arn:aws:iam::123456789012:role/hallpass", "hallpass", "ext")
    creds = prov.credentials(ctx)
    assert creds.access_key_id.startswith("ASIA") and creds.session_token != "" and creds.expiry is not None, creds
    with lock:
        n = calls[0]
    prov.credentials(ctx)
    with lock:
        assert calls[0] == n, "assumed credentials not cached"
    # Use the assumed credentials on a signed Query call.
    client = AWSClient(http=c, endpoint=srv.url, region="us-east-1", service="sts", creds=prov)
    root = client.query(ctx, "GetCallerIdentity", _STS_VERSION, {})
    arn = xmlutil.text(root, "GetCallerIdentityResult", "Arn")
    assert "assumed-role" in arn, arn
    # Web identity is unsigned.
    wi = sts.assume_role_with_web_identity(ctx, "arn:aws:iam::123456789012:role/irsa", "s", "oidc-" + itest.CANARY)
    assert wi.access_key_id == "ASIAWEB", wi
    # A wrong base credential surfaces as an AWSError.
    bad = STSClient(http=c, endpoint=srv.url, region="us-east-1", creds=StaticProvider(AWSCredentials(access_key_id="AKIAWRONG", secret_access_key="x")))
    with pytest.raises(Exception) as ei:
        bad.assume_role(ctx, "arn:aws:iam::123456789012:role/hallpass", "s", "ext", 0)
    assert classify_aws_error(ei.value).code == Code.CREDENTIAL_REJECTED, f"wrong creds -> {ei.value!r}"


def test_json11(srv: itest.Server) -> None:
    def handler(w: itest.ResponseWriter, r: itest.Request) -> None:
        if r.header.get("Content-Type") != "application/x-amz-json-1.1" or not r.header.get("Authorization").startswith("AWS4-HMAC-SHA256"):
            w.write_header(400)
            return
        target = r.header.get("X-Amz-Target")
        if target == "AWSIdentityStore.GetUserId":
            try:
                inp = r.json()
            except ValueError:
                inp = {}
            if not isinstance(inp, dict) or inp.get("IdentityStoreId") != "d-123":
                w.write_header(400)
                w.write(b'{"__type":"ValidationException","message":"bad"}')
                return
            w.write(b'{"IdentityStoreId":"d-123","UserId":"u-1"}')
        elif target == "AWSIdentityStore.Throttle":
            w.write_header(400)
            w.write(b'{"__type":"ThrottlingException","message":"slow","RetryAfterSeconds":1}')

    srv.handle("POST", "/", handler)
    c = plain_client(srv)
    client = AWSClient(
        http=c, endpoint=srv.url, region="eu-west-1", service="identitystore", creds=StaticProvider(AWSCredentials(access_key_id="AKIA", secret_access_key="s"))
    )
    out = client.json11(background(), "AWSIdentityStore.GetUserId", {"IdentityStoreId": "d-123"})
    assert isinstance(out, dict) and out.get("UserId") == "u-1", out
    with pytest.raises(Exception) as ei:
        client.json11(background(), "AWSIdentityStore.Throttle", {})
    assert classify_aws_error(ei.value).code == Code.UPSTREAM_RATE_LIMIT, f"throttle -> {ei.value!r}"


def test_credential_chain(plain_srv: itest.Server) -> None:
    # Container endpoint with an authorization token file.
    container = plain_srv

    def container_h(w: itest.ResponseWriter, r: itest.Request) -> None:
        if r.path != "/v2/credentials/abc" or r.header.get("Authorization") != "podtoken-" + itest.CANARY:
            w.write_header(403)
            return
        w.write(json.dumps({"AccessKeyId": "ASIACONT", "SecretAccessKey": "s", "Token": "t", "Expiration": _rfc3339_in_an_hour()}) + "\n")

    container.handle("", "*", container_h)

    def getenv(k: str) -> str:
        if k == "AWS_CONTAINER_CREDENTIALS_FULL_URI":
            return container.url + "/v2/credentials/abc"
        if k == "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE":
            return "/token"
        return ""

    env = OSEnv(getenv=getenv, read_file=lambda _p: ("podtoken-" + itest.CANARY + "\n").encode())
    hc = httpx.new_http_client(httpx.Options())
    plain = httpx.Client(http=hc)
    prov = ambient_provider("auto", env, plain, None, "")  # type: ignore[arg-type]
    creds = prov.credentials(background())
    assert creds.access_key_id == "ASIACONT", creds
    with pytest.raises(ValueError):
        _validate_container_uri("http://evil.example/creds")
    for ok in ("http://169.254.170.2/x", "http://169.254.170.23/x", "http://127.0.0.1:8080/x", "http://localhost/x", "https://anything.example/x"):
        _validate_container_uri(ok)

    # IMDSv2: PUT token, then role name, then credentials.
    imds = itest.Server(tls=False)
    try:

        def imds_h(w: itest.ResponseWriter, r: itest.Request) -> None:
            if r.method == "PUT" and r.path == "/latest/api/token":
                if r.header.get("X-aws-ec2-metadata-token-ttl-seconds") == "":
                    w.write_header(400)
                    return
                w.write(b"imds-token")
            elif r.header.get("X-aws-ec2-metadata-token") != "imds-token":
                w.write_header(401)
            elif r.path == "/latest/meta-data/iam/security-credentials/":
                w.write(b"instance-role\n")
            elif r.path == "/latest/meta-data/iam/security-credentials/instance-role":
                w.write(json.dumps({"AccessKeyId": "ASIAIMDS", "SecretAccessKey": "s", "Token": "t", "Expiration": _rfc3339_in_an_hour()}) + "\n")
            else:
                w.write_header(404)

        imds.handle("", "*", imds_h)
        empty = OSEnv(getenv=lambda _k: "", read_file=lambda _p: b"")
        prov = ambient_provider("imds", empty, plain, None, imds.url)  # type: ignore[arg-type]
        creds = prov.credentials(background())
        assert creds.access_key_id == "ASIAIMDS", f"imds: {creds}"
        prov = ambient_provider("auto", empty, plain, None, imds.url)  # type: ignore[arg-type]
        creds = prov.credentials(background())
        assert creds.access_key_id == "ASIAIMDS", f"auto -> imds: {creds}"
    finally:
        imds.close()

    # Env keys win in auto mode.
    keys = OSEnv(getenv=lambda k: {"AWS_ACCESS_KEY_ID": "AKIAENV", "AWS_SECRET_ACCESS_KEY": "s"}.get(k, ""))
    prov = ambient_provider("auto", keys, plain, None, "")  # type: ignore[arg-type]
    assert prov.credentials(background()).access_key_id == "AKIAENV", "env keys"
    with pytest.raises(ValueError):
        ambient_provider("bogus", empty, plain, None, "")  # type: ignore[arg-type]
    static_from_json(b'{"access_key_id":"a","secret_access_key":"b","session_token":"c"}')
    with pytest.raises(ValueError):
        static_from_json(b'{"access_key_id":"a"}')


class _CountingTransport:
    """Go's roundTripFunc: counts calls and fails every one."""

    def __init__(self) -> None:
        self.calls = 0
        self._lock = threading.Lock()

    def send(self, ctx: Context, req: httpx.PreparedRequest, max_body: int = httpx.MAX_BODY) -> httpx.RawResponse:
        with self._lock:
            self.calls += 1
        raise RuntimeError("must not be called")


def test_container_relative_uri() -> None:
    for bad in ("@evil.example/", "evil.example/creds", "v2/credentials/abc", ":8080/creds", "//evil.example/creds", "\\evil.example/creds"):
        try:
            ep = _container_relative_endpoint(bad)
        except ValueError:
            continue
        pytest.fail(f"{bad!r} accepted as {ep!r}")
    for ok in ("/v2/credentials/abc", "/v2/credentials/abc?x=1", "/"):
        ep = _container_relative_endpoint(ok)
        assert ep == "http://169.254.170.2" + ok, f"{ok!r} -> {ep!r}"
    # Through the provider: no request leaves for a bad value.
    rt = _CountingTransport()
    plain = httpx.Client(http=rt)  # type: ignore[arg-type]
    env = OSEnv(getenv=lambda k: "@evil.example/" if k == "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI" else "")
    with pytest.raises(Exception) as ei:
        ContainerProvider(http=plain, env=env).credentials(background())
    assert "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI" in str(ei.value), f"relative uri with userinfo accepted: {ei.value!r}"
    assert rt.calls == 0, "request sent for a rejected relative uri"


def test_cached_provider_refresh() -> None:
    now = [1_000_000.0]
    n = [0]

    def fetch(ctx: Context) -> AWSCredentials:
        n[0] += 1
        return AWSCredentials(access_key_id="k", secret_access_key="s", expiry=now[0] + 3600)

    p = CachedProvider(fetch, now=lambda: now[0])
    p.credentials(background())
    now[0] += 50 * 60
    p.credentials(background())
    assert n[0] == 1, "refetched early"
    now[0] += 6 * 60
    p.credentials(background())
    assert n[0] == 2, "not refreshed 5 minutes before expiry"


def test_cached_provider_panic_and_leader_cancel() -> None:
    """A crashing fetch must not wedge the provider, and a cancelled leader
    must not abort the fetch for a waiter with a live context."""
    calls = [0]

    def fetch(ctx: Context) -> AWSCredentials:
        calls[0] += 1
        if calls[0] == 1:
            # Go: panic("boom"). A bug exception type is Python's panic.
            raise TypeError("boom")
        return AWSCredentials(access_key_id="AKIA", secret_access_key="s")

    p = CachedProvider(fetch)
    with pytest.raises(Exception) as ei:
        p.credentials(background())
    assert "boom" in str(ei.value), f"panic not reported: {ei.value!r}"
    c = p.credentials(background())
    assert c.access_key_id == "AKIA", f"provider wedged after panic: {c}"

    release = threading.Event()
    started = threading.Event()
    fetches = [0]

    def fetch2(ctx: Context) -> AWSCredentials:
        fetches[0] += 1
        started.set()
        if ctx.wait(release):
            return AWSCredentials(access_key_id="AKIA2", secret_access_key="s")
        err = ctx.err()
        assert err is not None
        raise err

    p2 = CachedProvider(fetch2)
    leader_ctx, cancel_leader = with_cancel(background())
    leader_err: queue.Queue[BaseException | None] = queue.Queue(1)

    def leader() -> None:
        try:
            p2.credentials(leader_ctx)
            leader_err.put(None)
        except BaseException as e:
            leader_err.put(e)

    threading.Thread(target=leader).start()
    started.wait()
    waiter: queue.Queue[AWSCredentials | BaseException] = queue.Queue(1)

    def wait() -> None:
        try:
            waiter.put(p2.credentials(background()))
        except BaseException as e:
            waiter.put(e)

    threading.Thread(target=wait).start()
    cancel_leader()
    err = leader_err.get()
    assert is_error(err, Cancelled), f"leader: {err!r}"
    release.set()
    got = waiter.get()
    assert isinstance(got, AWSCredentials) and got.access_key_id == "AKIA2", f"waiter got {got!r}"
    assert fetches[0] == 1, f"fetches {fetches[0]}, want 1"
