"""AWS service calls: Query protocol (IAM, STS; form POST, XML replies) and
JSON 1.1 (Identity Store), signed with SigV4, and the errors they return."""

from __future__ import annotations

import copy
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from hallpass.authx import xmlutil
from hallpass.authx.sigv4 import AWSCredentials, SigV4Signer
from hallpass.authx.util import INT, STR, go_json_loads, go_json_marshal, go_sprint, go_unmarshal
from hallpass.core.context import Context
from hallpass.core.decision import Code, HallpassError, wrap_error
from hallpass.core.errors import as_error
from hallpass.net import httpx

__all__ = [
    "AWSClient",
    "AWSError",
    "CredentialProvider",
    "QueryParams",
    "classify_aws_error",
    "decode_json_error",
    "decode_xml_error",
    "dns_suffix",
    "iam_endpoint",
    "query_form",
    "regional_endpoint",
]


class AWSError(Exception):
    """A decoded AWS service error."""

    def __init__(self, status: int, code: str, message: str = "", retry_after_seconds: int = 0) -> None:
        self.status = status
        self.code = code
        # Kept but never rendered: for SignatureDoesNotMatch it can carry the
        # canonical request, and error strings end up in logs.
        self.message = message
        self.retry_after_seconds = retry_after_seconds
        super().__init__(str(self))

    def __str__(self) -> str:
        return f"aws: HTTP {self.status} {self.code}"

    def throttled(self) -> bool:
        if self.code in (
            "Throttling",
            "ThrottlingException",
            "RequestLimitExceeded",
            "TooManyRequestsException",
            "RequestThrottled",
            "RequestThrottledException",
        ):
            return True
        return self.status == 429

    def access_denied(self) -> bool:
        if self.code in (
            "AccessDenied",
            "AccessDeniedException",
            "UnauthorizedAccess",
            "UnrecognizedClientException",
            "InvalidClientTokenId",
            "ExpiredToken",
            "ExpiredTokenException",
            "SignatureDoesNotMatch",
            "InvalidSignatureException",
            "IncompleteSignature",
            "AuthFailure",
        ):
            return True
        return self.status in (401, 403)


def decode_xml_error(status: int, body: bytes) -> AWSError:
    """A Query-protocol error body."""
    code = msg = ""
    try:
        # Go ignores the decode error and keeps whatever it decoded.
        root = xmlutil.parse(body, partial=True)
    except xmlutil.XMLError:
        root = None
    if root is not None:
        code, msg = xmlutil.text(root, "Error", "Code"), xmlutil.text(root, "Error", "Message")
        if code == "":
            code, msg = xmlutil.text(root, "Code"), xmlutil.text(root, "Message")
    if code == "":
        code = f"HTTP{status}"
    return AWSError(status, code, msg)


def decode_json_error(status: int, header: httpx.Headers, body: bytes) -> AWSError:
    """A JSON-1.1 error body and the x-amzn-ErrorType header."""
    # Go ignores the decode error and keeps whatever it decoded.
    j, _ = go_unmarshal(body, (("__type", STR), ("message", STR), ("Message", STR), ("RetryAfterSeconds", INT)))
    code = j["__type"]
    h = header.get("x-amzn-ErrorType")
    if h:
        code = h
    # "com.amazonaws.service#ThrottlingException:http://..." -> ThrottlingException
    if "#" in code:
        code = code[code.index("#") + 1 :]
    if ":" in code:
        code = code[: code.index(":")]
    if code == "":
        code = f"HTTP{status}"
    msg = j["message"] or j["Message"]
    return AWSError(status, code, msg, j["RetryAfterSeconds"])


def classify_aws_error(err: BaseException) -> HallpassError:
    ae = as_error(err, AWSError)
    if ae is not None:
        if ae.throttled():
            return wrap_error(Code.UPSTREAM_RATE_LIMIT, err, f"AWS throttled the request ({ae.code})")
        if ae.access_denied():
            return wrap_error(Code.CREDENTIAL_REJECTED, err, f"AWS rejected hallpass's credential or denied the call ({ae.code})")
        return wrap_error(Code.UPSTREAM_ERROR, err, f"AWS returned {ae.code}")
    out = httpx.classify(err)
    assert out is not None
    return out


QueryParams = Mapping[str, Any]


def query_form(params: QueryParams, action: str, version: str) -> dict[str, list[str]]:
    """Query-protocol form values with Action and Version. Lists become
    Name.member.N (1-based); nested structures are flattened by the caller
    ("ContextEntries.member.1.ContextKeyName")."""
    v: dict[str, list[str]] = {"Action": [action], "Version": [version]}
    for k in sorted(params):
        val = params[k]
        if isinstance(val, bool):
            v[k] = ["true" if val else "false"]
        elif isinstance(val, str):
            v[k] = [val]
        elif isinstance(val, int):
            v[k] = [str(val)]
        elif isinstance(val, (list, tuple)) and all(isinstance(s, str) for s in val):
            # Go's []string case.
            for i, s in enumerate(val):
                v[f"{k}.member.{i + 1}"] = [s]
        else:
            v[k] = [go_sprint(val)]
    return v


class CredentialProvider(Protocol):
    def credentials(self, ctx: Context) -> AWSCredentials: ...


@dataclass
class AWSClient:
    """Signs and sends requests to one AWS service endpoint."""

    http: httpx.Client
    # The full base URL, e.g. https://iam.amazonaws.com.
    endpoint: str
    # The signing region and signing name.
    region: str
    service: str
    creds: CredentialProvider

    def query(self, ctx: Context, action: str, version: str, params: QueryParams) -> Any:
        """A Query-protocol request; returns the parsed XML root. Errors are
        AWSError or transport errors."""
        body = httpx.encode_query(query_form(params, action, version)).encode("ascii")
        hdr = {"Content-Type": "application/x-www-form-urlencoded; charset=utf-8", "Accept": "application/xml"}
        resp = self._send(ctx, body, hdr)
        if resp.status >= 400:
            raise decode_xml_error(resp.status, resp.body)
        try:
            return xmlutil.parse(resp.body)
        except xmlutil.XMLError as e:
            raise ValueError(f"decode {action} response: {e}") from None

    def json11(self, ctx: Context, target: str, body_in: Any) -> Any:
        """A JSON-1.1 request with X-Amz-Target; returns the decoded reply
        (None for an empty body)."""
        body = b"{}" if body_in is None else go_json_marshal(body_in)
        hdr = {"Content-Type": "application/x-amz-json-1.1", "X-Amz-Target": target}
        resp = self._send(ctx, body, hdr)
        if resp.status >= 400:
            raise decode_json_error(resp.status, resp.header, resp.body)
        if not resp.body.strip():
            return None
        try:
            return go_json_loads(resp.body)
        except ValueError as e:
            raise ValueError(f"decode {target} response: {e}") from None

    def _send(self, ctx: Context, body: bytes, hdr: Mapping[str, str]) -> httpx.Response:
        creds = self.creds.credentials(ctx)
        client = copy.copy(self.http)
        signer = SigV4Signer(self.region, self.service)

        def auth(_: Context, r: httpx.PreparedRequest) -> None:
            signer.sign(r, body, creds)

        client.auth = auth
        # Every call hallpass makes is a read, so it may be retried.
        return client.do(ctx, httpx.Request(method="POST", path=self.endpoint + "/", body=body, header=dict(hdr), idempotent=True, accept_4xx=True))


def dns_suffix(partition: str) -> str:
    return "amazonaws.com.cn" if partition == "aws-cn" else "amazonaws.com"


def regional_endpoint(partition: str, service: str, region: str) -> str:
    return f"https://{service}.{region}.{dns_suffix(partition)}"


def iam_endpoint(partition: str) -> tuple[str, str]:
    """The global IAM endpoint and its signing region. The China endpoint
    is UNVERIFIED."""
    if partition == "aws-us-gov":
        return "https://iam.us-gov.amazonaws.com", "us-gov-west-1"
    if partition == "aws-cn":
        return "https://iam.cn-north-1.amazonaws.com.cn", "cn-north-1"
    return "https://iam.amazonaws.com", "us-east-1"
