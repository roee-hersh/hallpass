"""AWS STS over the Query protocol, and cached credential providers."""

from __future__ import annotations

import re
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from hallpass.authx import xmlutil
from hallpass.authx.awsquery import AWSClient, CredentialProvider, decode_xml_error, query_form
from hallpass.authx.sigv4 import AWSCredentials
from hallpass.authx.token import DEFAULT_FETCH_TIMEOUT
from hallpass.authx.util import parse_rfc3339
from hallpass.core import evidence
from hallpass.core.cache import PanicError, detach, is_panic_type
from hallpass.core.context import Context
from hallpass.core.errors import go_quote
from hallpass.net import httpx

__all__ = ["CachedProvider", "STSClient", "StaticProvider", "assume_role_provider", "session_name", "validate_role_arn"]

_STS_VERSION = "2011-06-15"
_ROLE_ARN_RE = re.compile(r"arn:(aws|aws-us-gov|aws-cn):iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}")


def validate_role_arn(arn: str) -> None:
    if not _ROLE_ARN_RE.fullmatch(arn):
        raise ValueError(f"{go_quote(arn)} is not an IAM role ARN")


def _creds_from(root: Any, result: str) -> AWSCredentials:
    """stsCredentials.toCreds on {result}/Credentials under the root."""

    def field(name: str) -> str:
        return xmlutil.text(root, result, "Credentials", name)

    akid, secret = field("AccessKeyId"), field("SecretAccessKey")
    if akid == "" or secret == "":
        raise ValueError("sts: response has no credentials")
    exp_s = field("Expiration")
    try:
        exp = parse_rfc3339(exp_s)
    except ValueError:
        raise ValueError(f"sts: bad expiration {go_quote(exp_s)}") from None
    return AWSCredentials(akid, secret, field("SessionToken"), exp)


@dataclass
class STSClient:
    http: httpx.Client
    endpoint: str  # https://sts.{region}.amazonaws.com
    region: str
    # Signs AssumeRole. AssumeRoleWithWebIdentity is unsigned.
    creds: CredentialProvider | None = None

    def assume_role(self, ctx: Context, role_arn: str, session_name: str, external_id: str = "", duration: float = 0) -> AWSCredentials:
        """sts:AssumeRole. duration 0 means the STS default (1 h)."""
        validate_role_arn(role_arn)
        params: dict[str, Any] = {"RoleArn": role_arn, "RoleSessionName": session_name}
        if external_id:
            params["ExternalId"] = external_id
        if duration > 0:
            params["DurationSeconds"] = int(duration)
        assert self.creds is not None, "AssumeRole needs credentials to sign with"
        client = AWSClient(self.http, self.endpoint, self.region, "sts", self.creds)
        root = client.query(ctx, "AssumeRole", _STS_VERSION, params)
        return _creds_from(root, "AssumeRoleResult")

    def assume_role_with_web_identity(self, ctx: Context, role_arn: str, session_name: str, token: str) -> AWSCredentials:
        """Exchange an OIDC token (IRSA) for credentials. Unsigned."""
        validate_role_arn(role_arn)
        form = query_form({"RoleArn": role_arn, "RoleSessionName": session_name, "WebIdentityToken": token}, "AssumeRoleWithWebIdentity", _STS_VERSION)
        resp = self.http.do(
            ctx,
            httpx.Request(method="POST", path=self.endpoint + "/", form=form, idempotent=True, accept_4xx=True, header={"Accept": "application/xml"}),
        )
        if resp.status >= 400:
            raise decode_xml_error(resp.status, resp.body)
        try:
            root = xmlutil.parse(resp.body)
        except xmlutil.XMLError as e:
            raise ValueError(f"decode xml: {e}") from e
        return _creds_from(root, "AssumeRoleWithWebIdentityResult")


class _CredsCall:
    __slots__ = ("creds", "done", "err")

    def __init__(self) -> None:
        self.done = threading.Event()
        self.creds = AWSCredentials()
        self.err: BaseException | None = None


class CachedProvider:
    """Caches credentials and refreshes them 5 minutes before expiry.
    Concurrent refreshes are collapsed; the shared fetch runs on a context
    detached from the first caller's cancellation."""

    def __init__(self, fetch: Callable[[Context], AWSCredentials], now: Callable[[], float] | None = None, early: float = 0.0) -> None:
        self.fetch = fetch
        self.now = now
        self.early = early
        self._lock = threading.Lock()
        self._creds = AWSCredentials()
        self._inflight: _CredsCall | None = None

    def credentials(self, ctx: Context) -> AWSCredentials:
        now = self.now() if self.now is not None else time.time()
        early = self.early or 300.0
        with self._lock:
            c = self._creds
            if not c.is_zero() and (c.expiry is None or now < c.expiry - early):
                return c
            cc = self._inflight
            if cc is None:
                cc = _CredsCall()
                self._inflight = cc
                # Credentials are not evidence for a decision.
                fctx, cancel = detach(evidence.without_recorder(ctx), DEFAULT_FETCH_TIMEOUT)
                call = cc

                def run() -> None:
                    try:
                        self._fetch(call, fctx)
                    finally:
                        cancel()

                threading.Thread(target=run, name="hallpass-aws-creds", daemon=True).start()
        if not ctx.wait(cc.done):
            err = ctx.err()
            assert err is not None
            raise err
        if cc.err is not None:
            raise cc.err
        return cc.creds

    def _fetch(self, cc: _CredsCall, ctx: Context) -> None:
        try:
            try:
                cc.creds = self.fetch(ctx)
            except Exception as e:  # noqa: BLE001
                cc.creds = AWSCredentials()
                cc.err = PanicError(e) if is_panic_type(e) else e
            except BaseException:  # noqa: BLE001 - Go's runtime.Goexit
                cc.creds = AWSCredentials()
                cc.err = RuntimeError("credential fetch exited without returning")
        finally:
            with self._lock:
                self._inflight = None
                if cc.err is None:
                    self._creds = cc.creds
            cc.done.set()


@dataclass
class StaticProvider:
    creds: AWSCredentials

    def credentials(self, ctx: Context) -> AWSCredentials:
        if self.creds.is_zero():
            raise ValueError("no AWS credentials")
        return self.creds


def assume_role_provider(sts: STSClient, role_arn: str, session_name: str, external_id: str = "") -> CachedProvider:
    """A cached provider that assumes role_arn with the STS client's own credentials."""
    return CachedProvider(lambda ctx: sts.assume_role(ctx, role_arn, session_name, external_id, 0))


def session_name(prefix: str) -> str:
    """A valid RoleSessionName from a prefix."""
    # Go truncates the bytes; a cut rune is dropped rather than kept broken.
    return f"{prefix}-{int(time.time())}".encode()[:64].decode("utf-8", "ignore")
