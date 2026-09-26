"""Where AWS credentials come from: static JSON, the environment, the ECS
or EKS Pod Identity container endpoint, IRSA web identity, and IMDSv2."""

from __future__ import annotations

import ipaddress
import os
import re
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass, field

from hallpass.authx.awsquery import CredentialProvider
from hallpass.authx.sigv4 import AWSCredentials
from hallpass.authx.sts import CachedProvider, STSClient, session_name
from hallpass.authx.util import STR, go_unmarshal, parse_rfc3339, url_parse_check
from hallpass.core.cache import is_panic_type
from hallpass.core.context import Context
from hallpass.core.errors import go_quote, go_trim_space, path_error_text
from hallpass.net import httpx

__all__ = [
    "OS_ENV",
    "ContainerProvider",
    "EnvProvider",
    "IMDSProvider",
    "OSEnv",
    "WebIdentityProvider",
    "ambient_provider",
    "static_from_json",
]


def _read_file(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


@dataclass
class OSEnv:
    """The environment, abstracted for tests."""

    getenv: Callable[[str], str] = field(default=lambda k: os.environ.get(k, ""))
    read_file: Callable[[str], bytes] = _read_file


OS_ENV = OSEnv()


def static_from_json(b: bytes | str) -> AWSCredentials:
    """{"access_key_id": ..., "secret_access_key": ..., "session_token": ...}"""
    j, err = go_unmarshal(b, (("access_key_id", STR), ("secret_access_key", STR), ("session_token", STR)))
    if err is not None:
        raise ValueError(f"credential JSON: {err}")
    if not j["access_key_id"] or not j["secret_access_key"]:
        raise ValueError("credential JSON needs access_key_id and secret_access_key")
    return AWSCredentials(j["access_key_id"], j["secret_access_key"], j["session_token"])


# The ECS/EKS Pod Identity (and IMDS) credential document.
_CONTAINER_RESPONSE = (("AccessKeyId", STR), ("SecretAccessKey", STR), ("Token", STR), ("Expiration", STR))


def _decode_creds(body: bytes, what: str) -> AWSCredentials:
    """json.Unmarshal into containerResponse, then toCreds."""
    doc, err = go_unmarshal(body, _CONTAINER_RESPONSE)
    if err is not None:
        raise ValueError(f"{what}: {err}")
    if not doc["AccessKeyId"] or not doc["SecretAccessKey"]:
        raise ValueError("credential document has no keys")
    exp = None
    if doc["Expiration"]:
        try:
            exp = parse_rfc3339(doc["Expiration"])
        except ValueError:
            raise ValueError(f"bad expiration {go_quote(doc['Expiration'])}") from None
    return AWSCredentials(doc["AccessKeyId"], doc["SecretAccessKey"], doc["Token"], exp)


def _read_err(e: BaseException, path: str) -> str:
    """The text of a ReadFile failure: Go's *fs.PathError for an OS error."""
    if isinstance(e, OSError):
        return path_error_text("open", path, e)
    return str(e)


def _go_hostname(netloc: str) -> str:
    """url.URL.Hostname: the host without userinfo, port or brackets, its
    case kept (urlsplit's hostname lowercases)."""
    host = netloc.rpartition("@")[2]
    i = host.rfind(":")
    if i >= 0 and re.fullmatch(r":\d*", host[i:]):
        host = host[:i]
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return host


def _is_loopback_ip(host: str) -> bool:
    """net.ParseIP(host) != nil && IsLoopback(): no zone, and an IPv4-mapped
    IPv6 address counts as its IPv4 address."""
    if "%" in host:
        return False
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped.is_loopback
    return ip.is_loopback


_CONTAINER_HOST = "169.254.170.2"


def _container_relative_endpoint(rel: str) -> str:
    """The ECS credential URL. The value must be an absolute path so it
    cannot smuggle userinfo, a host or a port."""
    if not rel.startswith("/") or rel.startswith("//"):
        raise ValueError('AWS_CONTAINER_CREDENTIALS_RELATIVE_URI must be an absolute path starting with a single "/"')
    endpoint = "http://" + _CONTAINER_HOST + rel
    try:
        url_parse_check(endpoint)
        u = urllib.parse.urlsplit(endpoint)
    except ValueError as e:
        raise ValueError(f"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI: {e}") from None
    host = u.netloc.rpartition("@")[2]
    # The netloc carries any userinfo, so comparing it checks u.User too.
    if u.scheme != "http" or u.netloc != _CONTAINER_HOST:
        raise ValueError(f"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI resolves to host {go_quote(host)}, not {_CONTAINER_HOST}")
    return endpoint


def _validate_container_uri(full: str) -> None:
    try:
        url_parse_check(full)
        u = urllib.parse.urlsplit(full)
    except ValueError as e:
        raise ValueError(f"AWS_CONTAINER_CREDENTIALS_FULL_URI: {e}") from None
    if u.scheme == "https":
        return
    if u.scheme != "http":
        raise ValueError("AWS_CONTAINER_CREDENTIALS_FULL_URI must be http or https")
    host = _go_hostname(u.netloc)
    if host in ("localhost", "169.254.170.2", "169.254.170.23", "fd00:ec2::23"):
        return
    if _is_loopback_ip(host):
        return
    raise ValueError(f"AWS_CONTAINER_CREDENTIALS_FULL_URI host {go_quote(host)} is not allowed over http")


@dataclass
class ContainerProvider:
    """The ECS container endpoint or the EKS Pod Identity agent:
    AWS_CONTAINER_CREDENTIALS_RELATIVE_URI (http://169.254.170.2{uri}),
    AWS_CONTAINER_CREDENTIALS_FULL_URI, and AWS_CONTAINER_AUTHORIZATION_TOKEN[_FILE]
    (the file re-read on every refresh)."""

    http: httpx.Client | None = None
    env: OSEnv = field(default_factory=OSEnv)

    def configured(self) -> bool:
        return bool(self.env.getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI") or self.env.getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI"))

    def credentials(self, ctx: Context) -> AWSCredentials:
        rel = self.env.getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
        full = self.env.getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI")
        if rel:
            endpoint = _container_relative_endpoint(rel)
        elif full:
            _validate_container_uri(full)
            endpoint = full
        else:
            raise ValueError("no container credential endpoint in the environment")
        hdr: dict[str, str] = {}
        tf = self.env.getenv("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE")
        if tf:
            try:
                data = self.env.read_file(tf)
            except Exception as e:
                if is_panic_type(e):
                    raise
                raise ValueError(f"container authorization token file: {_read_err(e, tf)}") from e
            hdr["Authorization"] = go_trim_space(data.decode("utf-8", "replace"))
        elif self.env.getenv("AWS_CONTAINER_AUTHORIZATION_TOKEN"):
            hdr["Authorization"] = self.env.getenv("AWS_CONTAINER_AUTHORIZATION_TOKEN")
        assert self.http is not None
        try:
            resp = self.http.do(ctx, httpx.Request(method="GET", path=endpoint, header=hdr))
        except Exception as e:
            raise ValueError(f"container credentials: {e}") from e
        return _decode_creds(resp.body, "container credentials")


@dataclass
class WebIdentityProvider:
    """IRSA: AWS_ROLE_ARN, AWS_WEB_IDENTITY_TOKEN_FILE, AWS_ROLE_SESSION_NAME."""

    sts: STSClient | None = None
    env: OSEnv = field(default_factory=OSEnv)

    def configured(self) -> bool:
        return bool(self.env.getenv("AWS_ROLE_ARN") and self.env.getenv("AWS_WEB_IDENTITY_TOKEN_FILE"))

    def credentials(self, ctx: Context) -> AWSCredentials:
        arn = self.env.getenv("AWS_ROLE_ARN")
        f = self.env.getenv("AWS_WEB_IDENTITY_TOKEN_FILE")
        if not arn or not f:
            raise ValueError("AWS_ROLE_ARN and AWS_WEB_IDENTITY_TOKEN_FILE are not set")
        try:
            tok = self.env.read_file(f)
        except Exception as e:
            if is_panic_type(e):
                raise
            raise ValueError(f"web identity token: {_read_err(e, f)}") from e
        name = self.env.getenv("AWS_ROLE_SESSION_NAME") or session_name("hallpass")
        assert self.sts is not None
        return self.sts.assume_role_with_web_identity(ctx, arn, name, go_trim_space(tok.decode("utf-8", "replace")))


@dataclass
class IMDSProvider:
    """Instance role credentials with IMDSv2."""

    http: httpx.Client | None = None
    # Defaults to http://169.254.169.254.
    base: str = ""

    def credentials(self, ctx: Context) -> AWSCredentials:
        base = self.base or "http://169.254.169.254"
        assert self.http is not None
        try:
            tok_resp = self.http.do(
                ctx, httpx.Request(method="PUT", path=base + "/latest/api/token", header={"X-aws-ec2-metadata-token-ttl-seconds": "21600"}, idempotent=True)
            )
        except Exception as e:
            raise ValueError(f"imds token: {e}") from e
        token = go_trim_space(tok_resp.body.decode("utf-8", "replace"))
        if not token:
            raise ValueError("imds: empty token")
        hdr = {"X-aws-ec2-metadata-token": token}
        try:
            role_resp = self.http.do(ctx, httpx.Request(method="GET", path=base + "/latest/meta-data/iam/security-credentials/", header=hdr))
        except Exception as e:
            raise ValueError(f"imds role: {e}") from e
        role = go_trim_space(role_resp.body.decode("utf-8", "replace").split("\n", 1)[0])
        if not role:
            raise ValueError("imds: no instance role")
        try:
            cred_resp = self.http.do(
                ctx, httpx.Request(method="GET", path=base + "/latest/meta-data/iam/security-credentials/" + httpx.path_escape(role), header=hdr)
            )
        except Exception as e:
            raise ValueError(f"imds credentials: {e}") from e
        return _decode_creds(cred_resp.body, "imds credentials")


@dataclass
class EnvProvider:
    """AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN."""

    env: OSEnv = field(default_factory=OSEnv)

    def configured(self) -> bool:
        return bool(self.env.getenv("AWS_ACCESS_KEY_ID") and self.env.getenv("AWS_SECRET_ACCESS_KEY"))

    def credentials(self, ctx: Context) -> AWSCredentials:
        if not self.configured():
            raise ValueError("AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are not set")
        return AWSCredentials(self.env.getenv("AWS_ACCESS_KEY_ID"), self.env.getenv("AWS_SECRET_ACCESS_KEY"), self.env.getenv("AWS_SESSION_TOKEN"))


def ambient_provider(mode: str, env: OSEnv, plain: httpx.Client, sts: STSClient, imds_base: str = "") -> CredentialProvider:
    """auto: env keys, then container, then web identity, then IMDS;
    container, web_identity or imds: that source only. Cached and refreshed
    before expiry."""
    fetch: Callable[[Context], AWSCredentials]
    if mode == "container":
        fetch = ContainerProvider(plain, env).credentials
    elif mode == "web_identity":
        fetch = WebIdentityProvider(sts, env).credentials
    elif mode == "imds":
        fetch = IMDSProvider(plain, imds_base).credentials
    elif mode in ("auto", ""):
        if EnvProvider(env).configured():
            return EnvProvider(env)
        if ContainerProvider(env=env).configured():
            fetch = ContainerProvider(plain, env).credentials
        elif WebIdentityProvider(env=env).configured():
            fetch = WebIdentityProvider(sts, env).credentials
        else:
            fetch = IMDSProvider(plain, imds_base).credentials
    else:
        raise ValueError(f"unknown ambient credential mode {go_quote(mode)}")
    return CachedProvider(fetch)
