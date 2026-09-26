"""The Atlassian Cloud transport (Site) that the jira and confluence
integrations share: the three auth modes (basic, scoped_token,
oauth_client) and cloud id discovery."""

from __future__ import annotations

import dataclasses
import re
import threading
import time
from collections.abc import Callable, Mapping
from typing import Any

from hallpass.authx.oauth2 import TokenRequest, classify_token_error, fetch_token
from hallpass.authx.token import Token, TokenSource
from hallpass.core import jsonx
from hallpass.core.context import Context
from hallpass.core.decision import Code, errorf
from hallpass.core.errors import go_quote
from hallpass.core.integration import Deps, Field, Settings, credential_field, url_field
from hallpass.core.secret import Secret
from hallpass.net import httpx

__all__ = [
    "GATEWAY",
    "MODE_BASIC",
    "MODE_OAUTH_CLIENT",
    "MODE_SCOPED_TOKEN",
    "TOKEN_URL",
    "Site",
    "new_site",
    "site_fields",
]

# The Atlassian API gateway that scoped_token and oauth_client connections
# talk to, as https://api.atlassian.com/ex/<product>/<cloudId>. Read when a
# connection is built; tests point it at a fake server (monkeypatch).
GATEWAY = "https://api.atlassian.com"

# The OAuth 2.0 token endpoint used by oauth_client connections. Read when a
# connection is built; tests point it at a fake server (monkeypatch).
TOKEN_URL = "https://auth.atlassian.com/oauth/token"

# Auth modes.
MODE_BASIC = "basic"
MODE_SCOPED_TOKEN = "scoped_token"
MODE_OAUTH_CLIENT = "oauth_client"


def site_fields() -> list[Field]:
    """The connection keys every Atlassian Cloud integration accepts: url,
    auth_mode, username, credential and client_id."""
    return [
        url_field(True, "site URL, e.g. https://acme.atlassian.net"),
        Field(
            name="auth_mode",
            default=MODE_BASIC,
            enum=(MODE_BASIC, MODE_SCOPED_TOKEN, MODE_OAUTH_CLIENT),
            description=(
                "basic: email + API token against the site; scoped_token: scoped API token against api.atlassian.com; "
                "oauth_client: OAuth 2.0 client credentials"
            ),
        ),
        Field(name="username", description="email of the bot account (required for auth_mode basic)"),
        credential_field(True, "API token (basic, scoped_token) or OAuth client secret (oauth_client)"),
        Field(name="client_id", description="OAuth 2.0 client id (required for auth_mode oauth_client)"),
    ]


# Go: ^[A-Za-z0-9-]{1,128}$, matched in full.
_CLOUD_ID_RE = re.compile(r"[A-Za-z0-9-]{1,128}")


class Site:
    """One Atlassian Cloud site reached with one auth mode. A jira and a
    confluence connection each own one. Relative request paths are resolved
    against the site URL (basic) or the gateway (scoped_token,
    oauth_client), where the cloud id is discovered once and cached."""

    def __init__(self, url: str, mode: str, product: str, gateway: str, token_url: str, now: Callable[[], float]) -> None:
        # The site URL without a trailing slash.
        self.url = url
        # The auth mode.
        self.mode = mode
        # The gateway product segment: "jira" or "confluence".
        self.product = product
        self._gateway = gateway
        self._token_url = token_url
        self._now = now
        self._client: httpx.Client = httpx.Client()  # authenticated; set by new_site
        self._plain: httpx.Client = httpx.Client()  # unauthenticated: tenant_info and the token endpoint
        self._lock = threading.Lock()
        self._cloud_id = ""

    def _fetch_token(self, client_id: str, cred: Secret) -> Callable[[Context], Token]:
        """The OAuth 2.0 client credentials grant as Atlassian's token
        endpoint takes it: a JSON body with an audience. The response is the
        standard one, decoded by fetch_token; a failure is a TokenError whose
        message never carries error_description."""

        def fetch(ctx: Context) -> Token:
            sec = cred.get_string()
            # UNVERIFIED: Atlassian's client credentials grant is documented
            # here as a JSON body with audience api.atlassian.com; the exact
            # shape is not verified against a live token endpoint.
            body = {
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": sec,
                "audience": "api.atlassian.com",
            }
            return fetch_token(ctx, self._plain, TokenRequest(url=self._token_url, json=body, now=self._now))

        return fetch

    def cloud_id(self, ctx: Context) -> str:
        """The site's cloud id, discovered on first use from
        GET {url}/_edge/tenant_info."""
        with self._lock:
            if self._cloud_id != "":
                return self._cloud_id
            try:
                _, v = self._plain.get_json(ctx, self.url + "/_edge/tenant_info")
                cid = jsonx.s(jsonx.obj(v), "cloudId")
            except Exception as e:
                raise _classify(e) from e
            if not _CLOUD_ID_RE.fullmatch(cid):
                raise errorf(Code.UPSTREAM_ERROR, "tenant_info returned no usable cloudId")
            self._cloud_id = cid
            return cid

    def base(self, ctx: Context) -> str:
        """The URL relative paths are resolved against: the site URL for
        basic, or {gateway}/ex/{product}/{cloudId} for the token modes."""
        if self.mode == MODE_BASIC:
            return self.url
        cid = self.cloud_id(ctx)
        return self._gateway + "/ex/" + self.product + "/" + httpx.path_escape(cid)

    def client(self) -> httpx.Client:
        """The authenticated HTTP client. Requests through it must use
        absolute paths; resolve builds them."""
        return self._client

    def resolve(self, ctx: Context, path: str) -> str:
        """A site-relative path as an absolute URL."""
        if path.startswith("https://") or path.startswith("http://"):
            return path
        return self.base(ctx) + "/" + path.lstrip("/")

    def do(self, ctx: Context, r: httpx.Request) -> httpx.Response:
        """One request, a relative path resolved against base."""
        p = self.resolve(ctx, r.path)
        return self._client.do(ctx, dataclasses.replace(r, path=p))

    def get_json(self, ctx: Context, path: str, q: Mapping[str, str | list[str]] | None = None) -> tuple[httpx.Response, Any]:
        """do + JSON decode for a GET."""
        p = self.resolve(ctx, path)
        return self._client.get_json(ctx, p, q)

    def post_json(self, ctx: Context, path: str, body: Any, idempotent: bool = False) -> tuple[httpx.Response, Any]:
        """do + JSON decode for a POST with a JSON body."""
        p = self.resolve(ctx, path)
        return self._client.post_json(ctx, p, body, idempotent)


def _classify(e: BaseException) -> Exception:
    out = httpx.classify(e)
    assert out is not None
    return out


def new_site(s: Settings, d: Deps, product: str) -> Site:
    """The transport for one connection. It does not touch the network."""
    hc = d.http_client(s)
    cred = s.secret("credential")
    if cred.is_zero():
        raise ValueError("credential is required")
    mode = s.get("auth_mode")
    if mode == "":
        mode = MODE_BASIC
    site = Site(
        url=s.get("url").rstrip("/"),
        mode=mode,
        product=product,
        gateway=GATEWAY.rstrip("/"),
        token_url=TOKEN_URL,
        now=d.now if callable(d.now) else time.time,
    )
    site._plain = httpx.Client(http=hc, logger=d.logger)

    def secret_string(ctx: Context) -> str:
        return cred.get_string()

    auth: httpx.AuthFunc
    if mode == MODE_BASIC:
        user = s.get("username")
        if user == "":
            raise ValueError("username is required for auth_mode basic")
        auth = httpx.basic_auth(user, secret_string)
    elif mode == MODE_SCOPED_TOKEN:
        auth = httpx.bearer_auth(secret_string)
    elif mode == MODE_OAUTH_CLIENT:
        client_id = s.get("client_id")
        if client_id == "":
            raise ValueError("client_id is required for auth_mode oauth_client")
        ts = TokenSource(fetch=site._fetch_token(client_id, cred), now=site._now)

        def token(ctx: Context) -> str:
            try:
                return ts.get(ctx)
            except Exception as e:
                raise classify_token_error(e) from e

        auth = httpx.bearer_auth(token)
    else:
        raise ValueError(f"auth_mode {go_quote(mode)} must be basic, scoped_token or oauth_client")
    site._client = httpx.Client(http=hc, logger=d.logger, auth=auth)
    return site
