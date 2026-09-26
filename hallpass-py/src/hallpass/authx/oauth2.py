"""OAuth 2.0 token exchanges: client credentials (secret or signed
assertion) and the JWT bearer grant."""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from hallpass.authx.token import Token
from hallpass.authx.util import RAW, STR, go_unmarshal
from hallpass.core.context import Context
from hallpass.core.decision import Code, HallpassError, wrap_error
from hallpass.core.errors import as_error
from hallpass.net import httpx

__all__ = [
    "TokenError",
    "TokenRequest",
    "classify_token_error",
    "client_assertion",
    "client_credentials",
    "fetch_token",
    "jwt_bearer",
    "parse_expires_in",
    "post_token",
]


class TokenError(Exception):
    """A token endpoint failure."""

    def __init__(self, status: int, code: str = "", desc: str = "") -> None:
        self.status = status
        # The OAuth error code, such as invalid_grant or invalid_client.
        self.code = code
        # error_description, truncated. Never put it in a decision text.
        self.desc = desc
        super().__init__(str(self))

    def __str__(self) -> str:
        # The status and code only: the description is an upstream string
        # that may echo request data.
        s = f"token endpoint: HTTP {self.status}"
        if self.code:
            s += " " + self.code
        return s

    def is_credential_error(self) -> bool:
        """The client credential itself was rejected (not a transient failure)."""
        if self.code in ("invalid_client", "invalid_grant", "unauthorized_client", "invalid_request", "access_denied"):
            return True
        return self.status in (400, 401, 403)


def _truncate(s: str, n: int) -> str:
    b = s.encode("utf-8")
    if len(b) > n:
        return b[:n].decode("utf-8", "ignore") + "..."
    return s


@dataclass
class TokenRequest:
    # The token endpoint, absolute or relative to the client's base.
    url: str
    # The URL-encoded body OAuth 2.0 specifies, or a JSON body for endpoints
    # that take one instead (Atlassian). Exactly one is set.
    form: Mapping[str, str | list[str]] | None = None
    json: Any = None
    # Extra request headers, such as a client Authorization.
    header: Mapping[str, str] | None = None
    # The clock the expiry is computed from (default time.time).
    now: Callable[[], float] | None = None


# The OAuth 2.0 token endpoint response (Go's tokenResponse).
_TOKEN_RESPONSE = (("access_token", STR), ("token_type", STR), ("expires_in", RAW), ("scope", STR), ("error", STR), ("error_description", STR))


def fetch_token(ctx: Context, c: httpx.Client, req: TokenRequest) -> Token:
    """Post a token request and decode the OAuth 2.0 token response. A
    failure is a TokenError (an error code or a 4xx status) or a transport
    error. The expiry is now plus expires_in; without expires_in it is None
    so the TokenSource's default TTL applies."""
    if (req.form is None) == (req.json is None):
        raise ValueError("token request must carry exactly one of a form or a JSON body")
    now = req.now or time.time
    resp = c.do(
        ctx,
        httpx.Request(method="POST", path=req.url, form=req.form, json=req.json, header=req.header, idempotent=False, accept_4xx=True),
    )
    # A body that does not decode leaves the fields empty, as in Go.
    tr, _ = go_unmarshal(resp.body, _TOKEN_RESPONSE)
    if resp.status >= 400 or tr["error"]:
        raise TokenError(resp.status, tr["error"], _truncate(tr["error_description"], 200))
    access = tr["access_token"]
    if access == "":
        raise ValueError("token endpoint returned no access_token")
    secs = parse_expires_in(tr["expires_in"])
    return Token(access, now() + secs if secs > 0 else None)


def post_token(ctx: Context, c: httpx.Client, token_url: str, form: Mapping[str, str | list[str]], header: Mapping[str, str] | None = None) -> Token:
    return fetch_token(ctx, c, TokenRequest(url=token_url, form=form, header=header))


def parse_expires_in(raw: Any) -> int:
    """A number or a numeric string (Salesforce and some Microsoft endpoints
    send strings); anything else is 0."""
    if raw is None or isinstance(raw, bool):
        return 0
    if isinstance(raw, int):
        return raw if raw > 0 else 0
    if isinstance(raw, str):
        # The digits of the raw JSON text only: " 3600" and "3600.0" are 0.
        return int(raw) if raw and raw.isascii() and raw.isdigit() else 0
    # Floats (3600.0, 1e3) are not digits in the raw text either.
    return 0


SecretFunc = Callable[[Context], str]


def client_credentials(c: httpx.Client, token_url: str, client_id: str, secret: SecretFunc, scope: str = "") -> Callable[[Context], Token]:
    """The client credentials grant with a client secret."""

    def fetch(ctx: Context) -> Token:
        form = {"grant_type": "client_credentials", "client_id": client_id, "client_secret": secret(ctx)}
        if scope:
            form["scope"] = scope
        return post_token(ctx, c, token_url, form)

    return fetch


def client_assertion(c: httpx.Client, token_url: str, client_id: str, assertion: SecretFunc, scope: str = "") -> Callable[[Context], Token]:
    """The client credentials grant authenticated with a signed JWT
    (RFC 7523 section 2.2), built at fetch time so its timestamps are fresh."""

    def fetch(ctx: Context) -> Token:
        form = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": assertion(ctx),
        }
        if scope:
            form["scope"] = scope
        return post_token(ctx, c, token_url, form)

    return fetch


def jwt_bearer(c: httpx.Client, token_url: str, assertion: SecretFunc, extra: Mapping[str, str] | None = None) -> Callable[[Context], Token]:
    """The JWT bearer grant (RFC 7523 section 2.1): Google service accounts,
    Salesforce."""

    def fetch(ctx: Context) -> Token:
        form: dict[str, str | list[str]] = {"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": assertion(ctx)}
        form.update(extra or {})
        return post_token(ctx, c, token_url, form)

    return fetch


def classify_token_error(err: BaseException) -> HallpassError:
    """Credential rejections become credential_rejected; everything else
    goes through httpx.classify."""
    te = as_error(err, TokenError)
    if te is not None:
        if te.is_credential_error():
            return wrap_error(Code.CREDENTIAL_REJECTED, err, f"the token endpoint rejected hallpass's credential ({te.code})")
        if te.status == 429:
            return wrap_error(Code.UPSTREAM_RATE_LIMIT, err, "the token endpoint rate limited hallpass")
        return wrap_error(Code.UPSTREAM_ERROR, err, f"the token endpoint failed (HTTP {te.status})")
    out = httpx.classify(err)
    assert out is not None
    return out
