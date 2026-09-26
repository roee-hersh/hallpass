"""Port of internal/authx/oauth2_test.go."""

from __future__ import annotations

import datetime
import json
import time

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from hallpass.authx.jwt import PS256, Header, decode_jwt_claims, sign_jwt, standard_claims
from hallpass.authx.oauth2 import TokenError, TokenRequest, classify_token_error, client_assertion, client_credentials, fetch_token, jwt_bearer, post_token
from hallpass.core.context import Context, background
from hallpass.core.decision import Code
from hallpass.core.errors import as_error
from hallpass.net import httpx
from tests import harness as itest


def _form_get(r: itest.Request) -> dict[str, str]:
    """r.ParseForm then r.Form.Get: the query and the URL-encoded body,
    first value of each key."""
    out: dict[str, str] = {}
    for src in (r.form(), r.query):
        for k, vs in src.items():
            if vs and k not in out:
                out[k] = vs[0]
    return out


def test_client_credentials_and_assertion(srv: itest.Server) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def token(w: itest.ResponseWriter, r: itest.Request) -> None:
        f = _form_get(r)
        g = f.get
        if g("grant_type") == "client_credentials" and g("client_secret") == itest.CANARY + "secret":
            w.write(json.dumps({"access_token": itest.CANARY + "access", "expires_in": 3600, "token_type": "Bearer"}) + "\n")
        elif g("grant_type") == "client_credentials" and g("client_assertion", "") != "":
            parts = g("client_assertion", "").split(".")
            if len(parts) != 3:
                w.write_header(400)
                return
            try:
                claims = decode_jwt_claims(g("client_assertion", ""))
            except ValueError:
                claims = {}
            if not isinstance(claims, dict) or claims.get("iss") != "app" or claims.get("aud") != srv.url + "/token":
                w.write_header(400)
                w.write(b'{"error":"invalid_client","error_description":"bad assertion"}')
                return
            w.write(json.dumps({"access_token": "assert-tok", "expires_in": "1800"}) + "\n")
        elif g("grant_type") == "urn:ietf:params:oauth:grant-type:jwt-bearer":
            w.write(json.dumps({"access_token": "bearer-tok"}) + "\n")
        else:
            w.write_header(401)
            w.write('{"error":"invalid_client","error_description":"' + itest.CANARY + 'bad"}')

    srv.handle("POST", "/token", token)
    deps, _logs = itest.deps(srv)
    hc = deps.http_client(itest.settings("x", "x"))
    c = httpx.Client(http=hc, base=srv.url, logger=deps.logger)
    ctx = background()

    fetch = client_credentials(c, srv.url + "/token", "cid", lambda _ctx: itest.CANARY + "secret", "api://x/.default")
    tok = fetch(ctx)
    assert tok.value == itest.CANARY + "access" and tok.expiry is not None and tok.expiry - time.time() >= 59 * 60, tok
    call = srv.last_call()
    assert call.header.get("Content-Type") == "application/x-www-form-urlencoded" and call.q("client_secret") == "", f"form encoding: {call.header}"

    fetch = client_credentials(c, srv.url + "/token", "cid", lambda _ctx: "wrong", "")
    with pytest.raises(Exception) as ei:
        fetch(ctx)
    err = ei.value
    ie = classify_token_error(err)
    assert ie.code == Code.CREDENTIAL_REJECTED, f"wrong secret -> {ie}"
    assert itest.CANARY not in str(err), "token error leaked the description containing the canary"

    def assertion(_ctx: Context) -> str:
        return sign_jwt(key, Header(alg=PS256, x5t_s256="thumb"), standard_claims(iss="app", sub="app", aud=srv.url + "/token", exp=int(time.time() + 5 * 60)))

    fetch = client_assertion(c, srv.url + "/token", "app", assertion, "")
    tok = fetch(ctx)
    assert tok.value == "assert-tok" and tok.expiry is not None and tok.expiry - time.time() >= 29 * 60, f"assertion: {tok}"

    fetch = jwt_bearer(c, srv.url + "/token", lambda _ctx: "a.b.c", {"extra": ["1"]})
    tok = fetch(ctx)
    assert tok.value == "bearer-tok" and tok.expiry is None, f"bearer: {tok}"
    assert b"extra=1" in srv.last_call().body, "extra form values"
    srv.fail(itest.Failure.SERVER_ERROR)
    with pytest.raises(Exception) as ei:
        fetch(ctx)
    assert classify_token_error(ei.value).code == Code.UPSTREAM_ERROR, f"500 -> {classify_token_error(ei.value)}"
    srv.fail(itest.Failure.NONE)


def test_fetch_token_json_and_clock(srv: itest.Server) -> None:
    """fetch_token posts a JSON body when asked, decodes the standard
    response, computes the expiry from the injected clock, and keeps
    error_description out of the error message."""

    def json_token(w: itest.ResponseWriter, r: itest.Request) -> None:
        if r.header.get("Content-Type") != "application/json":
            w.write_header(415)
            return
        try:
            body = r.json()
            ok = isinstance(body, dict) and all(isinstance(v, str) for v in body.values())
        except ValueError:
            ok = False
        if not ok or body.get("grant_type") != "client_credentials" or body.get("audience") != "api.example":
            w.write_header(400)
            w.write(b'{"error":"invalid_request"}')
            return
        secret = body.get("client_secret")
        if secret == itest.CANARY + "secret":
            w.write(json.dumps({"access_token": itest.CANARY + "access", "expires_in": "3600", "token_type": "Bearer"}) + "\n")
        elif secret == "no-expiry":
            w.write(json.dumps({"access_token": "short"}) + "\n")
        else:
            w.write_header(401)
            w.write('{"error":"invalid_client","error_description":"' + itest.CANARY + 'bad"}')

    srv.handle("POST", "/json-token", json_token)
    deps, _ = itest.deps(srv)
    hc = deps.http_client(itest.settings("x", "x"))
    c = httpx.Client(http=hc, base=srv.url, logger=deps.logger)
    ctx = background()
    fixed = datetime.datetime(2031, 3, 1, 12, 0, 0, tzinfo=datetime.timezone.utc).timestamp()

    def clock() -> float:
        return fixed

    def body(secret: str) -> dict[str, str]:
        return {"grant_type": "client_credentials", "client_id": "cid", "client_secret": secret, "audience": "api.example"}

    tok = fetch_token(ctx, c, TokenRequest(url=srv.url + "/json-token", json=body(itest.CANARY + "secret"), now=clock))
    assert tok.value == itest.CANARY + "access", tok
    assert tok.expiry == fixed + 3600, f"expiry {tok.expiry}, want the injected clock plus 3600 s ({fixed + 3600})"
    ct = srv.last_call().header.get("Content-Type")
    assert ct == "application/json", f"content type {ct!r}"

    tok = fetch_token(ctx, c, TokenRequest(url=srv.url + "/json-token", json=body("no-expiry"), now=clock))
    assert tok.value == "short" and tok.expiry is None, f"no expires_in: {tok}"

    with pytest.raises(Exception) as ei:
        fetch_token(ctx, c, TokenRequest(url=srv.url + "/json-token", json=body("wrong"), now=clock))
    err = ei.value
    te = as_error(err, TokenError)
    assert te is not None and te.status == 401 and te.code == "invalid_client", f"wrong secret: {err}"
    assert itest.CANARY not in str(err) and itest.CANARY not in str(classify_token_error(err)), "the error message carries error_description"
    assert te.desc == itest.CANARY + "bad", f"Desc {te.desc!r}"
    assert classify_token_error(err).code == Code.CREDENTIAL_REJECTED, f"classified as {classify_token_error(err)}"

    # Exactly one body encoding.
    for req in (TokenRequest(url=srv.url + "/json-token"), TokenRequest(url=srv.url + "/json-token", form={"a": ["b"]}, json=body("x"))):
        with pytest.raises(Exception):  # noqa: B017 - any error
            fetch_token(ctx, c, req)
    n = len(srv.calls())
    assert n == 3, f"{n} calls, want 3: a malformed request must not reach the endpoint"

    # The wall clock applies when no clock is injected, and to post_token.
    def form_token(w: itest.ResponseWriter, r: itest.Request) -> None:
        if _form_get(r).get("grant_type") != "client_credentials":
            w.write_header(400)
            return
        w.write(json.dumps({"access_token": "form-tok", "expires_in": 600}) + "\n")

    srv.handle("POST", "/form-token", form_token)
    before = time.time()
    tok = post_token(ctx, c, srv.url + "/form-token", {"grant_type": ["client_credentials"]})
    assert tok.value == "form-tok" and tok.expiry is not None, f"post_token: {tok}"
    assert not (tok.expiry < before + 600 or tok.expiry > time.time() + 600), f"post_token: {tok}"
