"""Google service-account plumbing shared by the googleworkspace and
googlecloud integrations: the key JSON, the GCE metadata token and the
reason field of a Google API error."""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from hallpass.authx.jwt import parse_rsa_private_key
from hallpass.authx.oauth2 import parse_expires_in
from hallpass.authx.token import Token
from hallpass.authx.util import RAW, STR, go_unmarshal
from hallpass.core.context import Context
from hallpass.core.decision import Code, errorf, wrap_error
from hallpass.core.errors import as_error
from hallpass.net import httpx

__all__ = ["GoogleServiceAccountKey", "google_error_reason", "google_metadata_token", "google_reason_in", "parse_google_service_account_key"]


@dataclass
class GoogleServiceAccountKey:
    client_email: str
    private_key_id: str
    # The key's token endpoint, usually https://oauth2.googleapis.com/token; may be empty.
    token_uri: str
    key: Any


_EMAIL_RE = re.compile(r"[A-Za-z0-9!#$%&'*+/=?^_{|}~.-]{1,64}@[A-Za-z0-9.-]{1,255}")


def parse_google_service_account_key(raw: str) -> GoogleServiceAccountKey:
    """Decode a service-account key JSON. Every failure is a
    credential_rejected error whose text never quotes the key."""
    k, err = go_unmarshal(raw, (("client_email", STR), ("private_key", STR), ("private_key_id", STR), ("token_uri", STR)))
    if err is not None:
        raise wrap_error(Code.CREDENTIAL_REJECTED, ValueError(err), "credential is not a service-account key JSON")
    if not _EMAIL_RE.fullmatch(k["client_email"]) or k["private_key"] == "":
        raise errorf(Code.CREDENTIAL_REJECTED, "the service-account key JSON lacks client_email or private_key")
    try:
        key = parse_rsa_private_key(k["private_key"].encode("utf-8"))
    except ValueError as e:
        raise wrap_error(Code.CREDENTIAL_REJECTED, e, "the service-account private_key is not a PEM RSA key") from e
    return GoogleServiceAccountKey(k["client_email"], k["private_key_id"], k["token_uri"], key)


def google_metadata_token(ctx: Context, c: httpx.Client, metadata_url: str, now: Callable[[], float] | None = None) -> Token:
    """The attached service account's access token from the GCE metadata
    server (http://metadata.google.internal in production)."""
    now = now or time.time
    try:
        resp = c.do(
            ctx,
            httpx.Request(
                method="GET",
                path=metadata_url + "/computeMetadata/v1/instance/service-accounts/default/token",
                header={"Metadata-Flavor": "Google"},
            ),
        )
    except Exception as e:
        raise wrap_error(Code.CREDENTIAL_REJECTED, e, "the metadata server gave no token; auth_mode keyless needs a GCE or GKE Workload Identity") from e
    out, err = go_unmarshal(resp.body, (("access_token", STR), ("expires_in", RAW)), stream=True)
    if err is not None or out["access_token"] == "":
        raise errorf(Code.CREDENTIAL_REJECTED, "the metadata server returned no access_token")
    secs = parse_expires_in(out["expires_in"])
    return Token(out["access_token"], now() + secs if secs > 0 else None)


# RE2's \s is ASCII [\t\n\f\r ]; Python's matches any Unicode space.
_REASON_RE = re.compile(r'"reason"[\t\n\f\r ]*:[\t\n\f\r ]*"([A-Za-z_]+)"')


def google_error_reason(err: BaseException | None) -> str:
    """The first errors[].reason or details[].reason in the body snippet of
    a Google API error, or "". Only the reason token; never the message."""
    se = as_error(err, httpx.StatusError)
    if se is None:
        return ""
    return google_reason_in(se.snippet)


def google_reason_in(body: str) -> str:
    m = _REASON_RE.search(body)
    return m.group(1) if m else ""
