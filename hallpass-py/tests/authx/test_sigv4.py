"""Port of internal/authx/sigv4_test.go and sigv4_target_test.go."""

from __future__ import annotations

import dataclasses
import datetime
import os

import pytest

from hallpass.authx.sigv4 import AWSCredentials, SigV4Signer
from hallpass.net.httpx import Headers, PreparedRequest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "testdata", "aws-sig-v4-test-suite")
CREDS = AWSCredentials(access_key_id="AKIDEXAMPLE", secret_access_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY")
SIGNER = SigV4Signer(region="us-east-1", service="service")


def _cases() -> list[str]:
    """Every suite directory with a .req file, as the Go test walks them."""
    out = []
    for name in sorted(os.listdir(ROOT)):
        if os.path.isdir(os.path.join(ROOT, name)) and os.path.isfile(os.path.join(ROOT, name, name + ".req")):
            out.append(name)
    return out


CASES = _cases()


def test_sig_v4_suite_has_cases() -> None:
    """Go: TestSigV4Suite fails when fewer than 20 cases are found."""
    assert len(CASES) >= 20, f"only {len(CASES)} suite cases found"


@pytest.mark.parametrize("name", CASES)
def test_sig_v4_suite(name: str) -> None:
    """The official AWS Signature Version 4 test suite (vendored under
    testdata/aws-sig-v4-test-suite from botocore). Each case has the raw
    request (.req), the expected canonical request (.creq), string to sign
    (.sts) and Authorization header (.authz). Credentials, region and
    service are those the suite documents."""
    with open(os.path.join(ROOT, name, name + ".req"), "rb") as f:
        raw = f.read()
    req, body = parse_raw_request(raw)
    if name == "post-sts-header-before":
        # The token is part of the signed headers in this case.
        creds = dataclasses.replace(CREDS, session_token=req.headers.get("X-Amz-Security-Token"))
        check_case(name, SIGNER, req, body, creds)
        return
    if name == "post-sts-header-after":
        # The token header is added after signing and must not be signed.
        check_case(name, SIGNER, req, body, CREDS)
        return
    check_case(name, SIGNER, req, body, CREDS)


def check_case(name: str, signer: SigV4Signer, req: PreparedRequest, body: bytes, creds: AWSCredentials) -> None:
    def want(ext: str) -> str | None:
        try:
            with open(os.path.join(ROOT, name, name + "." + ext), "rb") as f:
                b = f.read()
        except OSError:
            return None
        # The vectors carry no carriage returns; a checkout with CRLF
        # conversion must not change what they mean.
        return b.decode("utf-8").replace("\r", "")

    errors = []
    creq, _ = signer.canonical_request(req, body)
    w = want("creq")
    if w is not None and creq != w:
        errors.append(f"canonical request mismatch\n got:\n{creq}\nwant:\n{w}")
    amz_date = req.headers.get("X-Amz-Date")
    sts = signer.string_to_sign(amz_date, creq)
    w = want("sts")
    if w is not None and sts != w:
        errors.append(f"string to sign mismatch\n got:\n{sts}\nwant:\n{w}")
    ts = datetime.datetime.strptime(amz_date, "%Y%m%dT%H%M%SZ").replace(tzinfo=datetime.timezone.utc)
    signer.sign_at(req, body, creds, ts)
    w = want("authz")
    if w is not None and req.headers.get("Authorization") != w:
        errors.append(f"authorization mismatch\n got: {req.headers.get('Authorization')}\nwant: {w}")
    assert not errors, "\n".join(errors)


def parse_raw_request(raw: bytes) -> tuple[PreparedRequest, bytes]:
    """The suite's raw HTTP request. The suite uses non-canonical forms
    (duplicate headers, odd whitespace, unencoded paths) that an HTTP parser
    would normalise, so it is parsed by hand."""
    pos = 0

    def read_line() -> tuple[str, bool]:
        """bufio.Reader.ReadString('\\n'): the line and whether EOF ended it."""
        nonlocal pos
        i = raw.find(b"\n", pos)
        if i < 0:
            line, pos = raw[pos:], len(raw)
            return line.decode("utf-8"), True
        line, pos = raw[pos : i + 1], i + 1
        return line.decode("utf-8"), False

    line, _ = read_line()
    line = line.rstrip("\r\n")
    parts = line.split(" ", 2)
    assert len(parts) >= 2, f"bad request line {line!r}"
    method, target = parts[0], parts[1]
    # The request-target is used verbatim: the signer must normalise it.
    url = parse_target(target)
    headers = Headers()
    last_key = ""
    while True:
        line, eof = read_line()
        line = line.rstrip("\r\n")
        if line == "":
            break
        if line.startswith(" ") or line.startswith("\t"):
            # Continuation line of a multiline header value.
            vals = headers.values(last_key)
            vals[-1] += "\n" + line.lstrip(" \t")
            headers.delete(last_key)
            for v in vals:
                headers.add(last_key, v)
            if eof:
                break
            continue
        k, sep, v = line.partition(":")
        assert sep, f"bad header line {line!r}"
        # Headers canonicalises the key; a Host header is the request's
        # host (Go sets req.Host from it).
        last_key = k
        headers.add(k, v)
        if eof:
            break
    return PreparedRequest(method=method, url=url, headers=headers), raw[pos:]


def parse_target(target: str) -> str:
    """The raw request-target as a URL whose path and query keep the
    original bytes, so the signer's normalisation is what gets tested.
    (Go builds a url.URL with RawPath set; the signer here reads the raw
    path from the URL string, and emulates Go's EscapedPath itself. No
    suite target carries a "#", which urlsplit would cut off.)"""
    return "https://example.amazonaws.com" + target
