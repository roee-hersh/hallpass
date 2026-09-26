"""Port of internal/authx/rfc7515_vector_test.go and the TestRFC7515A2
test in jwt_test.go that uses it.

RFC 7515 Appendix A.2: "Example JWS Using RSASSA-PKCS1-v1_5 SHA-256".
Header {"alg":"RS256"}, payload {"iss":"joe",\\r\\n "exp":1300819380,\\r\\n
"http://example.com/is_root":true}, and the RFC's RSA key.
"""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from hallpass.authx.jwt import RS256, sign

RFC_A2_HEADER = "eyJhbGciOiJSUzI1NiJ9"
RFC_A2_PAYLOAD = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
RFC_A2_SIGNATURE = (
    "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9"
    "uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB"
    "_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rq"
    "Vt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw"
)
RFC_KEY_N = (
    "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yR"
    "T-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXB"
    "dQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9ia"
    "GNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ"
)
RFC_KEY_D = (
    "Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46su"
    "i395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4"
    "qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB"
    "4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ"
)
RFC_KEY_P = (
    "4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8"
    "cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc"
)
RFC_KEY_Q = (
    "uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t"
    "62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc"
)


def _b64int(s: str) -> int:
    """base64.RawURLEncoding.DecodeString into a big.Int."""
    return int.from_bytes(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)), "big")


def test_rfc7515_a2() -> None:
    """Sign the RFC 7515 Appendix A.2 example with its key and check the
    signature byte for byte. RS256 is deterministic, so the signature must
    match the RFC exactly."""
    if RFC_KEY_N == "":
        pytest.skip("vector not vendored")
    n, d, p, q = _b64int(RFC_KEY_N), _b64int(RFC_KEY_D), _b64int(RFC_KEY_P), _b64int(RFC_KEY_Q)
    # Go: key.Precompute().
    key = rsa.RSAPrivateNumbers(
        p=p,
        q=q,
        d=d,
        dmp1=rsa.rsa_crt_dmp1(d, p),
        dmq1=rsa.rsa_crt_dmq1(d, q),
        iqmp=rsa.rsa_crt_iqmp(p, q),
        public_numbers=rsa.RSAPublicNumbers(65537, n),
    ).private_key()
    signing_input = RFC_A2_HEADER + "." + RFC_A2_PAYLOAD
    sig = sign(key, RS256, signing_input.encode())
    got = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
    assert got == RFC_A2_SIGNATURE, f"signature mismatch\n got {got}\nwant {RFC_A2_SIGNATURE}"
