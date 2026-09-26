"""Port of test/contract/key_test.go (Go: testRSAKey)."""

from __future__ import annotations

import functools

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


@functools.cache
def rsa_test_key() -> str:
    """A PKCS#1 RSA key generated once per process; contract tests never need
    a fixed key because the mock server does not verify signatures."""
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()).decode()
