"""Credential material that must never be printed.

A Secret is created from a reference such as ``env:NAME`` or ``file:/path``.
The value is resolved on every get() call, so a rotated file (a projected
Kubernetes ServiceAccount token, for example) keeps working without a
restart. str(), repr(), format() and pickling never reveal the value.
"""

from __future__ import annotations

import os
from typing import NoReturn

from hallpass.core.errors import go_quote, path_error_text

__all__ = ["REDACTED", "EmptySecretError", "Secret", "SecretError", "env", "file", "literal", "must_parse", "parse"]

REDACTED = "[REDACTED]"


class SecretError(ValueError):
    pass


class EmptySecretError(SecretError):
    """get() on the empty Secret (Go's secret.ErrEmpty)."""


class Secret:
    """A reference to credential material. ``Secret()`` is empty."""

    __slots__ = ("_kind", "_ref")

    def __init__(self, _kind: str = "", _ref: str = "") -> None:
        object.__setattr__(self, "_kind", _kind)
        object.__setattr__(self, "_ref", _ref)

    def __setattr__(self, name: str, value: object) -> NoReturn:
        raise AttributeError("Secret is immutable")

    def is_zero(self) -> bool:
        return self._kind == ""

    def ref(self) -> str:
        """Where the secret comes from without revealing it: "env:JIRA_TOKEN",
        "file:/secrets/token", or "literal"."""
        if self._kind in ("env", "file"):
            return f"{self._kind}:{self._ref}"
        if self._kind == "literal":
            return "literal"
        return ""

    def get(self) -> bytes:
        """Resolve the secret. File secrets are read on every call and
        trailing whitespace is trimmed, matching how tokens are mounted."""
        if self._kind == "env":
            v = os.environ.get(self._ref)
            if v is None:
                raise SecretError(f"secret: environment variable {self._ref} is not set")
            if v == "":
                raise SecretError(f"secret: environment variable {self._ref} is empty")
            return v.encode("utf-8", "surrogateescape")
        if self._kind == "file":
            try:
                with open(self._ref, "rb") as f:
                    b = f.read()
            except (OSError, ValueError) as e:
                # Go's os.ReadFile error, wrapped: "open /p: no such file or
                # directory"; a directory opens and then fails to read.
                op = "read" if isinstance(e, IsADirectoryError) else "open"
                raise SecretError(f"secret: read {self._ref}: {path_error_text(op, self._ref, e)}") from e
            b = b.rstrip(b" \t\r\n")
            if not b:
                raise SecretError(f"secret: file {self._ref} is empty")
            return b
        if self._kind == "literal":
            return self._ref.encode("utf-8", "surrogateescape")
        raise EmptySecretError("secret: empty")

    def get_string(self) -> str:
        return self.get().decode("utf-8", "surrogateescape")

    def __str__(self) -> str:
        return REDACTED

    def __repr__(self) -> str:
        return "Secret(" + REDACTED + ")"

    def __format__(self, spec: str) -> str:
        return REDACTED

    def __reduce__(self) -> NoReturn:
        raise TypeError("a Secret cannot be pickled")

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Secret) and self._kind == other._kind and self._ref == other._ref

    def __hash__(self) -> int:
        return hash((self._kind, self._ref))

    def __bool__(self) -> bool:
        return not self.is_zero()


def parse(ref: str) -> Secret:
    """Turn a config reference into a Secret.

    Accepted forms: ``env:NAME`` and ``file:/path``. Anything else is
    rejected so a plain credential can never be written into the config
    file by mistake.
    """
    if ref.startswith("env:"):
        name = ref[len("env:") :]
        if name == "" or any(c in name for c in " \t="):
            raise SecretError(f"secret: invalid environment variable name in {go_quote(ref)}")
        return Secret("env", name)
    if ref.startswith("file:"):
        path = ref[len("file:") :]
        if path == "":
            raise SecretError(f"secret: empty file path in {go_quote(ref)}")
        return Secret("file", path)
    if ref == "":
        raise SecretError("secret: empty reference")
    raise SecretError("secret: value must be a reference of the form env:NAME or file:/path, not an inline secret")


def must_parse(ref: str) -> Secret:
    return parse(ref)


def literal(value: str) -> Secret:
    """Wrap an in-memory value: an exchanged token, or a credential an
    application passes in code. Config files never produce one."""
    return Secret("literal", value)


def env(name: str) -> Secret:
    """``env:NAME`` as a Secret, for connections configured in code."""
    return parse("env:" + name)


def file(path: str) -> Secret:
    """``file:/path`` as a Secret, for connections configured in code."""
    return parse("file:" + path)
