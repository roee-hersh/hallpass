"""Port of internal/secret/secret_test.go."""

from __future__ import annotations

import io
import json
import logging
import pickle
import sys
from pathlib import Path

import pytest

from hallpass.core import secret
from hallpass.core.errors import is_error
from hallpass.core.log import JSONHandler, Logger, StdlibHandler, TextHandler
from hallpass.core.secret import EmptySecretError, Secret, SecretError

CANARY = "CANARY-SECRET-0f9d2a"


@pytest.mark.parametrize("ref", ["", "hunter2", "token:abc", "ENV:X"])
def test_parse_rejects_inline(ref: str) -> None:
    with pytest.raises(SecretError):
        secret.parse(ref)


def test_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HALLPASS_TEST_SECRET", CANARY)
    s = secret.parse("env:HALLPASS_TEST_SECRET")
    assert s.get_string() == CANARY
    assert s.ref() == "env:HALLPASS_TEST_SECRET"
    monkeypatch.delenv("HALLPASS_TEST_SECRET")
    with pytest.raises(SecretError):
        s.get()


def test_file_reread_and_trim(tmp_path: Path) -> None:
    p = tmp_path / "tok"
    p.write_bytes((CANARY + "\n").encode())
    s = secret.must_parse(f"file:{p}")
    assert s.get_string() == CANARY
    p.write_bytes((CANARY + "-rotated").encode())
    assert s.get_string() == CANARY + "-rotated", "file secret not re-read"


def test_never_prints() -> None:
    # Go: TestNeverPrints — fmt verbs, slog and encoding/json become str(),
    # repr(), format(), %-formatting, the hallpass log handlers, the stdlib
    # logging module and json.dumps (which cannot serialise a Secret, so
    # default=str stands in for MarshalJSON). Pickling is refused outright.
    s = secret.literal(CANARY)

    class Holder:
        def __init__(self, s: Secret) -> None:
            self.s = s

        def __repr__(self) -> str:
            return f"Holder(s={self.s!r})"

    buf = io.StringIO()
    Logger(JSONHandler(buf)).info("x", "secret", s, "list", [s], "map", {"k": s})
    tbuf = io.StringIO()
    Logger(TextHandler(tbuf)).info("x", secret=s)
    std = logging.getLogger("test_secret_never_prints")
    records: list[logging.LogRecord] = []

    class Collect(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    std.addHandler(Collect())
    std.setLevel(logging.DEBUG)
    Logger(StdlibHandler(std)).info("x", secret=s)
    std.info("%s %r", s, s)

    outputs = [
        str(s),
        repr(s),
        format(s),
        f"{s}",
        f"{s!r}",
        f"{s:>40}",
        "%s %r" % (s, s),  # noqa: UP031
        "{} {!r}".format(s, s),  # noqa: UP032
        repr(Holder(s)),
        str([s]),
        str({"s": s}),
        buf.getvalue(),
        tbuf.getvalue(),
        json.dumps({"s": s, "p": [s]}, default=str),
    ]
    outputs += [r.getMessage() for r in records]
    outputs += [json.dumps(getattr(r, "hallpass", {}), default=str) for r in records]
    for i, o in enumerate(outputs):
        assert CANARY not in o, f"output {i} leaked the secret: {o}"
    with pytest.raises(TypeError):
        pickle.dumps(s)
    with pytest.raises(EmptySecretError, match=r"^secret: empty$"):
        Secret().get()


# -- Behaviour pinned against the Go implementation ------------------------------


@pytest.mark.parametrize(
    ("ref", "want"),
    [
        ("", "secret: empty reference"),
        ("hunter2", "secret: value must be a reference of the form env:NAME or file:/path, not an inline secret"),
        ("env:", 'secret: invalid environment variable name in "env:"'),
        ("env:A B", 'secret: invalid environment variable name in "env:A B"'),
        ("env:A\tB", 'secret: invalid environment variable name in "env:A\\tB"'),
        ("env:A=B", 'secret: invalid environment variable name in "env:A=B"'),
        ("file:", 'secret: empty file path in "file:"'),
    ],
)
def test_parse_error_text(ref: str, want: str) -> None:
    with pytest.raises(SecretError) as ei:
        secret.parse(ref)
    assert str(ei.value) == want


def test_get_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HALLPASS_TEST_EMPTY", "")
    with pytest.raises(SecretError, match=r"^secret: environment variable HALLPASS_TEST_EMPTY is empty$"):
        secret.parse("env:HALLPASS_TEST_EMPTY").get()
    monkeypatch.delenv("HALLPASS_TEST_UNSET", raising=False)
    with pytest.raises(SecretError, match=r"^secret: environment variable HALLPASS_TEST_UNSET is not set$"):
        secret.parse("env:HALLPASS_TEST_UNSET").get()
    missing = tmp_path / "missing"
    with pytest.raises(SecretError) as ei:
        secret.parse(f"file:{missing}").get()
    # Go: fmt.Errorf("secret: read %s: %w", path, err) around os.ReadFile's *PathError.
    assert str(ei.value) == f"secret: read {missing}: open {missing}: no such file or directory"
    assert is_error(ei.value, FileNotFoundError)
    with pytest.raises(SecretError) as ei:
        secret.parse(f"file:{tmp_path}").get()
    if sys.platform == "win32":
        # Windows refuses to open a directory as a file.
        assert str(ei.value) == f"secret: read {tmp_path}: open {tmp_path}: permission denied"
    else:
        assert str(ei.value) == f"secret: read {tmp_path}: read {tmp_path}: is a directory"
    blank = tmp_path / "blank"
    blank.write_bytes(b" \t\r\n")
    with pytest.raises(SecretError, match=f"^secret: file {blank} is empty$"):
        secret.parse(f"file:{blank}").get()


def test_file_trims_only_trailing_whitespace(tmp_path: Path) -> None:
    p = tmp_path / "tok"
    p.write_bytes(b"  a b\xff \t\r\n")
    assert secret.parse(f"file:{p}").get() == b"  a b\xff"


def test_ref_and_zero() -> None:
    assert Secret().is_zero() and Secret().ref() == ""
    assert secret.literal("x").ref() == "literal"
    assert secret.literal("x").get() == b"x"
    assert secret.parse("file:/a").ref() == "file:/a"
    assert secret.env("A") == secret.parse("env:A")
    assert secret.file("/a") == secret.parse("file:/a")
