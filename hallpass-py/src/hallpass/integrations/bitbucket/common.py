"""What the Cloud and Data Center halves of the bitbucket connection share
(Go: the Connection type and helpers of bitbucket.go)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from hallpass.core import jsonx
from hallpass.core.context import Context
from hallpass.core.decision import Code, HallpassError, wrap_error
from hallpass.core.integration import Settings
from hallpass.net import httpx

EDITION_CLOUD = "cloud"
EDITION_DATA_CENTER = "datacenter"

_INT64_MIN, _INT64_MAX = -(1 << 63), (1 << 63) - 1


def equal_fold(a: str, b: str) -> bool:
    """Go's strings.EqualFold: rune by rune under simple case folding."""
    if a == b:
        return True
    if len(a) != len(b):
        return False
    for x, y in zip(a, b, strict=True):
        if x == y:
            continue
        xl, yl, xu, yu = x.lower(), y.lower(), x.upper(), y.upper()
        if len(xl) == 1 and xl == yl:
            continue
        if len(xu) == 1 and xu == yu:
            continue
        return False
    return True


def i64(d: dict[str, Any], key: str) -> int:
    """An int64 struct field: out of range is a decode error."""
    v = jsonx.i(d, key)
    if not _INT64_MIN <= v <= _INT64_MAX:
        raise jsonx.DecodeError(f"json: cannot unmarshal number {v} into field {key} of type int64")
    return v


def opt_bool(d: dict[str, Any], key: str) -> bool | None:
    """A *bool struct field: null or missing is None."""
    if d.get(key) is None:
        return None
    return jsonx.b(d, key)


def opt_i64(d: dict[str, Any], key: str) -> int | None:
    """A *int64 struct field: null or missing is None."""
    if d.get(key) is None:
        return None
    return i64(d, key)


def empty_struct(v: Any) -> None:
    """json.Unmarshal into struct{}: an object or null, nothing else."""
    jsonx.obj(v, "struct {}")


def classify(err: BaseException, what: str) -> BaseException:
    """Map an API error to a HallpassError. 404 is left to the caller:
    Bitbucket answers 404 for what the caller may not see. A Python bug
    (Go: a panic) passes through untouched."""
    from hallpass.core.cache import is_panic_type

    if is_panic_type(err):
        return err
    st = httpx.status(err)
    if st == 401:
        return wrap_error(Code.CREDENTIAL_REJECTED, err, "Bitbucket rejected hallpass's token")
    if st == 403:
        return wrap_error(Code.CREDENTIAL_REJECTED, err, f"Bitbucket refused to {what} (HTTP 403): hallpass's token lacks the permission that read needs")
    if st == 400:
        return wrap_error(Code.INVALID_REQUEST, err, f"Bitbucket rejected the request to {what} (HTTP 400)")
    out: HallpassError | None = httpx.classify(err)
    return out if out is not None else err


class Base:
    """The state both editions use."""

    def __init__(self, settings: Settings, edition: str, workspace: str, api: httpx.Client) -> None:
        self.settings = settings
        self.edition = edition
        self.workspace = workspace
        self.api = api

    def data_center(self) -> bool:
        return self.edition == EDITION_DATA_CENTER

    def get_json(self, ctx: Context, path: str, q: dict[str, str] | None, decode: Callable[[Any], Any] | None) -> Any:
        """One GET with JSON decoding (decode None: no decoding, Go's nil
        out). The raw httpx error is raised so callers can branch on 404."""
        resp = self.api.do(ctx, httpx.Request(method="GET", path=path, query=q))
        if decode is None:
            return None
        try:
            return decode(resp.json())
        except ValueError as e:
            raise wrap_error(Code.UPSTREAM_ERROR, e, "Bitbucket returned an unreadable response")
