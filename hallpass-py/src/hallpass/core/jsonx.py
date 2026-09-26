"""Typed reads of decoded JSON with the semantics of decoding into a Go
struct: a missing key or null is the zero value, a value of the wrong type
is an error (so a malformed upstream answer is upstream_error, never a
silently wrong decision), unknown keys are ignored.

    d = jsonx.obj(resp.json())
    account = jsonx.s(d, "accountId")
    for u in jsonx.arr(d, "values"):
        u = jsonx.obj(u)
"""

from __future__ import annotations

from typing import Any

__all__ = ["DecodeError", "arr", "b", "f", "i", "o", "obj", "s", "strs"]


class DecodeError(ValueError):
    """The upstream answer does not have the expected shape."""


def _type(v: Any) -> str:
    if isinstance(v, bool):
        return "bool"
    if isinstance(v, (int, float)):
        return "number"
    if isinstance(v, str):
        return "string"
    if isinstance(v, list):
        return "array"
    if isinstance(v, dict):
        return "object"
    return type(v).__name__


def obj(v: Any, what: str = "value") -> dict[str, Any]:
    """v as an object; null is empty."""
    if v is None:
        return {}
    if not isinstance(v, dict):
        raise DecodeError(f"json: cannot unmarshal {_type(v)} into {what} of type object")
    return v


def _get(d: dict[str, Any] | None, key: str) -> Any:
    if d is None:
        return None
    return d.get(key)


def s(d: dict[str, Any] | None, key: str) -> str:
    v = _get(d, key)
    if v is None:
        return ""
    if not isinstance(v, str):
        raise DecodeError(f"json: cannot unmarshal {_type(v)} into field {key} of type string")
    return v


def i(d: dict[str, Any] | None, key: str) -> int:
    """An integer; a number with a fraction or exponent is an error, as it
    is for a Go int field."""
    v = _get(d, key)
    if v is None:
        return 0
    if isinstance(v, bool) or not isinstance(v, int):
        raise DecodeError(f"json: cannot unmarshal {_type(v)} into field {key} of type int")
    return v


def f(d: dict[str, Any] | None, key: str) -> float:
    v = _get(d, key)
    if v is None:
        return 0.0
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        raise DecodeError(f"json: cannot unmarshal {_type(v)} into field {key} of type float64")
    return float(v)


def b(d: dict[str, Any] | None, key: str) -> bool:
    v = _get(d, key)
    if v is None:
        return False
    if not isinstance(v, bool):
        raise DecodeError(f"json: cannot unmarshal {_type(v)} into field {key} of type bool")
    return v


def arr(d: dict[str, Any] | None, key: str) -> list[Any]:
    v = _get(d, key)
    if v is None:
        return []
    if not isinstance(v, list):
        raise DecodeError(f"json: cannot unmarshal {_type(v)} into field {key} of type array")
    return v


def o(d: dict[str, Any] | None, key: str) -> dict[str, Any]:
    v = _get(d, key)
    if v is None:
        return {}
    if not isinstance(v, dict):
        raise DecodeError(f"json: cannot unmarshal {_type(v)} into field {key} of type object")
    return v


def strs(d: dict[str, Any] | None, key: str) -> list[str]:
    """A list of strings; a null element is "" as in a Go []string."""
    out = []
    for x in arr(d, key):
        if x is None:
            out.append("")
        elif isinstance(x, str):
            out.append(x)
        else:
            raise DecodeError(f"json: cannot unmarshal {_type(x)} into field {key} of type string")
    return out
