"""Go semantics the authx ports depend on: RFC 3339 times, decoding JSON
into a Go struct, marshalling a value the way encoding/json does, fmt's %v,
PEM blocks as encoding/pem finds them, and the checks url.Parse makes."""

from __future__ import annotations

import base64
import binascii
import datetime
import json
import math
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any

__all__ = [
    "PEMBlock",
    "StructDict",
    "go_float_json",
    "go_json_loads",
    "go_json_marshal",
    "go_sprint",
    "go_unmarshal",
    "parse_rfc3339",
    "pem_decode",
    "url_parse_check",
]

_RFC3339 = re.compile(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})")


def parse_rfc3339(s: str) -> float:
    """Go's time.Parse(time.RFC3339, s) as epoch seconds; ValueError otherwise."""
    m = _RFC3339.fullmatch(s)
    if not m:
        raise ValueError(f'parsing time "{s}" as RFC3339')
    y, mo, d, h, mi, sec, frac, tz = m.groups()
    if tz == "Z":
        tzinfo = datetime.timezone.utc
    else:
        sign = 1 if tz[0] == "+" else -1
        th, tm = int(tz[1:3]), int(tz[4:6])
        if th > 23 or tm > 59:
            raise ValueError(f'parsing time "{s}": time zone offset out of range')
        tzinfo = datetime.timezone(sign * datetime.timedelta(hours=th, minutes=tm))
    try:
        dt = datetime.datetime(int(y), int(mo), int(d), int(h), int(mi), int(sec), tzinfo=tzinfo)
    except ValueError as e:
        raise ValueError(f'parsing time "{s}": {e}') from None
    ts = dt.timestamp()
    if frac:
        ts += float("0" + frac)
    return ts


# -- decoding JSON into a Go struct ------------------------------------------

STR, INT, RAW = "string", "int", "raw"


class _Raw:
    """A JSON number kept as its literal text (json.RawMessage, int fields)."""

    __slots__ = ("text",)

    def __init__(self, text: str) -> None:
        self.text = text


def _fold_eq(key: str, name: str) -> bool:
    """encoding/json's case-insensitive key match for an ASCII field name:
    ASCII case folding plus the two non-ASCII runes that fold to ASCII
    letters (the Kelvin sign to k, the long s to s)."""
    if len(key) != len(name):
        return False
    for c, f in zip(key, name, strict=True):
        lf = f.lower()
        if c.isascii():
            if c.lower() != lf:
                return False
        elif not ((c == "K" and lf == "k") or (c == "ſ" and lf == "s")):
            return False
    return True


def _json_type(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "bool"
    if isinstance(v, _Raw):
        return "number"
    if isinstance(v, str):
        return "string"
    if isinstance(v, list):
        return "array"
    return "object"


def _plain(v: Any) -> Any:
    """A decoded value with number literals turned back into numbers."""
    if isinstance(v, _Raw):
        t = v.text
        return int(t) if re.fullmatch(r"-?\d+", t) else float(t)
    if isinstance(v, list):
        return [_plain(x) for x in v]
    if isinstance(v, _Pairs):
        return {k: _plain(x) for k, x in v}
    return v


class _Pairs(list):  # type: ignore[type-arg]
    """An object's members in document order, duplicates kept."""


def go_unmarshal(data: bytes | str, fields: Iterable[tuple[str, str]], stream: bool = False) -> tuple[dict[str, Any], str | None]:
    """json.Unmarshal(data, &struct) for a flat struct of string, int and
    json.RawMessage fields, given as (json name, kind) in field order.

    Returns the field values and the error Go would return, or None. As in
    Go: a syntax error sets nothing; null leaves every field zero with no
    error; keys match case-insensitively (an exact match first), later
    members overwrite earlier ones; a member of the wrong type is skipped
    and reported as the first error while the rest still decode. A RAW
    field holds the decoded value (numbers as int or float).
    """
    specs = list(fields)
    out: dict[str, Any] = {name: ("" if kind == STR else 0 if kind == INT else None) for name, kind in specs}
    if isinstance(data, (bytes, bytearray)):
        data = bytes(data).decode("utf-8", "replace")
    try:
        dec = json.JSONDecoder(object_pairs_hook=_Pairs, parse_int=_Raw, parse_float=_Raw, parse_constant=_bad_constant)
        if stream:
            text = data.lstrip(" \t\r\n")
            if not text:
                raise ValueError("EOF")
            v, _ = dec.raw_decode(text)
        else:
            v = dec.decode(data)
    except (ValueError, RecursionError) as e:
        return out, str(e)
    if v is None:
        return out, None
    if not isinstance(v, _Pairs):
        return out, f"json: cannot unmarshal {_json_type(v)} into Go value of type struct"
    first: str | None = None
    for key, val in v:
        spec = next((s for s in specs if s[0] == key), None) or next((s for s in specs if _fold_eq(key, s[0])), None)
        if spec is None:
            continue
        name, kind = spec
        if kind == RAW:
            out[name] = _plain(val)
            continue
        if val is None:
            continue  # null leaves a Go string or int unchanged
        if kind == STR and isinstance(val, str):
            out[name] = val
            continue
        if kind == INT and isinstance(val, _Raw) and re.fullmatch(r"-?\d+", val.text) and -(2**63) <= int(val.text) < 2**63:
            out[name] = int(val.text)
            continue
        if first is None:
            first = f"json: cannot unmarshal {_json_type(val)} into Go struct field .{name} of type {'string' if kind == STR else 'int'}"
    return out, first


def _bad_constant(name: str) -> Any:
    raise ValueError(f"invalid character '{name[0]}' looking for beginning of value")


def go_json_loads(data: bytes | str) -> Any:
    """json.Unmarshal(data, &v) with v an any: UTF-8 input (invalid bytes
    become U+FFFD), no NaN or Infinity."""
    if isinstance(data, (bytes, bytearray)):
        data = bytes(data).decode("utf-8", "replace")
    return json.loads(data, parse_constant=_bad_constant)


# -- encoding like encoding/json ----------------------------------------------


class StructDict(dict):  # type: ignore[type-arg]
    """A dict that marshals in insertion order, as a Go struct does; a plain
    dict marshals with sorted keys, as a Go map does."""


def _shortest(f: float) -> tuple[str, int, bool]:
    """(digits, decimal point position, negative) of the shortest decimal
    that round-trips f, as strconv's shortest formatting computes it."""
    d = Decimal(repr(f))
    sign, digits, exp = d.as_tuple()
    ds = "".join(str(x) for x in digits).rstrip("0")
    assert isinstance(exp, int)
    if not ds:
        return "0", 1, bool(sign)
    # digits * 10**exp, trailing zeros removed.
    dp = len("".join(str(x) for x in digits)) + exp
    return ds, dp, bool(sign)


def _fmt_e(ds: str, dp: int, neg: bool) -> str:
    mant = ds[0] + ("." + ds[1:] if len(ds) > 1 else "")
    e = dp - 1
    return ("-" if neg else "") + mant + "e" + ("-" if e < 0 else "+") + f"{abs(e):02d}"


def _fmt_f(ds: str, dp: int, neg: bool) -> str:
    if dp <= 0:
        s = "0." + "0" * (-dp) + ds
    elif dp >= len(ds):
        s = ds + "0" * (dp - len(ds))
    else:
        s = ds[:dp] + "." + ds[dp:]
    return ("-" if neg else "") + s


def go_float_json(f: float) -> str:
    """A float64 as encoding/json writes it."""
    if math.isnan(f) or math.isinf(f):
        raise ValueError(f"json: unsupported value: {go_sprint(f)}")
    ds, dp, neg = _shortest(f)
    a = abs(f)
    if a != 0 and (a < 1e-6 or a >= 1e21):
        s = _fmt_e(ds, dp, neg)
        # Clean up e-09 to e-9.
        if len(s) >= 4 and s[-4] == "e" and s[-3] == "-" and s[-2] == "0":
            s = s[:-2] + s[-1]
        return s
    return _fmt_f(ds, dp, neg)


_HTML_ESCAPES = {"<": "\\u003c", ">": "\\u003e", "&": "\\u0026", " ": "\\u2028", " ": "\\u2029"}


def _enc(v: Any, out: list[str]) -> None:
    if v is None:
        out.append("null")
    elif v is True:
        out.append("true")
    elif v is False:
        out.append("false")
    elif isinstance(v, int):
        out.append(str(int(v)))
    elif isinstance(v, float):
        out.append(go_float_json(v))
    elif isinstance(v, str):
        s = json.dumps(v, ensure_ascii=False)
        out.append("".join(_HTML_ESCAPES.get(c, c) for c in s))
    elif isinstance(v, (bytes, bytearray)):
        # []byte marshals as base64.
        out.append('"' + base64.b64encode(bytes(v)).decode("ascii") + '"')
    elif isinstance(v, Mapping):
        items = list(v.items()) if isinstance(v, StructDict) else sorted(v.items(), key=lambda kv: str(kv[0]))
        out.append("{")
        for n, (k, x) in enumerate(items):
            if n:
                out.append(",")
            _enc(str(k), out)
            out.append(":")
            _enc(x, out)
        out.append("}")
    elif isinstance(v, (list, tuple)):
        out.append("[")
        for n, x in enumerate(v):
            if n:
                out.append(",")
            _enc(x, out)
        out.append("]")
    else:
        raise TypeError(f"json: unsupported type: {type(v).__name__}")


def go_json_marshal(v: Any) -> bytes:
    """json.Marshal(v): map keys sorted (a StructDict keeps its order),
    <, > and & escaped, floats formatted as Go formats them."""
    out: list[str] = []
    _enc(v, out)
    return "".join(out).encode("utf-8")


def go_sprint(v: Any) -> str:
    """fmt.Sprint(v) for the plain values a caller might pass."""
    if v is None:
        return "<nil>"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, float):
        if math.isnan(v):
            return "NaN"
        if math.isinf(v):
            return "+Inf" if v > 0 else "-Inf"
        # %v is %g with the shortest digits: %e when the exponent is below
        # -4 or at least 6 (so 1e6 prints as 1e+06).
        ds, dp, neg = _shortest(v)
        e = dp - 1
        if v != 0 and (e < -4 or e >= 6):
            return _fmt_e(ds, dp, neg)
        return _fmt_f(ds, dp, neg)
    if isinstance(v, (list, tuple)):
        return "[" + " ".join(go_sprint(x) for x in v) + "]"
    if isinstance(v, Mapping):
        return "map[" + " ".join(f"{go_sprint(k)}:{go_sprint(x)}" for k, x in sorted(v.items(), key=lambda kv: str(kv[0]))) + "]"
    return str(v)


# -- encoding/pem ---------------------------------------------------------------


@dataclass
class PEMBlock:
    type: str
    headers: dict[str, str] = field(default_factory=dict)
    bytes: bytes = b""


def _get_line(data: bytes) -> tuple[bytes, bytes]:
    i = data.find(b"\n")
    if i < 0:
        i = j = len(data)
    else:
        j = i + 1
        if i > 0 and data[i - 1] == 0x0D:
            i -= 1
    return data[:i].rstrip(b" \t"), data[j:]


_PEM_START = b"\n-----BEGIN "
_PEM_END = b"\n-----END "
_PEM_EOL = b"-----"


def pem_decode(data: bytes) -> tuple[PEMBlock | None, bytes]:
    """encoding/pem.Decode: the next PEM block and the rest of the input,
    or (None, data) when there is none. A malformed block is skipped."""
    rest = data
    while True:
        if rest.startswith(_PEM_START[1:]):
            rest = rest[len(_PEM_START) - 1 :]
        else:
            i = rest.find(_PEM_START)
            if i < 0:
                return None, data
            rest = rest[i + len(_PEM_START) :]
        type_line, rest = _get_line(rest)
        if not type_line.endswith(_PEM_EOL):
            continue
        type_line = type_line[: len(type_line) - len(_PEM_EOL)]
        p = PEMBlock(type=type_line.decode("utf-8", "replace"))
        while True:
            if len(rest) == 0:
                return None, data
            line, nxt = _get_line(rest)
            key, sep, val = line.partition(b":")
            if not sep:
                break
            p.headers[key.strip().decode("utf-8", "replace")] = val.strip().decode("utf-8", "replace")
            rest = nxt
        if not p.headers and rest.startswith(_PEM_END[1:]):
            end_index = 0
            end_trailer_index = len(_PEM_END) - 1
        else:
            end_index = rest.find(_PEM_END)
            end_trailer_index = end_index + len(_PEM_END)
        if end_index < 0:
            continue
        end_trailer = rest[end_trailer_index:]
        end_trailer_len = len(type_line) + len(_PEM_EOL)
        if len(end_trailer) < end_trailer_len:
            continue
        rest_of_end_line = end_trailer[end_trailer_len:]
        end_trailer = end_trailer[:end_trailer_len]
        if not end_trailer.startswith(type_line) or not end_trailer.endswith(_PEM_EOL):
            continue
        if _get_line(rest_of_end_line)[0]:
            continue
        b64 = rest[:end_index].replace(b" ", b"").replace(b"\t", b"")
        # base64.StdEncoding skips \r and \n and nothing else.
        b64 = b64.replace(b"\r", b"").replace(b"\n", b"")
        try:
            if not re.fullmatch(rb"[A-Za-z0-9+/]*={0,2}", b64) or len(b64) % 4:
                raise binascii.Error("illegal base64 data")
            p.bytes = base64.b64decode(b64, validate=True)
        except binascii.Error:
            continue
        _, rest = _get_line(rest[end_index + len(_PEM_END) - 1 :])
        return p, rest


# -- net/url --------------------------------------------------------------------


def _check_escapes(s: str) -> None:
    i = 0
    while i < len(s):
        if s[i] == "%":
            h = s[i + 1 : i + 3]
            if len(h) < 2 or not all(c in "0123456789abcdefABCDEF" for c in h):
                raise ValueError(f"invalid URL escape {_quote(s[i : i + 3])}")
            i += 3
            continue
        i += 1


def _quote(s: str) -> str:
    from hallpass.core.errors import go_quote

    return go_quote(s)


def url_parse_check(raw: str) -> None:
    """The failures url.Parse reports that urllib.parse.urlsplit does not:
    control characters, a bad percent escape in the path or fragment, and a
    port that is not all digits. The message is Go's."""
    try:
        if any(ord(c) < 0x20 or ord(c) == 0x7F for c in raw):
            raise ValueError("net/url: invalid control character in URL")
        rest, _, frag = raw.partition("#")
        _check_escapes(frag)
        rest, _, _query = rest.partition("?")
        m = re.match(r"[A-Za-z][A-Za-z0-9+.-]*:", rest)
        if m:
            rest = rest[m.end() :]
        if rest.startswith("//"):
            authority, slash, path = rest[2:].partition("/")
            host = authority.rpartition("@")[2]
            if host.startswith("["):
                j = host.find("]")
                if j < 0:
                    raise ValueError("missing ']' in host")
                port = host[j + 1 :]
                if port and not re.fullmatch(r":\d*", port):
                    raise ValueError(f"invalid port {_quote(port)} after host")
            elif ":" in host:
                port = host[host.rindex(":") :]
                if not re.fullmatch(r":\d*", port):
                    raise ValueError(f"invalid port {_quote(port)} after host")
            _check_escapes(host)
            rest = slash + path
        _check_escapes(rest)
    except ValueError as e:
        raise ValueError(f"parse {_quote(raw)}: {e}") from None
