"""Go-style durations ("10s", "1m30s", "250ms") as float seconds."""

from __future__ import annotations

__all__ = ["format_duration", "parse_duration", "parse_duration_ns"]

_UNITS = {
    "ns": 1,
    "us": 1_000,
    "\u00b5s": 1_000,  # U+00B5 micro sign
    "\u03bcs": 1_000,  # U+03BC Greek small letter mu
    "ms": 1_000_000,
    "s": 1_000_000_000,
    "m": 60 * 1_000_000_000,
    "h": 3600 * 1_000_000_000,
}
_MAX = 1 << 63
_HEX = "0123456789abcdef"


def _quote(s: str) -> str:
    """The time package's own quote: ASCII kept (" and \\ escaped), every
    byte of a non-ASCII or control rune as \\xNN."""
    out = ['"']
    for c in s:
        if ord(c) >= 0x80 or c < " ":
            for b in c.encode("utf-8", "surrogatepass"):
                out.append("\\x" + _HEX[b >> 4] + _HEX[b & 0xF])
        else:
            if c in '"\\':
                out.append("\\")
            out.append(c)
    out.append('"')
    return "".join(out)


def _digits(s: bytes, i: int) -> int:
    while i < len(s) and 0x30 <= s[i] <= 0x39:
        i += 1
    return i


def parse_duration_ns(s: str) -> int:
    """Go's time.ParseDuration, in nanoseconds; raise ValueError with Go's text."""
    orig = s
    invalid = ValueError("time: invalid duration " + _quote(orig))
    b = s.encode("utf-8", "surrogatepass")
    neg = False
    if b[:1] in (b"-", b"+"):
        neg = b[:1] == b"-"
        b = b[1:]
    if b == b"0":
        return 0
    if b == b"":
        raise invalid
    d = 0
    i = 0
    n = len(b)
    while i < n:
        # The next character must be [0-9.].
        if not (b[i] == 0x2E or 0x30 <= b[i] <= 0x39):
            raise invalid
        j = _digits(b, i)
        pre = j != i
        v = 0
        for c in b[i:j]:
            if v > _MAX // 10:
                raise invalid
            v = v * 10 + c - 0x30
            if v > _MAX:
                raise invalid
        i = j
        f, scale, post = 0, 1.0, False
        if i < n and b[i] == 0x2E:
            i += 1
            j = _digits(b, i)
            post = j != i
            overflow = False
            for c in b[i:j]:
                if overflow:
                    continue
                if f > (_MAX - 1) // 10:
                    overflow = True
                    continue
                y = f * 10 + c - 0x30
                if y > _MAX:
                    overflow = True
                    continue
                f = y
                scale *= 10
            i = j
        if not pre and not post:
            raise invalid
        j = i
        while j < n and not (b[j] == 0x2E or 0x30 <= b[j] <= 0x39):
            j += 1
        if j == i:
            raise ValueError("time: missing unit in duration " + _quote(orig))
        u = b[i:j].decode("utf-8", "surrogatepass")
        i = j
        unit = _UNITS.get(u)
        if unit is None:
            raise ValueError("time: unknown unit " + _quote(u) + " in duration " + _quote(orig))
        if v > _MAX // unit:
            raise invalid
        v *= unit
        if f > 0:
            # float64, as Go does, to be nanosecond-accurate for fractions of hours.
            v += int(float(f) * (float(unit) / scale))
            if v > _MAX:
                raise invalid
        d += v
        if d > _MAX:
            raise invalid
    if neg:
        return -d
    if d > _MAX - 1:
        raise invalid
    return d


def parse_duration(s: str) -> float:
    """Parse like Go's time.ParseDuration, as float seconds; raise ValueError."""
    return parse_duration_ns(s) / 1e9


def format_duration(seconds: float) -> str:
    """A short Go-like rendering: 8s, 1m30s, 250ms."""
    if seconds == 0:
        return "0s"
    if seconds < 1:
        ms = seconds * 1000
        return f"{ms:g}ms"
    whole = int(seconds)
    frac = seconds - whole
    h, rem = divmod(whole, 3600)
    m, s = divmod(rem, 60)
    out = ""
    if h:
        out += f"{h}h"
    if h or m:
        out += f"{m}m"
    out += f"{s + frac:g}s"
    return out
