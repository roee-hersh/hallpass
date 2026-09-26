"""Go-style durations ("10s", "1m30s", "250ms") as float seconds."""

from __future__ import annotations

import re

__all__ = ["format_duration", "parse_duration"]

_UNITS = {
    "ns": 1e-9,
    "us": 1e-6,
    "µs": 1e-6,  # U+00B5
    "μs": 1e-6,  # U+03BC
    "ms": 1e-3,
    "s": 1.0,
    "m": 60.0,
    "h": 3600.0,
}
_PART = re.compile(r"([0-9]*(?:\.[0-9]*)?)(ns|us|µs|μs|ms|s|m|h)")


def parse_duration(s: str) -> float:
    """Parse like Go's time.ParseDuration; raise ValueError."""
    orig = s
    if s == "":
        raise ValueError(f'time: invalid duration "{orig}"')
    sign = 1.0
    if s[0] in "+-":
        if s[0] == "-":
            sign = -1.0
        s = s[1:]
    if s == "0":
        return 0.0
    if s == "":
        raise ValueError(f'time: invalid duration "{orig}"')
    total = 0.0
    pos = 0
    while pos < len(s):
        m = _PART.match(s, pos)
        if not m or m.group(1) in ("", "."):
            if m is None and re.match(r"[0-9.]+", s[pos:]):
                raise ValueError(f'time: missing unit in duration "{orig}"')
            raise ValueError(f'time: invalid duration "{orig}"')
        total += float(m.group(1)) * _UNITS[m.group(2)]
        pos = m.end()
    return sign * total


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
