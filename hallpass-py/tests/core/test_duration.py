"""hallpass.core.duration against Go's time.ParseDuration.

There is no Go test file for this (it is the standard library); every
expected value below is what time.ParseDuration returns for the input.
"""

from __future__ import annotations

import pytest

from hallpass.core.duration import parse_duration, parse_duration_ns


@pytest.mark.parametrize(
    ("s", "ns"),
    [
        ("0", 0),
        ("-0", 0),
        ("+0", 0),
        ("0s", 0),
        ("10s", 10_000_000_000),
        ("1m30s", 90_000_000_000),
        ("1.5h", 5_400_000_000_000),
        (".5s", 500_000_000),
        ("5.s", 5_000_000_000),
        ("1h2m3.5s", 3_723_500_000_000),
        ("250ms", 250_000_000),
        ("1us", 1_000),
        ("1µs", 1_000),
        ("1μs", 1_000),
        ("3ns", 3),
        ("-1.5m", -90_000_000_000),
        ("2562047h47m16.854775807s", 9_223_372_036_854_775_807),
        ("-2562047h47m16.854775808s", -9_223_372_036_854_775_808),
        # float64 arithmetic for fractions, as Go does.
        ("0.1234567891234h", 444_444_440_844),
        # Fraction digits past int64 precision are dropped, not an error.
        ("1.0000000000000000000001s", 1_000_000_000),
    ],
)
def test_parse_duration(s: str, ns: int) -> None:
    assert parse_duration_ns(s) == ns
    assert parse_duration(s) == ns / 1e9


@pytest.mark.parametrize(
    ("s", "want"),
    [
        ("", 'time: invalid duration ""'),
        ("1", 'time: missing unit in duration "1"'),
        (".s", 'time: invalid duration ".s"'),
        ("-.s", 'time: invalid duration "-.s"'),
        ("1x", 'time: unknown unit "x" in duration "1x"'),
        ("1sx", 'time: unknown unit "sx" in duration "1sx"'),
        ("s", 'time: invalid duration "s"'),
        ("+", 'time: invalid duration "+"'),
        ("2562047h47m16.854775808s", 'time: invalid duration "2562047h47m16.854775808s"'),
        ("9223372036854775808ns", 'time: invalid duration "9223372036854775808ns"'),
        ("1e3s", 'time: unknown unit "e" in duration "1e3s"'),
        # The time package's own quoting: every byte of non-ASCII as \xNN.
        ("é", 'time: invalid duration "\\xc3\\xa9"'),
        ("1 s", 'time: unknown unit " s" in duration "1 s"'),
        ('1"s', 'time: unknown unit "\\"s" in duration "1\\"s"'),
    ],
)
def test_parse_duration_errors(s: str, want: str) -> None:
    with pytest.raises(ValueError) as ei:
        parse_duration_ns(s)
    assert str(ei.value) == want
