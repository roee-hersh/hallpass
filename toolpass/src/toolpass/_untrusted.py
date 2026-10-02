"""What untrusted tools returned in a session, kept as word n-grams.

A tool marked ``untrusted_output=True`` (an email reader, a web fetcher)
records its output here. A tool that acts then asks whether any of its
string arguments repeats a run of ``n`` consecutive words from that output:
the sign of an injected instruction being carried into an action. Text is
normalized first (NFKC, case folded, invisible format characters removed),
so zero-width characters and full-width letters do not hide a match.

Only hashes of the n-grams are kept, never the text. The store is bounded;
once full, every question answers "match", so a flood of untrusted text
fails closed instead of pushing earlier content out.

A model that paraphrases what it read is not caught by this, and arguments
shorter than ``n`` words never match. The exfiltration guard does not depend
on the words and covers that gap for data leaving the system.
"""

from __future__ import annotations

import dataclasses
import hashlib
import re
import unicodedata
from collections.abc import Iterable, Iterator, Mapping

_WORD = re.compile(r"\w+")

DEFAULT_NGRAM = 6
DEFAULT_CAPACITY = 500_000


def words(text: str) -> list[str]:
    """The normalized words of ``text``."""
    text = unicodedata.normalize("NFKC", text)
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")
    return _WORD.findall(text.casefold())


def _grams(ws: list[str], n: int) -> Iterator[bytes]:
    for i in range(len(ws) - n + 1):
        yield hashlib.blake2b("\x1f".join(ws[i : i + n]).encode(), digest_size=8).digest()


def strings(value: object, depth: int = 0) -> Iterator[str]:
    """Every string inside ``value``: itself, the keys, values and items of
    mappings and sequences, the fields of dataclasses and pydantic models, or
    the text of any other object, to a bounded depth. Bytes are decoded
    leniently."""
    if depth > 20:
        return
    if isinstance(value, str):
        yield value
    elif isinstance(value, (bytes, bytearray)):
        yield bytes(value).decode("utf-8", "replace")
    elif isinstance(value, Mapping):
        for k, v in value.items():
            yield from strings(k, depth + 1)
            yield from strings(v, depth + 1)
    elif isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            yield from strings(item, depth + 1)
    elif value is None or isinstance(value, (bool, int, float)):
        return
    elif dataclasses.is_dataclass(value) and not isinstance(value, type):
        for f in dataclasses.fields(value):
            yield from strings(getattr(value, f.name, None), depth + 1)
    elif callable(model_dump := getattr(value, "model_dump", None)):  # a pydantic model
        try:
            dumped = model_dump()
        except Exception:
            dumped = None
        if dumped is not None:
            yield from strings(dumped, depth + 1)
        else:
            yield str(value)
    else:  # any other object: its text, so nothing untrusted goes unrecorded
        yield str(value)


class UntrustedText:
    """Hashed n-grams of everything untrusted tools returned. Not thread-safe:
    the owning session holds its lock around every call."""

    def __init__(self, n: int = DEFAULT_NGRAM, capacity: int = DEFAULT_CAPACITY) -> None:
        if n < 2:
            raise ValueError("n must be at least 2")
        self.n = n
        self.capacity = capacity
        self.overflowed = False
        self._grams: set[bytes] = set()

    def add(self, value: object) -> None:
        for s in strings(value):
            for g in _grams(words(s), self.n):
                if g in self._grams:
                    continue
                if len(self._grams) >= self.capacity:
                    self.overflowed = True
                    return
                self._grams.add(g)

    def matches(self, values: Iterable[object]) -> bool:
        if self.overflowed:
            return True
        if not self._grams:
            return False
        for value in values:
            for s in strings(value):
                if any(g in self._grams for g in _grams(words(s), self.n)):
                    return True
        return False
