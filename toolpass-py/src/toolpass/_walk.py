"""The one walk over a value's text, shared by the untrusted-output record
and credential redaction, so both see the same strings."""

from __future__ import annotations

import dataclasses
from collections.abc import Iterator, Mapping


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


def mentions(value: object, needles: list[str]) -> bool:
    """True when any string inside ``value`` contains one of ``needles``."""
    return any(n in s for s in strings(value) for n in needles)
