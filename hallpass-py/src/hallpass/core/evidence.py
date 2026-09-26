"""What each check asked the upstream and what the upstream answered.

The engine gives every check a Recorder through its Context; the HTTP
client records each response it returns on it, and a cache fill adds the
evidence of its lookup, by reference, marked by how the check came by it
(its own call, a concurrent check's it joined, or a cached one). It also
holds the fresh mark, so the packages on a check's way share them without
depending on each other.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, replace
from enum import IntEnum
from typing import Any

from hallpass.core.context import Context, with_value

__all__ = [
    "MAX_CALLS",
    "Call",
    "Evidence",
    "Origin",
    "Recorder",
    "fresh",
    "of",
    "recorder_from",
    "with_fresh",
    "with_recorder",
    "without_recorder",
]

# The calls one Evidence reports, at most, so a paginated lookup cannot
# grow a log line without limit. Calls made for the check take precedence
# over replayed ones, and among those the latest are kept.
MAX_CALLS = 100


@dataclass(frozen=True)
class Call:
    """One completed upstream request."""

    method: str = ""
    # The request path as sent. Never the query string.
    path: str = ""
    # Set when the call went to a host other than the client's base URL.
    host: str = ""
    status: int = 0
    # The response's ETag header, when it sent one.
    etag: str = ""
    # The hex SHA-256 of the response body, when there was no ETag and the
    # body was not empty.
    sha256: str = ""
    # Not made for this check: served from a stored cache entry.
    cached: bool = False
    # Made by a concurrent check whose lookup this check joined.
    shared: bool = False

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {"method": self.method, "path": self.path}
        if self.host:
            out["host"] = self.host
        out["status"] = self.status
        if self.etag:
            out["etag"] = self.etag
        if self.sha256:
            out["sha256"] = self.sha256
        if self.cached:
            out["cached"] = True
        if self.shared:
            out["shared"] = True
        return out

    @staticmethod
    def from_json(d: dict[str, Any]) -> Call:
        return Call(
            method=str(d.get("method", "")),
            path=str(d.get("path", "")),
            host=str(d.get("host", "")),
            status=int(d.get("status", 0)),
            etag=str(d.get("etag", "")),
            sha256=str(d.get("sha256", "")),
            cached=bool(d.get("cached", False)),
            shared=bool(d.get("shared", False)),
        )


class Origin(IntEnum):
    OWN = 0  # the check made the call
    SHARED = 1  # a concurrent check made it and this check joined it
    CACHED = 2  # made earlier and served from a cache


class _Item:
    __slots__ = ("by", "call", "src")

    def __init__(self, call: Call | None = None, src: Evidence | None = None, by: Origin = Origin.OWN) -> None:
        self.call = call
        self.src = src
        self.by = by


class Evidence:
    """The calls a decision was based on. Immutable once built.

    Calls a check got from a cache are held by reference to the evidence
    recorded when they were made, so a cached lookup's pages are stored
    once however many decisions replay them; calls() flattens on demand.
    """

    __slots__ = ("_cached", "_flat", "_items", "_lock", "_truncated")

    def __init__(self, items: list[_Item] | None = None, truncated: bool = False) -> None:
        self._items: list[_Item] = items or []
        self._truncated = truncated
        self._lock = threading.Lock()
        self._flat: tuple[list[Call], bool] | None = None
        self._cached: Evidence | None = None

    def calls(self) -> list[Call]:
        """The calls in completion order, marked by origin, at most
        MAX_CALLS; past the cap the oldest go, cached ones first."""
        return self._flatten()[0]

    def truncated(self) -> bool:
        return self._flatten()[1]

    def _flatten(self) -> tuple[list[Call], bool]:
        with self._lock:
            if self._flat is None:
                self._flat = self._flatten_once()
            return self._flat

    def _flatten_once(self) -> tuple[list[Call], bool]:
        total = 0
        cached = 0

        def count(c: Call) -> None:
            nonlocal total, cached
            total += 1
            if c.cached:
                cached += 1

        truncated = self._walk(Origin.OWN, count)
        drop_cached = drop_live = 0
        excess = total - MAX_CALLS
        if excess > 0:
            truncated = True
            drop_cached = min(excess, cached)
            drop_live = excess - drop_cached
        out: list[Call] = []

        def keep(c: Call) -> None:
            nonlocal drop_cached, drop_live
            if c.cached and drop_cached > 0:
                drop_cached -= 1
            elif not c.cached and drop_live > 0:
                drop_live -= 1
            else:
                out.append(c)

        self._walk(Origin.OWN, keep)
        return out, truncated

    def _walk(self, by: Origin, visit: Any) -> bool:
        truncated = self._truncated
        for it in self._items:
            if it.src is not None:
                inner = it.by
                if by == Origin.CACHED:
                    inner = Origin.CACHED
                elif by == Origin.SHARED and inner == Origin.OWN:
                    inner = Origin.SHARED
                if it.src._walk(inner, visit):
                    truncated = True
                continue
            c = it.call
            assert c is not None
            if by == Origin.CACHED:
                c = replace(c, cached=True, shared=False)
            elif by == Origin.SHARED:
                c = replace(c, shared=not c.cached)
            visit(c)
        return truncated

    def as_cached(self) -> Evidence:
        """This evidence's calls as served from a cache (the decision cache)."""
        with self._lock:
            if self._cached is None:
                self._cached = Evidence([_Item(src=self, by=Origin.CACHED)])
            return self._cached

    def to_json(self) -> dict[str, Any]:
        calls, truncated = self._flatten()
        out: dict[str, Any] = {"upstream": [c.to_json() for c in calls]}
        if truncated:
            out["truncated"] = True
        return out

    @staticmethod
    def from_json(d: dict[str, Any]) -> Evidence:
        return Evidence([_Item(call=Call.from_json(c)) for c in d.get("upstream") or []], bool(d.get("truncated", False)))


def of(*calls: Call) -> Evidence | None:
    """An Evidence of the given calls, as recorded."""
    if not calls:
        return None
    return Evidence([_Item(call=c) for c in calls])


def as_cached(ev: Evidence | None) -> Evidence | None:
    return None if ev is None else ev.as_cached()


class Recorder:
    """Collects the evidence of one check. Safe for concurrent use: a shared
    fill may still run after the check that started it has returned."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._items: list[_Item] = []
        self._truncated = False
        self._own = 0
        # When the oldest read added with add_at began, and the oldest a
        # fresh check would not tolerate; None when none.
        self._oldest: float | None = None
        self._strict: float | None = None

    def record(self, c: Call) -> None:
        """Add one call the check made. Past MAX_CALLS own calls the oldest
        own call is dropped: the calls made last decided the check."""
        with self._lock:
            if self._own >= MAX_CALLS:
                self._truncated = True
                for i, it in enumerate(self._items):
                    if it.src is None:
                        del self._items[i]
                        break
                self._own -= 1
            self._items.append(_Item(call=c))
            self._own += 1

    def add(self, ev: Evidence | None, by: Origin) -> None:
        """Add ev's calls by reference, marked by how the check came by them."""
        self.add_at(ev, by, None, None)

    def add_at(self, ev: Evidence | None, by: Origin, read_at: float | None, strict: float | None) -> None:
        """add for a read that began at read_at (a cache entry or a fill
        that started then). strict is the same read's date as a fresh check
        judges it. A None ev still dates the record."""
        with self._lock:
            if read_at is not None and (self._oldest is None or read_at < self._oldest):
                self._oldest = read_at
            if strict is not None and (self._strict is None or strict < self._strict):
                self._strict = strict
            if ev is None:
                return
            if len(self._items) - self._own >= MAX_CALLS:
                self._truncated = True
                return
            self._items.append(_Item(src=ev, by=by))

    def oldest(self) -> float | None:
        """When the oldest read behind the record began; None when every call
        was the check's own."""
        with self._lock:
            return self._oldest

    def oldest_strict(self) -> float | None:
        with self._lock:
            return self._strict

    def evidence(self) -> Evidence | None:
        """A snapshot of what was recorded, or None when nothing was."""
        with self._lock:
            if not self._items:
                return None
            return Evidence(list(self._items), self._truncated)


class _Key:
    __slots__ = ("name",)

    def __init__(self, name: str) -> None:
        self.name = name


_RECORDER = _Key("recorder")
_NO_RECORDER = object()
_FRESH = _Key("fresh")


def with_recorder(ctx: Context) -> tuple[Context, Recorder]:
    """A context carrying a new Recorder. The engine sets one up per check."""
    r = Recorder()
    return with_value(ctx, _RECORDER, r), r


def without_recorder(ctx: Context) -> Context:
    """A context whose recorder_from is None: auth runs on it and token
    fetches happen on it, since a token exchange is not what a decision was
    based on and its response carries the credential."""
    if ctx.value(_RECORDER) is None:
        return ctx
    return with_value(ctx, _RECORDER, _NO_RECORDER)


def recorder_from(ctx: Context | None) -> Recorder | None:
    if ctx is None:
        return None
    r = ctx.value(_RECORDER)
    return r if isinstance(r, Recorder) else None


def with_fresh(ctx: Context) -> Context:
    """Mark a context as belonging to a fresh check: every cache consulted
    under it looks the value up again and replaces its entry."""
    return with_value(ctx, _FRESH, True)


def fresh(ctx: Context | None) -> bool:
    return bool(ctx is not None and ctx.value(_FRESH))
