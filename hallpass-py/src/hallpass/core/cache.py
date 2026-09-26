"""A small TTL cache with singleflight: concurrent callers for the same
missing key share one fill.

Entries are dated by the reads they rest on, so a value computed from older
inputs never replaces one computed from newer ones, and a fresh check (one
that asked to bypass caches) is never answered by a read older than the
join window. See do() for the full contract.
"""

from __future__ import annotations

import threading
import time
import traceback
from collections.abc import Callable
from typing import Any, Generic, TypeVar

from hallpass.core import evidence
from hallpass.core.context import Context, with_timeout, without_cancel
from hallpass.core.errors import as_error

__all__ = ["DEFAULT_FILL_TIMEOUT", "FRESH_JOIN_WINDOW", "TTL", "FillExited", "PanicError", "detach", "is_panic_type"]

K = TypeVar("K")
V = TypeVar("V")

# How recently an entry must have been read for a fresh caller to take it
# rather than read again, so back-to-back fresh checks share one read.
FRESH_JOIN_WINDOW = 1.0

# Bounds a fill whose caller's context carries no deadline.
DEFAULT_FILL_TIMEOUT = 30.0

# Exceptions that mean the fill's code is broken rather than that the
# upstream failed: Go's panics. They reach every waiter as a PanicError,
# are logged once with their stack, and never fall back to a cached entry.
_PANIC_TYPES: tuple[type[BaseException], ...] = (
    TypeError,
    AttributeError,
    KeyError,
    IndexError,
    NameError,
    AssertionError,
    ZeroDivisionError,
    RecursionError,
    NotImplementedError,
)


def is_panic_type(e: BaseException) -> bool:
    return isinstance(e, _PANIC_TYPES)


class PanicError(Exception):
    """Every caller of a fill that crashed gets this error."""

    def __init__(self, value: BaseException, stack: str) -> None:
        self.value = value
        self.stack = stack
        self._reported = False
        self._lock = threading.Lock()
        super().__init__(f"fill panicked: {type(value).__name__}")

    def first_report(self) -> bool:
        """True once per PanicError: the first caller to ask logs it."""
        with self._lock:
            if self._reported:
                return False
            self._reported = True
            return True


class FillExited(Exception):
    def __init__(self) -> None:
        super().__init__("fill exited without returning")


def detach(ctx: Context, fallback: float) -> tuple[Context, Callable[[], None]]:
    """The context a shared fill runs on: ctx's values but not its
    cancellation, with ctx's remaining deadline (or fallback)."""
    rem = ctx.remaining()
    timeout = fallback if rem is None else rem
    return with_timeout(without_cancel(ctx), timeout)


class _Entry(Generic[V]):
    __slots__ = ("began", "ev", "exp", "own", "started", "v")

    def __init__(self, v: V, exp: float, started: float, own: float, began: float, ev: evidence.Evidence | None) -> None:
        self.v = v
        self.exp = exp
        # The oldest cached read v rests on (or the read's own start), the
        # read's own start, and started as a fresh check judges it.
        self.started = started
        self.own = own
        self.began = began
        # The evidence of the fill that produced v, replayed on hits.
        self.ev = ev


class _Call(Generic[V]):
    __slots__ = ("began", "done", "ended", "err", "ev", "fresh", "read_at", "rec", "started", "v")

    def __init__(self, started: float, fresh: bool) -> None:
        self.done = threading.Event()
        self.v: Any = None
        self.err: BaseException | None = None
        self.started = started
        self.fresh = fresh
        self.rec: evidence.Recorder | None = None
        self.ev: evidence.Evidence | None = None
        self.read_at = started
        self.began = started
        self.ended = False


class TTL(Generic[K, V]):
    """A bounded, time-limited map. Zero or negative TTLs disable storage
    but do() still collapses concurrent fills."""

    def __init__(self, max: int = 0) -> None:
        self._lock = threading.Lock()
        self._items: dict[K, _Entry[V]] = {}
        self._inflight: dict[K, _Call[V]] = {}
        # Fills started for fresh checks, apart from the ordinary ones: a
        # fresh caller never waits on an ordinary fill.
        self._fresh: dict[K, _Call[V]] = {}
        self._max = max if max > 0 else 10000
        self._now: Callable[[], float] = time.time
        self._fresh_max_age = 0.0
        # Told under the lock of every caller that joins a fill rather than
        # starting one. Tests set it.
        self.joined: Callable[[K, bool], None] | None = None

    def set_fresh_max_age(self, d: float) -> None:
        """Let a fresh check take a read that began less than d ago, when d
        is longer than FRESH_JOIN_WINDOW. For a bulk listing (an
        organization's whole identity index)."""
        with self._lock:
            self._fresh_max_age = d

    def set_clock(self, now: Callable[[], float]) -> None:
        with self._lock:
            self._now = now

    def get(self, k: K) -> tuple[V | None, bool]:
        e = self._entry(k)
        if e is None:
            return None, False
        return e.v, True

    def _entry(self, k: K) -> _Entry[V] | None:
        with self._lock:
            return self._get_locked(k, self._now())

    def set(self, k: K, v: V, ttl: float) -> None:
        """Store v for ttl seconds as a value read now. ttl <= 0 removes k."""
        with self._lock:
            now = self._now()
            self._store_locked(k, v, ttl, None, now, now, now, now)

    def store(self, k: K, v: V, ttl: float, started: float, own: float) -> None:
        """set for a value computed by a read that began at own and rests on
        cached inputs no older than started. Skipped when the entry already
        there rests on newer inputs, or on the same inputs and a read that
        began later."""
        with self._lock:
            now = self._now()
            self._store_locked(k, v, ttl, None, started, own, own, now)

    def _store_locked(self, k: K, v: V, ttl: float, ev: evidence.Evidence | None, started: float, own: float, began: float, now: float) -> None:
        e = self._get_locked(k, now)
        if e is not None and (e.started > started or (e.started == started and e.own > own)):
            return
        if ttl <= 0:
            self._items.pop(k, None)
            return
        self._evict_locked(now)
        self._items[k] = _Entry(v, now + ttl, started, own, began, ev)

    def delete(self, k: K) -> None:
        with self._lock:
            self._items.pop(k, None)

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)

    def len(self) -> int:
        return len(self)

    def _evict_locked(self, now: float) -> None:
        if len(self._items) < self._max:
            return
        for k in [k for k, e in self._items.items() if not now < e.exp]:
            del self._items[k]
        while len(self._items) >= self._max:
            del self._items[next(iter(self._items))]

    def do(self, ctx: Context, k: K, fill: Callable[[Context], tuple[V, float]]) -> V:
        """The cached value for k, or fill called once and shared with
        concurrent callers. fill returns (value, ttl); ttl 0 means do not
        store. Errors are never stored.

        The fill runs on its own Recorder; the caller that started it gets
        the calls as its own, one that waited for it gets them marked
        shared, and a later hit gets them marked cached.

        Under a fresh context, do() takes an entry only when it was read
        within the join window (or the fresh max age), joins a fresh fill
        in flight, and otherwise starts a fresh fill of its own; its answer
        replaces the entry unless an even later read stored one first. A
        fresh read that fails leaves the entry as it was. An ordinary
        caller takes the entry, else joins the ordinary fill, else the
        fresh one.

        The fill runs in its own thread on a context detached from the
        first caller's cancellation. Each caller stops waiting when its own
        context ends; a waiter whose leader's deadline ended the fill fills
        again with its own. A crash in fill is a PanicError for everyone.
        """
        rec = evidence.recorder_from(ctx)
        is_fresh = evidence.fresh(ctx)
        own_read = False
        while True:
            v, err, again, stale = self._do(ctx, k, fill, rec, is_fresh, own_read)
            if not again:
                if err is not None:
                    raise err
                return v  # type: ignore[return-value]
            own_read = own_read or stale

    def refresh(self, ctx: Context, k: K, fill: Callable[[Context], tuple[V, float]]) -> V:
        """Run fill for k now, on ctx, whatever the cache holds, and store
        the answer as a fresh read would. For a probe."""
        with self._lock:
            now = self._now()
        cl: _Call[V] = _Call(now, True)
        cancel: Callable[[], None] = lambda: None  # noqa: E731
        fctx = ctx
        if ctx.deadline() is None:
            fctx, cancel = with_timeout(ctx, DEFAULT_FILL_TIMEOUT)
        try:
            fctx, cl.rec = evidence.with_recorder(fctx)
            self._fill(k, cl, fctx, fill)
        finally:
            cancel()
        r = evidence.recorder_from(ctx)
        if r is not None:
            r.add_at(cl.ev, evidence.Origin.OWN, cl.read_at, cl.began)
        if cl.err is not None:
            raise cl.err
        return cl.v  # type: ignore[no-any-return]

    def _do(
        self,
        ctx: Context,
        k: K,
        fill: Callable[[Context], tuple[V, float]],
        rec: evidence.Recorder | None,
        is_fresh: bool,
        own_read: bool,
    ) -> tuple[V | None, BaseException | None, bool, bool]:
        self._lock.acquire()
        now = self._now()
        window = self._fresh_window()
        e = self._get_locked(k, now)
        if e is not None:
            young = self._young_locked(e, now)
            if not is_fresh or young:
                self._lock.release()
                # An entry young enough that a fresh check would take it
                # does not age what rests on it as a fresh check judges it.
                strict = now if young else e.began
                if rec is not None:
                    rec.add_at(e.ev, evidence.Origin.CACHED, e.started, strict)
                return e.v, None, False, False
        cl: _Call[V] | None = None
        if own_read:
            pass
        elif is_fresh:
            fc = self._fresh.get(k)
            if fc is not None:
                cl = fc
            else:
                oc = self._inflight.get(k)
                if oc is not None and now - oc.started < window:
                    cl = oc
        else:
            cl = self._inflight.get(k) or self._fresh.get(k)
        leader = cl is None
        if cl is None:
            cl = _Call(now, is_fresh)
            if is_fresh:
                self._fresh[k] = cl
            else:
                self._inflight[k] = cl
            fctx, cancel = detach(ctx, DEFAULT_FILL_TIMEOUT)
            fctx, cl.rec = evidence.with_recorder(fctx)
            call = cl

            def run() -> None:
                try:
                    self._fill(k, call, fctx, fill)
                finally:
                    cancel()

            threading.Thread(target=run, name="hallpass-fill", daemon=True).start()
        elif self.joined is not None:
            self.joined(k, is_fresh)
        self._lock.release()

        if not ctx.wait(cl.done):
            return None, ctx.err(), False, False
        by = evidence.Origin.OWN if leader else evidence.Origin.SHARED
        if cl.err is not None:
            if not is_fresh and as_error(cl.err, PanicError) is None:
                # The fill failed; an entry may have landed meanwhile and
                # answers an ordinary caller, leader or not. What the
                # failed fill did complete stays on the record, undated.
                ent = self._entry(k)
                if ent is not None:
                    if rec is not None:
                        rec.add(cl.ev, by)
                        rec.add_at(ent.ev, evidence.Origin.CACHED, ent.started, ent.began)
                    return ent.v, None, False, False
            if not leader and cl.ended and ctx.err() is None:
                # The fill ran on the leader's remaining deadline and ended
                # because of it; this caller still has time.
                if rec is not None:
                    rec.add(cl.ev, evidence.Origin.SHARED)
                return None, None, True, True
        if is_fresh and not leader and not cl.fresh and cl.err is None and now - cl.began >= window:
            # The ordinary fill this fresh caller joined rested on cached
            # reads older than the window: not fresh after all.
            if rec is not None:
                rec.add(cl.ev, evidence.Origin.SHARED)
            return None, None, True, True
        # A fresh caller that joined a read accepted it as current.
        strict = now if (is_fresh and not leader) else cl.began
        if rec is not None:
            rec.add_at(cl.ev, by, cl.read_at, strict)
        return cl.v, cl.err, False, False

    def _young_locked(self, e: _Entry[V], now: float) -> bool:
        return now - e.began < self._fresh_window()

    def _fresh_window(self) -> float:
        return max(FRESH_JOIN_WINDOW, self._fresh_max_age)

    def _get_locked(self, k: K, now: float) -> _Entry[V] | None:
        e = self._items.get(k)
        if e is None:
            return None
        if not now < e.exp:
            del self._items[k]
            return None
        return e

    def _fill(self, k: K, cl: _Call[V], ctx: Context, fill: Callable[[Context], tuple[V, float]]) -> None:
        ttl = 0.0
        try:
            try:
                cl.v, ttl = fill(ctx)
            except Exception as e:  # noqa: BLE001 - every failure reaches the waiters
                cl.v = None
                cl.err = PanicError(e, "".join(traceback.format_exception(e))) if is_panic_type(e) else e
            except BaseException:  # noqa: BLE001 - a thread must always close done
                cl.v = None
                cl.err = FillExited()
        finally:
            rec = cl.rec
            cl.ev = rec.evidence() if rec is not None else None
            cl.ended = ctx.err() is not None
            # The fill is as old as the oldest cached read it rested on.
            cl.read_at = cl.started
            o = rec.oldest() if rec is not None else None
            if o is not None and o < cl.read_at:
                cl.read_at = o
            cl.began = cl.started
            o = rec.oldest_strict() if rec is not None else None
            if o is not None and o < cl.began:
                cl.began = o
            with self._lock:
                inflight = self._fresh if cl.fresh else self._inflight
                if inflight.get(k) is cl:
                    del inflight[k]
                if cl.err is None and (ttl > 0 or cl.fresh):
                    # A fresh answer that may not be stored still removes the
                    # older entry it has just superseded.
                    self._store_locked(k, cl.v, ttl, cl.ev, cl.read_at, cl.started, cl.began, self._now())
            cl.done.set()
