"""Port of internal/cache/cache_test.go.

Goroutines are threads, channels threading.Event / queue.Queue. Go's
Do returns (v, err); the do() helper below turns the raised exception back
into that pair so the cases read as the Go ones do. A Go panic in a fill is
a raised TypeError (one of the "bug" types, see cache.is_panic_type).
"""

from __future__ import annotations

import queue
import threading
import time
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

import pytest

from hallpass.core import evidence
from hallpass.core.cache import FRESH_JOIN_WINDOW, TTL, PanicError, detach
from hallpass.core.context import Cancelled, Context, DeadlineExceeded, background, with_cancel, with_timeout, with_value
from hallpass.core.errors import as_error, is_error, wrap

MINUTE = 60.0
HOUR = 3600.0
MS = 0.001

Fill = Callable[[Context], tuple[Any, float]]


def do(c: TTL[Any, Any], ctx: Context, k: Any, fill: Fill | None) -> tuple[Any, BaseException | None]:
    """c.do as Go's Do: (value, error)."""
    try:
        return c.do(ctx, k, fill), None  # type: ignore[arg-type]
    except Exception as e:
        return None, e


def go(fn: Callable[[], object]) -> threading.Thread:
    t = threading.Thread(target=fn, daemon=True)
    t.start()
    return t


def rec_of(ctx: Context) -> evidence.Recorder:
    r = evidence.recorder_from(ctx)
    assert r is not None
    return r


def calls_of(rec: evidence.Recorder) -> list[evidence.Call]:
    ev = rec.evidence()
    return [] if ev is None else ev.calls()


def recv(q: queue.Queue[Any], timeout: float = 5.0) -> Any:
    """<-ch, failing rather than hanging when nothing arrives."""
    try:
        return q.get(timeout=timeout)
    except queue.Empty:
        pytest.fail("channel receive timed out")


def wait(ev: threading.Event, timeout: float = 5.0) -> None:
    assert ev.wait(timeout), "event not set in time"


class Atomic:
    def __init__(self) -> None:
        self._mu = threading.Lock()
        self._n = 0

    def add(self, d: int) -> int:
        with self._mu:
            self._n += d
            return self._n

    def load(self) -> int:
        with self._mu:
            return self._n


class Clock:
    """A settable clock, safe to read from fill threads."""

    def __init__(self, t: float) -> None:
        self._mu = threading.Lock()
        self._t = t

    def __call__(self) -> float:
        with self._mu:
            return self._t

    def tick(self, d: float) -> None:
        with self._mu:
            self._t += d


def _go_now() -> float:
    # Go: time.Now(). Whole seconds, so that clock arithmetic in float
    # seconds is exact as Go's integer nanoseconds are.
    return float(int(time.time()))


def _date(y: int, m: int, d: int) -> float:
    return datetime(y, m, d, tzinfo=timezone.utc).timestamp()


def inflight_count(c: TTL[Any, Any]) -> int:
    """The fills in flight, for the evidence test."""
    with c._lock:
        return len(c._inflight) + len(c._fresh)


class JoinCounter:
    """Counts, per key and kind, the callers that join a fill in one cache,
    through the cache's test hook."""

    def __init__(self) -> None:
        self._mu = threading.Lock()
        self.n: dict[tuple[Any, bool], int] = {}

    def hook(self, k: Any, fresh: bool) -> None:
        with self._mu:
            self.n[(k, fresh)] = self.n.get((k, fresh), 0) + 1

    def await_(self, k: Any, ordinary: int, fresh: int) -> None:
        """Spin until at least ordinary ordinary callers and fresh fresh
        callers have joined a fill for k (whichever fill they joined), so a
        test releases a fill only once the callers it wants on it have
        joined."""
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            with self._mu:
                o, f = self.n.get((k, False), 0), self.n.get((k, True), 0)
            if o >= ordinary and f >= fresh:
                return
            time.sleep(MS)
        pytest.fail(f"waiters on {k} did not arrive")


def track_joins(c: TTL[Any, Any]) -> JoinCounter:
    j = JoinCounter()
    with c._lock:
        c.joined = j.hook
    return j


def await_fresh(c: TTL[Any, Any], k: Any, want: bool) -> None:
    """Spin until k has (or no longer has) a fresh fill in flight."""
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        with c._lock:
            ok = k in c._fresh
        if ok == want:
            return
        time.sleep(MS)
    pytest.fail(f"fresh fill on {k}: in flight = {not want}, want {want}")


def test_get_set_expiry() -> None:
    c: TTL[str, int] = TTL(0)
    now = [1000.0]
    c.set_clock(lambda: now[0])
    c.set("a", 1, MINUTE)
    v, ok = c.get("a")
    assert ok and v == 1, "miss"
    now[0] += 61
    _, ok = c.get("a")
    assert not ok, "expired entry returned"
    c.set("b", 2, 0)
    _, ok = c.get("b")
    assert not ok, "zero ttl stored"


def test_evict_at_max() -> None:
    c: TTL[int, int] = TTL(3)
    for i in range(10):
        c.set(i, i, HOUR)
    assert c.len() <= 3, f"len {c.len()}"


def test_do_singleflight() -> None:
    c: TTL[str, int] = TTL(0)
    calls = Atomic()
    release = threading.Event()
    errors: list[str] = []

    def fill(_: Context) -> tuple[int, float]:
        calls.add(1)
        release.wait()
        return 7, MINUTE

    def worker() -> None:
        v, err = do(c, background(), "k", fill)
        if err is not None or v != 7:
            errors.append(f"got {v} {err}")

    threads = [go(worker) for _ in range(20)]
    time.sleep(20 * MS)
    release.set()
    for t in threads:
        t.join(5)
    assert not errors, errors
    assert calls.load() == 1, f"fill called {calls.load()} times"
    v, ok = c.get("k")
    assert ok and v == 7, "not stored"


def test_do_error_not_stored() -> None:
    c: TTL[str, int] = TTL(0)

    def boom(_: Context) -> tuple[int, float]:
        raise RuntimeError("boom")

    _, err = do(c, background(), "k", boom)
    assert err is not None, "expected error"
    _, ok = c.get("k")
    assert not ok, "error stored"
    v, err = do(c, background(), "k", lambda _: (1, 0))
    assert err is None and v == 1, (v, err)
    _, ok = c.get("k")
    assert not ok, "zero ttl stored"


def test_do_context_cancel_while_waiting() -> None:
    c: TTL[str, int] = TTL(0)
    release = threading.Event()

    def slow(_: Context) -> tuple[int, float]:
        release.wait()
        return 1, MINUTE

    go(lambda: do(c, background(), "k", slow))
    time.sleep(10 * MS)
    ctx, cancel = with_cancel(background())
    cancel()
    _, err = do(c, ctx, "k", lambda _: (2, 0))
    assert is_error(err, Cancelled), f"err = {err}"
    release.set()


def test_do_fill_panic_does_not_wedge_key() -> None:
    c: TTL[str, int] = TTL(0)
    calls = Atomic()
    entered = threading.Event()
    release = threading.Event()

    def fill(_: Context) -> tuple[int, float]:
        if calls.add(1) == 1:
            entered.set()
            release.wait()
            raise TypeError("boom")  # Go: panic("boom")
        return 9, MINUTE

    leader_err: list[BaseException | None] = [None]

    def leader() -> None:
        _, leader_err[0] = do(c, background(), "k", fill)

    lt = go(leader)
    wait(entered)
    waiter_errs: queue.Queue[BaseException | None] = queue.Queue()
    for _ in range(3):
        go(lambda: waiter_errs.put(do(c, background(), "k", fill)[1]))
    time.sleep(10 * MS)
    release.set()
    lt.join(5)
    pe = as_error(leader_err[0], PanicError)
    assert pe is not None and str(pe.value) == "boom" and "boom" in str(leader_err[0]), f"leader err = {leader_err[0]}"
    for _ in range(3):
        try:
            err = waiter_errs.get(timeout=2)
        except queue.Empty:
            pytest.fail("waiter wedged after fill panic")
        assert as_error(err, PanicError) is not None, f"waiter err = {err}"
    _, ok = c.get("k")
    assert not ok, "panic stored a value"
    # The key is not wedged: the next call runs fill again and succeeds.
    ctx, cancel = with_timeout(background(), 2)
    try:
        v, err = do(c, ctx, "k", fill)
    finally:
        cancel()
    assert err is None and v == 9, f"after panic: {v} {err}"
    assert calls.load() == 2, f"fill called {calls.load()} times, want 2"


def test_do_leader_cancel_does_not_abort_waiters() -> None:
    c: TTL[str, int] = TTL(0)
    calls = Atomic()
    entered = threading.Event()
    release = threading.Event()
    fill_ctx_err: list[BaseException | None] = [None]

    def fill(ctx: Context) -> tuple[int, float]:
        calls.add(1)
        assert not entered.is_set()  # Go: close(entered) twice would panic
        entered.set()
        ctx.wait(release)
        fill_ctx_err[0] = ctx.err()
        if fill_ctx_err[0] is not None:
            raise fill_ctx_err[0]
        return 7, MINUTE

    leader_ctx, cancel_leader = with_cancel(background())
    leader_done: queue.Queue[BaseException | None] = queue.Queue()
    go(lambda: leader_done.put(do(c, leader_ctx, "k", fill)[1]))
    wait(entered)
    waiter_done = threading.Event()
    got: list[Any] = [None, None]

    def waiter() -> None:
        try:
            got[0], got[1] = do(c, background(), "k", fill)
        finally:
            waiter_done.set()

    go(waiter)
    time.sleep(10 * MS)
    cancel_leader()
    err = recv(leader_done)
    assert is_error(err, Cancelled), f"leader err = {err}"
    assert not waiter_done.wait(20 * MS), "waiter returned before the fill finished"
    release.set()
    wait(waiter_done)
    wv, werr = got
    assert werr is None and wv == 7, f"waiter got {wv} {werr}; the leader's cancellation aborted the shared fill"
    assert fill_ctx_err[0] is None, f"fill context was cancelled: {fill_ctx_err[0]}"
    assert calls.load() == 1, f"fill called {calls.load()} times"
    v, ok = c.get("k")
    assert ok and v == 7, "not stored"


class _CtxKey:
    pass


def test_detach() -> None:
    key = _CtxKey()
    parent, cancel = with_cancel(with_value(background(), key, "v"))
    d, dcancel = detach(parent, MINUTE)
    try:
        assert d.value(key) == "v", "value not kept"
        rem = d.remaining()
        assert rem is not None and 50 <= rem <= MINUTE, f"fallback deadline {rem}"
        cancel()
        assert d.err() is None, f"cancellation propagated: {d.err()}"
    finally:
        dcancel()
    parent2, cancel2 = with_timeout(background(), 5)
    d2, dcancel2 = detach(parent2, MINUTE)
    try:
        rem2 = d2.remaining()
        assert rem2 is not None and rem2 <= 5, f"leader deadline not carried: {rem2}"
    finally:
        dcancel2()
        cancel2()


def test_do_evidence() -> None:
    """Do carries the evidence of a fill to every caller it serves: the
    leader gets the calls as its own, a waiter gets them marked shared, a
    later hit gets them marked cached, and a fill that failed still reports
    what it saw to its leader."""
    c: TTL[str, int] = TTL(0)
    jc = track_joins(c)

    def call(p: str) -> evidence.Call:
        return evidence.Call(method="GET", path=p, status=200)

    def fill(ctx: Context) -> tuple[int, float]:
        rec_of(ctx).record(call("/lookup"))
        return 1, MINUTE

    ctx, rec = evidence.with_recorder(background())
    _, err = do(c, ctx, "k", fill)
    assert err is None, err
    ev = rec.evidence()
    assert ev is not None and len(ev.calls()) == 1 and not ev.calls()[0].cached and ev.calls()[0].path == "/lookup", f"leader: {ev}"
    # A hit replays the fill's evidence, marked cached.
    ctx2, rec2 = evidence.with_recorder(background())
    _, err = do(c, ctx2, "k", fill)
    assert err is None, err
    ev = rec2.evidence()
    assert ev is not None and len(ev.calls()) == 1 and ev.calls()[0].cached, f"hit: {ev}"
    # A context without a recorder is fine.
    _, err = do(c, background(), "k", fill)
    assert err is None, err

    # A waiter on another caller's fill gets the calls marked shared; the
    # leader gets them as its own.
    started = threading.Event()
    release = threading.Event()

    def slow(ctx: Context) -> tuple[int, float]:
        rec_of(ctx).record(call("/slow"))
        # The waiter joins the in-flight call: its own fill never runs (in
        # Go it would close started twice and panic).
        assert not started.is_set(), "a second slow fill ran"
        started.set()
        release.wait()
        return 2, MINUTE

    lctx, lrec = evidence.with_recorder(background())
    wctx, wrec = evidence.with_recorder(background())
    t1 = go(lambda: do(c, lctx, "slow", slow))
    wait(started)
    t2 = go(lambda: do(c, wctx, "slow", slow))
    while inflight_count(c) != 1:
        time.sleep(MS)
    jc.await_("slow", 1, 0)
    release.set()
    t1.join(5)
    t2.join(5)
    # The leader made the call; the waiter joined it: shared, not cached.
    ev = lrec.evidence()
    assert ev is not None and len(ev.calls()) == 1 and not ev.calls()[0].cached and not ev.calls()[0].shared, f"leader of shared fill: {ev}"
    ev = wrec.evidence()
    assert ev is not None and len(ev.calls()) == 1 and not ev.calls()[0].cached and ev.calls()[0].shared, f"waiter: {ev}"

    # A failed fill is not stored but its leader still sees the evidence;
    # a fill that asks not to be stored (ttl 0) is live evidence too.
    ectx, erec = evidence.with_recorder(background())

    def failing(ctx: Context) -> tuple[int, float]:
        rec_of(ctx).record(evidence.Call(method="GET", path="/err", status=503))
        raise RuntimeError("upstream")

    _, err = do(c, ectx, "err", failing)
    assert err is not None, "no error"
    ev = erec.evidence()
    assert ev is not None and len(ev.calls()) == 1 and ev.calls()[0].status == 503 and not ev.calls()[0].cached, f"failed fill: {ev}"
    zctx, zrec = evidence.with_recorder(background())

    def zero(ctx: Context) -> tuple[int, float]:
        rec_of(ctx).record(call("/zero"))
        return 0, 0

    do(c, zctx, "zero", zero)
    ev = zrec.evidence()
    assert ev is not None and len(ev.calls()) == 1 and not ev.calls()[0].cached, f"unstored fill: {ev}"
    _, ok = c.get("zero")
    assert not ok, "ttl 0 stored"
    # Set stores no evidence, so a hit on it replays nothing.
    c.set("set", 3, MINUTE)
    sctx, srec = evidence.with_recorder(background())
    do(c, sctx, "set", fill)
    assert srec.evidence() is None, f"Set entry has evidence: {srec.evidence()}"


def test_do_fresh() -> None:
    """Under a fresh context Do looks the value up again, ignoring the entry
    and any fill in flight, records the calls as its own, and stores the
    answer for the callers after it."""
    c: TTL[str, int] = TTL(0)
    jc = track_joins(c)
    clock = Clock(_go_now())
    c.set_clock(clock)
    tick = clock.tick
    fills = Atomic()

    def fill(ctx: Context) -> tuple[int, float]:
        n = fills.add(1)
        rec_of(ctx).record(evidence.Call(method="GET", path="/v", status=200, etag=str(n)))
        return n, MINUTE

    ctx = background()
    v, _ = do(c, ctx, "k", fill)
    assert v == 1, v
    v, _ = do(c, ctx, "k", fill)
    assert v == 1 and fills.load() == 1, "not cached"
    # Within the join window a fresh caller takes the entry, dated now;
    # past it, it reads again.
    v, _ = do(c, evidence.with_fresh(ctx), "k", fill)
    assert v == 1 and fills.load() == 1, f"fresh caller re-read an entry younger than the window: v={v} fills={fills.load()}"
    tick(FRESH_JOIN_WINDOW)
    fctx, frec = evidence.with_recorder(evidence.with_fresh(ctx))
    v, err = do(c, fctx, "k", fill)
    assert err is None and v == 2 and fills.load() == 2, f"fresh: {v} {err} fills={fills.load()}"
    ev = frec.evidence()
    assert ev is not None and len(ev.calls()) == 1 and not ev.calls()[0].cached and ev.calls()[0].etag == "2", f"fresh evidence: {ev}"
    # The fresh answer replaced the entry, evidence included.
    nctx, nrec = evidence.with_recorder(ctx)
    v, _ = do(c, nctx, "k", fill)
    assert v == 2 and fills.load() == 2, "fresh answer not stored"
    ev = nrec.evidence()
    assert ev is not None and ev.calls()[0].cached and ev.calls()[0].etag == "2", f"after fresh: {ev}"

    # A fresh caller does not join an ordinary fill in flight that began
    # before the window, and the older fill finishing later does not
    # replace the fresh answer.
    started = threading.Event()
    release = threading.Event()

    def slow(_: Context) -> tuple[int, float]:
        started.set()
        release.wait()
        return 100, MINUTE

    slow_done = go(lambda: do(c, ctx, "slow", slow))
    wait(started)
    tick(FRESH_JOIN_WINDOW)  # the slow fill is now too old for a fresh caller
    done: queue.Queue[Any] = queue.Queue()
    go(lambda: done.put(do(c, evidence.with_fresh(ctx), "slow", lambda _: (7, MINUTE))[0]))
    try:
        v = done.get(timeout=2)
    except queue.Empty:
        pytest.fail("fresh caller waited for the in-flight fill")
    assert v == 7, v
    release.set()
    slow_done.join(5)
    v, ok = c.get("slow")
    assert ok and v == 7, f"older fill replaced the fresh answer: {v} {ok}"
    # The other order: the older fill stores while the fresh one is still
    # running. The fresh answer still stands, since its read began later.
    started2 = threading.Event()
    release2 = threading.Event()

    def slow2(_: Context) -> tuple[int, float]:
        started2.set()
        release2.wait()
        return 100, MINUTE

    slow_done2 = go(lambda: do(c, ctx, "order", slow2))
    wait(started2)
    tick(FRESH_JOIN_WINDOW)
    fstarted2 = threading.Event()
    frelease2 = threading.Event()

    def fresh2(_: Context) -> tuple[int, float]:
        fstarted2.set()
        frelease2.wait()
        return 7, MINUTE

    fresh_done2 = go(lambda: do(c, evidence.with_fresh(ctx), "order", fresh2))
    wait(fstarted2)
    release2.set()  # the older read stores first
    slow_done2.join(5)
    v, ok = c.get("order")
    assert ok and v == 100, f"older read not stored while the fresh one runs: {v} {ok}"
    frelease2.set()
    fresh_done2.join(5)
    v, ok = c.get("order")
    assert ok and v == 7, f"fresh answer lost to an older read that stored first: {v} {ok}"
    # Store (the engine's decision cache) follows the same rule.
    c.store("order", 1, MINUTE, clock() - HOUR, clock() - HOUR)
    v, _ = c.get("order")
    assert v == 7, "Store replaced a newer entry"
    tick(MS)
    c.store("order", 2, MINUTE, clock(), clock())
    v, _ = c.get("order")
    assert v == 2, "Store did not replace an older entry"
    c.store("order", 3, 0, clock() - HOUR, clock() - HOUR)
    _, ok = c.get("order")
    assert ok, "Store with ttl 0 dropped a newer entry"
    c.store("order", 3, 0, clock(), clock())
    _, ok = c.get("order")
    assert not ok, "Store with ttl 0 kept an older entry"

    # Fresh fills are kept apart from ordinary ones: an ordinary caller
    # joins the ordinary fill in flight, a fresh one within the join
    # window shares the fresh fill, one arriving later reads again, and
    # the latest read's answer is what the cache keeps.
    fresh_fills = Atomic()
    ostarted = threading.Event()
    orelease = threading.Event()

    def ordinary(_: Context) -> tuple[int, float]:
        ostarted.set()
        orelease.wait()
        return 10, MINUTE

    ordinary_done: queue.Queue[Any] = queue.Queue()
    go(lambda: ordinary_done.put(do(c, ctx, "join", ordinary)[0]))
    wait(ostarted)
    tick(FRESH_JOIN_WINDOW)  # the ordinary fill is now too old for a fresh caller to join
    fstarted = threading.Event()
    frelease = threading.Event()

    def joinable(_: Context) -> tuple[int, float]:
        fresh_fills.add(1)
        fstarted.set()
        frelease.wait()
        return 11, MINUTE

    fresh_done: queue.Queue[Any] = queue.Queue()
    go(lambda: fresh_done.put(do(c, evidence.with_fresh(ctx), "join", joinable)[0]))
    wait(fstarted)
    joined: queue.Queue[Any] = queue.Queue()

    def another(_: Context) -> tuple[int, float]:
        fresh_fills.add(1)
        return 12, MINUTE

    go(lambda: joined.put(do(c, ctx, "join", another)[0]))
    fresh_joined: queue.Queue[Any] = queue.Queue()
    go(lambda: fresh_joined.put(do(c, evidence.with_fresh(ctx), "join", another)[0]))
    jc.await_("join", 1, 1)
    # A fresh fill still in flight is shared however long ago it began.
    tick(FRESH_JOIN_WINDOW + 1)
    late_joined: queue.Queue[Any] = queue.Queue()
    go(lambda: late_joined.put(do(c, evidence.with_fresh(ctx), "join", another)[0]))
    jc.await_("join", 1, 2)
    frelease.set()
    for ch in (fresh_joined, late_joined, fresh_done):
        v = recv(ch)
        assert v == 11 and fresh_fills.load() == 1, f"fresh caller did not share the fresh fill: v={v} fills={fresh_fills.load()}"
    # Once it is done and its entry older than the window, a fresh caller
    # reads again.
    tick(FRESH_JOIN_WINDOW)
    v, _ = do(c, evidence.with_fresh(ctx), "join", another)
    assert v == 12 and fresh_fills.load() == 2, f"fresh caller took an entry older than the window: v={v} fills={fresh_fills.load()}"
    orelease.set()
    v = recv(joined)
    assert v == 10, f"ordinary caller did not join the ordinary fill: {v}"
    v = recv(ordinary_done)
    assert v == 10, f"ordinary leader lost its fill: {v}"
    v, _ = c.get("join")
    assert v == 12, f"an older read replaced the latest fresh answer: {v}"

    # An ordinary caller with a valid entry takes it even while a fresh
    # read is in flight, and never waits on it.
    c.set("keep", 1, MINUTE)
    tick(FRESH_JOIN_WINDOW)
    dstarted = threading.Event()
    drelease = threading.Event()

    def keep_fresh(_: Context) -> tuple[int, float]:
        dstarted.set()
        drelease.wait()
        return 2, MINUTE

    go(lambda: do(c, evidence.with_fresh(ctx), "keep", keep_fresh))
    wait(dstarted)
    v, _ = do(c, ctx, "keep", lambda _: (3, MINUTE))
    assert v == 1, f"ordinary caller got {v} while a fresh read was in flight, want the entry's 1"
    drelease.set()
    await_fresh(c, "keep", False)
    v, _ = c.get("keep")
    assert v == 2, f"fresh answer not stored: {v}"
    # With no entry and no ordinary fill, an ordinary caller joins the
    # fresh read (shared); when that read fails it gets the failure,
    # unless an entry has landed meanwhile.
    fstart = threading.Event()
    ffail = threading.Event()
    ferr: queue.Queue[BaseException | None] = queue.Queue()

    def joinfail(_: Context) -> tuple[int, float]:
        fstart.set()
        ffail.wait()
        raise RuntimeError("upstream")

    go(lambda: ferr.put(do(c, evidence.with_fresh(ctx), "joinfail", joinfail)[1]))
    wait(fstart)
    octx, orec = evidence.with_recorder(ctx)
    ogot: queue.Queue[BaseException | None] = queue.Queue()
    go(lambda: ogot.put(do(c, octx, "joinfail", lambda _: (3, MINUTE))[1]))
    jc.await_("joinfail", 1, 0)
    ffail.set()
    assert recv(ferr) is not None, "fresh caller did not get the error"
    assert recv(ogot) is not None, "ordinary caller that joined the failed fresh read got no error"
    ev = orec.evidence()
    assert ev is None or len(ev.calls()) == 0, f"ordinary caller's evidence: {ev.calls()}"
    # Same, but an entry lands (from an ordinary fill) before the fresh
    # read fails: the ordinary caller takes the entry.
    fstart2 = threading.Event()
    ffail2 = threading.Event()

    def landed_fill(_: Context) -> tuple[int, float]:
        fstart2.set()
        ffail2.wait()
        raise RuntimeError("upstream")

    go(lambda: do(c, evidence.with_fresh(ctx), "landed", landed_fill))
    wait(fstart2)
    got2: queue.Queue[Any] = queue.Queue()
    go(lambda: got2.put(do(c, ctx, "landed", lambda _: (3, MINUTE))[0]))
    jc.await_("landed", 1, 0)
    c.set("landed", 4, MINUTE)
    ffail2.set()
    v = recv(got2)
    assert v == 4, f"ordinary caller got {v}, want the entry that landed"
    # A failed fill's own calls stay on the record of the caller an entry
    # answered, next to the entry's, and do not date the answer.
    fctx3, frec3 = evidence.with_recorder(ctx)
    fstart3 = threading.Event()
    ffail3 = threading.Event()
    got3: queue.Queue[Any] = queue.Queue()

    def failed_record(ctx: Context) -> tuple[int, float]:
        rec_of(ctx).record(evidence.Call(method="GET", path="/failed", status=503))
        fstart3.set()
        ffail3.wait()
        raise RuntimeError("upstream")

    go(lambda: got3.put(do(c, fctx3, "failed-record", failed_record)[0]))
    wait(fstart3)
    _landed_ctx, landed_rec = evidence.with_recorder(ctx)
    landed_rec.record(evidence.Call(method="GET", path="/landed", status=200))
    now = clock()
    with c._lock:
        c._store_locked("failed-record", 6, MINUTE, landed_rec.evidence(), now - HOUR, now, now, now)
    ffail3.set()
    v = recv(got3)
    assert v == 6, f"got {v}"
    calls = calls_of(frec3)
    assert len(calls) == 2 and calls[0].path == "/failed" and not calls[0].cached and calls[1].path == "/landed" and calls[1].cached, (
        f"record after a failed fill answered by an entry: {calls}"
    )
    o = frec3.oldest()
    assert o is not None and o == now - HOUR, f"dated {o}, want the entry's read"

    # With a fresh max age, a fresh caller takes an entry younger than it
    # and reads again past it.
    aged: TTL[str, int] = TTL(0)
    ja = track_joins(aged)
    aged.set_clock(clock)
    aged.set_fresh_max_age(MINUTE)
    aged_fills = Atomic()

    def aged_fill(_: Context) -> tuple[int, float]:
        return aged_fills.add(1), HOUR

    actx, arec = evidence.with_recorder(evidence.with_fresh(ctx))
    v, _ = do(aged, actx, "k", aged_fill)
    assert v == 1, v
    v, _ = do(aged, actx, "k", aged_fill)
    assert v == 1 and aged_fills.load() == 1, f"young entry not taken by a fresh caller: v={v} fills={aged_fills.load()}"
    assert len(calls_of(arec)) == 0, f"no calls were recorded, got {calls_of(arec)}"
    # The young entry a fresh caller took is dated by its read for
    # ordering, and as of now as a fresh check judges it.
    o = arec.oldest()
    assert o is not None and o == clock(), f"fresh reuse dated {o}, want the entry's read ({clock()})"
    o = arec.oldest_strict()
    assert o is not None and not o < clock(), f"fresh reuse judged {o}, want now ({clock()})"
    tick(1)
    octx2, orec2 = evidence.with_recorder(ctx)
    do(aged, octx2, "k", aged_fill)
    o = orec2.oldest()
    assert o is not None and o < clock(), f"ordinary hit dated {o}, want the entry's read"
    # ... and under this cache's minute-long fresh max age the entry is
    # still one a fresh check would take, so it is judged as of now.
    o = orec2.oldest_strict()
    assert o is not None and not o < clock(), f"ordinary hit of a tolerated entry judged {o}, want now"
    tick(MINUTE)
    v, _ = do(aged, actx, "k", aged_fill)
    assert v == 2 and aged_fills.load() == 2, f"aged entry served to a fresh caller: v={v} fills={aged_fills.load()}"
    # A fresh fill in flight is shared whatever its age.
    astarted = threading.Event()
    arelease = threading.Event()

    def share_fill(_: Context) -> tuple[int, float]:
        aged_fills.add(1)
        astarted.set()
        arelease.wait()
        return 10, HOUR

    go(lambda: do(aged, evidence.with_fresh(ctx), "share", share_fill))
    wait(astarted)
    tick(FRESH_JOIN_WINDOW + 1)
    shared: queue.Queue[Any] = queue.Queue()
    go(lambda: shared.put(do(aged, evidence.with_fresh(ctx), "share", aged_fill)[0]))
    ja.await_("share", 0, 1)
    arelease.set()
    v = recv(shared)
    assert v == 10 and aged_fills.load() == 3, f"fresh caller within the max age did not share the fill: v={v} fills={aged_fills.load()}"
    # ... and an ordinary fill that began within the window as well (here
    # the max age, being longer).
    ostarted2 = threading.Event()
    orelease2 = threading.Event()

    def ordinary_fill(_: Context) -> tuple[int, float]:
        aged_fills.add(1)
        ostarted2.set()
        orelease2.wait()
        return 20, HOUR

    go(lambda: do(aged, ctx, "ordinary", ordinary_fill))
    wait(ostarted2)
    shared_o: queue.Queue[Any] = queue.Queue()
    go(lambda: shared_o.put(do(aged, evidence.with_fresh(ctx), "ordinary", aged_fill)[0]))
    ja.await_("ordinary", 0, 1)
    orelease2.set()
    v = recv(shared_o)
    assert v == 20 and aged_fills.load() == 4, f"fresh caller within the max age did not share the ordinary fill: v={v} fills={aged_fills.load()}"

    # A panic in a fresh fill is a PanicError, like any other.
    def panics(_: Context) -> tuple[int, float]:
        raise TypeError("x")  # Go: panic("x")

    _, err = do(c, evidence.with_fresh(ctx), "boom", panics)
    assert as_error(err, PanicError) is not None, f"fresh panic: {err}"

    # A failed fresh lookup stores nothing and leaves the entry for
    # ordinary callers; a fresh answer with ttl 0 removes it.
    c.set("k", 2, MINUTE)
    tick(FRESH_JOIN_WINDOW)

    def fails(_: Context) -> tuple[int, float]:
        raise RuntimeError("x")

    _, err = do(c, evidence.with_fresh(ctx), "k", fails)
    assert err is not None, "no error"
    v, ok = c.get("k")
    assert ok and v == 2, "entry lost on a failed fresh lookup"
    tick(FRESH_JOIN_WINDOW)
    v, err = do(c, evidence.with_fresh(ctx), "k", lambda _: (9, 0))
    assert err is None and v == 9, (v, err)
    _, ok = c.get("k")
    assert not ok, "ttl 0 fresh answer stored"


def test_do_failed_leader_takes_landed_entry() -> None:
    """The leader of an ordinary fill that fails takes an entry that landed
    meanwhile, like its waiters do."""
    c: TTL[str, int] = TTL(0)
    started = threading.Event()
    fail = threading.Event()
    got: queue.Queue[Any] = queue.Queue()

    def fill(_: Context) -> tuple[int, float]:
        started.set()
        fail.wait()
        raise RuntimeError("upstream")

    go(lambda: got.put(do(c, background(), "k", fill)[0]))
    wait(started)
    c.set("k", 5, MINUTE)
    fail.set()
    v = recv(got)
    assert v == 5, f"failed leader got {v}, want the entry that landed"
    # An expired resident does not block a live store.
    e: TTL[str, int] = TTL(0)
    clock = Clock(_go_now())
    e.set_clock(clock)
    e.store("k", 1, 1, clock(), clock())
    clock.tick(2)
    e.store("k", 2, MINUTE, clock() - HOUR, clock() - HOUR)
    v, ok = e.get("k")
    assert ok and v == 2, f"live store lost to an expired resident: {v} {ok}"


def test_do_no_refill_on_upstream_timeout() -> None:
    """A refill happens only when the fill's own context ended, not when the
    upstream timed out with time to spare: a waiter then gets the failure
    like the leader."""
    c: TTL[str, int] = TTL(0)
    fills = Atomic()
    started = threading.Event()

    def fill(_: Context) -> tuple[int, float]:
        fills.add(1)
        started.set()
        time.sleep(20 * MS)
        # Go: fmt.Errorf("upstream: %w", context.DeadlineExceeded)
        raise wrap(RuntimeError("upstream: context deadline exceeded"), DeadlineExceeded())

    go(lambda: do(c, background(), "k", fill))
    wait(started)
    _, err = do(c, background(), "k", fill)
    assert is_error(err, DeadlineExceeded) and fills.load() == 1, f"waiter refilled on an upstream timeout: err={err} fills={fills.load()}"


def test_do_fresh_joiner_rejects_old_reads() -> None:
    """A fresh caller that joined a young ordinary fill reads on its own when
    that fill turns out to rest on cached reads older than the window."""
    inner: TTL[str, int] = TTL(0)
    outer: TTL[str, int] = TTL(0)
    clock = Clock(_date(2026, 1, 1))
    inner.set_clock(clock)
    outer.set_clock(clock)
    do(inner, background(), "in", lambda _: (1, HOUR))
    clock.tick(MINUTE)
    jo = track_joins(outer)
    started = threading.Event()
    release = threading.Event()
    fills = Atomic()

    def fill(ctx: Context) -> tuple[int, float]:
        n = fills.add(1)
        v, _ = do(inner, ctx, "in", lambda _: (2, HOUR))
        if n == 1:
            started.set()
            release.wait()
        return v * 10 + n, HOUR

    go(lambda: do(outer, background(), "out", fill))
    wait(started)
    got: queue.Queue[Any] = queue.Queue()
    go(lambda: got.put(do(outer, evidence.with_fresh(background()), "out", fill)[0]))
    jo.await_("out", 0, 1)
    release.set()
    # The ordinary fill rested on the minute-old inner entry: the fresh
    # caller read again, and its own read went through the inner cache
    # fresh too.
    v = recv(got)
    assert v == 22 and fills.load() == 2, f"fresh joiner accepted old reads: v={v} fills={fills.load()}"
    # Its answer is the one stored: the ordinary fill's is older.
    v, _ = outer.get("out")
    assert v == 22, f"stored {v}"
    # A fresh caller's own age check looks at when the entry's read began,
    # not at the older reads it rests on.
    v, _ = do(outer, evidence.with_fresh(background()), "out", fill)
    assert v == 22 and fills.load() == 2, f"young entry re-read by a fresh caller: v={v} fills={fills.load()}"


def test_panic_error_first_report() -> None:
    """Every caller of a panicked fill gets the same PanicError, and only the
    first to ask reports it."""
    c: TTL[str, int] = TTL(0)
    jc = track_joins(c)
    started = threading.Event()
    release = threading.Event()
    errs: queue.Queue[BaseException | None] = queue.Queue()

    def fill(_: Context) -> tuple[int, float]:
        assert not started.is_set()  # Go: close(started) twice would panic
        started.set()
        release.wait()
        raise TypeError("x")  # Go: panic("x")

    for i in range(3):
        go(lambda: errs.put(do(c, background(), "k", fill)[1]))
        if i == 0:
            wait(started)
    jc.await_("k", 2, 0)
    release.set()
    reports = 0
    for _ in range(3):
        err = recv(errs)
        pe = as_error(err, PanicError)
        assert pe is not None, err
        if pe.first_report():
            reports += 1
    assert reports == 1, f"first reports = {reports}"


def test_do_panic_not_covered_by_entry() -> None:
    """A fill that panicked is reported even when an entry landed meanwhile."""
    c: TTL[str, int] = TTL(0)
    started = threading.Event()
    release = threading.Event()
    errs: queue.Queue[BaseException | None] = queue.Queue()

    def fill(_: Context) -> tuple[int, float]:
        started.set()
        release.wait()
        raise TypeError("boom")  # Go: panic("boom")

    go(lambda: errs.put(do(c, background(), "k", fill)[1]))
    wait(started)
    c.set("k", 5, MINUTE)
    release.set()
    err = recv(errs)
    assert as_error(err, PanicError) is not None, f"panic covered by the entry: {err}"
    # Refresh reads now, whatever the cache holds, and stores with the
    # read's evidence.
    rctx, rrec = evidence.with_recorder(background())

    def probe(ctx: Context) -> tuple[int, float]:
        rec_of(ctx).record(evidence.Call(method="GET", path="/probe", status=200))
        return 6, MINUTE

    v = c.refresh(rctx, "k", probe)
    assert v == 6, v
    calls = calls_of(rrec)
    assert len(calls) == 1 and calls[0].path == "/probe", f"refresh evidence: {calls}"
    hctx, hrec = evidence.with_recorder(background())
    v, _ = do(c, hctx, "k", None)
    hcalls = calls_of(hrec)
    assert v == 6 and len(hcalls) == 1 and hcalls[0].cached, f"refreshed entry: v={v} evidence={hcalls}"


def test_do_dates_reads() -> None:
    """A hit and a fill date the caller's record by when the read began, and
    an entry is as old as the oldest cached read its fill rested on: a later
    fill built on an older input does not replace a newer entry."""
    c: TTL[str, int] = TTL(0)
    clock = Clock(_date(2026, 1, 1))
    c.set_clock(clock)
    tick = clock.tick
    t0 = clock()

    def fill(_: Context) -> tuple[int, float]:
        return 1, HOUR

    do(c, background(), "in", fill)
    tick(MINUTE)
    # A hit is dated by the entry's read.
    hctx, hrec = evidence.with_recorder(background())
    do(c, hctx, "in", fill)
    o = hrec.oldest()
    assert o is not None and o == t0, f"hit dated {o}, want {t0}"
    # A fill that reads the cached input is as old as that input.
    built: TTL[str, int] = TTL(0)
    built.set_clock(clock)

    def build(ctx: Context) -> tuple[int, float]:
        v, _ = do(c, ctx, "in", fill)
        return v + 10, HOUR

    do(built, background(), "out", build)
    tick(MINUTE)
    # A read that began now, before the built entry's own start but after
    # its input, still replaces it: the built entry is dated by its input
    # at t0.
    built.store("out", 99, HOUR, t0 + 30, t0 + 30)
    v, _ = built.get("out")
    assert v == 99, f"entry dated by its own start, not its oldest input: {v}"
    # And one older than the input does not.
    built.store("out", 7, HOUR, t0 - 1, t0 - 1)
    v, _ = built.get("out")
    assert v == 99, f"older read replaced the entry: {v}"
    # On the same inputs, the read that began later wins, whichever
    # finished first: a fresh decision at t0+0.5s is replaced by an
    # ordinary one whose own reads began at t0+10s, and not by one whose
    # own reads began before it.
    d: TTL[str, int] = TTL(0)
    d.store("d", 1, HOUR, t0, t0 + 0.5)  # fresh, own reads at +0.5s
    d.store("d", 2, HOUR, t0, t0 + 0.3)  # ordinary, own reads at +0.3s
    v, _ = d.get("d")
    assert v == 1, f"a check whose reads began earlier replaced the fresh decision: {v}"
    d.store("d", 3, HOUR, t0, t0 + 10)  # ordinary, own reads at +10s
    v, _ = d.get("d")
    assert v == 3, f"a check whose reads began later did not replace the fresh decision: {v}"


def _slow_fill(counter: Atomic) -> Fill:
    """Go: select { case <-ctx.Done(): return ctx.Err(); case <-time.After(150ms): return n }."""

    def fill(ctx: Context) -> tuple[int, float]:
        n = counter.add(1)
        after = threading.Event()
        timer = threading.Timer(150 * MS, after.set)
        timer.daemon = True
        timer.start()
        try:
            if not ctx.wait(after):
                err = ctx.err()
                assert err is not None
                raise err
        finally:
            timer.cancel()
        return n, MINUTE

    return fill


def test_do_waiter_refills_after_leader_deadline() -> None:
    """A waiter is not failed by the leader's deadline: when the shared fill
    ended because the leader's remaining time ran out, the waiter, which has
    time left, fills again with its own context."""
    c: TTL[str, int] = TTL(0)
    fills = Atomic()
    fill = _slow_fill(fills)
    leader_ctx, cancel = with_timeout(background(), 50 * MS)
    try:
        leader_err: queue.Queue[BaseException | None] = queue.Queue()
        go(lambda: leader_err.put(do(c, leader_ctx, "k", fill)[1]))
        while inflight_count(c) != 1:
            time.sleep(MS)
        wctx, wrec = evidence.with_recorder(background())
        v, err = do(c, wctx, "k", fill)
        assert err is None and v == 2 and fills.load() == 2, f"waiter: v={v} err={err} fills={fills.load()}"
        assert is_error(recv(leader_err), DeadlineExceeded), "leader did not get its own deadline"
        assert wrec.evidence() is None, f"no calls were recorded, yet: {calls_of(wrec)}"
        got, ok = c.get("k")
        assert ok and got == 2, "waiter's answer not stored"
    finally:
        cancel()

    # The refill runs on the waiter's own fill: a third caller's short
    # deadline in flight at that moment does not fail it.
    c2: TTL[str, int] = TTL(0)
    fills2 = Atomic()
    slow_fill = _slow_fill(fills2)
    short_ctx, cancel2 = with_timeout(background(), 50 * MS)
    try:
        go(lambda: do(c2, short_ctx, "k", slow_fill))
        while inflight_count(c2) != 1:
            time.sleep(MS)
        # Another short-deadline leader keeps starting fills the waiter
        # would otherwise join on its refill.
        stop = threading.Event()

        def stranger() -> None:
            while not stop.is_set():
                sctx, scancel = with_timeout(background(), 50 * MS)
                do(c2, sctx, "k", slow_fill)
                scancel()

        go(stranger)
        v2, err2 = do(c2, background(), "k", slow_fill)
        stop.set()
        assert err2 is None and v2 not in (None, 0), f"waiter failed by a stranger's deadline: v={v2} err={err2}"
    finally:
        cancel2()
