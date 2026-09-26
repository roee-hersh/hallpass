"""Port of internal/authx/token_test.go."""

from __future__ import annotations

import queue
import threading
import time

import pytest

from hallpass.authx.sigv4 import AWSCredentials
from hallpass.authx.sts import CachedProvider
from hallpass.authx.token import Token, TokenSource
from hallpass.core import evidence
from hallpass.core.cache import PanicError
from hallpass.core.context import Cancelled, Context, background, with_cancel, with_timeout
from hallpass.core.errors import as_error, is_error


class _Counter:
    """sync/atomic.Int32."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._n = 0

    def add(self, d: int) -> int:
        with self._lock:
            self._n += d
            return self._n

    def load(self) -> int:
        with self._lock:
            return self._n

    def store(self, n: int) -> None:
        with self._lock:
            self._n = n


def test_token_source_fetch_is_not_evidence() -> None:
    """A token fetch is never evidence: the fetch runs without the caller's
    Recorder, whether the caller is the one that triggered it or a waiter."""
    saw_recorder = threading.Event()

    def fetch(ctx: Context) -> Token:
        if evidence.recorder_from(ctx) is not None:
            saw_recorder.set()
        return Token("t")

    src = TokenSource(fetch)
    ctx, rec = evidence.with_recorder(background())
    src.get(ctx)
    if saw_recorder.is_set() or rec.evidence() is not None:
        pytest.fail("token fetch ran with the check's recorder")

    def fetch_creds(ctx: Context) -> AWSCredentials:
        if evidence.recorder_from(ctx) is not None:
            saw_recorder.set()
        return AWSCredentials(access_key_id="a", secret_access_key="s")

    p = CachedProvider(fetch_creds)
    p.credentials(ctx)
    if saw_recorder.is_set():
        pytest.fail("credential fetch ran with the check's recorder")


def test_token_source_caches_and_refreshes_early() -> None:
    now = [1_000_000.0]
    fetches = _Counter()

    def fetch(ctx: Context) -> Token:
        n = fetches.add(1)
        return Token("tok" + chr(ord("0") + n), now[0] + 3600)

    src = TokenSource(fetch, now=lambda: now[0])
    ctx = background()
    v = src.get(ctx)
    assert v == "tok1"
    now[0] += 50 * 60
    assert src.get(ctx) == "tok1", "refetched too early"
    now[0] += 6 * 60  # 56 min: within 5 min of expiry
    v = src.get(ctx)
    assert v == "tok2", f"not refreshed early: {v}"
    src.invalidate()
    v = src.get(ctx)
    assert v == "tok3", f"invalidate: {v}"


def test_token_source_default_ttl_and_short_tokens() -> None:
    now = [1_000_000.0]
    fetches = _Counter()

    def fetch(ctx: Context) -> Token:
        fetches.add(1)
        return Token("t")

    src = TokenSource(fetch, now=lambda: now[0])
    src.get(background())
    now[0] += 9 * 60
    src.get(background())
    assert fetches.load() == 1, "default ttl 15m minus 5m early should still be cached at 9m"
    now[0] += 2 * 60
    src.get(background())
    assert fetches.load() == 2, "should refresh at 10m"

    # A 2-minute token refreshes at its half life, not immediately.
    def fetch2(ctx: Context) -> Token:
        fetches.add(1)
        return Token("s", now[0] + 120)

    src2 = TokenSource(fetch2, now=lambda: now[0])
    fetches.store(0)
    src2.get(background())
    now[0] += 30
    src2.get(background())
    assert fetches.load() == 1, "short token refetched before half life"
    now[0] += 45
    src2.get(background())
    assert fetches.load() == 2, "short token not refreshed after half life"


def test_token_source_singleflight_and_errors() -> None:
    fetches = _Counter()
    release = threading.Event()

    def fetch(ctx: Context) -> Token:
        fetches.add(1)
        release.wait()
        return Token("t")

    src = TokenSource(fetch)
    errors: queue.Queue[str] = queue.Queue()

    def get() -> None:
        try:
            v = src.get(background())
            if v != "t":
                errors.put(f"got {v!r}")
        except Exception as e:
            errors.put(repr(e))

    threads = [threading.Thread(target=get) for _ in range(10)]
    for t in threads:
        t.start()
    time.sleep(0.02)
    release.set()
    for t in threads:
        t.join()
    assert errors.empty(), errors.get()
    assert fetches.load() == 1, f"fetches = {fetches.load()}"

    def failing_fetch(ctx: Context) -> Token:
        raise ValueError("nope")

    failing = TokenSource(failing_fetch)
    with pytest.raises(Exception):  # noqa: B017 - any error
        failing.get(background())
    with pytest.raises(Exception):  # noqa: B017 - no fetch
        TokenSource(None).get(background())


def test_token_source_fetch_panic_does_not_wedge() -> None:
    fetches = _Counter()
    entered = threading.Event()
    release = threading.Event()

    def fetch(ctx: Context) -> Token:
        if fetches.add(1) == 1:
            entered.set()
            release.wait()
            # Go: panic("boom"). A bug exception type is Python's panic.
            raise TypeError("boom")
        return Token("ok")

    src = TokenSource(fetch)
    leader_err: queue.Queue[BaseException | None] = queue.Queue(1)

    def get_into(q: queue.Queue[BaseException | None]) -> None:
        try:
            src.get(background())
            q.put(None)
        except BaseException as e:
            q.put(e)

    threading.Thread(target=get_into, args=(leader_err,)).start()
    entered.wait()
    waiter_err: queue.Queue[BaseException | None] = queue.Queue(3)
    for _ in range(3):
        threading.Thread(target=get_into, args=(waiter_err,)).start()
    time.sleep(0.01)
    release.set()
    err = leader_err.get()
    pe = as_error(err, PanicError)
    assert pe is not None and str(pe.value) == "boom", f"leader err = {err!r}"
    for _ in range(3):
        try:
            err = waiter_err.get(timeout=2)
        except queue.Empty:
            pytest.fail("waiter wedged after fetch panic")
        assert as_error(err, PanicError) is not None, f"waiter err = {err!r}"
    ctx, cancel = with_timeout(background(), 2)
    try:
        v = src.get(ctx)
    finally:
        cancel()
    assert v == "ok", f"after panic: {v!r}"
    assert fetches.load() == 2, f"fetches = {fetches.load()}, want 2"


def test_token_source_leader_cancel_does_not_abort_waiters() -> None:
    fetches = _Counter()
    entered = threading.Event()
    release = threading.Event()

    def fetch(ctx: Context) -> Token:
        fetches.add(1)
        entered.set()
        ctx.wait(release)
        err = ctx.err()
        if err is not None:
            raise err
        return Token("t")

    src = TokenSource(fetch)
    leader_ctx, cancel_leader = with_cancel(background())
    leader_err: queue.Queue[BaseException | None] = queue.Queue(1)

    def leader() -> None:
        try:
            src.get(leader_ctx)
            leader_err.put(None)
        except BaseException as e:
            leader_err.put(e)

    threading.Thread(target=leader).start()
    entered.wait()
    waiter_done = threading.Event()
    result: dict[str, object] = {}

    def waiter() -> None:
        try:
            result["v"] = src.get(background())
        except BaseException as e:
            result["err"] = e
        finally:
            waiter_done.set()

    threading.Thread(target=waiter).start()
    time.sleep(0.01)
    cancel_leader()
    err = leader_err.get()
    assert is_error(err, Cancelled), f"leader err = {err!r}"
    if waiter_done.wait(0.02):
        pytest.fail("waiter returned before the fetch finished")
    release.set()
    waiter_done.wait()
    assert "err" not in result and result.get("v") == "t", f"waiter got {result}; the leader's cancellation aborted the shared fetch"
    assert fetches.load() == 1, f"fetches = {fetches.load()}"
    assert src.get(background()) == "t", "token not cached"
