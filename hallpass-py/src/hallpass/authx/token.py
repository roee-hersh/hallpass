"""A cached bearer token, refreshed shortly before it expires. Concurrent
callers share one refresh."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from hallpass.core import evidence
from hallpass.core.cache import PanicError, detach, is_panic_type
from hallpass.core.context import Context

__all__ = ["DEFAULT_FETCH_TIMEOUT", "Token", "TokenSource"]

# Bounds a fetch whose caller's context has no deadline.
DEFAULT_FETCH_TIMEOUT = 30.0


@dataclass(frozen=True)
class Token:
    value: str = ""
    # Epoch seconds; None means unknown and the source's TTL applies.
    expiry: float | None = None


class _FetchCall:
    __slots__ = ("done", "err", "tok")

    def __init__(self) -> None:
        self.done = threading.Event()
        self.tok = Token()
        self.err: BaseException | None = None


class TokenSource:
    """Obtains and caches a token, refreshing it before it expires."""

    def __init__(
        self,
        fetch: Callable[[Context], Token] | None,
        early: float = 0.0,
        default_ttl: float = 0.0,
        now: Callable[[], float] | None = None,
    ) -> None:
        # Obtains a fresh token.
        self.fetch = fetch
        # How long before expiry a refresh starts (default 5 min).
        self.early = early
        # Applies when a token has no known expiry (default 15 min).
        self.default_ttl = default_ttl
        self.now = now
        self._lock = threading.Lock()
        self._tok = Token()
        self._exp = 0.0
        self._inflight: _FetchCall | None = None

    def _now(self) -> float:
        return self.now() if self.now is not None else time.time()

    def get(self, ctx: Context) -> str:
        """A valid token, fetching one if needed.

        The shared fetch runs in its own thread on a context detached from
        the first caller's cancellation. Each caller stops waiting when its
        own context ends. A crash in fetch is a PanicError for everyone.
        """
        if self.fetch is None:
            raise RuntimeError("token source has no fetch function")
        now = self._now()
        with self._lock:
            if self._tok.value and now < self._exp:
                return self._tok.value
            fc = self._inflight
            if fc is None:
                fc = _FetchCall()
                self._inflight = fc
                # A token exchange is not evidence for a decision and its
                # response carries the credential: never record it.
                fctx, cancel = detach(evidence.without_recorder(ctx), DEFAULT_FETCH_TIMEOUT)
                call = fc

                def run() -> None:
                    try:
                        self._fetch(call, fctx, now)
                    finally:
                        cancel()

                threading.Thread(target=run, name="hallpass-token", daemon=True).start()
        if not ctx.wait(fc.done):
            err = ctx.err()
            assert err is not None
            raise err
        if fc.err is not None:
            raise fc.err
        return fc.tok.value

    def _fetch(self, fc: _FetchCall, ctx: Context, now: float) -> None:
        assert self.fetch is not None
        try:
            try:
                fc.tok = self.fetch(ctx)
            except Exception as e:  # noqa: BLE001 - every failure reaches the waiters
                fc.tok = Token()
                fc.err = PanicError(e) if is_panic_type(e) else e
            except BaseException:  # noqa: BLE001 - Go's runtime.Goexit
                fc.tok = Token()
                fc.err = RuntimeError("token fetch exited without returning")
        finally:
            with self._lock:
                self._inflight = None
                if fc.err is None:
                    self._tok = fc.tok
                    self._exp = self._expiry_of(fc.tok, now)
            fc.done.set()

    def invalidate(self) -> None:
        """Drop the cached token so the next get fetches again. Call it
        when the upstream rejected the token."""
        with self._lock:
            self._tok = Token()
            self._exp = 0.0

    def _expiry_of(self, t: Token, now: float) -> float:
        early = self.early or 300.0
        exp = t.expiry
        if exp is None:
            exp = now + (self.default_ttl or 900.0)
        refresh_at = exp - early
        # Very short-lived tokens: refresh at half life, not immediately.
        if not refresh_at > now:
            half = (exp - now) / 2
            if half <= 0:
                half = 1.0
            refresh_at = now + half
        return refresh_at
