"""A request-scoped context: a deadline, a cancellation signal and values.

hallpass passes a Context explicitly through every call on a check's way,
as the original Go code passed context.Context: the engine sets the
connection's timeout, the evidence recorder and the fresh mark on it; the
HTTP client reads the remaining time before every socket operation; the
caches run a shared lookup on a context detached from the first caller's
cancellation. An explicit object, rather than contextvars, because a shared
cache fill runs in a thread of its own and must see exactly the values the
caller handed it.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from typing import Any

__all__ = [
    "Cancelled",
    "Context",
    "ContextEnded",
    "DeadlineExceeded",
    "background",
    "context_ended",
    "with_cancel",
    "with_timeout",
    "with_value",
    "without_cancel",
]


class ContextEnded(Exception):
    """A context ended: it was cancelled or its deadline passed."""


class Cancelled(ContextEnded):
    def __init__(self) -> None:
        super().__init__("context canceled")


class DeadlineExceeded(ContextEnded, TimeoutError):
    def __init__(self) -> None:
        super().__init__("context deadline exceeded")


def _monotonic() -> float:
    return time.monotonic()


class Context:
    """One node of a context tree. Immutable apart from cancellation."""

    __slots__ = ("_callbacks", "_cancel_parent", "_deadline", "_err", "_key", "_lock", "_parent", "_val")

    def __init__(
        self,
        parent: Context | None = None,
        *,
        cancel_parent: Context | None = None,
        deadline: float | None = None,
        key: Any = None,
        val: Any = None,
    ) -> None:
        self._parent = parent  # for values
        self._cancel_parent = cancel_parent  # for cancellation and deadline
        self._deadline = deadline
        self._key = key
        self._val = val
        self._lock = threading.Lock()
        self._err: ContextEnded | None = None
        self._callbacks: list[Callable[[], None]] = []

    # -- deadline -------------------------------------------------------

    def deadline(self) -> float | None:
        """The monotonic time this context ends, or None."""
        own = self._deadline
        p = self._cancel_parent
        pd = p.deadline() if p is not None else None
        if own is None:
            return pd
        if pd is None:
            return own
        return min(own, pd)

    def remaining(self) -> float | None:
        """Seconds left before the deadline (never negative), or None."""
        d = self.deadline()
        if d is None:
            return None
        return max(0.0, d - _monotonic())

    # -- cancellation ---------------------------------------------------

    def err(self) -> ContextEnded | None:
        """Why the context ended, or None while it lives."""
        with self._lock:
            if self._err is not None:
                return self._err
        d = self.deadline()
        if d is not None and _monotonic() >= d:
            return DeadlineExceeded()
        p = self._cancel_parent
        if p is not None:
            return p.err()
        return None

    def check(self) -> None:
        """Raise the context's error when it has ended."""
        e = self.err()
        if e is not None:
            raise e

    def _cancel(self, err: ContextEnded) -> None:
        with self._lock:
            if self._err is not None:
                return
            self._err = err
            callbacks, self._callbacks = self._callbacks, []
        for cb in callbacks:
            try:
                cb()
            except Exception:  # noqa: BLE001 - a callback must not break cancellation
                pass

    def on_cancel(self, cb: Callable[[], None]) -> Callable[[], None]:
        """Run cb when this context (or an ancestor) is cancelled.

        Deadlines do not fire callbacks: whoever waits computes the
        remaining time itself. Returns a function that unregisters cb.
        """
        chain: list[Context] = []
        node: Context | None = self
        while node is not None:
            chain.append(node)
            node = node._cancel_parent
        for n in chain:
            with n._lock:
                n._callbacks.append(cb)
        if any(n._err is not None for n in chain):
            # Cancelled before or while registering: run it now (a callback
            # may run twice in that race; every caller's cb is idempotent).
            cb()

        def remove() -> None:
            for n in chain:
                with n._lock:
                    try:
                        n._callbacks.remove(cb)
                    except ValueError:
                        pass

        return remove

    def wait(self, event: threading.Event) -> bool:
        """Wait for event or for this context to end. True when event fired."""
        if event.is_set():
            return True
        cancelled = threading.Event()
        remove = self.on_cancel(cancelled.set)
        try:
            while not cancelled.is_set():
                rem = self.remaining()
                if rem is not None and rem <= 0:
                    break
                if event.wait(0.05 if rem is None else min(rem, 0.05)):
                    return True
            return event.is_set()
        finally:
            remove()

    # -- values ---------------------------------------------------------

    def value(self, key: Any) -> Any:
        node: Context | None = self
        while node is not None:
            if node._key is not None and node._key == key:
                return node._val
            node = node._parent
        return None


_BACKGROUND = Context()


def background() -> Context:
    """The root context: no deadline, never cancelled, no values."""
    return _BACKGROUND


def with_cancel(parent: Context) -> tuple[Context, Callable[[], None]]:
    c = Context(parent, cancel_parent=parent)
    return c, lambda: c._cancel(Cancelled())


def with_timeout(parent: Context, seconds: float) -> tuple[Context, Callable[[], None]]:
    c = Context(parent, cancel_parent=parent, deadline=_monotonic() + max(0.0, seconds))
    return c, lambda: c._cancel(Cancelled())


def with_value(parent: Context, key: Any, val: Any) -> Context:
    return Context(parent, cancel_parent=parent, key=key, val=val)


def without_cancel(parent: Context) -> Context:
    """Keep parent's values but none of its cancellation or deadline."""
    return Context(parent, cancel_parent=None)


def context_ended(err: BaseException | None) -> bool:
    """True when err is a context ending, as opposed to a failure of the work."""
    from hallpass.core.errors import is_error

    return is_error(err, ContextEnded)
