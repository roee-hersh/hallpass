"""Sessions: who is asking, and what has happened so far in one conversation.

The application creates a ``Session`` for the user it authenticated and makes
it current for the duration of a request or conversation turn. Tools read the
user from it, never from the model's arguments. The session also remembers
what its tools did: whether untrusted content or private data reached the
model, how many calls each tool and each effect made.
"""

from __future__ import annotations

import contextlib
import contextvars
import threading
import uuid
from collections.abc import Iterable, Iterator, Sequence

from securetools._untrusted import DEFAULT_CAPACITY, DEFAULT_NGRAM, UntrustedText

_current: contextvars.ContextVar[Session] = contextvars.ContextVar("securetools_session")


class Session:
    """One user's conversation with an agent.

    ``user`` is the identity the application authenticated; ``groups`` are
    optional group names passed to authorization. ``ngram`` is how many
    consecutive words of untrusted output an argument must repeat to count as
    carrying it.

        session = Session("dana@example.com")
        with session.active():
            agent.run(prompt)
    """

    def __init__(
        self,
        user: str,
        *,
        groups: Iterable[str] | None = None,
        id: str | None = None,
        ngram: int = DEFAULT_NGRAM,
        untrusted_capacity: int = DEFAULT_CAPACITY,
    ) -> None:
        if not isinstance(user, str) or not user.strip():
            raise ValueError("user must be a non-empty string")
        self.user = user
        self.groups: tuple[str, ...] | None = None if groups is None else tuple(groups)
        self.id = id or uuid.uuid4().hex
        self._lock = threading.Lock()
        self._untrusted = UntrustedText(ngram, untrusted_capacity)
        self._saw_untrusted = False
        self._read_private = False
        self._counts: dict[str, int] = {}

    def __repr__(self) -> str:
        return f"Session(user={self.user!r}, id={self.id!r})"

    @contextlib.contextmanager
    def active(self) -> Iterator[Session]:
        """Make this the current session inside the ``with`` block."""
        token = _current.set(self)
        try:
            yield self
        finally:
            _current.reset(token)

    @property
    def saw_untrusted(self) -> bool:
        """True once a tool marked ``untrusted_output`` ran in this session."""
        with self._lock:
            return self._saw_untrusted

    @property
    def read_private(self) -> bool:
        """True once a tool marked ``reads_private`` ran in this session."""
        with self._lock:
            return self._read_private

    def count(self, key: str) -> int:
        """Calls counted so far under ``key`` ("tool:<name>" or "effect:<effect>")."""
        with self._lock:
            return self._counts.get(key, 0)

    # The toolkit's side. Kept out of the public names on purpose.

    def _reserve(self, caps: Sequence[tuple[str, int]]) -> str | None:
        """Take one call from every cap, all or none. Returns the first key that
        is exhausted, or None when every cap had room and was taken."""
        with self._lock:
            for key, cap in caps:
                if self._counts.get(key, 0) >= cap:
                    return key
            for key, _ in caps:
                self._counts[key] = self._counts.get(key, 0) + 1
            return None

    def _release(self, caps: Sequence[tuple[str, int]]) -> None:
        with self._lock:
            for key, _ in caps:
                self._counts[key] = max(0, self._counts.get(key, 0) - 1)

    def _mark(self, *, untrusted: bool = False, private: bool = False) -> None:
        with self._lock:
            self._saw_untrusted = self._saw_untrusted or untrusted
            self._read_private = self._read_private or private

    def _record_untrusted(self, value: object) -> None:
        with self._lock:
            self._saw_untrusted = True
            self._untrusted.add(value)

    def _carries_untrusted(self, values: Iterable[object]) -> bool:
        with self._lock:
            return self._untrusted.matches(values)


def current_session() -> Session | None:
    """The session made current with ``Session.active()``, or None."""
    return _current.get(None)
