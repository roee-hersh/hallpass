"""Error chains: Go's errors.Is / errors.As over Python exceptions.

A cause is attached with ``raise X from cause`` (``__cause__``); a
:class:`JoinedError` carries several (Go's errors.Join). ``__context__``,
the exception that happened to be in flight, is deliberately not followed:
it is an accident of where the error was raised, not a wrapped cause.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import TypeVar

__all__ = ["JoinedError", "as_error", "chain", "is_error", "wrap"]

E = TypeVar("E", bound=BaseException)


class JoinedError(Exception):
    """Several errors reported as one; each is part of the chain."""

    def __init__(self, *errors: BaseException) -> None:
        self.errors = tuple(e for e in errors if e is not None)
        super().__init__("\n".join(str(e) for e in self.errors))


def chain(err: BaseException | None) -> Iterator[BaseException]:
    """Walk err and its causes depth-first, each exception once."""
    seen: set[int] = set()
    stack: list[BaseException] = [err] if err is not None else []
    while stack:
        e = stack.pop()
        if id(e) in seen:
            continue
        seen.add(id(e))
        yield e
        if isinstance(e, JoinedError):
            stack.extend(reversed(e.errors))
        if e.__cause__ is not None:
            stack.append(e.__cause__)


def as_error(err: BaseException | None, cls: type[E]) -> E | None:
    """The first exception in err's chain that is a cls, or None."""
    for e in chain(err):
        if isinstance(e, cls):
            return e
    return None


def is_error(err: BaseException | None, cls: type[BaseException]) -> bool:
    return as_error(err, cls) is not None


def wrap(err: E, cause: BaseException | None) -> E:
    """Attach cause to err and return err (``raise wrap(X(...), e)``)."""
    err.__cause__ = cause
    return err
