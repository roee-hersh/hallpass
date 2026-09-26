"""The answer to a check: outcome, a closed set of reason codes, and errors
that carry a code.

The rule everything else rests on: only ``allowed`` is allow, ``denied``
and ``user_not_found`` are deny, and every other code is unknown. The
outcome is always derived from the code, never set on its own.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import TYPE_CHECKING

from hallpass.core.context import Cancelled, DeadlineExceeded
from hallpass.core.errors import as_error, is_error

if TYPE_CHECKING:
    from hallpass.core.evidence import Evidence

__all__ = [
    "Code",
    "Decision",
    "HallpassError",
    "Outcome",
    "allowed",
    "denied",
    "errorf",
    "outcome_of",
    "to_decision",
    "unknown_decision",
    "unsupported",
    "user_ambiguous",
    "user_not_found",
    "wrap_error",
]


class Outcome(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    UNKNOWN = "unknown"

    def __str__(self) -> str:
        return self.value


class Code(str, Enum):
    """A stable, machine-readable reason. The set is closed."""

    ALLOWED = "allowed"
    DENIED = "denied"
    USER_NOT_FOUND = "user_not_found"
    USER_AMBIGUOUS = "user_ambiguous"
    UPSTREAM_TIMEOUT = "upstream_timeout"
    UPSTREAM_ERROR = "upstream_error"
    UPSTREAM_RATE_LIMIT = "upstream_rate_limited"
    CREDENTIAL_REJECTED = "credential_rejected"
    RESOURCE_NOT_VISIBLE = "resource_not_visible"
    UNSUPPORTED = "unsupported"
    INVALID_REQUEST = "invalid_request"
    UNKNOWN_CONNECTION = "unknown_connection"
    UNKNOWN_ACTION = "unknown_action"
    UNAUTHORIZED = "unauthorized"

    def __str__(self) -> str:
        return self.value


def outcome_of(code: Code | str | None) -> Outcome:
    """The only outcome a code may carry."""
    if code == Code.ALLOWED:
        return Outcome.ALLOW
    if code in (Code.DENIED, Code.USER_NOT_FOUND):
        return Outcome.DENY
    return Outcome.UNKNOWN


@dataclass(frozen=True)
class Decision:
    outcome: Outcome = Outcome.UNKNOWN
    code: Code | None = None
    # Text is a short human-readable explanation. It never contains
    # credential material or raw upstream bodies.
    text: str = ""
    # What the upstream system said when the decision was computed. The
    # engine fills it; integrations leave it None.
    evidence: Evidence | None = field(default=None, compare=False)

    def reason(self) -> str:
        """``"<code>: <text>"``, the wire form of the reason field."""
        code = "" if self.code is None else self.code.value
        if not self.text:
            return code
        return f"{code}: {self.text}"

    def with_(self, **changes: object) -> Decision:
        return replace(self, **changes)  # type: ignore[arg-type]


def allowed(text: str) -> Decision:
    return Decision(Outcome.ALLOW, Code.ALLOWED, text)


def denied(text: str) -> Decision:
    """The upstream system positively said no."""
    return Decision(Outcome.DENY, Code.DENIED, text)


def unknown_decision(code: Code, text: str) -> Decision:
    """An unknown decision. A code whose outcome is not unknown becomes unsupported."""
    if outcome_of(code) != Outcome.UNKNOWN:
        code = Code.UNSUPPORTED
    return Decision(Outcome.UNKNOWN, code, text)


def unsupported(text: str) -> Decision:
    return unknown_decision(Code.UNSUPPORTED, text)


class HallpassError(Exception):
    """An error that carries a decision code.

    Integrations raise it from resolve_identity and check when they cannot
    evaluate; the engine turns it into the matching decision. The cause
    (``__cause__``) is kept for logs and never put into the decision text.
    """

    def __init__(self, code: Code, text: str = "", cause: BaseException | None = None) -> None:
        self.code = code
        self.text = text
        self.cause = cause
        if cause is not None:
            self.__cause__ = cause
        super().__init__(str(self))

    def __str__(self) -> str:
        s = self.code.value
        if self.text:
            s += ": " + self.text
        if self.cause is not None:
            s += " (" + str(self.cause) + ")"
        return s

    def decision(self) -> Decision:
        return Decision(outcome_of(self.code), self.code, self.text)


def errorf(code: Code, text: str = "") -> HallpassError:
    return HallpassError(code, text)


def wrap_error(code: Code, err: BaseException | None, text: str = "") -> HallpassError:
    return HallpassError(code, text, err)


def user_not_found(text: str) -> HallpassError:
    """The error for an email with no account."""
    return HallpassError(Code.USER_NOT_FOUND, text)


def user_ambiguous(text: str) -> HallpassError:
    """The error for an email that matches several accounts."""
    return HallpassError(Code.USER_AMBIGUOUS, text)


def _is_timeout(err: BaseException) -> bool:
    for e in _walk(err):
        if isinstance(e, (socket.timeout, TimeoutError)) and not isinstance(e, DeadlineExceeded):
            return True
        t = getattr(e, "timeout", None)
        if callable(t):
            try:
                if t():
                    return True
            except Exception:  # noqa: BLE001
                pass
    return False


def _walk(err: BaseException):  # type: ignore[no-untyped-def]
    from hallpass.core.errors import chain

    return chain(err)


def to_decision(err: BaseException) -> Decision:
    """Any error as a decision.

    A HallpassError keeps its code; a spent deadline or a network timeout
    is upstream_timeout; everything else is upstream_error. The wrapped
    cause is never put into the text.
    """
    he = as_error(err, HallpassError)
    if he is not None:
        return he.decision()
    if is_error(err, DeadlineExceeded):
        return unknown_decision(Code.UPSTREAM_TIMEOUT, "upstream call timed out")
    if _is_timeout(err):
        return unknown_decision(Code.UPSTREAM_TIMEOUT, "upstream call timed out")
    if is_error(err, Cancelled):
        return unknown_decision(Code.UPSTREAM_ERROR, "request cancelled")
    return unknown_decision(Code.UPSTREAM_ERROR, "upstream call failed")
