"""decision.go semantics (hallpass.core.decision) beyond what
integration_test.go covers: outcome_of for every code, the constructors,
the coercion of unknown_decision, HallpassError, and to_decision on every
kind of error, never putting the cause into the reason text."""

from __future__ import annotations

import pytest

from hallpass.core.context import Cancelled, DeadlineExceeded, background, with_cancel, with_timeout
from hallpass.core.decision import (
    Code,
    Decision,
    HallpassError,
    Outcome,
    allowed,
    denied,
    errorf,
    outcome_of,
    to_decision,
    unknown_decision,
    unsupported,
    user_ambiguous,
    user_not_found,
    wrap_error,
)
from hallpass.core.errors import JoinedError, wrap

CANARY = "CANARY-SECRET-decision"

ALL_CODES = list(Code)


def test_codes_are_the_closed_wire_set() -> None:
    assert [c.value for c in Code] == [
        "allowed",
        "denied",
        "user_not_found",
        "user_ambiguous",
        "upstream_timeout",
        "upstream_error",
        "upstream_rate_limited",
        "credential_rejected",
        "resource_not_visible",
        "unsupported",
        "invalid_request",
        "unknown_connection",
        "unknown_action",
        "unauthorized",
    ]
    assert [o.value for o in Outcome] == ["allow", "deny", "unknown"]
    assert str(Code.USER_NOT_FOUND) == "user_not_found" and str(Outcome.DENY) == "deny"


@pytest.mark.parametrize("code", ALL_CODES)
def test_outcome_of_every_code(code: Code) -> None:
    want = {Code.ALLOWED: Outcome.ALLOW, Code.DENIED: Outcome.DENY, Code.USER_NOT_FOUND: Outcome.DENY}.get(code, Outcome.UNKNOWN)
    assert outcome_of(code) == want
    # The wire string maps the same way (Code is a string type in Go).
    assert outcome_of(code.value) == want


def test_outcome_of_unknown_strings() -> None:
    assert outcome_of("") == Outcome.UNKNOWN
    assert outcome_of("allow") == Outcome.UNKNOWN
    assert outcome_of(None) == Outcome.UNKNOWN


def test_constructors() -> None:
    assert allowed("ok") == Decision(Outcome.ALLOW, Code.ALLOWED, "ok")
    assert denied("no") == Decision(Outcome.DENY, Code.DENIED, "no")
    assert unsupported("x") == Decision(Outcome.UNKNOWN, Code.UNSUPPORTED, "x")
    assert unknown_decision(Code.UPSTREAM_RATE_LIMIT, "slow") == Decision(Outcome.UNKNOWN, Code.UPSTREAM_RATE_LIMIT, "slow")


@pytest.mark.parametrize("code", ALL_CODES)
def test_unknown_decision_never_allows_or_denies(code: Code) -> None:
    """UnknownDecision coerces a code whose outcome is not unknown."""
    d = unknown_decision(code, "t")
    assert d.outcome == Outcome.UNKNOWN
    assert d.code == (Code.UNSUPPORTED if outcome_of(code) != Outcome.UNKNOWN else code)
    assert d.text == "t"


def test_reason() -> None:
    assert allowed("").reason() == "allowed"
    assert denied("x: y").reason() == "denied: x: y"
    assert Decision().reason() == ""
    assert Decision(text="t").reason() == ": t"


def test_hallpass_error() -> None:
    e = errorf(Code.CREDENTIAL_REJECTED, "bot rejected")
    assert str(e) == "credential_rejected: bot rejected"
    assert e.decision() == Decision(Outcome.UNKNOWN, Code.CREDENTIAL_REJECTED, "bot rejected")
    assert str(errorf(Code.DENIED)) == "denied"
    cause = ValueError("401 body")
    w = wrap_error(Code.UPSTREAM_ERROR, cause, "failed")
    # Error() carries the cause for logs; Unwrap reaches it.
    assert str(w) == "upstream_error: failed (401 body)"
    assert w.__cause__ is cause and w.cause is cause
    assert str(wrap_error(Code.UPSTREAM_ERROR, None, "")) == "upstream_error"
    assert user_not_found("no account").decision() == Decision(Outcome.DENY, Code.USER_NOT_FOUND, "no account")
    assert user_ambiguous("two").decision() == Decision(Outcome.UNKNOWN, Code.USER_AMBIGUOUS, "two")
    # Decision derives the outcome from the code, whatever the code.
    assert errorf(Code.ALLOWED, "x").decision().outcome == Outcome.ALLOW


class NetTimeout(Exception):
    """A net.Error whose Timeout() reports true."""

    def timeout(self) -> bool:
        return True


class NetError(Exception):
    """A net.Error whose Timeout() reports false."""

    def timeout(self) -> bool:
        return False


def _ctx_err(timeout: bool) -> BaseException:
    if timeout:
        ctx, cancel = with_timeout(background(), 0)
    else:
        ctx, cancel = with_cancel(background())
        cancel()
    err = ctx.err()
    cancel()
    assert err is not None
    return err


@pytest.mark.parametrize(
    ("err", "code", "text"),
    [
        (user_not_found("no account"), Code.USER_NOT_FOUND, "no account"),
        (errorf(Code.UPSTREAM_RATE_LIMIT, "slow down"), Code.UPSTREAM_RATE_LIMIT, "slow down"),
        # errors.As finds a wrapped *Error anywhere in the chain.
        (wrap(RuntimeError("outer"), errorf(Code.RESOURCE_NOT_VISIBLE, "hidden")), Code.RESOURCE_NOT_VISIBLE, "hidden"),
        (JoinedError(ValueError("a"), user_ambiguous("two")), Code.USER_AMBIGUOUS, "two"),
        # A *Error wins over a deadline wrapped inside it.
        (wrap_error(Code.CREDENTIAL_REJECTED, DeadlineExceeded(), "rejected"), Code.CREDENTIAL_REJECTED, "rejected"),
        (DeadlineExceeded(), Code.UPSTREAM_TIMEOUT, "upstream call timed out"),
        (_ctx_err(timeout=True), Code.UPSTREAM_TIMEOUT, "upstream call timed out"),
        (wrap(RuntimeError("get"), DeadlineExceeded()), Code.UPSTREAM_TIMEOUT, "upstream call timed out"),
        (TimeoutError("timed out"), Code.UPSTREAM_TIMEOUT, "upstream call timed out"),
        (TimeoutError(), Code.UPSTREAM_TIMEOUT, "upstream call timed out"),
        (NetTimeout("i/o timeout"), Code.UPSTREAM_TIMEOUT, "upstream call timed out"),
        (wrap(OSError("dial"), NetTimeout("i/o timeout")), Code.UPSTREAM_TIMEOUT, "upstream call timed out"),
        (NetError("connection refused"), Code.UPSTREAM_ERROR, "upstream call failed"),
        (ConnectionRefusedError(111, "refused"), Code.UPSTREAM_ERROR, "upstream call failed"),
        (Cancelled(), Code.UPSTREAM_ERROR, "request cancelled"),
        (_ctx_err(timeout=False), Code.UPSTREAM_ERROR, "request cancelled"),
        (wrap(RuntimeError("get"), Cancelled()), Code.UPSTREAM_ERROR, "request cancelled"),
        (ValueError("boom"), Code.UPSTREAM_ERROR, "upstream call failed"),
    ],
)
def test_to_decision(err: BaseException, code: Code, text: str) -> None:
    d = to_decision(err)
    assert (d.outcome, d.code, d.text) == (outcome_of(code), code, text)
    assert d.evidence is None


@pytest.mark.parametrize(
    "err",
    [
        wrap_error(Code.UPSTREAM_ERROR, ValueError(CANARY), "failed"),
        wrap_error(Code.USER_NOT_FOUND, ValueError(CANARY), "no account"),
        wrap(RuntimeError(CANARY), DeadlineExceeded()),
        wrap(RuntimeError(CANARY), Cancelled()),
        NetTimeout(CANARY),
        ValueError(CANARY),
        JoinedError(ValueError(CANARY), errorf(Code.UNSUPPORTED, "x")),
    ],
)
def test_reason_never_contains_the_cause(err: BaseException) -> None:
    d = to_decision(err)
    assert CANARY not in d.reason() and CANARY not in d.text


def test_decision_with_() -> None:
    d = allowed("ok")
    assert d.with_(text="other") == Decision(Outcome.ALLOW, Code.ALLOWED, "other")
    assert d.text == "ok"


def test_hallpass_error_is_an_exception() -> None:
    with pytest.raises(HallpassError) as ei:
        raise user_not_found("x")
    assert ei.value.code == Code.USER_NOT_FOUND
