"""Port of internal/integration/integration_test.go.

The integration package is split in the port: decision.go is
hallpass.core.decision, integration.go and registry.go are
hallpass.core.integration. Go's (Action, bool) from FindAction is an
Action or None; Register's panic and register's error are a raised
ValueError.
"""

from __future__ import annotations

import pytest

from hallpass.core.catalog import Action
from hallpass.core.context import Cancelled, Context, DeadlineExceeded
from hallpass.core.decision import (
    Code,
    Outcome,
    outcome_of,
    to_decision,
    unknown_decision,
    user_not_found,
    wrap_error,
)
from hallpass.core.integration import (
    DEFAULT_TIMEOUT,
    Connection,
    Deps,
    Field,
    Integration,
    Registry,
    Settings,
    credential_field,
    find_action,
    url_field,
    validate_https_url,
)


def test_outcome_of() -> None:
    assert outcome_of(Code.ALLOWED) == Outcome.ALLOW
    assert outcome_of(Code.DENIED) == Outcome.DENY
    assert outcome_of(Code.USER_NOT_FOUND) == Outcome.DENY
    for c in [
        Code.USER_AMBIGUOUS,
        Code.UPSTREAM_TIMEOUT,
        Code.UPSTREAM_ERROR,
        Code.UPSTREAM_RATE_LIMIT,
        Code.CREDENTIAL_REJECTED,
        Code.RESOURCE_NOT_VISIBLE,
        Code.UNSUPPORTED,
        Code.INVALID_REQUEST,
        Code.UNKNOWN_CONNECTION,
        Code.UNKNOWN_ACTION,
        Code.UNAUTHORIZED,
    ]:
        assert outcome_of(c) == Outcome.UNKNOWN, f"{c} should be unknown"
    assert unknown_decision(Code.ALLOWED, "x").code == Code.UNSUPPORTED, "UnknownDecision must not allow"


class TimeoutErr(Exception):
    """Go's timeoutErr: a net.Error whose Timeout() is true."""

    def __init__(self) -> None:
        super().__init__("t")

    def timeout(self) -> bool:
        return True

    def temporary(self) -> bool:
        return True


class OpError(OSError):
    """Go's *net.OpError: its Timeout() asks the wrapped error."""

    def __init__(self, err: BaseException) -> None:
        super().__init__(str(err))
        self.err = err
        self.__cause__ = err

    def timeout(self) -> bool:
        t = getattr(self.err, "timeout", None)
        return bool(t()) if callable(t) else False


@pytest.mark.parametrize(
    ("err", "code"),
    [
        (user_not_found("no account"), Code.USER_NOT_FOUND),
        (wrap_error(Code.CREDENTIAL_REJECTED, Exception("401"), "bot rejected"), Code.CREDENTIAL_REJECTED),
        (DeadlineExceeded(), Code.UPSTREAM_TIMEOUT),
        (OpError(TimeoutErr()), Code.UPSTREAM_TIMEOUT),
        (Exception("boom"), Code.UPSTREAM_ERROR),
        (Cancelled(), Code.UPSTREAM_ERROR),
    ],
)
def test_to_decision(err: BaseException, code: Code) -> None:
    d = to_decision(err)
    assert d.code == code and d.outcome == outcome_of(code), f"{err!r} -> {d}"


def test_to_decision_keeps_cause_out_of_reason() -> None:
    d = to_decision(wrap_error(Code.UPSTREAM_ERROR, Exception("CANARY-SECRET-xyz"), "failed"))
    assert d.reason() == "upstream_error: failed", f"cause leaked into reason: {d.reason()!r}"


class Stub(Integration):
    def __init__(self, fields: list[Field] | None = None, actions: list[Action] | None = None) -> None:
        self._fields = fields or []
        self._actions = actions or []

    def name(self) -> str:
        return "stub"

    def fields(self) -> list[Field]:
        return self._fields

    def actions(self) -> list[Action]:
        return self._actions

    def new(self, ctx: Context, s: Settings, d: Deps) -> Connection:
        raise NotImplementedError

    def match_action(self, name: str) -> Action | None:
        if len(name) > 4 and name[:4] == "raw:":
            return Action(name=name)
        return None


BAD_STUBS = [
    Stub(fields=[Field(name="id")]),
    Stub(fields=[Field(name="Bad")]),
    Stub(fields=[Field(name="x"), Field(name="x")]),
    Stub(fields=[Field(name="k8s", ref="kubernetes")]),
    Stub(fields=[Field(name="tok", secret=True, default="x")]),
    Stub(actions=[Action(name="a"), Action(name="a")]),
    Stub(actions=[Action(name="bad action")]),
]


def test_registry() -> None:
    r = Registry()
    r.register(
        Stub(
            fields=[url_field(True, "u"), credential_field(True, "c"), Field(name="namespace", default="argocd")],
            actions=[Action(name="a.b"), Action(name="raw:<verb>:<resource>", pattern=True)],
        )
    )
    i = r.lookup("stub")
    assert i is not None, "not found"
    assert find_action(i, "a.b") is not None, "exact action"
    assert find_action(i, "raw:get:pods") is not None, "pattern action"
    assert find_action(i, "raw:<verb>:<resource>") is not None, "pattern name matched by matcher"
    assert find_action(i, "nope") is None, "unknown action found"
    for n, b in enumerate(BAD_STUBS):
        with pytest.raises(ValueError):
            Registry().register(b)
            pytest.fail(f"bad {n} accepted")
    with pytest.raises(ValueError):
        r.register(Stub())
    assert len(r.names()) == 1, r.names()


def test_settings() -> None:
    s = Settings("a", "stub", {"x": "true", "y": "no"}, None)
    assert s.bool("x", False) and not s.bool("y", True) and s.bool("z", True), "bool"
    assert s.effective_timeout() == DEFAULT_TIMEOUT, "timeout default"
    s.timeout = 1.0
    assert s.effective_timeout() == 1.0, "timeout"
    assert len(s.keys()) == 2 and s.keys()[0] == "x", s.keys()


@pytest.mark.parametrize(
    "url",
    [
        "",
        "https://x",
        "http://localhost:8080",
        "http://localhost",
        "http://127.0.0.1:1",
        "http://127.0.0.1",
        "http://127.1.2.3/api",
        "http://[::1]:9",
        "http://[::1]",
    ],
)
def test_validate_https_url_accepts(url: str) -> None:
    validate_https_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com",
        "https://x/?a=b",
        "https://x/#f",
        "ftp://x",
        "https://x y",
        # Loopback lookalikes: the host is not loopback, so a credential would
        # travel in clear text to wherever DNS points.
        "http://localhost.example.com",
        "http://localhostx",
        "http://localhost.evil:8080",
        "http://127.0.0.1.evil.com",
        "http://127.0.0.1x",
        "http://[::1].evil.com",
        "http://localhost@evil.com",
        "http://10.0.0.1",
        "http://[::2]",
        "https://u:p@x",
    ],
)
def test_validate_https_url_rejects(url: str) -> None:
    with pytest.raises(ValueError):
        validate_https_url(url)


# -- Behaviour pinned against the Go implementation ------------------------------
# Expected messages are what integration.ValidateHTTPSURL (url.Parse,
# net.ParseIP) returns for the same input.


@pytest.mark.parametrize(
    ("url", "want"),
    [
        ("http://example.com", 'url "http://example.com" must start with https://'),
        ("https://x y", "url \"https://x y\" must not contain whitespace, '?' or '#'"),
        ("https://u:p@x", 'url "https://u:p@x" must not contain userinfo'),
        ("https://@x", 'url "https://@x" must not contain userinfo'),
        ("https://x\x01", 'url "https://x\\x01": parse "https://x\\x01": net/url: invalid control character in URL'),
        ("https://x:abc", 'url "https://x:abc": parse "https://x:abc": invalid port ":abc" after host'),
        ("https://[::1", 'url "https://[::1": parse "https://[::1": missing \']\' in host'),
        ("https://x{y}", 'url "https://x{y}": parse "https://x{y}": invalid character "{" in host name'),
        ("https://x%zz", 'url "https://x%zz": parse "https://x%zz": invalid URL escape "%zz"'),
        ("https://x%41", 'url "https://x%41": parse "https://x%41": invalid URL escape "%41"'),
        ("https://x/%zz", 'url "https://x/%zz": parse "https://x/%zz": invalid URL escape "%zz"'),
        ("https://u%zz@x", 'url "https://u%zz@x": parse "https://u%zz@x": invalid URL escape "%zz"'),
        ("https://u{@x", 'url "https://u{@x": parse "https://u{@x": net/url: invalid userinfo'),
        (":x", 'url ":x": parse ":x": missing protocol scheme'),
        ("a:b/c", 'url "a:b/c" must start with https://'),
        ("x:y", 'url "x:y" must start with https://'),
        ("1a:b", 'url "1a:b": parse "1a:b": first path segment in URL cannot contain colon'),
        ("http:localhost", 'url "http:localhost" must start with https://'),
        ("http://[::1%25lo]", 'url "http://[::1%25lo]" must start with https://'),
        ("http://127.000.0.1", 'url "http://127.000.0.1" must start with https://'),
        ("*", 'url "*" must start with https://'),
    ],
)
def test_validate_https_url_error_text(url: str, want: str) -> None:
    with pytest.raises(ValueError) as ei:
        validate_https_url(url)
    assert str(ei.value) == want


@pytest.mark.parametrize(
    "url",
    [
        "HTTPS://x",
        "https:x",
        "https://x:",
        "http://localhost:",
        "http://[::1]:",
        "http://[::ffff:127.0.0.1]",
        "http://[::ffff:7f00:1]",
        "http://127.255.255.255",
        "https://x%C3%A9",
        "https://[fe80::1%25en0]",
    ],
)
def test_validate_https_url_go_accepts(url: str) -> None:
    validate_https_url(url)


def test_registry_error_text() -> None:
    with pytest.raises(ValueError, match=r'^integration stub: field "Bad": name must match \^\[a-z\]\[a-z0-9_\]\*\$$'):
        Registry().register(Stub(fields=[Field(name="Bad")]))
    with pytest.raises(ValueError, match=r'^integration stub: action "a b": action "a b" contains characters'):
        Registry().register(Stub(actions=[Action(name="a b")]))
    with pytest.raises(ValueError, match=r'^integration stub: action "a" declared twice$'):
        Registry().register(Stub(actions=[Action(name="a"), Action(name="a")]))
    # A pattern action's name documents a shape and is not validated.
    Registry().register(Stub(actions=[Action(name="raw:<verb> <resource>", pattern=True)]))
