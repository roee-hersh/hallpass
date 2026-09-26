"""Port of internal/catalog/catalog_test.go and fuzz_test.go.

The Go fuzz targets are Hypothesis property tests with the same
invariants. Their seed corpus runs as ordinary cases, as `go test` runs
it: the f.Add seeds and every file of the Go corpus (kept in
tests/core/testdata/catalog_fuzz, in Go's corpus format).
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest
from hypothesis import example, given, settings
from hypothesis import strategies as st

from hallpass.core.catalog import (
    MAX_ACTION_LENGTH,
    MAX_RESOURCE_LENGTH,
    ResourceError,
    is_control,
    parse_query,
    parse_resource,
    query_unescape,
    split_branch,
    validate_action_name,
)
from tests.harness import examples as _examples

# typeRe, anchored at both ends as Go's regexp is (no newline before $).
TYPE_RE = re.compile(r"[a-z][a-z0-9_]{0,63}")

# (in, type, id, query, want_err)
PARSE_RESOURCE_CASES: list[tuple[str, str, str, dict[str, str], bool]] = [
    ("repo:acme/api", "repo", "acme/api", {}, False),
    ("repo:acme/api@main", "repo", "acme/api@main", {}, False),
    ("global", "global", "", {}, False),
    ("nonresource:/metrics", "nonresource", "/metrics", {}, False),
    ("namespace:payments?resource=deployments.apps&name=api", "namespace", "payments", {"resource": "deployments.apps", "name": "api"}, False),
    ("cluster?resource=nodes", "cluster", "", {"resource": "nodes"}, False),
    ("issue:OPS-123", "issue", "OPS-123", {}, False),
    ("arn:aws:s3:::bucket/key", "arn", "aws:s3:::bucket/key", {}, False),
    ("", "", "", {}, True),
    ("Repo:x", "", "", {}, True),
    ("repo:x\n", "", "", {}, True),
    ("ns:x?resource=a&resource=b", "", "", {}, True),
    ("ns:x?Bad=1", "", "", {}, True),
    ("ns:x?%zz", "", "", {}, True),
    ("ns:x?k=%0A", "", "", {}, True),
    ("ns:x?k=%C2%85", "", "", {}, True),
    ("ns:x\u0085y", "", "", {}, True),
    ("ns:x?k=caf%C3%A9", "ns", "x", {"k": "café"}, False),
]


@pytest.mark.parametrize(("raw", "typ", "rid", "q", "want_err"), PARSE_RESOURCE_CASES)
def test_parse_resource(raw: str, typ: str, rid: str, q: dict[str, str], want_err: bool) -> None:
    if want_err:
        with pytest.raises(ResourceError):
            parse_resource(raw)
        return
    r = parse_resource(raw)
    assert (r.type, r.id) == (typ, rid)
    for k, v in q.items():
        assert r.q(k) == v


def test_split_branch() -> None:
    assert split_branch("acme/webapp@main") == ("acme/webapp", "main")
    assert split_branch("acme/webapp") == ("acme/webapp", "")


@pytest.mark.parametrize(
    "name",
    ["repo.push", "raw:create:deployments.apps/scale", "BROWSE_PROJECTS", "app.action/apps/Deployment/restart", "raw:s3:PutObject", "raw:iam:*"],
)
def test_validate_action_name_accepts(name: str) -> None:
    validate_action_name(name)


@pytest.mark.parametrize("name", ["", ".x", "a b", "a\n", "a;b"])
def test_validate_action_name_rejects(name: str) -> None:
    with pytest.raises(ValueError):
        validate_action_name(name)


# -- FuzzParseResource ---------------------------------------------------------

PARSE_RESOURCE_SEEDS = [
    "repo:acme/api",
    "global",
    "namespace:payments?resource=deployments.apps&name=api",
    "cluster?resource=nodes",
    "nonresource:/metrics",
    "arn:aws:s3:::b/k",
    "",
    "x:",
    ":x",
    "a?b=c&b=d",
    "a?%zz",
    "type:id?k=v#frag",
    "日本:語",
]

CORPUS = Path(__file__).parent / "testdata" / "catalog_fuzz"


def _go_string_literal(lit: str) -> str:
    """A Go interpreted string literal as the string Go holds, invalid
    UTF-8 bytes as surrogate escapes."""
    out = bytearray()
    for part in re.split(r"(\\x[0-9a-fA-F]{2}|\\[0-7]{3})", lit[1:-1]):
        if (part.startswith("\\x") and len(part) == 4) or re.fullmatch(r"\\[0-7]{3}", part):
            out += ast.literal_eval('b"' + part + '"')
        else:
            out += ast.literal_eval('"' + part + '"').encode("utf-8")
    return out.decode("utf-8", "surrogateescape")


def _corpus(target: str) -> list[tuple[str, str]]:
    """(file name, input) for each `go test fuzz v1` file of a target."""
    out = []
    for p in sorted((CORPUS / target).iterdir()):
        lines = p.read_text().splitlines()
        assert lines[0] == "go test fuzz v1", p
        m = re.fullmatch(r"string\((\".*\")\)", lines[1])
        assert m, p
        out.append((p.name, _go_string_literal(m.group(1))))
    return out


def check_parse_resource_invariants(raw: str) -> None:
    """FuzzParseResource: the parser never fails unexpectedly, an accepted
    resource has a well-formed type, no control characters survive, and
    the parts re-assemble to the input."""
    try:
        r = parse_resource(raw)
    except ResourceError:
        return
    assert TYPE_RE.fullmatch(r.type), f"accepted type {r.type!r}"
    for c in raw:
        assert not (ord(c) < 0x20 or ord(c) == 0x7F), f"control character accepted in {raw!r}"
    head = r.type
    if ":" in raw and (r.id != "" or raw.removeprefix(r.type).startswith(":")):
        head += ":" + r.id
    assert raw.startswith(head), f"parts {head!r} do not prefix {raw!r}"
    for k, vs in (r.query or {}).items():
        assert len(vs) == 1 and TYPE_RE.fullmatch(k), f"bad query {r.query}"
        assert not any(is_control(c) for c in vs[0]), "control character in query value"
    assert len(raw.encode("utf-8")) <= MAX_RESOURCE_LENGTH, "over-long resource accepted"


@pytest.mark.parametrize("raw", PARSE_RESOURCE_SEEDS)
def test_fuzz_parse_resource_seeds(raw: str) -> None:
    check_parse_resource_invariants(raw)


@pytest.mark.parametrize(("name", "raw"), _corpus("FuzzParseResource"))
def test_fuzz_parse_resource_corpus(name: str, raw: str) -> None:
    check_parse_resource_invariants(raw)


def test_fuzz_parse_resource_corpus_outcomes() -> None:
    """What the corpus files were added for: the NUL byte a %00 escape
    decodes to and the C1 control %C2%85 decodes to are both rejected."""
    corpus = dict(_corpus("FuzzParseResource"))
    with pytest.raises(ResourceError, match=r'^resource query value for "a" contains a control character$'):
        parse_resource(corpus["15aac6b49c47082f"])
    with pytest.raises(ResourceError, match=r'^resource query value for "k" contains a control character$'):
        parse_resource(corpus["c1-control-in-query"])


# Characters the parser treats specially, so generated inputs reach every branch.
_RESOURCE_ALPHABET = st.sampled_from([*"az09_:?&=%/@.-+;#A ", "%zz", "%0A", "%C2%85", "%C3%A9", "%E6%97", "%FF", "%", "\x85", "\x00", "\x7f", " ", "é", "日"])
_resource_text = st.one_of(st.text(), st.lists(_RESOURCE_ALPHABET, max_size=30).map("".join))


@settings(max_examples=_examples(500), deadline=None)
@given(_resource_text)
@example("a" * (MAX_RESOURCE_LENGTH + 1))
@example("a:" + "é" * 512)
def test_fuzz_parse_resource(raw: str) -> None:
    check_parse_resource_invariants(raw)


# -- FuzzValidateActionName ----------------------------------------------------

VALIDATE_ACTION_SEEDS = ["repo.push", "raw:get:pods/log", "", " ", "a\n", "BROWSE_PROJECTS"]


def check_validate_action_invariants(name: str) -> None:
    """FuzzValidateActionName: an accepted name is printable ASCII only and
    within the length limit."""
    try:
        validate_action_name(name)
    except ValueError:
        return
    for c in name:
        assert 0x21 <= ord(c) <= 0x7E, f"non-printable or non-ASCII accepted in {name!r}"
    assert len(name.encode("utf-8")) <= MAX_ACTION_LENGTH, "over-long action accepted"


@pytest.mark.parametrize("name", VALIDATE_ACTION_SEEDS)
def test_fuzz_validate_action_name_seeds(name: str) -> None:
    check_validate_action_invariants(name)


@settings(max_examples=_examples(500), deadline=None)
@given(st.one_of(st.text(), st.from_regex(r"[A-Za-z0-9][A-Za-z0-9_.:/*\- \n\x7f]*", fullmatch=True)))
@example("a" * (MAX_ACTION_LENGTH + 1))
@example("a\n")
def test_fuzz_validate_action_name(name: str) -> None:
    check_validate_action_invariants(name)


# -- Behaviour pinned against the Go implementation ------------------------------
# Expected values below were produced by the Go code (catalog.ParseResource,
# url.ParseQuery, url.QueryUnescape) for the same inputs.


@pytest.mark.parametrize(
    ("raw", "want"),
    [
        ("Repo:x", 'resource type "Repo" must match ^[a-z][a-z0-9_]{0,63}$'),
        ("a­b:x", 'resource type "a\\u00adb" must match ^[a-z][a-z0-9_]{0,63}$'),
        ("ns:x?%zz", 'resource query: invalid URL escape "%zz"'),
        ("ns:x?k=%E6%9", 'resource query: invalid URL escape "%9"'),
        ("ns:x?%日", 'resource query: invalid URL escape "%\\xe6\\x97"'),
        ("ns:x?a%FF=1", 'resource query key "a\\xff" must be a single lowercase key'),
        ("ns:x?k=%C2%85", 'resource query value for "k" contains a control character'),
        ("ns:x?a;b=1", "resource query: invalid semicolon separator in query"),
        ("a:" + "x" * 1023, "resource is longer than 1024 bytes"),
    ],
)
def test_parse_resource_error_text(raw: str, want: str) -> None:
    with pytest.raises(ResourceError) as ei:
        parse_resource(raw)
    assert str(ei.value) == want


def test_parse_resource_length_is_bytes() -> None:
    parse_resource("a:" + "é" * 511)  # 1024 bytes
    with pytest.raises(ResourceError, match=r"longer than 1024 bytes"):
        parse_resource("a:" + "é" * 511 + "x")


def test_parse_resource_invalid_utf8_value_reads_as_replacement() -> None:
    """Go keeps the bytes; wherever it prints them each bad byte is U+FFFD."""
    assert parse_resource("ns:x?k=%E6%97").q("k") == "��"
    assert parse_resource("ns:x?k=a+b%20c").q("k") == "a b c"
    assert parse_resource("ns?").query == {}


def test_parse_query_errors_like_go() -> None:
    # A later ';' error replaces an earlier escape error; the first escape
    # error is kept over a later one.
    with pytest.raises(ResourceError, match=r"^invalid semicolon separator in query$"):
        parse_query("%zz&a;b")
    with pytest.raises(ResourceError, match=r'^invalid URL escape "%zz"$'):
        parse_query("%zz&%yy")
    assert parse_query("a=1&&b=2&a=3") == {"a": ["1", "3"], "b": ["2"]}
    assert query_unescape("a+b%41") == "a bA"


def test_validate_action_name_error_text() -> None:
    with pytest.raises(ValueError) as ei:
        validate_action_name("a\n")
    assert str(ei.value) == 'action "a\\n" contains characters outside ^[A-Za-z0-9][A-Za-z0-9_.:/*-]*$'
    with pytest.raises(ValueError, match=r"^action is longer than 200 bytes$"):
        validate_action_name("a" * 201)
    validate_action_name("a" * 200)
