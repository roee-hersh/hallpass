"""Port of internal/integrations/vault/fuzz_test.go.

FuzzParseTarget and FuzzPolicy become Hypothesis properties with the same
invariants. Their seed corpora (the f.Add seeds, and for FuzzPolicy the
files under testdata/fuzz/FuzzPolicy) are replayed as plain cases.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from hallpass.core.catalog import ResourceError, parse_resource
from hallpass.core.decision import HallpassError
from hallpass.integrations.vault.actions import ACTION_LIST, parse_target
from hallpass.integrations.vault.policy import CAPABILITIES, PolicyError, TemplateContext, evaluate, parse_policy
from tests.harness import examples as _examples
from tests.integrations.vault.test_vault import DEFAULT_POLICY, DEV_POLICY, OPS_POLICY, TEAM_POLICY

TESTDATA = Path(__file__).parent / "testdata" / "fuzz"

# -- the go test fuzz v1 corpus format -------------------------------------------

_SIMPLE_ESCAPES = {"a": 7, "b": 8, "f": 12, "n": 10, "r": 13, "t": 9, "v": 11, "\\": 92, '"': 34, "'": 39}


def go_unquote(lit: str) -> str:
    """strconv.Unquote of a double-quoted Go string literal. \\x and octal
    escapes are bytes; invalid UTF-8 comes back surrogate-escaped."""
    if len(lit) < 2 or lit[0] != '"' or lit[-1] != '"':
        raise ValueError(f"not a Go string literal: {lit!r}")
    s = lit[1:-1]
    out = bytearray()
    i = 0
    while i < len(s):
        c = s[i]
        if c != "\\":
            out += c.encode("utf-8")
            i += 1
            continue
        e = s[i + 1]
        if e in _SIMPLE_ESCAPES:
            out.append(_SIMPLE_ESCAPES[e])
            i += 2
        elif e == "x":
            out.append(int(s[i + 2 : i + 4], 16))
            i += 4
        elif e in "01234567":
            out.append(int(s[i + 1 : i + 4], 8))
            i += 4
        elif e == "u":
            out += chr(int(s[i + 2 : i + 6], 16)).encode("utf-8", "surrogatepass")
            i += 6
        elif e == "U":
            out += chr(int(s[i + 2 : i + 10], 16)).encode("utf-8", "surrogatepass")
            i += 10
        else:
            raise ValueError(f"bad escape \\{e} in {lit!r}")
    return out.decode("utf-8", "surrogateescape")


def read_corpus_file(path: Path) -> list[str]:
    """The values of one corpus file: a header line, then one string(...)
    or []byte(...) literal per line."""
    lines = path.read_text().splitlines()
    assert lines and lines[0] == "go test fuzz v1", f"{path}: not a go test fuzz v1 file"
    out = []
    for line in lines[1:]:
        line = line.strip()
        if not line:
            continue
        for prefix in ("string(", "[]byte("):
            if line.startswith(prefix) and line.endswith(")"):
                out.append(go_unquote(line[len(prefix) : -1]))
                break
        else:
            raise ValueError(f"{path}: unsupported literal {line!r}")
    return out


def corpus(name: str) -> list[list[str]]:
    d = TESTDATA / name
    return [read_corpus_file(p) for p in sorted(d.iterdir())] if d.is_dir() else []


def test_go_unquote() -> None:
    assert go_unquote(r'"{\"pAth\":{\"/\":{}}}"') == '{"pAth":{"/":{}}}'
    assert go_unquote(r'"a\n\t\x41\101\u00e9"') == "a\n\tAAé"


# -- FuzzParseTarget -------------------------------------------------------------

TARGET_SEEDS = [
    ("secret.read", "kv:secret/dev/app"),
    ("raw:sudo", "path:sys/seal"),
    ("secret.list", "kv:secret/dev"),
    ("secret.read", "kv:secret/*"),
    ("secret.read", "kv:secret/../x"),
    ("secret.read", "path:a//b"),
    ("raw:read", "path:secret/data/x?v=1"),
    ("secret.write", "kv:secret/a+b/c"),
]


def fuzz_parse_target(action: str, resource: str) -> None:
    """An accepted path is plain segments without wildcards, dot-only
    segments or empty segments, and kv: always carries a key."""
    try:
        res = parse_resource(resource)
    except ResourceError:
        return
    try:
        tg = parse_target(action, res)
    except HallpassError:
        return
    assert not res.query, f"query slipped through {res}"
    p = tg.path
    assert not (p == "" or p.startswith("/") or p.endswith("/") or any(c in p for c in "*+?# \\%") or len(p.encode()) > 512), (
        f"bad path {p!r} from {resource!r}"
    )
    for seg in p.split("/"):
        assert seg != "" and seg.strip(".") != "", f"bad segment {seg!r} in {p!r}"
    if tg.kind == "kv":
        assert "/" in p, f"kv target without a key {tg}"
    for c in tg.action.need:
        assert c in CAPABILITIES and c != "deny", f"capability {c!r} from {action!r}"


@pytest.mark.parametrize(("action", "resource"), TARGET_SEEDS)
def test_fuzz_parse_target_seeds(action: str, resource: str) -> None:
    fuzz_parse_target(action, resource)


_ACTIONS = st.one_of(
    st.sampled_from([a.name for a in ACTION_LIST]),
    st.builds(lambda c: "raw:" + c, st.one_of(st.sampled_from(sorted(CAPABILITIES)), st.text(max_size=10))),
    st.text(max_size=30),
)
_PATH_CHARS = "abcXYZ019_.@:~=-/*+?# \\%\n"
_RESOURCES = st.one_of(
    st.builds(lambda t, i: t + i, st.sampled_from(["kv:", "path:", "mount:", "kv", ""]), st.text(alphabet=_PATH_CHARS, max_size=40)),
    st.text(max_size=60),
)


@settings(max_examples=_examples(500), deadline=None)
@given(_ACTIONS, _RESOURCES)
def test_fuzz_parse_target(action: str, resource: str) -> None:
    fuzz_parse_target(action, resource)


# -- FuzzPolicy ------------------------------------------------------------------

POLICY_SEEDS = [
    DEV_POLICY,
    TEAM_POLICY,
    OPS_POLICY,
    DEFAULT_POLICY,
    "",
    'path "a" { policy = "write" }',
    'path = { "a/*" = { capabilities = ["read"] } }',
    '{"path": [{"a": {"capabilities": ["read"]}}]}',
    'path "a" { capabilities = ["read"] } # trailing',
    'path "{{identity.entity.name}}/*" { capabilities = ["read"] }',
]

_TC = TemplateContext(entity_id="e1", entity_name="dana", metadata={"team": "x"})


def fuzz_policy(src: str) -> None:
    """The policy parser never crashes, and every rule it returns has a
    non-empty pattern and known capabilities."""
    try:
        rules = parse_policy("fuzz", src, _TC)
    except PolicyError:
        return
    for r in rules:
        assert r.pattern != "" and r.policy == "fuzz", f"rule {r}"
        for c in r.caps:
            assert c in CAPABILITIES, f"capability {c!r}"
        assert not ("{{" in r.pattern and not r.unresolved), f"template left in {r.pattern!r}"
    # Evaluation never crashes either.
    evaluate(rules, "secret/data/x", ["read"])
    evaluate(rules, "secret/metadata/x/", ["list"])


@pytest.mark.parametrize("src", POLICY_SEEDS)
def test_fuzz_policy_seeds(src: str) -> None:
    fuzz_policy(src)


@pytest.mark.parametrize("values", corpus("FuzzPolicy"), ids=lambda v: repr(v[0])[:40])
def test_fuzz_policy_corpus(values: list[str]) -> None:
    (src,) = values
    fuzz_policy(src)


def test_fuzz_policy_corpus_present() -> None:
    assert corpus("FuzzPolicy"), "the FuzzPolicy corpus is missing"


def test_fuzz_policy_regression_empty_json_path() -> None:
    # The corpus entry: a JSON stanza whose path is only the slash Vault
    # drops must be refused, not produce an empty pattern.
    with pytest.raises(PolicyError, match="empty path"):
        parse_policy("fuzz", '{"pAth":{"/":{}}}', _TC)


_HCL_TOKENS = st.sampled_from(
    [
        "path",
        '"secret/*"',
        '"a/+/b"',
        '"/"',
        '"{{identity.entity.name}}"',
        '"{{identity.entity.metadata.team}}/x"',
        '"{{bad"',
        "{",
        "}",
        "[",
        "]",
        "=",
        ":",
        ",",
        "\n",
        " ",
        "capabilities",
        "policy",
        '"read"',
        '"deny"',
        '"READ "',
        '"write"',
        '"bogus"',
        "allowed_parameters",
        "min_wrapping_ttl",
        "control_group",
        "factor",
        "0",
        "1s",
        "-",
        "null",
        "false",
        "# c\n",
        "// c\n",
        "/* c */",
        "/*",
        '"unterminated',
        "<<EOF",
        "name",
        "\\",
    ]
)
_JSON_TOKENS = st.sampled_from(
    ['{"path":', '{"PATH":', "{", "}", "[", "]", ":", ",", '"a/*"', '"/"', '"capabilities"', '"policy"', '"read"', '"x"', "null", "0", "{ }", '""', " "]
)
_POLICIES = st.one_of(
    st.text(max_size=200),
    st.lists(_HCL_TOKENS, max_size=40).map(" ".join),
    st.lists(_JSON_TOKENS, max_size=30).map("".join),
    st.builds(lambda s, i, t: s[:i] + t + s[i:], st.sampled_from(POLICY_SEEDS), st.integers(0, 400), st.text(max_size=10)),
    st.builds(lambda s, i, j: s[:i] + s[i + j :], st.sampled_from(POLICY_SEEDS), st.integers(0, 400), st.integers(0, 40)),
)


@settings(max_examples=_examples(1000), deadline=None)
@given(_POLICIES)
def test_fuzz_policy(src: str) -> None:
    fuzz_policy(src)
