"""Port of internal/integrations/snowflake/fuzz_test.go.

FuzzParseTarget and FuzzIdentifier become Hypothesis properties with the
same invariants; their seed corpora (the f.Add seeds; the Go package has no
testdata/fuzz files) are replayed as plain cases.
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from hallpass.core.catalog import ResourceError, parse_resource
from hallpass.core.decision import HallpassError
from hallpass.integrations.snowflake.actions import ACTION_LIST, KINDS, parse_target
from hallpass.integrations.snowflake.sql import parse_identifier, quote, split_name
from tests.harness import examples as _examples

PARSE_TARGET_SEEDS = [
    ("table.select", "table:prod.sales.orders"),
    ("table.select", 'table:prod.sales."Mixed Case"'),
    ("schema.usage", "schema:prod.sales"),
    ("database.usage", "database:prod"),
    ("role.use", "role:analyst"),
    ("account.create_database", "account"),
    ("raw:CREATE_STAGE", "schema:prod.sales"),
    ("table.select", 'table:prod.sales."a""b"'),
    ("table.select", "table:prod.sales.o;drop"),
    ("table.select", 'table:p."x"."y'),
]


def fuzz_parse_target(action: str, resource: str) -> None:
    """An accepted name has exactly the parts its kind takes, every part is
    a resolved identifier that quotes back to a safe literal (no unescaped
    quote, no control character), and raw privileges are upper-case
    words."""
    try:
        res = parse_resource(resource)
    except ResourceError:
        return
    try:
        tg = parse_target(action, res)
    except HallpassError:
        return
    assert not res.query, f"query slipped through {res}"
    k = KINDS[tg.kind]
    assert len(tg.name) == k.parts, f"{len(tg.name)} parts for {tg.kind}"
    for p in tg.name:
        assert p != "" and len(p.encode("utf-8", "surrogatepass")) <= 255, f"part {p!r}"
        for c in p:
            assert not (c < "\x20" or c == "\x7f"), f"control character in {p!r}"
        q = quote(p)
        assert q.count('"') % 2 == 0 and q.startswith('"') and q.endswith('"'), f"quote({p!r}) = {q!r}"
        # Round trip: the quoted form parses back to the same part.
        back = parse_identifier(q)
        assert back == p, f"round trip {p!r} -> {q!r} -> {back!r}"
    for priv in tg.action.privileges:
        assert priv != "" and priv != "OWNERSHIP" and priv.upper() == priv and not any(c in priv for c in "_;'\""), f"privilege {priv!r} from {action!r}"


@pytest.mark.parametrize(("action", "resource"), PARSE_TARGET_SEEDS)
def test_fuzz_parse_target_seeds(action: str, resource: str) -> None:
    fuzz_parse_target(action, resource)


_ACTIONS = st.one_of(
    st.sampled_from([a.name for a in ACTION_LIST]),
    st.builds(lambda p: "raw:" + p, st.one_of(st.from_regex(r"[A-Z_a-z ]{0,20}", fullmatch=True), st.text())),
    st.text(),
)
_TYPES = st.sampled_from([*sorted(KINDS), "other"])
_PART = st.one_of(
    st.from_regex(r"[A-Za-z_$0-9;]{0,10}", fullmatch=True), st.from_regex(r'"[^"\x00-\x1f]{0,6}("")?[^"]{0,3}"?', fullmatch=True), st.text(max_size=6)
)
_NAME = st.builds(lambda ps: ".".join(ps), st.lists(_PART, min_size=0, max_size=4))
_RESOURCES = st.one_of(st.text(), st.builds(lambda t, n: t + ":" + n, _TYPES, _NAME), _TYPES)


@settings(max_examples=_examples(500), deadline=None)
@given(_ACTIONS, _RESOURCES)
def test_fuzz_parse_target(action: str, resource: str) -> None:
    fuzz_parse_target(action, resource)


IDENTIFIER_SEEDS = ["a", '"a"', '"a""b"', "_$", '"', '""', "x.y", '"x.y"']


def fuzz_identifier(s: str) -> None:
    """parse_identifier never crashes and every accepted identifier survives
    quote/parse round trips."""
    try:
        id = parse_identifier(s)
    except ValueError:
        return
    back = parse_identifier(quote(id))
    assert back == id, f"round trip {id!r} -> {back!r}"
    parts = split_name(quote(id))
    assert len(parts) == 1, f"split_name({quote(id)!r}) = {parts!r}"


@pytest.mark.parametrize("s", IDENTIFIER_SEEDS)
def test_fuzz_identifier_seeds(s: str) -> None:
    fuzz_identifier(s)


@settings(max_examples=_examples(1000), deadline=None)
@given(st.one_of(st.text(), st.from_regex(r'"[^"]*("")?[^"]*"', fullmatch=True), st.from_regex(r"[A-Za-z_][A-Za-z0-9_$]{0,20}", fullmatch=True)))
def test_fuzz_identifier(s: str) -> None:
    fuzz_identifier(s)
