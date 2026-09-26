"""Port of internal/integration/itest/graphql_test.go."""

from __future__ import annotations

import os

import pytest

from tests.harness.graphql import GraphQL, looks_like_sdl
from tests.harness.spec import SpecError, SpecRequest, load_spec

SDL = '''
"""The root."""
schema { query: Query }

scalar DateTime

enum Visibility { public private }

input StringComparator { eq: String, eqIgnoreCase: String, in: [String!] }
input UserFilter { email: StringComparator, admin: Boolean, and: [UserFilter!] }

interface Node { id: ID! }

type User implements Node @key(fields: "id") {
  id: ID!
  email: String!
  admin: Boolean! @deprecated(reason: "no")
  teams(first: Int = 50, after: String): TeamConnection!
}
type Team implements Node { id: ID! key: String! visibility: Visibility! }
type TeamConnection { nodes: [Team!]! pageInfo: PageInfo! }
type PageInfo { hasNextPage: Boolean! endCursor: String }
union Entity = User | Team

type Query {
  users(filter: UserFilter, first: Int, includeDisabled: Boolean): [User!]!
  user(id: String!): User!
  entity(id: ID!): Entity
  viewer: User!
}
extend type Query { now: DateTime }
directive @key(fields: String!) repeatable on OBJECT | INTERFACE
'''


def gql(body: bytes | str) -> SpecRequest:
    return SpecRequest.from_url("POST", "https://api.example.com/graphql", "application/json")


def validate(s: object, r: SpecRequest, body: bytes | str | None) -> SpecError | None:
    if isinstance(body, str):
        body = body.encode()
    try:
        s.validate(r, body or b"")  # type: ignore[attr-defined]
    except SpecError as e:
        return e
    return None


OK = [
    r'{"query":"{ viewer { id email } }"}',
    r'{"query":"query($e:String!){ users(filter:{email:{eqIgnoreCase:$e}}, includeDisabled:true){ id teams(first:10){ nodes { key visibility } pageInfo { hasNextPage endCursor } } } }","variables":{"e":"a@b.c"}}',
    r'{"query":"query($f:UserFilter){ users(filter:$f){ id } }","variables":{"f":{"email":{"in":["a"]},"and":[{"admin":true}]}}}',
    r'{"query":"query { entity(id:\"1\") { __typename ... on User { email } ...T } } fragment T on Team { key }"}',
    r'{"query":"query A { now } query B { viewer { id } }","operationName":"B"}',
    r'{"query":"query($id:String!){ user(id:$id){ ...U } } fragment U on User { id admin }","variables":{"id":"x"}}',
    r'{"query":"query($e:String!){ users(filter:{email:{in:$e}}){ id } }","variables":{"e":"a@b.c"}}',
    b'{"query":"\xef\xbb\xbf{ viewer { id } }"}',
]

BAD = {
    r'{"query":"{ viewer { id emai } }"}': "no field emai",
    r'{"query":"{ viewer }"}': "needs a selection set",
    r'{"query":"{ viewer { id { x } } }"}': "takes no selection set",
    r'{"query":"{ user { id } }"}': "requires argument id",
    r'{"query":"{ users(filtr:{}) { id } }"}': "takes no argument filtr",
    r'{"query":"{ users(filter:{emial:{eq:\"a\"}}) { id } }"}': "has no field emial",
    r'{"query":"query($e:String){ user(id:$e){ id } }","variables":{"e":"a"}}': "may be null",
    r'{"query":"query($e:String!){ user(id:$e){ id } }"}': "required but not given",
    r'{"query":"query($e:String!){ user(id:$e){ id } }","variables":{"e":"a","x":1}}': "not declared",
    r'{"query":"query($f:UserFilter){ users(filter:$f){ id } }","variables":{"f":{"mail":1}}}': "has no field mail",
    r'{"query":"query($f:UserFilter){ users(filter:$f){ id } }","variables":{"f":{"admin":"yes"}}}': "Boolean wants",
    r'{"query":"{ viewer { teams(first:\"x\"){ nodes { id } } } }"}': "Int wants a number",
    r'{"query":"{ entity(id:\"1\") { id } }"}': "selected on union",
    r'{"query":"{ entity(id:\"1\") { ...Nope } }"}': "not defined",
    r'{"query":"query A { now } query B { viewer { id } }"}': "no operationName",
    r'{"query":"{ viewer { id "}': "does not parse",
    r'{"query":"{ viewer { teams { nodes { visibility(x:1) } } } }"}': "takes no argument",
    r'{"query":"{ viewer { id } } { viewer { emai } }"}': "two anonymous",
    r'{"query":"{ viewer { id } } query B { now }","operationName":"B"}': "mixed with named",
    r'{"query":"query($e:[String!]){ user(id:$e){ id } }","variables":{"e":["a"]}}': "argument wants String!",
}


def test_graph_ql() -> None:
    s = load_spec("t", SDL.encode())
    for b in OK:
        err = validate(s, gql(b), b)
        assert err is None, f"rejected {b!r}: {err}"
    for b, want in BAD.items():
        err = validate(s, gql(b), b)
        assert err is not None and want in str(err), f"{b}: err {err}, want {want!r}"
    assert validate(s, SpecRequest.from_url("GET", "https://api.example.com/graphql", ""), None) is not None, "GET accepted"


def test_sdl_detection() -> None:
    """A YAML description whose free text starts a line with an SDL keyword
    is not taken for a schema, and an SDL schema is."""
    yaml_doc = (
        "swagger: '2.0'\npaths:\n  /x:\n    get:\n      description: |\n        The\n"
        "        type of item to import is controlled by the `relation` attribute. Skips\n        enum values that do not fit.\n"
    )
    assert not looks_like_sdl(yaml_doc.encode()), "YAML taken for SDL"
    s = load_spec("y", yaml_doc.encode())
    assert s.name() == "y"
    assert not isinstance(s, GraphQL), "yaml loaded as GraphQL"
    for src in [SDL, "type Query { a: Int }", "schema {\n query: Q\n}", "scalar X\ntype Query { x: X }", '"""doc"""\ntype Query implements Node { id: ID! }']:
        assert looks_like_sdl(src.encode()), f"SDL not recognised: {src[:20]!r}"
        load_spec("g", src.encode())  # raises SpecError: SDL failed to load


def test_graph_ql_real_schema() -> None:
    """Parses the Linear schema when it is available."""
    d = os.environ.get("HALLPASS_SPECS_DIR", "")
    if d == "":
        pytest.skip("HALLPASS_SPECS_DIR not set")
    try:
        with open(os.path.join(d, "linear.spec"), "rb") as f:
            raw = f.read()
    except OSError as e:
        pytest.skip(str(e))
    s = load_spec("linear", raw)
    b = r'{"query":"query($e:String!){ users(filter:{email:{eqIgnoreCase:$e}}, includeDisabled:true, first:50){ nodes { id email active admin owner guest app disableReason } } }","variables":{"e":"a@b.c"}}'
    err = validate(s, gql(b), b)
    assert err is None, err
    b = r'{"query":"{ viewer { id emial } }"}'
    assert validate(s, gql(b), b) is not None, "typo accepted"
