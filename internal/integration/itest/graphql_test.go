package itest

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sdl = `
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
`

func gql(body string) *http.Request {
	return req("POST", "https://api.example.com/graphql", "application/json")
}

func TestGraphQL(t *testing.T) {
	s, err := LoadSpec("t", []byte(sdl))
	if err != nil {
		t.Fatal(err)
	}
	ok := []string{
		`{"query":"{ viewer { id email } }"}`,
		`{"query":"query($e:String!){ users(filter:{email:{eqIgnoreCase:$e}}, includeDisabled:true){ id teams(first:10){ nodes { key visibility } pageInfo { hasNextPage endCursor } } } }","variables":{"e":"a@b.c"}}`,
		`{"query":"query($f:UserFilter){ users(filter:$f){ id } }","variables":{"f":{"email":{"in":["a"]},"and":[{"admin":true}]}}}`,
		`{"query":"query { entity(id:\"1\") { __typename ... on User { email } ...T } } fragment T on Team { key }"}`,
		`{"query":"query A { now } query B { viewer { id } }","operationName":"B"}`,
		`{"query":"query($id:String!){ user(id:$id){ ...U } } fragment U on User { id admin }","variables":{"id":"x"}}`,
	}
	for _, b := range ok {
		if err := s.Validate(gql(b), []byte(b)); err != nil {
			t.Errorf("rejected %s: %v", b, err)
		}
	}
	bad := map[string]string{
		`{"query":"{ viewer { id emai } }"}`:                                                           "no field emai",
		`{"query":"{ viewer }"}`:                                                                       "needs a selection set",
		`{"query":"{ viewer { id { x } } }"}`:                                                          "takes no selection set",
		`{"query":"{ user { id } }"}`:                                                                  "requires argument id",
		`{"query":"{ users(filtr:{}) { id } }"}`:                                                       "takes no argument filtr",
		`{"query":"{ users(filter:{emial:{eq:\"a\"}}) { id } }"}`:                                      "has no field emial",
		`{"query":"query($e:String){ user(id:$e){ id } }","variables":{"e":"a"}}`:                      "may be null",
		`{"query":"query($e:String!){ user(id:$e){ id } }"}`:                                           "required but not given",
		`{"query":"query($e:String!){ user(id:$e){ id } }","variables":{"e":"a","x":1}}`:               "not declared",
		`{"query":"query($f:UserFilter){ users(filter:$f){ id } }","variables":{"f":{"mail":1}}}`:      "has no field mail",
		`{"query":"query($f:UserFilter){ users(filter:$f){ id } }","variables":{"f":{"admin":"yes"}}}`: "Boolean wants",
		`{"query":"{ viewer { teams(first:\"x\"){ nodes { id } } } }"}`:                                "Int wants a number",
		`{"query":"{ entity(id:\"1\") { id } }"}`:                                                      "selected on union",
		`{"query":"{ entity(id:\"1\") { ...Nope } }"}`:                                                 "not defined",
		`{"query":"query A { now } query B { viewer { id } }"}`:                                        "no operationName",
		`{"query":"{ viewer { id "}`:                                                                   "does not parse",
		`{"query":"{ viewer { teams { nodes { visibility(x:1) } } } }"}`:                               "takes no argument",
	}
	for b, want := range bad {
		err := s.Validate(gql(b), []byte(b))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err %v, want %q", b, err, want)
		}
	}
	if err := s.Validate(req("GET", "https://api.example.com/graphql", ""), nil); err == nil {
		t.Error("GET accepted")
	}
}

// TestGraphQLRealSchema parses the Linear schema when it is available.
func TestGraphQLRealSchema(t *testing.T) {
	dir := os.Getenv("HALLPASS_SPECS_DIR")
	if dir == "" {
		t.Skip("HALLPASS_SPECS_DIR not set")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "linear.spec"))
	if err != nil {
		t.Skip(err)
	}
	s, err := LoadSpec("linear", raw)
	if err != nil {
		t.Fatal(err)
	}
	b := `{"query":"query($e:String!){ users(filter:{email:{eqIgnoreCase:$e}}, includeDisabled:true, first:50){ nodes { id email active admin owner guest app disableReason } } }","variables":{"e":"a@b.c"}}`
	if err := s.Validate(gql(b), []byte(b)); err != nil {
		t.Error(err)
	}
	b = `{"query":"{ viewer { id emial } }"}`
	if err := s.Validate(gql(b), []byte(b)); err == nil {
		t.Error("typo accepted")
	}
}
