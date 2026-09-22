package github

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/roee-hersh/hallpass/internal/authx"
	"github.com/roee-hersh/hallpass/internal/integration"
	"github.com/roee-hersh/hallpass/internal/integration/itest"
	"github.com/roee-hersh/hallpass/internal/secret"
)

const (
	testAppID = "Iv1.0123456789abcdef"
	testInst  = "42"
)

// testKey is generated once per test binary; 2048-bit keys are slow.
var testKey = sync.OnceValue(func() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
})

// keySecret is the App private key as a test secret. The canary goes in a
// comment line before the PEM block, which ParseRSAPrivateKey skips.
func keySecret() secret.Secret {
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(testKey())}
	return itest.Literal("github\n" + string(pem.EncodeToMemory(block)))
}

// clock is a settable time source shared by the connection and the fake.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type membership struct{ state, role string }

type permRecord struct {
	role  string
	perms *permissions // nil: only the lossy string is reported
	str   string
}

// fake is a GitHub REST + GraphQL API for one organization "acme". Tests
// change its fields through with(), which takes the lock the handler holds.
type fake struct {
	t   *testing.T
	mu  sync.Mutex
	now func() time.Time

	minted      string // the token access_tokens hands out
	accepted    string // the token the API accepts
	mints       int    // access_tokens calls
	mintedFor   string // installation id of the last mint
	badJWTs     int
	instPerms   map[string]string
	users       map[string]string // login -> type
	perms       map[string]map[string]permRecord
	permStatus  int // override for the permission endpoint (0: normal)
	permHeader  http.Header
	repos       map[string]map[string]any
	members     map[string]membership
	org         map[string]any
	teams       map[string]map[string]membership
	rules       map[string][]map[string]any // "repo@branch" -> rules
	rulesStatus int
	saml        bool
	identities  []map[string]any
	pageSize    int
	pageQueries int
	gqlErrors   []map[string]any
}

func newFake(t *testing.T) *fake {
	all := permissions{Pull: true, Triage: true, Push: true, Maintain: true, Admin: true}
	write := permissions{Pull: true, Triage: true, Push: true}
	read := permissions{Pull: true}
	tok := itest.Canary + "ghs_1"
	return &fake{
		t:         t,
		now:       time.Now,
		minted:    tok,
		accepted:  tok,
		instPerms: map[string]string{"metadata": "read", "members": "read"},
		users:     map[string]string{"dana": "User", "bob": "User", "carol": "User", "acme": "Organization"},
		perms: map[string]map[string]permRecord{
			"dana": {
				"api":    {role: "admin", perms: &all, str: "admin"},
				"webapp": {role: "write", perms: &write, str: "write"},
				"legacy": {str: "write"},
			},
			"bob": {
				"api":    {role: "read", perms: &read, str: "read"},
				"webapp": {role: "read", perms: &read, str: "read"},
			},
			"carol": {
				"api":    {role: "none", perms: &permissions{}, str: "none"},
				"webapp": {role: "none", perms: &permissions{}, str: "none"},
			},
		},
		repos: map[string]map[string]any{
			"api":    {"name": "api", "has_issues": true},
			"webapp": {"name": "webapp", "has_issues": false},
			"legacy": {"name": "legacy"},
		},
		members: map[string]membership{
			"dana": {"active", "admin"},
			"bob":  {"active", "member"},
			"eve":  {"pending", "member"},
		},
		org: map[string]any{
			"login":                                   "acme",
			"members_can_create_repositories":         true,
			"members_can_create_public_repositories":  false,
			"members_can_create_private_repositories": true,
		},
		teams: map[string]map[string]membership{
			"platform": {"dana": {"active", "maintainer"}, "bob": {"active", "member"}, "eve": {"pending", "member"}},
		},
		rules: map[string][]map[string]any{
			"api@main":    {{"type": "pull_request"}, {"type": "required_status_checks"}, {"type": "pull_request"}},
			"api@release": {{"type": "required_signatures"}},
		},
		saml:     true,
		pageSize: 2,
		identities: []map[string]any{
			{"user": map[string]any{"login": "dana"}, "samlIdentity": map[string]any{"nameId": "dana@example.com", "username": "dana@example.com"}, "scimIdentity": nil},
			{"user": map[string]any{"login": "bob"}, "samlIdentity": map[string]any{"nameId": "bob@example.com", "username": nil}, "scimIdentity": map[string]any{"username": "bob@example.com"}},
			{"user": nil, "samlIdentity": map[string]any{"nameId": "ghost@example.com", "username": "ghost@example.com"}, "scimIdentity": nil},
			{"user": map[string]any{"login": "zed"}, "samlIdentity": map[string]any{"nameId": "Zed@Example.com", "username": "zed"}, "scimIdentity": nil},
			{"user": nil, "samlIdentity": map[string]any{"nameId": "phantom@example.com", "username": "phantom"}, "scimIdentity": nil},
			{"user": map[string]any{"login": "carol"}, "samlIdentity": map[string]any{"nameId": "carol@example.com", "username": "carol@example.com"}, "scimIdentity": nil},
			{"user": map[string]any{"login": "eve"}, "samlIdentity": map[string]any{"nameId": "eve@example.com", "username": "eve@example.com"}, "scimIdentity": nil},
		},
	}
}

// with runs fn under the fake's lock.
func (f *fake) with(fn func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn()
}

func (f *fake) mintCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.mints
}

func (f *fake) pageCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pageQueries
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// checkJWT verifies the App JWT: RS256, signed by the test key, iss is the
// app id, lifetime at most 10 minutes.
func (f *fake) checkJWT(w http.ResponseWriter, r *http.Request) bool {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	parts := strings.Split(tok, ".")
	fail := func(msg string) bool {
		f.with(func() { f.badJWTs++ })
		f.t.Errorf("bad App JWT: %s", msg)
		writeJSON(w, 401, map[string]any{"message": "Bad credentials"})
		return false
	}
	if len(parts) != 3 {
		return fail("not a compact JWS")
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fail("header")
	}
	var hdr struct{ Alg, Typ string }
	if json.Unmarshal(hb, &hdr) != nil || hdr.Alg != "RS256" || hdr.Typ != "JWT" {
		return fail("header " + string(hb))
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fail("signature encoding")
	}
	if err := authx.Verify(&testKey().PublicKey, authx.RS256, []byte(parts[0]+"."+parts[1]), sig); err != nil {
		return fail("signature: " + err.Error())
	}
	var claims struct {
		Iss string `json:"iss"`
		Iat int64  `json:"iat"`
		Exp int64  `json:"exp"`
	}
	if err := authx.DecodeJWTClaims(tok, &claims); err != nil {
		return fail("claims: " + err.Error())
	}
	if claims.Iss != testAppID {
		return fail("iss " + claims.Iss)
	}
	if claims.Exp-claims.Iat > 600 || claims.Exp <= claims.Iat {
		return fail("lifetime")
	}
	if now := f.now().Unix(); claims.Iat > now || claims.Exp < now {
		return fail("clock")
	}
	return true
}

func (f *fake) checkToken(w http.ResponseWriter, r *http.Request) bool {
	f.mu.Lock()
	want := "Bearer " + f.accepted
	f.mu.Unlock()
	if r.Header.Get("Authorization") != want {
		writeJSON(w, 401, map[string]any{"message": "Bad credentials", "note": itest.Canary + "body"})
		return false
	}
	if r.Header.Get("Accept") != "application/vnd.github+json" || r.Header.Get("X-GitHub-Api-Version") != "2022-11-28" {
		f.t.Errorf("missing GitHub headers on %s %s: %v", r.Method, r.URL.Path, r.Header)
		writeJSON(w, 400, map[string]any{"message": "headers"})
		return false
	}
	return true
}

func (f *fake) handle(w http.ResponseWriter, r *http.Request) {
	p := strings.TrimPrefix(r.URL.EscapedPath(), "/api")
	if p == "/graphql" && r.Method == "POST" {
		if f.checkToken(w, r) {
			f.graphql(w, r)
		}
		return
	}
	p = strings.TrimPrefix(p, "/v3")
	seg := strings.Split(strings.TrimPrefix(p, "/"), "/")
	switch {
	case p == "/app" && r.Method == "GET":
		if f.checkJWT(w, r) {
			writeJSON(w, 200, map[string]any{"slug": "hallpass-reader", "name": "hallpass reader", "note": itest.Canary + "app"})
		}
	case len(seg) == 3 && seg[0] == "orgs" && seg[2] == "installation" && r.Method == "GET":
		if !f.checkJWT(w, r) {
			return
		}
		if seg[1] != "acme" {
			writeJSON(w, 404, map[string]any{"message": "Not Found"})
			return
		}
		f.with(func() {
			writeJSON(w, 200, map[string]any{"id": 42, "permissions": f.instPerms, "account": map[string]any{"login": "acme"}})
		})
	case len(seg) == 4 && seg[0] == "app" && seg[1] == "installations" && seg[3] == "access_tokens" && r.Method == "POST":
		if f.checkJWT(w, r) {
			f.with(func() {
				f.mints++
				f.mintedFor = seg[2]
				writeJSON(w, 201, map[string]any{"token": f.minted, "expires_at": f.now().Add(time.Hour).UTC().Format(time.RFC3339)})
			})
		}
	default:
		if f.checkToken(w, r) {
			f.with(func() { f.rest(w, r, seg) })
		}
	}
}

// rest serves the installation-token endpoints. Called with f.mu held.
func (f *fake) rest(w http.ResponseWriter, r *http.Request, seg []string) {
	notFound := func() { writeJSON(w, 404, map[string]any{"message": "Not Found", "note": itest.Canary + "404"}) }
	if r.Method != "GET" {
		writeJSON(w, 405, map[string]any{"message": "method"})
		return
	}
	switch {
	case len(seg) == 2 && seg[0] == "users":
		typ, ok := f.users[seg[1]]
		if !ok {
			notFound()
			return
		}
		writeJSON(w, 200, map[string]any{"login": seg[1], "type": typ})
	case len(seg) == 3 && seg[0] == "repos" && seg[1] == "acme":
		body, ok := f.repos[seg[2]]
		if !ok {
			notFound()
			return
		}
		writeJSON(w, 200, body)
	case len(seg) == 6 && seg[0] == "repos" && seg[1] == "acme" && seg[3] == "collaborators" && seg[5] == "permission":
		if f.permStatus != 0 {
			for k, vs := range f.permHeader {
				w.Header()[k] = vs
			}
			writeJSON(w, f.permStatus, map[string]any{"message": "override"})
			return
		}
		rec, ok := f.perms[seg[4]][seg[2]]
		if _, repoExists := f.repos[seg[2]]; !ok || !repoExists {
			notFound()
			return
		}
		user := map[string]any{"login": seg[4]}
		if rec.perms != nil {
			user["permissions"] = rec.perms
		}
		writeJSON(w, 200, map[string]any{"permission": rec.str, "role_name": rec.role, "user": user})
	case len(seg) == 6 && seg[0] == "repos" && seg[1] == "acme" && seg[3] == "rules" && seg[4] == "branches":
		if f.rulesStatus != 0 {
			writeJSON(w, f.rulesStatus, map[string]any{"message": "override"})
			return
		}
		if _, ok := f.repos[seg[2]]; !ok {
			notFound()
			return
		}
		branch, _ := url.PathUnescape(seg[5])
		rules := f.rules[seg[2]+"@"+branch]
		if rules == nil {
			rules = []map[string]any{}
		}
		writeJSON(w, 200, rules)
	case len(seg) == 2 && seg[0] == "orgs" && seg[1] == "acme":
		writeJSON(w, 200, f.org)
	case len(seg) == 4 && seg[0] == "orgs" && seg[1] == "acme" && seg[2] == "memberships":
		m, ok := f.members[seg[3]]
		if !ok {
			notFound()
			return
		}
		writeJSON(w, 200, map[string]any{"state": m.state, "role": m.role})
	case len(seg) == 4 && seg[0] == "orgs" && seg[1] == "acme" && seg[2] == "teams":
		if _, ok := f.teams[seg[3]]; !ok {
			notFound()
			return
		}
		writeJSON(w, 200, map[string]any{"slug": seg[3]})
	case len(seg) == 6 && seg[0] == "orgs" && seg[1] == "acme" && seg[2] == "teams" && seg[4] == "memberships":
		m, ok := f.teams[seg[3]][seg[5]]
		if !ok {
			notFound()
			return
		}
		writeJSON(w, 200, map[string]any{"state": m.state, "role": m.role})
	default:
		notFound()
	}
}

func identityUsername(id map[string]any, key string) string {
	sub, _ := id[key].(map[string]any)
	if sub == nil {
		return ""
	}
	s, _ := sub["username"].(string)
	return s
}

func (f *fake) graphql(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Query     string         `json:"query"`
		Variables map[string]any `json:"variables"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]any{"message": "bad json"})
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if org, _ := req.Variables["org"].(string); org != "acme" {
		writeJSON(w, 200, map[string]any{"data": map[string]any{"organization": nil}})
		return
	}
	if f.gqlErrors != nil {
		writeJSON(w, 200, map[string]any{"data": nil, "errors": f.gqlErrors})
		return
	}
	if !f.saml {
		writeJSON(w, 200, map[string]any{"data": map[string]any{"organization": map[string]any{"samlIdentityProvider": nil}}})
		return
	}
	var ext map[string]any
	if strings.Contains(req.Query, "userName:$email") {
		email, _ := req.Variables["email"].(string)
		nodes := []map[string]any{}
		for _, id := range f.identities {
			if strings.EqualFold(identityUsername(id, "samlIdentity"), email) || strings.EqualFold(identityUsername(id, "scimIdentity"), email) {
				nodes = append(nodes, id)
			}
		}
		ext = map[string]any{"nodes": nodes}
	} else {
		f.pageQueries++
		start := 0
		if c, ok := req.Variables["cursor"].(string); ok {
			start, _ = strconv.Atoi(c)
		}
		end := start + f.pageSize
		if end > len(f.identities) {
			end = len(f.identities)
		}
		ext = map[string]any{
			"pageInfo": map[string]any{"hasNextPage": end < len(f.identities), "endCursor": strconv.Itoa(end)},
			"nodes":    f.identities[start:end],
		}
	}
	writeJSON(w, 200, map[string]any{"data": map[string]any{"organization": map[string]any{"samlIdentityProvider": map[string]any{"externalIdentities": ext}}}})
}

type env struct {
	srv   *itest.Server
	api   *fake
	conn  integration.Connection
	clock *clock
	logs  *itest.Logs
}

func setup(t *testing.T, values map[string]string) *env {
	t.Helper()
	srv := itest.NewServer(t)
	api := newFake(t)
	srv.Handle("", "/api/*", api.handle)
	deps, logs := itest.Deps(t, srv)
	ck := &clock{t: time.Now()}
	deps.Now = ck.now
	api.now = ck.now
	v := map[string]string{"url": srv.URL, "organization": "acme", "app_id": testAppID, "identity_mode": "saml", "login_template": "{local}"}
	for k, val := range values {
		v[k] = val
	}
	s := itest.Settings("gh", "github", v, map[string]secret.Secret{"credential": keySecret()})
	c, err := Integration{}.New(context.Background(), s, deps)
	if err != nil {
		t.Fatal(err)
	}
	return &env{srv: srv, api: api, conn: c, clock: ck, logs: logs}
}

var (
	dana  = integration.User{Email: "dana@example.com"}
	bob   = integration.User{Email: "bob@example.com"}
	carol = integration.User{Email: "carol@example.com"}
	eve   = integration.User{Email: "eve@example.com"}
)

func (e *env) check(t *testing.T, u integration.User, action, resource string) integration.Decision {
	t.Helper()
	return itest.Check(t, e.conn, Integration{}, u, action, resource)
}

func (e *env) calls(path string) int {
	n := 0
	for _, c := range e.srv.Calls() {
		if strings.Contains(c.Path, path) {
			n++
		}
	}
	return n
}

func expectText(t *testing.T, d integration.Decision, code integration.Code, substr string) {
	t.Helper()
	itest.ExpectCode(t, d, code)
	if !strings.Contains(d.Text, substr) {
		t.Errorf("decision text %q does not contain %q", d.Text, substr)
	}
}

// --- auth -------------------------------------------------------------------

func TestAuthFlowAndTokenCache(t *testing.T) {
	e := setup(t, nil)
	itest.ExpectCode(t, e.check(t, dana, "repo.read", "repo:acme/api"), integration.CodeAllowed)
	itest.ExpectCode(t, e.check(t, dana, "repo.push", "repo:acme/api"), integration.CodeAllowed)

	var paths []string
	for _, c := range e.srv.Calls() {
		paths = append(paths, c.Method+" "+c.Path)
	}
	want := []string{
		"GET /api/v3/orgs/acme/installation",
		"POST /api/v3/app/installations/42/access_tokens",
		"POST /api/graphql",
		"GET /api/v3/repos/acme/api/collaborators/dana/permission",
		"POST /api/graphql",
		"GET /api/v3/repos/acme/api/collaborators/dana/permission",
	}
	if strings.Join(paths, "\n") != strings.Join(want, "\n") {
		t.Errorf("calls:\n%s\nwant:\n%s", strings.Join(paths, "\n"), strings.Join(want, "\n"))
	}
	if n := e.api.mintCount(); n != 1 {
		t.Errorf("installation token minted %d times, want 1", n)
	}
	// Decode the JWT the connection presented and check the claims directly.
	var inst itest.Call
	for _, c := range e.srv.Calls() {
		if c.Path == "/api/v3/orgs/acme/installation" {
			inst = c
		}
	}
	jwt := strings.TrimPrefix(inst.Header.Get("Authorization"), "Bearer ")
	var claims authx.StandardClaims
	if err := authx.DecodeJWTClaims(jwt, &claims); err != nil {
		t.Fatal(err)
	}
	if claims.Iss != testAppID || claims.Exp-claims.Iat > 600 || claims.Exp-claims.Iat <= 0 {
		t.Errorf("claims %+v", claims)
	}
	parts := strings.Split(jwt, ".")
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	if err := authx.Verify(&testKey().PublicKey, authx.RS256, []byte(parts[0]+"."+parts[1]), sig); err != nil {
		t.Error(err)
	}
	last := e.srv.LastCall()
	if last.Header.Get("Authorization") != "Bearer "+itest.Canary+"ghs_1" || last.Header.Get("X-GitHub-Api-Version") != "2022-11-28" || last.Header.Get("Accept") != "application/vnd.github+json" {
		t.Errorf("REST headers: %v", last.Header)
	}
}

func TestConfiguredInstallationIDSkipsDiscovery(t *testing.T) {
	e := setup(t, map[string]string{"installation_id": testInst})
	itest.ExpectCode(t, e.check(t, dana, "repo.read", "repo:acme/api"), integration.CodeAllowed)
	if e.calls("/orgs/acme/installation") != 0 {
		t.Error("installation discovered although installation_id is set")
	}
	if n := e.api.mintCount(); n != 1 {
		t.Errorf("mints = %d", n)
	}
}

func TestTokenInvalidatedOn401(t *testing.T) {
	e := setup(t, nil)
	itest.ExpectCode(t, e.check(t, dana, "repo.read", "repo:acme/api"), integration.CodeAllowed)
	// GitHub revoked the token: the API wants the next one it mints.
	e.api.with(func() { e.api.minted, e.api.accepted = itest.Canary+"ghs_2", itest.Canary+"ghs_2" })
	e.srv.Reset()
	itest.ExpectCode(t, e.check(t, dana, "repo.read", "repo:acme/api"), integration.CodeAllowed)
	if n := e.api.mintCount(); n != 2 {
		t.Errorf("mints = %d, want 2", n)
	}
	if n := e.calls("/api/graphql"); n != 2 {
		t.Errorf("graphql called %d times, want 2 (401 then retry)", n)
	}
	if n := e.calls("/permission"); n != 1 {
		t.Errorf("permission called %d times, want 1", n)
	}
	// A token that keeps being rejected is retried once, then reported.
	e.api.with(func() { e.api.accepted = "never-matches" })
	e.srv.Reset()
	itest.ExpectCode(t, e.check(t, dana, "repo.read", "repo:acme/api"), integration.CodeCredentialRejected)
	if n := e.calls("/api/graphql"); n != 2 {
		t.Errorf("graphql called %d times, want 2", n)
	}
	if n := e.api.mintCount(); n != 3 {
		t.Errorf("mints = %d, want 3", n)
	}
}

func TestTokenRefreshNearExpiry(t *testing.T) {
	e := setup(t, nil)
	itest.ExpectCode(t, e.check(t, dana, "repo.read", "repo:acme/api"), integration.CodeAllowed)
	e.clock.advance(56 * time.Minute) // within 5 min of the 1 h expiry
	itest.ExpectCode(t, e.check(t, dana, "repo.read", "repo:acme/api"), integration.CodeAllowed)
	if n := e.api.mintCount(); n != 2 {
		t.Errorf("mints = %d, want 2 after the token neared expiry", n)
	}
}

func TestBadKeyAndMissingInstallation(t *testing.T) {
	srv := itest.NewServer(t)
	api := newFake(t)
	srv.Handle("", "/api/*", api.handle)
	deps, _ := itest.Deps(t, srv)
	v := map[string]string{"url": srv.URL, "organization": "acme", "app_id": testAppID, "identity_mode": "template"}
	s := itest.Settings("gh", "github", v, map[string]secret.Secret{"credential": itest.Literal("not-a-key")})
	c, err := Integration{}.New(context.Background(), s, deps)
	if err != nil {
		t.Fatal(err)
	}
	d := itest.Check(t, c, Integration{}, dana, "repo.read", "repo:acme/api")
	itest.ExpectCode(t, d, integration.CodeCredentialRejected)
	if len(srv.Calls()) != 0 {
		t.Error("an unparsable key reached the API")
	}

	e := setup(t, map[string]string{"organization": "other", "identity_mode": "template"})
	d = e.check(t, dana, "repo.read", "repo:other/api")
	expectText(t, d, integration.CodeCredentialRejected, "not installed")
}

// --- identity ---------------------------------------------------------------

func TestIdentitySAML(t *testing.T) {
	e := setup(t, nil)
	ctx := context.Background()
	id, err := e.conn.ResolveIdentity(ctx, dana)
	if err != nil || id.ID != "dana" || id.Attr("identity_mode") != "saml" {
		t.Fatalf("dana: %+v %v", id, err)
	}
	id, err = e.conn.ResolveIdentity(ctx, bob) // matched through scimIdentity.username
	if err != nil || id.ID != "bob" {
		t.Fatalf("bob: %+v %v", id, err)
	}
	if e.api.pageCount() != 0 {
		t.Error("direct hits should not list identities")
	}
	// Unlinked identity on a direct hit.
	_, err = e.conn.ResolveIdentity(ctx, integration.User{Email: "ghost@example.com"})
	expectText(t, integration.ToDecision(err), integration.CodeUnsupported, "not linked")

	// zed's userName is not the email: found through the paginated listing.
	id, err = e.conn.ResolveIdentity(ctx, integration.User{Email: "zed@example.com"})
	if err != nil || id.ID != "zed" {
		t.Fatalf("zed: %+v %v", id, err)
	}
	if n := e.api.pageCount(); n != 4 { // 7 identities, 2 per page
		t.Errorf("page queries = %d, want 4", n)
	}
	// The listing is cached: another miss does not re-list.
	_, err = e.conn.ResolveIdentity(ctx, integration.User{Email: "nobody@example.com"})
	itest.ExpectCode(t, integration.ToDecision(err), integration.CodeUserNotFound)
	_, err = e.conn.ResolveIdentity(ctx, integration.User{Email: "phantom@example.com"})
	expectText(t, integration.ToDecision(err), integration.CodeUnsupported, "not linked")
	if n := e.api.pageCount(); n != 4 {
		t.Errorf("page queries = %d after cache, want 4", n)
	}
	e.clock.advance(11 * time.Minute)
	_, _ = e.conn.ResolveIdentity(ctx, integration.User{Email: "nobody@example.com"})
	if n := e.api.pageCount(); n != 8 {
		t.Errorf("page queries = %d after the cache expired, want 8", n)
	}
	// The GraphQL variables carry the email, never string-interpolated.
	for _, c := range e.srv.Calls() {
		if c.Path != "/api/graphql" {
			continue
		}
		var body struct {
			Query     string            `json:"query"`
			Variables map[string]string `json:"variables"`
		}
		c.JSON(t, &body)
		if strings.Contains(body.Query, "@example.com") || body.Variables["org"] != "acme" {
			t.Errorf("graphql body: %+v", body)
		}
	}
	// A bad email never reaches the network.
	e.srv.Reset()
	for _, bad := range []string{"not an email", "", "a@b@c", "x@", "@x", "dana@exa mple.com"} {
		_, err = e.conn.ResolveIdentity(ctx, integration.User{Email: bad})
		itest.ExpectCode(t, integration.ToDecision(err), integration.CodeInvalidRequest)
	}
	if len(e.srv.Calls()) != 0 {
		t.Error("invalid email hit the API")
	}
}

func TestIdentitySAMLNoProviderAndErrors(t *testing.T) {
	e := setup(t, nil)
	e.api.with(func() { e.api.saml = false })
	d := e.check(t, dana, "repo.read", "repo:acme/api")
	expectText(t, d, integration.CodeUnsupported, "no SAML identity provider")

	e.api.with(func() { e.api.saml = true })
	for _, c := range []struct {
		errs []map[string]any
		code integration.Code
	}{
		{[]map[string]any{{"type": "FORBIDDEN", "message": "Resource not accessible by integration"}}, integration.CodeCredentialRejected},
		{[]map[string]any{{"type": "INSUFFICIENT_SCOPES", "message": "x"}}, integration.CodeCredentialRejected},
		{[]map[string]any{{"message": "Something went wrong", "note": itest.Canary + "gql"}}, integration.CodeUpstreamError},
		{[]map[string]any{{"type": "RATE_LIMITED", "message": "slow down"}}, integration.CodeUpstreamRateLimit},
	} {
		e.api.with(func() { e.api.gqlErrors = c.errs })
		itest.ExpectCode(t, e.check(t, dana, "repo.read", "repo:acme/api"), c.code)
	}
}

func TestIdentityTemplate(t *testing.T) {
	e := setup(t, map[string]string{"identity_mode": "template", "login_template": "{local}"})
	d := e.check(t, dana, "repo.read", "repo:acme/api")
	itest.ExpectCode(t, d, integration.CodeAllowed)
	if e.calls("/api/graphql") != 0 || e.calls("/users/dana") != 1 {
		t.Error("template mode must GET /users/{login} and not use GraphQL")
	}
	d = e.check(t, integration.User{Email: "nobody@example.com"}, "repo.read", "repo:acme/api")
	itest.ExpectCode(t, d, integration.CodeUserNotFound)
	// A login that renders to an organization is not a user.
	d = e.check(t, integration.User{Email: "acme@example.com"}, "repo.read", "repo:acme/api")
	expectText(t, d, integration.CodeUserNotFound, "organization")
	// A template producing an invalid login never hits the API.
	e2 := setup(t, map[string]string{"identity_mode": "template", "login_template": "{local}.{domain}"})
	d = e2.check(t, dana, "repo.read", "repo:acme/api")
	itest.ExpectCode(t, d, integration.CodeUserNotFound)
	if e2.calls("/users/") != 0 {
		t.Error("invalid login reached the API")
	}
}

func TestIdentityMapFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.txt")
	write := func(s string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("# hallpass users\n\ndana@example.com dana   # comment\nBob@Example.com=bob\n")
	e := setup(t, map[string]string{"identity_mode": "map_file", "user_map_file": path})
	itest.ExpectCode(t, e.check(t, dana, "repo.read", "repo:acme/api"), integration.CodeAllowed)
	itest.ExpectCode(t, e.check(t, integration.User{Email: "BOB@example.com"}, "repo.read", "repo:acme/api"), integration.CodeAllowed)
	itest.ExpectCode(t, e.check(t, carol, "repo.read", "repo:acme/api"), integration.CodeUserNotFound)
	if e.calls("/api/graphql") != 0 || e.calls("/users/") != 0 {
		t.Error("map_file mode must not look users up upstream")
	}
	// The file is re-read at most every 60 s.
	write("dana@example.com dana\ncarol@example.com carol\n")
	itest.ExpectCode(t, e.check(t, carol, "repo.read", "repo:acme/api"), integration.CodeUserNotFound)
	e.clock.advance(61 * time.Second)
	itest.ExpectCode(t, e.check(t, carol, "repo.read", "repo:acme/api"), integration.CodeDenied)
	// A broken rewrite keeps the previous map.
	write("dana@example.com not a login\n")
	e.clock.advance(61 * time.Second)
	itest.ExpectCode(t, e.check(t, carol, "repo.read", "repo:acme/api"), integration.CodeDenied)

	// New validates the file exists.
	srv := itest.NewServer(t)
	deps, _ := itest.Deps(t, srv)
	base := map[string]string{"url": srv.URL, "organization": "acme", "app_id": testAppID, "identity_mode": "map_file"}
	secrets := map[string]secret.Secret{"credential": keySecret()}
	v := map[string]string{"user_map_file": filepath.Join(t.TempDir(), "missing")}
	for k, val := range base {
		v[k] = val
	}
	if _, err := (Integration{}).New(context.Background(), itest.Settings("gh", "github", v, secrets), deps); err == nil {
		t.Error("New accepted a missing user_map_file")
	}
	if _, err := (Integration{}).New(context.Background(), itest.Settings("gh", "github", base, secrets), deps); err == nil {
		t.Error("New accepted map_file mode without user_map_file")
	}
	for _, bad := range []string{"x\n", "dana@example.com dana bob\n", "nope dana\n", "dana@example.com bad--login\n"} {
		write(bad)
		if _, err := readUserMap(path); err == nil {
			t.Errorf("readUserMap accepted %q", bad)
		}
	}
}

// --- fields and resources ---------------------------------------------------

func TestFields(t *testing.T) {
	if err := integration.ValidateFields(Integration{}.Fields()); err != nil {
		t.Fatal(err)
	}
	if err := validateLogin("bad--login"); err == nil {
		t.Error("double hyphen accepted")
	}
	if err := validateLogin("-bad"); err == nil {
		t.Error("leading hyphen accepted")
	}
	if err := validateLogin(strings.Repeat("a", 40)); err == nil {
		t.Error("40-character login accepted")
	}
	if err := validateAppID("has space"); err == nil {
		t.Error("app id with space accepted")
	}
	if err := validateInstallationID("x1"); err == nil {
		t.Error("non-numeric installation id accepted")
	}
	if err := validateTemplate("static"); err == nil {
		t.Error("template without placeholder accepted")
	}
	if err := validateTemplate("{user}"); err == nil {
		t.Error("unknown placeholder accepted")
	}
	if applyTemplate("{local}-{domain}", "dana@example.com") != "dana-example.com" {
		t.Error("template")
	}
	srv := itest.NewServer(t)
	deps, _ := itest.Deps(t, srv)
	s := itest.Settings("gh", "github", map[string]string{"organization": "acme", "app_id": testAppID, "identity_mode": "template", "login_template": "static"}, map[string]secret.Secret{"credential": keySecret()})
	if _, err := (Integration{}).New(context.Background(), s, deps); err == nil {
		t.Error("New accepted a template without placeholders")
	}
	s = itest.Settings("gh", "github", map[string]string{"organization": "acme", "app_id": testAppID}, nil)
	if _, err := (Integration{}).New(context.Background(), s, deps); err == nil {
		t.Error("New accepted a missing credential")
	}
	// github.com layout when url is omitted; defaults apply when keys are absent.
	s = itest.Settings("gh", "github", map[string]string{"organization": "acme", "app_id": testAppID}, map[string]secret.Secret{"credential": keySecret()})
	c, err := Integration{}.New(context.Background(), s, deps)
	if err != nil {
		t.Fatal(err)
	}
	gc := c.(*Connection)
	if gc.rest.Base != "https://api.github.com" || gc.graphqlURL != "https://api.github.com/graphql" || gc.mode != "saml" {
		t.Errorf("public bases: %s %s %s", gc.rest.Base, gc.graphqlURL, gc.mode)
	}
	if len(srv.Calls()) != 0 {
		t.Error("New touched the network")
	}
}

func TestBadResources(t *testing.T) {
	e := setup(t, nil)
	cases := []struct{ action, resource string }{
		{"repo.read", "repo:other/api"},
		{"repo.read", "repo:acme"},
		{"repo.read", "repo:acme/"},
		{"repo.read", "repo:acme/api/extra"},
		{"repo.read", "repo:acme/api@"},
		{"repo.read", "repo:acme/api@-x"},
		{"repo.read", "repo:acme/api@a..b"},
		{"repo.read", "repo:acme/api@a b"},
		{"repo.read", "repo:acme/api?x=1"},
		{"repo.read", "repo:ac me/api"},
		{"repo.read", "repo:acme/.."},
		{"repo.read", "org:acme"},
		{"org.member", "repo:acme/api"},
		{"org.member", "org:other"},
		{"org.member", "org:Acme Inc"},
		{"team.member", "team:acme"},
		{"team.member", "team:other/platform"},
		{"team.member", "team:acme/Platform"},
		{"team.member", "team:acme/plat_form"},
		{"team.member", "org:acme"},
	}
	for _, cs := range cases {
		d := e.check(t, dana, cs.action, cs.resource)
		if d.Code != integration.CodeInvalidRequest {
			t.Errorf("%s %s -> %s: %s", cs.action, cs.resource, d.Code, d.Text)
		}
	}
	// Owner comparison is case-insensitive, as GitHub's is.
	itest.ExpectCode(t, e.check(t, dana, "repo.read", "repo:Acme/api"), integration.CodeAllowed)
	itest.ExpectCode(t, e.check(t, dana, "org.member", "org:ACME"), integration.CodeAllowed)
	for _, ok := range []string{"main", "release/1.2", "feat_x", "v1.0-rc.1"} {
		if !validBranch(ok) {
			t.Errorf("branch %q rejected", ok)
		}
	}
}

// --- repository checks ------------------------------------------------------

func TestPermissionEndpointStatuses(t *testing.T) {
	e := setup(t, nil)
	d := e.check(t, dana, "repo.read", "repo:acme/secret")
	expectText(t, d, integration.CodeResourceNotVisible, "not visible")

	e.api.with(func() {
		e.api.permStatus = 403
		e.api.permHeader = http.Header{"X-Ratelimit-Remaining": {"0"}, "X-Ratelimit-Reset": {"1"}}
	})
	itest.ExpectCode(t, e.check(t, dana, "repo.read", "repo:acme/api"), integration.CodeUpstreamRateLimit)
	e.api.with(func() { e.api.permHeader = http.Header{"X-Ratelimit-Remaining": {"4999"}} })
	itest.ExpectCode(t, e.check(t, dana, "repo.read", "repo:acme/api"), integration.CodeCredentialRejected)
	e.api.with(func() { e.api.permStatus = 0 })

	// A response with only the lossy permission string is still usable.
	itest.ExpectCode(t, e.check(t, dana, "repo.push", "repo:acme/legacy"), integration.CodeAllowed)
	itest.ExpectCode(t, e.check(t, dana, "repo.admin", "repo:acme/legacy"), integration.CodeDenied)
	// has_issues absent -> unknown.
	itest.ExpectCode(t, e.check(t, dana, "issue.create", "repo:acme/legacy"), integration.CodeUnsupported)
}

func TestBranchRules(t *testing.T) {
	e := setup(t, nil)
	d := e.check(t, dana, "repo.push", "repo:acme/api@main")
	expectText(t, d, integration.CodeUnsupported, "requires pull requests")

	d = e.check(t, dana, "pr.merge", "repo:acme/api@main")
	expectText(t, d, integration.CodeAllowed, "branch main has 3 rules (types pull_request, required_status_checks)")

	d = e.check(t, dana, "repo.push", "repo:acme/api@release")
	expectText(t, d, integration.CodeAllowed, "branch release has 1 rules (types required_signatures)")

	d = e.check(t, dana, "repo.push", "repo:acme/api@feature/x")
	expectText(t, d, integration.CodeAllowed, "no rules")
	if last := e.srv.LastCall(); !strings.HasSuffix(last.Path, "/api/rules/branches/feature/x") {
		t.Errorf("branch path %s", last.Path)
	}

	// A deny needs no rules lookup.
	e.srv.Reset()
	itest.ExpectCode(t, e.check(t, bob, "repo.push", "repo:acme/api@main"), integration.CodeDenied)
	if e.calls("/rules/") != 0 {
		t.Error("rules fetched for a deny")
	}
	// Rules endpoint not readable: allow with a note.
	for _, st := range []int{403, 404} {
		e.api.with(func() { e.api.rulesStatus = st })
		d = e.check(t, dana, "repo.push", "repo:acme/api@main")
		expectText(t, d, integration.CodeAllowed, "could not be read")
	}
	e.api.with(func() { e.api.rulesStatus = 500 })
	itest.ExpectCode(t, e.check(t, dana, "repo.push", "repo:acme/api@main"), integration.CodeUpstreamError)
	// Other repo actions ignore @branch.
	e.api.with(func() { e.api.rulesStatus = 0 })
	e.srv.Reset()
	itest.ExpectCode(t, e.check(t, dana, "repo.read", "repo:acme/api@main"), integration.CodeAllowed)
	if e.calls("/rules/") != 0 {
		t.Error("rules fetched for repo.read")
	}
}

// --- organization and team checks ------------------------------------------

func TestOrgRepoCreateVariants(t *testing.T) {
	e := setup(t, nil)
	d := e.check(t, bob, "org.repo.create", "org:acme")
	expectText(t, d, integration.CodeAllowed, "(private)")
	itest.ExpectCode(t, e.check(t, dana, "org.repo.create", "org:acme"), integration.CodeAllowed)
	e.api.with(func() { e.api.org["members_can_create_repositories"] = false })
	itest.ExpectCode(t, e.check(t, bob, "org.repo.create", "org:acme"), integration.CodeDenied)
	itest.ExpectCode(t, e.check(t, dana, "org.repo.create", "org:acme"), integration.CodeAllowed)
	e.api.with(func() { delete(e.api.org, "members_can_create_repositories") })
	itest.ExpectCode(t, e.check(t, bob, "org.repo.create", "org:acme"), integration.CodeUnsupported)
	itest.ExpectCode(t, e.check(t, carol, "org.repo.create", "org:acme"), integration.CodeDenied)
	itest.ExpectCode(t, e.check(t, eve, "org.repo.create", "org:acme"), integration.CodeDenied)
}

func TestTeamNotFound(t *testing.T) {
	e := setup(t, nil)
	d := e.check(t, dana, "team.member", "team:acme/nope")
	itest.ExpectCode(t, d, integration.CodeResourceNotVisible)
	itest.ExpectCode(t, e.check(t, eve, "team.member", "team:acme/platform"), integration.CodeDenied)
	itest.ExpectCode(t, e.check(t, eve, "team.maintainer", "team:acme/platform"), integration.CodeDenied)
}

// --- failures, probe, canary ------------------------------------------------

func TestFailures(t *testing.T) {
	e := setup(t, nil)
	itest.ExpectCode(t, e.check(t, dana, "repo.read", "repo:acme/api"), integration.CodeAllowed)
	itest.FailureCases(t, e.srv, func() integration.Decision {
		return e.check(t, dana, "repo.read", "repo:acme/api")
	})
	// Also before any token exists: the failure hits the token exchange.
	e2 := setup(t, map[string]string{"identity_mode": "template"})
	itest.FailureCases(t, e2.srv, func() integration.Decision {
		return e2.check(t, dana, "repo.read", "repo:acme/api")
	})
}

func TestProbe(t *testing.T) {
	e := setup(t, nil)
	r, err := e.conn.Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r.Summary != "app hallpass-reader installed in acme" || len(r.Warnings) != 0 {
		t.Errorf("%+v", r)
	}
	e.api.with(func() {
		e.api.instPerms = map[string]string{"metadata": "read", "contents": "write", "administration": "admin"}
		e.api.saml = false
	})
	r, err = e.conn.Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(r.Warnings, "\n")
	for _, want := range []string{"members: read", "contents: write", "administration: admin", "no SAML identity provider"} {
		if !strings.Contains(joined, want) {
			t.Errorf("warnings lack %q:\n%s", want, joined)
		}
	}
	if len(r.Warnings) != 4 {
		t.Errorf("warnings: %v", r.Warnings)
	}
	e.api.with(func() {
		e.api.instPerms = map[string]string{"members": "read"}
		e.api.saml = true
	})
	r, _ = e.conn.Probe(context.Background())
	if len(r.Warnings) != 1 || !strings.Contains(r.Warnings[0], "metadata") {
		t.Errorf("warnings: %v", r.Warnings)
	}
	e3 := setup(t, map[string]string{"installation_id": "7"})
	r, _ = e3.conn.Probe(context.Background())
	if len(r.Warnings) != 1 || !strings.Contains(r.Warnings[0], "installation_id") {
		t.Errorf("warnings: %v", r.Warnings)
	}
	e.srv.Fail(itest.FailUnauthorized)
	if _, err := e.conn.Probe(context.Background()); err == nil {
		t.Error("probe succeeded on 401")
	}
	e.srv.Fail(itest.FailNone)
}

func TestNoSecretInDecisionsOrLogs(t *testing.T) {
	e := setup(t, nil)
	decisions := []integration.Decision{
		e.check(t, dana, "repo.read", "repo:acme/api"),
		e.check(t, dana, "repo.read", "repo:acme/secret"),
		e.check(t, carol, "repo.read", "repo:acme/api"),
	}
	e.srv.Fail(itest.FailUnauthorized)
	decisions = append(decisions, e.check(t, dana, "repo.read", "repo:acme/api"))
	e.srv.Fail(itest.FailNone)
	for _, d := range decisions {
		itest.AssertNoCanary(t, d.Text)
	}
	itest.AssertNoCanary(t, e.logs.String())
	if e.logs.String() == "" {
		t.Error("expected debug log lines from httpx")
	}
}

// --- per-action allow/deny (coverage gate) ---------------------------------

func TestAction_repo_read_allow(t *testing.T) {
	e := setup(t, nil)
	itest.ExpectCode(t, e.check(t, bob, "repo.read", "repo:acme/api"), integration.CodeAllowed)
}
func TestAction_repo_read_deny(t *testing.T) {
	e := setup(t, nil)
	expectText(t, e.check(t, carol, "repo.read", "repo:acme/api"), integration.CodeDenied, "does not include pull")
}
func TestAction_repo_triage_allow(t *testing.T) {
	e := setup(t, nil)
	itest.ExpectCode(t, e.check(t, dana, "repo.triage", "repo:acme/webapp"), integration.CodeAllowed)
}
func TestAction_repo_triage_deny(t *testing.T) {
	e := setup(t, nil)
	itest.ExpectCode(t, e.check(t, bob, "repo.triage", "repo:acme/api"), integration.CodeDenied)
}
func TestAction_repo_push_allow(t *testing.T) {
	e := setup(t, nil)
	itest.ExpectCode(t, e.check(t, dana, "repo.push", "repo:acme/webapp"), integration.CodeAllowed)
}
func TestAction_repo_push_deny(t *testing.T) {
	e := setup(t, nil)
	expectText(t, e.check(t, bob, "repo.push", "repo:acme/api"), integration.CodeDenied, "bob has read on acme/api")
}
func TestAction_repo_maintain_allow(t *testing.T) {
	e := setup(t, nil)
	itest.ExpectCode(t, e.check(t, dana, "repo.maintain", "repo:acme/api"), integration.CodeAllowed)
}
func TestAction_repo_maintain_deny(t *testing.T) {
	e := setup(t, nil)
	itest.ExpectCode(t, e.check(t, dana, "repo.maintain", "repo:acme/webapp"), integration.CodeDenied)
}
func TestAction_repo_admin_allow(t *testing.T) {
	e := setup(t, nil)
	itest.ExpectCode(t, e.check(t, dana, "repo.admin", "repo:acme/api"), integration.CodeAllowed)
}
func TestAction_repo_admin_deny(t *testing.T) {
	e := setup(t, nil)
	itest.ExpectCode(t, e.check(t, dana, "repo.admin", "repo:acme/webapp"), integration.CodeDenied)
}
func TestAction_issue_create_allow(t *testing.T) {
	e := setup(t, nil)
	expectText(t, e.check(t, bob, "issue.create", "repo:acme/api"), integration.CodeAllowed, "issues are enabled")
}
func TestAction_issue_create_deny(t *testing.T) {
	e := setup(t, nil)
	expectText(t, e.check(t, dana, "issue.create", "repo:acme/webapp"), integration.CodeDenied, "issues are disabled")
	itest.ExpectCode(t, e.check(t, carol, "issue.create", "repo:acme/api"), integration.CodeDenied)
}
func TestAction_pr_create_allow(t *testing.T) {
	e := setup(t, nil)
	expectText(t, e.check(t, bob, "pr.create", "repo:acme/api"), integration.CodeAllowed, "via fork; pushing a branch to the repository itself needs push")
	d := e.check(t, dana, "pr.create", "repo:acme/api")
	itest.ExpectCode(t, d, integration.CodeAllowed)
	if strings.Contains(d.Text, "via fork") {
		t.Errorf("admin should not be told to fork: %s", d.Text)
	}
}
func TestAction_pr_create_deny(t *testing.T) {
	e := setup(t, nil)
	itest.ExpectCode(t, e.check(t, carol, "pr.create", "repo:acme/api"), integration.CodeDenied)
}
func TestAction_pr_merge_allow(t *testing.T) {
	e := setup(t, nil)
	itest.ExpectCode(t, e.check(t, dana, "pr.merge", "repo:acme/webapp"), integration.CodeAllowed)
}
func TestAction_pr_merge_deny(t *testing.T) {
	e := setup(t, nil)
	itest.ExpectCode(t, e.check(t, bob, "pr.merge", "repo:acme/api"), integration.CodeDenied)
}
func TestAction_org_member_allow(t *testing.T) {
	e := setup(t, nil)
	itest.ExpectCode(t, e.check(t, bob, "org.member", "org:acme"), integration.CodeAllowed)
}
func TestAction_org_member_deny(t *testing.T) {
	e := setup(t, nil)
	expectText(t, e.check(t, carol, "org.member", "org:acme"), integration.CodeDenied, "not a member")
	expectText(t, e.check(t, eve, "org.member", "org:acme"), integration.CodeDenied, "pending")
}
func TestAction_org_admin_allow(t *testing.T) {
	e := setup(t, nil)
	itest.ExpectCode(t, e.check(t, dana, "org.admin", "org:acme"), integration.CodeAllowed)
}
func TestAction_org_admin_deny(t *testing.T) {
	e := setup(t, nil)
	itest.ExpectCode(t, e.check(t, bob, "org.admin", "org:acme"), integration.CodeDenied)
	itest.ExpectCode(t, e.check(t, carol, "org.admin", "org:acme"), integration.CodeDenied)
}
func TestAction_org_repo_create_allow(t *testing.T) {
	e := setup(t, nil)
	expectText(t, e.check(t, bob, "org.repo.create", "org:acme"), integration.CodeAllowed, "members may create repositories")
}
func TestAction_org_repo_create_deny(t *testing.T) {
	e := setup(t, nil)
	e.api.with(func() { e.api.org["members_can_create_repositories"] = false })
	expectText(t, e.check(t, bob, "org.repo.create", "org:acme"), integration.CodeDenied, "may not create repositories")
}
func TestAction_team_member_allow(t *testing.T) {
	e := setup(t, nil)
	itest.ExpectCode(t, e.check(t, bob, "team.member", "team:acme/platform"), integration.CodeAllowed)
}
func TestAction_team_member_deny(t *testing.T) {
	e := setup(t, nil)
	expectText(t, e.check(t, carol, "team.member", "team:acme/platform"), integration.CodeDenied, "not a member of team acme/platform")
}
func TestAction_team_maintainer_allow(t *testing.T) {
	e := setup(t, nil)
	itest.ExpectCode(t, e.check(t, dana, "team.maintainer", "team:acme/platform"), integration.CodeAllowed)
}
func TestAction_team_maintainer_deny(t *testing.T) {
	e := setup(t, nil)
	expectText(t, e.check(t, bob, "team.maintainer", "team:acme/platform"), integration.CodeDenied, "not a maintainer")
}
