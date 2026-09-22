package googleworkspace

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
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
	adminEmail = "hallpass-admin@example.com"
	saEmail    = "hallpass@proj.iam.gserviceaccount.com"
	fileA      = "1AbCdEfGhIjKlMnOpQrStUvWxYz"
	fileB      = "1BbCdEfGhIjKlMnOpQrStUvWxYz"
	fileNoCaps = "1CbCdEfGhIjKlMnOpQrStUvWxYz"
)

// fakeGoogle is an in-memory token endpoint plus the API subset hallpass uses.
type fakeGoogle struct {
	t   *testing.T
	key *rsa.PrivateKey
	kid string
	mu  sync.Mutex

	tokens       map[string]sourceKey // access token -> (sub, scope)
	minted       map[sourceKey]int    // per pair count
	badGrant     map[string]bool      // sub -> invalid_grant
	expire401    int                  // next n API calls answer 401
	metaCalls    int
	signCalls    int
	keylessIss   string
	users        map[string]fakeUser       // primary email -> user
	aliases      map[string]string         // alias -> primary
	files        map[string]map[string]any // file id -> fields visible to everyone in visible[]
	visible      map[string][]string       // file id -> users who can see it
	calendars    map[string]map[string]string
	sendAs       map[string][]map[string]any
	delegates    map[string][]map[string]string
	groupMembers map[string][]string // group -> members; missing group -> 404
	noIsMember   bool                // hasMember answers {} without isMember
}

// fakeUser is a Directory user as the fake serves it; a nil Suspended or
// Archived is left out of the body.
type fakeUser struct {
	ID, PrimaryEmail    string
	Suspended, Archived *bool
}

func ptr(b bool) *bool { return &b }

// testKey is generated once per package; the tests only need it to be a
// valid RSA key that the fake token endpoint can verify against.
var testKey = sync.OnceValues(func() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
})

func newFake(t *testing.T) *fakeGoogle {
	key, err := testKey()
	if err != nil {
		t.Fatal(err)
	}
	tr, fl := true, false
	return &fakeGoogle{t: t, key: key, kid: itest.Canary + "kid",
		tokens:   map[string]sourceKey{},
		minted:   map[sourceKey]int{},
		badGrant: map[string]bool{"nodelegation@example.com": true},
		users: map[string]fakeUser{
			"dana@example.com":         {ID: "100", PrimaryEmail: "dana@example.com", Suspended: ptr(false), Archived: ptr(false)},
			"bob@example.com":          {ID: "101", PrimaryEmail: "bob@example.com", Suspended: ptr(false), Archived: ptr(false)},
			"sus@example.com":          {ID: "102", PrimaryEmail: "sus@example.com", Suspended: ptr(true), Archived: ptr(false)},
			"arch@example.com":         {ID: "103", PrimaryEmail: "arch@example.com", Suspended: ptr(false), Archived: ptr(true)},
			"nodelegation@example.com": {ID: "104", PrimaryEmail: "nodelegation@example.com", Suspended: ptr(false), Archived: ptr(false)},
			// nostatus comes without suspended and archived.
			"nostatus@example.com": {ID: "105", PrimaryEmail: "nostatus@example.com"},
			// noarch has suspended but no archived.
			"noarch@example.com": {ID: "106", PrimaryEmail: "noarch@example.com", Suspended: ptr(false)},
		},
		aliases: map[string]string{"d.alias@example.com": "dana@example.com"},
		files: map[string]map[string]any{
			fileA:      {"capabilities": map[string]any{"canDownload": tr, "canEdit": tr, "canComment": tr, "canShare": tr, "canTrash": tr, "canDelete": tr, "canRename": tr, "canCopy": tr, "canAddChildren": tr, "canListChildren": tr}, "trashed": fl},
			fileB:      {"capabilities": map[string]any{"canDownload": fl, "canEdit": fl, "canComment": fl, "canShare": fl, "canTrash": fl, "canDelete": fl, "canRename": fl, "canCopy": fl, "canAddChildren": fl, "canListChildren": fl}, "trashed": tr},
			fileNoCaps: {"capabilities": map[string]any{}},
		},
		visible: map[string][]string{fileA: {"dana@example.com"}, fileB: {"dana@example.com", "bob@example.com"}, fileNoCaps: {"dana@example.com"}},
		calendars: map[string]map[string]string{
			"dana@example.com": {"team@group.calendar.google.com": "writer", "fb@example.com": "freeBusyReader", "ro@example.com": "reader", "wwpa@example.com": "writerWithoutPrivateAccess", "mine@example.com": "owner", "odd@example.com": "editor"},
		},
		sendAs: map[string][]map[string]any{
			// The primary entry carries no verificationStatus, like Gmail's
			// documented example; the others are custom "from" aliases.
			"dana@example.com": {
				{"sendAsEmail": "dana@example.com", "isPrimary": true, "isDefault": true},
				{"sendAsEmail": "support@example.com", "verificationStatus": "accepted"},
				{"sendAsEmail": "pending@example.com", "verificationStatus": "pending"},
				{"sendAsEmail": "unspec@example.com", "verificationStatus": "verificationStatusUnspecified", "treatAsAlias": true},
				{"sendAsEmail": "blank@example.com", "treatAsAlias": true},
			},
			// bob's list lacks the primary entry altogether.
			"bob@example.com": {{"sendAsEmail": "team@example.com", "verificationStatus": "accepted"}},
		},
		delegates: map[string][]map[string]string{
			"boss@example.com": {{"delegateEmail": "dana@example.com", "verificationStatus": "accepted"}, {"delegateEmail": "bob@example.com", "verificationStatus": "pending"}, {"delegateEmail": "nostatus@example.com", "verificationStatus": "verificationStatusUnspecified"}},
		},
		groupMembers: map[string][]string{"eng@example.com": {"dana@example.com"}},
	}
}

func (f *fakeGoogle) tokenURL(srv *itest.Server) string { return srv.URL + "/token" }

// token is the OAuth token endpoint: it verifies the JWT bearer assertion.
func (f *fakeGoogle) token(srv *itest.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		defer f.mu.Unlock()
		fail := func(code string) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"error":"` + code + `","error_description":"` + itest.Canary + `desc"}`))
		}
		if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
			fail("unsupported_grant_type")
			return
		}
		a := r.Form.Get("assertion")
		parts := strings.Split(a, ".")
		if len(parts) != 3 {
			fail("invalid_request")
			return
		}
		hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
		var hdr map[string]any
		_ = json.Unmarshal(hb, &hdr)
		if hdr["alg"] != "RS256" || hdr["typ"] != "JWT" || hdr["kid"] != f.kid {
			f.t.Errorf("assertion header %v", hdr)
			fail("invalid_request")
			return
		}
		sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
		if err := authx.Verify(&f.key.PublicKey, authx.RS256, []byte(parts[0]+"."+parts[1]), sig); err != nil {
			f.t.Errorf("assertion signature: %v", err)
			fail("invalid_grant")
			return
		}
		var cl claims
		_ = authx.DecodeJWTClaims(a, &cl)
		iss := saEmail
		if f.keylessIss != "" {
			iss = f.keylessIss
		}
		now := time.Now().Unix()
		if cl.Iss != iss || cl.Aud != f.tokenURL(srv) || cl.Sub == "" || cl.Scope == "" || strings.ContainsAny(cl.Scope, " ,") ||
			cl.Iat > now+5 || cl.Exp != cl.Iat+3600 {
			f.t.Errorf("assertion claims %+v", cl)
			fail("invalid_grant")
			return
		}
		if f.badGrant[cl.Sub] {
			fail("invalid_grant")
			return
		}
		k := sourceKey{cl.Sub, cl.Scope}
		f.minted[k]++
		tok := fmt.Sprintf("%s%s|%s|%d", itest.Canary, cl.Sub, cl.Scope, f.minted[k])
		f.tokens[tok] = k
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": tok, "expires_in": 3599, "token_type": "Bearer"})
	}
}

func apiErr(w http.ResponseWriter, status int, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(fmt.Sprintf(`{"error":{"code":%d,"message":"%smsg","errors":[{"domain":"global","reason":"%s"}]}}`, status, itest.Canary, reason)))
}

func write(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// api serves the Google APIs. Every handler checks that the token was
// minted for the expected sub and scope.
func (f *fakeGoogle) api(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.expire401 > 0 {
		f.expire401--
		apiErr(w, 401, "authError")
		return
	}
	k, ok := f.tokens[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
	if !ok {
		apiErr(w, 401, "authError")
		return
	}
	need := func(sub, scope string) bool {
		if k.sub != sub || k.scope != scope {
			f.t.Errorf("%s %s used token for %v, want (%s, %s)", r.Method, r.URL.Path, k, sub, scope)
			apiErr(w, 403, "insufficientPermissions")
			return false
		}
		return true
	}
	p := r.URL.Path
	q := r.URL.Query()
	switch {
	case p == "/admin/directory/v1/users":
		if !need(adminEmail, scopeDirectoryUser) {
			return
		}
		if q.Get("customer") != "my_customer" || q.Get("maxResults") != "1" {
			apiErr(w, 400, "invalid")
			return
		}
		write(w, map[string]any{"users": []map[string]any{{"primaryEmail": "dana@example.com", "id": "100"}}})
	case strings.HasPrefix(p, "/admin/directory/v1/users/"):
		if !need(adminEmail, scopeDirectoryUser) {
			return
		}
		if q.Get("projection") != "basic" || q.Get("viewType") != "admin_view" {
			f.t.Errorf("user lookup query %v", q)
		}
		email := strings.TrimPrefix(p, "/admin/directory/v1/users/")
		if primary, ok := f.aliases[email]; ok {
			email = primary
		}
		u, ok := f.users[email]
		if !ok {
			apiErr(w, 404, "notFound")
			return
		}
		body := map[string]any{"id": u.ID, "primaryEmail": u.PrimaryEmail, "name": map[string]any{"fullName": "Someone"}}
		if u.Suspended != nil {
			body["suspended"] = *u.Suspended
		}
		if u.Archived != nil {
			body["archived"] = *u.Archived
		}
		write(w, body)
	case strings.HasPrefix(p, "/admin/directory/v1/groups/"):
		if !need(adminEmail, scopeDirectoryGroup) {
			return
		}
		rest := strings.TrimPrefix(p, "/admin/directory/v1/groups/")
		group, member, ok := strings.Cut(rest, "/hasMember/")
		if !ok {
			apiErr(w, 404, "notFound")
			return
		}
		if group == "external@other.com" {
			apiErr(w, 400, "invalid")
			return
		}
		members, ok := f.groupMembers[group]
		if !ok {
			apiErr(w, 404, "notFound")
			return
		}
		if f.noIsMember {
			write(w, map[string]any{})
			return
		}
		is := false
		for _, m := range members {
			if m == member {
				is = true
			}
		}
		write(w, map[string]any{"isMember": is})
	case strings.HasPrefix(p, "/drive/v3/files/"):
		id := strings.TrimPrefix(p, "/drive/v3/files/")
		if !need(k.sub, scopeDrive) {
			return
		}
		if q.Get("supportsAllDrives") != "true" || !strings.HasPrefix(q.Get("fields"), "capabilities(") {
			f.t.Errorf("drive query %v", q)
		}
		seen := false
		for _, u := range f.visible[id] {
			if u == k.sub {
				seen = true
			}
		}
		if !seen {
			apiErr(w, 404, "notFound")
			return
		}
		write(w, f.files[id])
	case strings.HasPrefix(p, "/calendar/v3/users/me/calendarList/"):
		if !need(k.sub, scopeCalendar) {
			return
		}
		id := strings.TrimPrefix(p, "/calendar/v3/users/me/calendarList/")
		role, ok := f.calendars[k.sub][id]
		if !ok {
			apiErr(w, 404, "notFound")
			return
		}
		write(w, map[string]any{"id": id, "accessRole": role})
	case p == "/gmail/v1/users/me/settings/sendAs":
		if !need(k.sub, scopeGmailSettings) {
			return
		}
		write(w, map[string]any{"sendAs": f.sendAs[k.sub]})
	case p == "/gmail/v1/users/me/settings/delegates":
		if !need(k.sub, scopeGmailSettings) {
			return
		}
		write(w, map[string]any{"delegates": f.delegates[k.sub]})
	default:
		f.t.Errorf("fake google: no route for %s %s", r.Method, r.URL.String())
		apiErr(w, 404, "notFound")
	}
}

// keyless serves the metadata server and the IAM Credentials signJwt call.
func (f *fakeGoogle) keyless(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.URL.Path == "/computeMetadata/v1/instance/service-accounts/default/token":
		if r.Header.Get("Metadata-Flavor") != "Google" {
			w.WriteHeader(403)
			return
		}
		f.metaCalls++
		write(w, map[string]any{"access_token": itest.Canary + "meta", "expires_in": 3599, "token_type": "Bearer"})
	case r.URL.Path == "/v1/projects/-/serviceAccounts/"+saEmail+":signJwt":
		if r.Header.Get("Authorization") != "Bearer "+itest.Canary+"meta" {
			apiErr(w, 401, "authError")
			return
		}
		var body struct {
			Payload string `json:"payload"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		var cl claims
		if err := json.Unmarshal([]byte(body.Payload), &cl); err != nil || cl.Iss != saEmail {
			f.t.Errorf("signJwt payload %q: %v", body.Payload, err)
			apiErr(w, 400, "invalid")
			return
		}
		f.signCalls++
		jwt, err := authx.SignJWT(f.key, authx.Header{Alg: authx.RS256, Kid: f.kid}, []byte(body.Payload))
		if err != nil {
			f.t.Fatal(err)
		}
		write(w, map[string]any{"keyId": f.kid, "signedJwt": jwt})
	default:
		f.t.Errorf("fake keyless: no route for %s", r.URL.Path)
		w.WriteHeader(404)
	}
}

func (f *fakeGoogle) keyJSON(t *testing.T, srv *itest.Server) secret.Secret {
	t.Helper()
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustPKCS8(t, f.key)})
	b, err := json.Marshal(map[string]string{
		"type": "service_account", "project_id": "proj", "private_key_id": f.kid, "private_key": string(pemKey),
		"client_email": saEmail, "client_id": "123", "token_uri": f.tokenURL(srv),
	})
	if err != nil {
		t.Fatal(err)
	}
	return secret.Literal(string(b))
}

func mustPKCS8(t *testing.T, k *rsa.PrivateKey) []byte {
	t.Helper()
	b, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func setup(t *testing.T, values map[string]string) (*itest.Server, *fakeGoogle, integration.Connection) {
	t.Helper()
	srv := itest.NewServer(t)
	srv.UseSpec(itest.AnySpec(itest.SpecFromEnv(t, "google-directory"), itest.SpecFromEnv(t, "google-drive"), itest.SpecFromEnv(t, "google-calendar"), itest.SpecFromEnv(t, "google-gmail")), itest.SpecOptions{IgnorePaths: []string{`^/token$`, `/computeMetadata/`, `:signJwt$`}})
	f := newFake(t)
	srv.Handle("POST", "/token", f.token(srv))
	srv.Handle("", "/admin/*", f.api)
	srv.Handle("", "/drive/*", f.api)
	srv.Handle("", "/calendar/*", f.api)
	srv.Handle("", "/gmail/*", f.api)
	srv.Handle("", "/computeMetadata/*", f.keyless)
	srv.Handle("POST", "/v1/projects/*", f.keyless)
	deps, _ := itest.Deps(t, srv)
	v := map[string]string{"admin_email": adminEmail, "token_url": f.tokenURL(srv), "api_url": srv.URL, "metadata_url": srv.URL, "iamcredentials_url": srv.URL}
	for k, val := range values {
		v[k] = val
	}
	secrets := map[string]secret.Secret{}
	if v["auth_mode"] != modeKeyless {
		secrets["credential"] = f.keyJSON(t, srv)
	}
	s := itest.Settings("gws", "googleworkspace", v, secrets)
	c, err := Integration{}.New(context.Background(), s, deps)
	if err != nil {
		t.Fatal(err)
	}
	return srv, f, c
}

var (
	dana     = integration.User{Email: "dana@example.com"}
	bob      = integration.User{Email: "bob@example.com"}
	sus      = integration.User{Email: "sus@example.com"}
	arch     = integration.User{Email: "arch@example.com"}
	nod      = integration.User{Email: "nodelegation@example.com"}
	nostatus = integration.User{Email: "nostatus@example.com"}
	noarch   = integration.User{Email: "noarch@example.com"}
)

func check(t *testing.T, c integration.Connection, u integration.User, action, resource string) integration.Decision {
	t.Helper()
	return itest.Check(t, c, Integration{}, u, action, resource)
}

// --- authentication ---------------------------------------------------------

func TestTokenPerSubAndScopeCached(t *testing.T) {
	_, f, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, dana, "drive.file.read", "file:"+fileA), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, dana, "drive.file.edit", "file:"+fileA), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, dana, "calendar.read", "calendar:ro@example.com"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, bob, "drive.file.read", "file:"+fileB), integration.CodeAllowed)
	f.mu.Lock()
	defer f.mu.Unlock()
	want := map[sourceKey]int{
		{adminEmail, scopeDirectoryUser}:    1,
		{"dana@example.com", scopeDrive}:    1,
		{"dana@example.com", scopeCalendar}: 1,
		{"bob@example.com", scopeDrive}:     1,
	}
	if len(f.minted) != len(want) {
		t.Errorf("minted %v", f.minted)
	}
	for k, n := range want {
		if f.minted[k] != n {
			t.Errorf("minted %v %d times, want %d", k, f.minted[k], n)
		}
	}
}

func TestSourceCacheBounded(t *testing.T) {
	_, _, c := setup(t, nil)
	conn := c.(*Connection)
	for i := 0; i < maxSources+50; i++ {
		conn.source(fmt.Sprintf("u%d@example.com", i), scopeDrive)
	}
	if len(conn.sources) != maxSources || len(conn.order) != maxSources {
		t.Errorf("cache holds %d sources", len(conn.sources))
	}
	if _, ok := conn.sources[sourceKey{"u0@example.com", scopeDrive}]; ok {
		t.Error("oldest entry not evicted")
	}
}

func TestRetryOnceAfter401(t *testing.T) {
	_, f, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, dana, "drive.file.read", "file:"+fileA), integration.CodeAllowed)
	f.mu.Lock()
	f.expire401 = 1
	f.mu.Unlock()
	itest.ExpectCode(t, check(t, c, dana, "drive.file.read", "file:"+fileA), integration.CodeAllowed)
	f.mu.Lock()
	n := f.minted[sourceKey{adminEmail, scopeDirectoryUser}]
	f.expire401 = 10
	f.mu.Unlock()
	if n != 2 {
		t.Errorf("admin token minted %d times, want 2 (refreshed after 401)", n)
	}
	itest.ExpectCode(t, check(t, c, dana, "drive.file.read", "file:"+fileA), integration.CodeCredentialRejected)
}

func TestInvalidGrant(t *testing.T) {
	_, f, c := setup(t, nil)
	// A user hallpass may not impersonate: unknown, not deny.
	d := check(t, c, nod, "drive.file.read", "file:"+fileA)
	itest.ExpectCode(t, d, integration.CodeUnsupported)
	if !strings.Contains(d.Text, "could not act as the user") {
		t.Error(d.Text)
	}
	itest.AssertNoCanary(t, d.Text)
	// The admin: credential_rejected.
	f.mu.Lock()
	f.badGrant[adminEmail] = true
	f.mu.Unlock()
	c2 := setupWith(t, f, nil)
	d = check(t, c2, dana, "drive.file.read", "file:"+fileA)
	itest.ExpectCode(t, d, integration.CodeCredentialRejected)
	if !strings.Contains(d.Text, "domain-wide delegation") {
		t.Error(d.Text)
	}
}

// setupWith builds a second connection against an existing fake.
func setupWith(t *testing.T, f *fakeGoogle, values map[string]string) integration.Connection {
	t.Helper()
	srv := itest.NewServer(t)
	srv.UseSpec(itest.AnySpec(itest.SpecFromEnv(t, "google-directory"), itest.SpecFromEnv(t, "google-drive"), itest.SpecFromEnv(t, "google-calendar"), itest.SpecFromEnv(t, "google-gmail")), itest.SpecOptions{IgnorePaths: []string{`^/token$`, `/computeMetadata/`, `:signJwt$`}})
	srv.Handle("POST", "/token", f.token(srv))
	srv.Handle("", "/admin/*", f.api)
	srv.Handle("", "/drive/*", f.api)
	srv.Handle("", "/calendar/*", f.api)
	srv.Handle("", "/gmail/*", f.api)
	deps, _ := itest.Deps(t, srv)
	v := map[string]string{"admin_email": adminEmail, "token_url": f.tokenURL(srv), "api_url": srv.URL}
	for k, val := range values {
		v[k] = val
	}
	s := itest.Settings("gws2", "googleworkspace", v, map[string]secret.Secret{"credential": f.keyJSON(t, srv)})
	c, err := Integration{}.New(context.Background(), s, deps)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestKeyless(t *testing.T) {
	_, f, c := setup(t, map[string]string{"auth_mode": modeKeyless, "service_account_email": saEmail})
	f.mu.Lock()
	f.keylessIss = saEmail
	f.mu.Unlock()
	itest.ExpectCode(t, check(t, c, dana, "drive.file.read", "file:"+fileA), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, dana, "drive.file.edit", "file:"+fileA), integration.CodeAllowed)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.metaCalls != 1 {
		t.Errorf("metadata token fetched %d times, want 1 (cached)", f.metaCalls)
	}
	if f.signCalls != 2 {
		t.Errorf("signJwt called %d times, want 2 (admin + user, then cached)", f.signCalls)
	}
}

func TestBadKey(t *testing.T) {
	srv := itest.NewServer(t)
	srv.UseSpec(itest.AnySpec(itest.SpecFromEnv(t, "google-directory"), itest.SpecFromEnv(t, "google-drive"), itest.SpecFromEnv(t, "google-calendar"), itest.SpecFromEnv(t, "google-gmail")), itest.SpecOptions{IgnorePaths: []string{`^/token$`, `/computeMetadata/`, `:signJwt$`}})
	deps, _ := itest.Deps(t, srv)
	for _, cred := range []string{"not json", `{"client_email":"x@y.z"}`, `{"client_email":"x@y.z","private_key":"nope"}`} {
		s := itest.Settings("gws", "googleworkspace", map[string]string{"admin_email": adminEmail, "token_url": srv.URL + "/token", "api_url": srv.URL},
			map[string]secret.Secret{"credential": secret.Literal(itest.Canary + cred)})
		c, err := Integration{}.New(context.Background(), s, deps)
		if err != nil {
			t.Fatal(err)
		}
		d := check(t, c, dana, "drive.file.read", "file:"+fileA)
		itest.ExpectCode(t, d, integration.CodeCredentialRejected)
		itest.AssertNoCanary(t, d.Text)
	}
}

func TestNewValidation(t *testing.T) {
	srv := itest.NewServer(t)
	srv.UseSpec(itest.AnySpec(itest.SpecFromEnv(t, "google-directory"), itest.SpecFromEnv(t, "google-drive"), itest.SpecFromEnv(t, "google-calendar"), itest.SpecFromEnv(t, "google-gmail")), itest.SpecOptions{IgnorePaths: []string{`^/token$`, `/computeMetadata/`, `:signJwt$`}})
	deps, _ := itest.Deps(t, srv)
	cred := map[string]secret.Secret{"credential": itest.Literal("{}")}
	bad := []struct {
		v map[string]string
		s map[string]secret.Secret
	}{
		{map[string]string{}, cred},
		{map[string]string{"admin_email": "nope"}, cred},
		{map[string]string{"admin_email": adminEmail}, nil},
		{map[string]string{"admin_email": adminEmail, "auth_mode": "keyless"}, nil},
		{map[string]string{"admin_email": adminEmail, "auth_mode": "magic"}, cred},
		{map[string]string{"admin_email": adminEmail, "customer_id": "bad id"}, cred},
	}
	for _, b := range bad {
		s := itest.Settings("gws", "googleworkspace", b.v, b.s)
		if _, err := (Integration{}).New(context.Background(), s, deps); err == nil {
			t.Errorf("%v accepted", b.v)
		}
	}
	s := itest.Settings("gws", "googleworkspace", map[string]string{"admin_email": adminEmail}, cred)
	c, err := (Integration{}).New(context.Background(), s, deps)
	if err != nil {
		t.Fatal(err)
	}
	conn := c.(*Connection)
	if conn.api.Base != defaultAPI || conn.customer != "my_customer" || conn.mode != modeKey || conn.tokenURLFrom != "key" {
		t.Errorf("defaults: %+v", conn)
	}
	if err := integration.ValidateFields((Integration{}).Fields()); err != nil {
		t.Error(err)
	}
	if err := validateHTTPURL("http://metadata.google.internal"); err != nil {
		t.Error(err)
	}
	if err := validateHTTPURL("ftp://x"); err == nil {
		t.Error("ftp accepted")
	}
}

// --- identity ---------------------------------------------------------------

func TestResolveIdentity(t *testing.T) {
	srv, _, c := setup(t, nil)
	ctx := context.Background()
	id, err := c.ResolveIdentity(ctx, integration.User{Email: "Dana@Example.com"})
	if err != nil || id.ID != "dana@example.com" || id.Attr("suspended") != "false" || id.Attr("id") != "100" {
		t.Fatalf("%+v %v", id, err)
	}
	last := srv.LastCall()
	if last.Path != "/admin/directory/v1/users/dana@example.com" || last.Query.Get("viewType") != "admin_view" || last.Query.Get("projection") != "basic" {
		t.Errorf("%s %v", last.Path, last.Query)
	}
	id, err = c.ResolveIdentity(ctx, integration.User{Email: "d.alias@example.com"})
	if err != nil || id.ID != "dana@example.com" {
		t.Errorf("alias: %+v %v", id, err)
	}
	_, err = c.ResolveIdentity(ctx, integration.User{Email: "nobody@example.com"})
	itest.ExpectCode(t, integration.ToDecision(err), integration.CodeUserNotFound)
	_, err = c.ResolveIdentity(ctx, integration.User{Email: "not an email"})
	itest.ExpectCode(t, integration.ToDecision(err), integration.CodeInvalidRequest)
	id, err = c.ResolveIdentity(ctx, sus)
	if err != nil || id.Attr("suspended") != "true" {
		t.Errorf("suspended: %+v %v", id, err)
	}
	id, err = c.ResolveIdentity(ctx, arch)
	if err != nil || id.Attr("archived") != "true" {
		t.Errorf("archived: %+v %v", id, err)
	}
	id, err = c.ResolveIdentity(ctx, nostatus)
	if err != nil || id.Attr("suspended") != "unknown" || id.Attr("archived") != "unknown" {
		t.Errorf("no status fields: %+v %v", id, err)
	}
	srv.JSON("GET", "/admin/directory/v1/users/dana@example.com", 403, `{"error":{"code":403,"message":"`+itest.Canary+`","errors":[{"reason":"forbidden"}]}}`)
	_, err = c.ResolveIdentity(ctx, dana)
	itest.ExpectCode(t, integration.ToDecision(err), integration.CodeCredentialRejected)
}

func TestSuspendedAndArchivedDeny(t *testing.T) {
	_, _, c := setup(t, nil)
	d := check(t, c, sus, "drive.file.read", "file:"+fileA)
	itest.ExpectCode(t, d, integration.CodeDenied)
	if !strings.Contains(d.Text, "suspended") {
		t.Error(d.Text)
	}
	d = check(t, c, arch, "group.member", "group:eng@example.com")
	itest.ExpectCode(t, d, integration.CodeDenied)
	if !strings.Contains(d.Text, "archived") {
		t.Error(d.Text)
	}
}

// TestStatusFieldsAbsentUnknown: a user record without suspended or
// archived is not taken to be active.
func TestStatusFieldsAbsentUnknown(t *testing.T) {
	srv, _, c := setup(t, nil)
	for _, u := range []integration.User{nostatus, noarch} {
		for _, cs := range []struct{ action, resource string }{
			{"user.active", "user:" + u.Email},
			{"drive.file.read", "file:" + fileA},
			{"group.member", "group:eng@example.com"},
		} {
			srv.Reset()
			d := check(t, c, u, cs.action, cs.resource)
			itest.ExpectCode(t, d, integration.CodeUnsupported)
			if !strings.Contains(d.Text, "did not report") {
				t.Errorf("%s %s: %s", u.Email, cs.action, d.Text)
			}
			for _, call := range srv.Calls() {
				if !strings.HasPrefix(call.Path, "/admin/directory/v1/users/") && call.Path != "/token" {
					t.Errorf("%s %s: unexpected call %s", u.Email, cs.action, call.Path)
				}
			}
		}
	}
}

// --- actions ----------------------------------------------------------------

func TestAction_user_active_allow(t *testing.T) {
	_, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, dana, "user.active", "user:dana@example.com"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, integration.User{Email: "d.alias@example.com"}, "user.active", "user:d.alias@example.com"), integration.CodeAllowed)
}

func TestAction_user_active_deny(t *testing.T) {
	_, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, sus, "user.active", "user:sus@example.com"), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, arch, "user.active", "user:arch@example.com"), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, dana, "user.active", "user:bob@example.com"), integration.CodeUnsupported)
	itest.ExpectCode(t, check(t, c, nostatus, "user.active", "user:nostatus@example.com"), integration.CodeUnsupported)
}

func driveAllow(t *testing.T, action string) {
	t.Helper()
	srv, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, dana, action, "file:"+fileA), integration.CodeAllowed)
	if srv.LastCall().Path != "/drive/v3/files/"+fileA {
		t.Error(srv.LastCall().Path)
	}
}

func driveDeny(t *testing.T, action string) {
	t.Helper()
	_, _, c := setup(t, nil)
	// Capability false.
	itest.ExpectCode(t, check(t, c, bob, action, "file:"+fileB), integration.CodeDenied)
	// Not visible: 404 notFound is a deny.
	d := check(t, c, bob, action, "file:"+fileA)
	itest.ExpectCode(t, d, integration.CodeDenied)
	if !strings.Contains(d.Text, "does not distinguish") {
		t.Error(d.Text)
	}
	// Capability missing: unknown.
	if action != "drive.file.read" {
		itest.ExpectCode(t, check(t, c, dana, action, "file:"+fileNoCaps), integration.CodeUnsupported)
	}
}

func TestAction_drive_file_read_allow(t *testing.T) { driveAllow(t, "drive.file.read") }
func TestAction_drive_file_read_deny(t *testing.T) {
	_, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, bob, "drive.file.read", "file:"+fileA), integration.CodeDenied)
	// Visible with no capabilities is still readable.
	itest.ExpectCode(t, check(t, c, dana, "drive.file.read", "file:"+fileNoCaps), integration.CodeAllowed)
}
func TestAction_drive_file_download_allow(t *testing.T) { driveAllow(t, "drive.file.download") }
func TestAction_drive_file_download_deny(t *testing.T)  { driveDeny(t, "drive.file.download") }
func TestAction_drive_file_edit_allow(t *testing.T)     { driveAllow(t, "drive.file.edit") }
func TestAction_drive_file_edit_deny(t *testing.T)      { driveDeny(t, "drive.file.edit") }
func TestAction_drive_file_comment_allow(t *testing.T)  { driveAllow(t, "drive.file.comment") }
func TestAction_drive_file_comment_deny(t *testing.T)   { driveDeny(t, "drive.file.comment") }
func TestAction_drive_file_share_allow(t *testing.T)    { driveAllow(t, "drive.file.share") }
func TestAction_drive_file_share_deny(t *testing.T)     { driveDeny(t, "drive.file.share") }
func TestAction_drive_file_trash_allow(t *testing.T)    { driveAllow(t, "drive.file.trash") }
func TestAction_drive_file_trash_deny(t *testing.T)     { driveDeny(t, "drive.file.trash") }
func TestAction_drive_file_delete_allow(t *testing.T)   { driveAllow(t, "drive.file.delete") }
func TestAction_drive_file_delete_deny(t *testing.T)    { driveDeny(t, "drive.file.delete") }
func TestAction_drive_file_rename_allow(t *testing.T)   { driveAllow(t, "drive.file.rename") }
func TestAction_drive_file_rename_deny(t *testing.T)    { driveDeny(t, "drive.file.rename") }
func TestAction_drive_file_copy_allow(t *testing.T)     { driveAllow(t, "drive.file.copy") }
func TestAction_drive_file_copy_deny(t *testing.T)      { driveDeny(t, "drive.file.copy") }
func TestAction_drive_folder_add_child_allow(t *testing.T) {
	driveAllow(t, "drive.folder.add_child")
}
func TestAction_drive_folder_add_child_deny(t *testing.T) { driveDeny(t, "drive.folder.add_child") }
func TestAction_drive_folder_list_allow(t *testing.T)     { driveAllow(t, "drive.folder.list") }
func TestAction_drive_folder_list_deny(t *testing.T)      { driveDeny(t, "drive.folder.list") }

// TestDriveNotFoundOtherReason: only a 404 whose reason is notFound is a
// deny; any other 404 is resource_not_visible.
func TestDriveNotFoundOtherReason(t *testing.T) {
	srv, _, c := setup(t, nil)
	for _, body := range []string{
		`{"error":{"code":404,"message":"` + itest.Canary + `msg","errors":[{"domain":"global","reason":"fileNotFound"}]}}`,
		`{"error":{"code":404,"message":"` + itest.Canary + `msg"}}`,
		`not json`,
	} {
		srv.JSON("GET", "/drive/v3/files/"+fileA, 404, body)
		for _, action := range []string{"drive.file.read", "drive.file.edit"} {
			d := check(t, c, dana, action, "file:"+fileA)
			itest.ExpectCode(t, d, integration.CodeResourceNotVisible)
			itest.AssertNoCanary(t, d.Text)
		}
	}
	srv.JSON("GET", "/drive/v3/files/"+fileA, 404, `{"error":{"code":404,"message":"`+itest.Canary+`msg","errors":[{"domain":"global","reason":"notFound"}]}}`)
	itest.ExpectCode(t, check(t, c, dana, "drive.file.read", "file:"+fileA), integration.CodeDenied)
}

func TestDriveTrashedMentioned(t *testing.T) {
	_, _, c := setup(t, nil)
	d := check(t, c, dana, "drive.file.read", "file:"+fileB)
	itest.ExpectCode(t, d, integration.CodeAllowed)
	if !strings.Contains(d.Text, "trash") {
		t.Error(d.Text)
	}
}

func TestAction_calendar_read_allow(t *testing.T) {
	srv, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, dana, "calendar.read", "calendar:ro@example.com"), integration.CodeAllowed)
	if srv.LastCall().Path != "/calendar/v3/users/me/calendarList/ro@example.com" {
		t.Error(srv.LastCall().Path)
	}
	itest.ExpectCode(t, check(t, c, dana, "calendar.read", "calendar:team@group.calendar.google.com"), integration.CodeAllowed)
	// primary and the user's own email need no call.
	srv.Reset()
	itest.ExpectCode(t, check(t, c, dana, "calendar.read", "calendar:primary"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, dana, "calendar.share", "calendar:Dana@example.com"), integration.CodeAllowed)
	for _, call := range srv.Calls() {
		if strings.HasPrefix(call.Path, "/calendar/") {
			t.Errorf("unexpected calendar call %s", call.Path)
		}
	}
}

func TestAction_calendar_read_deny(t *testing.T) {
	_, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, dana, "calendar.read", "calendar:fb@example.com"), integration.CodeDenied)
	// Not in the list: unknown, ACLs may still grant access.
	d := check(t, c, dana, "calendar.read", "calendar:unknown@example.com")
	itest.ExpectCode(t, d, integration.CodeUnsupported)
	if !strings.Contains(d.Text, "ACL") {
		t.Error(d.Text)
	}
	itest.ExpectCode(t, check(t, c, dana, "calendar.read", "calendar:odd@example.com"), integration.CodeUnsupported)
}

func TestAction_calendar_event_write_allow(t *testing.T) {
	_, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, dana, "calendar.event.write", "calendar:wwpa@example.com"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, dana, "calendar.event.write", "calendar:team@group.calendar.google.com"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, dana, "calendar.event.write", "calendar:mine@example.com"), integration.CodeAllowed)
}

func TestAction_calendar_event_write_deny(t *testing.T) {
	_, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, dana, "calendar.event.write", "calendar:ro@example.com"), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, dana, "calendar.event.write", "calendar:fb@example.com"), integration.CodeDenied)
}

func TestAction_calendar_share_allow(t *testing.T) {
	_, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, dana, "calendar.share", "calendar:mine@example.com"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, dana, "calendar.share", "calendar:primary"), integration.CodeAllowed)
}

func TestAction_calendar_share_deny(t *testing.T) {
	_, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, dana, "calendar.share", "calendar:team@group.calendar.google.com"), integration.CodeDenied)
}

// gmailToken returns the (sub, scope) the last Gmail call was made with.
func gmailToken(t *testing.T, srv *itest.Server, f *fakeGoogle) sourceKey {
	t.Helper()
	last := srv.LastCall()
	if !strings.HasPrefix(last.Path, "/gmail/v1/users/me/settings/") {
		t.Fatalf("last call %s is not a Gmail settings call", last.Path)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tokens[strings.TrimPrefix(last.Header.Get("Authorization"), "Bearer ")]
}

func TestAction_mail_send_as_allow(t *testing.T) {
	srv, f, c := setup(t, map[string]string{"enable_gmail_settings": "true"})
	// The own mailbox is answered by the isPrimary entry of sendAs.list,
	// read as the user, never without a Gmail call.
	srv.Reset()
	d := check(t, c, dana, "mail.send_as", "mailbox:Dana@example.com")
	itest.ExpectCode(t, d, integration.CodeAllowed)
	if !strings.Contains(d.Text, "primary") {
		t.Error(d.Text)
	}
	if k := gmailToken(t, srv, f); k.sub != "dana@example.com" || k.scope != scopeGmailSettings {
		t.Errorf("sendAs read as %v, want the user", k)
	}
	if srv.LastCall().Path != "/gmail/v1/users/me/settings/sendAs" {
		t.Error(srv.LastCall().Path)
	}
	itest.ExpectCode(t, check(t, c, dana, "mail.send_as", "mailbox:support@example.com"), integration.CodeAllowed)
}

func TestAction_mail_send_as_deny(t *testing.T) {
	_, _, c := setup(t, map[string]string{"enable_gmail_settings": "true"})
	itest.ExpectCode(t, check(t, c, dana, "mail.send_as", "mailbox:other@example.com"), integration.CodeDenied)
	d := check(t, c, dana, "mail.send_as", "mailbox:pending@example.com")
	itest.ExpectCode(t, d, integration.CodeDenied)
	if !strings.Contains(d.Text, "awaiting verification") {
		t.Error(d.Text)
	}
	itest.ExpectCode(t, check(t, c, sus, "mail.send_as", "mailbox:sus@example.com"), integration.CodeDenied)
	// Feature off: unknown, for another address and for the own mailbox.
	srv2, _, c2 := setup(t, nil)
	for _, mailbox := range []string{"mailbox:support@example.com", "mailbox:dana@example.com"} {
		d := check(t, c2, dana, "mail.send_as", mailbox)
		itest.ExpectCode(t, d, integration.CodeUnsupported)
		if !strings.Contains(d.Text, "enable_gmail_settings") {
			t.Error(d.Text)
		}
	}
	for _, call := range srv2.Calls() {
		if strings.HasPrefix(call.Path, "/gmail/") {
			t.Errorf("gmail called with the feature off: %s", call.Path)
		}
	}
}

// TestSendAsVerificationStatus: only accepted (or the primary entry) allows;
// pending denies; an absent or unspecified status is unknown even when the
// alias is treatAsAlias in the same domain.
func TestSendAsVerificationStatus(t *testing.T) {
	srv, _, c := setup(t, map[string]string{"enable_gmail_settings": "true"})
	for _, mailbox := range []string{"mailbox:unspec@example.com", "mailbox:blank@example.com"} {
		d := check(t, c, dana, "mail.send_as", mailbox)
		itest.ExpectCode(t, d, integration.CodeUnsupported)
		if !strings.Contains(d.Text, "without a verification status") {
			t.Error(d.Text)
		}
	}
	// The own primary address missing from the list: unknown, not allow.
	d := check(t, c, bob, "mail.send_as", "mailbox:bob@example.com")
	itest.ExpectCode(t, d, integration.CodeUnsupported)
	if !strings.Contains(d.Text, "primary") {
		t.Error(d.Text)
	}
	// Gmail refusals as the user: no mailbox or a user-level policy is
	// unknown; hallpass's own scope or API enablement is credential_rejected.
	for _, cs := range []struct {
		status int
		reason string
		code   integration.Code
	}{
		{404, "notFound", integration.CodeUnsupported},
		{400, "failedPrecondition", integration.CodeUnsupported},
		{403, "domainPolicy", integration.CodeUnsupported},
		{403, "forbidden", integration.CodeUnsupported},
		{403, "insufficientPermissions", integration.CodeCredentialRejected},
		{403, "accessNotConfigured", integration.CodeCredentialRejected},
		{403, "userRateLimitExceeded", integration.CodeUpstreamRateLimit},
	} {
		srv.Handle("GET", "/gmail/v1/users/me/settings/sendAs", func(w http.ResponseWriter, r *http.Request) { apiErr(w, cs.status, cs.reason) })
		for _, mailbox := range []string{"mailbox:dana@example.com", "mailbox:support@example.com"} {
			d := check(t, c, dana, "mail.send_as", mailbox)
			itest.ExpectCode(t, d, cs.code)
			itest.AssertNoCanary(t, d.Text)
		}
	}
}

func TestAction_mail_delegate_access_allow(t *testing.T) {
	srv, f, c := setup(t, map[string]string{"enable_gmail_settings": "true"})
	itest.ExpectCode(t, check(t, c, dana, "mail.delegate_access", "mailbox:boss@example.com"), integration.CodeAllowed)
	last := srv.LastCall()
	if last.Path != "/gmail/v1/users/me/settings/delegates" {
		t.Error(last.Path)
	}
	f.mu.Lock()
	k := f.tokens[strings.TrimPrefix(last.Header.Get("Authorization"), "Bearer ")]
	f.mu.Unlock()
	if k.sub != "boss@example.com" || k.scope != scopeGmailSettings {
		t.Errorf("delegates read as %v, want the mailbox owner", k)
	}
	// The own mailbox is allowed only after Gmail answered as the user.
	srv.Reset()
	itest.ExpectCode(t, check(t, c, dana, "mail.delegate_access", "mailbox:dana@example.com"), integration.CodeAllowed)
	if k := gmailToken(t, srv, f); k.sub != "dana@example.com" || k.scope != scopeGmailSettings {
		t.Errorf("own mailbox read as %v, want the user", k)
	}
}

func TestAction_mail_delegate_access_deny(t *testing.T) {
	srv, _, c := setup(t, map[string]string{"enable_gmail_settings": "true"})
	itest.ExpectCode(t, check(t, c, bob, "mail.delegate_access", "mailbox:boss@example.com"), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, dana, "mail.delegate_access", "mailbox:bob@example.com"), integration.CodeDenied)
	// An unspecified verification status is not a deny.
	itest.ExpectCode(t, check(t, c, nostatus, "mail.delegate_access", "mailbox:boss@example.com"), integration.CodeUnsupported)
	// Mailbox hallpass cannot impersonate: unknown.
	itest.ExpectCode(t, check(t, c, dana, "mail.delegate_access", "mailbox:nodelegation@example.com"), integration.CodeUnsupported)
	// Gmail refuses the call as the user: unknown, including the own mailbox.
	for _, cs := range []struct {
		status int
		reason string
		code   integration.Code
	}{
		{404, "notFound", integration.CodeUnsupported},
		{403, "domainPolicy", integration.CodeUnsupported},
		{403, "insufficientPermissions", integration.CodeCredentialRejected},
	} {
		srv.Handle("GET", "/gmail/v1/users/me/settings/delegates", func(w http.ResponseWriter, r *http.Request) { apiErr(w, cs.status, cs.reason) })
		for _, mailbox := range []string{"mailbox:dana@example.com", "mailbox:boss@example.com"} {
			d := check(t, c, dana, "mail.delegate_access", mailbox)
			itest.ExpectCode(t, d, cs.code)
			itest.AssertNoCanary(t, d.Text)
		}
	}
	// Feature off: unknown, for another mailbox and for the own one.
	srv2, _, c2 := setup(t, nil)
	itest.ExpectCode(t, check(t, c2, dana, "mail.delegate_access", "mailbox:boss@example.com"), integration.CodeUnsupported)
	itest.ExpectCode(t, check(t, c2, dana, "mail.delegate_access", "mailbox:dana@example.com"), integration.CodeUnsupported)
	for _, call := range srv2.Calls() {
		if strings.HasPrefix(call.Path, "/gmail/") {
			t.Errorf("gmail called with the feature off: %s", call.Path)
		}
	}
}

func TestAction_group_member_allow(t *testing.T) {
	srv, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, dana, "group.member", "group:Eng@example.com"), integration.CodeAllowed)
	if srv.LastCall().Path != "/admin/directory/v1/groups/eng@example.com/hasMember/dana@example.com" {
		t.Error(srv.LastCall().Path)
	}
}

func TestAction_group_member_deny(t *testing.T) {
	_, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, bob, "group.member", "group:eng@example.com"), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, bob, "group.member", "group:missing@example.com"), integration.CodeUnsupported)
	itest.ExpectCode(t, check(t, c, bob, "group.member", "group:external@other.com"), integration.CodeUnsupported)
}

// TestGroupMemberUnreported: a hasMember body without isMember is unknown.
func TestGroupMemberUnreported(t *testing.T) {
	_, f, c := setup(t, nil)
	f.mu.Lock()
	f.noIsMember = true
	f.mu.Unlock()
	d := check(t, c, dana, "group.member", "group:eng@example.com")
	itest.ExpectCode(t, d, integration.CodeUnsupported)
	if !strings.Contains(d.Text, "did not report") {
		t.Error(d.Text)
	}
}

// --- resources and errors ---------------------------------------------------

func TestBadResources(t *testing.T) {
	_, _, c := setup(t, nil)
	cases := []struct{ action, resource string }{
		{"drive.file.read", "file:short"},
		{"drive.file.read", "file:has/slash/" + fileA},
		{"drive.file.read", "calendar:" + fileA},
		{"calendar.read", "calendar:bad calendar"},
		{"calendar.read", "calendar:x?y=1"},
		{"group.member", "group:not-an-email"},
		{"mail.send_as", "user:dana@example.com"},
		{"user.active", "mailbox:dana@example.com"},
	}
	for _, cs := range cases {
		d := check(t, c, dana, cs.action, cs.resource)
		if d.Code != integration.CodeInvalidRequest {
			t.Errorf("%s %s -> %s: %s", cs.action, cs.resource, d.Code, d.Text)
		}
	}
}

func TestErrorClassification(t *testing.T) {
	srv, _, c := setup(t, nil)
	for _, cs := range []struct {
		reason string
		code   integration.Code
	}{
		{"userRateLimitExceeded", integration.CodeUpstreamRateLimit},
		{"rateLimitExceeded", integration.CodeUpstreamRateLimit},
		{"insufficientPermissions", integration.CodeCredentialRejected},
		{"accessNotConfigured", integration.CodeCredentialRejected},
		{"forbidden", integration.CodeCredentialRejected},
		{"somethingElse", integration.CodeCredentialRejected},
		// About the user or the file, not hallpass's credential.
		{"insufficientFilePermissions", integration.CodeUnsupported},
		{"domainPolicy", integration.CodeUnsupported},
		{"cannotDownloadAbusiveFile", integration.CodeUnsupported},
	} {
		srv.Handle("GET", "/drive/v3/files/"+fileA, func(w http.ResponseWriter, r *http.Request) { apiErr(w, 403, cs.reason) })
		d := check(t, c, dana, "drive.file.edit", "file:"+fileA)
		itest.ExpectCode(t, d, cs.code)
		itest.AssertNoCanary(t, d.Text)
		if cs.code == integration.CodeUnsupported && !strings.Contains(d.Text, cs.reason) {
			t.Errorf("%s: %s", cs.reason, d.Text)
		}
	}
	// A 403 with no reason at all is hallpass's problem.
	srv.JSON("GET", "/drive/v3/files/"+fileA, 403, `{"error":{"code":403,"message":"`+itest.Canary+`"}}`)
	itest.ExpectCode(t, check(t, c, dana, "drive.file.edit", "file:"+fileA), integration.CodeCredentialRejected)
}

func TestFailures(t *testing.T) {
	srv, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, dana, "drive.file.read", "file:"+fileA), integration.CodeAllowed)
	itest.FailureCases(t, srv, func() integration.Decision {
		return check(t, c, dana, "drive.file.read", "file:"+fileA)
	})
}

func TestFailuresAtTokenEndpoint(t *testing.T) {
	srv, _, c := setup(t, nil)
	itest.FailureCases(t, srv, func() integration.Decision {
		return check(t, c, dana, "group.member", "group:eng@example.com")
	})
}

// --- probe ------------------------------------------------------------------

func TestProbe(t *testing.T) {
	srv, f, c := setup(t, nil)
	r, err := c.Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.Summary, saEmail) || !strings.Contains(r.Summary, adminEmail) {
		t.Error(r.Summary)
	}
	joined := strings.Join(r.Warnings, "\n")
	if strings.Contains(joined, "could not be minted") || strings.Contains(joined, "gmail.settings.basic") || !strings.Contains(joined, "domain-wide delegation") {
		t.Errorf("warnings: %q", joined)
	}
	found := false
	for _, call := range srv.Calls() {
		if call.Path == "/admin/directory/v1/users" && call.Query.Get("customer") == "my_customer" {
			found = true
		}
	}
	if !found {
		t.Error("probe did not list users")
	}
	f.mu.Lock()
	for _, sc := range []string{scopeDirectoryGroup, scopeDrive, scopeCalendar} {
		if f.minted[sourceKey{adminEmail, sc}] != 1 {
			t.Errorf("probe did not mint %s as the admin", sc)
		}
	}
	f.mu.Unlock()

	// Gmail on: warns about the write-capable scope.
	_, _, c2 := setup(t, map[string]string{"enable_gmail_settings": "true"})
	r, _ = c2.Probe(context.Background())
	if !strings.Contains(strings.Join(r.Warnings, "\n"), "gmail.settings.basic") {
		t.Errorf("warnings: %v", r.Warnings)
	}
}

func TestProbeScopeMissing(t *testing.T) {
	srv, f, c := setup(t, nil)
	// Drive scope not delegated: the token endpoint refuses that scope.
	orig := f.token(srv)
	srv.Handle("POST", "/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		var cl claims
		_ = authx.DecodeJWTClaims(r.Form.Get("assertion"), &cl)
		if cl.Scope == scopeDrive {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"` + itest.Canary + `x"}`))
			return
		}
		orig(w, r)
	})
	r, err := c.Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(r.Warnings, "\n")
	if !strings.Contains(joined, scopeDrive) || !strings.Contains(joined, "allowlist") {
		t.Errorf("warnings: %q", joined)
	}
	itest.AssertNoCanary(t, joined)

	// Admin delegation broken: probe fails with credential_rejected.
	f.mu.Lock()
	f.badGrant[adminEmail] = true
	f.mu.Unlock()
	c2 := setupWith(t, f, nil)
	_, err = c2.Probe(context.Background())
	itest.ExpectCode(t, integration.ToDecision(err), integration.CodeCredentialRejected)
}

func TestActionsListed(t *testing.T) {
	for _, a := range actionList {
		if _, ok := integration.FindAction(Integration{}, a.name); !ok {
			t.Errorf("%s not found", a.name)
		}
	}
	if len((Integration{}).Actions()) != 18 {
		t.Errorf("%d actions", len((Integration{}).Actions()))
	}
}
