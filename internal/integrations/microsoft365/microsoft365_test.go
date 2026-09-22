package microsoft365

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
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
	tenantID = "11111111-1111-1111-1111-111111111111"
	clientID = "22222222-2222-2222-2222-222222222222"
	danaID   = "aaaaaaaa-0000-0000-0000-000000000001"
	bobID    = "aaaaaaaa-0000-0000-0000-000000000002"
	guestID  = "aaaaaaaa-0000-0000-0000-000000000003"
	offID    = "aaaaaaaa-0000-0000-0000-000000000004"
	groupA   = "bbbbbbbb-0000-0000-0000-000000000001"
	groupB   = "bbbbbbbb-0000-0000-0000-000000000002"
	roleA    = "cccccccc-0000-0000-0000-000000000001"
	teamA    = "dddddddd-0000-0000-0000-000000000001"
	chanStd  = "19:std@thread.tacv2"
	chanPriv = "19:priv@thread.tacv2"
	chanShr  = "19:shared@thread.tacv2"
	chanMod  = "19:mod@thread.tacv2"
	drive    = "b!drive1"
	graphSP  = "eeeeeeee-0000-0000-0000-000000000001"
	ownSP    = "eeeeeeee-0000-0000-0000-000000000002"
)

// fakeGraph is an in-memory Graph.
type fakeGraph struct {
	t   *testing.T
	mu  sync.Mutex
	tok string // current valid access token; "" means every token is invalid
	// tokensIssued counts token endpoint calls.
	tokensIssued int
	// expire401 makes the next n Graph calls answer 401.
	expire401 int

	users    map[string]graphUser // by id
	byUPN    map[string]string    // upn -> id
	byMail   map[string]string    // mail -> id
	byProxy  map[string][]string  // smtp:addr -> ids
	groups   map[string][]string  // user id -> group ids
	roles    map[string][]string  // user id -> role template ids
	teams    map[string]map[string][]string
	channels map[string]channelDef
	perms    map[string][]drivePermission // item -> permissions
	owner    string                       // drive owner user id
	appRoles []string                     // granted app role values
	spDenied bool
}

type channelDef struct {
	membershipType string
	moderation     string
	members        map[string][]string
}

func newFake(t *testing.T) *fakeGraph {
	enabled, disabled := true, false
	f := &fakeGraph{t: t,
		users: map[string]graphUser{
			danaID:  {ID: danaID, UserPrincipalName: "dana@example.com", Mail: "dana@example.com", AccountEnabled: &enabled, UserType: "Member", DisplayName: "Dana"},
			bobID:   {ID: bobID, UserPrincipalName: "bob@example.com", Mail: "bob@example.com", AccountEnabled: &enabled, UserType: "Member", DisplayName: "Bob"},
			guestID: {ID: guestID, UserPrincipalName: "guest_gmail.com#EXT#@example.onmicrosoft.com", Mail: "guest@gmail.com", AccountEnabled: &enabled, UserType: "Guest", DisplayName: "Guest"},
			offID:   {ID: offID, UserPrincipalName: "off@example.com", Mail: "off@example.com", AccountEnabled: &disabled, UserType: "Member", DisplayName: "Off"},
		},
		byUPN:   map[string]string{"dana@example.com": danaID, "bob@example.com": bobID, "guest_gmail.com#EXT#@example.onmicrosoft.com": guestID, "off@example.com": offID},
		byMail:  map[string]string{"guest@gmail.com": guestID, "dana.alias@example.com": danaID},
		byProxy: map[string][]string{"smtp:dana.old@example.com": {danaID}, "smtp:shared@example.com": {danaID, bobID}},
		groups:  map[string][]string{danaID: {groupA}},
		roles:   map[string][]string{danaID: {roleA}},
		teams:   map[string]map[string][]string{teamA: {danaID: {"owner"}, bobID: {}}},
		channels: map[string]channelDef{
			chanStd:  {membershipType: "standard"},
			chanPriv: {membershipType: "private", members: map[string][]string{danaID: {}}},
			chanShr:  {membershipType: "shared", members: map[string][]string{danaID: {"owner"}}},
			chanMod:  {membershipType: "standard", moderation: "moderators"},
		},
		perms:    map[string][]drivePermission{},
		appRoles: []string{"User.Read.All", "GroupMember.Read.All", "TeamMember.Read.All", "ChannelMember.Read.All", "Files.Read.All"},
	}
	return f
}

func (f *fakeGraph) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path != "/"+tenantID+"/oauth2/v2.0/token" || r.Form.Get("grant_type") != "client_credentials" || r.Form.Get("client_id") != clientID {
		w.WriteHeader(400)
		_, _ = w.Write([]byte(`{"error":"invalid_request","error_description":"` + itest.Canary + `bad request"}`))
		return
	}
	if r.Form.Get("client_secret") != itest.Canary+"secret" {
		w.WriteHeader(401)
		_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"` + itest.Canary + `bad secret"}`))
		return
	}
	f.tokensIssued++
	f.tok = fmt.Sprintf("%stok%d", itest.Canary, f.tokensIssued)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"access_token": f.tok, "token_type": "Bearer", "expires_in": 3599})
}

func graphErr(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"error":{"code":"` + code + `","message":"` + itest.Canary + `upstream message"}}`))
}

func write(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (f *fakeGraph) userJSON(u graphUser) map[string]any {
	return map[string]any{"id": u.ID, "userPrincipalName": u.UserPrincipalName, "mail": u.Mail, "accountEnabled": *u.AccountEnabled, "userType": u.UserType, "displayName": u.DisplayName}
}

func (f *fakeGraph) memberList(members map[string][]string, userID string) []map[string]any {
	out := []map[string]any{}
	if roles, ok := members[userID]; ok {
		out = append(out, map[string]any{"@odata.type": "#microsoft.graph.aadUserConversationMember", "userId": userID, "roles": roles})
	}
	return out
}

// filterUser extracts the user id from the members $filter.
func filterUser(t *testing.T, r *http.Request) string {
	fl := r.URL.Query().Get("$filter")
	const want = "(microsoft.graph.aadUserConversationMember/userId eq '"
	if !strings.HasPrefix(fl, want) || !strings.HasSuffix(fl, "')") {
		t.Errorf("unexpected members filter %q", fl)
		return ""
	}
	return strings.TrimSuffix(strings.TrimPrefix(fl, want), "')")
}

func (f *fakeGraph) graph(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.expire401 > 0 || f.tok == "" || r.Header.Get("Authorization") != "Bearer "+f.tok {
		if f.expire401 > 0 {
			f.expire401--
		}
		graphErr(w, 401, "InvalidAuthenticationToken")
		return
	}
	p := strings.TrimPrefix(r.URL.Path, "/v1.0/")
	seg := strings.Split(p, "/")
	q := r.URL.Query()
	switch {
	case p == "organization":
		write(w, map[string]any{"value": []map[string]any{{"id": tenantID, "displayName": "Example Ltd"}}})
	case p == "users" && q.Get("$filter") != "":
		if q.Get("$select") != userSelect {
			f.t.Errorf("users filter without select: %v", q)
		}
		fl := q.Get("$filter")
		var ids []string
		switch {
		case strings.HasPrefix(fl, "mail eq '"):
			addr := strings.TrimSuffix(strings.TrimPrefix(fl, "mail eq '"), "'")
			if id, ok := f.byMail[strings.ReplaceAll(addr, "''", "'")]; ok {
				ids = []string{id}
			}
		case strings.HasPrefix(fl, "proxyAddresses/any(p:p eq '"):
			if r.Header.Get("ConsistencyLevel") != "eventual" || q.Get("$count") != "true" {
				f.t.Errorf("proxyAddresses query needs ConsistencyLevel eventual and $count=true: %v %v", r.Header, q)
			}
			addr := strings.TrimSuffix(strings.TrimPrefix(fl, "proxyAddresses/any(p:p eq '"), "')")
			ids = f.byProxy[addr]
		default:
			graphErr(w, 400, "Request_UnsupportedQuery")
			return
		}
		out := []map[string]any{}
		for _, id := range ids {
			out = append(out, f.userJSON(f.users[id]))
		}
		write(w, map[string]any{"value": out})
	case seg[0] == "users" && len(seg) == 2:
		key := seg[1]
		id := key
		if _, ok := f.users[id]; !ok {
			id = f.byUPN[key]
		}
		u, ok := f.users[id]
		if !ok {
			graphErr(w, 404, "Request_ResourceNotFound")
			return
		}
		if q.Get("$select") != userSelect {
			f.t.Errorf("user lookup without select: %v", q)
		}
		write(w, f.userJSON(u))
	case seg[0] == "users" && len(seg) == 3 && seg[2] == "checkMemberGroups":
		var body struct {
			GroupIDs []string `json:"groupIds"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if len(body.GroupIDs) > 20 {
			graphErr(w, 400, "Request_BadRequest")
			return
		}
		if _, ok := f.users[seg[1]]; !ok {
			graphErr(w, 404, "Request_ResourceNotFound")
			return
		}
		out := []string{}
		for _, g := range body.GroupIDs {
			for _, have := range f.groups[seg[1]] {
				if strings.EqualFold(g, have) {
					out = append(out, have)
				}
			}
		}
		write(w, map[string]any{"value": out})
	case seg[0] == "users" && len(seg) == 4 && seg[2] == "transitiveMemberOf" && seg[3] == "microsoft.graph.directoryRole":
		if q.Get("$select") != "roleTemplateId" {
			f.t.Errorf("roles without select: %v", q)
		}
		if f.spDenied {
			graphErr(w, 403, "Authorization_RequestDenied")
			return
		}
		out := []map[string]any{}
		for _, id := range f.roles[seg[1]] {
			out = append(out, map[string]any{"roleTemplateId": id})
		}
		write(w, map[string]any{"value": out})
	case seg[0] == "teams" && len(seg) == 3 && seg[2] == "members":
		members, ok := f.teams[seg[1]]
		if !ok {
			graphErr(w, 404, "NotFound")
			return
		}
		write(w, map[string]any{"value": f.memberList(members, filterUser(f.t, r))})
	case seg[0] == "teams" && len(seg) >= 4 && seg[2] == "channels":
		ch, ok := f.channels[seg[3]]
		if !ok || f.teams[seg[1]] == nil {
			graphErr(w, 404, "NotFound")
			return
		}
		if len(seg) == 4 {
			out := map[string]any{"id": seg[3], "membershipType": ch.membershipType}
			if ch.moderation != "" {
				out["moderationSettings"] = map[string]any{"userNewMessageRestriction": ch.moderation}
			}
			write(w, out)
			return
		}
		switch {
		case seg[4] == "members" && ch.membershipType == "private", seg[4] == "allMembers" && ch.membershipType == "shared":
			write(w, map[string]any{"value": f.memberList(ch.members, filterUser(f.t, r))})
		default:
			graphErr(w, 400, "BadRequest")
		}
	case seg[0] == "drives" && len(seg) == 2:
		if seg[1] != drive {
			graphErr(w, 404, "itemNotFound")
			return
		}
		out := map[string]any{"id": drive}
		if f.owner != "" {
			out["owner"] = map[string]any{"user": map[string]any{"id": f.owner}}
		}
		write(w, out)
	case seg[0] == "drives" && len(seg) == 5 && seg[2] == "items" && seg[4] == "permissions":
		perms, ok := f.perms[seg[3]]
		if seg[1] != drive || !ok {
			graphErr(w, 404, "itemNotFound")
			return
		}
		write(w, map[string]any{"value": perms})
	case p == "servicePrincipals":
		if f.spDenied {
			graphErr(w, 403, "Authorization_RequestDenied")
			return
		}
		if q.Get("$filter") != "appId eq '"+clientID+"'" {
			graphErr(w, 400, "BadRequest")
			return
		}
		write(w, map[string]any{"value": []map[string]any{{"id": ownSP}}})
	case p == "servicePrincipals/"+ownSP+"/appRoleAssignments":
		out := []map[string]any{}
		for i := range f.appRoles {
			out = append(out, map[string]any{"appRoleId": fmt.Sprintf("ffffffff-0000-0000-0000-%012d", i), "resourceId": graphSP})
		}
		write(w, map[string]any{"value": out})
	case p == "servicePrincipals/"+graphSP:
		out := []map[string]any{}
		for i, v := range f.appRoles {
			out = append(out, map[string]any{"id": fmt.Sprintf("ffffffff-0000-0000-0000-%012d", i), "value": v})
		}
		write(w, map[string]any{"appRoles": out})
	default:
		f.t.Errorf("fake graph: no route for %s %s", r.Method, r.URL.String())
		graphErr(w, 404, "Request_ResourceNotFound")
	}
}

type permOpt func(*drivePermission)

func perm(roles []string, opts ...permOpt) drivePermission {
	p := drivePermission{Roles: roles}
	for _, o := range opts {
		o(&p)
	}
	return p
}

func toUser(id string) permOpt {
	return func(p *drivePermission) { p.GrantedToV2 = &identitySet{User: &idRef{id}} }
}
func toGroup(id string) permOpt {
	return func(p *drivePermission) {
		p.GrantedToIdentitiesV2 = append(p.GrantedToIdentitiesV2, identitySet{Group: &idRef{id}})
	}
}
func toSiteGroup() permOpt {
	return func(p *drivePermission) { p.GrantedToV2 = &identitySet{SiteGroup: &idRef{"5"}} }
}
func link(scope string) permOpt {
	return func(p *drivePermission) { p.Link = &sharingLink{scope} }
}

func setup(t *testing.T, values map[string]string) (*itest.Server, *fakeGraph, integration.Connection) {
	t.Helper()
	srv := itest.NewServer(t)
	srv.UseSpec(itest.SpecFromEnv(t, "msgraph"), itest.SpecOptions{StripPrefix: []string{`/v1\.0`}, IgnorePaths: []string{`/oauth2/v2\.0/token$`}})
	f := newFake(t)
	srv.Handle("POST", "/"+tenantID+"/oauth2/v2.0/token", f.token)
	srv.Handle("", "/v1.0/*", f.graph)
	deps, _ := itest.Deps(t, srv)
	v := map[string]string{"tenant_id": tenantID, "client_id": clientID, "authority_url": srv.URL, "url": srv.URL}
	for k, val := range values {
		v[k] = val
	}
	s := itest.Settings("m365", "microsoft365", v, map[string]secret.Secret{"credential": itest.Literal("secret")})
	c, err := Integration{}.New(context.Background(), s, deps)
	if err != nil {
		t.Fatal(err)
	}
	return srv, f, c
}

var (
	dana  = integration.User{Email: "dana@example.com"}
	bob   = integration.User{Email: "bob@example.com"}
	guest = integration.User{Email: "guest_gmail.com#EXT#@example.onmicrosoft.com"}
	off   = integration.User{Email: "off@example.com"}
)

func check(t *testing.T, c integration.Connection, u integration.User, action, resource string) integration.Decision {
	t.Helper()
	return itest.Check(t, c, Integration{}, u, action, resource)
}

// --- authentication ---------------------------------------------------------

func TestClientSecretTokenAndCaching(t *testing.T) {
	srv, f, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, dana, "group.member", "group:"+groupA), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, dana, "group.member", "group:"+groupB), integration.CodeDenied)
	if f.tokensIssued != 1 {
		t.Errorf("token fetched %d times, want 1 (cached)", f.tokensIssued)
	}
	var tokenCalls int
	for _, call := range srv.Calls() {
		if strings.HasSuffix(call.Path, "/oauth2/v2.0/token") {
			tokenCalls++
			body := string(call.Body)
			if !strings.Contains(body, "scope="+url.QueryEscape(srv.URL+"/.default")) {
				t.Errorf("token form scope: %s", body)
			}
			if call.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
				t.Errorf("token content type %q", call.Header.Get("Content-Type"))
			}
		}
	}
	if tokenCalls != 1 {
		t.Errorf("%d token calls", tokenCalls)
	}
}

func TestWrongSecretIsCredentialRejected(t *testing.T) {
	srv := itest.NewServer(t)
	srv.UseSpec(itest.SpecFromEnv(t, "msgraph"), itest.SpecOptions{StripPrefix: []string{`/v1\.0`}, IgnorePaths: []string{`/oauth2/v2\.0/token$`}})
	f := newFake(t)
	srv.Handle("POST", "/"+tenantID+"/oauth2/v2.0/token", f.token)
	srv.Handle("", "/v1.0/*", f.graph)
	deps, _ := itest.Deps(t, srv)
	s := itest.Settings("m365", "microsoft365", map[string]string{"tenant_id": tenantID, "client_id": clientID, "authority_url": srv.URL, "url": srv.URL},
		map[string]secret.Secret{"credential": itest.Literal("wrong")})
	c, err := Integration{}.New(context.Background(), s, deps)
	if err != nil {
		t.Fatal(err)
	}
	itest.ExpectCode(t, check(t, c, dana, "group.member", "group:"+groupA), integration.CodeCredentialRejected)
}

func TestRetryOnceAfter401(t *testing.T) {
	_, f, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, dana, "group.member", "group:"+groupA), integration.CodeAllowed)
	f.mu.Lock()
	f.expire401 = 1
	f.mu.Unlock()
	itest.ExpectCode(t, check(t, c, dana, "group.member", "group:"+groupA), integration.CodeAllowed)
	if f.tokensIssued != 2 {
		t.Errorf("token fetched %d times, want 2 (refreshed after 401)", f.tokensIssued)
	}
	// A 401 that persists after one refresh is credential_rejected.
	f.mu.Lock()
	f.expire401 = 10
	f.mu.Unlock()
	itest.ExpectCode(t, check(t, c, dana, "group.member", "group:"+groupA), integration.CodeCredentialRejected)
	f.mu.Lock()
	n := f.tokensIssued
	f.mu.Unlock()
	if n != 3 {
		t.Errorf("token fetched %d times, want 3 (one refresh, then the identity lookup gives up)", n)
	}
}

// testCert generates a key and a self-signed certificate; the certificate
// is written to a file and the key returned as PEM.
func testCert(t *testing.T) (key *rsa.PrivateKey, keyPEM, certFile string, cert *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "hallpass-test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ = x509.ParseCertificate(der)
	certFile = filepath.Join(t.TempDir(), "cert.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	return key, keyPEM, certFile, cert
}

func TestCertificateAssertion(t *testing.T) {
	key, keyPEM, certFile, cert := testCert(t)
	srv := itest.NewServer(t)
	srv.UseSpec(itest.SpecFromEnv(t, "msgraph"), itest.SpecOptions{StripPrefix: []string{`/v1\.0`}, IgnorePaths: []string{`/oauth2/v2\.0/token$`}})
	f := newFake(t)
	tokenURL := srv.URL + "/" + tenantID + "/oauth2/v2.0/token"
	var assertions int
	srv.Handle("POST", "/"+tenantID+"/oauth2/v2.0/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("client_secret") != "" {
			t.Error("certificate mode sent a client_secret")
		}
		if r.Form.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" || r.Form.Get("grant_type") != "client_credentials" {
			t.Errorf("form %v", r.Form)
		}
		a := r.Form.Get("client_assertion")
		parts := strings.Split(a, ".")
		if len(parts) != 3 {
			t.Fatalf("assertion %q", a)
		}
		hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
		var hdr map[string]any
		if err := json.Unmarshal(hb, &hdr); err != nil {
			t.Fatal(err)
		}
		if hdr["alg"] != "PS256" || hdr["typ"] != "JWT" || hdr["x5t#S256"] != authx.CertThumbprintSHA256(cert) {
			t.Errorf("header %v", hdr)
		}
		sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
		if err := authx.Verify(&key.PublicKey, authx.PS256, []byte(parts[0]+"."+parts[1]), sig); err != nil {
			t.Errorf("signature: %v", err)
		}
		var claims authx.StandardClaims
		_ = authx.DecodeJWTClaims(a, &claims)
		now := time.Now().Unix()
		if claims.Aud != tokenURL || claims.Iss != clientID || claims.Sub != clientID || claims.Jti == "" ||
			claims.Nbf > now || claims.Iat > now || claims.Exp < now+4*60 || claims.Exp > now+6*60 {
			t.Errorf("claims %+v", claims)
		}
		assertions++
		f.mu.Lock()
		f.tokensIssued++
		f.tok = itest.Canary + "certtok"
		f.mu.Unlock()
		write(w, map[string]any{"access_token": itest.Canary + "certtok", "expires_in": "3599"})
	})
	srv.Handle("", "/v1.0/*", f.graph)
	deps, _ := itest.Deps(t, srv)
	s := itest.Settings("m365", "microsoft365", map[string]string{"tenant_id": tenantID, "client_id": clientID, "authority_url": srv.URL, "url": srv.URL, "certificate_file": certFile},
		map[string]secret.Secret{"credential": secret.Literal(keyPEM)})
	c, err := Integration{}.New(context.Background(), s, deps)
	if err != nil {
		t.Fatal(err)
	}
	itest.ExpectCode(t, check(t, c, dana, "group.member", "group:"+groupA), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, dana, "team.owner", "team:"+teamA), integration.CodeAllowed)
	if assertions != 1 {
		t.Errorf("%d assertions, want 1 (token cached)", assertions)
	}

	// A missing certificate file is credential_rejected, not a crash.
	s = itest.Settings("m365", "microsoft365", map[string]string{"tenant_id": tenantID, "client_id": clientID, "authority_url": srv.URL, "url": srv.URL, "certificate_file": certFile + ".missing"},
		map[string]secret.Secret{"credential": secret.Literal(keyPEM)})
	c2, _ := Integration{}.New(context.Background(), s, deps)
	itest.ExpectCode(t, check(t, c2, dana, "group.member", "group:"+groupA), integration.CodeCredentialRejected)
}

func TestNewValidation(t *testing.T) {
	srv := itest.NewServer(t)
	srv.UseSpec(itest.SpecFromEnv(t, "msgraph"), itest.SpecOptions{StripPrefix: []string{`/v1\.0`}, IgnorePaths: []string{`/oauth2/v2\.0/token$`}})
	deps, _ := itest.Deps(t, srv)
	cases := []map[string]string{
		{"client_id": clientID},
		{"tenant_id": tenantID},
		{"tenant_id": "not a tenant", "client_id": clientID},
		{"tenant_id": tenantID, "client_id": "abc"},
	}
	for _, v := range cases {
		s := itest.Settings("m365", "microsoft365", v, map[string]secret.Secret{"credential": itest.Literal("x")})
		if _, err := (Integration{}).New(context.Background(), s, deps); err == nil {
			t.Errorf("%v accepted", v)
		}
	}
	s := itest.Settings("m365", "microsoft365", map[string]string{"tenant_id": "contoso.onmicrosoft.com", "client_id": clientID}, nil)
	if _, err := (Integration{}).New(context.Background(), s, deps); err == nil {
		t.Error("missing credential accepted")
	}
	s = itest.Settings("m365", "microsoft365", map[string]string{"tenant_id": "contoso.onmicrosoft.com", "client_id": clientID}, map[string]secret.Secret{"credential": itest.Literal("x")})
	c, err := (Integration{}).New(context.Background(), s, deps)
	if err != nil {
		t.Fatal(err)
	}
	conn := c.(*Connection)
	if conn.tokenURL != "https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/token" || conn.scope != "https://graph.microsoft.com/.default" {
		t.Errorf("defaults: %s %s", conn.tokenURL, conn.scope)
	}
	if err := integration.ValidateFields((Integration{}).Fields()); err != nil {
		t.Error(err)
	}
}

// --- identity ---------------------------------------------------------------

func TestResolveIdentity(t *testing.T) {
	srv, _, c := setup(t, nil)
	ctx := context.Background()
	id, err := c.ResolveIdentity(ctx, dana)
	if err != nil || id.ID != danaID || id.Attr("account_enabled") != "true" || id.Attr("guest") != "false" || id.Attr("mail") != "dana@example.com" {
		t.Fatalf("%+v %v", id, err)
	}
	if len(srv.Calls()) != 2 { // token + direct lookup
		t.Errorf("direct lookup made %d calls", len(srv.Calls()))
	}
	last := srv.LastCall()
	if last.Path != "/v1.0/users/dana@example.com" || last.Query.Get("$select") != userSelect {
		t.Errorf("direct lookup %s %v", last.Path, last.Query)
	}

	// Guest UPN: #EXT# path-escaped, flagged.
	srv.Reset()
	id, err = c.ResolveIdentity(ctx, guest)
	if err != nil || id.ID != guestID || id.Attr("guest") != "true" {
		t.Fatalf("guest: %+v %v", id, err)
	}
	if srv.LastCall().Path != "/v1.0/users/guest_gmail.com#EXT#@example.onmicrosoft.com" {
		t.Errorf("guest path %q", srv.LastCall().Path)
	}

	// mail filter fallback.
	srv.Reset()
	id, err = c.ResolveIdentity(ctx, integration.User{Email: "dana.alias@example.com"})
	if err != nil || id.ID != danaID {
		t.Fatalf("mail fallback: %+v %v", id, err)
	}
	if calls := srv.Calls(); len(calls) != 2 || calls[1].Query.Get("$filter") != "mail eq 'dana.alias@example.com'" {
		t.Errorf("mail fallback calls: %+v", calls)
	}

	// proxyAddresses fallback.
	srv.Reset()
	id, err = c.ResolveIdentity(ctx, integration.User{Email: "dana.old@example.com"})
	if err != nil || id.ID != danaID {
		t.Fatalf("proxy fallback: %+v %v", id, err)
	}
	if calls := srv.Calls(); len(calls) != 3 || calls[2].Query.Get("$filter") != "proxyAddresses/any(p:p eq 'smtp:dana.old@example.com')" || calls[2].Header.Get("ConsistencyLevel") != "eventual" {
		t.Errorf("proxy fallback calls: %+v", calls)
	}

	// Ambiguous, not found, disabled, bad address, quote escaping.
	_, err = c.ResolveIdentity(ctx, integration.User{Email: "shared@example.com"})
	itest.ExpectCode(t, integration.ToDecision(err), integration.CodeUserAmbiguous)
	_, err = c.ResolveIdentity(ctx, integration.User{Email: "nobody@example.com"})
	itest.ExpectCode(t, integration.ToDecision(err), integration.CodeUserNotFound)
	id, err = c.ResolveIdentity(ctx, off)
	if err != nil || id.Attr("account_enabled") != "false" {
		t.Errorf("disabled: %+v %v", id, err)
	}
	_, err = c.ResolveIdentity(ctx, integration.User{Email: "not an email"})
	itest.ExpectCode(t, integration.ToDecision(err), integration.CodeInvalidRequest)
	srv.Reset()
	_, err = c.ResolveIdentity(ctx, integration.User{Email: "o'neil@example.com"})
	itest.ExpectCode(t, integration.ToDecision(err), integration.CodeUserNotFound)
	if calls := srv.Calls(); calls[1].Query.Get("$filter") != "mail eq 'o''neil@example.com'" {
		t.Errorf("quote escaping: %v", calls[1].Query)
	}
}

func TestDisabledAccountDeniesEverything(t *testing.T) {
	_, _, c := setup(t, nil)
	d := check(t, c, off, "group.member", "group:"+groupA)
	itest.ExpectCode(t, d, integration.CodeDenied)
	if !strings.Contains(d.Text, "disabled") {
		t.Error(d.Text)
	}
	itest.ExpectCode(t, check(t, c, off, "user.active", "user:off@example.com"), integration.CodeDenied)
}

func TestGuestFlaggedInReason(t *testing.T) {
	_, f, c := setup(t, nil)
	f.groups[guestID] = []string{groupA}
	d := check(t, c, guest, "group.member", "group:"+groupA)
	itest.ExpectCode(t, d, integration.CodeAllowed)
	if !strings.Contains(d.Text, "guest account") {
		t.Error(d.Text)
	}
}

// --- actions ----------------------------------------------------------------

func TestAction_user_active_allow(t *testing.T) {
	_, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, dana, "user.active", "user:dana@example.com"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, dana, "user.active", "user:"+danaID), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, dana, "user.active", "mailbox:DANA@example.com"), integration.CodeAllowed)
}

func TestAction_user_active_deny(t *testing.T) {
	_, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, off, "user.active", "user:off@example.com"), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, dana, "user.active", "user:bob@example.com"), integration.CodeUnsupported)
}

func TestAction_group_member_allow(t *testing.T) {
	srv, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, dana, "group.member", "group:"+groupA), integration.CodeAllowed)
	last := srv.LastCall()
	if last.Method != "POST" || last.Path != "/v1.0/users/"+danaID+"/checkMemberGroups" {
		t.Errorf("%s %s", last.Method, last.Path)
	}
	var body map[string][]string
	last.JSON(t, &body)
	if len(body["groupIds"]) != 1 || body["groupIds"][0] != groupA {
		t.Errorf("body %v", body)
	}
}

func TestAction_group_member_deny(t *testing.T) {
	_, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, dana, "group.member", "group:"+groupB), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, bob, "group.member", "group:"+groupA), integration.CodeDenied)
}

func TestCheckMemberGroupsBatching(t *testing.T) {
	srv, f, c := setup(t, nil)
	var perms []drivePermission
	var ids []string
	for i := 0; i < 45; i++ {
		g := fmt.Sprintf("bbbbbbbb-1111-0000-0000-%012d", i)
		ids = append(ids, g)
		perms = append(perms, perm([]string{"read"}, toGroup(g)))
	}
	f.perms["item1"] = perms
	f.groups[danaID] = []string{ids[44]}
	srv.Reset()
	itest.ExpectCode(t, check(t, c, dana, "file.read", "drive:"+drive+"/item/item1"), integration.CodeAllowed)
	var batches []int
	for _, call := range srv.Calls() {
		if strings.HasSuffix(call.Path, "/checkMemberGroups") {
			var body map[string][]string
			call.JSON(t, &body)
			batches = append(batches, len(body["groupIds"]))
		}
	}
	if len(batches) != 3 || batches[0] != 20 || batches[1] != 20 || batches[2] != 5 {
		t.Errorf("batches %v", batches)
	}
}

func TestAction_role_member_allow(t *testing.T) {
	srv, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, dana, "role.member", "role:"+strings.ToUpper(roleA)), integration.CodeAllowed)
	if !strings.HasSuffix(srv.LastCall().Path, "/transitiveMemberOf/microsoft.graph.directoryRole") {
		t.Error(srv.LastCall().Path)
	}
}

func TestAction_role_member_deny(t *testing.T) {
	_, f, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, bob, "role.member", "role:"+roleA), integration.CodeDenied)
	f.spDenied = true
	d := check(t, c, bob, "role.member", "role:"+roleA)
	itest.ExpectCode(t, d, integration.CodeCredentialRejected)
	if !strings.Contains(d.Text, "RoleManagement.Read.Directory") {
		t.Error(d.Text)
	}
}

func TestAction_team_member_allow(t *testing.T) {
	srv, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, bob, "team.member", "team:"+teamA), integration.CodeAllowed)
	last := srv.LastCall()
	if last.Path != "/v1.0/teams/"+teamA+"/members" || last.Query.Get("$filter") != "(microsoft.graph.aadUserConversationMember/userId eq '"+bobID+"')" {
		t.Errorf("%s %v", last.Path, last.Query)
	}
}

func TestAction_team_member_deny(t *testing.T) {
	_, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, guest, "team.member", "team:"+teamA), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, dana, "team.member", "team:dddddddd-0000-0000-0000-000000000099"), integration.CodeResourceNotVisible)
}

func TestAction_team_owner_allow(t *testing.T) {
	_, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, dana, "team.owner", "team:"+teamA), integration.CodeAllowed)
}

func TestAction_team_owner_deny(t *testing.T) {
	_, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, bob, "team.owner", "team:"+teamA), integration.CodeDenied)
}

func TestAction_channel_read_allow(t *testing.T) {
	srv, _, c := setup(t, nil)
	// Standard channel: team membership.
	itest.ExpectCode(t, check(t, c, bob, "channel.read", "team:"+teamA+"/channel/"+chanStd), integration.CodeAllowed)
	if srv.LastCall().Path != "/v1.0/teams/"+teamA+"/members" {
		t.Error(srv.LastCall().Path)
	}
	// Private channel: channel membership.
	itest.ExpectCode(t, check(t, c, dana, "channel.read", "team:"+teamA+"/channel/"+chanPriv), integration.CodeAllowed)
	if srv.LastCall().Path != "/v1.0/teams/"+teamA+"/channels/"+chanPriv+"/members" {
		t.Error(srv.LastCall().Path)
	}
	// Shared channel: allMembers.
	itest.ExpectCode(t, check(t, c, dana, "channel.read", "team:"+teamA+"/channel/"+chanShr), integration.CodeAllowed)
	if srv.LastCall().Path != "/v1.0/teams/"+teamA+"/channels/"+chanShr+"/allMembers" {
		t.Error(srv.LastCall().Path)
	}
}

func TestAction_channel_read_deny(t *testing.T) {
	_, _, c := setup(t, nil)
	// Bob is in the team but not in the private channel.
	itest.ExpectCode(t, check(t, c, bob, "channel.read", "team:"+teamA+"/channel/"+chanPriv), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, guest, "channel.read", "team:"+teamA+"/channel/"+chanStd), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, dana, "channel.read", "team:"+teamA+"/channel/19:missing@thread.tacv2"), integration.CodeResourceNotVisible)
}

func TestAction_channel_owner_allow(t *testing.T) {
	_, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, dana, "channel.owner", "team:"+teamA+"/channel/"+chanStd), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, dana, "channel.owner", "team:"+teamA+"/channel/"+chanShr), integration.CodeAllowed)
}

func TestAction_channel_owner_deny(t *testing.T) {
	_, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, bob, "channel.owner", "team:"+teamA+"/channel/"+chanStd), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, dana, "channel.owner", "team:"+teamA+"/channel/"+chanPriv), integration.CodeDenied)
}

func TestAction_channel_message_post_allow(t *testing.T) {
	_, _, c := setup(t, nil)
	d := check(t, c, bob, "channel.message.post", "team:"+teamA+"/channel/"+chanStd)
	itest.ExpectCode(t, d, integration.CodeAllowed)
	if !strings.Contains(d.Text, "moderation") {
		t.Error(d.Text)
	}
}

func TestAction_channel_message_post_deny(t *testing.T) {
	_, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, bob, "channel.message.post", "team:"+teamA+"/channel/"+chanPriv), integration.CodeDenied)
	// Moderated channel: unknown even for a member.
	itest.ExpectCode(t, check(t, c, bob, "channel.message.post", "team:"+teamA+"/channel/"+chanMod), integration.CodeUnsupported)
}

func fileRes(item string) string { return "drive:" + drive + "/item/" + item }

func TestAction_file_read_allow(t *testing.T) {
	_, f, c := setup(t, nil)
	f.perms["direct"] = []drivePermission{perm([]string{"read"}, toUser(danaID))}
	itest.ExpectCode(t, check(t, c, dana, "file.read", fileRes("direct")), integration.CodeAllowed)
	f.perms["group"] = []drivePermission{perm([]string{"write"}, toGroup(groupA))}
	d := check(t, c, dana, "file.read", fileRes("group"))
	itest.ExpectCode(t, d, integration.CodeAllowed)
	if !strings.Contains(d.Text, "group") {
		t.Error(d.Text)
	}
	f.perms["orglink"] = []drivePermission{perm([]string{"read"}, link("organization"))}
	d = check(t, c, bob, "file.read", fileRes("orglink"))
	itest.ExpectCode(t, d, integration.CodeAllowed)
	if !strings.Contains(d.Text, "organization-wide sharing link") {
		t.Error(d.Text)
	}
	// Drive owner.
	f.perms["owned"] = []drivePermission{}
	f.owner = bobID
	itest.ExpectCode(t, check(t, c, bob, "file.read", fileRes("owned")), integration.CodeAllowed)
}

func TestAction_file_read_deny(t *testing.T) {
	_, f, c := setup(t, nil)
	f.perms["other"] = []drivePermission{perm([]string{"owner"}, toUser(bobID)), perm([]string{"read"}, toGroup(groupB))}
	itest.ExpectCode(t, check(t, c, dana, "file.read", fileRes("other")), integration.CodeDenied)
	f.perms["none"] = []drivePermission{}
	itest.ExpectCode(t, check(t, c, dana, "file.read", fileRes("none")), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, dana, "file.read", fileRes("missing")), integration.CodeResourceNotVisible)
	// siteGroup-only grants and anonymous links cannot be evaluated.
	f.perms["sitegroup"] = []drivePermission{perm([]string{"read"}, toSiteGroup())}
	itest.ExpectCode(t, check(t, c, dana, "file.read", fileRes("sitegroup")), integration.CodeUnsupported)
	f.perms["anon"] = []drivePermission{perm([]string{"read"}, link("anonymous"))}
	itest.ExpectCode(t, check(t, c, dana, "file.read", fileRes("anon")), integration.CodeUnsupported)
}

func TestAction_file_edit_allow(t *testing.T) {
	_, f, c := setup(t, nil)
	f.perms["w"] = []drivePermission{perm([]string{"write"}, toUser(danaID))}
	itest.ExpectCode(t, check(t, c, dana, "file.edit", fileRes("w")), integration.CodeAllowed)
	f.perms["o"] = []drivePermission{perm([]string{"owner"}, toGroup(groupA))}
	itest.ExpectCode(t, check(t, c, dana, "file.edit", fileRes("o")), integration.CodeAllowed)
}

func TestAction_file_edit_deny(t *testing.T) {
	_, f, c := setup(t, nil)
	f.perms["r"] = []drivePermission{perm([]string{"read"}, toUser(danaID)), perm([]string{"read"}, link("organization"))}
	d := check(t, c, dana, "file.edit", fileRes("r"))
	itest.ExpectCode(t, d, integration.CodeDenied)
	if !strings.Contains(d.Text, "read access") {
		t.Error(d.Text)
	}
	// A read grant plus a siteGroup write grant: unknown, not deny.
	f.perms["sg"] = []drivePermission{perm([]string{"read"}, toUser(danaID)), perm([]string{"write"}, toSiteGroup())}
	itest.ExpectCode(t, check(t, c, dana, "file.edit", fileRes("sg")), integration.CodeUnsupported)
}

func TestAction_file_share_allow(t *testing.T) {
	_, f, c := setup(t, nil)
	f.perms["own"] = []drivePermission{perm([]string{"owner"}, toUser(danaID))}
	itest.ExpectCode(t, check(t, c, dana, "file.share", fileRes("own")), integration.CodeAllowed)
}

func TestAction_file_share_deny(t *testing.T) {
	_, f, c := setup(t, nil)
	f.perms["none"] = []drivePermission{perm([]string{"owner"}, toUser(bobID))}
	itest.ExpectCode(t, check(t, c, dana, "file.share", fileRes("none")), integration.CodeDenied)
	f.perms["w"] = []drivePermission{perm([]string{"write"}, toUser(danaID))}
	d := check(t, c, dana, "file.share", fileRes("w"))
	itest.ExpectCode(t, d, integration.CodeUnsupported)
	if !strings.Contains(d.Text, "site settings") {
		t.Error(d.Text)
	}
}

func TestAction_file_delete_allow(t *testing.T) {
	_, f, c := setup(t, nil)
	f.perms["w"] = []drivePermission{perm([]string{"write"}, toUser(danaID))}
	itest.ExpectCode(t, check(t, c, dana, "file.delete", fileRes("w")), integration.CodeAllowed)
}

func TestAction_file_delete_deny(t *testing.T) {
	_, f, c := setup(t, nil)
	f.perms["r"] = []drivePermission{perm([]string{"read"}, toUser(danaID))}
	itest.ExpectCode(t, check(t, c, dana, "file.delete", fileRes("r")), integration.CodeDenied)
}

func TestAction_mail_send_as_self_allow(t *testing.T) {
	_, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, dana, "mail.send_as_self", "mailbox:Dana@Example.com"), integration.CodeAllowed)
}

func TestAction_mail_send_as_self_deny(t *testing.T) {
	_, f, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, off, "mail.send_as_self", "mailbox:off@example.com"), integration.CodeDenied)
	u := f.users[bobID]
	u.Mail = ""
	f.users[bobID] = u
	itest.ExpectCode(t, check(t, c, bob, "mail.send_as_self", "mailbox:bob@example.com"), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, dana, "mail.send_as_self", "mailbox:bob@example.com"), integration.CodeUnsupported)
}

// Exchange delegation and calendar access on another mailbox are always
// unknown; both tests assert that.
func TestAction_mail_send_as_allow(t *testing.T)        { alwaysUnknown(t, "mail.send_as") }
func TestAction_mail_send_as_deny(t *testing.T)         { alwaysUnknown(t, "mail.send_as") }
func TestAction_mail_send_on_behalf_allow(t *testing.T) { alwaysUnknown(t, "mail.send_on_behalf") }
func TestAction_mail_send_on_behalf_deny(t *testing.T)  { alwaysUnknown(t, "mail.send_on_behalf") }
func TestAction_mailbox_full_access_allow(t *testing.T) { alwaysUnknown(t, "mailbox.full_access") }
func TestAction_mailbox_full_access_deny(t *testing.T)  { alwaysUnknown(t, "mailbox.full_access") }
func TestAction_calendar_read_allow(t *testing.T)       { alwaysUnknown(t, "calendar.read") }
func TestAction_calendar_read_deny(t *testing.T)        { alwaysUnknown(t, "calendar.read") }
func TestAction_calendar_write_allow(t *testing.T)      { alwaysUnknown(t, "calendar.write") }
func TestAction_calendar_write_deny(t *testing.T)       { alwaysUnknown(t, "calendar.write") }

func alwaysUnknown(t *testing.T, action string) {
	t.Helper()
	srv, _, c := setup(t, nil)
	d := check(t, c, dana, action, "mailbox:bob@example.com")
	itest.ExpectCode(t, d, integration.CodeUnsupported)
	if !strings.Contains(d.Text, "Graph API") {
		t.Error(d.Text)
	}
	itest.ExpectCode(t, check(t, c, dana, action, "mailbox:dana@example.com"), integration.CodeUnsupported)
	for _, call := range srv.Calls() {
		if strings.Contains(call.Path, "mail") || strings.Contains(call.Path, "calendar") {
			t.Errorf("unexpected call %s", call.Path)
		}
	}
	// A disabled account is still a deny.
	itest.ExpectCode(t, check(t, c, off, action, "mailbox:bob@example.com"), integration.CodeDenied)
}

// --- resources and errors ---------------------------------------------------

func TestBadResources(t *testing.T) {
	_, _, c := setup(t, nil)
	cases := []struct{ action, resource string }{
		{"group.member", "group:not-a-guid"},
		{"group.member", "team:" + teamA},
		{"role.member", "role:" + roleA + "?x=1"},
		{"team.member", "team:" + teamA + "/channel/" + chanStd},
		{"channel.read", "team:" + teamA},
		{"channel.read", "team:" + teamA + "/chan/" + chanStd},
		{"channel.read", "team:" + teamA + "/channel/bad channel"},
		{"file.read", "drive:" + drive},
		{"file.read", "drive:" + drive + "/items/x"},
		{"file.read", "drive:bad/drive/item/x"},
		{"file.read", "drive:" + drive + "/item/a b"},
		{"user.active", "group:" + groupA},
		{"mail.send_as_self", "mailbox:nope"},
	}
	for _, cs := range cases {
		d := check(t, c, dana, cs.action, cs.resource)
		if d.Code != integration.CodeInvalidRequest {
			t.Errorf("%s %s -> %s: %s", cs.action, cs.resource, d.Code, d.Text)
		}
	}
}

func TestGraphErrorsNeverLeakMessage(t *testing.T) {
	srv, f, c := setup(t, nil)
	f.spDenied = true
	d := check(t, c, dana, "role.member", "role:"+roleA)
	itest.ExpectCode(t, d, integration.CodeCredentialRejected)
	itest.AssertNoCanary(t, d.Text)
	srv.JSON("POST", "/v1.0/users/"+danaID+"/checkMemberGroups", 403, `{"error":{"code":"Other","message":"`+itest.Canary+`m"}}`)
	d = check(t, c, dana, "group.member", "group:"+groupA)
	itest.ExpectCode(t, d, integration.CodeCredentialRejected)
	itest.AssertNoCanary(t, d.Text)
	if errorCode(nil) != "" {
		t.Error("nil error has a code")
	}
}

func TestFailures(t *testing.T) {
	srv, _, c := setup(t, nil)
	// Warm the token cache so the failure modes hit Graph, then the token
	// endpoint on refresh.
	itest.ExpectCode(t, check(t, c, dana, "group.member", "group:"+groupA), integration.CodeAllowed)
	itest.FailureCases(t, srv, func() integration.Decision {
		return check(t, c, dana, "group.member", "group:"+groupA)
	})
}

func TestFailuresAtTokenEndpoint(t *testing.T) {
	srv, _, c := setup(t, nil)
	itest.FailureCases(t, srv, func() integration.Decision {
		return check(t, c, dana, "group.member", "group:"+groupA)
	})
}

func TestPagination(t *testing.T) {
	srv, _, c := setup(t, nil)
	srv.JSON("GET", "/v1.0/users/"+danaID+"/transitiveMemberOf/microsoft.graph.directoryRole", 200,
		`{"value":[{"roleTemplateId":"`+groupB+`"}],"@odata.nextLink":"`+srv.URL+`/v1.0/page2"}`)
	srv.JSON("GET", "/v1.0/page2", 200, `{"value":[{"roleTemplateId":"`+roleA+`"}]}`)
	itest.ExpectCode(t, check(t, c, dana, "role.member", "role:"+roleA), integration.CodeAllowed)
	srv.JSON("GET", "/v1.0/page2", 200, `{"value":[],"@odata.nextLink":"https://evil.example/v1.0/x"}`)
	itest.ExpectCode(t, check(t, c, dana, "role.member", "role:"+roleA), integration.CodeUpstreamError)
}

// --- probe ------------------------------------------------------------------

func TestProbe(t *testing.T) {
	_, f, c := setup(t, nil)
	r, err := c.Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.Summary, "Example Ltd") || !strings.Contains(r.Summary, clientID) {
		t.Error(r.Summary)
	}
	joined := strings.Join(r.Warnings, "\n")
	if !strings.Contains(joined, "Files.Read.All") || !strings.Contains(joined, "Member.Read.Hidden") {
		t.Errorf("warnings: %q", joined)
	}
	if strings.Contains(joined, "allows writes") {
		t.Errorf("no write role granted but warned: %q", joined)
	}

	f.appRoles = []string{"User.Read.All", "Directory.ReadWrite.All", "Mail.Send"}
	r, _ = c.Probe(context.Background())
	joined = strings.Join(r.Warnings, "\n")
	for _, want := range []string{"Directory.ReadWrite.All allows writes", "Mail.Send allows writes", "GroupMember.Read.All is not granted", "Files.Read.All is not granted"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %q", want, joined)
		}
	}

	f.spDenied = true
	r, err = c.Probe(context.Background())
	if err != nil || len(r.Warnings) != 1 || !strings.Contains(r.Warnings[0], "could not verify permissions") {
		t.Errorf("%+v %v", r, err)
	}
}

func TestProbeBadCredential(t *testing.T) {
	srv, f, c := setup(t, nil)
	f.mu.Lock()
	f.tok = "x"
	f.mu.Unlock()
	srv.JSON("POST", "/"+tenantID+"/oauth2/v2.0/token", 401, `{"error":"invalid_client","error_description":"`+itest.Canary+`nope"}`)
	_, err := c.Probe(context.Background())
	itest.ExpectCode(t, integration.ToDecision(err), integration.CodeCredentialRejected)
	if err != nil {
		itest.AssertNoCanary(t, err.Error())
	}
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
