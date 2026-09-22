package jira

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/roee-hersh/hallpass/internal/integration"
	"github.com/roee-hersh/hallpass/internal/integration/itest"
	"github.com/roee-hersh/hallpass/internal/secret"
)

const cloudID = "11111111-2222-3333-4444-555555555555"

// fakeJira is the fake Jira Cloud site. Grants are per accountId: a permission
// key maps to targets "p:<projectId>", "i:<issueId>" or "g" (global).
type fakeJira struct {
	t           *testing.T
	mode        string
	users       []map[string]any
	projects    map[string]string    // key -> id
	issues      map[string][2]string // key -> issue id, project id
	grants      map[string]map[string][]string
	checkStatus int  // injected status for permissions/check (0 = normal)
	echoDrop    bool // permissions/check omits the echo of the requested project permission
	admin       bool
	knownPerms  []string
	tokenCalls  int
	tenantCalls int
	logs        *itest.Logs
}

func newFake(t *testing.T, mode string) *fakeJira {
	return &fakeJira{
		t: t, mode: mode, admin: true,
		users: []map[string]any{
			{"accountId": "acc-dana", "accountType": "atlassian", "active": true, "emailAddress": "Dana@example.com", "displayName": "Dana"},
			{"accountId": "acc-bob", "accountType": "atlassian", "active": true, "emailAddress": "bob@example.com", "displayName": "Bob"},
			{"accountId": "acc-bob-old", "accountType": "atlassian", "active": false, "emailAddress": "bob@example.com", "displayName": "Bob (old)"},
			{"accountId": "acc-bot", "accountType": "app", "active": true, "emailAddress": "bob@example.com", "displayName": "Bot"},
			{"accountId": "acc-twin1", "accountType": "atlassian", "active": true, "emailAddress": "twin@example.com", "displayName": "Twin 1"},
			{"accountId": "acc-twin2", "accountType": "atlassian", "active": true, "emailAddress": "twin@example.com", "displayName": "Twin 2"},
			{"accountId": "acc-hidden", "accountType": "atlassian", "active": true, "emailAddress": "", "displayName": "Hidden"},
			{"accountId": "acc-hidden2", "accountType": "atlassian", "active": true, "emailAddress": "", "displayName": "Hidden 2"},
		},
		projects: map[string]string{"OPS": "10000", "SEC": "10001"},
		issues:   map[string][2]string{"OPS-1": {"10010", "10000"}, "SEC-7": {"10020", "10001"}},
		grants: map[string]map[string][]string{
			"acc-dana": {"*": {"p:10000", "i:10010", "g"}},
			"acc-bob":  {"BROWSE_PROJECTS": {"p:10000", "i:10010"}},
		},
		knownPerms: func() []string {
			var ks []string
			for _, a := range actionList {
				ks = append(ks, a.name)
			}
			return ks
		}(),
	}
}

func (f *fakeJira) authorized(r *http.Request) bool {
	h := r.Header.Get("Authorization")
	switch f.mode {
	case ModeBasic:
		return h == "Basic "+base64.StdEncoding.EncodeToString([]byte("bot@example.com:"+itest.Canary+"jira"))
	case ModeScopedToken:
		return h == "Bearer "+itest.Canary+"scoped"
	case ModeOAuthClient:
		return h == "Bearer "+itest.Canary+"access"
	}
	return false
}

func (f *fakeJira) has(account, perm, target string) bool {
	for _, key := range []string{"*", perm} {
		for _, tg := range f.grants[account][key] {
			if tg == target {
				return true
			}
		}
	}
	return false
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (f *fakeJira) handler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	switch {
	case path == "/_edge/tenant_info":
		f.tenantCalls++
		if r.Header.Get("Authorization") != "" {
			f.t.Errorf("tenant_info was sent an Authorization header")
		}
		writeJSON(w, 200, map[string]string{"cloudId": cloudID})
		return
	case path == "/oauth/token":
		f.tokenCalls++
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["grant_type"] != "client_credentials" || body["client_id"] != "cid-1" || body["audience"] != "api.atlassian.com" {
			f.t.Errorf("token body %v", body)
		}
		if body["client_secret"] != itest.Canary+"oauth" {
			writeJSON(w, 401, map[string]string{"error": "access_denied", "error_description": "Unauthorized " + itest.Canary})
			return
		}
		writeJSON(w, 200, map[string]any{"access_token": itest.Canary + "access", "expires_in": 3600, "token_type": "Bearer"})
		return
	}
	if f.mode != ModeBasic {
		prefix := "/ex/jira/" + cloudID
		if !strings.HasPrefix(path, prefix+"/") {
			f.t.Errorf("token mode request outside the gateway: %s", path)
			w.WriteHeader(404)
			return
		}
		path = strings.TrimPrefix(path, prefix)
	}
	if !f.authorized(r) {
		writeJSON(w, 401, map[string]any{"errorMessages": []string{"unauthorized " + itest.Canary}})
		return
	}
	switch {
	case path == "/rest/api/3/user/search":
		q := strings.ToLower(r.URL.Query().Get("query"))
		var out []map[string]any
		for _, u := range f.users {
			email, _ := u["emailAddress"].(string)
			name, _ := u["displayName"].(string)
			if strings.Contains(strings.ToLower(email), q) || strings.Contains(strings.ToLower(name), q) || (email == "" && strings.HasPrefix(q, "hidden")) {
				out = append(out, u)
			}
		}
		// startAt/maxResults paging, as Jira does it.
		startAt, _ := strconv.Atoi(r.URL.Query().Get("startAt"))
		maxResults, _ := strconv.Atoi(r.URL.Query().Get("maxResults"))
		if maxResults <= 0 {
			maxResults = 50
		}
		if startAt > len(out) {
			startAt = len(out)
		}
		end := startAt + maxResults
		if end > len(out) {
			end = len(out)
		}
		out = out[startAt:end]
		if out == nil {
			out = []map[string]any{}
		}
		writeJSON(w, 200, out)
	case strings.HasPrefix(path, "/rest/api/3/project/"):
		key := strings.TrimPrefix(path, "/rest/api/3/project/")
		id, ok := f.projects[key]
		if !ok {
			writeJSON(w, 404, map[string]any{"errorMessages": []string{"No project could be found with key " + key}})
			return
		}
		writeJSON(w, 200, map[string]any{"id": id, "key": key, "name": "Project " + key})
	case strings.HasPrefix(path, "/rest/api/3/issue/"):
		key := strings.TrimPrefix(path, "/rest/api/3/issue/")
		if r.URL.Query().Get("fields") != "project" {
			f.t.Errorf("issue lookup without fields=project: %s", r.URL.RawQuery)
		}
		iss, ok := f.issues[key]
		if !ok {
			writeJSON(w, 404, map[string]any{"errorMessages": []string{"Issue does not exist"}})
			return
		}
		writeJSON(w, 200, map[string]any{"id": iss[0], "key": key, "fields": map[string]any{"project": map[string]any{"id": iss[1]}}})
	case path == "/rest/api/3/permissions/check" && r.Method == "POST":
		if f.checkStatus != 0 {
			writeJSON(w, f.checkStatus, map[string]any{"errorMessages": []string{"injected " + itest.Canary}})
			return
		}
		var req checkRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		out := map[string]any{"projectPermissions": []any{}, "globalPermissions": []string{}}
		var pps []map[string]any
		for _, pp := range req.ProjectPermissions {
			for _, perm := range pp.Permissions {
				if f.echoDrop {
					continue
				}
				entry := map[string]any{"permission": perm, "projects": []int64{}, "issues": []int64{}}
				for _, p := range pp.Projects {
					if f.has(req.AccountID, perm, "p:"+jsonNum(p)) {
						entry["projects"] = append(entry["projects"].([]int64), p)
					}
				}
				for _, i := range pp.Issues {
					if f.has(req.AccountID, perm, "i:"+jsonNum(i)) {
						entry["issues"] = append(entry["issues"].([]int64), i)
					}
				}
				pps = append(pps, entry)
			}
		}
		if pps != nil {
			out["projectPermissions"] = pps
		}
		var gs []string
		for _, g := range req.GlobalPermissions {
			if f.has(req.AccountID, g, "g") {
				gs = append(gs, g)
			}
		}
		if gs != nil {
			out["globalPermissions"] = gs
		}
		writeJSON(w, 200, out)
	case path == "/rest/api/3/myself":
		writeJSON(w, 200, map[string]any{"accountId": "acc-hallpass", "displayName": "hallpass bot", "emailAddress": "bot@example.com"})
	case path == "/rest/api/3/mypermissions":
		writeJSON(w, 200, map[string]any{"permissions": map[string]any{"ADMINISTER": map[string]any{"havePermission": f.admin}}})
	case path == "/rest/api/3/permissions":
		perms := map[string]any{}
		for _, k := range f.knownPerms {
			perms[k] = map[string]any{"key": k}
		}
		writeJSON(w, 200, map[string]any{"permissions": perms})
	default:
		writeJSON(w, 404, map[string]string{"message": "no route " + path})
	}
}

func jsonNum(n int64) string { return strconv.FormatInt(n, 10) }

func setup(t *testing.T, mode string, values map[string]string) (*itest.Server, *fakeJira, integration.Connection) {
	t.Helper()
	srv := itest.NewServer(t)
	srv.UseSpec(itest.SpecFromEnv(t, "jira"), itest.SpecOptions{StripPrefix: []string{`/ex/jira/[^/]+`}, IgnorePaths: []string{`^/_edge/tenant_info$`, `/oauth/token$`}})
	f := newFake(t, mode)
	srv.Handle("", "*", f.handler)
	deps, logs := itest.Deps(t, srv)
	f.logs = logs
	oldGW, oldTok := Gateway, TokenURL
	Gateway, TokenURL = srv.URL, srv.URL+"/oauth/token"
	t.Cleanup(func() { Gateway, TokenURL = oldGW, oldTok })
	v := map[string]string{"url": srv.URL, "auth_mode": mode}
	var cred secret.Secret
	switch mode {
	case ModeBasic:
		v["username"] = "bot@example.com"
		cred = itest.Literal("jira")
	case ModeScopedToken:
		cred = itest.Literal("scoped")
	case ModeOAuthClient:
		v["client_id"] = "cid-1"
		cred = itest.Literal("oauth")
	}
	for k, val := range values {
		v[k] = val
	}
	s := itest.Settings("jira-1", "jira", v, map[string]secret.Secret{"credential": cred})
	c, err := Integration{}.New(context.Background(), s, deps)
	if err != nil {
		t.Fatal(err)
	}
	return srv, f, c
}

var (
	dana = integration.User{Email: "dana@example.com"}
	bob  = integration.User{Email: "bob@example.com"}
)

func check(t *testing.T, c integration.Connection, u integration.User, action, resource string) integration.Decision {
	t.Helper()
	return itest.Check(t, c, Integration{}, u, action, resource)
}

func TestFieldsValid(t *testing.T) {
	if err := integration.ValidateFields(Integration{}.Fields()); err != nil {
		t.Fatal(err)
	}
	for _, a := range (Integration{}).Actions() {
		if a.Pattern {
			t.Errorf("%s: pattern action unexpected", a.Name)
		}
	}
}

func TestNewValidation(t *testing.T) {
	srv := itest.NewServer(t)
	srv.UseSpec(itest.SpecFromEnv(t, "jira"), itest.SpecOptions{StripPrefix: []string{`/ex/jira/[^/]+`}, IgnorePaths: []string{`^/_edge/tenant_info$`, `/oauth/token$`}})
	deps, _ := itest.Deps(t, srv)
	cases := []struct {
		name   string
		values map[string]string
		secret secret.Secret
	}{
		{"no credential", map[string]string{"url": srv.URL}, secret.Secret{}},
		{"basic without username", map[string]string{"url": srv.URL, "auth_mode": "basic"}, itest.Literal("x")},
		{"oauth without client_id", map[string]string{"url": srv.URL, "auth_mode": "oauth_client"}, itest.Literal("x")},
		{"bad mode", map[string]string{"url": srv.URL, "auth_mode": "pat"}, itest.Literal("x")},
	}
	for _, cs := range cases {
		s := itest.Settings("j", "jira", cs.values, map[string]secret.Secret{"credential": cs.secret})
		if _, err := (Integration{}).New(context.Background(), s, deps); err == nil {
			t.Errorf("%s: New accepted", cs.name)
		}
	}
	if len(srv.Calls()) != 0 {
		t.Error("New touched the network")
	}
}

func TestIdentity(t *testing.T) {
	srv, _, c := setup(t, ModeBasic, nil)
	ctx := context.Background()
	id, err := c.ResolveIdentity(ctx, dana)
	if err != nil || id.ID != "acc-dana" || id.Display != "Dana" {
		t.Fatalf("dana: %+v %v", id, err)
	}
	call := srv.LastCall()
	if call.Path != "/rest/api/3/user/search" || call.Query.Get("query") != "dana@example.com" || call.Query.Get("maxResults") != "50" || call.Query.Get("startAt") != "0" {
		t.Errorf("search call %s %v", call.Path, call.Query)
	}
	// inactive and app accounts with the same email are ignored
	id, err = c.ResolveIdentity(ctx, bob)
	if err != nil || id.ID != "acc-bob" {
		t.Fatalf("bob: %+v %v", id, err)
	}
	_, err = c.ResolveIdentity(ctx, integration.User{Email: "twin@example.com"})
	itest.ExpectCode(t, integration.ToDecision(err), integration.CodeUserAmbiguous)
	_, err = c.ResolveIdentity(ctx, integration.User{Email: "nobody@example.com"})
	itest.ExpectCode(t, integration.ToDecision(err), integration.CodeUserNotFound)

	// hidden email: unknown, never a match, however many candidates
	_, err = c.ResolveIdentity(ctx, integration.User{Email: "hidden@example.com"})
	d := integration.ToDecision(err)
	itest.ExpectCode(t, d, integration.CodeUnsupported)
	if !strings.Contains(d.Text, "hidden") {
		t.Error(d.Text)
	}

	// search forbidden: credential_rejected
	srv.JSON("GET", "/rest/api/3/user/search", 403, `{"errorMessages":["forbidden"]}`)
	_, err = c.ResolveIdentity(ctx, dana)
	itest.ExpectCode(t, integration.ToDecision(err), integration.CodeCredentialRejected)
}

// TestIdentityEmptyEmail: a request without an email is a bad request, not
// a user that positively does not exist.
func TestIdentityEmptyEmail(t *testing.T) {
	srv, _, c := setup(t, ModeBasic, nil)
	for _, email := range []string{"", "   "} {
		_, err := c.ResolveIdentity(context.Background(), integration.User{Email: email})
		itest.ExpectCode(t, integration.ToDecision(err), integration.CodeInvalidRequest)
	}
	if len(srv.Calls()) != 0 {
		t.Error("an empty email must not reach upstream")
	}
}

// TestIdentityDisplayNameSpoof: user/search?query= also matches displayName,
// so an account named "cfo@example.com" is a candidate for that email. It
// must never be resolved as the CFO: with a hidden email it is unsupported,
// with a visible other email it is not found. The strict_email_match switch
// that used to accept a single hidden candidate is gone.
func TestIdentityDisplayNameSpoof(t *testing.T) {
	for _, f := range (Integration{}).Fields() {
		if f.Name == "strict_email_match" {
			t.Fatal("strict_email_match must no longer be a connection key")
		}
	}
	_, f, c := setup(t, ModeBasic, nil)
	ctx := context.Background()
	f.users = append(f.users, map[string]any{"accountId": "acc-spoof", "accountType": "atlassian", "active": true, "emailAddress": "", "displayName": "cfo@example.com"})
	id, err := c.ResolveIdentity(ctx, integration.User{Email: "cfo@example.com"})
	d := integration.ToDecision(err)
	itest.ExpectCode(t, d, integration.CodeUnsupported)
	if id.ID != "" || !strings.Contains(d.Text, "hidden") {
		t.Errorf("%+v %s", id, d.Text)
	}
	// The same name with a visible, different email: plainly not the CFO.
	f.users[len(f.users)-1]["emailAddress"] = "impostor@example.com"
	id, err = c.ResolveIdentity(ctx, integration.User{Email: "cfo@example.com"})
	itest.ExpectCode(t, integration.ToDecision(err), integration.CodeUserNotFound)
	if id.ID != "" {
		t.Errorf("%+v", id)
	}
	// Explicitly asking for the old non-strict behaviour changes nothing.
	_, f2, c2 := setup(t, ModeBasic, map[string]string{"strict_email_match": "false"})
	f2.users = append(f2.users, map[string]any{"accountId": "acc-spoof", "accountType": "atlassian", "active": true, "emailAddress": "", "displayName": "cfo@example.com"})
	id, err = c2.ResolveIdentity(ctx, integration.User{Email: "cfo@example.com"})
	itest.ExpectCode(t, integration.ToDecision(err), integration.CodeUnsupported)
	if id.ID != "" {
		t.Errorf("%+v", id)
	}
}

// crowd returns n active Atlassian accounts whose display name contains the
// query, so that a user search for it fills pages.
func crowd(n int, query string) []map[string]any {
	var users []map[string]any
	for i := 0; i < n; i++ {
		users = append(users, map[string]any{
			"accountId": "acc-crowd-" + strconv.Itoa(i), "accountType": "atlassian", "active": true,
			"emailAddress": "crowd-" + strconv.Itoa(i) + "@example.com", "displayName": "Crowd " + strconv.Itoa(i) + " (" + query + ")",
		})
	}
	return users
}

func searchCalls(srv *itest.Server) []int {
	var starts []int
	for _, call := range srv.Calls() {
		if call.Path == "/rest/api/3/user/search" {
			n, _ := strconv.Atoi(call.Query.Get("startAt"))
			starts = append(starts, n)
		}
	}
	return starts
}

// TestIdentityPagination: the match on a later page is found; a match on the
// last page hallpass reads still wins even when that page is full.
func TestIdentityPagination(t *testing.T) {
	srv, f, c := setup(t, ModeBasic, nil)
	ctx := context.Background()
	f.users = append(crowd(60, "dana@example.com"), f.users...)
	id, err := c.ResolveIdentity(ctx, dana)
	if err != nil || id.ID != "acc-dana" {
		t.Fatalf("dana on page 2: %+v %v", id, err)
	}
	if starts := searchCalls(srv); len(starts) != 2 || starts[0] != 0 || starts[1] != 50 {
		t.Errorf("search pages %v, want [0 50]", starts)
	}
	for _, call := range srv.Calls() {
		if call.Query.Get("maxResults") != "50" {
			t.Errorf("maxResults %q", call.Query.Get("maxResults"))
		}
	}

	srv.Reset()
	f.users = append(crowd(249, "dana@example.com"), f.users[60:]...) // dana is result 250, the last slot of page 5
	id, err = c.ResolveIdentity(ctx, dana)
	if err != nil || id.ID != "acc-dana" {
		t.Fatalf("dana on a full page 5: %+v %v", id, err)
	}
	if starts := searchCalls(srv); len(starts) != 5 {
		t.Errorf("search pages %v, want 5", starts)
	}
}

// TestIdentityTooManyCandidates: five full pages without an exact email
// match is unknown, since the user may sit on a page hallpass did not read.
func TestIdentityTooManyCandidates(t *testing.T) {
	srv, f, c := setup(t, ModeBasic, nil)
	f.users = append(append(crowd(300, "nobody@example.com"), crowd(300, "hidden@example.com")...), f.users...)
	_, err := c.ResolveIdentity(context.Background(), integration.User{Email: "nobody@example.com"})
	d := integration.ToDecision(err)
	itest.ExpectCode(t, d, integration.CodeUnsupported)
	if !strings.Contains(d.Text, "too many candidates") {
		t.Error(d.Text)
	}
	if starts := searchCalls(srv); len(starts) != 5 || starts[4] != 200 {
		t.Errorf("search pages %v, want [0 50 100 150 200]", starts)
	}
	// hidden candidates on full pages are "too many", not "hidden"
	srv.Reset()
	_, err = c.ResolveIdentity(context.Background(), integration.User{Email: "hidden@example.com"})
	d = integration.ToDecision(err)
	itest.ExpectCode(t, d, integration.CodeUnsupported)
	if !strings.Contains(d.Text, "too many candidates") {
		t.Error(d.Text)
	}
}

// TestCheckMissingPermissionEcho: a 200 whose projectPermissions does not
// echo the requested key means Jira did not evaluate it; that is unknown,
// not deny. The global list has no echo and is unaffected.
func TestCheckMissingPermissionEcho(t *testing.T) {
	_, f, c := setup(t, ModeBasic, nil)
	f.echoDrop = true
	for _, res := range []string{"project:OPS", "issue:OPS-1"} {
		d := check(t, c, dana, "CREATE_ISSUES", res)
		itest.ExpectCode(t, d, integration.CodeUnsupported)
		if !strings.Contains(d.Text, "did not evaluate") {
			t.Error(d.Text)
		}
	}
	itest.ExpectCode(t, check(t, c, dana, "ADMINISTER", "global"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, bob, "ADMINISTER", "global"), integration.CodeDenied)
	f.echoDrop = false
	itest.ExpectCode(t, check(t, c, dana, "CREATE_ISSUES", "project:OPS"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, bob, "CREATE_ISSUES", "project:OPS"), integration.CodeDenied)
}

func TestBasicRequestShape(t *testing.T) {
	srv, _, c := setup(t, ModeBasic, nil)
	d := check(t, c, dana, "CREATE_ISSUES", "project:OPS")
	itest.ExpectCode(t, d, integration.CodeAllowed)
	calls := srv.Calls()
	if len(calls) != 3 {
		t.Fatalf("%d calls", len(calls))
	}
	want := []string{"/rest/api/3/user/search", "/rest/api/3/project/OPS", "/rest/api/3/permissions/check"}
	for i, w := range want {
		if calls[i].Path != w {
			t.Errorf("call %d: %s, want %s", i, calls[i].Path, w)
		}
		if !strings.HasPrefix(calls[i].Header.Get("Authorization"), "Basic ") {
			t.Errorf("call %d: Authorization %q", i, calls[i].Header.Get("Authorization"))
		}
	}
	var req checkRequest
	calls[2].JSON(t, &req)
	if req.AccountID != "acc-dana" || len(req.ProjectPermissions) != 1 || req.ProjectPermissions[0].Permissions[0] != "CREATE_ISSUES" ||
		len(req.ProjectPermissions[0].Projects) != 1 || req.ProjectPermissions[0].Projects[0] != 10000 || req.ProjectPermissions[0].Issues != nil || req.GlobalPermissions != nil {
		t.Errorf("body %s", calls[2].Body)
	}
}

func TestScopedToken(t *testing.T) {
	srv, f, c := setup(t, ModeScopedToken, nil)
	itest.ExpectCode(t, check(t, c, dana, "CREATE_ISSUES", "project:OPS"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, bob, "CREATE_ISSUES", "project:OPS"), integration.CodeDenied)
	if f.tenantCalls != 1 {
		t.Errorf("tenant_info called %d times, want 1 (cached)", f.tenantCalls)
	}
	for _, call := range srv.Calls() {
		if call.Path == "/_edge/tenant_info" {
			continue
		}
		if !strings.HasPrefix(call.Path, "/ex/jira/"+cloudID+"/rest/api/3/") {
			t.Errorf("path %s not under the gateway", call.Path)
		}
		if call.Header.Get("Authorization") != "Bearer "+itest.Canary+"scoped" {
			t.Errorf("Authorization %q", call.Header.Get("Authorization"))
		}
	}
	// tenant_info failure surfaces as unknown, not as deny
	srv2, _, c2 := setup(t, ModeScopedToken, nil)
	srv2.JSON("GET", "/_edge/tenant_info", 200, `{}`)
	itest.ExpectCode(t, check(t, c2, dana, "CREATE_ISSUES", "project:OPS"), integration.CodeUpstreamError)
}

func TestOAuthClient(t *testing.T) {
	srv, f, c := setup(t, ModeOAuthClient, nil)
	itest.ExpectCode(t, check(t, c, dana, "ADMINISTER", "global"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, bob, "ADMINISTER", "global"), integration.CodeDenied)
	if f.tokenCalls != 1 {
		t.Errorf("token endpoint called %d times, want 1 (cached)", f.tokenCalls)
	}
	if f.tenantCalls != 1 {
		t.Errorf("tenant_info called %d times", f.tenantCalls)
	}
	var sawToken, sawAPI bool
	for _, call := range srv.Calls() {
		switch {
		case call.Path == "/oauth/token":
			sawToken = true
			if call.Header.Get("Content-Type") != "application/json" {
				t.Errorf("token request content type %q", call.Header.Get("Content-Type"))
			}
		case call.Path == "/_edge/tenant_info":
		default:
			sawAPI = true
			if !strings.HasPrefix(call.Path, "/ex/jira/"+cloudID+"/rest/api/3/") || call.Header.Get("Authorization") != "Bearer "+itest.Canary+"access" {
				t.Errorf("%s %q", call.Path, call.Header.Get("Authorization"))
			}
		}
	}
	if !sawToken || !sawAPI {
		t.Error("expected token and API calls")
	}
	// a rejected client secret is credential_rejected
	s := itest.Settings("j", "jira", map[string]string{"url": srv.URL, "auth_mode": ModeOAuthClient, "client_id": "cid-1"}, map[string]secret.Secret{"credential": itest.Literal("wrong")})
	deps, _ := itest.Deps(t, srv)
	c3, err := Integration{}.New(context.Background(), s, deps)
	if err != nil {
		t.Fatal(err)
	}
	itest.ExpectCode(t, check(t, c3, dana, "ADMINISTER", "global"), integration.CodeCredentialRejected)
}

func TestIssueAndGlobalChecks(t *testing.T) {
	srv, _, c := setup(t, ModeBasic, nil)
	itest.ExpectCode(t, check(t, c, dana, "EDIT_ISSUES", "issue:OPS-1"), integration.CodeAllowed)
	calls := srv.Calls()
	if calls[1].Path != "/rest/api/3/issue/OPS-1" || calls[1].Query.Get("fields") != "project" {
		t.Errorf("issue lookup %s %v", calls[1].Path, calls[1].Query)
	}
	var req checkRequest
	calls[2].JSON(t, &req)
	if len(req.ProjectPermissions) != 1 || len(req.ProjectPermissions[0].Issues) != 1 || req.ProjectPermissions[0].Issues[0] != 10010 || req.ProjectPermissions[0].Projects != nil {
		t.Errorf("issue body %s", calls[2].Body)
	}
	itest.ExpectCode(t, check(t, c, bob, "EDIT_ISSUES", "issue:OPS-1"), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, bob, "BROWSE_PROJECTS", "issue:OPS-1"), integration.CodeAllowed)

	srv.Reset()
	itest.ExpectCode(t, check(t, c, dana, "ADMINISTER", "global"), integration.CodeAllowed)
	calls = srv.Calls()
	if len(calls) != 2 {
		t.Fatalf("global check made %d calls, want 2", len(calls))
	}
	req = checkRequest{}
	calls[1].JSON(t, &req)
	if req.AccountID != "acc-dana" || len(req.GlobalPermissions) != 1 || req.GlobalPermissions[0] != "ADMINISTER" || req.ProjectPermissions != nil {
		t.Errorf("global body %s", calls[1].Body)
	}
	itest.ExpectCode(t, check(t, c, bob, "ADMINISTER", "global"), integration.CodeDenied)
}

func TestStatuses(t *testing.T) {
	_, f, c := setup(t, ModeBasic, nil)
	itest.ExpectCode(t, check(t, c, dana, "CREATE_ISSUES", "project:NOPE"), integration.CodeResourceNotVisible)
	itest.ExpectCode(t, check(t, c, dana, "EDIT_ISSUES", "issue:NOPE-1"), integration.CodeResourceNotVisible)
	f.checkStatus = 403
	d := check(t, c, dana, "CREATE_ISSUES", "project:OPS")
	itest.ExpectCode(t, d, integration.CodeCredentialRejected)
	if !strings.Contains(d.Text, "Administer Jira") {
		t.Error(d.Text)
	}
	f.checkStatus = 400
	itest.ExpectCode(t, check(t, c, dana, "CREATE_ISSUES", "project:OPS"), integration.CodeUnsupported)
	f.checkStatus = 0

	srv, _, c2 := setup(t, ModeBasic, nil)
	srv.JSON("GET", "/rest/api/3/project/OPS", 403, `{"errorMessages":["forbidden"]}`)
	itest.ExpectCode(t, check(t, c2, dana, "CREATE_ISSUES", "project:OPS"), integration.CodeCredentialRejected)
}

func TestInvalidRequests(t *testing.T) {
	srv, _, c := setup(t, ModeBasic, nil)
	cases := []struct{ action, resource string }{
		{"CREATE_ISSUES", "global"},
		{"ADMINISTER", "project:OPS"},
		{"ADMINISTER", "issue:OPS-1"},
		{"CREATE_ISSUES", "project:ops"},
		{"CREATE_ISSUES", "project:O"},
		{"CREATE_ISSUES", "project:TOOLONGKEY123"},
		{"CREATE_ISSUES", "project:OPS/../x"},
		{"CREATE_ISSUES", "issue:OPS"},
		{"CREATE_ISSUES", "issue:OPS-0"},
		{"CREATE_ISSUES", "issue:ops-1"},
		{"CREATE_ISSUES", "board:1"},
		{"ADMINISTER", "global:x"},
	}
	for _, cs := range cases {
		srv.Reset()
		d := check(t, c, dana, cs.action, cs.resource)
		if d.Code != integration.CodeInvalidRequest {
			t.Errorf("%s %s -> %s: %s", cs.action, cs.resource, d.Code, d.Text)
		}
		for _, call := range srv.Calls() {
			if call.Path != "/rest/api/3/user/search" {
				t.Errorf("%s %s reached upstream: %s", cs.action, cs.resource, call.Path)
			}
		}
	}
}

func TestFailures(t *testing.T) {
	srv, _, c := setup(t, ModeBasic, nil)
	itest.FailureCases(t, srv, func() integration.Decision {
		return check(t, c, dana, "CREATE_ISSUES", "project:OPS")
	})
}

func TestProbe(t *testing.T) {
	srv, f, c := setup(t, ModeBasic, nil)
	r, err := c.Probe(context.Background())
	if err != nil || !strings.Contains(r.Summary, "hallpass bot") || len(r.Warnings) != 0 {
		t.Fatalf("%+v %v", r, err)
	}
	f.admin = false
	f.knownPerms = f.knownPerms[:len(f.knownPerms)-2]
	r, err = c.Probe(context.Background())
	if err != nil || len(r.Warnings) != 2 {
		t.Fatalf("%+v %v", r, err)
	}
	if !strings.Contains(r.Warnings[0], "Administer Jira") || !strings.Contains(r.Warnings[1], "BULK_CHANGE") {
		t.Errorf("%v", r.Warnings)
	}
	srv.Fail(itest.FailUnauthorized)
	_, err = c.Probe(context.Background())
	srv.Fail(itest.FailNone)
	itest.ExpectCode(t, integration.ToDecision(err), integration.CodeCredentialRejected)
}

// TestCanaryNeverLogged drives the error paths whose upstream bodies carry
// the canary (401, 400, 403, a rejected token) and checks the log buffer the
// connection writes to. Every other test's cleanup checks it too.
func TestCanaryNeverLogged(t *testing.T) {
	srv, f, c := setup(t, ModeOAuthClient, nil)
	f.checkStatus = 400
	itest.ExpectCode(t, check(t, c, dana, "CREATE_ISSUES", "project:OPS"), integration.CodeUnsupported)
	f.checkStatus = 403
	itest.ExpectCode(t, check(t, c, dana, "CREATE_ISSUES", "project:OPS"), integration.CodeCredentialRejected)
	f.checkStatus = 0
	srv.Fail(itest.FailUnauthorized)
	itest.ExpectCode(t, check(t, c, dana, "CREATE_ISSUES", "project:OPS"), integration.CodeCredentialRejected)
	srv.Fail(itest.FailNone)
	s := itest.Settings("j", "jira", map[string]string{"url": srv.URL, "auth_mode": ModeOAuthClient, "client_id": "cid-1"}, map[string]secret.Secret{"credential": itest.Literal("wrong")})
	deps, logs := itest.Deps(t, srv)
	c2, err := Integration{}.New(context.Background(), s, deps)
	if err != nil {
		t.Fatal(err)
	}
	d := check(t, c2, dana, "CREATE_ISSUES", "project:OPS")
	itest.ExpectCode(t, d, integration.CodeCredentialRejected)
	itest.AssertNoCanary(t, d.Text)
	itest.AssertNoCanary(t, f.logs.String())
	itest.AssertNoCanary(t, logs.String())
	if len(f.logs.String()) == 0 {
		t.Error("expected http debug lines in the log buffer")
	}
}

// Allow/deny tests per action (coverage gate). Dana holds everything on
// project OPS, issue OPS-1 and globally; Bob holds only BROWSE_PROJECTS.

func projectAllow(t *testing.T, action string) {
	t.Helper()
	_, _, c := setup(t, ModeBasic, nil)
	itest.ExpectCode(t, check(t, c, dana, action, "project:OPS"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, dana, action, "issue:OPS-1"), integration.CodeAllowed)
}

func projectDeny(t *testing.T, action string) {
	t.Helper()
	_, _, c := setup(t, ModeBasic, nil)
	itest.ExpectCode(t, check(t, c, bob, action, "project:OPS"), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, dana, action, "project:SEC"), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, dana, action, "issue:SEC-7"), integration.CodeDenied)
}

func globalAllow(t *testing.T, action string) {
	t.Helper()
	_, _, c := setup(t, ModeBasic, nil)
	itest.ExpectCode(t, check(t, c, dana, action, "global"), integration.CodeAllowed)
}

func globalDeny(t *testing.T, action string) {
	t.Helper()
	_, _, c := setup(t, ModeBasic, nil)
	itest.ExpectCode(t, check(t, c, bob, action, "global"), integration.CodeDenied)
}

func TestAction_BROWSE_PROJECTS_allow(t *testing.T) { projectAllow(t, "BROWSE_PROJECTS") }
func TestAction_BROWSE_PROJECTS_deny(t *testing.T) {
	_, _, c := setup(t, ModeBasic, nil)
	itest.ExpectCode(t, check(t, c, bob, "BROWSE_PROJECTS", "project:SEC"), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, bob, "BROWSE_PROJECTS", "issue:SEC-7"), integration.CodeDenied)
}
func TestAction_CREATE_ISSUES_allow(t *testing.T)       { projectAllow(t, "CREATE_ISSUES") }
func TestAction_CREATE_ISSUES_deny(t *testing.T)        { projectDeny(t, "CREATE_ISSUES") }
func TestAction_EDIT_ISSUES_allow(t *testing.T)         { projectAllow(t, "EDIT_ISSUES") }
func TestAction_EDIT_ISSUES_deny(t *testing.T)          { projectDeny(t, "EDIT_ISSUES") }
func TestAction_DELETE_ISSUES_allow(t *testing.T)       { projectAllow(t, "DELETE_ISSUES") }
func TestAction_DELETE_ISSUES_deny(t *testing.T)        { projectDeny(t, "DELETE_ISSUES") }
func TestAction_ASSIGN_ISSUES_allow(t *testing.T)       { projectAllow(t, "ASSIGN_ISSUES") }
func TestAction_ASSIGN_ISSUES_deny(t *testing.T)        { projectDeny(t, "ASSIGN_ISSUES") }
func TestAction_ASSIGNABLE_USER_allow(t *testing.T)     { projectAllow(t, "ASSIGNABLE_USER") }
func TestAction_ASSIGNABLE_USER_deny(t *testing.T)      { projectDeny(t, "ASSIGNABLE_USER") }
func TestAction_TRANSITION_ISSUES_allow(t *testing.T)   { projectAllow(t, "TRANSITION_ISSUES") }
func TestAction_TRANSITION_ISSUES_deny(t *testing.T)    { projectDeny(t, "TRANSITION_ISSUES") }
func TestAction_RESOLVE_ISSUES_allow(t *testing.T)      { projectAllow(t, "RESOLVE_ISSUES") }
func TestAction_RESOLVE_ISSUES_deny(t *testing.T)       { projectDeny(t, "RESOLVE_ISSUES") }
func TestAction_CLOSE_ISSUES_allow(t *testing.T)        { projectAllow(t, "CLOSE_ISSUES") }
func TestAction_CLOSE_ISSUES_deny(t *testing.T)         { projectDeny(t, "CLOSE_ISSUES") }
func TestAction_MOVE_ISSUES_allow(t *testing.T)         { projectAllow(t, "MOVE_ISSUES") }
func TestAction_MOVE_ISSUES_deny(t *testing.T)          { projectDeny(t, "MOVE_ISSUES") }
func TestAction_LINK_ISSUES_allow(t *testing.T)         { projectAllow(t, "LINK_ISSUES") }
func TestAction_LINK_ISSUES_deny(t *testing.T)          { projectDeny(t, "LINK_ISSUES") }
func TestAction_ADD_COMMENTS_allow(t *testing.T)        { projectAllow(t, "ADD_COMMENTS") }
func TestAction_ADD_COMMENTS_deny(t *testing.T)         { projectDeny(t, "ADD_COMMENTS") }
func TestAction_EDIT_ALL_COMMENTS_allow(t *testing.T)   { projectAllow(t, "EDIT_ALL_COMMENTS") }
func TestAction_EDIT_ALL_COMMENTS_deny(t *testing.T)    { projectDeny(t, "EDIT_ALL_COMMENTS") }
func TestAction_DELETE_ALL_COMMENTS_allow(t *testing.T) { projectAllow(t, "DELETE_ALL_COMMENTS") }
func TestAction_DELETE_ALL_COMMENTS_deny(t *testing.T)  { projectDeny(t, "DELETE_ALL_COMMENTS") }
func TestAction_CREATE_ATTACHMENTS_allow(t *testing.T)  { projectAllow(t, "CREATE_ATTACHMENTS") }
func TestAction_CREATE_ATTACHMENTS_deny(t *testing.T)   { projectDeny(t, "CREATE_ATTACHMENTS") }
func TestAction_WORK_ON_ISSUES_allow(t *testing.T)      { projectAllow(t, "WORK_ON_ISSUES") }
func TestAction_WORK_ON_ISSUES_deny(t *testing.T)       { projectDeny(t, "WORK_ON_ISSUES") }
func TestAction_MANAGE_WATCHERS_allow(t *testing.T)     { projectAllow(t, "MANAGE_WATCHERS") }
func TestAction_MANAGE_WATCHERS_deny(t *testing.T)      { projectDeny(t, "MANAGE_WATCHERS") }
func TestAction_VIEW_VOTERS_AND_WATCHERS_allow(t *testing.T) {
	projectAllow(t, "VIEW_VOTERS_AND_WATCHERS")
}
func TestAction_VIEW_VOTERS_AND_WATCHERS_deny(t *testing.T) {
	projectDeny(t, "VIEW_VOTERS_AND_WATCHERS")
}
func TestAction_SCHEDULE_ISSUES_allow(t *testing.T)    { projectAllow(t, "SCHEDULE_ISSUES") }
func TestAction_SCHEDULE_ISSUES_deny(t *testing.T)     { projectDeny(t, "SCHEDULE_ISSUES") }
func TestAction_SET_ISSUE_SECURITY_allow(t *testing.T) { projectAllow(t, "SET_ISSUE_SECURITY") }
func TestAction_SET_ISSUE_SECURITY_deny(t *testing.T)  { projectDeny(t, "SET_ISSUE_SECURITY") }
func TestAction_MANAGE_SPRINTS_PERMISSION_allow(t *testing.T) {
	projectAllow(t, "MANAGE_SPRINTS_PERMISSION")
}
func TestAction_MANAGE_SPRINTS_PERMISSION_deny(t *testing.T) {
	projectDeny(t, "MANAGE_SPRINTS_PERMISSION")
}
func TestAction_ADMINISTER_PROJECTS_allow(t *testing.T)   { projectAllow(t, "ADMINISTER_PROJECTS") }
func TestAction_ADMINISTER_PROJECTS_deny(t *testing.T)    { projectDeny(t, "ADMINISTER_PROJECTS") }
func TestAction_ADMINISTER_allow(t *testing.T)            { globalAllow(t, "ADMINISTER") }
func TestAction_ADMINISTER_deny(t *testing.T)             { globalDeny(t, "ADMINISTER") }
func TestAction_SYSTEM_ADMIN_allow(t *testing.T)          { globalAllow(t, "SYSTEM_ADMIN") }
func TestAction_SYSTEM_ADMIN_deny(t *testing.T)           { globalDeny(t, "SYSTEM_ADMIN") }
func TestAction_USER_PICKER_allow(t *testing.T)           { globalAllow(t, "USER_PICKER") }
func TestAction_USER_PICKER_deny(t *testing.T)            { globalDeny(t, "USER_PICKER") }
func TestAction_CREATE_SHARED_OBJECTS_allow(t *testing.T) { globalAllow(t, "CREATE_SHARED_OBJECTS") }
func TestAction_CREATE_SHARED_OBJECTS_deny(t *testing.T)  { globalDeny(t, "CREATE_SHARED_OBJECTS") }
func TestAction_MANAGE_GROUP_FILTER_SUBSCRIPTIONS_allow(t *testing.T) {
	globalAllow(t, "MANAGE_GROUP_FILTER_SUBSCRIPTIONS")
}
func TestAction_MANAGE_GROUP_FILTER_SUBSCRIPTIONS_deny(t *testing.T) {
	globalDeny(t, "MANAGE_GROUP_FILTER_SUBSCRIPTIONS")
}
func TestAction_BULK_CHANGE_allow(t *testing.T) { globalAllow(t, "BULK_CHANGE") }
func TestAction_BULK_CHANGE_deny(t *testing.T)  { globalDeny(t, "BULK_CHANGE") }
