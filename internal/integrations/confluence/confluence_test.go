package confluence

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/roee-hersh/hallpass/internal/catalog"
	"github.com/roee-hersh/hallpass/internal/integration"
	"github.com/roee-hersh/hallpass/internal/integration/itest"
	"github.com/roee-hersh/hallpass/internal/integrations/jira"
	"github.com/roee-hersh/hallpass/internal/secret"
)

const cloudID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

type principal struct{ typ, id string }
type grant struct {
	principal  principal
	op, target string
}
type group struct{ id, name string }

// fakeSite is one fake Atlassian site serving Jira's user search (for the
// identity connection) and Confluence's content, space and group APIs.
type fakeSite struct {
	t            *testing.T
	confMode     string
	users        []map[string]any
	content      map[string]map[string][]string // id -> accountId -> operations
	spaces       map[string]string              // key -> id
	spaceGrants  map[string][]grant             // space id -> grants
	memberships  map[string][]group             // accountId -> groups
	pageSize     int
	checkStatus  int // injected status for the content permission check
	permPages    int
	memberPages  int
	permCalls    int
	memberofCall int
}

func newFake(t *testing.T) *fakeSite {
	dana := principal{"user", "acc-dana"}
	f := &fakeSite{
		t: t, confMode: jira.ModeBasic, pageSize: 1,
		users: []map[string]any{
			{"accountId": "acc-dana", "accountType": "atlassian", "active": true, "emailAddress": "dana@example.com", "displayName": "Dana"},
			{"accountId": "acc-bob", "accountType": "atlassian", "active": true, "emailAddress": "bob@example.com", "displayName": "Bob"},
		},
		content: map[string]map[string][]string{
			"100": {"acc-dana": {"read", "update", "delete"}, "acc-bob": {"read"}},
			"200": {"acc-dana": {"read", "update", "delete"}},
		},
		spaces: map[string]string{"DEV": "98307", "OPS": "98308"},
		memberships: map[string][]group{
			"acc-dana": {{"grp-a", "alpha"}, {"grp-b", "beta"}, {"grp-eng", "engineering"}},
			"acc-bob":  {{"grp-x", "xray"}},
		},
	}
	var dev []grant
	for _, g := range []grant{
		{op: "read", target: "space"}, {op: "create", target: "page"}, {op: "create", target: "blogpost"},
		{op: "create", target: "comment"}, {op: "create", target: "attachment"}, {op: "export", target: "space"},
		{op: "restrict_content", target: "space"}, {op: "administer", target: "space"},
	} {
		g.principal = dana
		dev = append(dev, g)
	}
	dev = append(dev,
		grant{principal{"group", "grp-eng"}, "read", "space"},
		grant{principal{"group", "grp-eng"}, "create", "page"},
		grant{principal{"group", "grp-x"}, "read", "space"},
	)
	f.spaceGrants = map[string][]grant{
		"98307": dev,
		"98308": {
			{principal{"group", "grp-ops"}, "create", "page"},
			{principal{"group", "grp-ops"}, "read", "space"},
			{principal{"role", "site-admins"}, "administer", "space"},
			{principal{"role", "site-admins"}, "read", "space"},
			{principal{"user", "acc-bob"}, "read", "space"},
		},
	}
	return f
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func basic(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

func (f *fakeSite) handler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if path == "/_edge/tenant_info" {
		writeJSON(w, 200, map[string]string{"cloudId": cloudID})
		return
	}
	// Jira side: the identity connection always uses basic auth.
	if path == "/rest/api/3/user/search" {
		if r.Header.Get("Authorization") != basic("jirabot@example.com", itest.Canary+"jira") {
			writeJSON(w, 401, map[string]any{"errorMessages": []string{"unauthorized " + itest.Canary}})
			return
		}
		q := strings.ToLower(r.URL.Query().Get("query"))
		out := []map[string]any{}
		for _, u := range f.users {
			if strings.Contains(strings.ToLower(u["emailAddress"].(string)), q) {
				out = append(out, u)
			}
		}
		writeJSON(w, 200, out)
		return
	}
	// Confluence side.
	if f.confMode != jira.ModeBasic {
		prefix := "/ex/confluence/" + cloudID
		if !strings.HasPrefix(path, prefix+"/wiki/") {
			f.t.Errorf("token mode request outside the gateway: %s", path)
			w.WriteHeader(404)
			return
		}
		path = strings.TrimPrefix(path, prefix)
	}
	wantAuth := basic("confbot@example.com", itest.Canary+"conf")
	if f.confMode == jira.ModeScopedToken {
		wantAuth = "Bearer " + itest.Canary + "scoped"
	}
	if r.Header.Get("Authorization") != wantAuth {
		writeJSON(w, 401, map[string]any{"message": "unauthorized " + itest.Canary})
		return
	}
	switch {
	case strings.HasPrefix(path, "/wiki/rest/api/content/") && strings.HasSuffix(path, "/permission/check") && r.Method == "POST":
		if f.checkStatus != 0 {
			writeJSON(w, f.checkStatus, map[string]any{"message": "injected " + itest.Canary})
			return
		}
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/wiki/rest/api/content/"), "/permission/check")
		perms, ok := f.content[id]
		if !ok {
			writeJSON(w, 404, map[string]any{"message": "No content found with id: " + id})
			return
		}
		var req permissionCheckRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Subject.Type != "user" {
			f.t.Errorf("subject type %q", req.Subject.Type)
		}
		has := false
		for _, op := range perms[req.Subject.Identifier] {
			if op == req.Operation {
				has = true
			}
		}
		out := map[string]any{"hasPermission": has, "errors": []any{}}
		if !has {
			out["errors"] = []any{map[string]any{"message": map[string]any{"key": "no.permission", "args": []any{}}}}
		}
		writeJSON(w, 200, out)
	case path == "/wiki/api/v2/spaces":
		key := r.URL.Query().Get("keys")
		results := []map[string]any{}
		if id, ok := f.spaces[key]; ok {
			results = append(results, map[string]any{"id": id, "key": key, "name": "Space " + key})
		}
		writeJSON(w, 200, map[string]any{"results": results, "_links": map[string]any{}})
	case strings.HasPrefix(path, "/wiki/api/v2/spaces/") && strings.HasSuffix(path, "/permissions"):
		f.permCalls++
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/wiki/api/v2/spaces/"), "/permissions")
		grants, ok := f.spaceGrants[id]
		if !ok {
			writeJSON(w, 404, map[string]any{"message": "not found"})
			return
		}
		cursor, _ := strconv.Atoi(r.URL.Query().Get("cursor"))
		end := cursor + f.pageSize
		if end > len(grants) {
			end = len(grants)
		}
		results := []map[string]any{}
		for i, g := range grants[cursor:end] {
			results = append(results, map[string]any{
				"id":        strconv.Itoa(cursor + i),
				"principal": map[string]any{"type": g.principal.typ, "id": g.principal.id},
				"operation": map[string]any{"key": g.op, "targetType": g.target},
			})
		}
		links := map[string]any{}
		if end < len(grants) {
			f.permPages++
			links["next"] = fmt.Sprintf("/wiki/api/v2/spaces/%s/permissions?cursor=%d&limit=%d", id, end, f.pageSize)
		}
		writeJSON(w, 200, map[string]any{"results": results, "_links": links})
	case path == "/wiki/rest/api/user/memberof":
		f.memberofCall++
		acc := r.URL.Query().Get("accountId")
		groups := f.memberships[acc]
		start, _ := strconv.Atoi(r.URL.Query().Get("start"))
		end := start + f.pageSize
		if end > len(groups) {
			end = len(groups)
		}
		results := []map[string]any{}
		for _, g := range groups[start:end] {
			results = append(results, map[string]any{"type": "group", "id": g.id, "name": g.name})
		}
		links := map[string]any{"base": "https://example.atlassian.net/wiki"}
		if end < len(groups) {
			f.memberPages++
			// v1 links are relative to {url}/wiki
			links["next"] = fmt.Sprintf("/rest/api/user/memberof?accountId=%s&start=%d&limit=%d", acc, end, f.pageSize)
		}
		writeJSON(w, 200, map[string]any{"results": results, "start": start, "limit": f.pageSize, "size": len(results), "_links": links})
	case path == "/wiki/rest/api/user/current":
		writeJSON(w, 200, map[string]any{"type": "known", "accountId": "acc-confbot", "displayName": "confluence bot"})
	default:
		writeJSON(w, 404, map[string]string{"message": "no route " + path})
	}
}

// setup wires a jira connection and a confluence connection against one
// fake site. withIdentity false leaves identity_connection unset.
func setup(t *testing.T, f *fakeSite, withIdentity bool) (*itest.Server, integration.Connection) {
	t.Helper()
	srv := itest.NewServer(t)
	srv.Handle("", "*", f.handler)
	deps, _ := itest.Deps(t, srv)
	oldGW, oldTok := jira.Gateway, jira.TokenURL
	jira.Gateway, jira.TokenURL = srv.URL, srv.URL+"/oauth/token"
	t.Cleanup(func() { jira.Gateway, jira.TokenURL = oldGW, oldTok })

	js := itest.Settings("jira-1", "jira", map[string]string{"url": srv.URL, "auth_mode": "basic", "username": "jirabot@example.com", "strict_email_match": "true"},
		map[string]secret.Secret{"credential": itest.Literal("jira")})
	jc, err := jira.Integration{}.New(context.Background(), js, deps)
	if err != nil {
		t.Fatal(err)
	}
	deps.Connection = func(id string) (integration.Connection, error) {
		if id != "jira-1" {
			return nil, fmt.Errorf("no connection %q", id)
		}
		return jc, nil
	}
	values := map[string]string{"url": srv.URL, "auth_mode": f.confMode, "strict_email_match": "true"}
	var cred secret.Secret
	switch f.confMode {
	case jira.ModeBasic:
		values["username"] = "confbot@example.com"
		cred = itest.Literal("conf")
	case jira.ModeScopedToken:
		cred = itest.Literal("scoped")
	}
	if withIdentity {
		values["identity_connection"] = "jira-1"
	}
	cs := itest.Settings("conf-1", "confluence", values, map[string]secret.Secret{"credential": cred})
	c, err := Integration{}.New(context.Background(), cs, deps)
	if err != nil {
		t.Fatal(err)
	}
	if len(srv.Calls()) != 0 {
		t.Fatal("New touched the network")
	}
	return srv, c
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
	var ref bool
	for _, f := range (Integration{}).Fields() {
		if f.Name == "identity_connection" && f.Ref == "jira" && !f.Required {
			ref = true
		}
	}
	if !ref {
		t.Error("identity_connection must be an optional ref to jira")
	}
}

func TestNewRejectsWrongIdentityConnection(t *testing.T) {
	srv := itest.NewServer(t)
	deps, _ := itest.Deps(t, srv)
	deps.Connection = func(string) (integration.Connection, error) { return fakeConn{}, nil }
	s := itest.Settings("c", "confluence", map[string]string{"url": srv.URL, "username": "x@example.com", "identity_connection": "k8s"}, map[string]secret.Secret{"credential": itest.Literal("x")})
	if _, err := (Integration{}).New(context.Background(), s, deps); err == nil || !strings.Contains(err.Error(), "not a jira connection") {
		t.Errorf("err = %v", err)
	}
}

type fakeConn struct{}

func (fakeConn) ResolveIdentity(context.Context, integration.User) (integration.Identity, error) {
	return integration.Identity{}, nil
}
func (fakeConn) Check(context.Context, integration.CheckRequest) (integration.Decision, error) {
	return integration.Decision{}, nil
}
func (fakeConn) Probe(context.Context) (integration.ProbeResult, error) {
	return integration.ProbeResult{}, nil
}

func TestNoIdentityConnection(t *testing.T) {
	srv, c := setup(t, newFake(t), false)
	d := check(t, c, dana, "page.read", "page:100")
	itest.ExpectCode(t, d, integration.CodeUnsupported)
	if !strings.Contains(d.Text, "identity_connection") {
		t.Error(d.Text)
	}
	if len(srv.Calls()) != 0 {
		t.Error("no upstream call expected without an identity")
	}
	r, err := c.Probe(context.Background())
	if err != nil || len(r.Warnings) != 2 || !strings.Contains(r.Warnings[0], "identity_connection") {
		t.Errorf("%+v %v", r, err)
	}
}

func TestContentCheck(t *testing.T) {
	srv, c := setup(t, newFake(t), true)
	d := check(t, c, dana, "page.update", "page:100")
	itest.ExpectCode(t, d, integration.CodeAllowed)
	calls := srv.Calls()
	if len(calls) != 2 || calls[0].Path != "/rest/api/3/user/search" || calls[1].Path != "/wiki/rest/api/content/100/permission/check" || calls[1].Method != "POST" {
		t.Fatalf("calls %+v", calls)
	}
	if !strings.HasPrefix(calls[1].Header.Get("Authorization"), "Basic ") {
		t.Errorf("Authorization %q", calls[1].Header.Get("Authorization"))
	}
	var req permissionCheckRequest
	calls[1].JSON(t, &req)
	if req.Subject.Type != "user" || req.Subject.Identifier != "acc-dana" || req.Operation != "update" {
		t.Errorf("body %s", calls[1].Body)
	}
	itest.ExpectCode(t, check(t, c, bob, "page.update", "page:100"), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, bob, "page.read", "page:100"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, dana, "blogpost.delete", "blogpost:200"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, bob, "blogpost.read", "blogpost:200"), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, dana, "page.read", "page:999"), integration.CodeResourceNotVisible)
	itest.ExpectCode(t, check(t, c, integration.User{Email: "nobody@example.com"}, "page.read", "page:100"), integration.CodeUserNotFound)
}

func TestContentForbidden(t *testing.T) {
	f := newFake(t)
	_, c := setup(t, f, true)
	f.checkStatus = 403
	d := check(t, c, dana, "page.read", "page:100")
	itest.ExpectCode(t, d, integration.CodeCredentialRejected)
	if !strings.Contains(d.Text, "Confluence Administrator") {
		t.Error(d.Text)
	}
}

func TestSpaceUserPrincipal(t *testing.T) {
	f := newFake(t)
	srv, c := setup(t, f, true)
	d := check(t, c, dana, "space.export", "space:DEV")
	itest.ExpectCode(t, d, integration.CodeAllowed)
	if f.memberofCall != 0 {
		t.Error("a direct user grant should not fetch groups")
	}
	var sawSpaces, sawPerms bool
	for _, call := range srv.Calls() {
		switch call.Path {
		case "/wiki/api/v2/spaces":
			sawSpaces = true
			if call.Query.Get("keys") != "DEV" {
				t.Errorf("spaces query %v", call.Query)
			}
		case "/wiki/api/v2/spaces/98307/permissions":
			sawPerms = true
		}
	}
	if !sawSpaces || !sawPerms {
		t.Errorf("calls %+v", srv.Calls())
	}
	itest.ExpectCode(t, check(t, c, dana, "space.export", "space:NOPE"), integration.CodeResourceNotVisible)
}

func TestSpaceGroupPrincipalWithPagination(t *testing.T) {
	f := newFake(t)
	_, c := setup(t, f, true)
	// dana holds create/page on DEV both directly and via grp-eng; remove the
	// direct grants so the group path is what allows.
	var kept []grant
	for _, g := range f.spaceGrants["98307"] {
		if g.principal.typ != "user" {
			kept = append(kept, g)
		}
	}
	f.spaceGrants["98307"] = kept
	d := check(t, c, dana, "page.create", "space:DEV")
	itest.ExpectCode(t, d, integration.CodeAllowed)
	if !strings.Contains(d.Text, "engineering") {
		t.Error(d.Text)
	}
	if f.permPages < 1 || f.memberPages < 2 {
		t.Errorf("expected pagination: permission pages %d, member pages %d", f.permPages, f.memberPages)
	}
	if f.memberofCall < 3 {
		t.Errorf("memberof pages fetched %d, want 3 (grp-eng is the third group)", f.memberofCall)
	}
	// bob is in grp-x, which has read/space but not create/page
	itest.ExpectCode(t, check(t, c, bob, "page.create", "space:DEV"), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, bob, "space.read", "space:DEV"), integration.CodeAllowed)
	// no grant at all for the operation: deny without a group lookup
	f.memberofCall = 0
	itest.ExpectCode(t, check(t, c, bob, "blogpost.create", "space:DEV"), integration.CodeDenied)
	if f.memberofCall != 0 {
		t.Error("no group principal for the operation, so no memberof call expected")
	}
}

func TestSpaceUnknownPrincipal(t *testing.T) {
	f := newFake(t)
	_, c := setup(t, f, true)
	// OPS: administer/space is granted to a role only
	d := check(t, c, dana, "space.admin", "space:OPS")
	itest.ExpectCode(t, d, integration.CodeUnsupported)
	if !strings.Contains(d.Text, "role") {
		t.Error(d.Text)
	}
	// read/space: a role and bob directly; dana is neither -> unsupported, bob -> allow
	itest.ExpectCode(t, check(t, c, dana, "space.read", "space:OPS"), integration.CodeUnsupported)
	itest.ExpectCode(t, check(t, c, bob, "space.read", "space:OPS"), integration.CodeAllowed)
	// create/page: a group dana is not in, no role -> deny
	itest.ExpectCode(t, check(t, c, dana, "page.create", "space:OPS"), integration.CodeDenied)
	// export/space: nothing at all -> deny
	itest.ExpectCode(t, check(t, c, dana, "space.export", "space:OPS"), integration.CodeDenied)
}

func TestSpaceForbidden(t *testing.T) {
	f := newFake(t)
	srv, c := setup(t, f, true)
	srv.JSON("GET", "/wiki/api/v2/spaces/98307/permissions", 403, `{"message":"forbidden"}`)
	itest.ExpectCode(t, check(t, c, dana, "space.export", "space:DEV"), integration.CodeCredentialRejected)
	srv.JSON("GET", "/wiki/api/v2/spaces", 404, `{"message":"gone"}`)
	itest.ExpectCode(t, check(t, c, dana, "space.export", "space:DEV"), integration.CodeResourceNotVisible)
}

func TestScopedTokenBase(t *testing.T) {
	f := newFake(t)
	f.confMode = jira.ModeScopedToken
	srv, c := setup(t, f, true)
	itest.ExpectCode(t, check(t, c, dana, "page.read", "page:100"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, dana, "page.create", "space:DEV"), integration.CodeAllowed)
	tenant := 0
	for _, call := range srv.Calls() {
		switch {
		case call.Path == "/_edge/tenant_info":
			tenant++
		case call.Path == "/rest/api/3/user/search":
		default:
			if !strings.HasPrefix(call.Path, "/ex/confluence/"+cloudID+"/wiki/") || call.Header.Get("Authorization") != "Bearer "+itest.Canary+"scoped" {
				t.Errorf("%s %q", call.Path, call.Header.Get("Authorization"))
			}
		}
	}
	if tenant != 1 {
		t.Errorf("tenant_info called %d times", tenant)
	}
}

func TestNextPath(t *testing.T) {
	cases := map[string]string{
		"": "",
		"/wiki/api/v2/spaces/1/permissions?cursor=x":                    "/wiki/api/v2/spaces/1/permissions?cursor=x",
		"/rest/api/user/memberof?start=1":                               "/wiki/rest/api/user/memberof?start=1",
		"rest/api/user/memberof?start=1":                                "/wiki/rest/api/user/memberof?start=1",
		"https://acme.atlassian.net/wiki/api/v2/x?c=1":                  "/wiki/api/v2/x?c=1",
		"https://api.atlassian.com/ex/confluence/abc/wiki/api/v2/x?c=1": "/wiki/api/v2/x?c=1",
	}
	for in, want := range cases {
		if got := nextPath(in); got != want {
			t.Errorf("nextPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestInvalidRequests(t *testing.T) {
	srv, c := setup(t, newFake(t), true)
	cases := []struct{ action, resource string }{
		{"page.read", "space:DEV"},
		{"page.read", "blogpost:200"},
		{"blogpost.read", "page:100"},
		{"space.read", "page:100"},
		{"page.create", "page:100"},
		{"page.read", "page:abc"},
		{"page.read", "page:0"},
		{"page.read", "page:100/x"},
		{"space.read", "space:bad key"},
		{"space.read", "space:"},
		{"page.read", "global"},
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
	srv, c := setup(t, newFake(t), true)
	itest.FailureCases(t, srv, func() integration.Decision {
		return check(t, c, dana, "page.read", "page:100")
	})
}

func TestFailuresAfterIdentity(t *testing.T) {
	// Identity resolved first, then the Confluence call fails.
	f := newFake(t)
	srv := itest.NewServer(t)
	srv.Handle("", "*", f.handler)
	deps, _ := itest.Deps(t, srv)
	js := itest.Settings("jira-1", "jira", map[string]string{"url": srv.URL, "username": "jirabot@example.com"}, map[string]secret.Secret{"credential": itest.Literal("jira")})
	jc, err := jira.Integration{}.New(context.Background(), js, deps)
	if err != nil {
		t.Fatal(err)
	}
	id, err := jc.ResolveIdentity(context.Background(), dana)
	if err != nil {
		t.Fatal(err)
	}
	deps.Connection = func(string) (integration.Connection, error) { return jc, nil }
	cs := itest.Settings("conf-1", "confluence", map[string]string{"url": srv.URL, "username": "confbot@example.com", "identity_connection": "jira-1"}, map[string]secret.Secret{"credential": itest.Literal("conf")})
	c, err := Integration{}.New(context.Background(), cs, deps)
	if err != nil {
		t.Fatal(err)
	}
	act, _ := integration.FindAction(Integration{}, "space.export")
	itest.FailureCases(t, srv, func() integration.Decision {
		res, _ := catalog.ParseResource("space:DEV")
		d, err := c.Check(context.Background(), integration.CheckRequest{User: dana, Identity: id, Action: act, ActionName: "space.export", Resource: res})
		if err != nil {
			return integration.ToDecision(err)
		}
		return d
	})
}

func TestProbe(t *testing.T) {
	srv, c := setup(t, newFake(t), true)
	r, err := c.Probe(context.Background())
	if err != nil || !strings.Contains(r.Summary, "confluence bot") || len(r.Warnings) != 1 || !strings.Contains(r.Warnings[0], "Confluence Administrator") {
		t.Fatalf("%+v %v", r, err)
	}
	if srv.LastCall().Path != "/wiki/rest/api/user/current" {
		t.Error(srv.LastCall().Path)
	}
	srv.Fail(itest.FailUnauthorized)
	_, err = c.Probe(context.Background())
	srv.Fail(itest.FailNone)
	itest.ExpectCode(t, integration.ToDecision(err), integration.CodeCredentialRejected)
}

// Allow/deny tests per action (coverage gate). Dana holds everything on page
// 100, blog post 200 and space DEV; Bob holds page.read on 100 and, through
// grp-x, space.read on DEV.

func allow(t *testing.T, action, resource string) {
	t.Helper()
	_, c := setup(t, newFake(t), true)
	itest.ExpectCode(t, check(t, c, dana, action, resource), integration.CodeAllowed)
}

func deny(t *testing.T, action, resource string) {
	t.Helper()
	_, c := setup(t, newFake(t), true)
	itest.ExpectCode(t, check(t, c, bob, action, resource), integration.CodeDenied)
}

func TestAction_page_read_allow(t *testing.T)   { allow(t, "page.read", "page:100") }
func TestAction_page_read_deny(t *testing.T)    { deny(t, "page.read", "page:200") }
func TestAction_page_update_allow(t *testing.T) { allow(t, "page.update", "page:100") }
func TestAction_page_update_deny(t *testing.T)  { deny(t, "page.update", "page:100") }
func TestAction_page_delete_allow(t *testing.T) { allow(t, "page.delete", "page:100") }
func TestAction_page_delete_deny(t *testing.T)  { deny(t, "page.delete", "page:100") }
func TestAction_blogpost_read_allow(t *testing.T) {
	allow(t, "blogpost.read", "blogpost:200")
}
func TestAction_blogpost_read_deny(t *testing.T) { deny(t, "blogpost.read", "blogpost:200") }
func TestAction_blogpost_update_allow(t *testing.T) {
	allow(t, "blogpost.update", "blogpost:200")
}
func TestAction_blogpost_update_deny(t *testing.T) {
	deny(t, "blogpost.update", "blogpost:200")
}
func TestAction_blogpost_delete_allow(t *testing.T) {
	allow(t, "blogpost.delete", "blogpost:200")
}
func TestAction_blogpost_delete_deny(t *testing.T) {
	deny(t, "blogpost.delete", "blogpost:200")
}
func TestAction_space_read_allow(t *testing.T) { allow(t, "space.read", "space:DEV") }
func TestAction_space_read_deny(t *testing.T) {
	// DEV grants read/space to grp-x (Bob's group); without it Bob has no read.
	f := newFake(t)
	var kept []grant
	for _, g := range f.spaceGrants["98307"] {
		if g.principal.id != "grp-x" {
			kept = append(kept, g)
		}
	}
	f.spaceGrants["98307"] = kept
	_, c := setup(t, f, true)
	itest.ExpectCode(t, check(t, c, bob, "space.read", "space:DEV"), integration.CodeDenied)
}
func TestAction_page_create_allow(t *testing.T) { allow(t, "page.create", "space:DEV") }
func TestAction_page_create_deny(t *testing.T)  { deny(t, "page.create", "space:DEV") }
func TestAction_blogpost_create_allow(t *testing.T) {
	allow(t, "blogpost.create", "space:DEV")
}
func TestAction_blogpost_create_deny(t *testing.T) { deny(t, "blogpost.create", "space:DEV") }
func TestAction_comment_create_allow(t *testing.T) { allow(t, "comment.create", "space:DEV") }
func TestAction_comment_create_deny(t *testing.T)  { deny(t, "comment.create", "space:DEV") }
func TestAction_attachment_create_allow(t *testing.T) {
	allow(t, "attachment.create", "space:DEV")
}
func TestAction_attachment_create_deny(t *testing.T) {
	deny(t, "attachment.create", "space:DEV")
}
func TestAction_space_export_allow(t *testing.T)  { allow(t, "space.export", "space:DEV") }
func TestAction_space_export_deny(t *testing.T)   { deny(t, "space.export", "space:DEV") }
func TestAction_page_restrict_allow(t *testing.T) { allow(t, "page.restrict", "space:DEV") }
func TestAction_page_restrict_deny(t *testing.T)  { deny(t, "page.restrict", "space:DEV") }
func TestAction_space_admin_allow(t *testing.T)   { allow(t, "space.admin", "space:DEV") }
func TestAction_space_admin_deny(t *testing.T)    { deny(t, "space.admin", "space:DEV") }
