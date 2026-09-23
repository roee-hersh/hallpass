package bitbucket

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/roee-hersh/hallpass/internal/integration"
	"github.com/roee-hersh/hallpass/internal/integration/itest"
	"github.com/roee-hersh/hallpass/internal/secret"
)

var (
	root = integration.User{Email: "root@example.com"} // global ADMIN
	eve  = integration.User{Email: "eve@example.com"}  // no grants
)

type dcFake struct {
	t  *testing.T
	mu sync.Mutex

	token        string
	users        map[string]map[string]any    // name -> user
	groups       map[string][]string          // name -> groups
	projects     map[string]bool              // key -> public
	repos        map[string]bool              // KEY/slug -> public
	userPerms    map[string]map[string]string // scope -> user name -> permission; scope "admin", "project:KEY", "repo:KEY/slug"
	groupPerms   map[string]map[string]string // scope -> group -> permission
	defaults     map[string]string            // project key -> default permission
	restrictions map[string][]map[string]any
	tokenIsAdmin bool
	groupsDenied bool // more-members answers 403
	status       int
	pageSize     int // when >0, lists are paged this small
}

func newDCFake(t *testing.T) *dcFake {
	return &dcFake{t: t, token: itest.Canary + "httptoken", tokenIsAdmin: true,
		users: map[string]map[string]any{
			"dana": {"name": "dana", "slug": "dana", "emailAddress": "dana@example.com", "displayName": itest.Canary + "Dana", "active": true, "id": 1, "type": "NORMAL"},
			"bob":  {"name": "bob", "slug": "bob", "emailAddress": "Bob@Example.com", "displayName": itest.Canary + "Bob", "active": true, "id": 2, "type": "NORMAL"},
			"root": {"name": "root", "slug": "root", "emailAddress": "root@example.com", "displayName": itest.Canary + "Root", "active": true, "id": 3, "type": "NORMAL"},
			"eve":  {"name": "eve", "slug": "eve", "emailAddress": "eve@example.com", "displayName": itest.Canary + "Eve", "active": true, "id": 4, "type": "NORMAL"},
			// A substring hit on the filter that must not count.
			"danaher": {"name": "danaher", "slug": "danaher", "emailAddress": "dana@example.com.au", "displayName": "x", "active": true, "id": 5, "type": "NORMAL"},
			"off":     {"name": "off", "slug": "off", "emailAddress": "off@example.com", "displayName": "Off", "active": false, "id": 6, "type": "NORMAL"},
		},
		groups:   map[string][]string{"dana": {"developers", "stash-users"}, "bob": {"stash-users"}, "root": {"stash-users"}, "eve": {}, "off": {}},
		projects: map[string]bool{"APP": false, "PUB": true},
		repos:    map[string]bool{"APP/api": false, "APP/open": true, "PUB/docs": false},
		userPerms: map[string]map[string]string{
			"admin":        {"root": "ADMIN"},
			"project:APP":  {"dana": "PROJECT_WRITE"},
			"repo:APP/api": {"bob": "REPO_READ"},
		},
		groupPerms: map[string]map[string]string{
			"project:APP":  {"developers": "PROJECT_READ"},
			"repo:APP/api": {"developers": "REPO_WRITE"},
			"project:PUB":  {"stash-users": "PROJECT_WRITE"},
		},
		defaults: map[string]string{},
		restrictions: map[string][]map[string]any{
			"APP/api": {
				{"id": 1, "type": "read-only", "matcher": map[string]any{"id": "refs/heads/main", "displayId": "main", "type": map[string]any{"id": "BRANCH", "name": "Branch"}}, "users": []map[string]any{{"name": "root"}}, "groups": []string{}, "accessKeys": []any{}},
				{"id": 2, "type": "pull-request-only", "matcher": map[string]any{"id": "release/*", "displayId": "release/*", "type": map[string]any{"id": "PATTERN", "name": "Pattern"}}, "users": []map[string]any{}, "groups": []string{"developers"}, "accessKeys": []any{}},
				{"id": 3, "type": "no-deletes", "matcher": map[string]any{"id": "**", "displayId": "**", "type": map[string]any{"id": "PATTERN", "name": "Pattern"}}, "users": []map[string]any{}, "groups": []string{}},
			},
			// Project-level: inherited by every repository of APP.
			"APP": {
				{"id": 20, "type": "read-only", "matcher": map[string]any{"id": "refs/heads/develop", "displayId": "develop", "type": map[string]any{"id": "BRANCH", "name": "Branch"}}, "users": []map[string]any{{"name": "root"}}, "groups": []string{}},
				// The same restriction Bitbucket may also list on the repository.
				{"id": 1, "type": "read-only", "matcher": map[string]any{"id": "refs/heads/main", "displayId": "main", "type": map[string]any{"id": "BRANCH", "name": "Branch"}}, "users": []map[string]any{{"name": "root"}}, "groups": []string{}},
			},
		},
	}
}

func dcErr(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(fmt.Sprintf(`{"errors":[{"message":"%s %s","exceptionName":"x"}]}`, itest.Canary, msg)))
}

// page writes one page of values honouring start/limit and pageSize. Values
// are sorted so pages are stable across calls.
func (f *dcFake) page(w http.ResponseWriter, r *http.Request, values []map[string]any) {
	sort.Slice(values, func(i, j int) bool {
		a, _ := json.Marshal(values[i])
		b, _ := json.Marshal(values[j])
		return string(a) < string(b)
	})
	start, _ := strconv.Atoi(r.URL.Query().Get("start"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 25
	}
	if f.pageSize > 0 && f.pageSize < limit {
		limit = f.pageSize
	}
	if start > len(values) {
		start = len(values)
	}
	end := start + limit
	if end > len(values) {
		end = len(values)
	}
	body := map[string]any{"start": start, "limit": limit, "size": end - start, "values": values[start:end], "isLastPage": end >= len(values)}
	if end < len(values) {
		body["nextPageStart"] = end
	}
	write(w, body)
}

func (f *dcFake) grantValues(scope string, kind string, filter string) []map[string]any {
	var out []map[string]any
	if kind == "users" {
		for name, perm := range f.userPerms[scope] {
			if filter != "" && !strings.Contains(name, filter) {
				continue
			}
			out = append(out, map[string]any{"permission": perm, "user": f.users[name]})
		}
		// A substring hit that must not count when the filter is "dana".
		if scope == "repo:APP/api" && strings.Contains("danaher", filter) {
			out = append(out, map[string]any{"permission": "REPO_ADMIN", "user": f.users["danaher"]})
		}
		return out
	}
	for g, perm := range f.groupPerms[scope] {
		out = append(out, map[string]any{"permission": perm, "group": map[string]any{"name": g}})
	}
	return out
}

func (f *dcFake) api(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer "+f.token {
		w.WriteHeader(401)
		return
	}
	if f.status != 0 {
		dcErr(w, f.status, "injected")
		return
	}
	p, q := r.URL.Path, r.URL.Query()
	switch {
	case p == dcAPI+"/application-properties":
		write(w, map[string]any{"version": "8.19.0", "displayName": "Bitbucket", "buildNumber": "8019000"})
	case p == dcAPI+"/users":
		filter := q.Get("filter")
		var values []map[string]any
		for _, u := range f.users {
			if strings.Contains(strings.ToLower(u["emailAddress"].(string)), strings.ToLower(filter)) || strings.Contains(u["name"].(string), filter) {
				values = append(values, u)
			}
		}
		if filter == "dup@example.com" {
			values = append(values, map[string]any{"name": "dup1", "emailAddress": "dup@example.com"}, map[string]any{"name": "dup2", "emailAddress": "DUP@example.com"})
		}
		f.page(w, r, values)
	case p == dcAPI+"/admin/users/more-members":
		if f.groupsDenied {
			dcErr(w, 403, "LICENSED_USER required")
			return
		}
		var values []map[string]any
		for _, g := range f.groups[q.Get("context")] {
			values = append(values, map[string]any{"name": g})
		}
		f.page(w, r, values)
	case strings.HasPrefix(p, dcAPI+"/admin/permissions/"):
		if !f.tokenIsAdmin {
			dcErr(w, 403, "ADMIN required")
			return
		}
		f.page(w, r, f.grantValues("admin", strings.TrimPrefix(p, dcAPI+"/admin/permissions/"), q.Get("filter")))
	case strings.HasPrefix(p, dcAPI+"/projects/"):
		rest := strings.TrimPrefix(p, dcAPI+"/projects/")
		key, sub, _ := strings.Cut(rest, "/")
		public, ok := f.projects[key]
		if !ok {
			dcErr(w, 404, "no project")
			return
		}
		switch {
		case sub == "":
			write(w, map[string]any{"key": key, "id": 7, "name": itest.Canary, "public": public, "type": "NORMAL"})
		case sub == "permissions/users" || sub == "permissions/groups":
			f.page(w, r, f.grantValues("project:"+key, strings.TrimPrefix(sub, "permissions/"), q.Get("filter")))
		case strings.HasPrefix(sub, "permissions/") && strings.HasSuffix(sub, "/all"):
			perm := strings.TrimSuffix(strings.TrimPrefix(sub, "permissions/"), "/all")
			write(w, map[string]any{"permitted": f.defaults[key] == perm})
		case strings.HasPrefix(sub, "repos/"):
			slug, rsub, _ := strings.Cut(strings.TrimPrefix(sub, "repos/"), "/")
			rpublic, ok := f.repos[key+"/"+slug]
			if !ok {
				dcErr(w, 404, "no repo")
				return
			}
			switch rsub {
			case "":
				write(w, map[string]any{"slug": slug, "id": 9, "name": itest.Canary, "public": rpublic, "project": map[string]any{"key": key}})
			case "permissions/users", "permissions/groups":
				f.page(w, r, f.grantValues("repo:"+key+"/"+slug, strings.TrimPrefix(rsub, "permissions/"), q.Get("filter")))
			default:
				dcErr(w, 404, "no route")
			}
		default:
			dcErr(w, 404, "no route")
		}
	case strings.HasPrefix(p, "/rest/branch-permissions/2.0/projects/"):
		rest := strings.TrimPrefix(p, "/rest/branch-permissions/2.0/projects/")
		parts := strings.Split(rest, "/")
		switch {
		case len(parts) == 2 && parts[1] == "restrictions":
			if _, ok := f.projects[parts[0]]; !ok {
				dcErr(w, 404, "no project")
				return
			}
			f.page(w, r, f.restrictions[parts[0]])
		case len(parts) == 4 && parts[1] == "repos" && parts[3] == "restrictions":
			key := parts[0] + "/" + parts[2]
			if _, ok := f.repos[key]; !ok {
				dcErr(w, 404, "no repo")
				return
			}
			f.page(w, r, f.restrictions[key])
		default:
			dcErr(w, 404, "no route")
		}
	default:
		f.t.Errorf("dc fake: no route for %s %s", r.Method, p)
		dcErr(w, 404, "no route")
	}
}

func setupDC(t *testing.T, values map[string]string) (*itest.Server, *dcFake, integration.Connection) {
	t.Helper()
	srv := itest.NewServer(t)
	f := newDCFake(t)
	srv.Handle("GET", "/rest/*", f.api)
	deps, _ := itest.Deps(t, srv)
	v := map[string]string{"url": srv.URL, "edition": editionDataCenter}
	for k, val := range values {
		v[k] = val
	}
	s := itest.Settings("bbdc", "bitbucket", v, map[string]secret.Secret{"credential": secret.Literal(f.token)})
	c, err := (Integration{}).New(context.Background(), s, deps)
	if err != nil {
		t.Fatal(err)
	}
	return srv, f, c
}

func TestDCIdentity(t *testing.T) {
	srv, f, c := setupDC(t, nil)
	conn := c.(*Connection)
	id, err := conn.ResolveIdentity(context.Background(), integration.User{Email: " Dana@Example.com "})
	if err != nil {
		t.Fatal(err)
	}
	if id.ID != "dana" || id.Attr("active") != "true" || strings.Join(id.Groups, ",") != "developers,stash-users" {
		t.Errorf("identity %+v", id)
	}
	if last := srv.Calls()[0]; last.Path != dcAPI+"/users" || last.Query.Get("filter") != "dana@example.com" || last.Query.Get("limit") != "100" {
		t.Errorf("lookup %s %v", last.Path, last.Query)
	}
	// bob's address differs in case only.
	if id, err := conn.ResolveIdentity(context.Background(), bob); err != nil || id.ID != "bob" {
		t.Errorf("bob: %+v %v", id, err)
	}
	expect(t, check(t, c, integration.User{Email: "nobody@example.com"}, "workspace.member", "workspace"), integration.CodeUserNotFound, "")
	expect(t, check(t, c, integration.User{Email: "dup@example.com"}, "workspace.member", "workspace"), integration.CodeUserAmbiguous, "")
	expect(t, check(t, c, integration.User{Email: "off@example.com"}, "repo.read", "repo:APP/open"), integration.CodeDenied, "deactivated")
	// Groups unreadable: the identity still resolves, marked.
	f.mu.Lock()
	f.groupsDenied = true
	f.mu.Unlock()
	id, err = conn.ResolveIdentity(context.Background(), dana)
	if err != nil || id.Attr("groups") != "unavailable" || len(id.Groups) != 0 {
		t.Errorf("identity without groups %+v %v", id, err)
	}
	var lookup itest.Call
	for _, call := range srv.Calls() {
		if call.Path == dcAPI+"/admin/users/more-members" {
			lookup = call
		}
	}
	if lookup.Query.Get("context") != "dana" {
		t.Errorf("groups lookup %v", lookup.Query)
	}
}

func TestDCRepo(t *testing.T) {
	_, f, c := setupDC(t, nil)
	expect(t, check(t, c, bob, "repo.read", "repo:APP/api"), integration.CodeAllowed, "REPO_READ granted directly")
	expect(t, check(t, c, dana, "repo.push", "repo:APP/api"), integration.CodeAllowed, "REPO_WRITE via group developers")
	expect(t, check(t, c, bob, "repo.push", "repo:APP/api"), integration.CodeDenied, "has read, needs write")
	expect(t, check(t, c, eve, "repo.read", "repo:APP/api"), integration.CodeDenied, "has none, needs read")
	// Project grants reach the repository; public repositories are readable.
	expect(t, check(t, c, dana, "repo.push", "repo:APP/open"), integration.CodeAllowed, "PROJECT_WRITE granted directly on project APP")
	expect(t, check(t, c, eve, "repo.read", "repo:APP/open"), integration.CodeAllowed, "public repository")
	expect(t, check(t, c, eve, "repo.push", "repo:APP/open"), integration.CodeDenied, "")
	// The global administrator has admin everywhere.
	expect(t, check(t, c, root, "repo.admin", "repo:APP/api"), integration.CodeAllowed, "ADMIN granted directly globally")
	expect(t, check(t, c, dana, "repo.admin", "repo:APP/api"), integration.CodeDenied, "has write, needs admin")
	// Default project permission.
	f.mu.Lock()
	f.defaults["APP"] = "PROJECT_READ"
	f.mu.Unlock()
	expect(t, check(t, c, eve, "repo.read", "repo:APP/api"), integration.CodeAllowed, "PROJECT_READ is the project default")
	// Missing objects are unknown.
	expect(t, check(t, c, dana, "repo.read", "repo:APP/nope"), integration.CodeResourceNotVisible, "")
	expect(t, check(t, c, dana, "repo.read", "repo:NOPE/api"), integration.CodeResourceNotVisible, "")
}

func TestDCBranches(t *testing.T) {
	_, f, c := setupDC(t, nil)
	// read-only on main exempts root only.
	expect(t, check(t, c, dana, "repo.push", "repo:APP/api@main"), integration.CodeDenied, "read-only restriction on main")
	expect(t, check(t, c, dana, "pr.merge", "repo:APP/api@main"), integration.CodeDenied, "read-only restriction")
	expect(t, check(t, c, root, "repo.push", "repo:APP/api@main"), integration.CodeAllowed, "no branch permission stops main")
	// pull-request-only on release/* exempts the developers group; it does
	// not stop merges.
	expect(t, check(t, c, dana, "repo.push", "repo:APP/api@release/2.0"), integration.CodeAllowed, "")
	expect(t, check(t, c, root, "repo.push", "repo:APP/api@release/2.0"), integration.CodeDenied, "pull-request-only restriction")
	expect(t, check(t, c, root, "pr.merge", "repo:APP/api@release/2.0"), integration.CodeAllowed, "")
	// no-deletes never stops a push.
	expect(t, check(t, c, dana, "repo.push", "repo:APP/api@feature/x"), integration.CodeAllowed, "")
	// A project-level restriction applies to the repository too.
	expect(t, check(t, c, dana, "repo.push", "repo:APP/api@develop"), integration.CodeDenied, "read-only restriction on develop")
	expect(t, check(t, c, root, "repo.push", "repo:APP/api@develop"), integration.CodeAllowed, "")
	// A slash-less pattern against a nested branch is ambiguous.
	f.mu.Lock()
	f.restrictions["APP"] = append(f.restrictions["APP"], map[string]any{"id": 21, "type": "read-only", "matcher": map[string]any{"id": "hotfix", "displayId": "hotfix", "type": map[string]any{"id": "PATTERN", "name": "Pattern"}}, "users": []map[string]any{}, "groups": []string{}})
	f.mu.Unlock()
	expect(t, check(t, c, dana, "repo.push", "repo:APP/api@release/hotfix"), integration.CodeUnsupported, `pattern "hotfix"`)
	expect(t, check(t, c, dana, "repo.push", "repo:APP/api@hotfix"), integration.CodeDenied, "")
	f.mu.Lock()
	f.restrictions["APP"] = f.restrictions["APP"][:2]
	f.mu.Unlock()
	// Without the user's groups a group exemption is unresolvable.
	f.mu.Lock()
	f.groupsDenied = true
	f.mu.Unlock()
	expect(t, check(t, c, root, "repo.push", "repo:APP/api@release/2.0"), integration.CodeUnsupported, "could not list the groups")
	// Ant-style: "release/*" does not reach a nested branch.
	f.mu.Lock()
	f.groupsDenied = false
	f.mu.Unlock()
	expect(t, check(t, c, root, "repo.push", "repo:APP/api@release/2.0/fix"), integration.CodeAllowed, "")
	// An all-branches restriction matches everything.
	f.mu.Lock()
	f.restrictions["APP/api"] = append(f.restrictions["APP/api"], map[string]any{"id": 9, "type": "read-only", "matcher": map[string]any{"id": "ANY_REF_MATCHER_ID", "displayId": "ANY_REF_MATCHER_ID", "type": map[string]any{"id": "ANY_REF", "name": "Any branch"}}, "users": []map[string]any{{"name": "dana"}}, "groups": []string{}})
	f.mu.Unlock()
	expect(t, check(t, c, root, "repo.push", "repo:APP/api@feature/x"), integration.CodeDenied, "read-only restriction on ANY_REF_MATCHER_ID")
	expect(t, check(t, c, dana, "repo.push", "repo:APP/api@feature/x"), integration.CodeAllowed, "")
	f.mu.Lock()
	f.restrictions["APP/api"] = f.restrictions["APP/api"][:3]
	f.mu.Unlock()
	// Branching-model matchers are unknown.
	f.mu.Lock()
	f.groupsDenied = false
	f.restrictions["APP/api"] = append(f.restrictions["APP/api"], map[string]any{"id": 4, "type": "read-only", "matcher": map[string]any{"id": "PRODUCTION", "displayId": "Production", "type": map[string]any{"id": "MODEL_CATEGORY"}}, "users": []any{}, "groups": []any{}})
	f.mu.Unlock()
	expect(t, check(t, c, dana, "repo.push", "repo:APP/api@feature/x"), integration.CodeUnsupported, "branching model matcher MODEL_CATEGORY")
}

func TestDCProjectAndInstance(t *testing.T) {
	_, f, c := setupDC(t, nil)
	expect(t, check(t, c, dana, "project.read", "project:APP"), integration.CodeAllowed, "")
	expect(t, check(t, c, dana, "project.write", "project:APP"), integration.CodeAllowed, "PROJECT_WRITE granted directly")
	expect(t, check(t, c, eve, "project.read", "project:APP"), integration.CodeDenied, "has none, needs read")
	expect(t, check(t, c, eve, "project.read", "project:PUB"), integration.CodeAllowed, "public project")
	expect(t, check(t, c, bob, "project.write", "project:PUB"), integration.CodeAllowed, "via group stash-users")
	expect(t, check(t, c, root, "project.admin", "project:APP"), integration.CodeAllowed, "globally")
	expect(t, check(t, c, dana, "project.admin", "project:APP"), integration.CodeDenied, "has write, needs admin")
	// repo.create needs admin on Data Center (see the UNVERIFIED note).
	expect(t, check(t, c, root, "repo.create", "project:APP"), integration.CodeAllowed, "")
	expect(t, check(t, c, dana, "repo.create", "project:APP"), integration.CodeDenied, "needs admin")
	expect(t, check(t, c, dana, "project.read", "project:NOPE"), integration.CodeResourceNotVisible, "")
	// Instance.
	expect(t, check(t, c, dana, "workspace.member", "workspace"), integration.CodeAllowed, "active user")
	expect(t, check(t, c, root, "workspace.admin", "workspace"), integration.CodeAllowed, "global administrator")
	expect(t, check(t, c, dana, "workspace.admin", "workspace"), integration.CodeDenied, "no global administrator permission")
	// A token without ADMIN cannot see global permissions: unknown where
	// they would matter, and the probe warns.
	f.mu.Lock()
	f.tokenIsAdmin = false
	f.mu.Unlock()
	expect(t, check(t, c, dana, "workspace.admin", "workspace"), integration.CodeCredentialRejected, "needs ADMIN")
	expect(t, check(t, c, root, "repo.admin", "repo:APP/api"), integration.CodeUnsupported, "global permissions (not readable without ADMIN)")
	expect(t, check(t, c, bob, "repo.read", "repo:APP/api"), integration.CodeAllowed, "")
	r, err := c.Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.Summary, "Bitbucket 8.19.0") || !strings.Contains(strings.Join(r.Warnings, "\n"), "lacks ADMIN") {
		t.Errorf("probe %q %q", r.Summary, r.Warnings)
	}
	// Groups unreadable and a group grant that would matter.
	f.mu.Lock()
	f.tokenIsAdmin = true
	f.groupsDenied = true
	f.mu.Unlock()
	// dana still has PROJECT_WRITE directly; eve's only hope is a group.
	expect(t, check(t, c, dana, "repo.push", "repo:APP/api"), integration.CodeAllowed, "PROJECT_WRITE granted directly")
	expect(t, check(t, c, eve, "repo.push", "repo:APP/api"), integration.CodeUnsupported, "REPO_WRITE of group developers")
	expect(t, check(t, c, bob, "repo.read", "repo:APP/api"), integration.CodeAllowed, "")
}

func TestDCPaging(t *testing.T) {
	srv, f, c := setupDC(t, nil)
	f.mu.Lock()
	f.pageSize = 1
	f.mu.Unlock()
	expect(t, check(t, c, dana, "repo.push", "repo:APP/api"), integration.CodeAllowed, "via group developers")
	pages := 0
	for _, call := range srv.Calls() {
		if call.Path == dcAPI+"/admin/users/more-members" {
			pages++
		}
	}
	if pages != 2 {
		t.Errorf("groups read in %d pages, want 2", pages)
	}
}

func TestDCRejectsBadResources(t *testing.T) {
	srv, _, c := setupDC(t, nil)
	expect(t, check(t, c, bob, "repo.read", "repo:APP/api"), integration.CodeAllowed, "")
	n := len(srv.Calls())
	for _, res := range []string{"repo:api", "repo:APP/api/x", "repo:APP/", "repo:/api", "repo:APP/a b", "repo:APP/api@a..b"} {
		d := check(t, c, bob, "repo.read", res)
		if d.Code != integration.CodeInvalidRequest {
			t.Errorf("%s: %s (%s)", res, d.Code, d.Text)
		}
	}
	extra := 0
	for _, call := range srv.Calls()[n:] {
		if call.Path != dcAPI+"/users" && call.Path != dcAPI+"/admin/users/more-members" {
			extra++
		}
	}
	if extra != 0 {
		t.Errorf("%d calls reached the upstream for rejected resources", extra)
	}
}

func TestDCFailures(t *testing.T) {
	srv, _, c := setupDC(t, nil)
	expect(t, check(t, c, bob, "repo.read", "repo:APP/api"), integration.CodeAllowed, "")
	itest.FailureCases(t, srv, func() integration.Decision {
		return check(t, c, bob, "repo.read", "repo:APP/api")
	})
	// Bodies decode as JSON with the canary in every message.
	var e map[string]any
	if err := json.Unmarshal([]byte(`{"errors":[{"message":"x"}]}`), &e); err != nil {
		t.Fatal(err)
	}
}
