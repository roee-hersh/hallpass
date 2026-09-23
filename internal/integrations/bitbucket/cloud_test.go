package bitbucket

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/roee-hersh/hallpass/internal/integration"
	"github.com/roee-hersh/hallpass/internal/integration/itest"
	"github.com/roee-hersh/hallpass/internal/secret"
)

var (
	dana = integration.User{Email: "dana@example.com"} // write on api, write on APP
	bob  = integration.User{Email: "bob@example.com"}  // read on api, read on APP and DOCS
	ola  = integration.User{Email: "ola@example.com"}  // workspace owner
	cr   = integration.User{Email: "cr@example.com"}   // create-repo on APP, nothing else
	left = integration.User{Email: "left@example.com"} // listed by email, no longer a member
)

type cloudMember struct {
	accountID, uuid, nickname, email string
}

type cloudFake struct {
	t  *testing.T
	mu sync.Mutex

	token          string
	members        map[string]cloudMember       // email -> member
	owners         []string                     // account ids
	repos          map[string]bool              // slug -> is_private
	repoPerms      map[string]map[string]string // slug -> account id -> permission
	restrictions   map[string][]map[string]any  // slug -> restrictions
	projects       map[string]bool              // key -> exists
	projectUsers   map[string]map[string]string // key -> account id -> permission
	projectGroups  map[string]map[string]string // key -> group slug -> permission
	publicProjects map[string]bool              // key -> is_private false
	rejectFilter   bool                         // 400 on q=user.account_id
	status         int                          // when set, every API call fails with it
	filtered       int                          // repository permission calls that carried a user filter
}

func newCloudFake(t *testing.T) *cloudFake {
	return &cloudFake{t: t, token: itest.Canary + "wstoken",
		members: map[string]cloudMember{
			"dana@example.com": {"557058:dana", "{11111111-1111-1111-1111-111111111111}", "dana", "dana@example.com"},
			"bob@example.com":  {"557058:bob", "{22222222-2222-2222-2222-222222222222}", "bobby", "bob@example.com"},
			"ola@example.com":  {"557058:ola", "{33333333-3333-3333-3333-333333333333}", "ola", "ola@example.com"},
			"cr@example.com":   {"557058:cr", "{44444444-4444-4444-4444-444444444444}", "cr", "cr@example.com"},
			"left@example.com": {"557058:left", "{55555555-5555-5555-5555-555555555555}", "left", "left@example.com"},
		},
		owners: []string{"557058:ola"},
		repos:  map[string]bool{"api": true, "site": false},
		repoPerms: map[string]map[string]string{
			"api":  {"557058:dana": "write", "557058:bob": "read", "557058:ola": "admin"},
			"site": {},
		},
		restrictions: map[string][]map[string]any{
			"api": {
				{"id": 1, "kind": "push", "branch_match_kind": "glob", "pattern": "main", "users": []map[string]any{{"account_id": "557058:ola", "uuid": "{33333333-3333-3333-3333-333333333333}", "display_name": itest.Canary}}, "groups": []map[string]any{}},
				{"id": 2, "kind": "push", "branch_match_kind": "glob", "pattern": "release/*", "users": []map[string]any{}, "groups": []map[string]any{{"slug": "developers", "name": itest.Canary}}},
				{"id": 3, "kind": "restrict_merges", "branch_match_kind": "glob", "pattern": "refs/heads/main", "users": []map[string]any{{"account_id": "557058:dana", "uuid": "{11111111-1111-1111-1111-111111111111}"}}, "groups": []map[string]any{}},
				{"id": 4, "kind": "require_approvals_to_merge", "branch_match_kind": "glob", "pattern": "main", "value": 2},
				{"id": 5, "kind": "delete", "branch_match_kind": "glob", "pattern": "*", "users": []map[string]any{}, "groups": []map[string]any{}},
			},
		},
		projects: map[string]bool{"APP": true, "DOCS": true},
		projectUsers: map[string]map[string]string{
			"APP":  {"557058:dana": "write", "557058:bob": "read", "557058:cr": "create-repo"},
			"DOCS": {"557058:bob": "read", "557058:dana": "write"},
		},
		projectGroups: map[string]map[string]string{
			"APP":  {"developers": "admin"},
			"DOCS": {},
		},
	}
}

func cloudErr(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(fmt.Sprintf(`{"type":"error","error":{"message":"%s %s"}}`, itest.Canary, msg)))
}

func write(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (f *cloudFake) user(m cloudMember, withEmail bool) map[string]any {
	u := map[string]any{"type": "user", "account_id": m.accountID, "uuid": m.uuid, "nickname": m.nickname, "display_name": itest.Canary + "name"}
	if withEmail {
		u["email"] = m.email
	}
	return u
}

// paged writes a one-page list, or two pages when the caller asks for
// pagelen=1 on a list longer than one.
func (f *cloudFake) paged(w http.ResponseWriter, r *http.Request, values []map[string]any) {
	page := 1
	_, _ = fmt.Sscanf(r.URL.Query().Get("page"), "%d", &page)
	if r.URL.Query().Get("pagelen") == "1" && len(values) > 1 {
		body := map[string]any{"pagelen": 1, "page": page, "values": values[page-1 : page]}
		if page < len(values) {
			q := r.URL.Query()
			q.Set("page", fmt.Sprint(page+1))
			body["next"] = "https://" + r.Host + r.URL.Path + "?" + q.Encode()
		}
		write(w, body)
		return
	}
	write(w, map[string]any{"pagelen": 100, "page": 1, "values": values})
}

func (f *cloudFake) api(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer "+f.token {
		w.WriteHeader(401)
		return
	}
	if f.status != 0 {
		cloudErr(w, f.status, "injected")
		return
	}
	p, q := r.URL.Path, r.URL.Query()
	const ws = "/2.0/workspaces/acme"
	switch {
	case p == ws:
		write(w, map[string]any{"slug": "acme", "name": "Acme " + itest.Canary, "uuid": "{aaaa}"})
	case p == ws+"/members":
		filter := q.Get("q")
		if !strings.HasPrefix(filter, `user.email IN ("`) || !strings.HasSuffix(filter, `")`) {
			cloudErr(w, 400, "bad filter")
			return
		}
		if !strings.Contains(q.Get("fields"), "values.user.email") {
			f.t.Error("member lookup without the email field")
		}
		email := strings.TrimSuffix(strings.TrimPrefix(filter, `user.email IN ("`), `")`)
		var values []map[string]any
		for e, m := range f.members {
			if strings.EqualFold(e, email) {
				values = append(values, map[string]any{"type": "workspace_membership", "user": f.user(m, true)})
			}
		}
		if email == "dup@example.com" {
			values = append(values, map[string]any{"user": map[string]any{"account_id": "1", "email": "dup@example.com"}}, map[string]any{"user": map[string]any{"account_id": "2", "email": "Dup@example.com"}})
		}
		write(w, map[string]any{"pagelen": 100, "page": 1, "values": values})
	case strings.HasPrefix(p, ws+"/members/"):
		id := strings.TrimPrefix(p, ws+"/members/")
		for _, m := range f.members {
			if m.accountID == id && id != "557058:left" {
				write(w, map[string]any{"user": f.user(m, false)})
				return
			}
		}
		cloudErr(w, 404, "not a member")
	case p == ws+"/permissions":
		if q.Get("q") != `permission="owner"` {
			f.t.Errorf("owner listing filter %q", q.Get("q"))
		}
		var values []map[string]any
		for _, id := range f.owners {
			for _, m := range f.members {
				if m.accountID == id {
					values = append(values, map[string]any{"permission": "owner", "user": f.user(m, false)})
				}
			}
		}
		// A member entry that must not count as owner even if the filter
		// were ignored.
		values = append(values, map[string]any{"permission": "member", "user": f.user(f.members["dana@example.com"], false)})
		f.paged(w, r, values)
	case strings.HasPrefix(p, ws+"/permissions/repositories/"):
		slug := strings.TrimPrefix(p, ws+"/permissions/repositories/")
		perms, ok := f.repoPerms[slug]
		if !ok {
			cloudErr(w, 404, "no repo")
			return
		}
		var only string
		if filter := q.Get("q"); filter != "" {
			if f.rejectFilter {
				cloudErr(w, 400, "bad query")
				return
			}
			if !strings.HasPrefix(filter, `user.account_id="`) {
				f.t.Errorf("repository permission filter %q", filter)
			}
			only = strings.TrimSuffix(strings.TrimPrefix(filter, `user.account_id="`), `"`)
			f.filtered++
		}
		var values []map[string]any
		for _, m := range f.members {
			perm, ok := perms[m.accountID]
			if !ok || (only != "" && only != m.accountID) {
				continue
			}
			values = append(values, map[string]any{"type": "repository_permission", "permission": perm, "user": f.user(m, false), "repository": map[string]any{"name": slug}})
		}
		f.paged(w, r, values)
	case strings.HasPrefix(p, "/2.0/repositories/acme/"):
		rest := strings.TrimPrefix(p, "/2.0/repositories/acme/")
		slug, sub, _ := strings.Cut(rest, "/")
		private, ok := f.repos[slug]
		if !ok {
			cloudErr(w, 404, "You may not have access to this repository or it no longer exists")
			return
		}
		switch sub {
		case "":
			write(w, map[string]any{"slug": slug, "is_private": private, "project": map[string]any{"key": "APP"}, "description": itest.Canary})
		case "branch-restrictions":
			var values []map[string]any
			for _, rs := range f.restrictions[slug] {
				if k := q.Get("kind"); k == "" || k == rs["kind"] {
					values = append(values, rs)
				}
			}
			f.paged(w, r, values)
		default:
			cloudErr(w, 404, "no route")
		}
	case strings.HasPrefix(p, ws+"/projects/"):
		rest := strings.TrimPrefix(p, ws+"/projects/")
		key, sub, _ := strings.Cut(rest, "/")
		if !f.projects[key] {
			cloudErr(w, 404, "no project")
			return
		}
		switch {
		case sub == "":
			write(w, map[string]any{"key": key, "name": itest.Canary, "is_private": !f.publicProjects[key]})
		case strings.HasPrefix(sub, "permissions-config/users/"):
			id := strings.TrimPrefix(sub, "permissions-config/users/")
			perm, ok := f.projectUsers[key][id]
			if !ok {
				perm = "none"
			}
			write(w, map[string]any{"type": "project_user_permission", "permission": perm})
		case sub == "permissions-config/groups":
			var values []map[string]any
			for g, perm := range f.projectGroups[key] {
				values = append(values, map[string]any{"type": "project_group_permission", "permission": perm, "group": map[string]any{"slug": g, "name": itest.Canary}})
			}
			f.paged(w, r, values)
		default:
			cloudErr(w, 404, "no route")
		}
	default:
		f.t.Errorf("cloud fake: no route for %s %s", r.Method, p)
		cloudErr(w, 404, "no route")
	}
}

func cloudSpec(t *testing.T) (itest.Spec, itest.SpecOptions) {
	// The description declares neither pagination nor the q/fields filters
	// on the members list.
	return itest.SpecFromEnv(t, "bitbucket-cloud"), itest.SpecOptions{AllowQuery: []string{"q", "fields", "pagelen", "page", "kind"}}
}

func setupCloud(t *testing.T, values map[string]string) (*itest.Server, *cloudFake, integration.Connection) {
	t.Helper()
	srv := itest.NewServer(t)
	spec, opts := cloudSpec(t)
	srv.UseSpec(spec, opts)
	f := newCloudFake(t)
	srv.Handle("GET", "/2.0/*", f.api)
	deps, _ := itest.Deps(t, srv)
	v := map[string]string{"url": srv.URL, "workspace": "acme"}
	for k, val := range values {
		v[k] = val
	}
	s := itest.Settings("bb", "bitbucket", v, map[string]secret.Secret{"credential": secret.Literal(f.token)})
	c, err := (Integration{}).New(context.Background(), s, deps)
	if err != nil {
		t.Fatal(err)
	}
	return srv, f, c
}

func check(t *testing.T, c integration.Connection, u integration.User, action, resource string) integration.Decision {
	t.Helper()
	return itest.Check(t, c, Integration{}, u, action, resource)
}

func expect(t *testing.T, d integration.Decision, code integration.Code, text string) {
	t.Helper()
	itest.ExpectCode(t, d, code)
	if text != "" && !strings.Contains(d.Text, text) {
		t.Errorf("text %q does not contain %q", d.Text, text)
	}
	itest.AssertNoCanary(t, d.Text)
}

// --- the action table (Cloud) -------------------------------------------------

func TestAction_repo_read_allow(t *testing.T) {
	_, _, c := setupCloud(t, nil)
	expect(t, check(t, c, bob, "repo.read", "repo:api"), integration.CodeAllowed, "has read (needs read)")
	expect(t, check(t, c, cr, "repo.read", "repo:site"), integration.CodeAllowed, "public repository")
}
func TestAction_repo_read_deny(t *testing.T) {
	_, _, c := setupCloud(t, nil)
	expect(t, check(t, c, cr, "repo.read", "repo:api"), integration.CodeDenied, "has none, needs read")
}
func TestAction_repo_push_allow(t *testing.T) {
	_, _, c := setupCloud(t, nil)
	expect(t, check(t, c, dana, "repo.push", "repo:api"), integration.CodeAllowed, "")
	expect(t, check(t, c, dana, "repo.push", "repo:api@feature/x"), integration.CodeAllowed, "no push restriction stops feature/x")
	expect(t, check(t, c, ola, "repo.push", "repo:api@main"), integration.CodeAllowed, "")
}
func TestAction_repo_push_deny(t *testing.T) {
	_, _, c := setupCloud(t, nil)
	expect(t, check(t, c, bob, "repo.push", "repo:api"), integration.CodeDenied, "has read, needs write")
	expect(t, check(t, c, dana, "repo.push", "repo:api@main"), integration.CodeDenied, "push restriction")
	// Write is checked before the branch: no restriction call for a reader.
	expect(t, check(t, c, bob, "repo.push", "repo:api@main"), integration.CodeDenied, "needs write")
}
func TestAction_pr_merge_allow(t *testing.T) {
	_, _, c := setupCloud(t, nil)
	expect(t, check(t, c, dana, "pr.merge", "repo:api@main"), integration.CodeAllowed, "")
	expect(t, check(t, c, dana, "pr.merge", "repo:api"), integration.CodeAllowed, "")
}
func TestAction_pr_merge_deny(t *testing.T) {
	_, _, c := setupCloud(t, nil)
	expect(t, check(t, c, bob, "pr.merge", "repo:api"), integration.CodeDenied, "")
	// The owner has admin but the merge restriction lists only dana.
	expect(t, check(t, c, ola, "pr.merge", "repo:api@main"), integration.CodeDenied, "restrict_merges restriction")
}
func TestAction_repo_admin_allow(t *testing.T) {
	_, _, c := setupCloud(t, nil)
	expect(t, check(t, c, ola, "repo.admin", "repo:api"), integration.CodeAllowed, "")
	// Owners administer every repository, listed or not.
	expect(t, check(t, c, ola, "repo.admin", "repo:site"), integration.CodeAllowed, "workspace owner")
}
func TestAction_repo_admin_deny(t *testing.T) {
	_, _, c := setupCloud(t, nil)
	expect(t, check(t, c, dana, "repo.admin", "repo:api"), integration.CodeDenied, "has write, needs admin")
}
func TestAction_project_read_allow(t *testing.T) {
	_, _, c := setupCloud(t, nil)
	expect(t, check(t, c, bob, "project.read", "project:APP"), integration.CodeAllowed, "has read on project APP directly")
}
func TestAction_project_read_deny(t *testing.T) {
	_, f, c := setupCloud(t, nil)
	expect(t, check(t, c, cr, "project.read", "project:DOCS"), integration.CodeDenied, "has none on project DOCS, needs read")
	// A public project is readable by everyone, but only readable.
	f.mu.Lock()
	f.publicProjects = map[string]bool{"DOCS": true}
	f.mu.Unlock()
	expect(t, check(t, c, cr, "project.read", "project:DOCS"), integration.CodeAllowed, "public")
	expect(t, check(t, c, cr, "project.write", "project:DOCS"), integration.CodeDenied, "")
}
func TestAction_project_write_allow(t *testing.T) {
	_, _, c := setupCloud(t, nil)
	expect(t, check(t, c, dana, "project.write", "project:APP"), integration.CodeAllowed, "")
	// create-repo carries write.
	expect(t, check(t, c, cr, "project.write", "project:APP"), integration.CodeAllowed, "create-repo")
}
func TestAction_project_write_deny(t *testing.T) {
	_, _, c := setupCloud(t, nil)
	expect(t, check(t, c, bob, "project.write", "project:DOCS"), integration.CodeDenied, "has read on project DOCS, needs write")
}
func TestAction_repo_create_allow(t *testing.T) {
	_, _, c := setupCloud(t, nil)
	expect(t, check(t, c, cr, "repo.create", "project:APP"), integration.CodeAllowed, "create-repo")
	expect(t, check(t, c, ola, "repo.create", "project:DOCS"), integration.CodeAllowed, "owner")
}
func TestAction_repo_create_deny(t *testing.T) {
	_, _, c := setupCloud(t, nil)
	expect(t, check(t, c, dana, "repo.create", "project:DOCS"), integration.CodeDenied, "has write on project DOCS, needs create-repo")
}
func TestAction_project_admin_allow(t *testing.T) {
	_, _, c := setupCloud(t, nil)
	expect(t, check(t, c, ola, "project.admin", "project:APP"), integration.CodeAllowed, "owner of workspace acme")
}
func TestAction_project_admin_deny(t *testing.T) {
	_, _, c := setupCloud(t, nil)
	expect(t, check(t, c, bob, "project.admin", "project:DOCS"), integration.CodeDenied, "needs admin")
	// A group that would suffice makes the answer unknown, not deny.
	expect(t, check(t, c, bob, "project.admin", "project:APP"), integration.CodeUnsupported, "group developers grants admin")
}
func TestAction_workspace_member_allow(t *testing.T) {
	_, _, c := setupCloud(t, nil)
	expect(t, check(t, c, dana, "workspace.member", "workspace"), integration.CodeAllowed, "member of workspace acme")
}
func TestAction_workspace_member_deny(t *testing.T) {
	_, _, c := setupCloud(t, nil)
	expect(t, check(t, c, left, "workspace.member", "workspace"), integration.CodeDenied, "not a member")
}
func TestAction_workspace_admin_allow(t *testing.T) {
	_, _, c := setupCloud(t, nil)
	expect(t, check(t, c, ola, "workspace.admin", "workspace"), integration.CodeAllowed, "owner")
}
func TestAction_workspace_admin_deny(t *testing.T) {
	_, _, c := setupCloud(t, nil)
	expect(t, check(t, c, dana, "workspace.admin", "workspace"), integration.CodeDenied, "not an owner")
}

// --- Cloud semantics -----------------------------------------------------------

func TestCloudBranchRestrictionsUnknowns(t *testing.T) {
	_, f, c := setupCloud(t, nil)
	// A restriction exempting a group: Cloud does not say who is in it.
	expect(t, check(t, c, dana, "repo.push", "repo:api@release/1.2"), integration.CodeUnsupported, "exempts group developers")
	// "release/*" against a nested branch: Cloud's glob semantics are
	// undocumented, so the answer is unknown rather than a guess.
	expect(t, check(t, c, dana, "repo.push", "repo:api@release/1/hotfix"), integration.CodeUnsupported, `pattern "release/*"`)
	// Branching model and character classes cannot be evaluated.
	f.mu.Lock()
	f.restrictions["api"] = append(f.restrictions["api"],
		map[string]any{"id": 6, "kind": "push", "branch_match_kind": "branching_model", "branch_type": "production", "pattern": "", "users": []any{}, "groups": []any{}},
		map[string]any{"id": 7, "kind": "push", "branch_match_kind": "glob", "pattern": "hotfix/[0-9]*", "users": []any{}, "groups": []any{}})
	f.mu.Unlock()
	d := check(t, c, dana, "repo.push", "repo:api@feature/x")
	expect(t, d, integration.CodeUnsupported, "branching model production")
	if !strings.Contains(d.Text, `pattern "hotfix/[0-9]*"`) {
		t.Error(d.Text)
	}
	// A matching restriction still denies before the unknowns are reported.
	expect(t, check(t, c, dana, "repo.push", "repo:api@main"), integration.CodeDenied, "")
}

func TestCloudRepoPermissionFilterFallback(t *testing.T) {
	srv, f, c := setupCloud(t, nil)
	f.mu.Lock()
	f.rejectFilter = true
	f.mu.Unlock()
	expect(t, check(t, c, dana, "repo.push", "repo:api"), integration.CodeAllowed, "")
	expect(t, check(t, c, bob, "repo.push", "repo:api"), integration.CodeDenied, "")
	unfiltered := 0
	for _, call := range srv.Calls() {
		if strings.Contains(call.Path, "/permissions/repositories/api") && call.Query.Get("q") == "" {
			unfiltered++
		}
	}
	if unfiltered != 2 {
		t.Errorf("%d unfiltered reads, want 2", unfiltered)
	}
}

func TestCloudPagination(t *testing.T) {
	srv, _, c := setupCloud(t, nil)
	// Force one-entry pages on the owner listing by asking for pagelen=1.
	conn := c.(*Connection)
	id, err := conn.ResolveIdentity(context.Background(), ola)
	if err != nil {
		t.Fatal(err)
	}
	// The owner list has two entries (ola owner, dana member); with the
	// fake's two-page mode the second page must be followed on the same host.
	srv.Handle("GET", "/2.0/workspaces/acme/permissions", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		q.Set("pagelen", "1")
		r.URL.RawQuery = q.Encode()
		newCloudFake(t).api(w, r)
	})
	owner, err := conn.cloudIsOwner(context.Background(), id)
	if err != nil || !owner {
		t.Fatalf("owner = %v, %v", owner, err)
	}
	pages := 0
	for _, call := range srv.Calls() {
		if call.Path == "/2.0/workspaces/acme/permissions" {
			pages++
		}
	}
	if pages != 2 {
		t.Errorf("read %d pages, want 2", pages)
	}
	// A next link on another host is refused.
	srv.Handle("GET", "/2.0/workspaces/acme/permissions", func(w http.ResponseWriter, r *http.Request) {
		write(w, map[string]any{"values": []any{}, "next": "https://evil.example/2.0/workspaces/acme/permissions?page=2"})
	})
	if _, err := conn.cloudIsOwner(context.Background(), id); err == nil || !strings.Contains(err.Error(), "outside its API") {
		t.Errorf("foreign next link accepted: %v", err)
	}
}

func TestCloudMissingObjects(t *testing.T) {
	_, f, c := setupCloud(t, nil)
	expect(t, check(t, c, dana, "repo.read", "repo:hidden"), integration.CodeResourceNotVisible, "does not exist in workspace acme or hallpass cannot see it")
	expect(t, check(t, c, dana, "project.read", "project:NOPE"), integration.CodeResourceNotVisible, "")
	f.mu.Lock()
	f.status = 403
	f.mu.Unlock()
	expect(t, check(t, c, dana, "repo.read", "repo:api"), integration.CodeCredentialRejected, "")
}

func TestCloudIdentity(t *testing.T) {
	srv, _, c := setupCloud(t, nil)
	expect(t, check(t, c, integration.User{Email: " Dana@Example.com "}, "workspace.member", "workspace"), integration.CodeAllowed, "")
	var lookup itest.Call
	for _, call := range srv.Calls() {
		if call.Path == "/2.0/workspaces/acme/members" {
			lookup = call
		}
	}
	if lookup.Query.Get("q") != `user.email IN ("dana@example.com")` {
		t.Errorf("lookup %v", lookup.Query)
	}
	expect(t, check(t, c, integration.User{Email: "nobody@example.com"}, "workspace.member", "workspace"), integration.CodeUserNotFound, "no member of workspace acme")
	expect(t, check(t, c, integration.User{Email: "dup@example.com"}, "workspace.member", "workspace"), integration.CodeUserAmbiguous, "")
	expect(t, check(t, c, integration.User{Email: `a"b@example.com`}, "workspace.member", "workspace"), integration.CodeInvalidRequest, "")
}

func TestRejectsBadResources(t *testing.T) {
	srv, _, c := setupCloud(t, nil)
	expect(t, check(t, c, dana, "repo.read", "repo:api"), integration.CodeAllowed, "")
	n := len(srv.Calls())
	cases := []struct{ action, resource string }{
		{"repo.read", "repo:APP/api"},   // Data Center shape on Cloud
		{"repo.read", "repo:api@main"},  // read takes no branch
		{"repo.admin", "repo:api@main"}, // admin takes no branch
		{"repo.push", "repo:api@"},      // empty branch
		{"repo.push", "repo:api@-x"},    // bad branch
		{"repo.push", "repo:api@a..b"},  // bad branch
		{"repo.push", "repo:api@a/"},    // bad branch
		{"repo.push", "repo:api@x?y"},   // query, not a branch
		{"repo.read", "repo:a b"},       // bad slug
		{"repo.read", "repo:"},          // empty
		{"repo.read", "project:APP"},    // wrong type
		{"project.read", "repo:api"},    // wrong type
		{"project.read", "project:A/B"}, // bad key
		{"workspace.member", "workspace:acme"},
		{"workspace.member", "repo:api"},
		{"repo.read", "repo:api?x=1"},
	}
	for _, tc := range cases {
		d := check(t, c, dana, tc.action, tc.resource)
		if d.Code != integration.CodeInvalidRequest {
			t.Errorf("%s %s: %s (%s), want invalid_request", tc.action, tc.resource, d.Code, d.Text)
		}
	}
	// Only the identity lookups reached the upstream.
	extra := 0
	for _, call := range srv.Calls()[n:] {
		if call.Path != "/2.0/workspaces/acme/members" {
			extra++
		}
	}
	if extra != 0 {
		t.Errorf("%d calls reached the upstream for rejected resources", extra)
	}
}

func TestGlob(t *testing.T) {
	cases := []struct {
		pattern, branch string
		dc, cloud       bool // matched
		dcOK, cloudOK   bool // supported
	}{
		{"main", "main", true, true, true, true},
		{"main", "main2", false, false, true, true},
		// A slash-less pattern against a nested branch: ambiguous on both.
		{"main", "release/main", false, false, false, false},
		{"**/main", "release/main", true, true, true, true},
		{"release/*", "release/1.2", true, true, true, true},
		// "*" across "/": Data Center says no; Cloud is undocumented, so unknown.
		{"release/*", "release/a/b", false, false, true, false},
		{"release/*", "releases", false, false, true, true},
		{"*", "main", true, true, true, true},
		{"*", "a/b", false, false, false, false},
		{"**", "anything/at/all", true, true, true, true},
		{"**/hotfix", "a/b/hotfix", true, true, true, true},
		{"**/hotfix", "hotfix", true, true, true, true},
		{"release/**", "release/a/b", true, true, true, true},
		{"feature/?", "feature/a", true, true, true, true},
		{"feature/?", "feature/ab", false, false, true, true},
		{"feature/?", "feature//", false, false, true, false},
		{"refs/heads/main", "main", true, true, true, true},
		{"release/[0-9]", "release/1", false, false, false, false},
		{"{a,b}", "a", false, false, false, false},
	}
	for _, tc := range cases {
		if m, ok := refMatch(tc.pattern, tc.branch, true); m != tc.dc || ok != tc.dcOK {
			t.Errorf("data center refMatch(%q, %q) = %v, %v; want %v, %v", tc.pattern, tc.branch, m, ok, tc.dc, tc.dcOK)
		}
		if m, ok := refMatch(tc.pattern, tc.branch, false); m != tc.cloud || ok != tc.cloudOK {
			t.Errorf("cloud refMatch(%q, %q) = %v, %v; want %v, %v", tc.pattern, tc.branch, m, ok, tc.cloud, tc.cloudOK)
		}
	}
}

func TestCloudFailures(t *testing.T) {
	srv, _, c := setupCloud(t, nil)
	expect(t, check(t, c, dana, "repo.read", "repo:api"), integration.CodeAllowed, "")
	itest.FailureCases(t, srv, func() integration.Decision {
		return check(t, c, dana, "repo.read", "repo:api")
	})
}

func TestCloudBasicAuth(t *testing.T) {
	srv := itest.NewServer(t)
	f := newCloudFake(t)
	srv.Handle("GET", "/2.0/*", func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != "bot@example.com" || p != f.token {
			w.WriteHeader(401)
			return
		}
		r.Header.Set("Authorization", "Bearer "+f.token)
		f.api(w, r)
	})
	deps, _ := itest.Deps(t, srv)
	s := itest.Settings("bb", "bitbucket", map[string]string{"url": srv.URL, "workspace": "acme", "auth_mode": "basic", "username": "bot@example.com"},
		map[string]secret.Secret{"credential": secret.Literal(f.token)})
	c, err := (Integration{}).New(context.Background(), s, deps)
	if err != nil {
		t.Fatal(err)
	}
	expect(t, check(t, c, dana, "repo.read", "repo:api"), integration.CodeAllowed, "")
}

func TestCloudProbe(t *testing.T) {
	_, f, c := setupCloud(t, nil)
	r, err := c.Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.Summary, "workspace acme") || !strings.Contains(r.Summary, "looked up by email") {
		t.Error(r.Summary)
	}
	itest.AssertNoCanary(t, r.Summary)
	if !strings.Contains(strings.Join(r.Warnings, "\n"), "no group membership") {
		t.Errorf("warnings %q", r.Warnings)
	}
	f.mu.Lock()
	f.status = 403
	f.mu.Unlock()
	if _, err := c.Probe(context.Background()); err == nil {
		t.Error("probe passed on 403")
	} else {
		itest.AssertNoCanary(t, err.Error())
	}
	f.mu.Lock()
	f.status = 503
	f.mu.Unlock()
	_, err = c.Probe(context.Background())
	if d := integration.ToDecision(err); d.Code != integration.CodeUpstreamError {
		t.Errorf("probe on 503: %s (%s)", d.Code, d.Text)
	}
}

func TestNewRejectsBadSettings(t *testing.T) {
	srv := itest.NewServer(t)
	deps, _ := itest.Deps(t, srv)
	cases := []map[string]string{
		{},                                    // cloud without workspace
		{"workspace": "acme", "edition": "x"}, // bad edition
		{"workspace": "a b"},                  // bad slug
		{"edition": "datacenter"},             // no url
		{"edition": "datacenter", "url": srv.URL, "workspace": "acme"},
		{"workspace": "acme", "auth_mode": "basic"}, // no username
		{"workspace": "acme", "auth_mode": "digest"},
	}
	for _, v := range cases {
		s := itest.Settings("bb", "bitbucket", v, map[string]secret.Secret{"credential": itest.Literal("x")})
		if _, err := (Integration{}).New(context.Background(), s, deps); err == nil {
			t.Errorf("New accepted %v", v)
		}
	}
	s := itest.Settings("bb", "bitbucket", map[string]string{"workspace": "acme"}, nil)
	if _, err := (Integration{}).New(context.Background(), s, deps); err == nil {
		t.Error("New accepted a connection without a credential")
	}
	if err := integration.ValidateFields((Integration{}).Fields()); err != nil {
		t.Error(err)
	}
	for _, f := range (Integration{}).Fields() {
		if f.Validate != nil {
			if err := f.Validate(""); err != nil {
				t.Errorf("field %s rejects the empty value: %v", f.Name, err)
			}
		}
	}
}

func TestCatalog(t *testing.T) {
	seen := map[string]bool{}
	for _, a := range (Integration{}).Actions() {
		if seen[a.Name] || a.Description == "" {
			t.Errorf("action %s duplicated or undescribed", a.Name)
		}
		seen[a.Name] = true
	}
	for _, a := range actionList {
		if a.resource == "workspace" && a.role == "" || a.resource != "workspace" && a.level == levelNone {
			t.Errorf("action %s is incompletely defined", a.name)
		}
	}
}
