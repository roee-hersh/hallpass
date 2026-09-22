package gitlab

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/roee-hersh/hallpass/internal/integration"
	"github.com/roee-hersh/hallpass/internal/integration/itest"
	"github.com/roee-hersh/hallpass/internal/secret"
)

// fakeUser is one account in the fake GitLab.
type fakeUser struct {
	ID          int64
	Username    string
	State       string
	Email       string
	PublicEmail string
	Bot         bool
	IsAdmin     bool
	External    bool
	// Emails, when set, is written as the "emails" array of the full record.
	Emails []any
}

// fakeMember is one effective membership.
type fakeMember struct {
	Level    int
	State    string
	RoleID   int64
	RoleName string
}

type fakeProject struct {
	ID         int64
	Visibility string
	Members    map[int64]fakeMember
	Protected  []map[string]any
	// pbStatus, when non-zero, is answered for the protected_branches list.
	pbStatus int
	// IssuesAccessLevel and IssuesEnabled are written when set.
	IssuesAccessLevel string
	IssuesEnabled     *bool
}

type fakeGroup struct {
	ID      int64
	Members map[int64]fakeMember
	// status, when non-zero, is answered for every call about the group.
	status int
}

// fakeGitLab is the fake API. Only what hallpass reads is modelled.
type fakeGitLab struct {
	admin       bool // the token is an administrator's: search returns email and is_admin
	users       []fakeUser
	searchHits  []fakeUser              // when set, every /users?search answers these (paginated)
	enterprise  []fakeUser              // enterprise users of the configured group (with email)
	saml        []map[string]any        // SAML identities of the configured group
	samlPages   int                     // split saml into this many pages
	nextLink    string                  // when set, every paginated list points its next page here
	projects    map[string]*fakeProject // by path and by numeric id
	groups      map[string]*fakeGroup
	me          fakeUser
	scopes      []string
	tokenCode   int // status for /personal_access_tokens/self (0 = 200)
	expiresAt   string
	lastEscaped string
}

const token = "glpat"

func (f *fakeGitLab) userJSON(u fakeUser, full bool) map[string]any {
	m := map[string]any{
		"id": u.ID, "username": u.Username, "state": u.State, "bot": u.Bot,
		"name": itest.Canary + "name", "web_url": "https://gitlab.example/" + u.Username,
		"public_email": u.PublicEmail,
	}
	if full {
		m["email"] = u.Email
		m["is_admin"] = u.IsAdmin
		m["external"] = u.External
		if u.Emails != nil {
			m["emails"] = u.Emails
		}
	}
	return m
}

func memberJSON(m fakeMember) map[string]any {
	out := map[string]any{"access_level": m.Level, "state": m.State, "name": itest.Canary + "member"}
	if m.RoleID != 0 {
		out["member_role"] = map[string]any{"id": m.RoleID, "name": m.RoleName, "base_access_level": m.Level}
	} else {
		out["member_role"] = nil
	}
	return out
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func notFound(w http.ResponseWriter) {
	writeJSON(w, 404, map[string]any{"message": "404 Not Found " + itest.Canary + "body"})
}

func (f *fakeGitLab) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("PRIVATE-TOKEN") != itest.Canary+token {
			writeJSON(w, 401, map[string]any{"message": "401 Unauthorized"})
			return
		}
		if r.Header.Get("Authorization") != "" {
			t.Errorf("unexpected Authorization header")
		}
		esc := r.URL.EscapedPath()
		f.lastEscaped = esc
		if !strings.HasPrefix(esc, "/api/v4/") {
			notFound(w)
			return
		}
		raw := strings.Split(strings.TrimPrefix(esc, "/api/v4/"), "/")
		seg := make([]string, len(raw))
		for i, s := range raw {
			u, err := url.PathUnescape(s)
			if err != nil {
				t.Errorf("bad escaping in %s", esc)
			}
			seg[i] = u
		}
		q := r.URL.Query()
		switch {
		case len(seg) == 1 && seg[0] == "user":
			writeJSON(w, 200, f.userJSON(f.me, true))
		case len(seg) == 2 && seg[0] == "personal_access_tokens" && seg[1] == "self":
			if f.tokenCode != 0 {
				writeJSON(w, f.tokenCode, map[string]any{"message": "nope"})
				return
			}
			writeJSON(w, 200, map[string]any{"scopes": f.scopes, "expires_at": f.expiresAt, "active": true, "name": itest.Canary + "tok"})
		case len(seg) == 1 && seg[0] == "users":
			var out []map[string]any
			if uname := q.Get("username"); uname != "" {
				for _, u := range f.users {
					if u.Username == uname {
						out = append(out, f.userJSON(u, f.admin))
					}
				}
			} else if s := strings.ToLower(q.Get("search")); s != "" {
				if f.searchHits != nil {
					for _, u := range f.searchHits {
						out = append(out, f.userJSON(u, f.admin))
					}
				} else {
					for _, u := range f.users {
						hay := strings.ToLower(u.Username + " " + u.Email + " " + u.PublicEmail)
						if strings.Contains(hay, s) {
							out = append(out, f.userJSON(u, f.admin))
						}
					}
				}
				// Offset pagination like GitLab: page and per_page, Link rel=next.
				per, _ := strconv.Atoi(q.Get("per_page"))
				if per < 1 {
					per = 20
				}
				page, _ := strconv.Atoi(q.Get("page"))
				if page < 1 {
					page = 1
				}
				lo, hi := (page-1)*per, page*per
				if lo > len(out) {
					lo = len(out)
				}
				if hi > len(out) {
					hi = len(out)
				}
				if hi < len(out) {
					next := *r.URL
					nq := next.Query()
					nq.Set("page", strconv.Itoa(page+1))
					next.RawQuery = nq.Encode()
					w.Header().Set("Link", fmt.Sprintf(`<%s>; rel="next"`, f.link(r, next)))
				}
				out = out[lo:hi]
			}
			if out == nil {
				out = []map[string]any{}
			}
			writeJSON(w, 200, out)
		case len(seg) == 2 && seg[0] == "users":
			id, _ := strconv.ParseInt(seg[1], 10, 64)
			for _, u := range f.users {
				if u.ID == id {
					writeJSON(w, 200, f.userJSON(u, f.admin))
					return
				}
			}
			notFound(w)
		case len(seg) >= 2 && seg[0] == "projects":
			p := f.projects[seg[1]]
			if p == nil {
				notFound(w)
				return
			}
			switch {
			case len(seg) == 2:
				pj := map[string]any{"id": p.ID, "visibility": p.Visibility, "description": itest.Canary + "desc"}
				if p.IssuesAccessLevel != "" {
					pj["issues_access_level"] = p.IssuesAccessLevel
				}
				if p.IssuesEnabled != nil {
					pj["issues_enabled"] = *p.IssuesEnabled
				}
				writeJSON(w, 200, pj)
			case len(seg) == 5 && seg[2] == "members" && seg[3] == "all":
				uid, _ := strconv.ParseInt(seg[4], 10, 64)
				m, ok := p.Members[uid]
				if !ok {
					notFound(w)
					return
				}
				writeJSON(w, 200, memberJSON(m))
			case len(seg) == 3 && seg[2] == "protected_branches":
				if p.pbStatus != 0 {
					writeJSON(w, p.pbStatus, map[string]any{"message": "nope"})
					return
				}
				pbs := p.Protected
				if pbs == nil {
					pbs = []map[string]any{}
				}
				writeJSON(w, 200, pbs)
			default:
				notFound(w)
			}
		case len(seg) >= 2 && seg[0] == "groups":
			g := f.groups[seg[1]]
			if g == nil {
				notFound(w)
				return
			}
			if g.status != 0 {
				writeJSON(w, g.status, map[string]any{"message": "nope"})
				return
			}
			switch {
			case len(seg) == 2:
				writeJSON(w, 200, map[string]any{"id": g.ID, "full_path": seg[1], "visibility": "private"})
			case len(seg) == 5 && seg[2] == "members" && seg[3] == "all":
				uid, _ := strconv.ParseInt(seg[4], 10, 64)
				m, ok := g.Members[uid]
				if !ok {
					notFound(w)
					return
				}
				writeJSON(w, 200, memberJSON(m))
			case len(seg) == 3 && seg[2] == "enterprise_users":
				s := strings.ToLower(q.Get("search"))
				out := []map[string]any{}
				for _, u := range f.enterprise {
					if strings.Contains(strings.ToLower(u.Email+" "+u.Username), s) {
						out = append(out, f.userJSON(u, f.admin))
					}
				}
				writeJSON(w, 200, out)
			case len(seg) == 4 && seg[2] == "saml" && seg[3] == "identities":
				pages := f.samlPages
				if pages < 1 {
					pages = 1
				}
				page, _ := strconv.Atoi(q.Get("page"))
				if page < 1 {
					page = 1
				}
				per := (len(f.saml) + pages - 1) / pages
				if per < 1 {
					per = 1
				}
				lo, hi := (page-1)*per, page*per
				if lo > len(f.saml) {
					lo = len(f.saml)
				}
				if hi > len(f.saml) {
					hi = len(f.saml)
				}
				if hi < len(f.saml) {
					next := *r.URL
					nq := next.Query()
					nq.Set("page", strconv.Itoa(page+1))
					next.RawQuery = nq.Encode()
					w.Header().Set("Link", fmt.Sprintf(`<%s>; rel="next"`, f.link(r, next)))
				}
				writeJSON(w, 200, f.saml[lo:hi])
			default:
				notFound(w)
			}
		default:
			notFound(w)
		}
	}
}

var (
	alice   = fakeUser{ID: 7, Username: "alice", State: "active", Email: "Alice@Example.com", PublicEmail: ""}
	bob     = fakeUser{ID: 8, Username: "bob", State: "active", Email: "bob@example.com"}
	blocked = fakeUser{ID: 9, Username: "blocked", State: "blocked", Email: "blocked@example.com"}
	bot     = fakeUser{ID: 10, Username: "project_bot", State: "active", Email: "bot@example.com", Bot: true}
	root    = fakeUser{ID: 1, Username: "root", State: "active", Email: "root@example.com", IsAdmin: true}
	dup1    = fakeUser{ID: 11, Username: "dup1", State: "active", Email: "dup@example.com"}
	dup2    = fakeUser{ID: 12, Username: "dup2", State: "active", Email: "dup@example.com"}
	pub     = fakeUser{ID: 13, Username: "pub", State: "active", Email: "hidden@example.com", PublicEmail: "pub@example.com"}
)

func newFake() *fakeGitLab {
	f := &fakeGitLab{
		admin:    true,
		users:    []fakeUser{alice, bob, blocked, bot, root, dup1, dup2, pub},
		me:       fakeUser{ID: 2, Username: "hallpass", State: "active", IsAdmin: true},
		scopes:   []string{"read_api"},
		projects: map[string]*fakeProject{},
		groups:   map[string]*fakeGroup{},
	}
	webapp := &fakeProject{ID: 100, Visibility: "private", Members: map[int64]fakeMember{}}
	f.projects["acme/webapp"] = webapp
	f.projects["100"] = webapp
	f.projects["acme/public"] = &fakeProject{ID: 101, Visibility: "public", Members: map[int64]fakeMember{}}
	f.projects["acme/internal"] = &fakeProject{ID: 102, Visibility: "internal", Members: map[int64]fakeMember{}}
	acme := &fakeGroup{ID: 200, Members: map[int64]fakeMember{}}
	f.groups["acme"] = acme
	f.groups["200"] = acme
	return f
}

// link renders a next-page URL on the fake's own host, or nextLink when set.
func (f *fakeGitLab) link(r *http.Request, next url.URL) string {
	if f.nextLink != "" {
		return f.nextLink
	}
	return "https://" + r.Host + next.String()
}

func (f *fakeGitLab) member(project string, u fakeUser, level int) {
	f.projects[project].Members[u.ID] = fakeMember{Level: level, State: "active"}
}

func (f *fakeGitLab) groupMember(group string, u fakeUser, level int) {
	f.groups[group].Members[u.ID] = fakeMember{Level: level, State: "active"}
}

func setup(t *testing.T, f *fakeGitLab, values map[string]string) (*itest.Server, integration.Connection) {
	t.Helper()
	srv := itest.NewServer(t)
	// GitLab's published OpenAPI keys paths with /api/v4 and leaves out the
	// users, user, SAML identities, enterprise users and token endpoints.
	srv.UseSpec(itest.SpecFromEnv(t, "gitlab"), itest.SpecOptions{IgnorePaths: []string{`^/api/v4/users(/|$)`, `^/api/v4/user$`, `/saml/identities$`, `/enterprise_users$`, `^/api/v4/personal_access_tokens/self$`}})
	srv.Handle("", "/api/v4/*", f.handler(t))
	deps, _ := itest.Deps(t, srv)
	v := map[string]string{"url": srv.URL, "identity_mode": "admin_search", "username_template": "{local}"}
	for k, val := range values {
		v[k] = val
	}
	s := itest.Settings("gl", "gitlab", v, map[string]secret.Secret{"credential": itest.Literal(token)})
	c, err := Integration{}.New(context.Background(), s, deps)
	if err != nil {
		t.Fatal(err)
	}
	return srv, c
}

func check(t *testing.T, c integration.Connection, email, action, resource string) integration.Decision {
	t.Helper()
	return itest.Check(t, c, Integration{}, integration.User{Email: email}, action, resource)
}

// Identity modes.

func TestIdentityAdminSearch(t *testing.T) {
	f := newFake()
	srv, c := setup(t, f, nil)
	id, err := c.ResolveIdentity(context.Background(), integration.User{Email: "alice@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if id.ID != "7" || id.Display != "alice" || id.Attr("state") != "active" || id.Attr("bot") != "false" || id.Attr("is_admin") != "false" {
		t.Errorf("identity %+v", id)
	}
	last := srv.LastCall()
	if last.Path != "/api/v4/users" || last.Query.Get("search") != "alice@example.com" {
		t.Errorf("call %s %v", last.Path, last.Query)
	}
	if last.Header.Get("PRIVATE-TOKEN") == "" {
		t.Error("PRIVATE-TOKEN header missing")
	}
	// public_email is used when email is absent.
	f.admin = false
	id, err = c.ResolveIdentity(context.Background(), integration.User{Email: "PUB@example.com"})
	if err != nil || id.ID != "13" || id.Attr("is_admin") != "" {
		t.Errorf("public_email match: %+v %v", id, err)
	}
}

func TestIdentityNotFoundAmbiguousAndNonAdmin(t *testing.T) {
	f := newFake()
	_, c := setup(t, f, nil)
	itest.ExpectCode(t, check(t, c, "nobody@example.com", "project.read", "project:acme/webapp"), integration.CodeUserNotFound)
	itest.ExpectCode(t, check(t, c, "dup@example.com", "project.read", "project:acme/webapp"), integration.CodeUserAmbiguous)
	// Search hits (substring of alice's email) that do not match exactly: not found.
	itest.ExpectCode(t, check(t, c, "alice@example.co", "project.read", "project:acme/webapp"), integration.CodeUserNotFound)
	// A non-admin token gets results without an email field: unknown, not user_not_found.
	f.admin = false
	d := check(t, c, "alice@example.com", "project.read", "project:acme/webapp")
	itest.ExpectCode(t, d, integration.CodeUnsupported)
	if !strings.Contains(d.Text, "administrator") {
		t.Errorf("text %q should explain the token is not an administrator's", d.Text)
	}
}

func TestIdentityEnterpriseUsers(t *testing.T) {
	f := newFake()
	f.enterprise = []fakeUser{alice, bob}
	f.member("acme/webapp", alice, levelDeveloper)
	srv, c := setup(t, f, map[string]string{"identity_mode": "enterprise_users", "group": "acme"})
	itest.ExpectCode(t, check(t, c, "alice@example.com", "mr.create", "project:acme/webapp"), integration.CodeAllowed)
	var sawEnterprise bool
	for _, call := range srv.Calls() {
		if call.Path == "/api/v4/groups/acme/enterprise_users" && call.Query.Get("search") == "alice@example.com" {
			sawEnterprise = true
		}
	}
	if !sawEnterprise {
		t.Error("enterprise_users endpoint not called")
	}
	itest.ExpectCode(t, check(t, c, "nobody@example.com", "mr.create", "project:acme/webapp"), integration.CodeUserNotFound)
	f.admin = false
	itest.ExpectCode(t, check(t, c, "alice@example.com", "mr.create", "project:acme/webapp"), integration.CodeUnsupported)
	// Group not visible.
	f.groups["acme"].status = 404
	itest.ExpectCode(t, check(t, c, "alice@example.com", "mr.create", "project:acme/webapp"), integration.CodeResourceNotVisible)
	f.groups["acme"].status = 403
	itest.ExpectCode(t, check(t, c, "alice@example.com", "mr.create", "project:acme/webapp"), integration.CodeCredentialRejected)
}

func TestIdentitySAML(t *testing.T) {
	f := newFake()
	f.saml = []map[string]any{
		{"extern_uid": "someone@example.com", "user_id": 99},
		{"extern_uid": "bob@example.com", "user_id": 8},
		{"extern_uid": "ALICE@example.com", "user_id": 7},
		{"extern_uid": "dup@example.com", "user_id": 11},
		{"extern_uid": "dup@example.com", "user_id": 12},
	}
	f.samlPages = 3
	f.member("acme/webapp", alice, levelMaintainer)
	srv, c := setup(t, f, map[string]string{"identity_mode": "saml", "group": "acme"})
	d := check(t, c, "alice@example.com", "project.admin", "project:acme/webapp")
	itest.ExpectCode(t, d, integration.CodeAllowed)
	pages := 0
	for _, call := range srv.Calls() {
		if call.Path == "/api/v4/groups/acme/saml/identities" {
			pages++
		}
	}
	if pages != 3 {
		t.Errorf("saml identities fetched in %d pages, want 3", pages)
	}
	itest.ExpectCode(t, check(t, c, "nobody@example.com", "project.admin", "project:acme/webapp"), integration.CodeUserNotFound)
	itest.ExpectCode(t, check(t, c, "dup@example.com", "project.admin", "project:acme/webapp"), integration.CodeUserAmbiguous)
	// A next page on another host is not fetched: the request would carry
	// the token there.
	var elsewhere atomic.Int32
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		elsewhere.Add(1)
		if r.Header.Get("PRIVATE-TOKEN") != "" {
			t.Errorf("token sent to %s", r.Host)
		}
		writeJSON(w, 200, []any{})
	}))
	defer evil.Close()
	f.nextLink = evil.URL + "/api/v4/groups/acme/saml/identities?page=2"
	d = check(t, c, "carol@example.com", "project.admin", "project:acme/webapp")
	itest.ExpectCode(t, d, integration.CodeUpstreamError)
	if !strings.Contains(d.Text, "outside the connection's url") || elsewhere.Load() != 0 {
		t.Errorf("off-host next link: %+v, %d requests elsewhere", d, elsewhere.Load())
	}
	f.nextLink = ""
	// Identity pointing at a deleted user.
	itest.ExpectCode(t, check(t, c, "someone@example.com", "project.admin", "project:acme/webapp"), integration.CodeUserNotFound)
}

func TestIdentityTemplate(t *testing.T) {
	f := newFake()
	f.admin = false
	f.member("acme/webapp", bob, levelReporter)
	srv, c := setup(t, f, map[string]string{"identity_mode": "template", "username_template": "{local}", "email_domains": "corp.example"})
	itest.ExpectCode(t, check(t, c, "bob@corp.example", "issue.create", "project:acme/webapp"), integration.CodeAllowed)
	if q := srv.Calls()[0].Query; q.Get("username") != "bob" || q.Get("search") != "" {
		t.Errorf("query %v", q)
	}
	itest.ExpectCode(t, check(t, c, "nobody@corp.example", "issue.create", "project:acme/webapp"), integration.CodeUserNotFound)

	_, c2 := setup(t, f, map[string]string{"identity_mode": "template", "username_template": "{domain}-{local}", "email_domains": "corp.example"})
	id, err := c2.ResolveIdentity(context.Background(), integration.User{Email: "bob@corp.example"})
	if err == nil || id.ID != "" {
		t.Errorf("corp.example-bob should not exist: %+v %v", id, err)
	}
	if u := c2.(*Connection).Username("bob@corp.example"); u != "corp.example-bob" {
		t.Error(u)
	}
}

func TestNewValidation(t *testing.T) {
	srv := itest.NewServer(t)
	// GitLab's published OpenAPI keys paths with /api/v4 and leaves out the
	// users, user, SAML identities, enterprise users and token endpoints.
	srv.UseSpec(itest.SpecFromEnv(t, "gitlab"), itest.SpecOptions{IgnorePaths: []string{`^/api/v4/users(/|$)`, `^/api/v4/user$`, `/saml/identities$`, `/enterprise_users$`, `^/api/v4/personal_access_tokens/self$`}})
	deps, _ := itest.Deps(t, srv)
	build := func(values map[string]string, cred secret.Secret) error {
		v := map[string]string{"url": srv.URL}
		for k, val := range values {
			v[k] = val
		}
		_, err := Integration{}.New(context.Background(), itest.Settings("gl", "gitlab", v, map[string]secret.Secret{"credential": cred}), deps)
		return err
	}
	if err := build(map[string]string{"identity_mode": "saml"}, itest.Literal(token)); err == nil || !strings.Contains(err.Error(), "group is required") {
		t.Errorf("saml without group: %v", err)
	}
	if err := build(map[string]string{"identity_mode": "enterprise_users"}, itest.Literal(token)); err == nil {
		t.Error("enterprise_users without group accepted")
	}
	if err := build(map[string]string{"identity_mode": "saml", "group": "bad path!"}, itest.Literal(token)); err == nil {
		t.Error("bad group path accepted")
	}
	if err := build(map[string]string{"identity_mode": "ldap"}, itest.Literal(token)); err == nil {
		t.Error("unknown identity_mode accepted")
	}
	if err := build(map[string]string{"username_template": "static"}, itest.Literal(token)); err == nil {
		t.Error("static template accepted")
	}
	if err := build(map[string]string{"identity_mode": "template"}, itest.Literal(token)); err == nil || !strings.Contains(err.Error(), "email_domains") {
		t.Errorf("template without email_domains: %v", err)
	}
	for _, bad := range []string{"acme.com,", ",acme.com", "acme.com, ,acme.io", "acme.com;acme.io", "a/b", ",", "a b.com", "exa_mple.com"} {
		if err := build(map[string]string{"identity_mode": "template", "email_domains": bad}, itest.Literal(token)); err == nil {
			t.Errorf("email_domains %q accepted", bad)
		}
	}
	// Spaces around the commas and upper case are normalised, as in github.
	for _, good := range []string{"acme.com,acme.io", "acme.com, acme.io", "Acme.com"} {
		if err := build(map[string]string{"identity_mode": "template", "email_domains": good}, itest.Literal(token)); err != nil {
			t.Errorf("email_domains %q: %v", good, err)
		}
	}
	if err := build(nil, secret.Secret{}); err == nil {
		t.Error("missing credential accepted")
	}
	if err := build(map[string]string{"identity_mode": "saml", "group": "acme/sub"}, itest.Literal(token)); err != nil {
		t.Error(err)
	}
	if err := build(map[string]string{}, itest.Literal(token)); err != nil {
		t.Error(err)
	}
	if len(srv.Calls()) != 0 {
		t.Error("New touched the network")
	}
	for _, f := range (Integration{}).Fields() {
		if f.Name == "url" && f.Default != "https://gitlab.com" {
			t.Errorf("url default %q", f.Default)
		}
	}
	if err := integration.ValidateFields(Integration{}.Fields()); err != nil {
		t.Error(err)
	}
}

// Users that exist but may not act.

func TestInactiveAndBotUsersDenied(t *testing.T) {
	f := newFake()
	f.member("acme/webapp", blocked, levelOwner)
	f.member("acme/webapp", bot, levelOwner)
	srv, c := setup(t, f, nil)
	d := check(t, c, "blocked@example.com", "project.read", "project:acme/webapp")
	itest.ExpectCode(t, d, integration.CodeDenied)
	if !strings.Contains(d.Text, "blocked") {
		t.Error(d.Text)
	}
	for _, call := range srv.Calls() {
		if strings.Contains(call.Path, "/members/") {
			t.Error("membership looked up for a blocked user")
		}
	}
	d = check(t, c, "bot@example.com", "project.read", "project:acme/webapp")
	itest.ExpectCode(t, d, integration.CodeDenied)
	if !strings.Contains(d.Text, "bot") {
		t.Error(d.Text)
	}
}

func TestMembershipNotActive(t *testing.T) {
	f := newFake()
	f.projects["acme/webapp"].Members[alice.ID] = fakeMember{Level: levelOwner, State: "awaiting"}
	_, c := setup(t, f, nil)
	d := check(t, c, "alice@example.com", "project.read", "project:acme/webapp")
	itest.ExpectCode(t, d, integration.CodeDenied)
	if !strings.Contains(d.Text, "awaiting") {
		t.Error(d.Text)
	}
}

// Level semantics.

func TestNonCumulativeLevels(t *testing.T) {
	f := newFake()
	f.member("acme/webapp", alice, levelPlanner)
	f.member("acme/webapp", bob, levelSecurityManager)
	_, c := setup(t, f, nil)
	itest.ExpectCode(t, check(t, c, "alice@example.com", "mr.create", "project:acme/webapp"), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, "alice@example.com", "issue.edit", "project:acme/webapp"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, "alice@example.com", "project.read", "project:acme/webapp"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, "bob@example.com", "repo.push", "project:acme/webapp"), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, "bob@example.com", "pipeline.run", "project:acme/webapp"), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, "bob@example.com", "project.read", "project:acme/webapp"), integration.CodeAllowed)
	// Minimal Access (5) grants nothing.
	f.member("acme/webapp", root, levelMinimal)
	itest.ExpectCode(t, check(t, c, "root@example.com", "project.read", "project:acme/webapp"), integration.CodeDenied)
}

func TestConditionalLevelIsUnknown(t *testing.T) {
	f := newFake()
	f.member("acme/webapp", alice, levelReporter)
	f.member("acme/webapp", bob, levelPlanner)
	_, c := setup(t, f, nil)
	d := check(t, c, "alice@example.com", "mr.approve", "project:acme/webapp")
	itest.ExpectCode(t, d, integration.CodeUnsupported)
	if !strings.Contains(d.Text, "approval rules") {
		t.Error(d.Text)
	}
	itest.ExpectCode(t, check(t, c, "bob@example.com", "mr.approve", "project:acme/webapp"), integration.CodeUnsupported)
}

func TestNonMemberVisibility(t *testing.T) {
	f := newFake()
	srv, c := setup(t, f, nil)
	itest.ExpectCode(t, check(t, c, "alice@example.com", "project.read", "project:acme/public"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, "alice@example.com", "project.read", "project:acme/internal"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, "alice@example.com", "issue.create", "project:acme/internal"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, "alice@example.com", "issue.create", "project:acme/public"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, "alice@example.com", "project.read", "project:acme/webapp"), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, "alice@example.com", "mr.create", "project:acme/public"), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, "alice@example.com", "repo.push", "project:acme/public@main"), integration.CodeDenied)
	// A non-member never triggers a protected-branch lookup.
	for _, call := range srv.Calls() {
		if strings.HasSuffix(call.Path, "/protected_branches") {
			t.Error("protected branches read for a non-member")
		}
	}
	// Group: non-member of an existing group is denied; a missing group is not visible.
	itest.ExpectCode(t, check(t, c, "alice@example.com", "group.member", "group:acme"), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, "alice@example.com", "group.member", "group:nope"), integration.CodeResourceNotVisible)
}

func TestProjectNotVisible(t *testing.T) {
	f := newFake()
	_, c := setup(t, f, nil)
	d := check(t, c, "alice@example.com", "project.read", "project:acme/missing")
	itest.ExpectCode(t, d, integration.CodeResourceNotVisible)
	itest.ExpectCode(t, check(t, c, "alice@example.com", "project.read", "project:12345"), integration.CodeResourceNotVisible)
}

func TestPathEscapingAndNumericIDs(t *testing.T) {
	f := newFake()
	f.member("acme/webapp", alice, levelDeveloper)
	srv, c := setup(t, f, nil)
	itest.ExpectCode(t, check(t, c, "alice@example.com", "mr.create", "project:acme/webapp"), integration.CodeAllowed)
	if !strings.Contains(f.lastEscaped, "/projects/acme%2Fwebapp/members/all/7") {
		t.Errorf("path %q should encode / as %%2F", f.lastEscaped)
	}
	itest.ExpectCode(t, check(t, c, "alice@example.com", "mr.create", "project:100"), integration.CodeAllowed)
	if last := srv.LastCall(); last.Path != "/api/v4/projects/100/members/all/7" {
		t.Error(last.Path)
	}
	f.groupMember("acme", alice, levelGuest)
	itest.ExpectCode(t, check(t, c, "alice@example.com", "group.member", "group:200"), integration.CodeAllowed)
}

func TestCustomRoleUnknown(t *testing.T) {
	f := newFake()
	f.projects["acme/webapp"].Members[alice.ID] = fakeMember{Level: levelGuest, State: "active", RoleID: 5, RoleName: "guest-plus"}
	_, c := setup(t, f, nil)
	// Base level grants: allow.
	itest.ExpectCode(t, check(t, c, "alice@example.com", "project.read", "project:acme/webapp"), integration.CodeAllowed)
	// Base level does not grant: unknown, the custom role may add it.
	d := check(t, c, "alice@example.com", "repo.push", "project:acme/webapp")
	itest.ExpectCode(t, d, integration.CodeUnsupported)
	if !strings.Contains(d.Text, "guest-plus") {
		t.Error(d.Text)
	}
	itest.ExpectCode(t, check(t, c, "alice@example.com", "project.delete", "project:acme/webapp"), integration.CodeUnsupported)
}

func TestCredentialRejectedOn403(t *testing.T) {
	f := newFake()
	_, c := setup(t, f, nil)
	f.groups["acme"].status = 403
	itest.ExpectCode(t, check(t, c, "alice@example.com", "group.member", "group:acme"), integration.CodeCredentialRejected)
}

// Protected branches.

func entry(kv ...any) map[string]any {
	m := map[string]any{"access_level": 0, "user_id": nil, "group_id": nil, "access_level_description": itest.Canary + "entry"}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i].(string)] = kv[i+1]
	}
	return m
}

func protect(name string, push, merge []map[string]any) map[string]any {
	if push == nil {
		push = []map[string]any{}
	}
	if merge == nil {
		merge = []map[string]any{}
	}
	return map[string]any{"name": name, "push_access_levels": push, "merge_access_levels": merge}
}

func TestProtectedBranchWildcardAndLevels(t *testing.T) {
	f := newFake()
	p := f.projects["acme/webapp"]
	f.member("acme/webapp", alice, levelDeveloper)
	f.member("acme/webapp", bob, levelMaintainer)
	p.Protected = []map[string]any{
		protect("main", []map[string]any{entry("access_level", 40)}, []map[string]any{entry("access_level", 30)}),
		protect("release/*", []map[string]any{entry("access_level", 40)}, []map[string]any{entry("access_level", 40)}),
		protect("*-hotfix", []map[string]any{entry("access_level", 30)}, nil),
	}
	_, c := setup(t, f, nil)
	// main: push maintainers, merge developers.
	itest.ExpectCode(t, check(t, c, "alice@example.com", "repo.push", "project:acme/webapp@main"), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, "alice@example.com", "mr.merge", "project:acme/webapp@main"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, "bob@example.com", "repo.push", "project:acme/webapp@main"), integration.CodeAllowed)
	// Wildcards.
	itest.ExpectCode(t, check(t, c, "alice@example.com", "repo.push", "project:acme/webapp@release/2.0"), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, "bob@example.com", "repo.push", "project:acme/webapp@release/2.0/rc1"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, "alice@example.com", "repo.push", "project:acme/webapp@v1-hotfix"), integration.CodeAllowed)
	// Unprotected branch: the unprotected rule applies.
	itest.ExpectCode(t, check(t, c, "alice@example.com", "repo.push", "project:acme/webapp@feature/x"), integration.CodeAllowed)
	// No branch given while rules exist: unknown, the caller must name the branch.
	itest.ExpectCode(t, check(t, c, "alice@example.com", "repo.push", "project:acme/webapp"), integration.CodeUnsupported)
	// Merge on "*-hotfix" allows no one (empty entry list): deny.
	itest.ExpectCode(t, check(t, c, "bob@example.com", "mr.merge", "project:acme/webapp@v1-hotfix"), integration.CodeDenied)
}

func TestProtectedBranchUserAndNoOne(t *testing.T) {
	f := newFake()
	p := f.projects["acme/webapp"]
	f.member("acme/webapp", alice, levelDeveloper)
	f.member("acme/webapp", bob, levelOwner)
	p.Protected = []map[string]any{
		protect("main", []map[string]any{entry("access_level", 40, "user_id", 7)}, []map[string]any{entry("access_level", 0)}),
		protect("locked", []map[string]any{entry("access_level", 0)}, []map[string]any{entry("access_level", 0)}),
	}
	_, c := setup(t, f, nil)
	// user_id entry names alice: allowed although she is only a Developer.
	itest.ExpectCode(t, check(t, c, "alice@example.com", "repo.push", "project:acme/webapp@main"), integration.CodeAllowed)
	// bob is an Owner but the only entry names alice.
	itest.ExpectCode(t, check(t, c, "bob@example.com", "repo.push", "project:acme/webapp@main"), integration.CodeDenied)
	// access_level 0 for every entry: no one, even an Owner.
	d := check(t, c, "bob@example.com", "mr.merge", "project:acme/webapp@main")
	itest.ExpectCode(t, d, integration.CodeDenied)
	if !strings.Contains(d.Text, "no one") {
		t.Error(d.Text)
	}
	itest.ExpectCode(t, check(t, c, "bob@example.com", "repo.push", "project:acme/webapp@locked"), integration.CodeDenied)
}

func TestProtectedBranchGroupEntries(t *testing.T) {
	f := newFake()
	p := f.projects["acme/webapp"]
	f.member("acme/webapp", alice, levelDeveloper)
	f.member("acme/webapp", bob, levelDeveloper)
	f.groups["300"] = &fakeGroup{ID: 300, Members: map[int64]fakeMember{alice.ID: {Level: levelDeveloper, State: "active"}}}
	f.groups["301"] = &fakeGroup{ID: 301, Members: map[int64]fakeMember{}, status: 403}
	p.Protected = []map[string]any{
		protect("main", []map[string]any{entry("access_level", 40, "group_id", 300)}, nil),
		protect("staging", []map[string]any{entry("access_level", 40, "group_id", 301)}, nil),
	}
	srv, c := setup(t, f, nil)
	// Group resolved: alice is in group 300, bob is not.
	itest.ExpectCode(t, check(t, c, "alice@example.com", "repo.push", "project:acme/webapp@main"), integration.CodeAllowed)
	if last := srv.LastCall(); last.Path != "/api/v4/groups/300/members/all/7" {
		t.Error(last.Path)
	}
	itest.ExpectCode(t, check(t, c, "bob@example.com", "repo.push", "project:acme/webapp@main"), integration.CodeDenied)
	// Group unresolved (403): unknown.
	d := check(t, c, "alice@example.com", "repo.push", "project:acme/webapp@staging")
	itest.ExpectCode(t, d, integration.CodeUnsupported)
	if !strings.Contains(d.Text, "301") {
		t.Error(d.Text)
	}
}

func TestProtectedBranchAdminsAndCustomRoles(t *testing.T) {
	f := newFake()
	p := f.projects["acme/webapp"]
	f.member("acme/webapp", alice, levelMaintainer)
	f.member("acme/webapp", root, levelMaintainer)
	f.projects["acme/webapp"].Members[bob.ID] = fakeMember{Level: levelDeveloper, State: "active", RoleID: 5, RoleName: "pusher"}
	p.Protected = []map[string]any{
		protect("main", []map[string]any{entry("access_level", 60)}, nil),
		protect("roles", []map[string]any{entry("access_level", 30, "member_role_id", 5)}, nil),
		protect("strict", []map[string]any{entry("access_level", 40)}, nil),
	}
	_, c := setup(t, f, nil)
	// Admins only: known admin allowed, known non-admin denied.
	itest.ExpectCode(t, check(t, c, "root@example.com", "repo.push", "project:acme/webapp@main"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, "alice@example.com", "repo.push", "project:acme/webapp@main"), integration.CodeDenied)
	// Admin status unknown (non-admin token does not return is_admin): unknown.
	f.admin = false
	f.users = []fakeUser{{ID: 7, Username: "alice", State: "active", PublicEmail: "alice@example.com"}, {ID: 8, Username: "bob", State: "active", PublicEmail: "bob@example.com"}}
	itest.ExpectCode(t, check(t, c, "alice@example.com", "repo.push", "project:acme/webapp@main"), integration.CodeUnsupported)
	// Custom role entries.
	itest.ExpectCode(t, check(t, c, "bob@example.com", "repo.push", "project:acme/webapp@roles"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, "alice@example.com", "repo.push", "project:acme/webapp@roles"), integration.CodeUnsupported)
	// A member with a custom role whose base level misses the rule: unknown.
	itest.ExpectCode(t, check(t, c, "bob@example.com", "repo.push", "project:acme/webapp@strict"), integration.CodeUnsupported)
	itest.ExpectCode(t, check(t, c, "alice@example.com", "repo.push", "project:acme/webapp@strict"), integration.CodeAllowed)
}

func TestProtectedBranchListForbidden(t *testing.T) {
	f := newFake()
	f.member("acme/webapp", alice, levelDeveloper)
	f.projects["acme/webapp"].pbStatus = 403
	_, c := setup(t, f, nil)
	itest.ExpectCode(t, check(t, c, "alice@example.com", "repo.push", "project:acme/webapp@main"), integration.CodeCredentialRejected)
	// Without a branch the rules are still listed, so the 403 shows here too.
	itest.ExpectCode(t, check(t, c, "alice@example.com", "repo.push", "project:acme/webapp"), integration.CodeCredentialRejected)
	// Actions without a branch rule never list protected branches.
	itest.ExpectCode(t, check(t, c, "alice@example.com", "mr.create", "project:acme/webapp"), integration.CodeAllowed)
}

func TestWildcard(t *testing.T) {
	cases := []struct {
		pattern, name string
		want          bool
	}{
		{"main", "main", true},
		{"main", "maint", false},
		{"*", "anything/at/all", true},
		{"release/*", "release/1.0", true},
		{"release/*", "release/", true},
		{"release/*", "releases/1.0", false},
		{"*-stable", "v1-stable", true},
		{"*-stable", "v1-stable-x", false},
		{"v*.*.*", "v1.2.3", true},
		{"v*.*.*", "v1.2", false},
		{"**", "x", true},
		{"a*b*c", "abc", true},
		{"a*b*c", "axxbyyc", true},
		{"a*b*c", "axxbyy", false},
		{"", "", true},
		{"", "x", false},
	}
	for _, c := range cases {
		if got := matchWildcard(c.pattern, c.name); got != c.want {
			t.Errorf("matchWildcard(%q, %q) = %v", c.pattern, c.name, got)
		}
	}
}

func TestBadResources(t *testing.T) {
	f := newFake()
	_, c := setup(t, f, nil)
	cases := []struct{ action, resource string }{
		{"project.read", "group:acme"},
		{"group.member", "project:acme/webapp"},
		{"project.read", "repo:acme/webapp"},
		{"project.read", "project:"},
		{"project.read", "project:-bad"},
		{"project.read", "project:acme//webapp"},
		{"project.read", "project:acme/webapp/"},
		{"project.read", "project:acme/web app"},
		{"project.read", "project:../etc"},
		{"project.read", "project:acme/webapp?x=1"},
		{"repo.push", "project:acme/webapp@"},
		{"repo.push", "project:acme/webapp@-x"},
		{"repo.push", "project:acme/webapp@a..b"},
		{"repo.push", "project:acme/webapp@a b"},
		{"repo.push", "project:acme/webapp@a~b"},
		{"repo.push", "project:acme/webapp@a/"},
		{"group.member", "group:acme@main"},
	}
	for _, cs := range cases {
		d := check(t, c, "alice@example.com", cs.action, cs.resource)
		if d.Code != integration.CodeInvalidRequest {
			t.Errorf("%s %s -> %s: %s", cs.action, cs.resource, d.Code, d.Text)
		}
	}
	for _, ok := range []string{"acme/webapp", "acme/sub.group/web-app_2", "42", "a.b"} {
		if err := validatePath(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, ok := range []string{"main", "release/2.0", "feature/JIRA-123_x", "v1.2.3", "a@b"} {
		if err := validateBranch(ok); err != nil {
			t.Errorf("branch %q: %v", ok, err)
		}
	}
}

func TestFailures(t *testing.T) {
	f := newFake()
	f.member("acme/webapp", alice, levelDeveloper)
	srv, c := setup(t, f, nil)
	itest.FailureCases(t, srv, func() integration.Decision {
		return check(t, c, "alice@example.com", "repo.push", "project:acme/webapp@main")
	})
}

func TestProbe(t *testing.T) {
	f := newFake()
	srv, c := setup(t, f, nil)
	r, err := c.Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.Summary, "hallpass") || !strings.Contains(r.Summary, "administrator") || len(r.Warnings) != 0 {
		t.Errorf("%+v", r)
	}

	// Non-admin token with admin_search: warn. Broad scopes: warn.
	f.me.IsAdmin = false
	f.scopes = []string{"api", "read_api", "sudo"}
	r, err = c.Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Warnings) != 2 || !strings.Contains(r.Warnings[0], "administrator") || !strings.Contains(r.Warnings[1], "sudo") {
		t.Errorf("%+v", r.Warnings)
	}

	// Missing read_api.
	f.me.IsAdmin = true
	f.scopes = []string{"read_user"}
	r, _ = c.Probe(context.Background())
	if len(r.Warnings) != 1 || !strings.Contains(r.Warnings[0], "read_api") {
		t.Errorf("%+v", r.Warnings)
	}

	// Token endpoint unavailable: a warning, not an error.
	f.scopes = []string{"read_api"}
	f.tokenCode = 404
	r, err = c.Probe(context.Background())
	if err != nil || len(r.Warnings) != 1 || !strings.Contains(r.Warnings[0], "could not verify") {
		t.Errorf("%+v %v", r, err)
	}
	f.tokenCode = 0

	// Expiring soon.
	f.expiresAt = time.Now().Add(3 * 24 * time.Hour).Format("2006-01-02")
	r, _ = c.Probe(context.Background())
	if len(r.Warnings) != 1 || !strings.Contains(r.Warnings[0], "expires") {
		t.Errorf("%+v", r.Warnings)
	}
	f.expiresAt = ""

	// Group modes report the group; a missing group fails the probe.
	f.enterprise = []fakeUser{alice}
	_, c2 := setup(t, f, map[string]string{"identity_mode": "enterprise_users", "group": "acme"})
	r, err = c2.Probe(context.Background())
	if err != nil || !strings.Contains(r.Summary, "group acme") {
		t.Errorf("%+v %v", r, err)
	}
	_, c3 := setup(t, f, map[string]string{"identity_mode": "saml", "group": "other"})
	if _, err := c3.Probe(context.Background()); err == nil {
		t.Error("probe with an invisible group succeeded")
	}
	// Template mode on a non-admin token: no admin warning.
	f.me.IsAdmin = false
	_, c4 := setup(t, f, map[string]string{"identity_mode": "template", "email_domains": "example.com"})
	r, _ = c4.Probe(context.Background())
	if len(r.Warnings) != 0 {
		t.Errorf("%+v", r.Warnings)
	}
	// Bad credential.
	srv.Fail(itest.FailUnauthorized)
	defer srv.Fail(itest.FailNone)
	if _, err := c.Probe(context.Background()); err == nil {
		t.Error("expected error")
	} else if integration.ToDecision(err).Code != integration.CodeCredentialRejected {
		t.Errorf("401 on probe: %v", err)
	}
}

// Allow/deny tests per action (coverage gate).

func actionAllow(t *testing.T, action, resource string, level int) {
	t.Helper()
	f := newFake()
	if strings.HasPrefix(resource, "group:") {
		f.groupMember("acme", alice, level)
	} else {
		f.member("acme/webapp", alice, level)
	}
	_, c := setup(t, f, nil)
	itest.ExpectCode(t, check(t, c, "alice@example.com", action, resource), integration.CodeAllowed)
}

func actionDeny(t *testing.T, action, resource string, level int) {
	t.Helper()
	f := newFake()
	if strings.HasPrefix(resource, "group:") {
		f.groupMember("acme", alice, level)
	} else {
		f.member("acme/webapp", alice, level)
	}
	_, c := setup(t, f, nil)
	itest.ExpectCode(t, check(t, c, "alice@example.com", action, resource), integration.CodeDenied)
}

const proj = "project:acme/webapp"

func TestAction_project_read_allow(t *testing.T) { actionAllow(t, "project.read", proj, levelGuest) }
func TestAction_project_read_deny(t *testing.T)  { actionDeny(t, "project.read", proj, levelMinimal) }
func TestAction_issue_create_allow(t *testing.T) { actionAllow(t, "issue.create", proj, levelGuest) }
func TestAction_issue_create_deny(t *testing.T)  { actionDeny(t, "issue.create", proj, levelMinimal) }
func TestAction_issue_edit_allow(t *testing.T)   { actionAllow(t, "issue.edit", proj, levelPlanner) }
func TestAction_issue_edit_deny(t *testing.T)    { actionDeny(t, "issue.edit", proj, levelGuest) }
func TestAction_mr_create_allow(t *testing.T)    { actionAllow(t, "mr.create", proj, levelDeveloper) }
func TestAction_mr_create_deny(t *testing.T)     { actionDeny(t, "mr.create", proj, levelSecurityManager) }
func TestAction_mr_approve_allow(t *testing.T)   { actionAllow(t, "mr.approve", proj, levelDeveloper) }
func TestAction_mr_approve_deny(t *testing.T)    { actionDeny(t, "mr.approve", proj, levelGuest) }
func TestAction_repo_push_allow(t *testing.T)    { actionAllow(t, "repo.push", proj, levelDeveloper) }
func TestAction_repo_push_deny(t *testing.T)     { actionDeny(t, "repo.push", proj, levelReporter) }
func TestAction_mr_merge_allow(t *testing.T)     { actionAllow(t, "mr.merge", proj, levelMaintainer) }
func TestAction_mr_merge_deny(t *testing.T)      { actionDeny(t, "mr.merge", proj, levelReporter) }
func TestAction_branch_protect_allow(t *testing.T) {
	actionAllow(t, "branch.protect", proj, levelMaintainer)
}
func TestAction_branch_protect_deny(t *testing.T) {
	actionDeny(t, "branch.protect", proj, levelDeveloper)
}
func TestAction_project_admin_allow(t *testing.T) { actionAllow(t, "project.admin", proj, levelOwner) }
func TestAction_project_admin_deny(t *testing.T) {
	actionDeny(t, "project.admin", proj, levelDeveloper)
}
func TestAction_member_manage_allow(t *testing.T) {
	actionAllow(t, "member.manage", proj, levelMaintainer)
}
func TestAction_member_manage_deny(t *testing.T) {
	actionDeny(t, "member.manage", proj, levelDeveloper)
}
func TestAction_project_delete_allow(t *testing.T) {
	actionAllow(t, "project.delete", proj, levelOwner)
}
func TestAction_project_delete_deny(t *testing.T) {
	actionDeny(t, "project.delete", proj, levelMaintainer)
}
func TestAction_pipeline_run_allow(t *testing.T) {
	actionAllow(t, "pipeline.run", proj, levelDeveloper)
}
func TestAction_pipeline_run_deny(t *testing.T) { actionDeny(t, "pipeline.run", proj, levelPlanner) }
func TestAction_variable_manage_allow(t *testing.T) {
	actionAllow(t, "variable.manage", proj, levelMaintainer)
}
func TestAction_variable_manage_deny(t *testing.T) {
	actionDeny(t, "variable.manage", proj, levelDeveloper)
}
func TestAction_runner_manage_allow(t *testing.T) {
	actionAllow(t, "runner.manage", proj, levelMaintainer)
}
func TestAction_runner_manage_deny(t *testing.T) {
	actionDeny(t, "runner.manage", proj, levelDeveloper)
}
func TestAction_group_member_allow(t *testing.T) {
	actionAllow(t, "group.member", "group:acme", levelGuest)
}
func TestAction_group_member_deny(t *testing.T) {
	actionDeny(t, "group.member", "group:acme", levelMinimal)
}
func TestAction_group_admin_allow(t *testing.T) {
	actionAllow(t, "group.admin", "group:acme", levelOwner)
}
func TestAction_group_admin_deny(t *testing.T) {
	actionDeny(t, "group.admin", "group:acme", levelMaintainer)
}
func TestAction_group_project_create_allow(t *testing.T) {
	actionAllow(t, "group.project.create", "group:acme", levelDeveloper)
}
func TestAction_group_project_create_deny(t *testing.T) {
	actionDeny(t, "group.project.create", "group:acme", levelReporter)
}

func TestEveryActionHasASpec(t *testing.T) {
	for _, a := range (Integration{}).Actions() {
		if _, ok := actions[a.Name]; !ok || a.Pattern {
			t.Errorf("action %s", a.Name)
		}
		if _, ok := integration.FindAction(Integration{}, a.Name); !ok {
			t.Errorf("action %s not found", a.Name)
		}
	}
	if _, ok := integration.FindAction(Integration{}, "repo.delete"); ok {
		t.Error("unknown action matched")
	}
}

// Security-review findings.

func TestProtectedBranchDeployKeyEntry(t *testing.T) {
	f := newFake()
	p := f.projects["acme/webapp"]
	f.member("acme/webapp", alice, levelMaintainer)
	// alice's user id is 7, the same number as the deploy key: the entry
	// must never be read as naming her, nor as "Maintainers and up".
	p.Protected = []map[string]any{
		protect("main", []map[string]any{entry("access_level", 40, "deploy_key_id", 7)}, nil),
		protect("both", []map[string]any{entry("access_level", 40, "deploy_key_id", 7), entry("access_level", 40)}, nil),
	}
	_, c := setup(t, f, nil)
	d := check(t, c, "alice@example.com", "repo.push", "project:acme/webapp@main")
	itest.ExpectCode(t, d, integration.CodeDenied)
	if strings.Contains(d.Text, "no one") {
		t.Errorf("a deploy key may push, so the rule is not 'no one': %s", d.Text)
	}
	itest.ExpectCode(t, check(t, c, "alice@example.com", "repo.push", "project:acme/webapp@both"), integration.CodeAllowed)
}

func TestExternalUserOnInternalProject(t *testing.T) {
	f := newFake()
	ext := fakeUser{ID: 20, Username: "ext", State: "active", Email: "ext@example.com", PublicEmail: "ext@example.com", External: true}
	f.users = append(f.users, ext)
	_, c := setup(t, f, nil)
	id, err := c.ResolveIdentity(context.Background(), integration.User{Email: "ext@example.com"})
	if err != nil || id.Attr("external") != "true" {
		t.Fatalf("identity %+v %v", id, err)
	}
	// External users cannot see internal projects; public ones they can.
	d := check(t, c, "ext@example.com", "project.read", "project:acme/internal")
	itest.ExpectCode(t, d, integration.CodeDenied)
	if !strings.Contains(d.Text, "external") {
		t.Error(d.Text)
	}
	itest.ExpectCode(t, check(t, c, "ext@example.com", "issue.create", "project:acme/internal"), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, "ext@example.com", "project.read", "project:acme/public"), integration.CodeAllowed)
	// A known non-external user is still allowed.
	itest.ExpectCode(t, check(t, c, "alice@example.com", "project.read", "project:acme/internal"), integration.CodeAllowed)
	// A non-admin token cannot see the external flag: unknown on internal, allow on public.
	f.admin = false
	id, err = c.ResolveIdentity(context.Background(), integration.User{Email: "ext@example.com"})
	if err != nil || id.Attr("external") != "" {
		t.Fatalf("identity %+v %v", id, err)
	}
	itest.ExpectCode(t, check(t, c, "ext@example.com", "project.read", "project:acme/internal"), integration.CodeUnsupported)
	itest.ExpectCode(t, check(t, c, "ext@example.com", "project.read", "project:acme/public"), integration.CodeAllowed)
}

func TestAdminNonMemberAllowed(t *testing.T) {
	f := newFake()
	_, c := setup(t, f, nil)
	d := check(t, c, "root@example.com", "project.delete", "project:acme/webapp")
	itest.ExpectCode(t, d, integration.CodeAllowed)
	if !strings.Contains(d.Text, "instance administrator") {
		t.Error(d.Text)
	}
	itest.ExpectCode(t, check(t, c, "root@example.com", "group.admin", "group:acme"), integration.CodeAllowed)
	// A project the token cannot see is still not visible, even for an administrator.
	itest.ExpectCode(t, check(t, c, "root@example.com", "project.read", "project:acme/missing"), integration.CodeResourceNotVisible)
	// Issues disabled: even an administrator cannot create one.
	f.projects["acme/webapp"].IssuesAccessLevel = "disabled"
	itest.ExpectCode(t, check(t, c, "root@example.com", "issue.create", "project:acme/webapp"), integration.CodeDenied)
	// Administrator status unknown (non-admin token): the membership deny stands.
	f.admin = false
	f.users = []fakeUser{{ID: 1, Username: "root", State: "active", PublicEmail: "root@example.com"}}
	itest.ExpectCode(t, check(t, c, "root@example.com", "project.delete", "project:acme/webapp"), integration.CodeDenied)
}

func fillerUsers(n int) []fakeUser {
	out := make([]fakeUser, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, fakeUser{ID: int64(1000 + i), Username: fmt.Sprintf("filler%d", i), State: "active", Email: fmt.Sprintf("filler%d@example.com", i)})
	}
	return out
}

func TestSecondaryEmailsAndPagination(t *testing.T) {
	f := newFake()
	carol := fakeUser{ID: 30, Username: "carol", State: "active", Email: "carol@example.com", Emails: []any{
		map[string]any{"email": "Carol.Alias@example.com", "confirmed_at": "2020-01-02T03:04:05Z"},
		map[string]any{"email": "pending@example.com", "confirmed_at": nil},
		"plain@example.com",
	}}
	// carol is on page 2 of a 100-per-page listing.
	f.searchHits = append(fillerUsers(150), carol)
	srv, c := setup(t, f, nil)
	id, err := c.ResolveIdentity(context.Background(), integration.User{Email: "carol@example.com"})
	if err != nil || id.ID != "30" {
		t.Fatalf("primary email on page 2: %+v %v", id, err)
	}
	pages := map[string]bool{}
	for _, call := range srv.Calls() {
		if call.Path == "/api/v4/users" {
			if call.Query.Get("per_page") != "100" {
				t.Errorf("per_page %q", call.Query.Get("per_page"))
			}
			pages[call.Query.Get("page")] = true
		}
	}
	if len(pages) != 2 || !pages["1"] || !pages["2"] {
		t.Errorf("pages fetched: %v", pages)
	}
	// A confirmed secondary email matches, ignoring case.
	id, err = c.ResolveIdentity(context.Background(), integration.User{Email: "carol.alias@example.com"})
	if err != nil || id.ID != "30" {
		t.Errorf("confirmed secondary email: %+v %v", id, err)
	}
	// A secondary email without confirmed_at at all is accepted.
	id, err = c.ResolveIdentity(context.Background(), integration.User{Email: "plain@example.com"})
	if err != nil || id.ID != "30" {
		t.Errorf("secondary email without confirmed_at: %+v %v", id, err)
	}
	// An unconfirmed secondary email never matches.
	_, err = c.ResolveIdentity(context.Background(), integration.User{Email: "pending@example.com"})
	if integration.ToDecision(err).Code != integration.CodeUserNotFound {
		t.Errorf("unconfirmed secondary email: %v", err)
	}
	// Never a substring.
	_, err = c.ResolveIdentity(context.Background(), integration.User{Email: "alias@example.com"})
	if integration.ToDecision(err).Code != integration.CodeUserNotFound {
		t.Errorf("substring: %v", err)
	}
	// Two accounts sharing a secondary email are ambiguous.
	dave := fakeUser{ID: 31, Username: "dave", State: "active", Email: "dave@example.com", Emails: []any{map[string]any{"email": "carol.alias@example.com", "confirmed_at": "2020-01-02T03:04:05Z"}}}
	f.searchHits = []fakeUser{carol, dave}
	_, err = c.ResolveIdentity(context.Background(), integration.User{Email: "carol.alias@example.com"})
	if integration.ToDecision(err).Code != integration.CodeUserAmbiguous {
		t.Errorf("shared secondary email: %v", err)
	}
}

func TestSearchTooManyCandidates(t *testing.T) {
	f := newFake()
	f.searchHits = fillerUsers(520)
	srv, c := setup(t, f, nil)
	_, err := c.ResolveIdentity(context.Background(), integration.User{Email: "alice@example.com"})
	d := integration.ToDecision(err)
	itest.ExpectCode(t, d, integration.CodeUnsupported)
	if !strings.Contains(d.Text, "too many candidates") {
		t.Error(d.Text)
	}
	n := 0
	for _, call := range srv.Calls() {
		if call.Path == "/api/v4/users" {
			n++
		}
	}
	if n != 5 {
		t.Errorf("%d pages fetched, want 5", n)
	}
	// A match on the fifth page is still found.
	f.searchHits = append(fillerUsers(450), alice)
	id, err := c.ResolveIdentity(context.Background(), integration.User{Email: "alice@example.com"})
	if err != nil || id.ID != "7" {
		t.Errorf("match on page 5: %+v %v", id, err)
	}
	// Exactly five full pages and no match: unknown, not user_not_found.
	f.searchHits = fillerUsers(500)
	_, err = c.ResolveIdentity(context.Background(), integration.User{Email: "alice@example.com"})
	itest.ExpectCode(t, integration.ToDecision(err), integration.CodeUnsupported)
	// A short last page with no match: user_not_found.
	f.searchHits = fillerUsers(499)
	_, err = c.ResolveIdentity(context.Background(), integration.User{Email: "alice@example.com"})
	itest.ExpectCode(t, integration.ToDecision(err), integration.CodeUserNotFound)
}

func TestBranchlessPushWithProtectedRules(t *testing.T) {
	f := newFake()
	f.member("acme/webapp", alice, levelDeveloper)
	f.member("acme/webapp", bob, levelMaintainer)
	f.projects["acme/webapp"].Protected = []map[string]any{
		protect("main", []map[string]any{entry("access_level", 40)}, []map[string]any{entry("access_level", 40)}),
	}
	srv, c := setup(t, f, nil)
	for _, action := range []string{"repo.push", "mr.merge"} {
		for _, u := range []string{"alice@example.com", "bob@example.com"} {
			d := check(t, c, u, action, "project:acme/webapp")
			itest.ExpectCode(t, d, integration.CodeUnsupported)
			if !strings.Contains(d.Text, "@branch") {
				t.Errorf("%s %s: %s", action, u, d.Text)
			}
		}
	}
	// With the branch named, the rule decides.
	itest.ExpectCode(t, check(t, c, "alice@example.com", "repo.push", "project:acme/webapp@main"), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, "bob@example.com", "repo.push", "project:acme/webapp@main"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, "alice@example.com", "repo.push", "project:acme/webapp@feature"), integration.CodeAllowed)
	// No rules at all: the level rule applies.
	f.projects["acme/webapp"].Protected = nil
	srv.Reset()
	itest.ExpectCode(t, check(t, c, "alice@example.com", "repo.push", "project:acme/webapp"), integration.CodeAllowed)
	listed := false
	for _, call := range srv.Calls() {
		if strings.HasSuffix(call.Path, "/protected_branches") {
			listed = true
		}
	}
	if !listed {
		t.Error("protected branches were not listed for a branchless push")
	}
	// A level that never pushes is still denied when no rules exist.
	f.member("acme/webapp", alice, levelReporter)
	itest.ExpectCode(t, check(t, c, "alice@example.com", "repo.push", "project:acme/webapp"), integration.CodeDenied)
}

func TestPublicIssueCreationAndIssuesDisabled(t *testing.T) {
	f := newFake()
	pub := f.projects["acme/public"]
	_, c := setup(t, f, nil)
	itest.ExpectCode(t, check(t, c, "alice@example.com", "issue.create", "project:acme/public"), integration.CodeAllowed)
	pub.IssuesAccessLevel = "enabled"
	itest.ExpectCode(t, check(t, c, "alice@example.com", "issue.create", "project:acme/public"), integration.CodeAllowed)
	pub.IssuesAccessLevel = "disabled"
	d := check(t, c, "alice@example.com", "issue.create", "project:acme/public")
	itest.ExpectCode(t, d, integration.CodeDenied)
	if !strings.Contains(d.Text, "issues") {
		t.Error(d.Text)
	}
	// Issues disabled does not touch other actions.
	itest.ExpectCode(t, check(t, c, "alice@example.com", "project.read", "project:acme/public"), integration.CodeAllowed)
	// issues_enabled false (older shape) also denies.
	pub.IssuesAccessLevel = ""
	no := false
	pub.IssuesEnabled = &no
	itest.ExpectCode(t, check(t, c, "alice@example.com", "issue.create", "project:acme/public"), integration.CodeDenied)
	// Issues for members only: a non-member is denied.
	pub.IssuesEnabled = nil
	pub.IssuesAccessLevel = "private"
	itest.ExpectCode(t, check(t, c, "alice@example.com", "issue.create", "project:acme/public"), integration.CodeDenied)
	// Internal projects stay open to non-external signed-in users.
	itest.ExpectCode(t, check(t, c, "alice@example.com", "issue.create", "project:acme/internal"), integration.CodeAllowed)
	f.projects["acme/internal"].IssuesAccessLevel = "disabled"
	itest.ExpectCode(t, check(t, c, "alice@example.com", "issue.create", "project:acme/internal"), integration.CodeDenied)
}

func TestAccountStateHandling(t *testing.T) {
	f := newFake()
	mk := func(id int64, state string) fakeUser {
		return fakeUser{ID: id, Username: fmt.Sprintf("u%d", id), State: state, Email: fmt.Sprintf("u%d@example.com", id)}
	}
	states := map[int64]string{40: "", 41: "deactivated", 42: "ldap_blocked", 43: "banned", 44: "blocked_pending_approval", 45: "blocked", 46: "something_new"}
	for id, st := range states {
		u := mk(id, st)
		f.users = append(f.users, u)
		f.member("acme/webapp", u, levelOwner)
	}
	_, c := setup(t, f, nil)
	for _, id := range []int64{41, 42, 43, 44, 45} {
		d := check(t, c, fmt.Sprintf("u%d@example.com", id), "project.read", "project:acme/webapp")
		itest.ExpectCode(t, d, integration.CodeDenied)
		if !strings.Contains(d.Text, states[id]) {
			t.Error(d.Text)
		}
	}
	// Empty or unrecognised state: hallpass cannot tell, so unknown.
	for _, id := range []int64{40, 46} {
		d := check(t, c, fmt.Sprintf("u%d@example.com", id), "project.read", "project:acme/webapp")
		itest.ExpectCode(t, d, integration.CodeUnsupported)
	}
}

// TestEmailDomainsSpacedList: `acme.com, acme.io` (with the space) is one
// list of two domains, and an upper-case entry matches the lower-case email.
func TestEmailDomainsSpacedList(t *testing.T) {
	f := newFake()
	f.admin = false
	f.member("acme/webapp", bob, levelDeveloper)
	_, c := setup(t, f, map[string]string{"identity_mode": "template", "username_template": "{local}", "email_domains": "Acme.com, acme.io"})
	itest.ExpectCode(t, check(t, c, "bob@acme.io", "mr.create", "project:acme/webapp"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, "bob@acme.com", "mr.create", "project:acme/webapp"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, "bob@acme.org", "mr.create", "project:acme/webapp"), integration.CodeUnsupported)
}

func TestTemplateDomainAllowlist(t *testing.T) {
	f := newFake()
	f.admin = false
	f.member("acme/webapp", root, levelOwner)
	f.member("acme/webapp", bob, levelDeveloper)
	_, c := setup(t, f, map[string]string{"identity_mode": "template", "username_template": "{local}", "email_domains": "acme.com,acme.io"})
	// A listed domain resolves through the template.
	itest.ExpectCode(t, check(t, c, "bob@acme.io", "mr.create", "project:acme/webapp"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, "bob@ACME.com", "mr.create", "project:acme/webapp"), integration.CodeAllowed)
	// root@attacker.example must not become the root account: unknown, not a lookup.
	d := check(t, c, "root@attacker.example", "project.delete", "project:acme/webapp")
	itest.ExpectCode(t, d, integration.CodeUnsupported)
	if !strings.Contains(d.Text, "domain not allowed for template identities") {
		t.Error(d.Text)
	}
	for _, e := range []string{"root@sub.acme.com", "root@acme.com.evil", "root@acme.comm", "root", "root@"} {
		itest.ExpectCode(t, check(t, c, e, "project.delete", "project:acme/webapp"), integration.CodeUnsupported)
	}
	// With an administrator's token the account's email is visible and must
	// equal the request email.
	f.admin = true
	itest.ExpectCode(t, check(t, c, "bob@acme.com", "mr.create", "project:acme/webapp"), integration.CodeUserNotFound)
	f.users = append(f.users, fakeUser{ID: 50, Username: "eve", State: "active", Email: "Eve@Acme.com"})
	f.member("acme/webapp", fakeUser{ID: 50}, levelDeveloper)
	itest.ExpectCode(t, check(t, c, "eve@acme.com", "mr.create", "project:acme/webapp"), integration.CodeAllowed)
}
