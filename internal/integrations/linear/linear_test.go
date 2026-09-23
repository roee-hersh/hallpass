package linear

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/roee-hersh/hallpass/internal/integration"
	"github.com/roee-hersh/hallpass/internal/integration/itest"
	"github.com/roee-hersh/hallpass/internal/secret"
)

const (
	uOwner = "00000000-0000-4000-8000-000000000001"
	uAdmin = "00000000-0000-4000-8000-000000000002"
	uDana  = "00000000-0000-4000-8000-000000000003" // member of ENG and SEC
	uBob   = "00000000-0000-4000-8000-000000000004" // member of nothing
	uGus   = "00000000-0000-4000-8000-000000000005" // guest in SEC
	uLead  = "00000000-0000-4000-8000-000000000006" // owner of team ENG
	uApp   = "00000000-0000-4000-8000-000000000007"
	uSusp  = "00000000-0000-4000-8000-000000000008"
	uPend  = "00000000-0000-4000-8000-000000000009"
	uBot   = "00000000-0000-4000-8000-000000000010"

	tENG = "10000000-0000-4000-8000-000000000001" // public
	tSEC = "10000000-0000-4000-8000-000000000002" // private
	tRST = "10000000-0000-4000-8000-000000000003" // restricted
	tOLD = "10000000-0000-4000-8000-000000000004" // archived

	pENG  = "20000000-0000-4000-8000-000000000001"
	pSEC  = "20000000-0000-4000-8000-000000000002"
	pBoth = "20000000-0000-4000-8000-000000000003"
	pNone = "20000000-0000-4000-8000-000000000004"
)

var (
	owner = integration.User{Email: "owner@example.com"}
	admin = integration.User{Email: "admin@example.com"}
	dana  = integration.User{Email: "dana@example.com"}
	bob   = integration.User{Email: "bob@example.com"}
	gus   = integration.User{Email: "gus@example.com"}
	lead  = integration.User{Email: "lead@example.com"}
	app   = integration.User{Email: "app@example.com"}
)

type fakeUser struct {
	id, email                        string
	active, admin, owner, guest, app bool
	disableReason                    *string
	teams                            map[string]bool // team id -> owner
}

type fakeTeam struct {
	id, key, visibility string
	archived            bool
}

type fakeIssue struct {
	id, identifier, team string
	trashed              bool
}

type fakeProject struct {
	id, slug string
	teams    []string
	trashed  bool
}

func sp(s string) *string { return &s }

type fake struct {
	t  *testing.T
	mu sync.Mutex

	token    string
	users    []fakeUser
	teams    map[string]fakeTeam
	issues   map[string]fakeIssue
	projects map[string]fakeProject
	status   int
	gqlError string // extensions.type to answer every query with
	notFound string // message for lookups of unknown objects
	ghost    string // a user id whose memberships answer not found
	pageSize int
}

func newFake(t *testing.T) *fake {
	return &fake{t: t, token: itest.Canary + "key", pageSize: 100, notFound: "Entity not found: Issue - Could not find referenced Issue.",
		users: []fakeUser{
			{id: uBot, email: "bot@example.com", active: true, admin: true},
			{id: uOwner, email: "owner@example.com", active: true, admin: true, owner: true, teams: map[string]bool{tENG: true}},
			{id: uAdmin, email: "admin@example.com", active: true, admin: true},
			{id: uDana, email: "dana@example.com", active: true, teams: map[string]bool{tENG: false, tSEC: false}},
			{id: uBob, email: "bob@example.com", active: true},
			{id: uGus, email: "gus@example.com", active: true, guest: true, teams: map[string]bool{tSEC: false}},
			{id: uLead, email: "lead@example.com", active: true, teams: map[string]bool{tENG: true}},
			{id: uApp, email: "app@example.com", active: true, app: true},
			{id: uSusp, email: "susp@example.com", active: false, disableReason: sp("admin suspension")},
			{id: uPend, email: "pend@example.com", active: false, disableReason: sp("pending invite")},
		},
		teams: map[string]fakeTeam{
			tENG: {tENG, "ENG", "public", false},
			tSEC: {tSEC, "SEC", "private", false},
			tRST: {tRST, "RST", "restricted", false},
			tOLD: {tOLD, "OLD", "public", true},
		},
		issues: map[string]fakeIssue{
			"ENG-1": {"30000000-0000-4000-8000-000000000001", "ENG-1", tENG, false},
			"ENG-2": {"30000000-0000-4000-8000-000000000002", "ENG-2", tENG, true},
			"SEC-1": {"30000000-0000-4000-8000-000000000003", "SEC-1", tSEC, false},
			"RST-1": {"30000000-0000-4000-8000-000000000004", "RST-1", tRST, false},
		},
		projects: map[string]fakeProject{
			pENG:  {pENG, "eng-proj", []string{tENG}, false},
			pSEC:  {pSEC, "sec-proj", []string{tSEC}, false},
			pBoth: {pBoth, "both-proj", []string{tSEC, tENG}, false},
			pNone: {pNone, "none-proj", nil, false},
		},
	}
}

func write(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func gqlErr(w http.ResponseWriter, status int, typ, msg string) {
	write(w, status, map[string]any{"errors": []map[string]any{{"message": msg, "extensions": map[string]any{"type": typ, "userError": true, "userPresentableMessage": itest.Canary}}}})
}

func (f *fake) userJSON(u fakeUser) map[string]any {
	return map[string]any{"id": u.id, "email": u.email, "name": itest.Canary + " name", "active": u.active, "admin": u.admin, "owner": u.owner, "guest": u.guest, "app": u.app, "disableReason": u.disableReason}
}

func (f *fake) teamJSON(id string) map[string]any {
	t := f.teams[id]
	var archived any
	if t.archived {
		archived = "2026-01-01T00:00:00.000Z"
	}
	return map[string]any{"id": t.id, "key": t.key, "name": itest.Canary + " team", "visibility": t.visibility, "archivedAt": archived}
}

func (f *fake) api(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if h := r.Header.Get("Authorization"); h != f.token && !strings.EqualFold(h, "Bearer "+f.token) {
		gqlErr(w, 401, "authentication error", itest.Canary)
		return
	}
	if f.status != 0 {
		write(w, f.status, map[string]any{"errors": []map[string]any{{"message": itest.Canary}}})
		return
	}
	if f.gqlError != "" {
		gqlErr(w, 400, f.gqlError, itest.Canary)
		return
	}
	var body struct {
		Query     string         `json:"query"`
		Variables map[string]any `json:"variables"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		f.t.Errorf("fake: bad body: %v", err)
		return
	}
	q, v := body.Query, body.Variables
	data := map[string]any{}
	switch {
	case strings.Contains(q, "users(filter"):
		email, _ := v["email"].(string)
		nodes := []map[string]any{}
		for _, u := range f.users {
			if strings.EqualFold(u.email, email) {
				nodes = append(nodes, f.userJSON(u))
			}
		}
		if email == "dup@example.com" {
			nodes = append(nodes, f.userJSON(fakeUser{id: "00000000-0000-4000-8000-0000000000aa", email: "dup@example.com", active: true}), f.userJSON(fakeUser{id: "00000000-0000-4000-8000-0000000000ab", email: "Dup@example.com", active: true}))
		}
		data["users"] = map[string]any{"nodes": nodes}
	case strings.Contains(q, "teamMemberships("):
		id, _ := v["id"].(string)
		var u *fakeUser
		for i := range f.users {
			if f.users[i].id == id {
				u = &f.users[i]
			}
		}
		if u == nil || u.id == f.ghost {
			gqlErr(w, 200, "invalid input", strings.ReplaceAll(f.notFound, "Issue", "User"))
			return
		}
		var all []map[string]any
		for _, tid := range sortedKeys(u.teams) {
			all = append(all, map[string]any{"owner": u.teams[tid], "team": map[string]any{"id": tid, "key": f.teams[tid].key}})
		}
		start := 0
		if after, _ := v["after"].(string); after != "" {
			fmt.Sscanf(after, "cursor-%d", &start)
		}
		end := start + f.pageSize
		if end > len(all) {
			end = len(all)
		}
		if start > len(all) {
			start = len(all)
		}
		nodes := all[start:end]
		if nodes == nil {
			nodes = []map[string]any{}
		}
		var cursor any
		if end < len(all) {
			cursor = fmt.Sprintf("cursor-%d", end)
		}
		data["user"] = map[string]any{"teamMemberships": map[string]any{"nodes": nodes, "pageInfo": map[string]any{"hasNextPage": end < len(all), "endCursor": cursor}}}
	case strings.Contains(q, "teams(filter"):
		filter, _ := v["filter"].(map[string]any)
		nodes := []map[string]any{}
		for _, id := range sortedKeys(f.teams) {
			t := f.teams[id]
			if key, ok := filter["key"].(map[string]any); ok && key["eq"] == t.key {
				nodes = append(nodes, f.teamJSON(id))
			}
			if idf, ok := filter["id"].(map[string]any); ok && idf["eq"] == t.id {
				nodes = append(nodes, f.teamJSON(id))
			}
		}
		data["teams"] = map[string]any{"nodes": nodes}
	case strings.Contains(q, "issue(id"):
		id, _ := v["id"].(string)
		var found *fakeIssue
		for k := range f.issues {
			is := f.issues[k]
			if is.identifier == id || is.id == id {
				found = &is
			}
		}
		if found == nil {
			gqlErr(w, 200, "invalid input", f.notFound)
			return
		}
		var archived any
		data["issue"] = map[string]any{"id": found.id, "identifier": found.identifier, "trashed": found.trashed, "archivedAt": archived, "team": f.teamJSON(found.team)}
	case strings.Contains(q, "project(id"):
		id, _ := v["id"].(string)
		var found *fakeProject
		for k := range f.projects {
			p := f.projects[k]
			if p.id == id || p.slug == id {
				found = &p
			}
		}
		if found == nil {
			gqlErr(w, 200, "invalid input", strings.ReplaceAll(f.notFound, "Issue", "Project"))
			return
		}
		teams := []map[string]any{}
		for _, tid := range found.teams {
			teams = append(teams, f.teamJSON(tid))
		}
		data["project"] = map[string]any{"id": found.id, "name": itest.Canary, "slugId": found.slug, "trashed": found.trashed, "archivedAt": nil, "teams": map[string]any{"nodes": teams}}
	case strings.Contains(q, "viewer {"):
		data["viewer"] = f.userJSON(f.users[0])
		data["organization"] = map[string]any{"id": "40000000-0000-4000-8000-000000000001", "name": itest.Canary, "urlKey": "acme"}
	default:
		f.t.Errorf("fake: no handler for query %s", q)
		gqlErr(w, 400, "graphql error", itest.Canary)
		return
	}
	write(w, 200, map[string]any{"data": data})
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	for i := range keys {
		for j := i + 1; j < len(keys); j++ {
			if keys[j] < keys[i] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	return keys
}

func setupMode(t *testing.T, mode string) (*itest.Server, *fake, integration.Connection) {
	t.Helper()
	srv := itest.NewServer(t)
	srv.UseSpec(itest.SpecFromEnv(t, "linear"), itest.SpecOptions{})
	f := newFake(t)
	srv.Handle("POST", "/graphql", f.api)
	deps, _ := itest.Deps(t, srv)
	values := map[string]string{"url": srv.URL + "/graphql"}
	if mode != "" {
		values["auth_mode"] = mode
	}
	s := itest.Settings("ln", "linear", values, map[string]secret.Secret{"credential": secret.Literal(f.token)})
	c, err := (Integration{}).New(context.Background(), s, deps)
	if err != nil {
		t.Fatal(err)
	}
	return srv, f, c
}

func setup(t *testing.T) (*itest.Server, *fake, integration.Connection) {
	t.Helper()
	return setupMode(t, "")
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

// --- the action table -------------------------------------------------------

func TestAction_team_view_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, bob, "team.view", "team:ENG"), integration.CodeAllowed, "public")
	expect(t, check(t, c, dana, "team.view", "team:SEC"), integration.CodeAllowed, "member of private team SEC")
	expect(t, check(t, c, gus, "team.view", "team:SEC"), integration.CodeAllowed, "member of private team SEC")
	// By id, in any case.
	expect(t, check(t, c, bob, "team.view", "team:"+strings.ToUpper(tENG)), integration.CodeAllowed, "public")
}
func TestAction_team_view_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, bob, "team.view", "team:SEC"), integration.CodeDenied, "private")
	expect(t, check(t, c, gus, "team.view", "team:ENG"), integration.CodeDenied, "guest")
}
func TestTeamVisibilityUnknowns(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, admin, "team.view", "team:SEC"), integration.CodeUnsupported, "administrator but not a member")
	expect(t, check(t, c, bob, "team.view", "team:RST"), integration.CodeUnsupported, "restricted")
	expect(t, check(t, c, bob, "team.view", "team:OLD"), integration.CodeUnsupported, "archived")
	expect(t, check(t, c, admin, "team.admin", "team:OLD"), integration.CodeUnsupported, "archived")
	expect(t, check(t, c, admin, "team.member", "team:OLD"), integration.CodeUnsupported, "archived")
	expect(t, check(t, c, bob, "team.view", "team:NOPE"), integration.CodeResourceNotVisible, "team NOPE")
	expect(t, check(t, c, app, "team.view", "team:ENG"), integration.CodeUnsupported, "app user")
}
func TestAction_team_member_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, dana, "team.member", "team:ENG"), integration.CodeAllowed, "member of team ENG")
	expect(t, check(t, c, gus, "team.member", "team:SEC"), integration.CodeAllowed, "")
}
func TestAction_team_member_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, bob, "team.member", "team:ENG"), integration.CodeDenied, "not a member")
	expect(t, check(t, c, admin, "team.member", "team:ENG"), integration.CodeDenied, "not a member")
}
func TestAction_team_admin_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, lead, "team.admin", "team:ENG"), integration.CodeAllowed, "owner of team ENG")
	expect(t, check(t, c, admin, "team.admin", "team:SEC"), integration.CodeAllowed, "workspace administrator")
	expect(t, check(t, c, owner, "team.admin", "team:SEC"), integration.CodeAllowed, "")
}
func TestAction_team_admin_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, bob, "team.admin", "team:ENG"), integration.CodeDenied, "not a member")
	expect(t, check(t, c, dana, "team.admin", "team:ENG"), integration.CodeUnsupported, "not an owner")
}
func TestAction_issue_view_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, bob, "issue.view", "issue:ENG-1"), integration.CodeAllowed, "public")
	expect(t, check(t, c, dana, "issue.view", "issue:SEC-1"), integration.CodeAllowed, "private team SEC")
	expect(t, check(t, c, bob, "issue.view", "issue:eng-1"), integration.CodeAllowed, "")
	expect(t, check(t, c, bob, "issue.view", "issue:30000000-0000-4000-8000-000000000001"), integration.CodeAllowed, "")
}
func TestAction_issue_view_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, bob, "issue.view", "issue:SEC-1"), integration.CodeDenied, "private")
	expect(t, check(t, c, gus, "issue.view", "issue:ENG-1"), integration.CodeDenied, "guest")
	expect(t, check(t, c, bob, "issue.view", "issue:ENG-9"), integration.CodeResourceNotVisible, "issue ENG-9")
	expect(t, check(t, c, bob, "issue.view", "issue:ENG-2"), integration.CodeUnsupported, "trash")
	expect(t, check(t, c, bob, "issue.view", "issue:RST-1"), integration.CodeUnsupported, "restricted")
}
func TestAction_issue_edit_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, gus, "issue.edit", "issue:SEC-1"), integration.CodeAllowed, "edit and comment")
	expect(t, check(t, c, bob, "issue.edit", "issue:ENG-1"), integration.CodeAllowed, "")
}
func TestAction_issue_edit_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, bob, "issue.edit", "issue:SEC-1"), integration.CodeDenied, "")
}
func TestAction_project_view_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, bob, "project.view", "project:"+pENG), integration.CodeAllowed, "public")
	// One visible team suffices.
	expect(t, check(t, c, bob, "project.view", "project:both-proj"), integration.CodeAllowed, "public")
	expect(t, check(t, c, gus, "project.view", "project:both-proj"), integration.CodeAllowed, "private team SEC")
}
func TestAction_project_view_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, bob, "project.view", "project:sec-proj"), integration.CodeDenied, "cannot see any of the 1 team(s)")
	expect(t, check(t, c, gus, "project.view", "project:eng-proj"), integration.CodeDenied, "")
	expect(t, check(t, c, bob, "project.view", "project:none-proj"), integration.CodeUnsupported, "no team")
	expect(t, check(t, c, admin, "project.view", "project:sec-proj"), integration.CodeUnsupported, "administrator")
	expect(t, check(t, c, bob, "project.view", "project:missing"), integration.CodeResourceNotVisible, "project missing")
}
func TestAction_workspace_member_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, bob, "workspace.member", "workspace"), integration.CodeAllowed, "full member")
	expect(t, check(t, c, admin, "workspace.member", "workspace"), integration.CodeAllowed, "")
}
func TestAction_workspace_member_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, gus, "workspace.member", "workspace"), integration.CodeDenied, "guest")
	expect(t, check(t, c, app, "workspace.member", "workspace"), integration.CodeDenied, "app")
}
func TestAction_workspace_admin_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, admin, "workspace.admin", "workspace"), integration.CodeAllowed, "administrator")
	expect(t, check(t, c, owner, "workspace.admin", "workspace"), integration.CodeAllowed, "owner")
}
func TestAction_workspace_admin_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, dana, "workspace.admin", "workspace"), integration.CodeDenied, "neither")
}
func TestAction_workspace_owner_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, owner, "workspace.owner", "workspace"), integration.CodeAllowed, "owner")
}
func TestAction_workspace_owner_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, admin, "workspace.owner", "workspace"), integration.CodeDenied, "not a workspace owner")
}

// --- identity ---------------------------------------------------------------

func TestIdentity(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, integration.User{Email: "nobody@example.com"}, "workspace.member", "workspace"), integration.CodeUserNotFound, "no Linear user")
	expect(t, check(t, c, integration.User{Email: "dup@example.com"}, "workspace.member", "workspace"), integration.CodeUserAmbiguous, "2 Linear users")
	expect(t, check(t, c, integration.User{Email: "not an email"}, "workspace.member", "workspace"), integration.CodeInvalidRequest, "")
	expect(t, check(t, c, integration.User{Email: "susp@example.com"}, "workspace.member", "workspace"), integration.CodeDenied, "admin suspension")
	expect(t, check(t, c, integration.User{Email: "pend@example.com"}, "team.view", "team:ENG"), integration.CodeDenied, "pending invite")
}

func TestIdentityAttrs(t *testing.T) {
	_, _, c := setup(t)
	id, err := c.ResolveIdentity(context.Background(), lead)
	if err != nil {
		t.Fatal(err)
	}
	if id.ID != uLead || id.Attr("owned_teams") != tENG || len(id.Groups) != 1 || id.Groups[0] != tENG {
		t.Errorf("identity %+v", id)
	}
	for k, v := range id.Attrs {
		itest.AssertNoCanary(t, k+"="+v)
	}
}

func TestMembershipPaging(t *testing.T) {
	srv, f, c := setup(t)
	f.mu.Lock()
	f.pageSize = 1
	for i := range f.users {
		if f.users[i].id == uDana {
			f.users[i].teams = map[string]bool{tENG: false, tSEC: true, tRST: false}
		}
	}
	f.mu.Unlock()
	id, err := c.ResolveIdentity(context.Background(), dana)
	if err != nil {
		t.Fatal(err)
	}
	if len(id.Groups) != 3 || id.Attr("owned_teams") != tSEC {
		t.Errorf("identity %+v", id)
	}
	pages := 0
	for _, call := range srv.Calls() {
		if strings.Contains(string(call.Body), "teamMemberships") {
			pages++
		}
	}
	if pages != 3 {
		t.Errorf("%d membership pages, want 3", pages)
	}
}

func TestCallerGroupsIgnored(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, integration.User{Email: "bob@example.com", Groups: []string{tSEC, "SEC"}}, "team.view", "team:SEC"), integration.CodeDenied, "")
}

func TestVariablesCarryInput(t *testing.T) {
	srv, _, c := setup(t)
	check(t, c, bob, "issue.view", "issue:ENG-1")
	for _, call := range srv.Calls() {
		var body struct {
			Query     string         `json:"query"`
			Variables map[string]any `json:"variables"`
		}
		if err := json.Unmarshal(call.Body, &body); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(body.Query, "example.com") || strings.Contains(body.Query, "ENG-1") {
			t.Errorf("value interpolated into the query: %s", body.Query)
		}
	}
}

func TestInvalidRequests(t *testing.T) {
	_, _, c := setup(t)
	for _, tc := range [][2]string{
		{"team.view", "team:eng team"}, {"team.view", "team:"}, {"team.view", "issue:ENG-1"},
		{"team.view", "team:ENG?x=1"}, {"workspace.admin", "workspace:1"}, {"issue.view", "issue:ENG"},
		{"issue.view", "issue:ENG-0"}, {"issue.view", "issue:ENG-1/2"}, {"project.view", "project:a/b"},
		{"team.view", "team:TOOLONGTEAMKEY"},
	} {
		d := check(t, c, bob, tc[0], tc[1])
		if d.Code != integration.CodeInvalidRequest {
			t.Errorf("%s %s: %s %s", tc[0], tc[1], d.Code, d.Text)
		}
	}
}

func TestFailures(t *testing.T) {
	srv, _, c := setup(t)
	itest.FailureCases(t, srv, func() integration.Decision { return check(t, c, bob, "team.view", "team:ENG") })
}

func TestGraphQLErrors(t *testing.T) {
	_, f, c := setup(t)
	for typ, code := range map[string]integration.Code{
		"ratelimited":            integration.CodeUpstreamRateLimit,
		"usage limit exceeded":   integration.CodeUpstreamRateLimit,
		"authentication error":   integration.CodeCredentialRejected,
		"forbidden":              integration.CodeCredentialRejected,
		"feature not accessible": integration.CodeCredentialRejected,
		"internal error":         integration.CodeUpstreamError,
	} {
		f.mu.Lock()
		f.gqlError = typ
		f.mu.Unlock()
		d := check(t, c, bob, "team.view", "team:ENG")
		if d.Code != code {
			t.Errorf("%s: %s %s, want %s", typ, d.Code, d.Text, code)
		}
		itest.AssertNoCanary(t, d.Text)
	}
	// A not-found while listing memberships is an upstream inconsistency,
	// not resource_not_visible.
	f.mu.Lock()
	f.gqlError = ""
	f.users = append(f.users, fakeUser{id: "00000000-0000-4000-8000-0000000000ff", email: "ghost@example.com", active: true})
	f.mu.Unlock()
	f.mu.Lock()
	f.ghost = "00000000-0000-4000-8000-0000000000ff"
	f.mu.Unlock()
	expect(t, check(t, c, integration.User{Email: "ghost@example.com"}, "workspace.member", "workspace"), integration.CodeUpstreamError, "vanished")
}

func TestOAuthMode(t *testing.T) {
	srv, _, c := setupMode(t, authOAuth)
	expect(t, check(t, c, bob, "workspace.member", "workspace"), integration.CodeAllowed, "")
	if h := srv.LastCall().Header.Get("Authorization"); !strings.HasPrefix(h, "Bearer ") {
		t.Errorf("authorization %q", h)
	}
	// A token stored with its scheme, in any case, is not prefixed twice.
	for _, stored := range []string{"Bearer ", "bearer "} {
		srv := itest.NewServer(t)
		f := newFake(t)
		srv.Handle("POST", "/graphql", f.api)
		deps, _ := itest.Deps(t, srv)
		s := itest.Settings("ln", "linear", map[string]string{"url": srv.URL + "/graphql", "auth_mode": authOAuth}, map[string]secret.Secret{"credential": secret.Literal(stored + f.token)})
		c, err := (Integration{}).New(context.Background(), s, deps)
		if err != nil {
			t.Fatal(err)
		}
		expect(t, check(t, c, bob, "workspace.member", "workspace"), integration.CodeAllowed, "")
		if h := srv.LastCall().Header.Get("Authorization"); h != stored+f.token {
			t.Errorf("authorization %q", h)
		}
	}
}

func TestNullObjectIsNotVisible(t *testing.T) {
	srv, _, c := setup(t)
	srv.Reset()
	srv.Handle("POST", "/graphql", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Query string `json:"query"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		switch {
		case strings.Contains(body.Query, "users(filter"):
			write(w, 200, map[string]any{"data": map[string]any{"users": map[string]any{"nodes": []map[string]any{{"id": uBob, "email": "bob@example.com", "active": true}}}}})
		case strings.Contains(body.Query, "teamMemberships("):
			write(w, 200, map[string]any{"data": map[string]any{"user": map[string]any{"teamMemberships": map[string]any{"nodes": []any{}, "pageInfo": map[string]any{"hasNextPage": false}}}}})
		case strings.Contains(body.Query, "issue(id"):
			write(w, 200, map[string]any{"data": map[string]any{"issue": nil}})
		default:
			write(w, 200, map[string]any{"data": map[string]any{"project": nil}})
		}
	})
	expect(t, check(t, c, bob, "issue.view", "issue:ENG-1"), integration.CodeResourceNotVisible, "issue ENG-1")
	expect(t, check(t, c, bob, "project.view", "project:x"), integration.CodeResourceNotVisible, "project x")
}

func TestNewValidation(t *testing.T) {
	srv := itest.NewServer(t)
	deps, _ := itest.Deps(t, srv)
	for _, tc := range []struct {
		values map[string]string
		secret bool
	}{
		{map[string]string{}, false},
		{map[string]string{"url": "ftp://x"}, true},
		{map[string]string{"auth_mode": "magic"}, true},
	} {
		secrets := map[string]secret.Secret{}
		if tc.secret {
			secrets["credential"] = secret.Literal("x")
		}
		if _, err := (Integration{}).New(context.Background(), itest.Settings("ln", "linear", tc.values, secrets), deps); err == nil {
			t.Errorf("New(%v, secret=%v) accepted", tc.values, tc.secret)
		}
	}
	if _, err := (Integration{}).New(context.Background(), itest.Settings("ln", "linear", map[string]string{}, map[string]secret.Secret{"credential": secret.Literal("x")}), deps); err != nil {
		t.Errorf("default url rejected: %v", err)
	}
}

func TestProbe(t *testing.T) {
	_, f, c := setup(t)
	res, err := c.Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Summary, "bot@example.com in workspace acme") || len(res.Warnings) != 1 {
		t.Errorf("probe %+v", res)
	}
	itest.AssertNoCanary(t, res.Summary)
	f.mu.Lock()
	f.users[0].admin = false
	f.mu.Unlock()
	res, err = c.Probe(context.Background())
	if err != nil || len(res.Warnings) != 2 {
		t.Errorf("probe %+v %v", res, err)
	}
	f.mu.Lock()
	f.token = "other"
	f.mu.Unlock()
	var ie *integration.Error
	if _, err := c.Probe(context.Background()); !errors.As(err, &ie) || ie.Code != integration.CodeCredentialRejected {
		t.Errorf("bad token: %v", err)
	}
}

func TestNoSecretInLogs(t *testing.T) {
	srv := itest.NewServer(t)
	f := newFake(t)
	srv.Handle("POST", "/graphql", f.api)
	deps, logs := itest.Deps(t, srv)
	s := itest.Settings("ln", "linear", map[string]string{"url": srv.URL + "/graphql"}, map[string]secret.Secret{"credential": secret.Literal(f.token)})
	c, err := (Integration{}).New(context.Background(), s, deps)
	if err != nil {
		t.Fatal(err)
	}
	check(t, c, bob, "issue.view", "issue:ENG-1")
	check(t, c, bob, "issue.view", "issue:ENG-9")
	itest.AssertNoCanary(t, logs.String())
}
