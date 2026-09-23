package zendesk

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/roee-hersh/hallpass/internal/httpx"
	"github.com/roee-hersh/hallpass/internal/integration"
	"github.com/roee-hersh/hallpass/internal/integration/itest"
	"github.com/roee-hersh/hallpass/internal/secret"
)

// Users. Ids are Zendesk-style integers.
const (
	botID    = 1
	adminID  = 10
	danaID   = 11 // custom role "Tier 1": within-groups, edits, public comments, no delete
	bobID    = 12 // custom role "Reader": assigned-only, read only, private comments
	liteID   = 13 // light agent, no custom role
	saraID   = 14 // plain agent, ticket_restriction groups (non-Enterprise style)
	orgAgent = 15 // custom role "Org": within-organization, edit-within-org profiles
	endID    = 20 // end user
	end2ID   = 21 // end user in org 500
	goneID   = 22 // deleted
	suspID   = 23 // suspended

	roleTier1  = 100
	roleReader = 101
	roleOrg    = 102

	groupA  = 300
	groupB  = 301
	groupPu = 302 // public
	org500  = 500
)

var (
	admin  = integration.User{Email: "admin@example.com"}
	dana   = integration.User{Email: "dana@example.com"}
	bob    = integration.User{Email: "bob@example.com"}
	lite   = integration.User{Email: "lite@example.com"}
	sara   = integration.User{Email: "sara@example.com"}
	orgAg  = integration.User{Email: "orgagent@example.com"}
	endUsr = integration.User{Email: "end@example.com"}
	end2   = integration.User{Email: "end2@example.com"}
)

type fakeUser struct {
	id                  int64
	email, role         string
	roleType            *int
	customRole          *int64
	active, suspended   bool
	ticketRestriction   *string
	onlyPrivateComments *bool
	orgID               *int64
	groups              []int64
}

func ip(i int) *int       { return &i }
func i64(i int64) *int64  { return &i }
func sp(s string) *string { return &s }
func bp(b bool) *bool     { return &b }

type fakeTicket struct {
	status                            string
	group, assignee, requester, orgID *int64
	collaborators                     []int64
}

type fake struct {
	t  *testing.T
	mu sync.Mutex

	token    string
	users    []fakeUser
	roles    map[int64]map[string]any
	tickets  map[int64]fakeTicket
	orgs     map[int64]bool
	groups   map[int64]bool // id -> is_public
	status   int
	rolesGot int
	perPage  int
}

func newFake(t *testing.T) *fake {
	cfg := func(kv map[string]any) map[string]any {
		base := map[string]any{
			"ticket_access": "all", "ticket_editing": true, "ticket_deletion": false, "ticket_merge": false,
			"ticket_comment_access": "public", "modify_closed_tickets": false, "macro_access": "readonly",
			"view_access": "readonly", "organization_editing": false, "end_user_profile_access": "readonly",
			"manage_business_rules": false, "light_agent": false, "chat_access": false, "voice_access": false,
			"explore_access": "none", "report_access": "none", "forum_access": "readonly", "group_access": false,
		}
		for k, v := range kv {
			base[k] = v
		}
		return base
	}
	return &fake{t: t, token: itest.Canary + "tok", perPage: 100,
		users: []fakeUser{
			{id: botID, email: "bot@example.com", role: roleAdmin, active: true},
			{id: adminID, email: "admin@example.com", role: roleAdmin, active: true, groups: []int64{groupA}},
			{id: danaID, email: "dana@example.com", role: roleAgent, roleType: ip(0), customRole: i64(roleTier1), active: true, groups: []int64{groupA}, orgID: i64(org500)},
			{id: bobID, email: "bob@example.com", role: roleAgent, roleType: ip(0), customRole: i64(roleReader), active: true, groups: []int64{groupB}},
			{id: liteID, email: "lite@example.com", role: roleAgent, roleType: ip(1), active: true, onlyPrivateComments: bp(true), groups: []int64{groupA}},
			{id: saraID, email: "sara@example.com", role: roleAgent, active: true, ticketRestriction: sp("groups"), onlyPrivateComments: bp(false), groups: []int64{groupB}},
			{id: orgAgent, email: "orgagent@example.com", role: roleAgent, roleType: ip(0), customRole: i64(roleOrg), active: true, orgID: i64(org500)},
			{id: endID, email: "end@example.com", role: roleEndUser, active: true, ticketRestriction: sp("requested")},
			{id: end2ID, email: "end2@example.com", role: roleEndUser, active: true, ticketRestriction: sp("requested"), orgID: i64(org500)},
			{id: goneID, email: "gone@example.com", role: roleAgent, active: false},
			{id: suspID, email: "susp@example.com", role: roleAgent, active: true, suspended: true},
			// Matches an email: search loosely; must not count.
			{id: 99, email: "dana@example.com.au", role: roleAdmin, active: true},
		},
		roles: map[int64]map[string]any{
			roleTier1:  cfg(map[string]any{"ticket_access": "within-groups", "ticket_merge": true, "macro_access": "manage-personal", "view_access": "full", "end_user_profile_access": "full"}),
			roleReader: cfg(map[string]any{"ticket_access": "assigned-only", "ticket_editing": false, "ticket_comment_access": "none"}),
			roleOrg:    cfg(map[string]any{"ticket_access": "within-organization", "organization_editing": true, "end_user_profile_access": "edit-within-org", "manage_business_rules": true}),
		},
		tickets: map[int64]fakeTicket{
			1: {status: "open", group: i64(groupA), assignee: i64(adminID), requester: i64(endID)},
			2: {status: "open", group: i64(groupB), assignee: i64(bobID), requester: i64(end2ID), orgID: i64(org500)},
			3: {status: "closed", group: i64(groupA), requester: i64(endID)},
			4: {status: "open", group: i64(groupPu), requester: i64(end2ID), orgID: i64(org500), collaborators: []int64{endID}},
			5: {status: "open", requester: i64(liteID)},
			6: {status: "open", group: i64(groupB), requester: i64(endID)},
		},
		orgs:   map[int64]bool{org500: true},
		groups: map[int64]bool{groupA: false, groupB: false, groupPu: true},
	}
}

func zdErr(w http.ResponseWriter, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	switch status {
	case 404:
		_, _ = fmt.Fprintf(w, `{"error":"RecordNotFound","description":"%s"}`, itest.Canary)
	case 403:
		_, _ = fmt.Fprintf(w, `{"error":{"title":"Forbidden","message":"%s"}}`, itest.Canary)
	default:
		_, _ = fmt.Fprintf(w, `{"error":"Unavailable","description":"%s"}`, itest.Canary)
	}
}

func write(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (f *fake) userJSON(u fakeUser) map[string]any {
	m := map[string]any{"id": u.id, "email": u.email, "role": u.role, "active": u.active, "suspended": u.suspended,
		"name": itest.Canary + " name", "notes": itest.Canary, "url": fmt.Sprintf("https://example.zendesk.com/api/v2/users/%d.json", u.id)}
	if u.roleType != nil {
		m["role_type"] = *u.roleType
	} else {
		m["role_type"] = nil
	}
	if u.customRole != nil {
		m["custom_role_id"] = *u.customRole
	}
	if u.ticketRestriction != nil {
		m["ticket_restriction"] = *u.ticketRestriction
	} else {
		m["ticket_restriction"] = nil
	}
	if u.onlyPrivateComments != nil {
		m["only_private_comments"] = *u.onlyPrivateComments
	}
	if u.orgID != nil {
		m["organization_id"] = *u.orgID
	}
	return m
}

func (f *fake) authed(r *http.Request) bool {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ") == f.token
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(h, "Basic "))
	return err == nil && string(raw) == "bot@example.com/token:"+f.token
}

func (f *fake) api(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.authed(r) {
		w.WriteHeader(401)
		_, _ = fmt.Fprintf(w, `{"error":"Couldn't authenticate you"}`)
		return
	}
	if f.status != 0 {
		zdErr(w, f.status)
		return
	}
	p, q := r.URL.Path, r.URL.Query()
	seg := func(prefix string) (int64, bool) {
		rest := strings.TrimPrefix(p, prefix)
		id, err := strconv.ParseInt(strings.SplitN(rest, "/", 2)[0], 10, 64)
		return id, err == nil
	}
	switch {
	case p == "/api/v2/users/me":
		write(w, map[string]any{"user": f.userJSON(f.users[0])})
	case p == "/api/v2/users/search":
		query := q.Get("query")
		if !strings.HasPrefix(query, "email:") {
			f.t.Errorf("search without an email clause: %q", query)
		}
		needle := strings.TrimPrefix(query, "email:")
		var users []map[string]any
		for _, u := range f.users {
			if strings.Contains(u.email, needle) {
				users = append(users, f.userJSON(u))
			}
		}
		if needle == "dup@example.com" {
			users = append(users, f.userJSON(fakeUser{id: 501, email: "dup@example.com", role: roleAgent, active: true}), f.userJSON(fakeUser{id: 502, email: "DUP@example.com", role: roleAgent, active: true}))
		}
		if users == nil {
			users = []map[string]any{}
		}
		write(w, map[string]any{"users": users, "count": len(users), "next_page": nil, "previous_page": nil})
	case strings.HasPrefix(p, "/api/v2/users/") && strings.HasSuffix(p, "/group_memberships"):
		id, _ := seg("/api/v2/users/")
		var all []map[string]any
		for _, u := range f.users {
			if u.id != id {
				continue
			}
			for i, g := range u.groups {
				all = append(all, map[string]any{"id": id*10 + int64(i), "user_id": id, "group_id": g, "default": i == 0, "url": itest.Canary})
			}
		}
		page, _ := strconv.Atoi(q.Get("page"))
		if page < 1 {
			page = 1
		}
		start := (page - 1) * f.perPage
		if start > len(all) {
			start = len(all)
		}
		end := start + f.perPage
		if end > len(all) {
			end = len(all)
		}
		out := all[start:end]
		if out == nil {
			out = []map[string]any{}
		}
		var next any
		if end < len(all) {
			next = fmt.Sprintf("https://%s/api/v2/users/%d/group_memberships?page=%d", r.Host, id, page+1)
		}
		write(w, map[string]any{"group_memberships": out, "next_page": next, "previous_page": nil, "count": len(all)})
	case strings.HasPrefix(p, "/api/v2/users/"):
		id, ok := seg("/api/v2/users/")
		for _, u := range f.users {
			if ok && u.id == id {
				write(w, map[string]any{"user": f.userJSON(u)})
				return
			}
		}
		zdErr(w, 404)
	case p == "/api/v2/custom_roles":
		f.rolesGot++
		var roles []map[string]any
		for id, cfg := range f.roles {
			roles = append(roles, map[string]any{"id": id, "name": fmt.Sprintf("role-%d", id), "description": itest.Canary, "role_type": 0, "team_member_count": 1, "configuration": cfg})
		}
		write(w, map[string]any{"custom_roles": roles})
	case strings.HasPrefix(p, "/api/v2/tickets/"):
		id, ok := seg("/api/v2/tickets/")
		tk, found := f.tickets[id]
		if !ok || !found {
			zdErr(w, 404)
			return
		}
		if id == 7 {
			zdErr(w, 403)
			return
		}
		m := map[string]any{"id": id, "status": tk.status, "subject": itest.Canary, "description": itest.Canary,
			"group_id": tk.group, "assignee_id": tk.assignee, "requester_id": tk.requester, "organization_id": tk.orgID, "collaborator_ids": tk.collaborators}
		write(w, map[string]any{"ticket": m})
	case strings.HasPrefix(p, "/api/v2/organizations/"):
		id, ok := seg("/api/v2/organizations/")
		if !ok || !f.orgs[id] {
			zdErr(w, 404)
			return
		}
		write(w, map[string]any{"organization": map[string]any{"id": id, "name": itest.Canary, "notes": itest.Canary}})
	case strings.HasPrefix(p, "/api/v2/groups/"):
		id, ok := seg("/api/v2/groups/")
		public, found := f.groups[id]
		if !ok || !found {
			zdErr(w, 404)
			return
		}
		write(w, map[string]any{"group": map[string]any{"id": id, "name": itest.Canary, "is_public": public}})
	default:
		f.t.Errorf("fake: no route for %s %s", r.Method, p)
		zdErr(w, 404)
	}
}

func setupMode(t *testing.T, mode string) (*itest.Server, *fake, integration.Connection) {
	t.Helper()
	srv := itest.NewServer(t)
	srv.UseSpec(itest.SpecFromEnv(t, "zendesk"), itest.SpecOptions{})
	f := newFake(t)
	srv.Handle("GET", "/api/*", f.api)
	deps, _ := itest.Deps(t, srv)
	values := map[string]string{"url": srv.URL, "auth_mode": mode}
	if mode == authToken {
		values["username"] = "bot@example.com"
	}
	s := itest.Settings("zd", "zendesk", values, map[string]secret.Secret{"credential": secret.Literal(f.token)})
	c, err := (Integration{}).New(context.Background(), s, deps)
	if err != nil {
		t.Fatal(err)
	}
	return srv, f, c
}

func setup(t *testing.T) (*itest.Server, *fake, integration.Connection) {
	t.Helper()
	return setupMode(t, authToken)
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

func TestAction_ticket_view_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, admin, "ticket.view", "ticket:2"), integration.CodeAllowed, "administrator")
	// Within groups.
	expect(t, check(t, c, dana, "ticket.view", "ticket:1"), integration.CodeAllowed, "group 300")
	// Assigned only.
	expect(t, check(t, c, bob, "ticket.view", "ticket:2"), integration.CodeAllowed, "assigned to bob@example.com")
	// Within organization.
	expect(t, check(t, c, orgAg, "ticket.view", "ticket:2"), integration.CodeAllowed, "organization 500")
	// Non-Enterprise groups restriction.
	expect(t, check(t, c, sara, "ticket.view", "ticket:6"), integration.CodeAllowed, "group 301")
	// End user: requester and collaborator.
	expect(t, check(t, c, endUsr, "ticket.view", "ticket:1"), integration.CodeAllowed, "requested")
	expect(t, check(t, c, endUsr, "ticket.view", "ticket:4"), integration.CodeAllowed, "collaborator")
}
func TestAction_ticket_view_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, dana, "ticket.view", "ticket:2"), integration.CodeDenied, "tickets of their groups only")
	expect(t, check(t, c, bob, "ticket.view", "ticket:1"), integration.CodeDenied, "assigned tickets only")
	expect(t, check(t, c, orgAg, "ticket.view", "ticket:1"), integration.CodeDenied, "organization only")
	expect(t, check(t, c, sara, "ticket.view", "ticket:1"), integration.CodeDenied, "group 300")
	expect(t, check(t, c, endUsr, "ticket.view", "ticket:2"), integration.CodeDenied, "did not request")
	expect(t, check(t, c, end2, "ticket.view", "ticket:1"), integration.CodeDenied, "")
}
func TestPublicGroups(t *testing.T) {
	_, f, c := setup(t)
	// Ticket 4 is in a public group dana is not in.
	expect(t, check(t, c, dana, "ticket.view", "ticket:4"), integration.CodeDenied, "group 302")
	_, f, c = setup(t)
	f.mu.Lock()
	f.roles[roleTier1]["ticket_access"] = "within-groups-and-public-groups"
	f.mu.Unlock()
	expect(t, check(t, c, dana, "ticket.view", "ticket:4"), integration.CodeAllowed, "public group 302")
	expect(t, check(t, c, dana, "ticket.view", "ticket:2"), integration.CodeDenied, "group 301")
}
func TestUngroupedTicketIsUnknownForGroupAgents(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, dana, "ticket.view", "ticket:5"), integration.CodeUnsupported, "in no group")
	// A light agent without a ticket restriction sees all tickets.
	expect(t, check(t, c, lite, "ticket.view", "ticket:5"), integration.CodeAllowed, "all tickets")
}
func TestAction_ticket_edit_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, admin, "ticket.edit", "ticket:1"), integration.CodeAllowed, "administrator")
	expect(t, check(t, c, dana, "ticket.edit", "ticket:1"), integration.CodeAllowed, "may change the ticket's properties")
	expect(t, check(t, c, sara, "ticket.edit", "ticket:6"), integration.CodeAllowed, "")
}
func TestAction_ticket_edit_deny(t *testing.T) {
	_, _, c := setup(t)
	// Role forbids editing.
	expect(t, check(t, c, bob, "ticket.edit", "ticket:2"), integration.CodeDenied, "may not change ticket properties")
	// Closed tickets, even for administrators.
	expect(t, check(t, c, admin, "ticket.edit", "ticket:3"), integration.CodeDenied, "closed")
	expect(t, check(t, c, dana, "ticket.edit", "ticket:3"), integration.CodeDenied, "may not modify closed tickets")
	// Light agents unless requester; end users never.
	expect(t, check(t, c, lite, "ticket.edit", "ticket:1"), integration.CodeDenied, "light agent")
	expect(t, check(t, c, endUsr, "ticket.edit", "ticket:1"), integration.CodeDenied, "end user")
	// Not visible at all.
	expect(t, check(t, c, dana, "ticket.edit", "ticket:2"), integration.CodeDenied, "groups only")
}
func TestModifyClosedTickets(t *testing.T) {
	_, f, c := setup(t)
	f.mu.Lock()
	f.roles[roleTier1]["modify_closed_tickets"] = true
	f.mu.Unlock()
	expect(t, check(t, c, dana, "ticket.edit", "ticket:3"), integration.CodeAllowed, "closed tickets")
}
func TestAction_ticket_comment_public_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, dana, "ticket.comment_public", "ticket:1"), integration.CodeAllowed, "comment publicly")
	expect(t, check(t, c, sara, "ticket.comment_public", "ticket:6"), integration.CodeAllowed, "")
	expect(t, check(t, c, endUsr, "ticket.comment_public", "ticket:1"), integration.CodeAllowed, "requested")
}
func TestAction_ticket_comment_public_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, bob, "ticket.comment_public", "ticket:2"), integration.CodeDenied, "privately")
	expect(t, check(t, c, lite, "ticket.comment_public", "ticket:1"), integration.CodeDenied, "light agent")
	expect(t, check(t, c, endUsr, "ticket.comment_public", "ticket:2"), integration.CodeDenied, "")
}
func TestAction_ticket_merge_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, dana, "ticket.merge", "ticket:1"), integration.CodeAllowed, "merge")
	expect(t, check(t, c, admin, "ticket.merge", "ticket:2"), integration.CodeAllowed, "")
}
func TestAction_ticket_merge_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, bob, "ticket.merge", "ticket:2"), integration.CodeDenied, "may not merge")
	expect(t, check(t, c, lite, "ticket.merge", "ticket:1"), integration.CodeDenied, "")
	expect(t, check(t, c, endUsr, "ticket.merge", "ticket:1"), integration.CodeDenied, "")
}
func TestAction_ticket_delete_allow(t *testing.T) {
	_, f, c := setup(t)
	expect(t, check(t, c, admin, "ticket.delete", "ticket:1"), integration.CodeAllowed, "")
	f.mu.Lock()
	f.roles[roleTier1]["ticket_deletion"] = true
	f.mu.Unlock()
	expect(t, check(t, c, dana, "ticket.delete", "ticket:1"), integration.CodeAllowed, "delete")
}
func TestAction_ticket_delete_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, dana, "ticket.delete", "ticket:1"), integration.CodeDenied, "may not delete")
	// Non-Enterprise plans do not expose the setting.
	expect(t, check(t, c, sara, "ticket.delete", "ticket:6"), integration.CodeUnsupported, "does not expose")
}
func TestAction_organization_edit_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, admin, "organization.edit", "organization:500"), integration.CodeAllowed, "")
	expect(t, check(t, c, orgAg, "organization.edit", "organization:500"), integration.CodeAllowed, "organizations")
}
func TestAction_organization_edit_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, dana, "organization.edit", "organization:500"), integration.CodeDenied, "may not")
	expect(t, check(t, c, endUsr, "organization.edit", "organization:500"), integration.CodeDenied, "end user")
	expect(t, check(t, c, sara, "organization.edit", "organization:500"), integration.CodeUnsupported, "")
	expect(t, check(t, c, admin, "organization.edit", "organization:9"), integration.CodeResourceNotVisible, "organization 9")
}
func TestAction_user_edit_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, admin, "user.edit", "user:11"), integration.CodeAllowed, "any profile")
	// full end-user profile access.
	expect(t, check(t, c, dana, "user.edit", "user:20"), integration.CodeAllowed, "end-user profiles")
	// edit-within-org: end2 shares org 500.
	expect(t, check(t, c, orgAg, "user.edit", "user:21"), integration.CodeAllowed, "own organization")
	// Own profile.
	expect(t, check(t, c, bob, "user.edit", "user:12"), integration.CodeAllowed, "own profile")
	expect(t, check(t, c, endUsr, "user.edit", "user:20"), integration.CodeAllowed, "own profile")
}
func TestAction_user_edit_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, bob, "user.edit", "user:20"), integration.CodeDenied, "only view")
	expect(t, check(t, c, orgAg, "user.edit", "user:20"), integration.CodeDenied, "not one")
	// Team members are edited by administrators only.
	expect(t, check(t, c, dana, "user.edit", "user:12"), integration.CodeDenied, "administrators edit other team members")
	expect(t, check(t, c, endUsr, "user.edit", "user:21"), integration.CodeDenied, "own profile only")
	// Non-Enterprise: sara sees group tickets only, so read-only profiles.
	expect(t, check(t, c, sara, "user.edit", "user:20"), integration.CodeDenied, "only view")
	expect(t, check(t, c, admin, "user.edit", "user:404"), integration.CodeResourceNotVisible, "")
}
func TestAction_macro_manage_allow(t *testing.T) {
	_, f, c := setup(t)
	expect(t, check(t, c, admin, "macro.manage", "account"), integration.CodeAllowed, "administrator")
	f.mu.Lock()
	f.roles[roleTier1]["macro_access"] = "full"
	f.mu.Unlock()
	expect(t, check(t, c, dana, "macro.manage", "account"), integration.CodeAllowed, "shared macros")
}
func TestAction_macro_manage_deny(t *testing.T) {
	_, _, c := setup(t)
	// manage-personal is not shared macros.
	expect(t, check(t, c, dana, "macro.manage", "account"), integration.CodeDenied, "may not")
	expect(t, check(t, c, endUsr, "macro.manage", "account"), integration.CodeDenied, "end user")
	expect(t, check(t, c, sara, "macro.manage", "account"), integration.CodeUnsupported, "does not expose")
}
func TestAction_view_manage_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, dana, "view.manage", "account"), integration.CodeAllowed, "shared views")
}
func TestAction_view_manage_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, bob, "view.manage", "account"), integration.CodeDenied, "")
}
func TestAction_business_rules_manage_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, orgAg, "business_rules.manage", "account"), integration.CodeAllowed, "business rules")
	expect(t, check(t, c, admin, "business_rules.manage", "account"), integration.CodeAllowed, "")
}
func TestAction_business_rules_manage_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, dana, "business_rules.manage", "account"), integration.CodeDenied, "")
}
func TestAction_account_admin_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, admin, "account.admin", "account"), integration.CodeAllowed, "is an administrator")
}
func TestAction_account_admin_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, dana, "account.admin", "account"), integration.CodeDenied, "not an administrator")
	expect(t, check(t, c, endUsr, "account.admin", "account"), integration.CodeDenied, "")
}

// --- identity ---------------------------------------------------------------

func TestIdentity(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, integration.User{Email: "nobody@example.com"}, "account.admin", "account"), integration.CodeUserNotFound, "no Zendesk user")
	expect(t, check(t, c, integration.User{Email: "dup@example.com"}, "account.admin", "account"), integration.CodeUserAmbiguous, "2 Zendesk users")
	expect(t, check(t, c, integration.User{Email: "not an email"}, "account.admin", "account"), integration.CodeInvalidRequest, "")
	// Deleted and suspended users are denied everything.
	expect(t, check(t, c, integration.User{Email: "gone@example.com"}, "ticket.view", "ticket:1"), integration.CodeDenied, "deleted")
	expect(t, check(t, c, integration.User{Email: "susp@example.com"}, "ticket.view", "ticket:1"), integration.CodeDenied, "suspended")
	// The loose match by suffix does not resolve to the admin.
	expect(t, check(t, c, dana, "account.admin", "account"), integration.CodeDenied, "")
}

func TestIdentityAttrs(t *testing.T) {
	_, _, c := setup(t)
	id, err := c.ResolveIdentity(context.Background(), dana)
	if err != nil {
		t.Fatal(err)
	}
	if id.ID != "11" || id.Attr("role") != "agent" || id.Attr("custom_role_id") != "100" || id.Attr("organization_id") != "500" {
		t.Errorf("identity %+v", id)
	}
	if len(id.Groups) != 1 || id.Groups[0] != "300" {
		t.Errorf("groups %v", id.Groups)
	}
	for k, v := range id.Attrs {
		itest.AssertNoCanary(t, k+"="+v)
	}
}

func TestGroupPaging(t *testing.T) {
	srv, f, c := setup(t)
	f.mu.Lock()
	f.perPage = 1
	for i := range f.users {
		if f.users[i].id == danaID {
			f.users[i].groups = []int64{groupA, groupB, groupPu}
		}
	}
	f.mu.Unlock()
	id, err := c.ResolveIdentity(context.Background(), dana)
	if err != nil {
		t.Fatal(err)
	}
	if len(id.Groups) != 3 {
		t.Errorf("groups %v, want 3", id.Groups)
	}
	pages := 0
	for _, call := range srv.Calls() {
		if strings.HasSuffix(call.Path, "/group_memberships") {
			pages++
		}
	}
	if pages != 3 {
		t.Errorf("%d membership pages, want 3", pages)
	}
}

func TestNextPageOffHostIsRefused(t *testing.T) {
	srv, _, _ := setup(t)
	srv.Reset()
	srv.Handle("GET", "/api/v2/users/*", func(w http.ResponseWriter, r *http.Request) {
		write(w, map[string]any{"group_memberships": []any{}, "next_page": "https://evil.example.com/api/v2/users/11/group_memberships?page=2"})
	})
	deps, _ := itest.Deps(t, srv)
	hc, err := deps.HTTPClient(itest.Settings("zd", "zendesk", nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	c := &Connection{api: &httpx.Client{HTTP: hc, Base: srv.URL}}
	_, err = c.groupMemberships(context.Background(), 11)
	if err == nil || !strings.Contains(err.Error(), "outside its API") {
		t.Fatalf("err %v", err)
	}
}

func TestUnknownRoleShapes(t *testing.T) {
	_, f, c := setup(t)
	f.mu.Lock()
	f.users = append(f.users,
		fakeUser{id: 60, email: "contrib@example.com", role: roleAgent, roleType: ip(3), active: true},
		fakeUser{id: 61, email: "norole@example.com", role: roleAgent, roleType: ip(0), customRole: i64(999), active: true},
		fakeUser{id: 62, email: "weird@example.com", role: "owner", active: true},
	)
	f.mu.Unlock()
	expect(t, check(t, c, integration.User{Email: "contrib@example.com"}, "ticket.view", "ticket:1"), integration.CodeUnsupported, "role type 3")
	expect(t, check(t, c, integration.User{Email: "norole@example.com"}, "ticket.view", "ticket:1"), integration.CodeResourceNotVisible, "custom role 999")
	expect(t, check(t, c, integration.User{Email: "weird@example.com"}, "ticket.view", "ticket:1"), integration.CodeUnsupported, "does not know")
}

func TestRolesAreCached(t *testing.T) {
	_, f, c := setup(t)
	check(t, c, dana, "ticket.view", "ticket:1")
	check(t, c, bob, "ticket.view", "ticket:2")
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.rolesGot != 1 {
		t.Errorf("custom_roles fetched %d times, want 1", f.rolesGot)
	}
}

func TestTicketNotVisible(t *testing.T) {
	_, f, c := setup(t)
	expect(t, check(t, c, admin, "ticket.view", "ticket:404"), integration.CodeResourceNotVisible, "ticket 404")
	f.mu.Lock()
	f.tickets[7] = fakeTicket{status: "open"}
	f.mu.Unlock()
	expect(t, check(t, c, admin, "ticket.view", "ticket:7"), integration.CodeResourceNotVisible, "HTTP 403")
}

func TestInvalidRequests(t *testing.T) {
	_, _, c := setup(t)
	for _, tc := range [][2]string{
		{"ticket.view", "ticket:abc"}, {"ticket.view", "ticket:"}, {"ticket.view", "organization:1"},
		{"ticket.view", "ticket:1?x=1"}, {"account.admin", "account:1"},
		{"ticket.view", "ticket:1/2"}, {"ticket.view", "ticket:-1"},
	} {
		d := check(t, c, admin, tc[0], tc[1])
		if d.Code != integration.CodeInvalidRequest {
			t.Errorf("%s %s: %s %s", tc[0], tc[1], d.Code, d.Text)
		}
	}
}

func TestFailures(t *testing.T) {
	srv, _, c := setup(t)
	itest.FailureCases(t, srv, func() integration.Decision { return check(t, c, dana, "ticket.view", "ticket:1") })
}

func TestForbiddenIsCredentialProblem(t *testing.T) {
	_, f, c := setup(t)
	f.mu.Lock()
	f.status = 403
	f.mu.Unlock()
	expect(t, check(t, c, dana, "ticket.view", "ticket:1"), integration.CodeCredentialRejected, "use an administrator")
}

func TestOAuthMode(t *testing.T) {
	_, _, c := setupMode(t, authOAuth)
	expect(t, check(t, c, admin, "account.admin", "account"), integration.CodeAllowed, "")
}

func TestNewValidation(t *testing.T) {
	srv := itest.NewServer(t)
	deps, _ := itest.Deps(t, srv)
	for _, tc := range []struct {
		values map[string]string
		secret bool
	}{
		{map[string]string{"url": srv.URL}, false},
		{map[string]string{"url": srv.URL}, true},                       // token mode without username
		{map[string]string{"url": srv.URL, "username": "bot"}, true},    // not an email
		{map[string]string{"url": srv.URL, "auth_mode": "magic"}, true}, // unknown mode
		{map[string]string{"username": "bot@example.com"}, true},        // no url
	} {
		secrets := map[string]secret.Secret{}
		if tc.secret {
			secrets["credential"] = secret.Literal("x")
		}
		if _, err := (Integration{}).New(context.Background(), itest.Settings("zd", "zendesk", tc.values, secrets), deps); err == nil {
			t.Errorf("New(%v, secret=%v) accepted", tc.values, tc.secret)
		}
	}
}

func TestProbe(t *testing.T) {
	_, f, c := setup(t)
	res, err := c.Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Summary, "bot@example.com (admin)") {
		t.Errorf("summary %q", res.Summary)
	}
	itest.AssertNoCanary(t, res.Summary)
	f.mu.Lock()
	f.users[0].role = roleAgent
	f.mu.Unlock()
	res, err = c.Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Warnings) < 2 || !strings.Contains(res.Warnings[0], "not an administrator") {
		t.Errorf("warnings %v", res.Warnings)
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
	srv.Handle("GET", "/api/*", f.api)
	deps, logs := itest.Deps(t, srv)
	s := itest.Settings("zd", "zendesk", map[string]string{"url": srv.URL, "username": "bot@example.com"}, map[string]secret.Secret{"credential": secret.Literal(f.token)})
	c, err := (Integration{}).New(context.Background(), s, deps)
	if err != nil {
		t.Fatal(err)
	}
	check(t, c, dana, "ticket.view", "ticket:1")
	check(t, c, admin, "ticket.view", "ticket:404")
	itest.AssertNoCanary(t, logs.String())
}
