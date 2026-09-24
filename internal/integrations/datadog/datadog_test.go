package datadog

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/roee-hersh/hallpass/internal/catalog"
	"github.com/roee-hersh/hallpass/internal/evidence"
	"github.com/roee-hersh/hallpass/internal/integration"
	"github.com/roee-hersh/hallpass/internal/integration/itest"
	"github.com/roee-hersh/hallpass/internal/secret"
)

const (
	roleRO    = "11111111-1111-1111-1111-111111111111"
	roleStd   = "22222222-2222-2222-2222-222222222222"
	roleAdmin = "33333333-3333-3333-3333-333333333333"
	roleTeamX = "44444444-4444-4444-4444-444444444444"
	teamT1    = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	orgID     = "99999999-9999-9999-9999-999999999999"
	danaID    = "d1d1d1d1-0000-0000-0000-000000000001"
	bobID     = "b0b0b0b0-0000-0000-0000-000000000002"
	rootID    = "r00tr00t-0000-0000-0000-000000000003"
)

var (
	dana = integration.User{Email: "dana@example.com"} // Standard role
	bob  = integration.User{Email: "bob@example.com"}  // Read Only role
	root = integration.User{Email: "root@example.com"} // Admin role, member of team T1
	off  = integration.User{Email: "off@example.com"}  // disabled
)

type ddFakeUser struct {
	id, email, handle, status string
	disabled                  *bool
	roles                     []string
}

func ptr(b bool) *bool { return &b }

type fake struct {
	t  *testing.T
	mu sync.Mutex

	apiKey, appKey  string
	users           []ddFakeUser
	rolePerms       map[string][]string
	monitors        map[string]map[string]any
	dashboards      map[string]map[string]any
	slos, notebooks map[string]bool
	policies        map[string][]map[string]any // "type:id" -> bindings
	teams           map[string][]string         // team -> user ids
	permsCalls      int
	status          int
	pageSize        int
}

func newFake(t *testing.T) *fake {
	return &fake{t: t, apiKey: itest.Canary + "api", appKey: itest.Canary + "app", pageSize: 100,
		users: []ddFakeUser{
			{danaID, "dana@example.com", "dana@example.com", "Active", ptr(false), []string{roleStd}},
			{bobID, "bob@example.com", "bob@example.com", "Active", ptr(false), []string{roleRO}},
			{rootID, "root@example.com", "root@example.com", "Active", ptr(false), []string{roleAdmin, roleRO}},
			{"0ff00000-0000-0000-0000-000000000004", "off@example.com", "off@example.com", "Disabled", ptr(true), []string{roleStd}},
			{"aaaaaaaa-0000-0000-0000-000000000005", "nostatus@example.com", "nostatus", "Active", nil, []string{roleStd}},
			// Matches "dana@example.com" as a substring; must not count.
			{"eeeeeeee-0000-0000-0000-000000000006", "dana@example.com.au", "dana2", "Active", ptr(false), []string{roleAdmin}},
		},
		rolePerms: map[string][]string{
			roleRO:    {"monitors_read", "dashboards_read", "slos_read", "notebooks_read", "logs_read_data"},
			roleStd:   {"monitors_read", "dashboards_read", "slos_read", "notebooks_read", "logs_read_data", "monitors_write", "monitors_downtime", "dashboards_write", "slos_write", "notebooks_write", "api_keys_read"},
			roleAdmin: {"monitors_read", "monitors_write", "monitors_downtime", "dashboards_read", "dashboards_write", "slos_read", "slos_write", "notebooks_read", "notebooks_write", "logs_read_data", "user_access_manage", "api_keys_write"},
			roleTeamX: {"monitors_read", "monitors_write"},
		},
		monitors: map[string]map[string]any{
			"1": {"id": 1, "name": itest.Canary, "restricted_roles": nil, "creator": map[string]any{"email": "someone@example.com", "handle": "someone@example.com"}},
			"2": {"id": 2, "name": itest.Canary, "restricted_roles": []string{roleTeamX}},
			"3": {"id": 3, "name": itest.Canary, "restricted_roles": nil},
			"4": {"id": 4, "name": itest.Canary, "restricted_roles": nil},
		},
		dashboards: map[string]map[string]any{
			"abc-def-ghi": {"id": "abc-def-ghi", "title": itest.Canary, "restricted_roles": []string{roleTeamX}, "author_handle": "dana@example.com"},
			"pub-lic":     {"id": "pub-lic", "title": itest.Canary},
		},
		slos:      map[string]bool{"slo1": true},
		notebooks: map[string]bool{"100": true},
		policies: map[string][]map[string]any{
			"monitor:3":    {{"relation": "editor", "principals": []string{"team:" + teamT1}}, {"relation": "viewer", "principals": []string{"org:" + orgID}}},
			"monitor:4":    {{"relation": "editor", "principals": []string{"user:" + danaID}}},
			"slo:slo1":     {{"relation": "editor", "principals": []string{"role:" + roleAdmin}}},
			"notebook:100": {{"relation": "viewer", "principals": []string{"user:" + bobID}}},
		},
		teams: map[string][]string{teamT1: {rootID}},
	}
}

func ddErr(w http.ResponseWriter, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(fmt.Sprintf(`{"errors":["%s error"]}`, itest.Canary)))
}

func write(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (f *fake) userJSON(u ddFakeUser) map[string]any {
	attrs := map[string]any{"email": u.email, "handle": u.handle, "status": u.status, "name": itest.Canary + " name"}
	if u.disabled != nil {
		attrs["disabled"] = *u.disabled
	}
	var roles []map[string]any
	for _, r := range u.roles {
		roles = append(roles, map[string]any{"id": r, "type": "roles"})
	}
	return map[string]any{"id": u.id, "type": "users", "attributes": attrs, "relationships": map[string]any{"roles": map[string]any{"data": roles}}}
}

func (f *fake) api(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("DD-API-KEY") != f.apiKey || r.Header.Get("DD-APPLICATION-KEY") != f.appKey {
		ddErr(w, 403)
		return
	}
	if f.status != 0 {
		ddErr(w, f.status)
		return
	}
	p, q := r.URL.Path, r.URL.Query()
	size, _ := strconv.Atoi(q.Get("page[size]"))
	num, _ := strconv.Atoi(q.Get("page[number]"))
	if size <= 0 || size > f.pageSize {
		size = f.pageSize
	}
	page := func(values []map[string]any) []map[string]any {
		start := num * size
		if start > len(values) {
			start = len(values)
		}
		end := start + size
		if end > len(values) {
			end = len(values)
		}
		out := values[start:end]
		if out == nil {
			out = []map[string]any{}
		}
		return out
	}
	switch {
	case p == "/api/v1/validate":
		write(w, map[string]any{"valid": true})
	case p == "/api/v2/users":
		var values []map[string]any
		for _, u := range f.users {
			if q.Get("filter") != "" && !strings.Contains(u.email, q.Get("filter")) {
				continue
			}
			if q.Get("filter[status]") != "" && !strings.Contains(q.Get("filter[status]"), u.status) {
				continue
			}
			values = append(values, f.userJSON(u))
		}
		if q.Get("filter") == "dup@example.com" {
			values = append(values, f.userJSON(ddFakeUser{"dup1", "dup@example.com", "d1", "Active", ptr(false), nil}), f.userJSON(ddFakeUser{"dup2", "DUP@example.com", "d2", "Active", ptr(false), nil}))
		}
		write(w, map[string]any{"data": page(values), "meta": map[string]any{"page": map[string]any{"total_count": len(f.users), "total_filtered_count": len(values)}}})
	case strings.HasPrefix(p, "/api/v2/roles/") && strings.HasSuffix(p, "/permissions"):
		role := strings.TrimSuffix(strings.TrimPrefix(p, "/api/v2/roles/"), "/permissions")
		perms, ok := f.rolePerms[role]
		if !ok {
			ddErr(w, 404)
			return
		}
		f.permsCalls++
		var data []map[string]any
		for i, name := range perms {
			data = append(data, map[string]any{"id": fmt.Sprintf("p%d", i), "type": "permissions", "attributes": map[string]any{"name": name, "description": itest.Canary}})
		}
		write(w, map[string]any{"data": data})
	case strings.HasPrefix(p, "/api/v2/restriction_policy/"):
		id := strings.TrimPrefix(p, "/api/v2/restriction_policy/")
		bindings, ok := f.policies[id]
		if !ok {
			bindings = []map[string]any{}
		}
		write(w, map[string]any{"data": map[string]any{"type": "restriction_policy", "id": id, "attributes": map[string]any{"bindings": bindings}}})
	case strings.HasPrefix(p, "/api/v2/team/") && strings.HasSuffix(p, "/memberships"):
		team := strings.TrimSuffix(strings.TrimPrefix(p, "/api/v2/team/"), "/memberships")
		members, ok := f.teams[team]
		if !ok {
			ddErr(w, 404)
			return
		}
		if q.Get("filter[keyword]") == "" {
			f.t.Error("membership listing without filter[keyword]")
		}
		var values []map[string]any
		for i, uid := range members {
			// The keyword narrows by email or name: a member whose email
			// does not contain it is not listed.
			var match bool
			for _, u := range f.users {
				if u.id == uid && strings.Contains(u.email, q.Get("filter[keyword]")) {
					match = true
				}
			}
			if !match {
				continue
			}
			values = append(values, map[string]any{"id": fmt.Sprintf("TeamMembership-%s-%d", team, i), "type": "team_memberships", "attributes": map[string]any{"role": nil}, "relationships": map[string]any{"user": map[string]any{"data": map[string]any{"id": uid, "type": "users"}}}})
		}
		write(w, map[string]any{"data": page(values)})
	case strings.HasPrefix(p, "/api/v1/monitor/"):
		m, ok := f.monitors[strings.TrimPrefix(p, "/api/v1/monitor/")]
		if !ok {
			ddErr(w, 404)
			return
		}
		write(w, m)
	case strings.HasPrefix(p, "/api/v1/dashboard/"):
		d, ok := f.dashboards[strings.TrimPrefix(p, "/api/v1/dashboard/")]
		if !ok {
			ddErr(w, 404)
			return
		}
		write(w, d)
	case strings.HasPrefix(p, "/api/v1/slo/"):
		id := strings.TrimPrefix(p, "/api/v1/slo/")
		if !f.slos[id] {
			ddErr(w, 404)
			return
		}
		write(w, map[string]any{"data": map[string]any{"id": id, "name": itest.Canary, "creator": map[string]any{"email": "someone@example.com"}}})
	case strings.HasPrefix(p, "/api/v1/notebooks/"):
		id := strings.TrimPrefix(p, "/api/v1/notebooks/")
		if !f.notebooks[id] {
			ddErr(w, 404)
			return
		}
		n, _ := strconv.Atoi(id)
		write(w, map[string]any{"data": map[string]any{"id": n, "type": "notebooks", "attributes": map[string]any{"name": itest.Canary, "author": map[string]any{"email": "someone@example.com"}}}})
	default:
		f.t.Errorf("fake: no route for %s %s", r.Method, p)
		ddErr(w, 404)
	}
}

func setup(t *testing.T) (*itest.Server, *fake, integration.Connection) {
	t.Helper()
	srv := itest.NewServer(t)
	srv.UseSpec(itest.AnySpec(itest.SpecFromEnv(t, "datadog-v1"), itest.SpecFromEnv(t, "datadog-v2")), itest.SpecOptions{})
	f := newFake(t)
	srv.Handle("GET", "/api/*", f.api)
	deps, _ := itest.Deps(t, srv)
	s := itest.Settings("dd", "datadog", map[string]string{"url": srv.URL}, map[string]secret.Secret{"api_key": secret.Literal(f.apiKey), "credential": secret.Literal(f.appKey)})
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

// --- the action table -------------------------------------------------------

func TestAction_monitor_edit_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, dana, "monitor.edit", "monitor:1"), integration.CodeAllowed, "carries no restriction")
	// A policy naming the user directly.
	expect(t, check(t, c, dana, "monitor.edit", "monitor:4"), integration.CodeAllowed, "grants editor to dana@example.com")
	// A policy naming a team the user is on.
	expect(t, check(t, c, root, "monitor.edit", "monitor:3"), integration.CodeAllowed, "team "+teamT1)
}
func TestAction_monitor_edit_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, bob, "monitor.edit", "monitor:1"), integration.CodeDenied, "no role of bob@example.com carries monitors_write")
	// Legacy restricted_roles the user lacks.
	expect(t, check(t, c, dana, "monitor.edit", "monitor:2"), integration.CodeDenied, "restricted to 1 role(s)")
	// A policy that grants editor to a team the user is not on; the admin
	// role does not help.
	expect(t, check(t, c, dana, "monitor.edit", "monitor:3"), integration.CodeDenied, "grants editor to none")
}
func TestAction_monitor_mute_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, dana, "monitor.mute", "monitor:1"), integration.CodeAllowed, "monitors_downtime")
}
func TestAction_monitor_mute_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, bob, "monitor.mute", "monitor:1"), integration.CodeDenied, "")
	expect(t, check(t, c, dana, "monitor.mute", "monitor:2"), integration.CodeDenied, "restricted")
}
func TestAction_monitor_read_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, bob, "monitor.read", "monitor:1"), integration.CodeAllowed, "")
	// The org is a viewer of monitor 3.
	expect(t, check(t, c, bob, "monitor.read", "monitor:3"), integration.CodeAllowed, "whole org")
	// restricted_roles restrict editing only.
	expect(t, check(t, c, bob, "monitor.read", "monitor:2"), integration.CodeAllowed, "")
}
func TestEditorOnlyPolicyLeavesViewingOpen(t *testing.T) {
	_, _, c := setup(t)
	// monitor 4's policy names an editor only.
	expect(t, check(t, c, bob, "monitor.read", "monitor:4"), integration.CodeAllowed, "restricts editing only")
	expect(t, check(t, c, bob, "monitor.edit", "monitor:4"), integration.CodeDenied, "")
	// A viewer binding restricts viewing.
	expect(t, check(t, c, dana, "raw:notebooks_read", "notebook:100"), integration.CodeDenied, "grants viewer to none")
	expect(t, check(t, c, bob, "raw:notebooks_read", "notebook:100"), integration.CodeAllowed, "grants viewer to bob@example.com")
}

func TestPendingUser(t *testing.T) {
	_, f, c := setup(t)
	f.mu.Lock()
	f.users = append(f.users, ddFakeUser{"aaaaaaaa-0000-0000-0000-000000000008", "pending@example.com", "pending", "Pending", ptr(false), []string{roleAdmin}})
	f.mu.Unlock()
	expect(t, check(t, c, integration.User{Email: "pending@example.com"}, "users.manage", "org"), integration.CodeDenied, "has not accepted")
}

func TestIdentityLookupIsOneCall(t *testing.T) {
	srv, _, c := setup(t)
	expect(t, check(t, c, dana, "logs.read", "org"), integration.CodeAllowed, "")
	n := 0
	for _, call := range srv.Calls() {
		if call.Path == "/api/v2/users" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("user lookup took %d calls, want 1", n)
	}
}

func TestAction_monitor_read_deny(t *testing.T) {
	_, f, c := setup(t)
	f.mu.Lock()
	f.rolePerms[roleRO] = []string{"dashboards_read"}
	f.mu.Unlock()
	expect(t, check(t, c, bob, "monitor.read", "monitor:1"), integration.CodeDenied, "monitors_read")
}
func TestAction_dashboard_edit_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, dana, "dashboard.edit", "dashboard:pub-lic"), integration.CodeAllowed, "")
	// The author edits a dashboard restricted to roles they lack.
	expect(t, check(t, c, dana, "dashboard.edit", "dashboard:abc-def-ghi"), integration.CodeAllowed, "author")
}
func TestAction_dashboard_edit_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, root, "dashboard.edit", "dashboard:abc-def-ghi"), integration.CodeDenied, "restricted to 1 role(s)")
	expect(t, check(t, c, bob, "dashboard.edit", "dashboard:pub-lic"), integration.CodeDenied, "dashboards_write")
}
func TestAction_dashboard_read_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, bob, "dashboard.read", "dashboard:abc-def-ghi"), integration.CodeAllowed, "")
}
func TestAction_dashboard_read_deny(t *testing.T) {
	_, f, c := setup(t)
	f.mu.Lock()
	f.rolePerms[roleRO] = []string{"monitors_read"}
	f.mu.Unlock()
	expect(t, check(t, c, bob, "dashboard.read", "dashboard:pub-lic"), integration.CodeDenied, "")
}
func TestAction_slo_edit_allow(t *testing.T) {
	_, _, c := setup(t)
	// The policy grants editor to the admin role.
	expect(t, check(t, c, root, "slo.edit", "slo:slo1"), integration.CodeAllowed, "grants editor to a role")
}
func TestAction_slo_edit_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, dana, "slo.edit", "slo:slo1"), integration.CodeDenied, "grants editor to none")
}
func TestAction_notebook_edit_allow(t *testing.T) {
	_, f, c := setup(t)
	f.mu.Lock()
	delete(f.policies, "notebook:100")
	f.mu.Unlock()
	expect(t, check(t, c, dana, "notebook.edit", "notebook:100"), integration.CodeAllowed, "")
}
func TestAction_notebook_edit_deny(t *testing.T) {
	_, _, c := setup(t)
	// A viewer-only policy grants no editing, even to the named user.
	expect(t, check(t, c, bob, "notebook.edit", "notebook:100"), integration.CodeDenied, "")
	expect(t, check(t, c, dana, "notebook.edit", "notebook:100"), integration.CodeDenied, "grants editor to none")
}
func TestAction_logs_read_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, bob, "logs.read", "org"), integration.CodeAllowed, "carries logs_read_data")
}
func TestAction_logs_read_deny(t *testing.T) {
	_, f, c := setup(t)
	f.mu.Lock()
	f.rolePerms[roleRO] = []string{"monitors_read"}
	f.mu.Unlock()
	expect(t, check(t, c, bob, "logs.read", "org"), integration.CodeDenied, "no role of bob@example.com carries logs_read_data")
}
func TestAction_users_manage_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, root, "users.manage", "org"), integration.CodeAllowed, "")
}
func TestAction_users_manage_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, dana, "users.manage", "org"), integration.CodeDenied, "")
}
func TestAction_apikeys_manage_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, root, "apikeys.manage", "org"), integration.CodeAllowed, "")
}
func TestAction_apikeys_manage_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, dana, "apikeys.manage", "org"), integration.CodeDenied, "api_keys_write")
}

// --- semantics ------------------------------------------------------------------

func TestRawActions(t *testing.T) {
	srv, _, c := setup(t)
	expect(t, check(t, c, dana, "raw:api_keys_read", "org"), integration.CodeAllowed, "")
	expect(t, check(t, c, bob, "raw:api_keys_read", "org"), integration.CodeDenied, "")
	// The asset's write permission is checked against its restrictions.
	expect(t, check(t, c, dana, "raw:monitors_write", "monitor:2"), integration.CodeDenied, "restricted")
	// monitors_downtime changes a monitor: the same answer as monitor.mute.
	expect(t, check(t, c, dana, "raw:monitors_downtime", "monitor:3"), integration.CodeDenied, "grants editor to none")
	// A read permission on an asset is a read as far as restrictions go.
	expect(t, check(t, c, dana, "raw:monitors_read", "monitor:3"), integration.CodeAllowed, "whole org")
	n := len(srv.Calls())
	for _, bad := range []string{"raw:", "raw:Monitors_Write", "raw:a", "raw:monitors write", "monitors_write"} {
		if _, ok := (Integration{}).MatchAction(bad); ok {
			t.Errorf("%q matched", bad)
		}
	}
	if len(srv.Calls()) != n {
		t.Error("a rejected action reached the upstream")
	}
}

func TestPermissionsCached(t *testing.T) {
	_, f, c := setup(t)
	expect(t, check(t, c, dana, "logs.read", "org"), integration.CodeAllowed, "")
	expect(t, check(t, c, dana, "monitor.edit", "monitor:1"), integration.CodeAllowed, "")
	expect(t, check(t, c, dana, "users.manage", "org"), integration.CodeDenied, "")
	f.mu.Lock()
	if f.permsCalls != 1 {
		t.Errorf("role permissions read %d times, want 1", f.permsCalls)
	}
	f.mu.Unlock()
	// A fresh check reads the role's permissions again inside the window.
	id, err := c.ResolveIdentity(context.Background(), dana)
	if err != nil {
		t.Fatal(err)
	}
	d, err := c.Check(evidence.WithFresh(context.Background()), integration.CheckRequest{User: dana, Identity: id, Action: catalog.Action{Name: "logs.read"}, ActionName: "logs.read", Resource: catalog.Resource{Type: "org"}})
	if err != nil || d.Code != integration.CodeAllowed {
		t.Fatalf("fresh: %+v %v", d, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.permsCalls != 2 {
		t.Errorf("role permissions read %d times after a fresh check, want 2", f.permsCalls)
	}
}

func TestTeamMembershipPaged(t *testing.T) {
	srv, f, c := setup(t)
	f.mu.Lock()
	f.pageSize = 1
	// A second member whose email also contains "root@example.com".
	f.users = append(f.users, ddFakeUser{"f00tf00t-0000-0000-0000-000000000007", "notroot@example.com", "nr", "Active", ptr(false), nil})
	f.teams[teamT1] = []string{"f00tf00t-0000-0000-0000-000000000007", rootID}
	f.mu.Unlock()
	expect(t, check(t, c, root, "monitor.edit", "monitor:3"), integration.CodeAllowed, "team")
	pages := 0
	for _, call := range srv.Calls() {
		if strings.HasSuffix(call.Path, "/memberships") {
			pages++
			if call.Query.Get("filter[keyword]") != "root@example.com" {
				t.Errorf("membership keyword %q", call.Query.Get("filter[keyword]"))
			}
		}
	}
	// Two one-member pages; root is on the second.
	if pages != 2 {
		t.Errorf("read %d membership pages, want 2", pages)
	}
	// A team the policy names but hallpass cannot see is unknown, not deny.
	f.mu.Lock()
	delete(f.teams, teamT1)
	f.mu.Unlock()
	expect(t, check(t, c, root, "monitor.edit", "monitor:3"), integration.CodeResourceNotVisible, "team "+teamT1)
}

func TestIdentity(t *testing.T) {
	srv, _, c := setup(t)
	expect(t, check(t, c, integration.User{Email: " Dana@Example.com "}, "logs.read", "org"), integration.CodeAllowed, "")
	var lookup itest.Call
	for _, call := range srv.Calls() {
		if call.Path == "/api/v2/users" {
			lookup = call
		}
	}
	if lookup.Query.Get("filter") != "dana@example.com" || !strings.Contains(lookup.Query.Get("filter[status]"), "Disabled") {
		t.Errorf("lookup %v", lookup.Query)
	}
	expect(t, check(t, c, integration.User{Email: "ghost@example.com"}, "logs.read", "org"), integration.CodeUserNotFound, "")
	expect(t, check(t, c, integration.User{Email: "dup@example.com"}, "logs.read", "org"), integration.CodeUserAmbiguous, "")
	expect(t, check(t, c, off, "logs.read", "org"), integration.CodeDenied, "disabled")
	expect(t, check(t, c, integration.User{Email: "nostatus@example.com"}, "logs.read", "org"), integration.CodeUnsupported, "did not report")
	expect(t, check(t, c, integration.User{Email: "not an email"}, "logs.read", "org"), integration.CodeInvalidRequest, "")
}

func TestMissingAssetsAndErrors(t *testing.T) {
	_, f, c := setup(t)
	expect(t, check(t, c, dana, "monitor.edit", "monitor:999"), integration.CodeResourceNotVisible, "does not exist or hallpass cannot see it")
	expect(t, check(t, c, dana, "dashboard.edit", "dashboard:nope"), integration.CodeResourceNotVisible, "")
	expect(t, check(t, c, dana, "slo.edit", "slo:nope"), integration.CodeResourceNotVisible, "")
	expect(t, check(t, c, dana, "notebook.edit", "notebook:1"), integration.CodeResourceNotVisible, "")
	// Even a user without the permission gets unknown on a missing asset.
	expect(t, check(t, c, bob, "monitor.edit", "monitor:999"), integration.CodeResourceNotVisible, "")
	// A role hallpass cannot read.
	f.mu.Lock()
	f.users[0].roles = []string{"55555555-5555-5555-5555-555555555555"}
	f.mu.Unlock()
	expect(t, check(t, c, dana, "logs.read", "org"), integration.CodeResourceNotVisible, "role 55555555")
	f.mu.Lock()
	f.users[0].roles = []string{roleStd}
	f.status = 403
	f.mu.Unlock()
	expect(t, check(t, c, dana, "logs.read", "org"), integration.CodeCredentialRejected, "invalid, or the application key lacks the scope")
}

func TestRejectsBadResources(t *testing.T) {
	srv, _, c := setup(t)
	expect(t, check(t, c, dana, "logs.read", "org"), integration.CodeAllowed, "")
	n := len(srv.Calls())
	cases := []struct{ action, resource string }{
		{"monitor.edit", "dashboard:abc"},
		{"logs.read", "monitor:1"},
		{"logs.read", "org:1"},
		{"monitor.edit", "monitor:"},
		{"monitor.edit", "monitor:1/2"},
		{"monitor.edit", "monitor:1?x=1"},
		{"monitor.edit", "monitor:-1"},
		{"monitor.edit", "synthetic:1"},
	}
	for _, tc := range cases {
		d := check(t, c, dana, tc.action, tc.resource)
		if d.Code != integration.CodeInvalidRequest {
			t.Errorf("%s %s: %s (%s), want invalid_request", tc.action, tc.resource, d.Code, d.Text)
		}
	}
	for _, call := range srv.Calls()[n:] {
		if call.Path != "/api/v2/users" {
			t.Errorf("rejected resource reached %s", call.Path)
		}
	}
}

func TestFailures(t *testing.T) {
	srv, _, c := setup(t)
	expect(t, check(t, c, dana, "monitor.edit", "monitor:1"), integration.CodeAllowed, "")
	itest.FailureCases(t, srv, func() integration.Decision {
		return check(t, c, dana, "monitor.edit", "monitor:1")
	})
}

func TestProbe(t *testing.T) {
	_, f, c := setup(t)
	r, err := c.Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.Summary, "reads users") {
		t.Error(r.Summary)
	}
	itest.AssertNoCanary(t, r.Summary)
	if !strings.Contains(strings.Join(r.Warnings, "\n"), "teams_read") {
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
}

func TestNewRejectsBadSettings(t *testing.T) {
	srv := itest.NewServer(t)
	deps, _ := itest.Deps(t, srv)
	for _, secrets := range []map[string]secret.Secret{{}, {"api_key": itest.Literal("a")}, {"credential": itest.Literal("b")}} {
		s := itest.Settings("dd", "datadog", map[string]string{}, secrets)
		if _, err := (Integration{}).New(context.Background(), s, deps); err == nil {
			t.Errorf("New accepted secrets %v", secrets)
		}
	}
	if err := integration.ValidateFields((Integration{}).Fields()); err != nil {
		t.Error(err)
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
	if _, ok := integration.FindAction(Integration{}, "raw:monitors_write"); !ok {
		t.Error("raw:monitors_write not matched")
	}
	for _, a := range actionList {
		if _, asset := assetTypes[a.resource]; !asset && a.resource != "org" {
			t.Errorf("action %s names unknown resource %s", a.name, a.resource)
		}
		if (a.resource == "org") != (a.relation == "") {
			t.Errorf("action %s: org actions carry no relation, asset actions do", a.name)
		}
	}
}
