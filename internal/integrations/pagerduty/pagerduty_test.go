package pagerduty

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/roee-hersh/hallpass/internal/integration"
	"github.com/roee-hersh/hallpass/internal/integration/itest"
	"github.com/roee-hersh/hallpass/internal/secret"
)

var (
	owner     = integration.User{Email: "owner@example.com"}     // owner
	manager   = integration.User{Email: "manager@example.com"}   // user (Manager)
	responder = integration.User{Email: "responder@example.com"} // limited_user (Responder)
	observer  = integration.User{Email: "observer@example.com"}  // observer, team manager on PTEAM1, responder on PTEAM2
	restrict  = integration.User{Email: "restrict@example.com"}  // restricted_access, team observer on PTEAM1
	stake     = integration.User{Email: "stake@example.com"}     // read_only_user
	nobody    = integration.User{Email: "nobody@example.com"}    // observer, no teams
)

type pdFakeUser struct {
	id, email, role string
	teams           []string
}

type fake struct {
	t  *testing.T
	mu sync.Mutex

	key       string
	users     []pdFakeUser
	teamRoles map[string]map[string]string // team -> user id -> role
	objects   map[string][]string          // "<type>/<id>" -> team ids
	incidents map[string]string            // incident id -> service id
	abilities []string
	status    int
	pageSize  int
}

func newFake(t *testing.T) *fake {
	return &fake{t: t, key: itest.Canary + "key", pageSize: 100,
		users: []pdFakeUser{
			{"PUOWNER", "owner@example.com", roleOwner, nil},
			{"PUMANAG", "manager@example.com", roleUser, nil},
			{"PURESP", "responder@example.com", roleLimitedUser, nil},
			{"PUOBS", "observer@example.com", roleObserver, []string{"PTEAM1", "PTEAM2"}},
			{"PUREST", "restrict@example.com", roleRestricted, []string{"PTEAM1"}},
			{"PUSTAKE", "stake@example.com", roleReadOnly, nil},
			{"PUNOBODY", "nobody@example.com", roleObserver, nil},
			// A name match that must not count as an email match.
			{"PUOTHER", "other@example.com", roleUser, nil},
		},
		teamRoles: map[string]map[string]string{
			"PTEAM1": {"PUOBS": teamRoleManager, "PUREST": teamRoleObserver},
			"PTEAM2": {"PUOBS": teamRoleResponder},
		},
		objects: map[string][]string{
			"services/PSVC1":           {"PTEAM1"},
			"services/PSVC2":           {"PTEAM2"},
			"services/PSVC0":           {},
			"escalation_policies/PEP1": {"PTEAM1"},
			"escalation_policies/PEP2": {"PTEAM2"},
			"schedules/PSCH1":          {"PTEAM1"},
			"schedules/PSCH2":          {"PTEAM2"},
			"teams/PTEAM1":             {"PTEAM1"},
			"teams/PTEAM2":             {"PTEAM2"},
		},
		incidents: map[string]string{"PINC1": "PSVC1", "PINC2": "PSVC2", "PINC0": "PSVC0"},
		abilities: []string{"teams", "advanced_permissions", "read_only_users"},
	}
}

func pdErr(w http.ResponseWriter, status int, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(fmt.Sprintf(`{"error":{"code":%d,"message":"%s message","errors":["%s detail"]}}`, code, itest.Canary, itest.Canary)))
}

func write(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func refs(ids []string, typ string) []map[string]any {
	out := []map[string]any{}
	for _, id := range ids {
		out = append(out, map[string]any{"id": id, "type": typ + "_reference", "summary": itest.Canary + id, "self": "https://api.pagerduty.com/" + typ + "s/" + id})
	}
	return out
}

func (f *fake) api(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Token token="+f.key {
		pdErr(w, 401, 2001)
		return
	}
	if r.Header.Get("Accept") != accept {
		f.t.Errorf("Accept %q", r.Header.Get("Accept"))
	}
	if f.status != 0 {
		pdErr(w, f.status, 2010)
		return
	}
	p, q := r.URL.Path, r.URL.Query()
	offset, _ := strconv.Atoi(q.Get("offset"))
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > f.pageSize {
		limit = f.pageSize
	}
	page := func(key string, values []map[string]any) {
		if offset > len(values) {
			offset = len(values)
		}
		end := offset + limit
		if end > len(values) {
			end = len(values)
		}
		write(w, map[string]any{key: values[offset:end], "limit": limit, "offset": offset, "more": end < len(values), "total": nil})
	}
	switch {
	case p == "/abilities":
		write(w, map[string]any{"abilities": f.abilities})
	case p == "/users":
		var values []map[string]any
		for _, u := range f.users {
			// PagerDuty's query matches names too; "other" carries the
			// searched address in its name.
			if q.Get("query") != "" && !strings.Contains(u.email, q.Get("query")) && !(u.id == "PUOTHER" && q.Get("query") == "owner@example.com") {
				continue
			}
			m := map[string]any{"id": u.id, "type": "user", "email": u.email, "role": u.role, "name": itest.Canary + " name"}
			if q.Get("include[]") == "teams" {
				m["teams"] = refs(u.teams, "team")
			}
			values = append(values, m)
		}
		if q.Get("query") == "dup@example.com" {
			values = append(values, map[string]any{"id": "PDUP1", "email": "dup@example.com", "role": roleUser}, map[string]any{"id": "PDUP2", "email": "Dup@example.com", "role": roleUser})
		}
		page("users", values)
	case strings.HasPrefix(p, "/teams/") && strings.HasSuffix(p, "/members"):
		team := strings.TrimSuffix(strings.TrimPrefix(p, "/teams/"), "/members")
		roles, ok := f.teamRoles[team]
		if !ok {
			pdErr(w, 404, 2100)
			return
		}
		var values []map[string]any
		for _, u := range f.users {
			if role, ok := roles[u.id]; ok {
				values = append(values, map[string]any{"user": map[string]any{"id": u.id, "type": "user_reference", "summary": itest.Canary}, "role": role})
			}
		}
		page("members", values)
	case strings.HasPrefix(p, "/incidents/"):
		id := strings.TrimPrefix(p, "/incidents/")
		svc, ok := f.incidents[id]
		if !ok {
			pdErr(w, 404, 2100)
			return
		}
		inc := map[string]any{"id": id, "type": "incident", "status": "triggered", "title": itest.Canary, "teams": refs(nil, "team")}
		if q.Get("include[]") == "services" {
			inc["service"] = map[string]any{"id": svc, "type": "service", "teams": refs(f.objects["services/"+svc], "team")}
		} else {
			inc["service"] = map[string]any{"id": svc, "type": "service_reference"}
		}
		write(w, map[string]any{"incident": inc})
	case strings.HasPrefix(p, "/services/") || strings.HasPrefix(p, "/escalation_policies/") || strings.HasPrefix(p, "/schedules/") || strings.HasPrefix(p, "/teams/"):
		teams, ok := f.objects[strings.TrimPrefix(p, "/")]
		if !ok {
			pdErr(w, 404, 2100)
			return
		}
		key := strings.TrimSuffix(strings.SplitN(strings.TrimPrefix(p, "/"), "/", 2)[0], "s")
		if key == "escalation_policie" {
			key = "escalation_policy"
		}
		body := map[string]any{"id": strings.SplitN(strings.TrimPrefix(p, "/"), "/", 2)[1], "type": key, "summary": itest.Canary, "teams": refs(teams, "team")}
		write(w, map[string]any{key: body})
	default:
		f.t.Errorf("fake: no route for %s %s", r.Method, p)
		pdErr(w, 404, 2100)
	}
}

func setup(t *testing.T) (*itest.Server, *fake, integration.Connection) {
	t.Helper()
	srv := itest.NewServer(t)
	srv.UseSpec(itest.SpecFromEnv(t, "pagerduty"), itest.SpecOptions{})
	f := newFake(t)
	srv.Handle("GET", "/*", f.api)
	deps, _ := itest.Deps(t, srv)
	s := itest.Settings("pd", "pagerduty", map[string]string{"url": srv.URL}, map[string]secret.Secret{"credential": secret.Literal(f.key)})
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

func TestAction_incident_acknowledge_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, responder, "incident.acknowledge", "incident:PINC0"), integration.CodeAllowed, "Responder base role")
	// Observer with a responder team role on the incident's service team.
	expect(t, check(t, c, observer, "incident.acknowledge", "incident:PINC2"), integration.CodeAllowed, "team responder")
}
func TestAction_incident_acknowledge_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, nobody, "incident.acknowledge", "incident:PINC1"), integration.CodeDenied, "no team role")
	expect(t, check(t, c, stake, "incident.acknowledge", "incident:PINC1"), integration.CodeDenied, "read-only role")
	// A team observer may not respond.
	expect(t, check(t, c, restrict, "incident.acknowledge", "incident:PINC1"), integration.CodeDenied, "team observer")
}
func TestAction_incident_resolve_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, manager, "incident.resolve", "incident:PINC1"), integration.CodeAllowed, "Manager base role")
}
func TestAction_incident_resolve_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, nobody, "incident.resolve", "incident:PINC0"), integration.CodeDenied, "belongs to no team")
}
func TestAction_incident_reassign_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, owner, "incident.reassign", "incident:PINC1"), integration.CodeAllowed, "Account Owner")
	// Team manager on the service's team.
	expect(t, check(t, c, observer, "incident.reassign", "incident:PINC1"), integration.CodeAllowed, "team manager")
}
func TestAction_incident_reassign_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, observer, "incident.reassign", "incident:PINC0"), integration.CodeDenied, "")
}
func TestAction_service_edit_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, manager, "service.edit", "service:PSVC1"), integration.CodeAllowed, "")
	expect(t, check(t, c, observer, "service.edit", "service:PSVC1"), integration.CodeAllowed, "team manager")
}
func TestAction_service_edit_deny(t *testing.T) {
	_, _, c := setup(t)
	// A Responder base role does not edit configuration.
	expect(t, check(t, c, responder, "service.edit", "service:PSVC1"), integration.CodeDenied, "no team role")
	// A team responder does not either.
	expect(t, check(t, c, observer, "service.edit", "service:PSVC2"), integration.CodeDenied, "team responder")
}
func TestAction_service_maintenance_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, manager, "service.maintenance", "service:PSVC0"), integration.CodeAllowed, "")
	expect(t, check(t, c, observer, "service.maintenance", "service:PSVC2"), integration.CodeAllowed, "team responder")
	expect(t, check(t, c, responder, "service.maintenance", "service:PSVC2"), integration.CodeUnsupported, "not documented")
}
func TestAction_service_maintenance_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, nobody, "service.maintenance", "service:PSVC1"), integration.CodeDenied, "")
	expect(t, check(t, c, stake, "service.maintenance", "service:PSVC1"), integration.CodeDenied, "")
}
func TestAction_escalation_policy_edit_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, observer, "escalation_policy.edit", "escalation_policy:PEP1"), integration.CodeAllowed, "team manager")
}
func TestAction_escalation_policy_edit_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, observer, "escalation_policy.edit", "escalation_policy:PEP2"), integration.CodeDenied, "")
}
func TestAction_schedule_edit_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, manager, "schedule.edit", "schedule:PSCH2"), integration.CodeAllowed, "")
}
func TestAction_schedule_edit_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, restrict, "schedule.edit", "schedule:PSCH1"), integration.CodeDenied, "team observer")
}
func TestAction_schedule_override_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, responder, "schedule.override", "schedule:PSCH1"), integration.CodeAllowed, "")
	expect(t, check(t, c, observer, "schedule.override", "schedule:PSCH2"), integration.CodeAllowed, "")
}
func TestAction_schedule_override_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, restrict, "schedule.override", "schedule:PSCH1"), integration.CodeDenied, "")
}
func TestAction_team_manage_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, observer, "team.manage", "team:PTEAM1"), integration.CodeAllowed, "team manager")
	expect(t, check(t, c, owner, "team.manage", "team:PTEAM2"), integration.CodeAllowed, "")
}
func TestAction_team_manage_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, observer, "team.manage", "team:PTEAM2"), integration.CodeDenied, "team responder")
}
func TestAction_team_member_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, restrict, "team.member", "team:PTEAM1"), integration.CodeAllowed, "member of team PTEAM1")
}
func TestAction_team_member_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, manager, "team.member", "team:PTEAM1"), integration.CodeDenied, "not a member")
}
func TestAction_account_admin_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, owner, "account.admin", "account"), integration.CodeAllowed, "Account Owner")
}
func TestAction_account_admin_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, manager, "account.admin", "account"), integration.CodeDenied, "Manager")
}

// --- semantics -----------------------------------------------------------------

func TestIncidentTeamsFromService(t *testing.T) {
	srv, _, c := setup(t)
	expect(t, check(t, c, observer, "incident.acknowledge", "incident:PINC2"), integration.CodeAllowed, "")
	// The service came expanded with the incident: no separate service read.
	for _, call := range srv.Calls() {
		if strings.HasPrefix(call.Path, "/services/") {
			t.Error("service read although the incident expanded it")
		}
		if strings.HasPrefix(call.Path, "/incidents/") && call.Query.Get("include[]") != "services" {
			t.Errorf("incident read without include[]=services: %v", call.Query)
		}
	}
}

func TestPaging(t *testing.T) {
	srv, f, c := setup(t)
	f.mu.Lock()
	f.pageSize = 1
	f.mu.Unlock()
	// Team PTEAM1 has two members; the restricted user is on the second page.
	expect(t, check(t, c, restrict, "schedule.edit", "schedule:PSCH1"), integration.CodeDenied, "team observer")
	pages := 0
	for _, call := range srv.Calls() {
		if call.Path == "/teams/PTEAM1/members" {
			pages++
		}
	}
	if pages < 2 {
		t.Errorf("read %d member pages, want at least 2", pages)
	}
}

func TestIdentity(t *testing.T) {
	srv, _, c := setup(t)
	expect(t, check(t, c, integration.User{Email: " Owner@Example.com "}, "account.admin", "account"), integration.CodeAllowed, "")
	var lookup itest.Call
	for _, call := range srv.Calls() {
		if call.Path == "/users" {
			lookup = call
		}
	}
	if lookup.Query.Get("query") != "owner@example.com" || lookup.Query.Get("include[]") != "teams" {
		t.Errorf("lookup %v", lookup.Query)
	}
	expect(t, check(t, c, integration.User{Email: "ghost@example.com"}, "account.admin", "account"), integration.CodeUserNotFound, "")
	expect(t, check(t, c, integration.User{Email: "dup@example.com"}, "account.admin", "account"), integration.CodeUserAmbiguous, "")
	expect(t, check(t, c, integration.User{Email: "bad email"}, "account.admin", "account"), integration.CodeInvalidRequest, "")
}

func TestUnknownRole(t *testing.T) {
	_, f, c := setup(t)
	f.mu.Lock()
	f.users = append(f.users, pdFakeUser{"PUNEW", "new@example.com", "team_responder", nil})
	f.mu.Unlock()
	expect(t, check(t, c, integration.User{Email: "new@example.com"}, "incident.acknowledge", "incident:PINC1"), integration.CodeUnsupported, "does not know")
}

func TestMissingObjectsAndErrors(t *testing.T) {
	_, f, c := setup(t)
	expect(t, check(t, c, observer, "incident.acknowledge", "incident:PNOPE"), integration.CodeResourceNotVisible, "does not exist or hallpass cannot see it")
	expect(t, check(t, c, observer, "service.edit", "service:PNOPE"), integration.CodeResourceNotVisible, "")
	expect(t, check(t, c, observer, "team.member", "team:PNOPE"), integration.CodeResourceNotVisible, "")
	// Account-wide roles need no object read, but the object must exist.
	expect(t, check(t, c, manager, "service.edit", "service:PNOPE"), integration.CodeAllowed, "")
	f.mu.Lock()
	f.status = 403
	f.mu.Unlock()
	d := check(t, c, observer, "service.edit", "service:PSVC1")
	expect(t, d, integration.CodeCredentialRejected, "error 2010")
	f.mu.Lock()
	f.status = 402
	f.mu.Unlock()
	expect(t, check(t, c, observer, "service.edit", "service:PSVC1"), integration.CodeUnsupported, "lacks the ability")
}

func TestRejectsBadResources(t *testing.T) {
	srv, _, c := setup(t)
	expect(t, check(t, c, owner, "account.admin", "account"), integration.CodeAllowed, "")
	n := len(srv.Calls())
	cases := []struct{ action, resource string }{
		{"incident.acknowledge", "service:PSVC1"},
		{"service.edit", "incident:PINC1"},
		{"account.admin", "account:x"},
		{"team.member", "team:"},
		{"team.member", "team:P TEAM"},
		{"team.member", "team:PTEAM1/x"},
		{"team.member", "team:PTEAM1?x=1"},
		{"incident.resolve", "incident:p-1"},
	}
	for _, tc := range cases {
		d := check(t, c, owner, tc.action, tc.resource)
		if d.Code != integration.CodeInvalidRequest {
			t.Errorf("%s %s: %s (%s), want invalid_request", tc.action, tc.resource, d.Code, d.Text)
		}
	}
	for _, call := range srv.Calls()[n:] {
		if call.Path != "/users" {
			t.Errorf("rejected resource reached %s", call.Path)
		}
	}
	// Lower-case ids are accepted and upper-cased.
	expect(t, check(t, c, owner, "team.member", "team:pteam1"), integration.CodeDenied, "PTEAM1")
}

func TestFailures(t *testing.T) {
	srv, _, c := setup(t)
	expect(t, check(t, c, observer, "service.edit", "service:PSVC1"), integration.CodeAllowed, "")
	itest.FailureCases(t, srv, func() integration.Decision {
		return check(t, c, observer, "service.edit", "service:PSVC1")
	})
}

func TestProbe(t *testing.T) {
	_, f, c := setup(t)
	r, err := c.Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.Summary, "3 abilities") {
		t.Error(r.Summary)
	}
	itest.AssertNoCanary(t, r.Summary)
	joined := strings.Join(r.Warnings, "\n")
	if strings.Contains(joined, "lacks the teams ability") || !strings.Contains(joined, "Read-only API Key") {
		t.Errorf("warnings %q", r.Warnings)
	}
	f.mu.Lock()
	f.abilities = []string{"urgencies"}
	f.mu.Unlock()
	r, err = c.Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if joined := strings.Join(r.Warnings, "\n"); !strings.Contains(joined, "lacks the teams ability") || !strings.Contains(joined, "advanced permissions") {
		t.Errorf("warnings %q", r.Warnings)
	}
	f.mu.Lock()
	f.status = 401
	f.mu.Unlock()
	if _, err := c.Probe(context.Background()); err == nil {
		t.Error("probe passed on 401")
	} else {
		itest.AssertNoCanary(t, err.Error())
	}
}

func TestNewRejectsBadSettings(t *testing.T) {
	srv := itest.NewServer(t)
	deps, _ := itest.Deps(t, srv)
	s := itest.Settings("pd", "pagerduty", map[string]string{}, nil)
	if _, err := (Integration{}).New(context.Background(), s, deps); err == nil {
		t.Error("New accepted a connection without a credential")
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
}
