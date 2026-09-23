package databricks

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

const (
	clientID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
	tableRN  = "table:main.sales.orders"
)

var (
	dana = integration.User{Email: "dana@example.com"} // groups: users, data-readers
	bob  = integration.User{Email: "bob@example.com"}  // groups: users
	eve  = integration.User{Email: "eve@example.com"}  // no groups
	sam  = integration.User{Email: "sam@example.com"}  // groups: users, admins
)

// privilege is one effective privilege entry as the fake serves it.
type privilege struct {
	name, fromType, fromName string
}

// assignment is one principal's privileges on a securable.
type assignment struct {
	principal  string
	privileges []privilege
}

// aclEntry is one Permissions API entry.
type aclEntry struct {
	user, group string
	levels      []string
}

type fakeWorkspace struct {
	t  *testing.T
	mu sync.Mutex

	tokens    map[string]bool
	minted    int
	users     map[string]map[string]any // userName -> SCIM record
	grants    map[string][]assignment   // "<securable>/<name>" -> assignments
	pages     map[string][][]assignment // paginated override
	owners    map[string]string         // "<securable>/<name>" -> owner
	acls      map[string][]aclEntry     // "<object>/<id>" -> entries
	status    int                       // when set, every API call fails with it
	errorCode string
	pat       string // the personal access token the fake accepts
}

func ptr(b bool) *bool { return &b }

func user(id, name string, active *bool, groups ...string) map[string]any {
	m := map[string]any{"id": id, "userName": name, "displayName": itest.Canary + "name", "schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:User"}}
	if active != nil {
		m["active"] = *active
	}
	var gs []map[string]any
	for i, g := range groups {
		gs = append(gs, map[string]any{"display": g, "value": fmt.Sprint(1000 + i), "type": "direct"})
	}
	m["groups"] = gs
	return m
}

func newFake(t *testing.T) *fakeWorkspace {
	inh := func(name, fromType, fromName string) privilege { return privilege{name, fromType, fromName} }
	direct := func(name string) privilege { return privilege{name: name} }
	f := &fakeWorkspace{t: t, tokens: map[string]bool{}, pat: itest.Canary + "dapi123"}
	f.users = map[string]map[string]any{
		"dana@example.com":     user("100", "dana@example.com", ptr(true), "users", "data-readers"),
		"bob@example.com":      user("101", "bob@example.com", ptr(true), "users"),
		"eve@example.com":      user("102", "eve@example.com", ptr(true)),
		"sam@example.com":      user("103", "sam@example.com", ptr(true), "users", "admins"),
		"off@example.com":      user("104", "off@example.com", ptr(false), "users"),
		"nostatus@example.com": user("105", "nostatus@example.com", nil, "users"),
	}
	f.grants = map[string][]assignment{
		"catalog/main": {
			{"dana@example.com", []privilege{direct("USE_CATALOG"), direct("CREATE_SCHEMA")}},
			{"bob@example.com", []privilege{direct("BROWSE")}},
		},
		"schema/main.sales": {
			{"dana@example.com", []privilege{direct("CREATE_TABLE"), direct("USE_SCHEMA"), inh("USE_CATALOG", "CATALOG", "main")}},
			{"bob@example.com", []privilege{inh("BROWSE", "CATALOG", "main")}},
		},
		"table/main.sales.orders": {
			{"data-readers", []privilege{inh("SELECT", "SCHEMA", "main.sales"), inh("USE_SCHEMA", "SCHEMA", "main.sales"), inh("USE_CATALOG", "CATALOG", "main")}},
			{"dana@example.com", []privilege{direct("MODIFY")}},
			{"bob@example.com", []privilege{inh("BROWSE", "CATALOG", "main")}},
		},
		"volume/main.sales.files": {
			{"dana@example.com", []privilege{direct("READ_VOLUME"), direct("WRITE_VOLUME"), inh("USE_SCHEMA", "SCHEMA", "main.sales"), inh("USE_CATALOG", "CATALOG", "main")}},
		},
		"function/main.sales.fn": {
			{"dana@example.com", []privilege{direct("EXECUTE"), inh("USE_SCHEMA", "SCHEMA", "main.sales"), inh("USE_CATALOG", "CATALOG", "main")}},
		},
		"model/main.sales.churn": {
			{"dana@example.com", []privilege{direct("EXECUTE")}},
		},
		// ALL_PRIVILEGES on the catalog covers everything below it.
		"table/legacy.s.t": {{"data-readers", []privilege{inh("ALL_PRIVILEGES", "CATALOG", "legacy")}}},
		// The legacy USAGE stands for USE_CATALOG and USE_SCHEMA.
		"table/old.s.t": {{"dana@example.com", []privilege{direct("SELECT")}}, {"data-readers", []privilege{inh("USAGE", "CATALOG", "old"), inh("USAGE", "SCHEMA", "old.s")}}},
		// A quoted-looking name that is still a plain identifier.
		"table/main.sales.q_1": {{"dana@example.com", []privilege{direct("SELECT"), direct("USE_SCHEMA"), direct("USE_CATALOG")}}},
	}
	f.pages = map[string][][]assignment{
		"table/big.s.t": {
			{{"bob@example.com", []privilege{direct("BROWSE")}}},
			{}, // an empty page that still carries a token
			{{"dana@example.com", []privilege{direct("SELECT"), inh("USE_SCHEMA", "SCHEMA", "big.s"), inh("USE_CATALOG", "CATALOG", "big")}}},
		},
	}
	f.owners = map[string]string{
		"table/main.sales.orders": "dana@example.com",
		"catalog/main":            "data-owners",
		"schema/main.sales":       "data-readers",
		"volume/main.sales.files": "someone@example.com",
		"function/main.sales.fn":  "someone@example.com",
		"model/main.sales.churn":  "someone@example.com",
		"table/legacy.s.t":        "someone@example.com",
		"table/old.s.t":           "someone@example.com",
		"table/big.s.t":           "someone@example.com",
		"table/main.sales.q_1":    "someone@example.com",
	}
	f.acls = map[string][]aclEntry{
		"clusters/0123-456789-abcde1f2": {{group: "users", levels: []string{"CAN_ATTACH_TO"}}, {user: "dana@example.com", levels: []string{"CAN_RESTART"}}},
		"jobs/42":                       {{user: "dana@example.com", levels: []string{"CAN_MANAGE_RUN"}}, {user: "bob@example.com", levels: []string{"CAN_VIEW"}}},
		"jobs/43":                       {{user: "dana@example.com", levels: []string{"IS_OWNER"}}},
		"warehouses/abc123def456":       {{user: "dana@example.com", levels: []string{"CAN_USE"}}, {user: "bob@example.com", levels: []string{"CAN_MONITOR"}}},
		"notebooks/1234567890":          {{group: "data-readers", levels: []string{"CAN_EDIT"}}},
		"directories/222":               {{group: "data-readers", levels: []string{"CAN_READ"}}},
		"repos/333":                     {{user: "dana@example.com", levels: []string{"CAN_RUN"}}},
		"pipelines/p-1":                 {{user: "dana@example.com", levels: []string{"CAN_RUN"}}},
		"serving-endpoints/churn-v2":    {{user: "dana@example.com", levels: []string{"CAN_QUERY"}}, {user: "bob@example.com", levels: []string{"CAN_VIEW"}}},
		"cluster-policies/pol":          {{group: "users", levels: []string{"CAN_USE"}}},
	}
	return f
}

func apiErr(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(fmt.Sprintf(`{"error_code":"%s","message":"%smessage"}`, code, itest.Canary)))
}

func write(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// token is POST /oidc/v1/token with HTTP Basic client credentials.
func (f *fakeWorkspace) token(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fail := func(status int, code string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"error":"` + code + `","error_description":"` + itest.Canary + `desc"}`))
	}
	id, secret, ok := r.BasicAuth()
	if !ok || id != clientID || secret != itest.Canary+"secret" {
		fail(401, "invalid_client")
		return
	}
	_ = r.ParseForm()
	if r.Form.Get("grant_type") != "client_credentials" || r.Form.Get("scope") != scopeAllAPIs {
		f.t.Errorf("token form %v", r.Form)
		fail(400, "invalid_request")
		return
	}
	if r.Form.Get("client_secret") != "" || r.Form.Get("client_id") != "" {
		f.t.Error("client credentials sent in the form body, not the Basic header")
	}
	f.minted++
	tok := fmt.Sprintf("%stoken%d", itest.Canary, f.minted)
	f.tokens[tok] = true
	write(w, map[string]any{"access_token": tok, "token_type": "Bearer", "expires_in": 3600, "scope": scopeAllAPIs})
}

// api serves the workspace APIs.
func (f *fakeWorkspace) api(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !f.tokens[bearer] && bearer != f.pat {
		apiErr(w, 401, "UNAUTHENTICATED")
		return
	}
	if f.status != 0 {
		apiErr(w, f.status, f.errorCode)
		return
	}
	p, q := r.URL.Path, r.URL.Query()
	switch {
	case p == scimUsers:
		filter := q.Get("filter")
		if !strings.HasPrefix(filter, `userName eq "`) || !strings.HasSuffix(filter, `"`) {
			f.t.Errorf("SCIM filter %q", filter)
			apiErr(w, 400, "INVALID_PARAMETER_VALUE")
			return
		}
		if q.Get("attributes") == "" {
			f.t.Error("SCIM search without attributes")
		}
		email := strings.TrimSuffix(strings.TrimPrefix(filter, `userName eq "`), `"`)
		var res []map[string]any
		for name, u := range f.users {
			if strings.EqualFold(name, email) {
				res = append(res, u)
			}
		}
		if email == "dup@example.com" {
			res = append(res, user("200", "dup@example.com", ptr(true)), user("201", "Dup@example.com", ptr(true)))
		}
		if res == nil {
			res = []map[string]any{}
		}
		write(w, map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"}, "totalResults": len(res), "startIndex": 1, "itemsPerPage": len(res), "Resources": res})
	case p == scimMe:
		if bearer == f.pat {
			write(w, user("7", "hallpass-bot@example.com", ptr(true), "users"))
			return
		}
		write(w, user("8", clientID, ptr(true), "users", "admins"))
	case strings.HasPrefix(p, "/api/2.1/unity-catalog/effective-permissions/"):
		key := strings.TrimPrefix(p, "/api/2.1/unity-catalog/effective-permissions/")
		if q.Get("max_results") != "0" {
			f.t.Errorf("effective-permissions without max_results=0: %v", q)
		}
		if pages, ok := f.pages[key]; ok {
			i := 0
			if tok := q.Get("page_token"); tok != "" {
				_, _ = fmt.Sscanf(tok, "page-%d", &i)
			}
			if i >= len(pages) {
				apiErr(w, 400, "INVALID_PARAMETER_VALUE")
				return
			}
			body := map[string]any{"privilege_assignments": renderAssignments(pages[i])}
			if i+1 < len(pages) {
				body["next_page_token"] = fmt.Sprintf("page-%d", i+1)
			}
			write(w, body)
			return
		}
		as, ok := f.grants[key]
		if !ok {
			apiErr(w, 404, "RESOURCE_DOES_NOT_EXIST")
			return
		}
		write(w, map[string]any{"privilege_assignments": renderAssignments(as)})
	case strings.HasPrefix(p, "/api/2.1/unity-catalog/"):
		rest := strings.TrimPrefix(p, "/api/2.1/unity-catalog/")
		coll, name, _ := strings.Cut(rest, "/")
		var typ string
		for t, c := range ucCollections {
			if c == coll {
				typ = t
			}
		}
		owner, ok := f.owners[typ+"/"+name]
		if !ok {
			apiErr(w, 404, "RESOURCE_DOES_NOT_EXIST")
			return
		}
		write(w, map[string]any{"name": name, "full_name": name, "owner": owner, "comment": itest.Canary + "comment"})
	case strings.HasPrefix(p, "/api/2.0/permissions/"):
		key := strings.TrimPrefix(p, "/api/2.0/permissions/")
		entries, ok := f.acls[key]
		if !ok {
			apiErr(w, 404, "RESOURCE_DOES_NOT_EXIST")
			return
		}
		var list []map[string]any
		for _, e := range entries {
			var perms []map[string]any
			for _, l := range e.levels {
				perms = append(perms, map[string]any{"permission_level": l, "inherited": e.group != "", "inherited_from_object": []string{"/" + key}})
			}
			m := map[string]any{"all_permissions": perms, "display_name": itest.Canary + "display"}
			if e.user != "" {
				m["user_name"] = e.user
			} else {
				m["group_name"] = e.group
			}
			list = append(list, m)
		}
		// A service principal entry is always present and never matches a user.
		list = append(list, map[string]any{"service_principal_name": clientID, "all_permissions": []map[string]any{{"permission_level": "CAN_MANAGE", "inherited": false}}})
		write(w, map[string]any{"object_id": "/" + key, "object_type": strings.TrimSuffix(strings.Split(key, "/")[0], "s"), "access_control_list": list})
	default:
		f.t.Errorf("fake: no route for %s %s", r.Method, p)
		apiErr(w, 404, "NOT_FOUND")
	}
}

func renderAssignments(as []assignment) []map[string]any {
	out := []map[string]any{}
	for _, a := range as {
		var ps []map[string]any
		for _, p := range a.privileges {
			m := map[string]any{"privilege": p.name}
			if p.fromType != "" {
				m["inherited_from_type"] = p.fromType
				m["inherited_from_name"] = p.fromName
			}
			ps = append(ps, m)
		}
		out = append(out, map[string]any{"principal": a.principal, "privileges": ps})
	}
	return out
}

func setup(t *testing.T, values map[string]string) (*itest.Server, *fakeWorkspace, integration.Connection) {
	t.Helper()
	srv := itest.NewServer(t)
	f := newFake(t)
	srv.Handle("POST", "/oidc/v1/token", f.token)
	srv.Handle("GET", "/api/*", f.api)
	deps, _ := itest.Deps(t, srv)
	v := map[string]string{"url": srv.URL, "client_id": clientID}
	for k, val := range values {
		v[k] = val
	}
	sec := itest.Literal("secret")
	if v["auth_mode"] == modeToken {
		sec = secret.Literal(f.pat)
		delete(v, "client_id")
	}
	s := itest.Settings("dbx", "databricks", v, map[string]secret.Secret{"credential": sec})
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

// --- the action table -------------------------------------------------------

func allowDeny(t *testing.T, u integration.User, action, resource string, want integration.Code, text string) {
	t.Helper()
	_, _, c := setup(t, nil)
	d := check(t, c, u, action, resource)
	itest.ExpectCode(t, d, want)
	if text != "" && !strings.Contains(d.Text, text) {
		t.Errorf("text %q does not contain %q", d.Text, text)
	}
	itest.AssertNoCanary(t, d.Text)
}

func TestAction_table_read_allow(t *testing.T) {
	allowDeny(t, dana, "table.read", tableRN, integration.CodeAllowed, "via group data-readers on schema main.sales")
}
func TestAction_table_read_deny(t *testing.T) {
	allowDeny(t, bob, "table.read", tableRN, integration.CodeDenied, "lacks SELECT, USE_SCHEMA, USE_CATALOG")
}
func TestAction_table_write_allow(t *testing.T) {
	allowDeny(t, dana, "table.write", tableRN, integration.CodeAllowed, "granted directly")
}
func TestAction_table_write_deny(t *testing.T) {
	allowDeny(t, bob, "table.write", tableRN, integration.CodeDenied, "lacks MODIFY")
}
func TestAction_table_create_allow(t *testing.T) {
	allowDeny(t, dana, "table.create", "schema:main.sales", integration.CodeAllowed, "")
}
func TestAction_table_create_deny(t *testing.T) {
	allowDeny(t, bob, "table.create", "schema:main.sales", integration.CodeDenied, "")
}
func TestAction_schema_create_allow(t *testing.T) {
	allowDeny(t, dana, "schema.create", "catalog:main", integration.CodeAllowed, "")
}
func TestAction_schema_create_deny(t *testing.T) {
	allowDeny(t, bob, "schema.create", "catalog:main", integration.CodeDenied, "")
}
func TestAction_catalog_use_allow(t *testing.T) {
	allowDeny(t, dana, "catalog.use", "catalog:main", integration.CodeAllowed, "")
}
func TestAction_catalog_use_deny(t *testing.T) {
	allowDeny(t, bob, "catalog.use", "catalog:main", integration.CodeDenied, "lacks USE_CATALOG")
}
func TestAction_volume_read_allow(t *testing.T) {
	allowDeny(t, dana, "volume.read", "volume:main.sales.files", integration.CodeAllowed, "")
}
func TestAction_volume_read_deny(t *testing.T) {
	allowDeny(t, bob, "volume.read", "volume:main.sales.files", integration.CodeDenied, "")
}
func TestAction_volume_write_allow(t *testing.T) {
	allowDeny(t, dana, "volume.write", "volume:main.sales.files", integration.CodeAllowed, "")
}
func TestAction_volume_write_deny(t *testing.T) {
	allowDeny(t, bob, "volume.write", "volume:main.sales.files", integration.CodeDenied, "")
}
func TestAction_function_execute_allow(t *testing.T) {
	allowDeny(t, dana, "function.execute", "function:main.sales.fn", integration.CodeAllowed, "")
}
func TestAction_function_execute_deny(t *testing.T) {
	allowDeny(t, bob, "function.execute", "function:main.sales.fn", integration.CodeDenied, "")
}
func TestAction_uc_manage_allow(t *testing.T) {
	// dana has no MANAGE grant but owns the table.
	allowDeny(t, dana, "uc.manage", tableRN, integration.CodeAllowed, "owns table main.sales.orders")
}
func TestAction_uc_manage_deny(t *testing.T) {
	allowDeny(t, bob, "uc.manage", tableRN, integration.CodeDenied, "lacks MANAGE")
}
func TestAction_cluster_attach_allow(t *testing.T) {
	allowDeny(t, bob, "cluster.attach", "cluster:0123-456789-abcde1f2", integration.CodeAllowed, "via group users")
}
func TestAction_cluster_attach_deny(t *testing.T) {
	allowDeny(t, eve, "cluster.attach", "cluster:0123-456789-abcde1f2", integration.CodeDenied, "no permission")
}
func TestAction_cluster_restart_allow(t *testing.T) {
	allowDeny(t, dana, "cluster.restart", "cluster:0123-456789-abcde1f2", integration.CodeAllowed, "granted directly")
}
func TestAction_cluster_restart_deny(t *testing.T) {
	allowDeny(t, bob, "cluster.restart", "cluster:0123-456789-abcde1f2", integration.CodeDenied, "holds only CAN_ATTACH_TO")
}
func TestAction_cluster_manage_allow(t *testing.T) {
	allowDeny(t, sam, "cluster.manage", "cluster:0123-456789-abcde1f2", integration.CodeAllowed, "workspace admin")
}
func TestAction_cluster_manage_deny(t *testing.T) {
	allowDeny(t, dana, "cluster.manage", "cluster:0123-456789-abcde1f2", integration.CodeDenied, "not CAN_MANAGE")
}
func TestAction_job_view_allow(t *testing.T) {
	allowDeny(t, bob, "job.view", "job:42", integration.CodeAllowed, "")
}
func TestAction_job_view_deny(t *testing.T) {
	allowDeny(t, eve, "job.view", "job:42", integration.CodeDenied, "")
}
func TestAction_job_run_allow(t *testing.T) {
	allowDeny(t, dana, "job.run", "job:42", integration.CodeAllowed, "")
}
func TestAction_job_run_deny(t *testing.T) {
	allowDeny(t, bob, "job.run", "job:42", integration.CodeDenied, "holds only CAN_VIEW")
}
func TestAction_job_manage_allow(t *testing.T) {
	allowDeny(t, dana, "job.manage", "job:43", integration.CodeAllowed, "IS_OWNER, which implies CAN_MANAGE")
}
func TestAction_job_manage_deny(t *testing.T) {
	allowDeny(t, dana, "job.manage", "job:42", integration.CodeDenied, "")
}
func TestAction_warehouse_use_allow(t *testing.T) {
	allowDeny(t, dana, "warehouse.use", "warehouse:abc123def456", integration.CodeAllowed, "")
}
func TestAction_warehouse_use_deny(t *testing.T) {
	// CAN_MONITOR does not imply CAN_USE.
	allowDeny(t, bob, "warehouse.use", "warehouse:abc123def456", integration.CodeDenied, "holds only CAN_MONITOR")
}
func TestAction_warehouse_manage_allow(t *testing.T) {
	allowDeny(t, sam, "warehouse.manage", "warehouse:abc123def456", integration.CodeAllowed, "")
}
func TestAction_warehouse_manage_deny(t *testing.T) {
	allowDeny(t, dana, "warehouse.manage", "warehouse:abc123def456", integration.CodeDenied, "")
}
func TestAction_notebook_read_allow(t *testing.T) {
	allowDeny(t, dana, "notebook.read", "directory:222", integration.CodeAllowed, "")
}
func TestAction_notebook_read_deny(t *testing.T) {
	allowDeny(t, eve, "notebook.read", "notebook:1234567890", integration.CodeDenied, "")
}
func TestAction_notebook_run_allow(t *testing.T) {
	allowDeny(t, dana, "notebook.run", "repo:333", integration.CodeAllowed, "")
}
func TestAction_notebook_run_deny(t *testing.T) {
	allowDeny(t, dana, "notebook.run", "directory:222", integration.CodeDenied, "holds only CAN_READ")
}
func TestAction_notebook_edit_allow(t *testing.T) {
	allowDeny(t, dana, "notebook.edit", "notebook:1234567890", integration.CodeAllowed, "CAN_EDIT")
}
func TestAction_notebook_edit_deny(t *testing.T) {
	allowDeny(t, dana, "notebook.edit", "repo:333", integration.CodeDenied, "")
}
func TestAction_pipeline_run_allow(t *testing.T) {
	allowDeny(t, dana, "pipeline.run", "pipeline:p-1", integration.CodeAllowed, "")
}
func TestAction_pipeline_run_deny(t *testing.T) {
	allowDeny(t, bob, "pipeline.run", "pipeline:p-1", integration.CodeDenied, "")
}
func TestAction_endpoint_query_allow(t *testing.T) {
	allowDeny(t, dana, "endpoint.query", "endpoint:churn-v2", integration.CodeAllowed, "")
}
func TestAction_endpoint_query_deny(t *testing.T) {
	allowDeny(t, bob, "endpoint.query", "endpoint:churn-v2", integration.CodeDenied, "holds only CAN_VIEW")
}

// --- Unity Catalog semantics ------------------------------------------------

func TestAllPrivilegesAndUsage(t *testing.T) {
	_, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, dana, "table.read", "table:legacy.s.t"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, dana, "table.write", "table:legacy.s.t"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, dana, "raw:CREATE_VOLUME", "table:legacy.s.t"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, eve, "table.read", "table:legacy.s.t"), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, dana, "table.read", "table:old.s.t"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, dana, "table.write", "table:old.s.t"), integration.CodeDenied)
}

func TestEffectivePermissionsPaginate(t *testing.T) {
	srv, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, dana, "table.read", "table:big.s.t"), integration.CodeAllowed)
	pages := 0
	for _, call := range srv.Calls() {
		if strings.Contains(call.Path, "effective-permissions/table/big.s.t") {
			pages++
		}
	}
	if pages != 3 {
		t.Errorf("read %d pages, want 3", pages)
	}
	itest.ExpectCode(t, check(t, c, bob, "table.read", "table:big.s.t"), integration.CodeDenied)
}

func TestOwnerByGroupAndMissingObject(t *testing.T) {
	_, f, c := setup(t, nil)
	// The schema is owned by dana's group; bob is in neither.
	d := check(t, c, dana, "uc.manage", "schema:main.sales")
	itest.ExpectCode(t, d, integration.CodeAllowed)
	if !strings.Contains(d.Text, "owner data-readers") {
		t.Error(d.Text)
	}
	itest.ExpectCode(t, check(t, c, bob, "uc.manage", "schema:main.sales"), integration.CodeDenied)
	// Missing securable: unknown, not deny.
	itest.ExpectCode(t, check(t, c, dana, "table.read", "table:main.sales.nothing"), integration.CodeResourceNotVisible)
	// Grants readable but the object itself vanished between the two calls.
	f.mu.Lock()
	delete(f.owners, "table/main.sales.orders")
	f.mu.Unlock()
	itest.ExpectCode(t, check(t, c, bob, "table.read", tableRN), integration.CodeResourceNotVisible)
	itest.ExpectCode(t, check(t, c, dana, "table.read", tableRN), integration.CodeAllowed)
}

// --- workspace object semantics ---------------------------------------------

func TestAdminsRule(t *testing.T) {
	_, _, c := setup(t, map[string]string{"admins_manage_all": "false"})
	itest.ExpectCode(t, check(t, c, sam, "cluster.manage", "cluster:0123-456789-abcde1f2"), integration.CodeDenied)
	// Admins get no free pass on Unity Catalog data.
	_, _, c = setup(t, nil)
	itest.ExpectCode(t, check(t, c, sam, "table.read", tableRN), integration.CodeDenied)
	// And no free pass on an object that does not exist.
	itest.ExpectCode(t, check(t, c, sam, "cluster.manage", "cluster:nope"), integration.CodeResourceNotVisible)
}

func TestRawActions(t *testing.T) {
	srv, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, dana, "raw:CAN_RESTART", "cluster:0123-456789-abcde1f2"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, dana, "raw:CAN_MANAGE", "cluster:0123-456789-abcde1f2"), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, bob, "raw:CAN_USE", "policy:pol"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, dana, "raw:MODIFY", tableRN), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, dana, "raw:CREATE_VOLUME", "table:main.sales.q_1"), integration.CodeDenied)
	// The owner holds every privilege, raw ones included.
	itest.ExpectCode(t, check(t, c, dana, "raw:CREATE_VOLUME", tableRN), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, dana, "raw:EXECUTE", "model:main.sales.churn"), integration.CodeAllowed)
	n := len(srv.Calls())
	for _, bad := range []string{"raw:", "raw:select", "raw:SELECT x", "raw:S", "raw:1SELECT", "SELECT"} {
		if _, ok := (Integration{}).MatchAction(bad); ok {
			t.Errorf("%q matched", bad)
		}
	}
	if len(srv.Calls()) != n {
		t.Error("a rejected action reached the upstream")
	}
}

// nonSCIM counts the calls that are not identity lookups: itest.Check
// resolves the identity before every check, where the engine would cache it.
func nonSCIM(srv *itest.Server) int {
	n := 0
	for _, call := range srv.Calls() {
		if call.Path != scimUsers {
			n++
		}
	}
	return n
}

func TestRejectsBadResources(t *testing.T) {
	srv, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, dana, "catalog.use", "catalog:main"), integration.CodeAllowed)
	n := nonSCIM(srv)
	cases := []struct{ action, resource string }{
		{"table.read", "table:main.sales"},
		{"table.read", "table:main.sales.orders.extra"},
		{"table.read", "table:main.sales.or ders"},
		{"table.read", "table:main.sales.`orders`"},
		{"table.read", "table:main..orders"},
		{"table.read", "table:main.sales.orders?x=1"},
		{"table.read", "schema:main.sales"},
		{"table.read", "cluster:abc"},
		{"catalog.use", "catalog:main/x"},
		{"cluster.attach", "cluster:"},
		{"cluster.attach", "cluster:a/b"},
		{"cluster.attach", "cluster:-abc"},
		{"cluster.attach", "job:42"},
		{"notebook.read", "table:main.sales.orders"},
		{"uc.manage", "cluster:abc"},
		{"job.view", "user:dana@example.com"},
		{"raw:SELECT", "thing:1"},
	}
	for _, tc := range cases {
		d := check(t, c, dana, tc.action, tc.resource)
		if d.Code != integration.CodeInvalidRequest {
			t.Errorf("%s %s: %s (%s), want invalid_request", tc.action, tc.resource, d.Code, d.Text)
		}
	}
	if nonSCIM(srv) != n {
		t.Error("a rejected resource reached the upstream")
	}
}

func TestNamesAreEscapedInPaths(t *testing.T) {
	srv, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, dana, "table.read", "table:main.sales.q_1"), integration.CodeAllowed)
	found := false
	for _, call := range srv.Calls() {
		if call.Path == "/api/2.1/unity-catalog/effective-permissions/table/main.sales.q_1" {
			found = true
		}
	}
	if !found {
		t.Error("effective-permissions path not as expected")
	}
}

// --- identity -----------------------------------------------------------------

func TestIdentity(t *testing.T) {
	srv, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, integration.User{Email: " Dana@Example.com "}, "catalog.use", "catalog:main"), integration.CodeAllowed)
	last := srv.Calls()[len(srv.Calls())-2]
	if last.Path != scimUsers || last.Query.Get("filter") != `userName eq "dana@example.com"` {
		t.Errorf("SCIM lookup %s %v", last.Path, last.Query)
	}
	itest.ExpectCode(t, check(t, c, integration.User{Email: "nobody@example.com"}, "catalog.use", "catalog:main"), integration.CodeUserNotFound)
	itest.ExpectCode(t, check(t, c, integration.User{Email: "dup@example.com"}, "catalog.use", "catalog:main"), integration.CodeUserAmbiguous)
	itest.ExpectCode(t, check(t, c, integration.User{Email: `da"na@example.com`}, "catalog.use", "catalog:main"), integration.CodeInvalidRequest)
	itest.ExpectCode(t, check(t, c, integration.User{Email: "not an email"}, "catalog.use", "catalog:main"), integration.CodeInvalidRequest)
	n := len(srv.Calls())
	d := check(t, c, integration.User{Email: "off@example.com"}, "catalog.use", "catalog:main")
	itest.ExpectCode(t, d, integration.CodeDenied)
	if !strings.Contains(d.Text, "deactivated") {
		t.Error(d.Text)
	}
	itest.ExpectCode(t, check(t, c, integration.User{Email: "nostatus@example.com"}, "catalog.use", "catalog:main"), integration.CodeUnsupported)
	// Neither reached the grants: the SCIM lookup is the only call each.
	if len(srv.Calls()) != n+2 {
		t.Errorf("%d calls for a deactivated and a status-less user, want 2", len(srv.Calls())-n)
	}
}

// --- errors and auth ----------------------------------------------------------

func TestAPIErrors(t *testing.T) {
	_, f, c := setup(t, nil)
	set := func(status int, code string) {
		f.mu.Lock()
		f.status, f.errorCode = status, code
		f.mu.Unlock()
	}
	itest.ExpectCode(t, check(t, c, dana, "catalog.use", "catalog:main"), integration.CodeAllowed)
	set(403, "PERMISSION_DENIED")
	d := check(t, c, dana, "catalog.use", "catalog:main")
	itest.ExpectCode(t, d, integration.CodeCredentialRejected)
	if !strings.Contains(d.Text, "PERMISSION_DENIED") {
		t.Error(d.Text)
	}
	set(400, "INVALID_PARAMETER_VALUE")
	itest.ExpectCode(t, check(t, c, dana, "catalog.use", "catalog:main"), integration.CodeInvalidRequest)
	set(404, "RESOURCE_DOES_NOT_EXIST")
	itest.ExpectCode(t, check(t, c, dana, "catalog.use", "catalog:main"), integration.CodeUserNotFound)
	set(0, "")
	itest.ExpectCode(t, check(t, c, dana, "catalog.use", "catalog:main"), integration.CodeAllowed)
}

func TestFailures(t *testing.T) {
	srv, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, dana, "catalog.use", "catalog:main"), integration.CodeAllowed)
	itest.FailureCases(t, srv, func() integration.Decision {
		return check(t, c, dana, "catalog.use", "catalog:main")
	})
}

func TestFailuresAtTokenEndpoint(t *testing.T) {
	srv, _, c := setup(t, nil)
	itest.FailureCases(t, srv, func() integration.Decision {
		return check(t, c, dana, "catalog.use", "catalog:main")
	})
}

func TestTokenCachedAndBasicAuth(t *testing.T) {
	srv, f, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, dana, "catalog.use", "catalog:main"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, bob, "catalog.use", "catalog:main"), integration.CodeDenied)
	f.mu.Lock()
	if f.minted != 1 {
		t.Errorf("minted %d tokens, want 1", f.minted)
	}
	f.mu.Unlock()
	for _, call := range srv.Calls() {
		if strings.HasPrefix(call.Path, "/api/") && !strings.HasPrefix(call.Header.Get("Authorization"), "Bearer "+itest.Canary+"token") {
			t.Errorf("API call without the minted bearer: %q", call.Header.Get("Authorization"))
		}
	}
}

func TestBadSecret(t *testing.T) {
	srv := itest.NewServer(t)
	f := newFake(t)
	srv.Handle("POST", "/oidc/v1/token", f.token)
	srv.Handle("GET", "/api/*", f.api)
	deps, _ := itest.Deps(t, srv)
	s := itest.Settings("dbx", "databricks", map[string]string{"url": srv.URL, "client_id": clientID}, map[string]secret.Secret{"credential": itest.Literal("wrong")})
	c, err := (Integration{}).New(context.Background(), s, deps)
	if err != nil {
		t.Fatal(err)
	}
	d := check(t, c, dana, "catalog.use", "catalog:main")
	itest.ExpectCode(t, d, integration.CodeCredentialRejected)
	itest.AssertNoCanary(t, d.Text)
}

func TestPersonalAccessToken(t *testing.T) {
	srv, f, c := setup(t, map[string]string{"auth_mode": modeToken})
	itest.ExpectCode(t, check(t, c, dana, "catalog.use", "catalog:main"), integration.CodeAllowed)
	f.mu.Lock()
	if f.minted != 0 {
		t.Error("PAT mode minted a token")
	}
	f.mu.Unlock()
	for _, call := range srv.Calls() {
		if call.Path == "/oidc/v1/token" {
			t.Error("PAT mode called the token endpoint")
		}
		if strings.HasPrefix(call.Path, "/api/") && call.Header.Get("Authorization") != "Bearer "+f.pat {
			t.Errorf("Authorization %q", call.Header.Get("Authorization"))
		}
	}
	r, err := c.Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.Summary, "hallpass-bot@example.com") || !strings.Contains(r.Summary, "workspace admin: false") {
		t.Error(r.Summary)
	}
	if !strings.Contains(strings.Join(r.Warnings, "\n"), "not a workspace admin") {
		t.Errorf("warnings %q", r.Warnings)
	}
}

func TestNewRejectsBadSettings(t *testing.T) {
	srv := itest.NewServer(t)
	deps, _ := itest.Deps(t, srv)
	cases := []map[string]string{
		{},
		{"url": srv.URL},                   // no client_id in oauth mode
		{"url": srv.URL, "client_id": "x"}, // too short
		{"url": srv.URL, "client_id": "a b c d e f g h"}, // spaces
		{"url": srv.URL, "client_id": clientID, "auth_mode": "magic"},
	}
	for _, v := range cases {
		s := itest.Settings("dbx", "databricks", v, map[string]secret.Secret{"credential": itest.Literal("x")})
		if _, err := (Integration{}).New(context.Background(), s, deps); err == nil {
			t.Errorf("New accepted %v", v)
		}
	}
	s := itest.Settings("dbx", "databricks", map[string]string{"url": srv.URL, "client_id": clientID}, nil)
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

// --- probe ------------------------------------------------------------------------

func TestProbe(t *testing.T) {
	srv, f, c := setup(t, nil)
	r, err := c.Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.Summary, clientID) || !strings.Contains(r.Summary, "workspace admin: true") {
		t.Error(r.Summary)
	}
	if !strings.Contains(strings.Join(r.Warnings, "\n"), "no read-only admin role") {
		t.Errorf("warnings %q", r.Warnings)
	}
	if last := srv.LastCall(); last.Path != scimMe {
		t.Errorf("probe called %s", last.Path)
	}
	f.mu.Lock()
	f.status, f.errorCode = 403, "PERMISSION_DENIED"
	f.mu.Unlock()
	if _, err := c.Probe(context.Background()); err == nil {
		t.Error("probe passed on 403")
	} else {
		itest.AssertNoCanary(t, err.Error())
	}
}

func TestCatalog(t *testing.T) {
	seen := map[string]bool{}
	for _, a := range (Integration{}).Actions() {
		if seen[a.Name] {
			t.Errorf("action %s listed twice", a.Name)
		}
		seen[a.Name] = true
		if a.Description == "" {
			t.Errorf("action %s has no description", a.Name)
		}
	}
	if _, ok := integration.FindAction(Integration{}, "raw:SELECT"); !ok {
		t.Error("raw:SELECT not matched")
	}
	// Every named action's types resolve to a known resource type.
	for _, a := range actionList {
		for _, typ := range a.types {
			if _, uc := ucTypes[typ]; !uc {
				if _, ws := wsTypes[typ]; !ws {
					t.Errorf("action %s names unknown type %s", a.name, typ)
				}
			}
		}
		if (a.level == "") == (len(a.privileges) == 0) {
			t.Errorf("action %s must set exactly one of level and privileges", a.name)
		}
	}
}
