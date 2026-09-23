package azure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/roee-hersh/hallpass/internal/integration"
	"github.com/roee-hersh/hallpass/internal/integration/itest"
	"github.com/roee-hersh/hallpass/internal/secret"
)

const (
	tenantID = "11111111-1111-1111-1111-111111111111"
	clientID = "22222222-2222-2222-2222-222222222222"
	subID    = "33333333-3333-3333-3333-333333333333"

	oidDana = "aaaaaaaa-0000-0000-0000-000000000001"
	oidBob  = "aaaaaaaa-0000-0000-0000-000000000002"
	oidLead = "aaaaaaaa-0000-0000-0000-000000000003"
	oidOff  = "aaaaaaaa-0000-0000-0000-000000000004"
	oidNone = "aaaaaaaa-0000-0000-0000-000000000005"
	groupG1 = "bbbbbbbb-0000-0000-0000-000000000001"
	groupG2 = "bbbbbbbb-0000-0000-0000-000000000002"

	roleReader      = "/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7"
	roleContributor = "/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c"
	roleOwner       = "/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
	roleBlobReader  = "/providers/Microsoft.Authorization/roleDefinitions/2a2b9908-6ea1-4ae2-8e65-a410df84e7d1"
	roleVMOperator  = "/subscriptions/" + subID + "/providers/Microsoft.Authorization/roleDefinitions/cccccccc-0000-0000-0000-000000000001"

	scopeSub   = "/subscriptions/" + subID
	scopeProd  = scopeSub + "/resourceGroups/prod"
	scopeOther = scopeSub + "/resourceGroups/other"
	scopeCond  = scopeSub + "/resourceGroups/cond"
	scopeVM    = scopeProd + "/providers/Microsoft.Compute/virtualMachines/web-1"
	scopeStor  = scopeProd + "/providers/Microsoft.Storage/storageAccounts/prodstore"
	scopeMG    = "/providers/Microsoft.Management/managementGroups/corp"
	scopeMG2   = "/providers/Microsoft.Management/managementGroups/other-mg"
	allPrinces = "00000000-0000-0000-0000-000000000000"
)

var (
	dana = integration.User{Email: "dana@example.com"} // Reader at sub, VM Operator at prod via G1, Blob Reader on prodstore, conditional Contributor at cond
	bob  = integration.User{Email: "bob@example.com"}  // Owner at management group corp; Contributor at other
	lead = integration.User{Email: "lead@example.com"} // Contributor at sub; denied vm delete in prod
	none = integration.User{Email: "none@example.com"} // no assignments
)

type fakeUser struct {
	oid, mail, upn string
	enabled        bool
	groups         []string
}

type assignment struct {
	id, scope, role, principal, ptype, condition string
}

type deny struct {
	id, name, scope  string
	exact            bool
	actions, notActs []string
	dataActions      []string
	principals       []string
	excludes         []string
	condition        string
}

type fake struct {
	t  *testing.T
	mu sync.Mutex

	secret      string
	users       []fakeUser
	roles       map[string]map[string]any // role definition id (lower) -> properties
	assignments []assignment
	denies      []deny
	forbidden   map[string]bool // scopes the app may not read
	tokens      int
	pageSize    int
	status      int
}

func newFake(t *testing.T) *fake {
	return &fake{t: t, secret: itest.Canary + "secret", pageSize: 100,
		users: []fakeUser{
			{oidDana, "dana@example.com", "dana@corp.example", true, []string{groupG1}},
			{oidBob, "bob@example.com", "bob@corp.example", true, nil},
			{oidLead, "lead@example.com", "lead@corp.example", true, []string{groupG2}},
			{oidOff, "off@example.com", "off@corp.example", false, nil},
			{oidNone, "none@example.com", "none@corp.example", true, nil},
			// A mail that contains another; filters are exact so it never matches.
			{"aaaaaaaa-0000-0000-0000-000000000009", "dana@example.com.au", "danaau@corp.example", true, nil},
		},
		roles: map[string]map[string]any{
			strings.ToLower(roleReader):      {"roleName": "Reader", "type": "BuiltInRole", "description": itest.Canary, "permissions": []map[string]any{{"actions": []string{"*/read"}, "notActions": []string{}, "dataActions": []string{}, "notDataActions": []string{}}}, "assignableScopes": []string{"/"}},
			strings.ToLower(roleContributor): {"roleName": "Contributor", "type": "BuiltInRole", "description": itest.Canary, "permissions": []map[string]any{{"actions": []string{"*"}, "notActions": []string{"Microsoft.Authorization/*/Delete", "Microsoft.Authorization/*/Write", "Microsoft.Authorization/elevateAccess/Action"}, "dataActions": []string{}, "notDataActions": []string{}}}, "assignableScopes": []string{"/"}},
			strings.ToLower(roleOwner):       {"roleName": "Owner", "type": "BuiltInRole", "description": itest.Canary, "permissions": []map[string]any{{"actions": []string{"*"}, "notActions": []string{}, "dataActions": []string{}, "notDataActions": []string{}}}, "assignableScopes": []string{"/"}},
			strings.ToLower(roleBlobReader):  {"roleName": "Storage Blob Data Reader", "type": "BuiltInRole", "description": itest.Canary, "permissions": []map[string]any{{"actions": []string{"Microsoft.Storage/storageAccounts/blobServices/containers/read"}, "notActions": []string{}, "dataActions": []string{"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"}, "notDataActions": []string{}}}, "assignableScopes": []string{"/"}},
			strings.ToLower(roleVMOperator):  {"roleName": "VM Operator", "type": "CustomRole", "description": itest.Canary, "permissions": []map[string]any{{"actions": []string{"Microsoft.Compute/virtualMachines/start/action", "Microsoft.Compute/virtualMachines/restart/action", "Microsoft.Compute/*/read"}, "notActions": []string{}, "dataActions": []string{}, "notDataActions": []string{}}}, "assignableScopes": []string{scopeSub}},
		},
		assignments: []assignment{
			{"ra-1", scopeSub, roleReader, oidDana, "User", ""},
			{"ra-2", scopeProd, roleVMOperator, groupG1, "Group", ""},
			{"ra-3", scopeStor, roleBlobReader, oidDana, "User", ""},
			{"ra-4", scopeCond, roleContributor, oidDana, "User", "@Resource[Microsoft.Storage/storageAccounts/blobServices/containers:name] StringEquals 'x'"},
			{"ra-5", scopeMG, roleOwner, oidBob, "User", ""},
			{"ra-6", scopeOther, roleContributor, oidBob, "User", ""},
			{"ra-7", scopeSub, roleContributor, oidLead, "User", ""},
		},
		denies: []deny{
			{id: "da-1", name: "no-vm-delete-prod", scope: scopeProd, actions: []string{"Microsoft.Compute/virtualMachines/delete"}, principals: []string{allPrinces}},
			// Excludes a group: whether it holds the user is not readable.
			{id: "da-2", name: "no-listkeys", scope: scopeSub, actions: []string{"Microsoft.Storage/storageAccounts/listkeys/action"}, principals: []string{allPrinces}, excludes: []string{groupG2}},
			// Conditional deny.
			{id: "da-3", name: "cond-deny", scope: scopeOther, actions: []string{"Microsoft.Compute/virtualMachines/deallocate/action"}, principals: []string{allPrinces}, condition: "@Resource[Microsoft.Compute/virtualMachines:name] StringEquals 'x'"},
			// Excludes the user directly.
			{id: "da-4", name: "no-restart-except-dana", scope: scopeProd, actions: []string{"Microsoft.Compute/virtualMachines/restart/action"}, principals: []string{allPrinces}, excludes: []string{oidDana}},
			// Deny only at the exact scope.
			{id: "da-5", name: "no-deploy-sub-exact", scope: scopeSub, exact: true, actions: []string{"Microsoft.Resources/deployments/write"}, principals: []string{allPrinces}},
		},
		forbidden: map[string]bool{},
	}
}

func write(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func armErr(w http.ResponseWriter, status int, code string) {
	write(w, status, map[string]any{"error": map[string]any{"code": code, "message": itest.Canary}})
}

func (f *fake) token(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := r.ParseForm(); err != nil || r.PostForm.Get("client_secret") != f.secret || r.PostForm.Get("client_id") != clientID || r.PostForm.Get("grant_type") != "client_credentials" {
		write(w, 401, map[string]any{"error": "invalid_client", "error_description": itest.Canary})
		return
	}
	scope := r.PostForm.Get("scope")
	if !strings.HasSuffix(scope, "/.default") {
		f.t.Errorf("token scope %q", scope)
	}
	f.tokens++
	write(w, 200, map[string]any{"token_type": "Bearer", "expires_in": 3599, "access_token": itest.Canary + "-token-" + scope})
}

func (f *fake) authed(r *http.Request) bool {
	return strings.HasPrefix(r.Header.Get("Authorization"), "Bearer "+itest.Canary+"-token-")
}

func (f *fake) graph(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.authed(r) {
		armErr(w, 401, "InvalidAuthenticationToken")
		return
	}
	if f.status != 0 {
		armErr(w, f.status, "ServiceUnavailable")
		return
	}
	if r.URL.Path != "/v1.0/users" {
		f.t.Errorf("graph: no route for %s", r.URL.Path)
		armErr(w, 404, "Request_ResourceNotFound")
		return
	}
	filter := r.URL.Query().Get("$filter")
	var value []map[string]any
	for _, u := range f.users {
		for _, lit := range []string{"mail eq '" + u.mail + "'", "userPrincipalName eq '" + u.upn + "'"} {
			if strings.Contains(strings.ToLower(filter), strings.ToLower(lit)) {
				value = append(value, map[string]any{"id": u.oid, "mail": u.mail, "userPrincipalName": u.upn, "accountEnabled": u.enabled, "displayName": itest.Canary})
				break
			}
		}
	}
	if strings.Contains(filter, "dup@example.com") {
		value = append(value, map[string]any{"id": "aaaaaaaa-0000-0000-0000-0000000000d1", "mail": "dup@example.com", "accountEnabled": true}, map[string]any{"id": "aaaaaaaa-0000-0000-0000-0000000000d2", "userPrincipalName": "DUP@example.com", "accountEnabled": true})
	}
	if value == nil {
		value = []map[string]any{}
	}
	write(w, 200, map[string]any{"value": value})
}

// principalsOf are the user's own id and the groups it belongs to: what
// assignedTo() expands to.
func (f *fake) principalsOf(oid string) map[string]bool {
	set := map[string]bool{strings.ToLower(oid): true}
	for _, u := range f.users {
		if strings.EqualFold(u.oid, oid) {
			for _, g := range u.groups {
				set[strings.ToLower(g)] = true
			}
		}
	}
	return set
}

func (f *fake) arm(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.authed(r) {
		armErr(w, 401, "InvalidAuthenticationToken")
		return
	}
	if f.status != 0 {
		armErr(w, f.status, "InternalServerError")
		return
	}
	q := r.URL.Query()
	if q.Get("api-version") != apiVersion {
		f.t.Errorf("api-version %q", q.Get("api-version"))
	}
	p := r.URL.Path
	const marker = "/providers/Microsoft.Authorization/"
	i := strings.LastIndex(p, marker)
	if i < 0 {
		armErr(w, 404, "InvalidResourceType")
		return
	}
	scope, rest := p[:i], p[i+len(marker):]
	if f.forbidden[strings.ToLower(scope)] {
		armErr(w, 403, "AuthorizationFailed")
		return
	}
	oid := ""
	if fl := q.Get("$filter"); fl != "" {
		if !strings.HasPrefix(fl, "assignedTo('") && !strings.HasPrefix(fl, "type eq") {
			f.t.Errorf("filter %q", fl)
		}
		oid = strings.TrimSuffix(strings.TrimPrefix(fl, "assignedTo('"), "')")
	}
	switch {
	case rest == "roleAssignments":
		if !strings.HasPrefix(scope, "/subscriptions/"+subID) && !strings.HasPrefix(scope, "/providers/Microsoft.Management/") {
			armErr(w, 404, "SubscriptionNotFound")
			return
		}
		set := f.principalsOf(oid)
		var all []map[string]any
		for _, a := range f.assignments {
			if !set[strings.ToLower(a.principal)] {
				continue
			}
			props := map[string]any{"scope": a.scope, "roleDefinitionId": a.role, "principalId": a.principal, "principalType": a.ptype, "description": itest.Canary}
			if a.condition != "" {
				props["condition"] = a.condition
				props["conditionVersion"] = "2.0"
			}
			all = append(all, map[string]any{"id": a.scope + "/providers/Microsoft.Authorization/roleAssignments/" + a.id, "name": a.id, "type": "Microsoft.Authorization/roleAssignments", "properties": props})
		}
		start := 0
		if q.Get("$skipToken") != "" {
			fmt.Sscanf(q.Get("$skipToken"), "s%d", &start)
		}
		end := start + f.pageSize
		if end > len(all) {
			end = len(all)
		}
		if start > len(all) {
			start = len(all)
		}
		page := all[start:end]
		if page == nil {
			page = []map[string]any{}
		}
		body := map[string]any{"value": page}
		if end < len(all) {
			// Azure's next link is opaque; here it carries the filter along.
			body["nextLink"] = "https://" + r.Host + p + "?api-version=" + apiVersion + "&$filter=" + url.QueryEscape(q.Get("$filter")) + "&$skipToken=s" + fmt.Sprint(end)
		}
		write(w, 200, body)
	case rest == "denyAssignments":
		set := f.principalsOf(oid)
		value := []map[string]any{}
		for _, d := range f.denies {
			applies := false
			for _, pr := range d.principals {
				if pr == allPrinces || set[strings.ToLower(pr)] {
					applies = true
				}
			}
			if !applies {
				continue
			}
			principals := []map[string]any{}
			for _, pr := range d.principals {
				typ := "Group"
				if pr == allPrinces {
					typ = "SystemDefined"
				}
				principals = append(principals, map[string]any{"id": pr, "type": typ})
			}
			excludes := []map[string]any{}
			for _, pr := range d.excludes {
				typ := "Group"
				if strings.HasPrefix(pr, "aaaaaaaa") {
					typ = "User"
				}
				excludes = append(excludes, map[string]any{"id": pr, "type": typ})
			}
			perm := map[string]any{"actions": d.actions, "notActions": d.notActs, "dataActions": d.dataActions, "notDataActions": []string{}}
			props := map[string]any{"denyAssignmentName": d.name, "description": itest.Canary, "scope": d.scope, "doNotApplyToChildScopes": d.exact, "permissions": []map[string]any{perm}, "principals": principals, "excludePrincipals": excludes, "isSystemProtected": true}
			if d.condition != "" {
				props["condition"] = d.condition
				props["conditionVersion"] = "2.0"
			}
			value = append(value, map[string]any{"id": d.scope + "/providers/Microsoft.Authorization/denyAssignments/" + d.id, "name": d.id, "type": "Microsoft.Authorization/denyAssignments", "properties": props})
		}
		write(w, 200, map[string]any{"value": value})
	case strings.HasPrefix(rest, "roleDefinitions/"):
		props, ok := f.roles[strings.ToLower(p)]
		if !ok {
			armErr(w, 404, "RoleDefinitionDoesNotExist")
			return
		}
		write(w, 200, map[string]any{"id": p, "name": strings.TrimPrefix(rest, "roleDefinitions/"), "type": "Microsoft.Authorization/roleDefinitions", "properties": props})
	case rest == "roleDefinitions":
		var value []map[string]any
		for id, props := range f.roles {
			if props["type"] == "BuiltInRole" {
				value = append(value, map[string]any{"id": id, "properties": props})
			}
		}
		write(w, 200, map[string]any{"value": value})
	default:
		f.t.Errorf("arm: no route for %s", p)
		armErr(w, 404, "NotFound")
	}
}

func specs(t *testing.T) itest.Spec {
	return itest.AnySpec(
		itest.SpecFromEnv(t, "azure-RoleAssignmentsCalls"),
		itest.SpecFromEnv(t, "azure-RoleDefinitionsCalls"),
		itest.SpecFromEnv(t, "azure-DenyAssignmentCalls"),
		itest.SpecFromEnv(t, "msgraph"),
	)
}

func newServer(t *testing.T) (*itest.Server, *fake) {
	t.Helper()
	srv := itest.NewServer(t)
	// api-version and the {scope} parameter are defined in a sibling file
	// the description references; $skipToken is declared on the generic
	// scope path only; the tenant-root role definition listing the probe
	// uses has no path in the description.
	srv.UseSpec(specs(t), itest.SpecOptions{StripPrefix: []string{`/v1\.0`}, AllowQuery: []string{"api-version", "$skipToken"},
		IgnorePaths: []string{`/oauth2/v2\.0/token$`, `^/providers/Microsoft\.Authorization/roleDefinitions$`}})
	f := newFake(t)
	srv.Handle("POST", "/"+tenantID+"/oauth2/v2.0/token", f.token)
	srv.Handle("GET", "/v1.0/*", f.graph)
	srv.Handle("GET", "/subscriptions/*", f.arm)
	srv.Handle("GET", "/providers/*", f.arm)
	return srv, f
}

func setup(t *testing.T) (*itest.Server, *fake, integration.Connection) {
	t.Helper()
	srv, f := newServer(t)
	deps, _ := itest.Deps(t, srv)
	s := itest.Settings("az", "azure", map[string]string{"tenant_id": tenantID, "client_id": clientID, "url": srv.URL, "graph_url": srv.URL, "authority_url": srv.URL},
		map[string]secret.Secret{"credential": secret.Literal(f.secret)})
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

func TestAction_vm_read_allow(t *testing.T) {
	_, _, c := setup(t)
	// Reader at the subscription, inherited by the VM.
	expect(t, check(t, c, dana, "vm.read", "resource:"+scopeVM), integration.CodeAllowed, `role "Reader" assigned directly at `+scopeSub)
	// Owner at a management group, inherited by everything in the subscription.
	expect(t, check(t, c, bob, "vm.read", "subscription:"+subID), integration.CodeAllowed, "Owner")
}
func TestAction_vm_read_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, none, "vm.read", "resource:"+scopeVM), integration.CodeDenied, "no role assignment")
}
func TestAction_vm_start_allow(t *testing.T) {
	_, _, c := setup(t)
	// Custom role through group G1 at the resource group.
	expect(t, check(t, c, dana, "vm.start", "resource:"+scopeVM), integration.CodeAllowed, "through group "+groupG1)
}
func TestAction_vm_start_deny(t *testing.T) {
	_, _, c := setup(t)
	// The group assignment is at prod; a VM in another group is not covered.
	expect(t, check(t, c, dana, "vm.start", "resource:"+scopeOther+"/providers/Microsoft.Compute/virtualMachines/x"), integration.CodeDenied, "none of dana@example.com's 1 role assignment(s)")
}
func TestAction_vm_restart_allow(t *testing.T) {
	_, _, c := setup(t)
	// The deny excludes dana directly.
	expect(t, check(t, c, dana, "vm.restart", "resource:"+scopeVM), integration.CodeAllowed, "VM Operator")
}
func TestAction_vm_restart_deny(t *testing.T) {
	_, _, c := setup(t)
	// Contributor grants it, the deny at prod blocks it.
	expect(t, check(t, c, lead, "vm.restart", "resource:"+scopeVM), integration.CodeDenied, `deny assignment "no-restart-except-dana"`)
}
func TestAction_vm_deallocate_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, lead, "vm.deallocate", "resource:"+scopeVM), integration.CodeAllowed, "Contributor")
}
func TestAction_vm_deallocate_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, dana, "vm.deallocate", "resource:"+scopeVM), integration.CodeDenied, "")
	// A conditional deny leaves the answer unknown.
	expect(t, check(t, c, lead, "vm.deallocate", "resource:"+scopeOther+"/providers/Microsoft.Compute/virtualMachines/x"), integration.CodeUnsupported, `deny assignment "cond-deny" may block`)
}
func TestAction_vm_delete_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, lead, "vm.delete", "resource:"+scopeOther+"/providers/Microsoft.Compute/virtualMachines/x"), integration.CodeAllowed, "Contributor")
}
func TestAction_vm_delete_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, lead, "vm.delete", "resource:"+scopeVM), integration.CodeDenied, `deny assignment "no-vm-delete-prod" at `+scopeProd+" blocks")
	expect(t, check(t, c, dana, "vm.delete", "resource:"+scopeVM), integration.CodeDenied, "")
}
func TestAction_storage_listkeys_allow(t *testing.T) {
	_, f, c := setup(t)
	f.mu.Lock()
	f.denies = f.denies[:1]
	f.mu.Unlock()
	expect(t, check(t, c, lead, "storage.listkeys", "resource:"+scopeStor), integration.CodeAllowed, "Contributor")
}
func TestAction_storage_listkeys_deny(t *testing.T) {
	_, _, c := setup(t)
	// The deny excludes group G2; whether lead is in it is not readable.
	expect(t, check(t, c, lead, "storage.listkeys", "resource:"+scopeStor), integration.CodeUnsupported, `"no-listkeys" may block`)
	expect(t, check(t, c, dana, "storage.listkeys", "resource:"+scopeStor), integration.CodeDenied, "")
}
func TestAction_storage_blob_read_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, dana, "storage.blob.read", "resource:"+scopeStor), integration.CodeAllowed, "Storage Blob Data Reader")
}
func TestAction_storage_blob_read_deny(t *testing.T) {
	_, _, c := setup(t)
	// Contributor has no data actions.
	expect(t, check(t, c, lead, "storage.blob.read", "resource:"+scopeStor), integration.CodeDenied, "grants Microsoft.Storage")
}
func TestAction_storage_blob_write_allow(t *testing.T) {
	_, f, c := setup(t)
	f.mu.Lock()
	f.roles[strings.ToLower(roleBlobReader)]["permissions"] = []map[string]any{{"actions": []string{}, "notActions": []string{}, "dataActions": []string{"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/*"}, "notDataActions": []string{"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete"}}}
	f.mu.Unlock()
	expect(t, check(t, c, dana, "storage.blob.write", "resource:"+scopeStor), integration.CodeAllowed, "")
	expect(t, check(t, c, dana, "data:Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete", "resource:"+scopeStor), integration.CodeDenied, "")
}
func TestAction_storage_blob_write_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, dana, "storage.blob.write", "resource:"+scopeStor), integration.CodeDenied, "")
}
func TestAction_keyvault_secret_read_allow(t *testing.T) {
	_, f, c := setup(t)
	kv := scopeProd + "/providers/Microsoft.KeyVault/vaults/prod-kv"
	f.mu.Lock()
	f.roles["/providers/microsoft.authorization/roledefinitions/4633458b-17de-408a-b874-0445c86b69e6"] = map[string]any{"roleName": "Key Vault Secrets User", "type": "BuiltInRole", "permissions": []map[string]any{{"actions": []string{}, "notActions": []string{}, "dataActions": []string{"Microsoft.KeyVault/vaults/secrets/getSecret/action", "Microsoft.KeyVault/vaults/secrets/readMetadata/action"}, "notDataActions": []string{}}}}
	f.assignments = append(f.assignments, assignment{"ra-kv", kv, "/providers/Microsoft.Authorization/roleDefinitions/4633458b-17de-408a-b874-0445c86b69e6", oidNone, "User", ""})
	f.mu.Unlock()
	expect(t, check(t, c, none, "keyvault.secret.read", "resource:"+kv), integration.CodeAllowed, "Key Vault Secrets User")
}
func TestAction_keyvault_secret_read_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, lead, "keyvault.secret.read", "resource:"+scopeProd+"/providers/Microsoft.KeyVault/vaults/prod-kv"), integration.CodeDenied, "")
}
func TestAction_keyvault_secret_write_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, bob, "keyvault.secret.write", "resource:"+scopeProd+"/providers/Microsoft.KeyVault/vaults/prod-kv"), integration.CodeDenied, "")
	_, f, c := setup(t)
	f.mu.Lock()
	f.roles[strings.ToLower(roleOwner)]["permissions"] = []map[string]any{{"actions": []string{"*"}, "notActions": []string{}, "dataActions": []string{"*"}, "notDataActions": []string{}}}
	f.mu.Unlock()
	expect(t, check(t, c, bob, "keyvault.secret.write", "resource:"+scopeProd+"/providers/Microsoft.KeyVault/vaults/prod-kv"), integration.CodeAllowed, "Owner")
}
func TestAction_keyvault_secret_write_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, dana, "keyvault.secret.write", "resource:"+scopeProd+"/providers/Microsoft.KeyVault/vaults/prod-kv"), integration.CodeDenied, "")
}
func TestAction_aks_admin_credentials_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, lead, "aks.admin_credentials", "resource:"+scopeProd+"/providers/Microsoft.ContainerService/managedClusters/k8s"), integration.CodeAllowed, "")
}
func TestAction_aks_admin_credentials_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, dana, "aks.admin_credentials", "resource:"+scopeProd+"/providers/Microsoft.ContainerService/managedClusters/k8s"), integration.CodeDenied, "")
}
func TestAction_aks_user_credentials_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, bob, "aks.user_credentials", "resource:"+scopeProd+"/providers/Microsoft.ContainerService/managedClusters/k8s"), integration.CodeAllowed, "")
}
func TestAction_aks_user_credentials_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, none, "aks.user_credentials", "resource:"+scopeProd+"/providers/Microsoft.ContainerService/managedClusters/k8s"), integration.CodeDenied, "")
}
func TestAction_rbac_write_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, bob, "rbac.write", "resourcegroup:"+subID+"/prod"), integration.CodeAllowed, "Owner")
}
func TestAction_rbac_write_deny(t *testing.T) {
	_, _, c := setup(t)
	// Contributor's notActions subtract Microsoft.Authorization/*/Write.
	expect(t, check(t, c, lead, "rbac.write", "resourcegroup:"+subID+"/prod"), integration.CodeDenied, "none of lead@example.com's 1 role assignment(s)")
}
func TestAction_resourcegroup_delete_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, lead, "resourcegroup.delete", "resourcegroup:"+subID+"/prod"), integration.CodeAllowed, "")
}
func TestAction_resourcegroup_delete_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, dana, "resourcegroup.delete", "resourcegroup:"+subID+"/prod"), integration.CodeDenied, "")
}
func TestAction_deployment_write_allow(t *testing.T) {
	_, _, c := setup(t)
	// The exact-scope deny at the subscription does not reach the group.
	expect(t, check(t, c, lead, "deployment.write", "resourcegroup:"+subID+"/prod"), integration.CodeAllowed, "")
}
func TestAction_deployment_write_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, lead, "deployment.write", "subscription:"+subID), integration.CodeDenied, `"no-deploy-sub-exact"`)
}

func TestRawActions(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, dana, "raw:Microsoft.Network/publicIPAddresses/read", "resourcegroup:"+subID+"/prod"), integration.CodeAllowed, "Reader")
	expect(t, check(t, c, dana, "raw:Microsoft.Network/publicIPAddresses/delete", "resourcegroup:"+subID+"/prod"), integration.CodeDenied, "")
	expect(t, check(t, c, dana, "data:Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read", "resource:"+scopeStor), integration.CodeAllowed, "")
	// Reader's */read is a control-plane action, not a data action.
	expect(t, check(t, c, dana, "data:Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read", "resourcegroup:"+subID+"/prod"), integration.CodeDenied, "")
}

func TestConditionalAssignment(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, dana, "vm.delete", "resourcegroup:"+subID+"/cond"), integration.CodeUnsupported, "ABAC condition")
	// An unconditional grant elsewhere still answers.
	expect(t, check(t, c, dana, "vm.read", "resourcegroup:"+subID+"/cond"), integration.CodeAllowed, "Reader")
}

func TestManagementGroups(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, bob, "vm.delete", "managementgroup:corp"), integration.CodeAllowed, "Owner")
	// Another management group: bob's Owner at corp may or may not be above it.
	expect(t, check(t, c, bob, "vm.delete", "managementgroup:other-mg"), integration.CodeUnsupported, "management group")
	expect(t, check(t, c, dana, "vm.read", "managementgroup:corp"), integration.CodeDenied, "")
}

func TestAssignmentsBelowDoNotApply(t *testing.T) {
	_, _, c := setup(t)
	// bob's Contributor at other is below the subscription; only Owner at corp applies.
	expect(t, check(t, c, bob, "rbac.write", "subscription:"+subID), integration.CodeAllowed, "Owner")
	_, f, c := setup(t)
	f.mu.Lock()
	f.assignments = f.assignments[:4]
	f.assignments = append(f.assignments, assignment{"ra-6", scopeOther, roleContributor, oidBob, "User", ""})
	f.mu.Unlock()
	expect(t, check(t, c, bob, "vm.read", "subscription:"+subID), integration.CodeDenied, "no role assignment at or above")
	expect(t, check(t, c, bob, "vm.read", "resourcegroup:"+subID+"/other"), integration.CodeAllowed, "Contributor")
}

// --- identity ---------------------------------------------------------------

func TestIdentity(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, integration.User{Email: "nobody@example.com"}, "vm.read", "subscription:"+subID), integration.CodeUserNotFound, "no Entra user")
	expect(t, check(t, c, integration.User{Email: "dup@example.com"}, "vm.read", "subscription:"+subID), integration.CodeUserAmbiguous, "2 Entra users")
	expect(t, check(t, c, integration.User{Email: "off@example.com"}, "vm.read", "subscription:"+subID), integration.CodeDenied, "disabled")
	expect(t, check(t, c, integration.User{Email: "not an email"}, "vm.read", "subscription:"+subID), integration.CodeInvalidRequest, "")
	// By UPN as well as mail.
	expect(t, check(t, c, integration.User{Email: "dana@corp.example"}, "vm.read", "subscription:"+subID), integration.CodeAllowed, "")
}

func TestFilterQuotesEmail(t *testing.T) {
	srv, _, c := setup(t)
	check(t, c, integration.User{Email: "o'neil@example.com"}, "vm.read", "subscription:"+subID)
	for _, call := range srv.Calls() {
		if call.Path == "/v1.0/users" && !strings.Contains(call.Query.Get("$filter"), "'o''neil@example.com'") {
			t.Errorf("filter %q", call.Query.Get("$filter"))
		}
	}
}

// stubIdentity is a microsoft365 connection that resolves one user.
type stubIdentity struct {
	integration.Connection
	id integration.Identity
}

func (s stubIdentity) ResolveIdentity(context.Context, integration.User) (integration.Identity, error) {
	return s.id, nil
}

func TestMicrosoft365Connection(t *testing.T) {
	srv, _ := newServer(t)
	deps, _ := itest.Deps(t, srv)
	deps.Connection = func(id string) (integration.Connection, error) {
		if id != "m365" {
			return nil, errors.New("no such connection")
		}
		return stubIdentity{id: integration.Identity{ID: oidDana, Display: "dana@example.com", Attrs: map[string]string{"account_enabled": "true"}}}, nil
	}
	s := itest.Settings("az", "azure", map[string]string{"tenant_id": tenantID, "client_id": clientID, "url": srv.URL, "authority_url": srv.URL, "microsoft365_connection": "m365"},
		map[string]secret.Secret{"credential": secret.Literal(itest.Canary + "secret")})
	c, err := (Integration{}).New(context.Background(), s, deps)
	if err != nil {
		t.Fatal(err)
	}
	expect(t, check(t, c, dana, "vm.read", "subscription:"+subID), integration.CodeAllowed, "Reader")
	for _, call := range srv.Calls() {
		if strings.HasPrefix(call.Path, "/v1.0/") {
			t.Errorf("Graph called although a microsoft365 connection resolves users: %s", call.Path)
		}
	}
	// The token endpoint was used for ARM only.
	tokens := 0
	for _, call := range srv.Calls() {
		if strings.HasSuffix(call.Path, "/oauth2/v2.0/token") {
			tokens++
		}
	}
	if tokens != 1 {
		t.Errorf("%d token calls, want 1", tokens)
	}
	if _, err := (Integration{}).New(context.Background(), itest.Settings("az", "azure", map[string]string{"tenant_id": tenantID, "client_id": clientID, "microsoft365_connection": "nope"}, map[string]secret.Secret{"credential": secret.Literal("x")}), deps); err == nil {
		t.Error("unknown connection accepted")
	}
}

func TestCallerGroupsIgnored(t *testing.T) {
	srv, _, c := setup(t)
	expect(t, check(t, c, integration.User{Email: "none@example.com", Groups: []string{groupG1}}, "vm.start", "resource:"+scopeVM), integration.CodeDenied, "")
	for _, call := range srv.Calls() {
		if strings.Contains(call.Query.Get("$filter"), groupG1) {
			t.Error("caller group reached the filter")
		}
	}
}

// --- transport --------------------------------------------------------------

func TestPagingAndCaching(t *testing.T) {
	srv, f, c := setup(t)
	f.mu.Lock()
	f.pageSize = 1
	f.mu.Unlock()
	// No assignment grants this, so every page and every covering role
	// definition is read; the second check finds the definitions cached.
	expect(t, check(t, c, dana, "rbac.write", "resourcegroup:"+subID+"/prod"), integration.CodeDenied, "2 role assignment(s)")
	expect(t, check(t, c, dana, "rbac.write", "resourcegroup:"+subID+"/prod"), integration.CodeDenied, "")
	pages, defs, tokens := 0, 0, 0
	for _, call := range srv.Calls() {
		switch {
		case strings.HasSuffix(call.Path, "/roleAssignments"):
			pages++
		case strings.Contains(call.Path, "/roleDefinitions/"):
			defs++
		case strings.HasSuffix(call.Path, "/token"):
			tokens++
		}
	}
	// dana has four assignments: four pages per check.
	if pages != 8 {
		t.Errorf("%d assignment pages, want 8", pages)
	}
	if defs != 2 {
		t.Errorf("%d role definition reads, want 2 (Reader and VM Operator, cached)", defs)
	}
	if tokens != 2 {
		t.Errorf("%d token calls, want 2 (ARM and Graph, cached)", tokens)
	}
}

func TestNextLinkOffHostIsRefused(t *testing.T) {
	srv, _, c := setup(t)
	srv.Handle("GET", "/subscriptions/*", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/denyAssignments") {
			write(w, 200, map[string]any{"value": []any{}})
			return
		}
		write(w, 200, map[string]any{"value": []any{}, "nextLink": "https://evil.example.com/subscriptions/x/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"})
	})
	expect(t, check(t, c, dana, "vm.read", "subscription:"+subID), integration.CodeUpstreamError, "outside the ARM endpoint")
}

func TestScopeNotVisible(t *testing.T) {
	_, f, c := setup(t)
	f.mu.Lock()
	f.forbidden[strings.ToLower(scopeOther)] = true
	f.mu.Unlock()
	expect(t, check(t, c, dana, "vm.read", "resourcegroup:"+subID+"/other"), integration.CodeResourceNotVisible, "needs Reader")
	expect(t, check(t, c, dana, "vm.read", "subscription:44444444-4444-4444-4444-444444444444"), integration.CodeResourceNotVisible, "")
}

func TestInvalidRequests(t *testing.T) {
	_, _, c := setup(t)
	for _, tc := range [][2]string{
		{"vm.read", "subscription:not-a-guid"}, {"vm.read", "resourcegroup:" + subID}, {"vm.read", "resourcegroup:" + subID + "/bad."},
		{"vm.read", "resource:/subscriptions/" + subID + "/resourceGroups/prod"}, {"vm.read", "resource:/subscriptions/" + subID + "/resourceGroups/prod/providers/Microsoft.Compute/virtualMachines"},
		{"vm.read", "resource:/subscriptions/" + subID + "/resourceGroups/prod/providers/Compute/virtualMachines/x"},
		{"vm.read", "resource:/subscriptions/" + subID + "/resourceGroups/prod/providers/Microsoft.Compute/virtualMachines/a b"},
		{"vm.read", "subscription:" + subID + "?x=1"}, {"vm.read", "vm:x"},
		{"vm.read", "managementgroup:a/b"},
	} {
		d := check(t, c, dana, tc[0], tc[1])
		if d.Code != integration.CodeInvalidRequest {
			t.Errorf("%s %s: %s %s", tc[0], tc[1], d.Code, d.Text)
		}
	}
}

func TestRawActionShapes(t *testing.T) {
	for _, bad := range []string{"raw:virtualMachines/read", "raw:Microsoft.Compute/*/read", "raw:Microsoft.Compute", "data:Microsoft.Compute/virtualMachines/read/../x", "raw:", "data:Microsoft.Compute/vm read", "raw:Microsoft.Compute/vm?x"} {
		if _, ok := (Integration{}).MatchAction(bad); ok {
			t.Errorf("%q accepted", bad)
		}
	}
	for _, good := range []string{"raw:Microsoft.Compute/virtualMachines/read", "data:Microsoft.KeyVault/vaults/secrets/getSecret/action", "raw:microsoft.web/sites/restart/Action"} {
		if _, ok := (Integration{}).MatchAction(good); !ok {
			t.Errorf("%q rejected", good)
		}
	}
}

func TestMatchOperation(t *testing.T) {
	for _, tc := range []struct {
		pattern, op string
		want        bool
	}{
		{"*", "Microsoft.Compute/virtualMachines/delete", true},
		{"*/read", "Microsoft.Compute/virtualMachines/read", true},
		{"*/read", "Microsoft.Compute/virtualMachines/delete", false},
		{"Microsoft.Compute/*", "microsoft.compute/virtualMachines/start/action", true},
		{"Microsoft.Compute/virtualMachines/*", "Microsoft.Compute/disks/read", false},
		{"Microsoft.Authorization/*/Write", "Microsoft.Authorization/roleAssignments/write", true},
		{"Microsoft.Authorization/*/Write", "Microsoft.Authorization/roleAssignments/read", false},
		{"Microsoft.Compute/virtualMachines/read", "Microsoft.Compute/virtualMachines/read", true},
		{"Microsoft.Compute/virtualMachines/read", "Microsoft.Compute/virtualMachines/readx", false},
		{"Microsoft.*/read", "Microsoft.Compute/virtualMachines/read", true},
	} {
		if got := matchOperation(tc.pattern, tc.op); got != tc.want {
			t.Errorf("match(%q, %q) = %v", tc.pattern, tc.op, got)
		}
	}
}

func TestFailures(t *testing.T) {
	srv, _, c := setup(t)
	// Warm the tokens so the failure lands on ARM, not the token endpoint.
	check(t, c, dana, "vm.read", "subscription:"+subID)
	itest.FailureCases(t, srv, func() integration.Decision { return check(t, c, dana, "vm.read", "subscription:"+subID) })
}

func TestBadSecret(t *testing.T) {
	srv, f := newServer(t)
	deps, _ := itest.Deps(t, srv)
	s := itest.Settings("az", "azure", map[string]string{"tenant_id": tenantID, "client_id": clientID, "url": srv.URL, "graph_url": srv.URL, "authority_url": srv.URL},
		map[string]secret.Secret{"credential": secret.Literal("wrong")})
	c, err := (Integration{}).New(context.Background(), s, deps)
	if err != nil {
		t.Fatal(err)
	}
	_ = f
	expect(t, check(t, c, dana, "vm.read", "subscription:"+subID), integration.CodeCredentialRejected, "")
}

func TestNewValidation(t *testing.T) {
	srv := itest.NewServer(t)
	deps, _ := itest.Deps(t, srv)
	for _, tc := range []struct {
		values map[string]string
		secret bool
	}{
		{map[string]string{"tenant_id": tenantID, "client_id": clientID}, false},
		{map[string]string{"tenant_id": "bad tenant", "client_id": clientID}, true},
		{map[string]string{"tenant_id": tenantID, "client_id": "not-a-guid"}, true},
		{map[string]string{"tenant_id": tenantID, "client_id": clientID, "url": "ftp://x"}, true},
	} {
		secrets := map[string]secret.Secret{}
		if tc.secret {
			secrets["credential"] = secret.Literal("x")
		}
		if _, err := (Integration{}).New(context.Background(), itest.Settings("az", "azure", tc.values, secrets), deps); err == nil {
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
	if !strings.Contains(res.Summary, "4 built-in role definitions") || !strings.Contains(res.Summary, "Graph user listing works") {
		t.Errorf("summary %q", res.Summary)
	}
	itest.AssertNoCanary(t, res.Summary)
	f.mu.Lock()
	f.secret = "rotated"
	f.mu.Unlock()
	// Cached tokens still work; a fresh connection fails.
	if _, err := c.Probe(context.Background()); err != nil {
		t.Errorf("cached token: %v", err)
	}
}

func TestNoSecretInLogs(t *testing.T) {
	srv, f := newServer(t)
	deps, logs := itest.Deps(t, srv)
	s := itest.Settings("az", "azure", map[string]string{"tenant_id": tenantID, "client_id": clientID, "url": srv.URL, "graph_url": srv.URL, "authority_url": srv.URL},
		map[string]secret.Secret{"credential": secret.Literal(f.secret)})
	c, err := (Integration{}).New(context.Background(), s, deps)
	if err != nil {
		t.Fatal(err)
	}
	check(t, c, dana, "vm.read", "resource:"+scopeVM)
	check(t, c, dana, "vm.read", "subscription:44444444-4444-4444-4444-444444444444")
	itest.AssertNoCanary(t, logs.String())
}
