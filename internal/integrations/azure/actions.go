package azure

import (
	"regexp"
	"strings"

	"github.com/roee-hersh/hallpass/internal/catalog"
	"github.com/roee-hersh/hallpass/internal/httpx"
	"github.com/roee-hersh/hallpass/internal/integration"
)

// action is one named question: an Azure operation on the control plane
// (actions) or the data plane (dataActions).
type action struct {
	name, desc, operation string
	data                  bool
}

var actionList = []action{
	{"vm.read", "read the virtual machine", "Microsoft.Compute/virtualMachines/read", false},
	{"vm.start", "start the virtual machine", "Microsoft.Compute/virtualMachines/start/action", false},
	{"vm.restart", "restart the virtual machine", "Microsoft.Compute/virtualMachines/restart/action", false},
	{"vm.deallocate", "deallocate (stop) the virtual machine", "Microsoft.Compute/virtualMachines/deallocate/action", false},
	{"vm.delete", "delete the virtual machine", "Microsoft.Compute/virtualMachines/delete", false},
	{"storage.listkeys", "list the storage account's access keys", "Microsoft.Storage/storageAccounts/listkeys/action", false},
	{"storage.blob.read", "read blobs (data plane)", "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read", true},
	{"storage.blob.write", "write blobs (data plane)", "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write", true},
	{"keyvault.secret.read", "read a Key Vault secret's value (data plane, RBAC permission model)", "Microsoft.KeyVault/vaults/secrets/getSecret/action", true},
	{"keyvault.secret.write", "set a Key Vault secret (data plane, RBAC permission model)", "Microsoft.KeyVault/vaults/secrets/setSecret/action", true},
	{"aks.admin_credentials", "fetch the AKS cluster admin credential", "Microsoft.ContainerService/managedClusters/listClusterAdminCredential/action", false},
	{"aks.user_credentials", "fetch the AKS cluster user credential", "Microsoft.ContainerService/managedClusters/listClusterUserCredential/action", false},
	{"rbac.write", "create or change role assignments", "Microsoft.Authorization/roleAssignments/write", false},
	{"resourcegroup.delete", "delete the resource group", "Microsoft.Resources/subscriptions/resourceGroups/delete", false},
	{"deployment.write", "create or change an ARM deployment", "Microsoft.Resources/deployments/write", false},
}

var actions = func() map[string]action {
	m := map[string]action{}
	for _, a := range actionList {
		m[a.name] = a
	}
	return m
}()

const (
	rawPattern  = "raw:<operation>"
	dataPattern = "data:<operation>"
)

// Actions of the azure integration.
func (Integration) Actions() []catalog.Action {
	out := make([]catalog.Action, 0, len(actionList)+2)
	for _, a := range actionList {
		desc := a.desc + " (" + a.operation + ")"
		out = append(out, catalog.Action{Name: a.name, Description: desc})
	}
	out = append(out,
		catalog.Action{Name: rawPattern, Pattern: true, Description: "any control-plane operation, e.g. raw:Microsoft.Network/publicIPAddresses/delete"},
		catalog.Action{Name: dataPattern, Pattern: true, Description: "any data-plane operation, e.g. data:Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete"},
	)
	return out
}

// operationRe is a resource provider operation: a namespace, then
// resource types and a verb. Wildcards are for role definitions only.
var operationRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*(\.[A-Za-z0-9]+)+(/[A-Za-z0-9][A-Za-z0-9_.-]*)+$`)

// parseRaw parses raw:<operation> and data:<operation>.
func parseRaw(name string) (action, bool) {
	for _, prefix := range []string{"raw:", "data:"} {
		op, ok := strings.CutPrefix(name, prefix)
		if !ok {
			continue
		}
		if !operationRe.MatchString(op) || len(op) > 256 {
			return action{}, false
		}
		return action{name: name, desc: "perform " + op, operation: op, data: prefix == "data:"}, true
	}
	return action{}, false
}

// MatchAction accepts raw:<operation> and data:<operation>.
func (Integration) MatchAction(name string) (catalog.Action, bool) {
	a, ok := parseRaw(name)
	if !ok {
		return catalog.Action{}, false
	}
	pattern := rawPattern
	if a.data {
		pattern = dataPattern
	}
	return catalog.Action{Name: pattern, Pattern: true, Description: a.desc}, true
}

var (
	guidRe    = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	rgRe      = regexp.MustCompile(`^[-\w.()]{1,90}$`)
	mgRe      = regexp.MustCompile(`^[A-Za-z0-9_().-]{1,90}$`)
	nsRe      = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*(\.[A-Za-z0-9]+)+$`)
	segmentRe = regexp.MustCompile(`^[A-Za-z0-9_.()-]{1,260}$`)
)

func invalid(format string, args ...any) error {
	return integration.Errorf(integration.CodeInvalidRequest, format, args...)
}

// target is a parsed question.
type target struct {
	action action
	// scope is the ARM scope, leading slash included, each segment
	// path-escaped: /subscriptions/<id>/resourceGroups/<rg>/providers/...
	scope string
	// kind is managementgroup, subscription, resourcegroup or resource.
	kind string
}

// parseTarget validates the action and builds the scope from the resource.
func parseTarget(actionName string, r catalog.Resource) (target, error) {
	a, ok := actions[actionName]
	if !ok {
		if a, ok = parseRaw(actionName); !ok {
			return target{}, invalid("unknown action %q", actionName)
		}
	}
	if len(r.Query) > 0 {
		return target{}, invalid("resource %q must not carry a query", r.Raw)
	}
	id := strings.TrimSpace(r.ID)
	t := target{action: a, kind: r.Type}
	switch r.Type {
	case "managementgroup":
		if !mgRe.MatchString(id) {
			return target{}, invalid("managementgroup: takes the group's name or id")
		}
		t.scope = "/providers/Microsoft.Management/managementGroups/" + httpx.PathEscape(id)
	case "subscription":
		if !guidRe.MatchString(id) {
			return target{}, invalid("subscription: takes the subscription id (a GUID)")
		}
		t.scope = "/subscriptions/" + strings.ToLower(id)
	case "resourcegroup":
		sub, rg, ok := strings.Cut(id, "/")
		if !ok || !guidRe.MatchString(sub) || !rgRe.MatchString(rg) || strings.HasSuffix(rg, ".") {
			return target{}, invalid("resourcegroup: takes <subscription id>/<resource group name>")
		}
		t.scope = "/subscriptions/" + strings.ToLower(sub) + "/resourceGroups/" + httpx.PathEscape(rg)
	case "resource":
		scope, err := parseResourceID(id)
		if err != nil {
			return target{}, err
		}
		t.scope = scope
	default:
		return target{}, invalid("resource type %q is not managementgroup:, subscription:, resourcegroup: or resource:", r.Type)
	}
	return t, nil
}

// parseResourceID validates a full ARM resource id:
// /subscriptions/<id>/resourceGroups/<rg>/providers/<ns>/<type>/<name>[/<type>/<name>...]
func parseResourceID(id string) (string, error) {
	segs := strings.Split(strings.TrimPrefix(id, "/"), "/")
	if len(segs) < 7 || !strings.EqualFold(segs[0], "subscriptions") || !guidRe.MatchString(segs[1]) ||
		!strings.EqualFold(segs[2], "resourceGroups") || !rgRe.MatchString(segs[3]) || strings.HasSuffix(segs[3], ".") ||
		!strings.EqualFold(segs[4], "providers") || !nsRe.MatchString(segs[5]) {
		return "", invalid("resource: takes a full ARM id /subscriptions/<id>/resourceGroups/<rg>/providers/<namespace>/<type>/<name>")
	}
	rest := segs[6:]
	if len(rest)%2 != 0 {
		return "", invalid("resource: the id must end in <type>/<name> pairs")
	}
	out := []string{"subscriptions", strings.ToLower(segs[1]), "resourceGroups", httpx.PathEscape(segs[3]), "providers", segs[5]}
	for _, seg := range rest {
		if !segmentRe.MatchString(seg) {
			return "", invalid("resource: segment %q is not a resource type or name", seg)
		}
		out = append(out, httpx.PathEscape(seg))
	}
	return "/" + strings.Join(out, "/"), nil
}

// String names the target for decision texts.
func (t target) String() string {
	return t.kind + " " + t.scope
}
