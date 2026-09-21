package kubernetes

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/roee-hersh/hallpass/internal/catalog"
)

// alias is a named action that expands to a verb and resource.
// An empty resource means "take resource/group from the request".
type alias struct {
	name, desc  string
	verb        string
	resource    string
	group       string
	subresource string
}

var aliasList = []alias{
	{name: "pods.exec", desc: "run a command in a pod (create pods/exec)", verb: "create", resource: "pods", subresource: "exec"},
	{name: "pods.logs", desc: "read pod logs (get pods/log)", verb: "get", resource: "pods", subresource: "log"},
	{name: "pods.portforward", desc: "port-forward to a pod (create pods/portforward)", verb: "create", resource: "pods", subresource: "portforward"},
	{name: "pods.attach", desc: "attach to a pod (create pods/attach)", verb: "create", resource: "pods", subresource: "attach"},
	{name: "scale", desc: "scale the resource named in the request (update <resource>/scale)", verb: "update", subresource: "scale"},
	{name: "secrets.read", desc: "read a secret (get secrets)", verb: "get", resource: "secrets"},
	{name: "secrets.list", desc: "list secrets (list secrets)", verb: "list", resource: "secrets"},
	{name: "impersonate", desc: "impersonate the subject named in the request, default users (impersonate <resource>)", verb: "impersonate"},
	{name: "deployment.create", desc: "create a deployment (create deployments.apps)", verb: "create", resource: "deployments", group: "apps"},
	{name: "deployment.update", desc: "update a deployment (update deployments.apps)", verb: "update", resource: "deployments", group: "apps"},
	{name: "deployment.delete", desc: "delete a deployment (delete deployments.apps)", verb: "delete", resource: "deployments", group: "apps"},
	{name: "deployment.restart", desc: "restart a deployment (patch deployments.apps)", verb: "patch", resource: "deployments", group: "apps"},
	{name: "namespace.create", desc: "create a namespace (create namespaces)", verb: "create", resource: "namespaces"},
	{name: "namespace.delete", desc: "delete a namespace (delete namespaces)", verb: "delete", resource: "namespaces"},
	{name: "rbac.bind", desc: "bind a role (create rolebindings.rbac.authorization.k8s.io)", verb: "create", resource: "rolebindings", group: "rbac.authorization.k8s.io"},
}

var aliases = func() map[string]alias {
	m := map[string]alias{}
	for _, a := range aliasList {
		m[a.name] = a
	}
	return m
}()

var (
	verbRe      = regexp.MustCompile(`^[a-z]{1,32}$`)
	resourceRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	groupRe     = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)
	nameRe      = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._:-]{0,252}[A-Za-z0-9])?$`)
	namespaceRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	pathRe      = regexp.MustCompile(`^/[A-Za-z0-9/._~*-]{0,1000}$`)
)

// rawSpec is a parsed raw:<verb>:<resource>[.<group>][/<subresource>] action.
type rawSpec struct {
	verb, resource, group, subresource string
}

// parseRaw accepts raw:<verb>:<resource>... and, for non-resource paths,
// the verb-only form raw:<verb>.
func parseRaw(name string) (rawSpec, error) {
	parts := strings.SplitN(name, ":", 3)
	if len(parts) < 2 || parts[0] != "raw" {
		return rawSpec{}, errors.New("raw action must be raw:<verb>:<resource>[.<group>][/<subresource>] or raw:<verb> for non-resource paths")
	}
	verb := parts[1]
	if !verbRe.MatchString(verb) {
		return rawSpec{}, fmt.Errorf("verb %q must be lowercase letters", verb)
	}
	if len(parts) == 2 {
		return rawSpec{verb: verb}, nil
	}
	res, group, sub, err := splitResource(parts[2])
	if err != nil {
		return rawSpec{}, err
	}
	return rawSpec{verb: verb, resource: res, group: group, subresource: sub}, nil
}

// splitResource parses "deployments.apps/scale" into resource, group and
// subresource. The group is everything after the first dot, as kubectl does.
func splitResource(s string) (resource, group, subresource string, err error) {
	if s == "" {
		return "", "", "", errors.New("resource is empty")
	}
	res, sub, _ := strings.Cut(s, "/")
	res, group, _ = strings.Cut(res, ".")
	if !resourceRe.MatchString(res) {
		return "", "", "", fmt.Errorf("resource %q must be a lowercase plural such as pods or deployments", res)
	}
	if group != "" && !groupRe.MatchString(group) {
		return "", "", "", fmt.Errorf("API group %q is not a valid group name", group)
	}
	if sub != "" && !resourceRe.MatchString(sub) {
		return "", "", "", fmt.Errorf("subresource %q is not valid", sub)
	}
	return res, group, sub, nil
}

// buildAttributes combines the action and the resource reference.
//
//	namespace:<ns>[?resource=<res>[.<group>]&name=<n>&subresource=<s>]
//	cluster[?resource=<res>[.<group>]&name=<n>&subresource=<s>]
//	nonresource:<path>
func buildAttributes(actionName string, res catalog.Resource) (attributes, error) {
	var a attributes
	var actRes, actGroup, actSub string
	if strings.HasPrefix(actionName, "raw:") {
		spec, err := parseRaw(actionName)
		if err != nil {
			return a, err
		}
		a.verb, actRes, actGroup, actSub = spec.verb, spec.resource, spec.group, spec.subresource
	} else {
		al, ok := aliases[actionName]
		if !ok {
			return a, fmt.Errorf("unknown action %q", actionName)
		}
		a.verb, actRes, actGroup, actSub = al.verb, al.resource, al.group, al.subresource
	}

	switch res.Type {
	case "nonresource":
		if !pathRe.MatchString(res.ID) {
			return a, fmt.Errorf("nonresource path %q must start with / and contain only URL path characters", res.ID)
		}
		if actRes != "" {
			return a, fmt.Errorf("action %s names a resource but the request is a non-resource path; use raw:<verb>", actionName)
		}
		a.nonResourcePath = res.ID
		return a, nil
	case "namespace":
		if !namespaceRe.MatchString(res.ID) {
			return a, fmt.Errorf("namespace %q is not a valid namespace name", res.ID)
		}
		a.namespace = res.ID
	case "cluster":
		if res.ID != "" {
			return a, errors.New("cluster resources take no id: use cluster?resource=nodes")
		}
	default:
		return a, fmt.Errorf("resource type %q; use namespace:<ns>, cluster or nonresource:<path>", res.Type)
	}

	reqRes, reqGroup, reqSub := "", "", ""
	if q := res.Q("resource"); q != "" {
		var err error
		reqRes, reqGroup, reqSub, err = splitResource(q)
		if err != nil {
			return a, err
		}
	}
	if s := res.Q("subresource"); s != "" {
		if !resourceRe.MatchString(s) {
			return a, fmt.Errorf("subresource %q is not valid", s)
		}
		reqSub = s
	}
	if n := res.Q("name"); n != "" {
		if !nameRe.MatchString(n) {
			return a, fmt.Errorf("name %q is not a valid object name", n)
		}
		a.name = n
	}
	if ns := res.Q("namespace"); ns != "" {
		return a, errors.New("put the namespace in the resource id: namespace:<ns>")
	}

	switch {
	case actRes != "" && reqRes != "" && (actRes != reqRes || actGroup != reqGroup):
		return a, fmt.Errorf("action %s targets %s but the request names %s", actionName, joinRes(actRes, actGroup), joinRes(reqRes, reqGroup))
	case actRes != "":
		a.resource, a.group = actRes, actGroup
	case reqRes != "":
		a.resource, a.group = reqRes, reqGroup
	case actionName == "impersonate":
		a.resource = "users"
	case strings.HasPrefix(actionName, "raw:") && !strings.Contains(actionName[4:], ":"):
		return a, fmt.Errorf("action %s is the non-resource form; use it with nonresource:<path>, or add ?resource=<plural>[.<group>] to the request", actionName)
	default:
		return a, fmt.Errorf("action %s needs a resource: add ?resource=<plural>[.<group>] to the request", actionName)
	}
	switch {
	case actSub != "" && reqSub != "" && actSub != reqSub:
		return a, fmt.Errorf("action %s targets subresource %s but the request names %s", actionName, actSub, reqSub)
	case actSub != "":
		a.subresource = actSub
	default:
		a.subresource = reqSub
	}
	return a, nil
}

func joinRes(res, group string) string {
	if group == "" {
		return res
	}
	return res + "." + group
}
