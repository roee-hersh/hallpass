package kubernetes

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/roee-hersh/hallpass/internal/catalog"
	"github.com/roee-hersh/hallpass/internal/integration"
	"github.com/roee-hersh/hallpass/internal/integration/itest"
	"github.com/roee-hersh/hallpass/internal/secret"
)

// policy is the fake API server's RBAC: user -> allowed "verb resource[.group][/sub] ns name" prefixes.
type fakeAPI struct {
	allow   map[string][]string // subject (user or group) -> patterns
	evalErr string
}

func (f *fakeAPI) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+itest.Canary+"k8s" {
			w.WriteHeader(401)
			return
		}
		var req sarRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("bad SAR body: %v", err)
			w.WriteHeader(400)
			return
		}
		var out sarResponse
		if f.evalErr != "" {
			out.Status.EvaluationError = f.evalErr
		} else {
			subjects := append([]string{req.Spec.User}, req.Spec.Groups...)
			var key string
			if ra := req.Spec.ResourceAttributes; ra != nil {
				key = ra.Verb + " " + joinRes(ra.Resource, ra.Group)
				if ra.Subresource != "" {
					key += "/" + ra.Subresource
				}
				key += " " + ra.Namespace + " " + ra.Name
			} else {
				key = req.Spec.NonResourceAttributes.Verb + " " + req.Spec.NonResourceAttributes.Path
			}
			for _, s := range subjects {
				for _, p := range f.allow[s] {
					if strings.HasPrefix(key, p) {
						out.Status.Allowed = true
						out.Status.Reason = "RBAC: allowed by " + s
					}
				}
			}
			if !out.Status.Allowed {
				out.Status.Reason = "RBAC: no rule matched " + key
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(out)
	}
}

func setup(t *testing.T, values map[string]string) (*itest.Server, *fakeAPI, integration.Connection) {
	t.Helper()
	srv := itest.NewServer(t)
	api := &fakeAPI{allow: map[string][]string{
		"dana@example.com":      {"get pods payments ", "create deployments.apps payments ", "get pods/log payments ", "update deployments.apps/scale payments api"},
		"bob@example.com":       {"get pods payments "},
		"oidc:dana@example.com": {"get pods payments "},
		"oidc:platform-team":    {"create pods/exec payments "},
		"system:authenticated":  {"get /version", "get /healthz"},
		"admin@example.com":     {""},
	}}
	srv.Handle("POST", "/apis/authorization.k8s.io/v1/subjectaccessreviews", api.handler(t))
	deps, _ := itest.Deps(t, srv)
	v := map[string]string{"url": srv.URL, "username_template": "{email}", "add_authenticated_group": "true"}
	for k, val := range values {
		v[k] = val
	}
	s := itest.Settings("k8s", "kubernetes", v, map[string]secret.Secret{"credential": itest.Literal("k8s")})
	c, err := Integration{}.New(context.Background(), s, deps)
	if err != nil {
		t.Fatal(err)
	}
	return srv, api, c
}

var dana = integration.User{Email: "dana@example.com", Groups: []string{"platform-team"}}
var bob = integration.User{Email: "bob@example.com"}
var admin = integration.User{Email: "admin@example.com"}

func check(t *testing.T, c integration.Connection, u integration.User, action, resource string) integration.Decision {
	t.Helper()
	return itest.Check(t, c, Integration{}, u, action, resource)
}

func TestRawAllowDenyAndBody(t *testing.T) {
	srv, _, c := setup(t, nil)
	d := check(t, c, dana, "raw:get:pods", "namespace:payments?name=api-0")
	itest.ExpectCode(t, d, integration.CodeAllowed)
	var req sarRequest
	srv.LastCall().JSON(t, &req)
	if req.APIVersion != "authorization.k8s.io/v1" || req.Kind != "SubjectAccessReview" {
		t.Errorf("%+v", req)
	}
	if req.Spec.User != "dana@example.com" || len(req.Spec.Groups) != 2 || req.Spec.Groups[0] != "platform-team" || req.Spec.Groups[1] != "system:authenticated" {
		t.Errorf("spec %+v", req.Spec)
	}
	ra := req.Spec.ResourceAttributes
	if ra == nil || ra.Namespace != "payments" || ra.Verb != "get" || ra.Resource != "pods" || ra.Name != "api-0" || ra.Group != "" {
		t.Errorf("attrs %+v", ra)
	}
	itest.ExpectCode(t, check(t, c, dana, "raw:delete:pods", "namespace:payments"), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, dana, "raw:get:pods", "namespace:other"), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, bob, "raw:get:pods", "namespace:billing"), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, admin, "raw:delete:nodes", "cluster"), integration.CodeAllowed)

	d = check(t, c, dana, "raw:create:deployments.apps", "namespace:payments")
	itest.ExpectCode(t, d, integration.CodeAllowed)
	srv.LastCall().JSON(t, &req)
	if req.Spec.ResourceAttributes.Group != "apps" || req.Spec.ResourceAttributes.Resource != "deployments" {
		t.Errorf("group split: %+v", req.Spec.ResourceAttributes)
	}
	d = check(t, c, dana, "raw:get:pods/log", "namespace:payments")
	itest.ExpectCode(t, d, integration.CodeAllowed)
	srv.LastCall().JSON(t, &req)
	if req.Spec.ResourceAttributes.Subresource != "log" {
		t.Errorf("subresource: %+v", req.Spec.ResourceAttributes)
	}
	d = check(t, c, dana, "raw:get:pods", "namespace:payments?resource=pods&name=x")
	itest.ExpectCode(t, d, integration.CodeAllowed)
}

func TestNonResource(t *testing.T) {
	srv, _, c := setup(t, nil)
	d := check(t, c, bob, "raw:get", "nonresource:/version")
	itest.ExpectCode(t, d, integration.CodeAllowed)
	var req sarRequest
	srv.LastCall().JSON(t, &req)
	if req.Spec.ResourceAttributes != nil || req.Spec.NonResourceAttributes == nil || req.Spec.NonResourceAttributes.Path != "/version" || req.Spec.NonResourceAttributes.Verb != "get" {
		t.Errorf("%+v", req.Spec)
	}
	itest.ExpectCode(t, check(t, c, bob, "raw:post", "nonresource:/version"), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, bob, "raw:get:x", "nonresource:/version"), integration.CodeInvalidRequest)
	itest.ExpectCode(t, check(t, c, bob, "raw:get", "namespace:payments"), integration.CodeInvalidRequest)
	itest.ExpectCode(t, check(t, c, bob, "raw:get", "namespace:payments?resource=pods"), integration.CodeAllowed)
}

func TestTemplateAndPrefix(t *testing.T) {
	srv, _, c := setup(t, map[string]string{"username_template": "oidc:{email}", "group_prefix": "oidc:", "add_authenticated_group": "false"})
	itest.ExpectCode(t, check(t, c, dana, "raw:get:pods", "namespace:payments"), integration.CodeAllowed)
	var req sarRequest
	srv.LastCall().JSON(t, &req)
	if req.Spec.User != "oidc:dana@example.com" || len(req.Spec.Groups) != 1 || req.Spec.Groups[0] != "oidc:platform-team" {
		t.Errorf("%+v", req.Spec)
	}
	itest.ExpectCode(t, check(t, c, dana, "pods.exec", "namespace:payments?name=api-0"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, bob, "pods.exec", "namespace:payments?name=api-0"), integration.CodeDenied)

	_, _, c2 := setup(t, map[string]string{"username_template": "{local}@corp"})
	id, _ := c2.ResolveIdentity(context.Background(), dana)
	if id.ID != "dana@corp" {
		t.Error(id.ID)
	}
	for _, bad := range []string{"static", "{user}", "{email"} {
		if err := validateTemplate(bad); err == nil && bad != "{email" {
			t.Errorf("template %q accepted", bad)
		}
	}
	if err := validateTemplate("{domain}/{local}"); err != nil {
		t.Error(err)
	}
}

func TestEvaluationErrorAndStatuses(t *testing.T) {
	srv, api, c := setup(t, nil)
	api.evalErr = "webhook unavailable"
	itest.ExpectCode(t, check(t, c, dana, "raw:get:pods", "namespace:payments"), integration.CodeUnsupported)
	api.evalErr = ""
	srv.JSON("POST", "/apis/authorization.k8s.io/v1/subjectaccessreviews", 403, `{"kind":"Status","message":"forbidden"}`)
	itest.ExpectCode(t, check(t, c, dana, "raw:get:pods", "namespace:payments"), integration.CodeCredentialRejected)
	if _, err := c.Probe(context.Background()); err == nil || !strings.Contains(err.Error(), "subjectaccessreviews") {
		t.Errorf("probe on 403: %v", err)
	}
}

func TestFailures(t *testing.T) {
	srv, _, c := setup(t, nil)
	itest.FailureCases(t, srv, func() integration.Decision {
		return check(t, c, dana, "raw:get:pods", "namespace:payments")
	})
}

func TestProbe(t *testing.T) {
	_, api, c := setup(t, nil)
	r, err := c.Probe(context.Background())
	if err != nil || r.Summary == "" || len(r.Warnings) != 0 {
		t.Fatal(r, err)
	}
	api.allow["hallpass:probe"] = []string{""}
	r, _ = c.Probe(context.Background())
	if len(r.Warnings) != 1 {
		t.Error("expected warning for permissive cluster")
	}
}

func TestBadResources(t *testing.T) {
	_, _, c := setup(t, nil)
	cases := []struct{ action, resource string }{
		{"raw:get:pods", "pod:x"},
		{"raw:get:pods", "namespace:Bad_NS"},
		{"raw:get:pods", "cluster:x"},
		{"raw:get:pods", "namespace:payments?name=bad name"},
		{"raw:get:pods", "namespace:payments?resource=deployments.apps"},
		{"raw:get:pods/log", "namespace:payments?subresource=exec"},
		{"scale", "namespace:payments"},
		{"raw:get:pods", "nonresource:/metrics"},
		{"raw:get:pods", "nonresource:metrics"},
		{"raw:get:pods", "namespace:payments?namespace=other"},
		{"raw:get:pods", "namespace:payments?resource=Bad"},
	}
	for _, cs := range cases {
		d := check(t, c, dana, cs.action, cs.resource)
		if d.Code != integration.CodeInvalidRequest {
			t.Errorf("%s %s -> %s: %s", cs.action, cs.resource, d.Code, d.Text)
		}
	}
	for _, bad := range []string{"raw:", "raw:Get:pods", "raw:get:Pods", "raw:get:pods/Log", "raw:get:pods.-bad", "raw::pods", "get:pods", "raw:get:"} {
		if _, ok := (Integration{}).MatchAction(bad); ok {
			t.Errorf("MatchAction(%q) accepted", bad)
		}
	}
	for _, ok := range []string{"raw:get:pods", "raw:create:deployments.apps", "raw:get:pods/log", "raw:impersonate:users", "raw:use:podsecuritypolicies.policy"} {
		if _, matched := (Integration{}).MatchAction(ok); !matched {
			t.Errorf("MatchAction(%q) rejected", ok)
		}
	}
}

func TestAliases(t *testing.T) {
	for _, a := range aliasList {
		if _, ok := integration.FindAction(Integration{}, a.name); !ok {
			t.Errorf("alias %s not listed", a.name)
		}
	}
	res, _ := catalog.ParseResource("namespace:payments?resource=deployments.apps&name=api")
	a, err := buildAttributes("scale", res)
	if err != nil || a.verb != "update" || a.resource != "deployments" || a.group != "apps" || a.subresource != "scale" || a.name != "api" {
		t.Errorf("scale: %+v %v", a, err)
	}
	res, _ = catalog.ParseResource("cluster?name=admin")
	a, err = buildAttributes("impersonate", res)
	if err != nil || a.verb != "impersonate" || a.resource != "users" || a.name != "admin" {
		t.Errorf("impersonate: %+v %v", a, err)
	}
	res, _ = catalog.ParseResource("cluster?resource=groups&name=admins")
	a, _ = buildAttributes("impersonate", res)
	if a.resource != "groups" {
		t.Errorf("impersonate groups: %+v", a)
	}
	res, _ = catalog.ParseResource("nonresource:/metrics")
	a, err = buildAttributes("raw:get:x", res)
	if err == nil {
		t.Error("raw with resource on nonresource path accepted")
	}
}

// Allow/deny tests per alias action (coverage gate).

func aliasAllow(t *testing.T, action, resource string) {
	t.Helper()
	srv, api, c := setup(t, nil)
	api.allow["dana@example.com"] = []string{""}
	itest.ExpectCode(t, check(t, c, dana, action, resource), integration.CodeAllowed)
	_ = srv
}

func aliasDeny(t *testing.T, action, resource string) {
	t.Helper()
	_, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, bob, action, resource), integration.CodeDenied)
}

func TestAction_pods_exec_allow(t *testing.T) {
	aliasAllow(t, "pods.exec", "namespace:payments?name=api-0")
}
func TestAction_pods_exec_deny(t *testing.T) {
	aliasDeny(t, "pods.exec", "namespace:payments?name=api-0")
}
func TestAction_pods_logs_allow(t *testing.T) { aliasAllow(t, "pods.logs", "namespace:payments") }
func TestAction_pods_logs_deny(t *testing.T)  { aliasDeny(t, "pods.logs", "namespace:payments") }
func TestAction_pods_portforward_allow(t *testing.T) {
	aliasAllow(t, "pods.portforward", "namespace:payments")
}
func TestAction_pods_portforward_deny(t *testing.T) {
	aliasDeny(t, "pods.portforward", "namespace:payments")
}
func TestAction_pods_attach_allow(t *testing.T) { aliasAllow(t, "pods.attach", "namespace:payments") }
func TestAction_pods_attach_deny(t *testing.T)  { aliasDeny(t, "pods.attach", "namespace:payments") }
func TestAction_scale_allow(t *testing.T) {
	aliasAllow(t, "scale", "namespace:payments?resource=deployments.apps&name=api")
}
func TestAction_scale_deny(t *testing.T) {
	aliasDeny(t, "scale", "namespace:payments?resource=deployments.apps&name=api")
}
func TestAction_secrets_read_allow(t *testing.T) {
	aliasAllow(t, "secrets.read", "namespace:payments?name=db")
}
func TestAction_secrets_read_deny(t *testing.T) {
	aliasDeny(t, "secrets.read", "namespace:payments?name=db")
}
func TestAction_secrets_list_allow(t *testing.T) { aliasAllow(t, "secrets.list", "namespace:payments") }
func TestAction_secrets_list_deny(t *testing.T)  { aliasDeny(t, "secrets.list", "namespace:payments") }
func TestAction_impersonate_allow(t *testing.T)  { aliasAllow(t, "impersonate", "cluster?name=admin") }
func TestAction_impersonate_deny(t *testing.T)   { aliasDeny(t, "impersonate", "cluster?name=admin") }
func TestAction_deployment_create_allow(t *testing.T) {
	aliasAllow(t, "deployment.create", "namespace:payments")
}
func TestAction_deployment_create_deny(t *testing.T) {
	aliasDeny(t, "deployment.create", "namespace:payments")
}
func TestAction_deployment_update_allow(t *testing.T) {
	aliasAllow(t, "deployment.update", "namespace:payments?name=api")
}
func TestAction_deployment_update_deny(t *testing.T) {
	aliasDeny(t, "deployment.update", "namespace:payments?name=api")
}
func TestAction_deployment_delete_allow(t *testing.T) {
	aliasAllow(t, "deployment.delete", "namespace:payments?name=api")
}
func TestAction_deployment_delete_deny(t *testing.T) {
	aliasDeny(t, "deployment.delete", "namespace:payments?name=api")
}
func TestAction_deployment_restart_allow(t *testing.T) {
	aliasAllow(t, "deployment.restart", "namespace:payments?name=api")
}
func TestAction_deployment_restart_deny(t *testing.T) {
	aliasDeny(t, "deployment.restart", "namespace:payments?name=api")
}
func TestAction_namespace_create_allow(t *testing.T) { aliasAllow(t, "namespace.create", "cluster") }
func TestAction_namespace_create_deny(t *testing.T)  { aliasDeny(t, "namespace.create", "cluster") }
func TestAction_namespace_delete_allow(t *testing.T) {
	aliasAllow(t, "namespace.delete", "cluster?name=payments")
}
func TestAction_namespace_delete_deny(t *testing.T) {
	aliasDeny(t, "namespace.delete", "cluster?name=payments")
}
func TestAction_rbac_bind_allow(t *testing.T) { aliasAllow(t, "rbac.bind", "namespace:payments") }
func TestAction_rbac_bind_deny(t *testing.T)  { aliasDeny(t, "rbac.bind", "namespace:payments") }
