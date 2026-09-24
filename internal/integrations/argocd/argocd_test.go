package argocd

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/roee-hersh/hallpass/internal/cache"
	"github.com/roee-hersh/hallpass/internal/evidence"
	"github.com/roee-hersh/hallpass/internal/integration"
	"github.com/roee-hersh/hallpass/internal/integration/itest"
	"github.com/roee-hersh/hallpass/internal/integrations/kubernetes"
	"github.com/roee-hersh/hallpass/internal/secret"
)

// cluster is the fake API server state.
type cluster struct {
	rbacCM   map[string]string // nil = 404
	argocdCM map[string]string // nil = 404
	projects []map[string]any
	reads    int
}

func (c *cluster) install(srv *itest.Server, t *testing.T) {
	cm := func(data map[string]string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			c.reads++
			if r.Header.Get("Authorization") != "Bearer "+itest.Canary+"k8s" {
				w.WriteHeader(401)
				return
			}
			if data == nil {
				w.WriteHeader(404)
				w.Write([]byte(`{"kind":"Status","code":404}`))
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"data": data})
		}
	}
	srv.Handle("GET", "/api/v1/namespaces/argocd/configmaps/argocd-rbac-cm", func(w http.ResponseWriter, r *http.Request) { cm(c.rbacCM)(w, r) })
	srv.Handle("GET", "/api/v1/namespaces/argocd/configmaps/argocd-cm", func(w http.ResponseWriter, r *http.Request) { cm(c.argocdCM)(w, r) })
	srv.Handle("GET", "/apis/argoproj.io/v1alpha1/namespaces/argocd/appprojects", func(w http.ResponseWriter, r *http.Request) {
		c.reads++
		json.NewEncoder(w).Encode(map[string]any{"items": c.projects})
	})
}

func project(name string, roles ...map[string]any) map[string]any {
	return map[string]any{"metadata": map[string]any{"name": name}, "spec": map[string]any{"roles": roles}}
}

func setup(t *testing.T, cl *cluster, userSubject string) (*itest.Server, integration.Connection, *time.Time) {
	t.Helper()
	srv := itest.NewServer(t)
	cl.install(srv, t)
	deps, _ := itest.Deps(t, srv)
	now := time.Now()
	deps.Now = func() time.Time { return now }
	ks := itest.Settings("k8s", "kubernetes", map[string]string{"url": srv.URL, "username_template": "{email}", "add_authenticated_group": "true"},
		map[string]secret.Secret{"credential": itest.Literal("k8s")})
	kc, err := kubernetes.Integration{}.New(context.Background(), ks, deps)
	if err != nil {
		t.Fatal(err)
	}
	deps.Connection = func(id string) (integration.Connection, error) { return kc, nil }
	s := itest.Settings("argo", "argocd", map[string]string{"kubernetes_connection": "k8s", "namespace": "argocd", "rbac_configmap": "argocd-rbac-cm", "user_subject": userSubject}, nil)
	c, err := Integration{}.New(context.Background(), s, deps)
	if err != nil {
		t.Fatal(err)
	}
	return srv, c, &now
}

func check(t *testing.T, c integration.Connection, u integration.User, action, resource string) integration.Decision {
	t.Helper()
	return itest.Check(t, c, Integration{}, u, action, resource)
}

const policy = `
p, role:dev, applications, get, dev/*, allow
p, role:dev, applications, sync, dev/*, allow
p, role:dev, logs, get, dev/*, allow
p, role:ops, applications, get, */*, allow
p, role:ops, applications, create, */*, allow
p, role:ops, applications, update, */*, allow
p, role:ops, applications, delete, */*, allow
p, role:ops, applications, sync, */*, allow
p, role:ops, applications, override, */*, allow
p, role:ops, applications, delete, prod/*, deny
p, role:ops, clusters, get, *, allow
p, role:ops, projects, get, *, allow
p, role:ops, applications, action/apps/Deployment/*, */*, allow
p, role:ops, applications, update/apps/Deployment/*, */*, allow
g, developers, role:dev
g, sre, role:ops
g, dana@example.com, role:ops
`

func defaultCluster() *cluster {
	return &cluster{
		rbacCM:   map[string]string{"policy.csv": policy, "policy.default": "", "scopes": "[groups, email]"},
		argocdCM: map[string]string{},
		projects: []map[string]any{
			project("dev"), project("prod"),
			project("team-a", map[string]any{
				"name":     "deployer",
				"policies": []string{"p, proj:team-a:deployer, applications, sync, team-a/*, allow"},
				"groups":   []string{"team-a-devs"},
			}),
		},
	}
}

var (
	dev   = integration.User{Email: "dev@example.com", Groups: []string{"developers"}}
	sre   = integration.User{Email: "sre@example.com", Groups: []string{"sre"}}
	dana  = integration.User{Email: "dana@example.com"}
	none  = integration.User{Email: "nobody@example.com"}
	teamA = integration.User{Email: "a@example.com", Groups: []string{"team-a-devs"}}
)

func TestGroupsAndRoles(t *testing.T) {
	_, c, _ := setup(t, defaultCluster(), "none")
	itest.ExpectCode(t, check(t, c, dev, "app.get", "applications:dev/web"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, dev, "app.sync", "applications:dev/web"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, dev, "logs.get", "applications:dev/web"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, dev, "logs.get", "logs:dev/web"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, dev, "app.delete", "applications:dev/web"), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, dev, "app.get", "applications:prod/web"), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, sre, "app.delete", "applications:dev/web"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, sre, "app.delete", "applications:prod/web"), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, sre, "cluster.get", "clusters:https://kubernetes.default.svc"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, none, "app.get", "applications:dev/web"), integration.CodeDenied)
}

func TestEmailAsGroupAndSubject(t *testing.T) {
	// scopes include email, so the email is a group value even with user_subject none.
	_, c, _ := setup(t, defaultCluster(), "none")
	itest.ExpectCode(t, check(t, c, dana, "app.sync", "applications:prod/web"), integration.CodeAllowed)

	cl := defaultCluster()
	cl.rbacCM["policy.csv"] = policy + "\np, dana@example.com, projects, update, dev, allow\n"
	cl.rbacCM["scopes"] = "[groups]"
	_, c, _ = setup(t, cl, "email")
	itest.ExpectCode(t, check(t, c, dana, "project.update", "projects:dev"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, dana, "app.sync", "applications:prod/web"), integration.CodeAllowed) // via g dana -> role:ops
	itest.ExpectCode(t, check(t, c, none, "app.get", "applications:dev/web"), integration.CodeDenied)    // subject known: real deny
	_, c, _ = setup(t, cl, "none")
	// without the email scope and user_subject none, dana's user-level rules are invisible: unknown, not deny
	itest.ExpectCode(t, check(t, c, dana, "project.update", "projects:dev"), integration.CodeUnsupported)
}

func TestProjectRoles(t *testing.T) {
	_, c, _ := setup(t, defaultCluster(), "none")
	itest.ExpectCode(t, check(t, c, teamA, "app.sync", "applications:team-a/api"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, teamA, "project.get", "projects:team-a"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, teamA, "app.sync", "applications:dev/api"), integration.CodeDenied)
	// The group is only bound inside team-a: for another project the g line is absent.
	cl := defaultCluster()
	cl.rbacCM["policy.csv"] = "p, role:x, applications, get, */*, allow\ng, some-group, role:x"
	_, c, _ = setup(t, cl, "none")
	itest.ExpectCode(t, check(t, c, teamA, "app.sync", "applications:dev/api"), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, teamA, "app.sync", "applications:team-a/api"), integration.CodeAllowed)
}

func TestDefaultRoleAndBuiltin(t *testing.T) {
	cl := defaultCluster()
	cl.rbacCM["policy.default"] = "role:readonly"
	_, c, _ := setup(t, cl, "none")
	itest.ExpectCode(t, check(t, c, none, "app.get", "applications:prod/web"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, none, "app.sync", "applications:prod/web"), integration.CodeDenied)
	cl = defaultCluster()
	cl.rbacCM["policy.csv"] = "g, admins, role:admin"
	_, c, _ = setup(t, cl, "none")
	admin := integration.User{Email: "x@example.com", Groups: []string{"admins"}}
	itest.ExpectCode(t, check(t, c, admin, "app.delete", "applications:prod/web"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, admin, "app.rollback", "applications:prod/web"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, admin, "exec.create", "applications:prod/web"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, admin, "extension.invoke", "extensions:metrics"), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, none, "app.get", "applications:prod/web"), integration.CodeDenied)
}

func TestNoRBACConfigMap(t *testing.T) {
	cl := &cluster{}
	_, c, _ := setup(t, cl, "email")
	adminUser := integration.User{Email: "admin"}
	// Only the builtin policy: the local "admin" account.
	itest.ExpectCode(t, check(t, c, integration.User{Email: "admin@x"}, "app.get", "applications:a/b"), integration.CodeDenied)
	_ = adminUser
	r, err := c.Probe(context.Background())
	if err != nil || !strings.Contains(r.Summary, "0 policy lines") || len(r.Warnings) != 1 {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestFineGrainedAndRollbackFlags(t *testing.T) {
	cl := defaultCluster()
	_, c, _ := setup(t, cl, "none")
	// v3 default: update does not imply update/<resource>.
	itest.ExpectCode(t, check(t, c, sre, "app.update/apps/Deployment/default/web", "applications:dev/web"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, sre, "app.update/apps/StatefulSet/default/db", "applications:dev/web"), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, sre, "app.delete/apps/StatefulSet/default/db", "applications:dev/web"), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, sre, "app.action/apps/Deployment/restart", "applications:dev/web"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, sre, "app.action/apps/StatefulSet/restart", "applications:dev/web"), integration.CodeDenied)
	// rollback checks sync by default; sre has applications * so both pass, dev has sync only.
	itest.ExpectCode(t, check(t, c, dev, "app.rollback", "applications:dev/web"), integration.CodeAllowed)

	cl = defaultCluster()
	cl.argocdCM = map[string]string{"server.rbac.disableApplicationFineGrainedRBACInheritance": "false", "server.rbac.rollback.enforce.enable": "true"}
	_, c, _ = setup(t, cl, "none")
	itest.ExpectCode(t, check(t, c, sre, "app.update/apps/StatefulSet/default/db", "applications:dev/web"), integration.CodeAllowed)
	// v2 inheritance: delete on dev/* is allowed, so the fine-grained delete is too; on prod the explicit deny wins.
	itest.ExpectCode(t, check(t, c, sre, "app.delete/apps/StatefulSet/default/db", "applications:dev/web"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, sre, "app.delete/apps/StatefulSet/default/db", "applications:prod/web"), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, dev, "app.rollback", "applications:dev/web"), integration.CodeDenied)
}

func TestInvalidPolicy(t *testing.T) {
	cl := defaultCluster()
	cl.rbacCM["policy.csv"] = "this, is, not, a, good, policy"
	_, c, _ := setup(t, cl, "none")
	itest.ExpectCode(t, check(t, c, sre, "app.get", "applications:dev/web"), integration.CodeUnsupported)
	r, err := c.Probe(context.Background())
	if err != nil || len(r.Warnings) == 0 || !strings.Contains(r.Warnings[0], "invalid") {
		t.Fatalf("%+v %v", r, err)
	}
	// An invalid project policy falls back to the policy without the project, as Argo CD does.
	cl = defaultCluster()
	cl.projects = append(cl.projects, project("broken", map[string]any{"name": "r", "policies": []string{"garbage"}, "groups": []string{"sre"}}))
	_, c, _ = setup(t, cl, "none")
	itest.ExpectCode(t, check(t, c, sre, "app.get", "applications:broken/x"), integration.CodeAllowed)
}

func TestPolicyCacheAndFailures(t *testing.T) {
	cl := defaultCluster()
	srv, c, now := setup(t, cl, "none")
	check(t, c, dev, "app.get", "applications:dev/web")
	reads := cl.reads
	check(t, c, dev, "app.sync", "applications:dev/web")
	if cl.reads != reads {
		t.Fatal("policy re-read within the cache window")
	}
	// A fresh check re-reads the policy inside the window and the next
	// check is served from what it read.
	if _, err := c.(*Connection).load(evidence.WithFresh(context.Background())); err != nil {
		t.Fatal(err)
	}
	if cl.reads == reads {
		t.Fatal("policy not re-read for a fresh check")
	}
	reads = cl.reads
	check(t, c, dev, "app.sync", "applications:dev/web")
	if cl.reads != reads {
		t.Fatal("fresh read not stored")
	}
	*now = now.Add(policyCacheTTL + time.Second)
	check(t, c, dev, "app.sync", "applications:dev/web")
	if cl.reads == reads {
		t.Fatal("policy not re-read after expiry")
	}
	*now = now.Add(policyCacheTTL + time.Second)
	itest.FailureCases(t, srv, func() integration.Decision {
		*now = now.Add(policyCacheTTL + time.Second)
		return check(t, c, dev, "app.get", "applications:dev/web")
	})
	srv.JSON("GET", "/api/v1/namespaces/argocd/configmaps/argocd-rbac-cm", 403, `{"kind":"Status","code":403}`)
	*now = now.Add(policyCacheTTL + time.Second)
	itest.ExpectCode(t, check(t, c, dev, "app.get", "applications:dev/web"), integration.CodeCredentialRejected)
}

func TestBadRequests(t *testing.T) {
	_, c, _ := setup(t, defaultCluster(), "none")
	for _, cs := range [][2]string{
		{"app.get", "projects:dev"},
		{"app.get", "applications:noslash"},
		{"app.get", "things:dev/web"},
		{"project.get", "projects:"},
		{"app.get", "applications:dev/we b"},
	} {
		itest.ExpectCode(t, check(t, c, dev, cs[0], cs[1]), integration.CodeInvalidRequest)
	}
	for _, bad := range []string{"app.action/apps", "app.action/apps/Deployment/", "app.update/apps/Deployment/x", "app.get/x", "app.action/a b/c/d"} {
		if _, ok := (Integration{}).MatchAction(bad); ok {
			t.Errorf("MatchAction(%q) accepted", bad)
		}
	}
	for _, ok := range []string{"app.action/apps/Deployment/restart", "app.update/apps/Deployment/default/web", "app.delete//Pod/default/web-0", "app.action/argoproj.io/Rollout/resume"} {
		if _, matched := (Integration{}).MatchAction(ok); !matched {
			t.Errorf("MatchAction(%q) rejected", ok)
		}
	}
}

// Per-action allow/deny tests (coverage gate). role:ops is applications *,
// plus clusters/projects get; sre is in role:ops. "none" has nothing and the
// policy has user-level rules, so plain denies use a cluster without them.

func opsCluster() *cluster {
	cl := defaultCluster()
	cl.rbacCM["policy.csv"] = `
p, role:ops, *, *, *, allow
p, role:ops, *, *, */*, allow
p, role:limited, applications, get, dev/*, allow
g, sre, role:ops
g, limited, role:limited
`
	cl.rbacCM["scopes"] = "[groups]"
	return cl
}

var limited = integration.User{Email: "l@example.com", Groups: []string{"limited"}}

func allowDeny(t *testing.T, action, resource string) {
	t.Helper()
	_, c, _ := setup(t, opsCluster(), "none")
	itest.ExpectCode(t, check(t, c, sre, action, resource), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, limited, action, resource), integration.CodeDenied)
}

func TestAction_app_get_allow(t *testing.T)    { allowDeny(t, "app.get", "applications:prod/web") }
func TestAction_app_get_deny(t *testing.T)     { allowDeny(t, "app.get", "applications:prod/web") }
func TestAction_app_create_allow(t *testing.T) { allowDeny(t, "app.create", "applications:dev/web") }
func TestAction_app_create_deny(t *testing.T)  { allowDeny(t, "app.create", "applications:dev/web") }
func TestAction_app_update_allow(t *testing.T) { allowDeny(t, "app.update", "applications:dev/web") }
func TestAction_app_update_deny(t *testing.T)  { allowDeny(t, "app.update", "applications:dev/web") }
func TestAction_app_delete_allow(t *testing.T) { allowDeny(t, "app.delete", "applications:dev/web") }
func TestAction_app_delete_deny(t *testing.T)  { allowDeny(t, "app.delete", "applications:dev/web") }
func TestAction_app_sync_allow(t *testing.T)   { allowDeny(t, "app.sync", "applications:dev/web") }
func TestAction_app_sync_deny(t *testing.T)    { allowDeny(t, "app.sync", "applications:dev/web") }
func TestAction_app_rollback_allow(t *testing.T) {
	allowDeny(t, "app.rollback", "applications:dev/web")
}
func TestAction_app_rollback_deny(t *testing.T) { allowDeny(t, "app.rollback", "applications:dev/web") }
func TestAction_app_override_allow(t *testing.T) {
	allowDeny(t, "app.override", "applications:dev/web")
}
func TestAction_app_override_deny(t *testing.T) { allowDeny(t, "app.override", "applications:dev/web") }
func TestAction_logs_get_allow(t *testing.T)    { allowDeny(t, "logs.get", "logs:dev/web") }
func TestAction_logs_get_deny(t *testing.T)     { allowDeny(t, "logs.get", "logs:dev/web") }
func TestAction_exec_create_allow(t *testing.T) { allowDeny(t, "exec.create", "exec:dev/web") }
func TestAction_exec_create_deny(t *testing.T)  { allowDeny(t, "exec.create", "exec:dev/web") }
func TestAction_appset_get_allow(t *testing.T)  { allowDeny(t, "appset.get", "applicationsets:dev/s") }
func TestAction_appset_get_deny(t *testing.T)   { allowDeny(t, "appset.get", "applicationsets:dev/s") }
func TestAction_appset_create_allow(t *testing.T) {
	allowDeny(t, "appset.create", "applicationsets:dev/s")
}
func TestAction_appset_create_deny(t *testing.T) {
	allowDeny(t, "appset.create", "applicationsets:dev/s")
}
func TestAction_appset_update_allow(t *testing.T) {
	allowDeny(t, "appset.update", "applicationsets:dev/s")
}
func TestAction_appset_update_deny(t *testing.T) {
	allowDeny(t, "appset.update", "applicationsets:dev/s")
}
func TestAction_appset_delete_allow(t *testing.T) {
	allowDeny(t, "appset.delete", "applicationsets:dev/s")
}
func TestAction_appset_delete_deny(t *testing.T) {
	allowDeny(t, "appset.delete", "applicationsets:dev/s")
}
func TestAction_project_get_allow(t *testing.T)    { allowDeny(t, "project.get", "projects:dev") }
func TestAction_project_get_deny(t *testing.T)     { allowDeny(t, "project.get", "projects:dev") }
func TestAction_project_create_allow(t *testing.T) { allowDeny(t, "project.create", "projects:new") }
func TestAction_project_create_deny(t *testing.T)  { allowDeny(t, "project.create", "projects:new") }
func TestAction_project_update_allow(t *testing.T) { allowDeny(t, "project.update", "projects:dev") }
func TestAction_project_update_deny(t *testing.T)  { allowDeny(t, "project.update", "projects:dev") }
func TestAction_project_delete_allow(t *testing.T) { allowDeny(t, "project.delete", "projects:dev") }
func TestAction_project_delete_deny(t *testing.T)  { allowDeny(t, "project.delete", "projects:dev") }
func TestAction_cluster_get_allow(t *testing.T)    { allowDeny(t, "cluster.get", "clusters:https://k") }
func TestAction_cluster_get_deny(t *testing.T)     { allowDeny(t, "cluster.get", "clusters:https://k") }
func TestAction_cluster_create_allow(t *testing.T) {
	allowDeny(t, "cluster.create", "clusters:https://k")
}
func TestAction_cluster_create_deny(t *testing.T) {
	allowDeny(t, "cluster.create", "clusters:https://k")
}
func TestAction_cluster_update_allow(t *testing.T) {
	allowDeny(t, "cluster.update", "clusters:https://k")
}
func TestAction_cluster_update_deny(t *testing.T) {
	allowDeny(t, "cluster.update", "clusters:https://k")
}
func TestAction_cluster_delete_allow(t *testing.T) {
	allowDeny(t, "cluster.delete", "clusters:https://k")
}
func TestAction_cluster_delete_deny(t *testing.T) {
	allowDeny(t, "cluster.delete", "clusters:https://k")
}
func TestAction_repo_get_allow(t *testing.T) { allowDeny(t, "repo.get", "repositories:https://r") }
func TestAction_repo_get_deny(t *testing.T)  { allowDeny(t, "repo.get", "repositories:https://r") }
func TestAction_repo_create_allow(t *testing.T) {
	allowDeny(t, "repo.create", "repositories:https://r")
}
func TestAction_repo_create_deny(t *testing.T) { allowDeny(t, "repo.create", "repositories:https://r") }
func TestAction_repo_update_allow(t *testing.T) {
	allowDeny(t, "repo.update", "repositories:https://r")
}
func TestAction_repo_update_deny(t *testing.T) { allowDeny(t, "repo.update", "repositories:https://r") }
func TestAction_repo_delete_allow(t *testing.T) {
	allowDeny(t, "repo.delete", "repositories:https://r")
}
func TestAction_repo_delete_deny(t *testing.T) { allowDeny(t, "repo.delete", "repositories:https://r") }
func TestAction_writerepo_get_allow(t *testing.T) {
	allowDeny(t, "writerepo.get", "write_repositories:https://r")
}
func TestAction_writerepo_get_deny(t *testing.T) {
	allowDeny(t, "writerepo.get", "write_repositories:https://r")
}
func TestAction_writerepo_create_allow(t *testing.T) {
	allowDeny(t, "writerepo.create", "write_repositories:https://r")
}
func TestAction_writerepo_create_deny(t *testing.T) {
	allowDeny(t, "writerepo.create", "write_repositories:https://r")
}
func TestAction_writerepo_update_allow(t *testing.T) {
	allowDeny(t, "writerepo.update", "write_repositories:https://r")
}
func TestAction_writerepo_update_deny(t *testing.T) {
	allowDeny(t, "writerepo.update", "write_repositories:https://r")
}
func TestAction_writerepo_delete_allow(t *testing.T) {
	allowDeny(t, "writerepo.delete", "write_repositories:https://r")
}
func TestAction_writerepo_delete_deny(t *testing.T) {
	allowDeny(t, "writerepo.delete", "write_repositories:https://r")
}
func TestAction_certificate_get_allow(t *testing.T) {
	allowDeny(t, "certificate.get", "certificates:h")
}
func TestAction_certificate_get_deny(t *testing.T) { allowDeny(t, "certificate.get", "certificates:h") }
func TestAction_certificate_create_allow(t *testing.T) {
	allowDeny(t, "certificate.create", "certificates:h")
}
func TestAction_certificate_create_deny(t *testing.T) {
	allowDeny(t, "certificate.create", "certificates:h")
}
func TestAction_certificate_update_allow(t *testing.T) {
	allowDeny(t, "certificate.update", "certificates:h")
}
func TestAction_certificate_update_deny(t *testing.T) {
	allowDeny(t, "certificate.update", "certificates:h")
}
func TestAction_certificate_delete_allow(t *testing.T) {
	allowDeny(t, "certificate.delete", "certificates:h")
}
func TestAction_certificate_delete_deny(t *testing.T) {
	allowDeny(t, "certificate.delete", "certificates:h")
}
func TestAction_account_get_allow(t *testing.T)    { allowDeny(t, "account.get", "accounts:admin") }
func TestAction_account_get_deny(t *testing.T)     { allowDeny(t, "account.get", "accounts:admin") }
func TestAction_account_update_allow(t *testing.T) { allowDeny(t, "account.update", "accounts:admin") }
func TestAction_account_update_deny(t *testing.T)  { allowDeny(t, "account.update", "accounts:admin") }
func TestAction_gpgkey_get_allow(t *testing.T)     { allowDeny(t, "gpgkey.get", "gpgkeys:ABCD") }
func TestAction_gpgkey_get_deny(t *testing.T)      { allowDeny(t, "gpgkey.get", "gpgkeys:ABCD") }
func TestAction_gpgkey_create_allow(t *testing.T)  { allowDeny(t, "gpgkey.create", "gpgkeys:ABCD") }
func TestAction_gpgkey_create_deny(t *testing.T)   { allowDeny(t, "gpgkey.create", "gpgkeys:ABCD") }
func TestAction_gpgkey_delete_allow(t *testing.T)  { allowDeny(t, "gpgkey.delete", "gpgkeys:ABCD") }
func TestAction_gpgkey_delete_deny(t *testing.T)   { allowDeny(t, "gpgkey.delete", "gpgkeys:ABCD") }
func TestAction_extension_invoke_allow(t *testing.T) {
	allowDeny(t, "extension.invoke", "extensions:x")
}
func TestAction_extension_invoke_deny(t *testing.T) { allowDeny(t, "extension.invoke", "extensions:x") }

func TestLoadFetchPanicDoesNotWedge(t *testing.T) {
	_, ic, _ := setup(t, defaultCluster(), "none")
	c := ic.(*Connection)
	k8s := c.k8s
	c.k8s = nil // fetch dereferences it and panics
	leaderErr := make(chan error, 1)
	go func() {
		_, err := c.load(context.Background())
		leaderErr <- err
	}()
	waiterErr := make(chan error, 3)
	for i := 0; i < 3; i++ {
		go func() {
			_, err := c.load(context.Background())
			waiterErr <- err
		}()
	}
	var pe *cache.PanicError
	for i := 0; i < 4; i++ {
		var err error
		select {
		case err = <-leaderErr:
		case err = <-waiterErr:
		case <-time.After(2 * time.Second):
			t.Fatal("load wedged after fetch panic")
		}
		if !errors.As(err, &pe) {
			t.Fatalf("err = %v, want *cache.PanicError", err)
		}
	}
	c.k8s = k8s
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	b, err := c.load(ctx)
	if err != nil || b == nil {
		t.Fatalf("after panic: %v %v", b, err)
	}
}

func TestLoadLeaderCancelDoesNotAbortWaiters(t *testing.T) {
	cl := defaultCluster()
	srv, ic, _ := setup(t, cl, "none")
	c := ic.(*Connection)
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	var hits atomic.Int32
	srv.Handle("GET", "/api/v1/namespaces/argocd/configmaps/argocd-rbac-cm", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		once.Do(func() { close(entered) })
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"data": cl.rbacCM})
	})
	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderErr := make(chan error, 1)
	go func() {
		_, err := c.load(leaderCtx)
		leaderErr <- err
	}()
	<-entered
	waiterDone := make(chan struct{})
	var wb *bundle
	var werr error
	go func() {
		defer close(waiterDone)
		wb, werr = c.load(context.Background())
	}()
	time.Sleep(10 * time.Millisecond)
	cancelLeader()
	if err := <-leaderErr; !errors.Is(err, context.Canceled) {
		t.Fatalf("leader err = %v", err)
	}
	select {
	case <-waiterDone:
		t.Fatal("waiter returned before the fetch finished")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	<-waiterDone
	if werr != nil || wb == nil {
		t.Fatalf("waiter got %v %v; the leader's cancellation aborted the shared fetch", wb, werr)
	}
	if wb.userPolicy == "" {
		t.Fatal("waiter's bundle has no policy")
	}
	// The abandoned leader's fetch was reused, not aborted and repeated.
	if n := hits.Load(); n != 1 {
		t.Fatalf("rbac config map fetched %d times, want 1", n)
	}
}
