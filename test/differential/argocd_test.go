//go:build differential

// Package differential compares hallpass evaluators with the real tools.
// Run with `go test -tags differential ./test/differential/` and the tool
// on the PATH; tests skip when it is absent.
package differential

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/roee-hersh/hallpass/internal/integrations/argocd/rbac"
)

// dummyKubeconfig satisfies the CLI, which builds a Kubernetes client even
// when the policy comes from a file. Nothing is ever contacted.
const dummyKubeconfig = `apiVersion: v1
kind: Config
clusters:
- cluster: {server: "https://127.0.0.1:1"}
  name: dummy
contexts:
- context: {cluster: dummy, user: dummy}
  name: dummy
current-context: dummy
users:
- name: dummy
  user: {token: dummy}
`

// argocdCan runs `argocd admin settings rbac can` and returns its printed
// answer. Anything other than "Yes" or "No" fails the test.
func argocdCan(t *testing.T, kubeconfig, policyFile, defaultRole, sub, act, res, obj string) bool {
	t.Helper()
	args := []string{"admin", "settings", "rbac", "can", sub, act, res, obj, "--policy-file", policyFile, "--strict=false"}
	if defaultRole != "" {
		args = append(args, "--default-role", defaultRole)
	}
	cmd := exec.Command("argocd", args...)
	cmd.Env = append(os.Environ(), "KUBECONFIG="+kubeconfig)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	_ = cmd.Run()
	switch strings.TrimSpace(out.String()) {
	case "Yes":
		return true
	case "No":
		return false
	}
	t.Fatalf("argocd %v: unexpected output\n%s%s", args, out.String(), errb.String())
	return false
}

type triple struct{ res, act, obj string }

func TestArgoCDRBACDifferential(t *testing.T) {
	if _, err := exec.LookPath("argocd"); err != nil {
		t.Skip("argocd binary not on PATH")
	}
	type policy struct {
		mode     string
		csv      string
		subjects []string
		triples  []triple
	}
	policies := []policy{
		{
			mode: "glob",
			csv: `
p, role:dev, applications, get, dev/*, allow
p, role:dev, applications, sync, dev/*, allow
p, role:ops, applications, *, */*, allow
p, role:ops, applications, delete, prod/*, deny
p, role:ops, clusters, get, *, allow
p, role:ops, applications, action/apps/Deployment/*, */*, allow
p, alice, repositories, *, foo/*, allow
p, bob, repositories, *, foo/https://github.com/argoproj/argo-cd.git, allow
p, carol, clusters, get, "https://github.com/*/*.git", allow
p, dan, applications, get, "{dev,staging}/*", allow
p, erin, applications, get, dev/app-?, allow
p, frank, applications, get, dev/[a-c]*, allow
p, grace, applications, get, dev/[!a-c]*, allow
p, heidi, applications, update, */*, allow
p, ivan, applications, get, dev/**, allow
p, judy, applications, get, dev/\*, allow
g, developers, role:dev
g, sre, role:ops
g, role:ops, role:dev
g, admins, role:admin
g, chain1, chain2
g, chain2, chain3
g, chain3, role:dev
`,
			subjects: []string{"admin", "role:admin", "role:readonly", "role:dev", "role:ops", "developers", "sre", "admins", "alice", "bob", "carol", "dan", "erin", "frank", "grace", "heidi", "ivan", "judy", "chain1", "nobody"},
			triples: []triple{
				{"applications", "get", "dev/web"}, {"applications", "get", "prod/web"}, {"applications", "get", "staging/web"},
				{"applications", "sync", "dev/web"}, {"applications", "delete", "dev/web"}, {"applications", "delete", "prod/web"},
				{"applications", "create", "dev/web"}, {"applications", "override", "prod/web"}, {"applications", "rollback", "dev/web"},
				{"applications", "action/apps/Deployment/restart", "dev/web"}, {"applications", "action/apps/StatefulSet/restart", "dev/web"},
				{"applications", "update", "dev/web"}, {"applications", "update/apps/Deployment/ns/x", "dev/web"}, {"applications", "delete/apps/Deployment/ns/x", "prod/web"},
				{"applications", "get", "dev/app-1"}, {"applications", "get", "dev/app-12"}, {"applications", "get", "dev/bee"}, {"applications", "get", "dev/zed"},
				{"applications", "get", "dev/a/b"}, {"applications", "get", "dev/*"}, {"applications", "get", "dev"},
				{"clusters", "get", "https://github.com/argoproj/argo-cd.git"}, {"clusters", "get", "https://github.com/argo-cd.git"}, {"clusters", "get", "in-cluster"},
				{"clusters", "create", "in-cluster"},
				{"repositories", "delete", "foo/https://github.com/argoproj/argo-cd.git"}, {"repositories", "delete", "foo/https://github.com/golang/go.git"}, {"repositories", "get", "bar/x"},
				{"projects", "get", "dev"}, {"projects", "update", "dev"}, {"logs", "get", "dev/web"}, {"exec", "create", "dev/web"},
				{"accounts", "get", "admin"}, {"certificates", "create", "x"}, {"gpgkeys", "delete", "x"}, {"extensions", "invoke", "x"},
				{"write-repositories", "get", "x"}, {"applicationsets", "delete", "dev/set"},
			},
		},
		{
			mode: "regex",
			csv: `
p, alice, clusters, get, "https://github.com/argo[a-z]{4}/argo-[a-z]+.git", allow
p, bob, applications, get, ^dev/, allow
p, carol, applications, get, dev, allow
p, dan, applications, "get|sync", "^(dev|staging)/", allow
p, erin, applications, get, "dev/(", allow
g, team, role:readonly
`,
			subjects: []string{"alice", "bob", "carol", "dan", "erin", "team", "role:readonly", "admin", "nobody"},
			triples: []triple{
				{"clusters", "get", "https://github.com/argoproj/argo-cd.git"}, {"clusters", "get", "https://github.com/argoproj/1argo-cd.git"},
				{"applications", "get", "dev/web"}, {"applications", "get", "xdev/web"}, {"applications", "get", "my-dev-1"}, {"applications", "sync", "staging/web"},
				{"applications", "sync", "prod/web"}, {"applications", "get", "dev/("}, {"applications", "get", "prod/x"},
				{"projects", "get", "dev"}, {"clusters", "get", "in-cluster"},
			},
		},
	}

	dir := t.TempDir()
	kubeconfig := filepath.Join(dir, "kubeconfig")
	if err := os.WriteFile(kubeconfig, []byte(dummyKubeconfig), 0o600); err != nil {
		t.Fatal(err)
	}
	total, mismatches := 0, 0
	for _, p := range policies {
		for _, defaultRole := range []string{"", "role:readonly"} {
			cm := "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: argocd-rbac-cm\ndata:\n  policy.matchMode: " + p.mode + "\n  policy.csv: |\n"
			for _, line := range strings.Split(p.csv, "\n") {
				cm += "    " + line + "\n"
			}
			file := filepath.Join(dir, p.mode+".yaml")
			if err := os.WriteFile(file, []byte(cm), 0o600); err != nil {
				t.Fatal(err)
			}
			enf, err := rbac.NewEnforcer(rbac.Options{Builtin: rbac.BuiltinPolicyCSV, User: p.csv, MatchMode: p.mode, DefaultRole: defaultRole})
			if err != nil {
				t.Fatal(err)
			}
			for _, sub := range p.subjects {
				for _, tr := range p.triples {
					total++
					want := argocdCan(t, kubeconfig, file, defaultRole, sub, tr.act, tr.res, tr.obj)
					got := enf.Enforce(sub, tr.res, tr.act, tr.obj)
					if want != got {
						mismatches++
						t.Errorf("mode=%s default=%q sub=%q %s %s %s: argocd=%v hallpass=%v", p.mode, defaultRole, sub, tr.res, tr.act, tr.obj, want, got)
					}
				}
			}
		}
	}
	t.Logf("differential: %d cases, %d mismatches", total, mismatches)
}
