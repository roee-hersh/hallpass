//go:build e2e

// Package e2e holds tests that run against real systems. They are skipped
// unless the environment names one. test/kind/run.sh sets up Kubernetes.
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/roee-hersh/hallpass/internal/config"
	"github.com/roee-hersh/hallpass/internal/engine"
	"github.com/roee-hersh/hallpass/internal/integrations/all"
	"github.com/roee-hersh/hallpass/internal/server"
)

func TestKubernetes(t *testing.T) {
	url := os.Getenv("HALLPASS_E2E_KUBERNETES_URL")
	tokenFile := os.Getenv("HALLPASS_E2E_KUBERNETES_TOKEN_FILE")
	caFile := os.Getenv("HALLPASS_E2E_KUBERNETES_CA_FILE")
	if url == "" || tokenFile == "" || caFile == "" {
		t.Skip("HALLPASS_E2E_KUBERNETES_* not set")
	}
	t.Setenv("HALLPASS_API_KEY", "e2e")
	yml := "api_key: env:HALLPASS_API_KEY\ndecision_log: none\nconnections:\n" +
		"  - id: kind\n    integration: kubernetes\n    url: " + url + "\n    ca_file: " + caFile + "\n    credential: file:" + tokenFile + "\n"
	cfg, err := config.Parse("e2e.yaml", []byte(yml), all.Registry())
	if err != nil {
		t.Fatal(err)
	}
	eng, err := engine.Build(context.Background(), cfg, engine.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range eng.Probe(context.Background()) {
		if p.Err != nil {
			t.Fatalf("probe %s: %v", p.ID, p.Err)
		}
		t.Logf("probe %s: %s %v", p.ID, p.Result.Summary, p.Result.Warnings)
	}
	srv := httptest.NewServer(server.New(eng, cfg.APIKey, nil))
	defer srv.Close()

	check := func(user string, groups []string, action, resource string) (string, string) {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"user": user, "groups": groups, "connection": "kind", "action": action, "resource": resource})
		req, _ := http.NewRequest("POST", srv.URL+"/check", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer e2e")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var out struct{ Decision, Reason string }
		if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
		if res.StatusCode != 200 {
			t.Fatalf("%s %s %s: HTTP %d %s", user, action, resource, res.StatusCode, out.Reason)
		}
		return out.Decision, out.Reason
	}

	cases := []struct {
		user     string
		groups   []string
		action   string
		resource string
		want     string
	}{
		{"dana@example.com", nil, "raw:get:pods", "namespace:payments", "allow"},
		{"dana@example.com", nil, "raw:list:pods", "namespace:payments", "allow"},
		{"dana@example.com", nil, "pods.logs", "namespace:payments?name=api-0", "allow"},
		{"dana@example.com", nil, "raw:delete:pods", "namespace:payments", "deny"},
		{"dana@example.com", nil, "raw:get:pods", "namespace:billing", "deny"},
		{"dana@example.com", nil, "deployment.create", "namespace:payments", "deny"},
		{"dana@example.com", []string{"platform-team"}, "deployment.create", "namespace:payments", "allow"},
		{"dana@example.com", []string{"platform-team"}, "scale", "namespace:payments?resource=deployments.apps&name=api", "allow"},
		{"dana@example.com", []string{"platform-team"}, "pods.exec", "namespace:payments?name=api-0", "allow"},
		{"dana@example.com", []string{"platform-team"}, "deployment.delete", "namespace:payments?name=api", "deny"},
		{"bob@example.com", nil, "raw:get:pods", "namespace:payments", "allow"},
		{"bob@example.com", nil, "raw:list:pods", "namespace:payments", "deny"},
		{"bob@example.com", nil, "pods.logs", "namespace:payments", "deny"},
		{"nobody@example.com", nil, "raw:get:pods", "namespace:payments", "deny"},
		{"nobody@example.com", nil, "raw:get", "nonresource:/version", "allow"},
		{"nobody@example.com", nil, "raw:get", "nonresource:/api", "allow"},
		{"nobody@example.com", nil, "raw:post", "nonresource:/api", "deny"},
		{"nobody@example.com", nil, "raw:get:nodes", "cluster", "deny"},
		{"nobody@example.com", nil, "secrets.read", "namespace:kube-system?name=x", "deny"},
	}
	for _, c := range cases {
		got, reason := check(c.user, c.groups, c.action, c.resource)
		if got != c.want {
			t.Errorf("%s %v %s %s: got %s (%s), want %s", c.user, c.groups, c.action, c.resource, got, reason, c.want)
		} else {
			t.Logf("%s %v %s %s: %s (%s)", c.user, c.groups, c.action, c.resource, got, reason)
		}
	}
}
