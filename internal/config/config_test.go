package config

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/roee-hersh/hallpass/internal/catalog"
	"github.com/roee-hersh/hallpass/internal/integration"
)

type stubIntegration struct {
	name   string
	fields []integration.Field
}

func (s stubIntegration) Name() string                { return s.name }
func (s stubIntegration) Fields() []integration.Field { return s.fields }
func (s stubIntegration) Actions() []catalog.Action   { return nil }
func (s stubIntegration) New(context.Context, *integration.Settings, integration.Deps) (integration.Connection, error) {
	return nil, nil
}

func reg() *integration.Registry {
	r := integration.NewRegistry()
	r.Register(stubIntegration{name: "kubernetes", fields: []integration.Field{
		integration.URLField(true, ""), integration.CredentialField(true, ""),
		{Name: "username_template", Default: "{email}"},
	}})
	r.Register(stubIntegration{name: "argocd", fields: []integration.Field{
		integration.ConnectionRefField("kubernetes_connection", "kubernetes", true, ""),
		{Name: "namespace", Default: "argocd"},
		{Name: "user_subject", Default: "none", Enum: []string{"none", "email"}},
	}})
	r.Register(stubIntegration{name: "loop", fields: []integration.Field{
		integration.ConnectionRefField("loop_connection", "loop", false, ""),
	}})
	return r
}

func parse(t *testing.T, yml string) (*Config, error) {
	t.Helper()
	return Parse("test.yaml", []byte(yml), reg())
}

func TestValidConfig(t *testing.T) {
	ca := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(ca, []byte("x"), 0o600)
	cfg, err := parse(t, `
api_key: env:HALLPASS_API_KEY
listen: ":9090"
decision_cache_seconds: 0
connections:
  - id: argocd-prod
    integration: argocd
    kubernetes_connection: k8s-prod
  - id: k8s-prod
    integration: kubernetes
    url: https://10.0.0.1:6443
    ca_file: `+ca+`
    credential: file:/secrets/token
    timeout: 10s
    tls_server_name: kubernetes
`)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != ":9090" || cfg.DecisionCache != 0 || cfg.IdentityCache != DefaultIdentityCache {
		t.Errorf("%+v", cfg)
	}
	if len(cfg.Connections) != 2 || cfg.Connections[0].ID != "k8s-prod" || cfg.Connections[1].ID != "argocd-prod" {
		t.Fatalf("order: %v", ids(cfg))
	}
	k8s := cfg.Connections[0]
	if k8s.Get("url") != "https://10.0.0.1:6443" || k8s.Get("username_template") != "{email}" || k8s.CAFile != ca || k8s.TLSServerName != "kubernetes" || k8s.Timeout.Seconds() != 10 {
		t.Errorf("%+v", k8s)
	}
	if k8s.Secret("credential").Ref() != "file:/secrets/token" {
		t.Error("secret")
	}
	argo := cfg.Connections[1]
	if argo.Get("namespace") != "argocd" || argo.Get("user_subject") != "none" || argo.Get("kubernetes_connection") != "k8s-prod" {
		t.Errorf("%+v", argo)
	}
	if cfg.Integrations["argocd-prod"].Name() != "argocd" {
		t.Error("integrations map")
	}
}

func ids(c *Config) []string {
	var out []string
	for _, s := range c.Connections {
		out = append(out, s.ID)
	}
	return out
}

func TestErrors(t *testing.T) {
	cases := []struct{ name, yml, want string }{
		{"no api key", "connections: []\n", "api_key is required"},
		{"inline api key", "api_key: hunter2\nconnections: []\n", "inline secret"},
		{"unknown top key", "api_key: env:K\nconnections: []\nfoo: 1\n", `unknown key "foo"`},
		{"no connections", "api_key: env:K\n", "connections is required"},
		{"unknown integration", "api_key: env:K\nconnections:\n  - id: a\n    integration: nope\n", `unknown integration "nope"`},
		{"unknown key", "api_key: env:K\nconnections:\n  - id: a\n    integration: kubernetes\n    url: https://x\n    credential: env:T\n    server: https://x\n", `does not accept key "server"`},
		{"missing required", "api_key: env:K\nconnections:\n  - id: a\n    integration: kubernetes\n    url: https://x\n", "requires credential"},
		{"inline secret", "api_key: env:K\nconnections:\n  - id: a\n    integration: kubernetes\n    url: https://x\n    credential: abc123\n", "inline secret"},
		{"bad url", "api_key: env:K\nconnections:\n  - id: a\n    integration: kubernetes\n    url: http://x\n    credential: env:T\n", "must start with https://"},
		{"bad id", "api_key: env:K\nconnections:\n  - id: Bad_ID\n    integration: kubernetes\n    url: https://x\n    credential: env:T\n", "must match"},
		{"dup id", "api_key: env:K\nconnections:\n  - id: a\n    integration: kubernetes\n    url: https://x\n    credential: env:T\n  - id: a\n    integration: kubernetes\n    url: https://x\n    credential: env:T\n", "already used at line 3"},
		{"bad enum", "api_key: env:K\nconnections:\n  - id: a\n    integration: kubernetes\n    url: https://x\n    credential: env:T\n  - id: b\n    integration: argocd\n    kubernetes_connection: a\n    user_subject: sub\n", "must be one of none, email"},
		{"dangling ref", "api_key: env:K\nconnections:\n  - id: b\n    integration: argocd\n    kubernetes_connection: zzz\n", `refers to unknown connection "zzz"`},
		{"wrong ref type", "api_key: env:K\nconnections:\n  - id: b\n    integration: argocd\n    kubernetes_connection: c\n  - id: c\n    integration: argocd\n    kubernetes_connection: b\n", "must name a kubernetes connection"},
		{"self ref", "api_key: env:K\nconnections:\n  - id: b\n    integration: loop\n    loop_connection: b\n", "refers to itself"},
		{"cycle", "api_key: env:K\nconnections:\n  - id: b\n    integration: loop\n    loop_connection: c\n  - id: c\n    integration: loop\n    loop_connection: b\n", "reference cycle"},
		{"nested", "api_key: env:K\nconnections:\n  - id: a\n    integration: kubernetes\n    url:\n      host: x\n    credential: env:T\n", "must be a single value"},
		{"bad timeout", "api_key: env:K\nconnections:\n  - id: a\n    integration: kubernetes\n    url: https://x\n    credential: env:T\n    timeout: fast\n", "timeout must be a duration"},
		{"missing ca", "api_key: env:K\nconnections:\n  - id: a\n    integration: kubernetes\n    url: https://x\n    credential: env:T\n    ca_file: /nope/ca.pem\n", "ca_file"},
		{"bad cache", "api_key: env:K\ndecision_cache_seconds: -1\nconnections: []\n", "whole number of seconds"},
		{"dup connections", "api_key: env:K\nconnections:\n  - id: a\n    integration: kubernetes\n    url: https://x\n    credential: env:T\nconnections:\n  - id: b\n    integration: kubernetes\n    url: https://x\n    credential: env:T\n", `test.yaml:7: key "connections" repeated (first set at line 2)`},
		{"dup api_key", "api_key: env:K\napi_key: env:K2\nconnections: []\n", `test.yaml:2: key "api_key" repeated (first set at line 1)`},
		{"dup listen", "api_key: env:K\nlisten: \":1\"\nconnections: []\nlisten: \":2\"\n", `test.yaml:4: key "listen" repeated`},
		{"not yaml", "api_key: [\n", "test.yaml"},
	}
	for _, c := range cases {
		_, err := parse(t, c.yml)
		if err == nil {
			t.Errorf("%s: no error", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %q, want substring %q", c.name, err, c.want)
		}
		if !strings.HasPrefix(err.Error(), "test.yaml") {
			t.Errorf("%s: error lacks file: %q", c.name, err)
		}
	}
}

func TestErrorsReportAll(t *testing.T) {
	_, err := parse(t, "api_key: env:K\nconnections:\n  - id: a\n    integration: kubernetes\n    url: http://x\n    credential: abc\n    bogus: 1\n")
	if err == nil {
		t.Fatal("no error")
	}
	if n := len(err.(Errors)); n != 3 {
		t.Fatalf("got %d errors: %v", n, err)
	}
	if !strings.Contains(err.Error(), "test.yaml:5") {
		t.Errorf("line numbers: %v", err)
	}
}

func TestLoadFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.yaml")
	os.WriteFile(p, []byte("api_key: env:K\nconnections: []\n"), 0o600)
	cfg, err := Load(p, reg())
	if err != nil || len(cfg.Connections) != 0 {
		t.Fatal(cfg, err)
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing"), reg()); err == nil {
		t.Fatal("missing file")
	}
}
