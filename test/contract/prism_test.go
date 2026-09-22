//go:build contract

// Package contract runs integrations against Prism (@stoplight/prism-cli),
// a mock server that answers from the vendor's OpenAPI description: every
// response is built from the description's examples and schemas, and Prism
// rejects requests that violate the description. The tests prove that the
// integration's requests are accepted and that its decoders understand
// schema-conformant responses. Decisions themselves are not asserted
// beyond "hallpass produced a decision, not a decode failure".
//
//	HALLPASS_SPECS_DIR=$PWD/.specs go test -tags contract ./test/contract/
//
// Needs node (npx) on the PATH; the Prism CLI is fetched by npx.
package contract

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/roee-hersh/hallpass/internal/config"
	"github.com/roee-hersh/hallpass/internal/engine"
	"github.com/roee-hersh/hallpass/internal/integration"
	"github.com/roee-hersh/hallpass/internal/integrations/all"
)

func specPath(t *testing.T, name string) string {
	dir := os.Getenv("HALLPASS_SPECS_DIR")
	if dir == "" {
		t.Skip("HALLPASS_SPECS_DIR not set")
	}
	p := filepath.Join(dir, name+".spec")
	if _, err := os.Stat(p); err != nil {
		t.Skipf("no %s", p)
	}
	return p
}

// startPrism runs `prism mock` on the description and returns its base URL.
func startPrism(t *testing.T, spec string) string {
	t.Helper()
	if _, err := exec.LookPath("npx"); err != nil {
		t.Skip("npx not on PATH")
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	// Prism wants a file extension it recognises.
	tmp := filepath.Join(t.TempDir(), "spec"+extFor(t, spec))
	data, err := os.ReadFile(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, "npx", "--yes", "@stoplight/prism-cli@5", "mock", "-p", fmt.Sprint(port), "-h", "127.0.0.1", "--errors", tmp)
	logf, _ := os.Create(filepath.Join(t.TempDir(), "prism.log"))
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
		logf.Close()
		if t.Failed() {
			b, _ := os.ReadFile(logf.Name())
			if len(b) > 8000 {
				b = b[len(b)-8000:]
			}
			t.Logf("prism log tail:\n%s", b)
		}
	})
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	deadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return base
		}
		time.Sleep(500 * time.Millisecond)
	}
	b, _ := os.ReadFile(logf.Name())
	t.Fatalf("prism did not start:\n%s", b)
	return ""
}

func extFor(t *testing.T, path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(strings.TrimSpace(string(b)), "{") {
		return ".json"
	}
	return ".yaml"
}

// build makes an engine from a config snippet.
func build(t *testing.T, yml string) *engine.Engine {
	t.Helper()
	t.Setenv("HALLPASS_API_KEY", "contract")
	cfg, err := config.Parse("contract.yaml", []byte("api_key: env:HALLPASS_API_KEY\ndecision_log: none\nconnections:\n"+yml), all.Registry())
	if err != nil {
		t.Fatal(err)
	}
	eng, err := engine.Build(context.Background(), cfg, engine.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return eng
}

// run performs a probe and a set of checks and fails only on decode-level
// failures: an upstream_error means hallpass could not understand a
// schema-conformant response (or Prism rejected the request as invalid).
func run(t *testing.T, eng *engine.Engine, conn string, cases [][3]string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for _, p := range eng.Probe(ctx, conn) {
		t.Logf("probe %s: summary=%q warnings=%v err=%v", p.ID, p.Result.Summary, p.Result.Warnings, p.Err)
	}
	for _, c := range cases {
		res := eng.Check(ctx, engine.Request{User: "dana@example.com", Groups: []string{"team"}, Connection: conn, Action: c[0], Resource: c[1]})
		t.Logf("%s on %s -> %s (%s)", c[0], c[1], res.Decision.Outcome, res.Decision.Reason())
		if res.Decision.Code == integration.CodeUpstreamError {
			t.Errorf("%s on %s: %s", c[0], c[1], res.Decision.Reason())
		}
		if c[2] != "" && string(res.Decision.Code) != c[2] {
			t.Errorf("%s on %s: code %s, want %s", c[0], c[1], res.Decision.Code, c[2])
		}
	}
}

func TestGitHubAgainstPrism(t *testing.T) {
	base := startPrism(t, specPath(t, "github"))
	key := filepath.Join(t.TempDir(), "app.pem")
	if err := os.WriteFile(key, []byte(testRSAKey), 0o600); err != nil {
		t.Fatal(err)
	}
	eng := build(t, fmt.Sprintf(`  - id: gh
    integration: github
    url: %s
    organization: octo-org
    app_id: "12345"
    identity_mode: template
    email_domains: example.com
    credential: file:%s
`, base, key))
	run(t, eng, "gh", [][3]string{
		{"repo.read", "repo:octo-org/hello-world", ""},
		{"repo.push", "repo:octo-org/hello-world", ""},
		{"org.member", "org:octo-org", ""},
		{"team.member", "team:octo-org/justice-league", ""},
	})
}

func TestJiraAgainstPrism(t *testing.T) {
	base := startPrism(t, specPath(t, "jira"))
	t.Setenv("JIRA_TOKEN", "contract-token")
	eng := build(t, fmt.Sprintf(`  - id: jira
    integration: jira
    url: %s
    username: bot@example.com
    credential: env:JIRA_TOKEN
`, base))
	run(t, eng, "jira", [][3]string{
		{"BROWSE_PROJECTS", "project:EX", ""},
		{"CREATE_ISSUES", "project:EX", ""},
		{"EDIT_ISSUES", "issue:EX-1", ""},
		{"ADMINISTER", "global", ""},
	})
}

func TestSlackAgainstPrism(t *testing.T) {
	base := startPrism(t, specPath(t, "slack"))
	t.Setenv("SLACK_TOKEN", "xoxb-contract")
	eng := build(t, fmt.Sprintf(`  - id: slack
    integration: slack
    url: %s
    credential: env:SLACK_TOKEN
`, base))
	run(t, eng, "slack", [][3]string{
		{"user.active", "workspace", ""},
		{"channel.read", "channel:C012AB3CD", ""},
		{"message.post", "channel:C012AB3CD", ""},
		{"usergroup.member", "usergroup:S0604QSJC", ""},
	})
}

func TestGitLabAgainstPrism(t *testing.T) {
	base := startPrism(t, specPath(t, "gitlab"))
	t.Setenv("GITLAB_TOKEN", "contract-token")
	eng := build(t, fmt.Sprintf(`  - id: gl
    integration: gitlab
    url: %s
    credential: env:GITLAB_TOKEN
    identity_mode: template
    email_domains: example.com
`, base))
	run(t, eng, "gl", [][3]string{
		{"project.read", "project:5", ""},
		{"repo.push", "project:5@main", ""},
		{"group.member", "group:7", ""},
	})
}

func init() {
	_ = http.StatusOK
}
