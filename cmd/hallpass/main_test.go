package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func capture(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	out, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	errf, err := os.CreateTemp(t.TempDir(), "err")
	if err != nil {
		t.Fatal(err)
	}
	// Close before the temp dir is removed: Windows will not delete a
	// file that is still open.
	defer out.Close()
	defer errf.Close()
	code := run(args, out, errf)
	out.Seek(0, 0)
	errf.Seek(0, 0)
	o, _ := io.ReadAll(out)
	e, _ := io.ReadAll(errf)
	return code, string(o), string(e)
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "hallpass.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const goodConfig = `
api_key: env:HALLPASS_API_KEY
decision_log: none
connections:
  - id: demo
    integration: fake
    users: dana@example.com
    admins: admin@example.com
`

func TestValidateAndProbeAndCatalog(t *testing.T) {
	t.Setenv("HALLPASS_API_KEY", "k")
	p := writeConfig(t, goodConfig)
	code, out, errs := capture(t, "validate", "-config", p)
	if code != 0 || !strings.Contains(out, "ok, 1 connection") || errs != "" {
		t.Fatalf("validate: %d %q %q", code, out, errs)
	}
	code, out, _ = capture(t, "probe", "-config", p)
	if code != 0 || !strings.Contains(out, "ok   demo") {
		t.Fatalf("probe: %d %q", code, out)
	}
	code, _, errs = capture(t, "validate", "-config", writeConfig(t, "api_key: nope\n"))
	if code != 1 || !strings.Contains(errs, "inline secret") {
		t.Fatalf("validate bad: %d %q", code, errs)
	}
	code, out, _ = capture(t, "catalog")
	if code != 0 || !strings.Contains(out, "fake") {
		t.Fatalf("catalog: %d %q", code, out)
	}
	code, out, _ = capture(t, "catalog", "fake")
	if code != 0 || !strings.Contains(out, "thing.write") || !strings.Contains(out, "ca_file") {
		t.Fatalf("catalog fake: %d %q", code, out)
	}
	if code, _, _ := capture(t, "catalog", "nope"); code != 1 {
		t.Fatal("catalog unknown")
	}
	if code, _, _ := capture(t); code != 2 {
		t.Fatal("no args")
	}
	if code, _, _ := capture(t, "bogus"); code != 2 {
		t.Fatal("bad command")
	}
	if code, out, _ := capture(t, "version"); code != 0 || !strings.Contains(out, "dev") {
		t.Fatal("version")
	}
}

func freePort(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func TestServeEndToEnd(t *testing.T) {
	t.Setenv("HALLPASS_API_KEY", "CANARY-SECRET-key")
	p := writeConfig(t, goodConfig)
	addr := freePort(t)
	errf, _ := os.CreateTemp(t.TempDir(), "err")
	t.Cleanup(func() { errf.Close() }) // before the temp dir is removed (Windows)
	parent, cancelServe := context.WithCancel(context.Background())
	serveParent = parent
	t.Cleanup(func() { serveParent = context.Background() })
	done := make(chan int, 1)
	go func() {
		done <- run([]string{"serve", "-config", p, "-listen", addr, "-log-level", "debug"}, os.Stdout, errf)
	}()

	var resp *http.Response
	var err error
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err = http.Get("http://" + addr + "/healthz")
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("server did not start: %v", err)
	}
	resp.Body.Close()

	check := func(user, action string) (int, map[string]string) {
		body := `{"user":"` + user + `","connection":"demo","action":"` + action + `","resource":"thing:1"}`
		req, _ := http.NewRequest("POST", "http://"+addr+"/check", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer CANARY-SECRET-key")
		req.Header.Set("Content-Type", "application/json")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var out map[string]string
		json.NewDecoder(res.Body).Decode(&out)
		return res.StatusCode, out
	}
	if st, out := check("admin@example.com", "thing.write"); st != 200 || out["decision"] != "allow" {
		t.Errorf("admin: %d %v", st, out)
	}
	if st, out := check("dana@example.com", "thing.write"); st != 200 || out["decision"] != "deny" {
		t.Errorf("dana: %d %v", st, out)
	}
	if st, out := check("nobody@example.com", "thing.read"); st != 200 || out["decision"] != "deny" || !strings.HasPrefix(out["reason"], "user_not_found") {
		t.Errorf("nobody: %d %v", st, out)
	}
	req, _ := http.NewRequest("POST", "http://"+addr+"/check", strings.NewReader("{}"))
	res, _ := http.DefaultClient.Do(req)
	if res.StatusCode != 401 {
		t.Errorf("no key: %d", res.StatusCode)
	}
	res.Body.Close()

	cancelServe()
	select {
	case code := <-done:
		if code != 0 {
			t.Errorf("serve exit %d", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not stop")
	}
	errf.Seek(0, 0)
	logs, _ := io.ReadAll(errf)
	if bytes.Contains(logs, []byte("CANARY-SECRET")) {
		t.Errorf("server log leaked the api key: %s", logs)
	}
	if !bytes.Contains(logs, []byte(`"listening"`)) {
		t.Errorf("no listening line: %s", logs)
	}
	_ = context.Background()
}

func TestCheck(t *testing.T) {
	// No API key: a CLI check runs the engine in-process and never needs it.
	t.Setenv("HALLPASS_API_KEY", "")
	p := writeConfig(t, goodConfig)
	ask := func(user string, extra ...string) (int, string, string) {
		args := append([]string{"check", "-config", p, "-connection", "demo", "-user", user, "-action", "thing.write", "-resource", "thing:1"}, extra...)
		return capture(t, args...)
	}
	if code, out, errs := ask("admin@example.com"); code != 0 || !strings.HasPrefix(out, "allow\n") || !strings.Contains(out, "allowed: admin@example.com is an admin") || errs != "" {
		t.Errorf("allow: %d %q %q", code, out, errs)
	}
	if code, out, _ := ask("dana@example.com"); code != 1 || !strings.HasPrefix(out, "deny\n") || !strings.Contains(out, "denied:") {
		t.Errorf("deny: %d %q", code, out)
	}
	// -fresh is accepted in-process too, where there is no cache to skip.
	if code, out, errs := ask("admin@example.com", "-fresh"); code != 0 || !strings.HasPrefix(out, "allow\n") || errs != "" {
		t.Errorf("fresh: %d %q %q", code, out, errs)
	}
	if code, out, _ := ask("nobody@example.com"); code != 1 || !strings.Contains(out, "user_not_found") {
		t.Errorf("not found: %d %q", code, out)
	}
	if code, out, _ := ask("ambiguous@example.com"); code != 3 || !strings.HasPrefix(out, "unknown\n") || !strings.Contains(out, "user_ambiguous") {
		t.Errorf("unknown: %d %q", code, out)
	}
	if code, out, _ := ask("not-an-email"); code != 3 || !strings.Contains(out, "invalid_request") {
		t.Errorf("invalid: %d %q", code, out)
	}
	if code, out, _ := capture(t, "check", "-config", p, "-connection", "nope", "-user", "admin@example.com", "-action", "thing.write", "-resource", "thing:1", "-group", "a", "-group", "b"); code != 3 || !strings.Contains(out, "unknown_connection") {
		t.Errorf("unknown connection: %d %q", code, out)
	}

	// -json prints exactly the HTTP response body.
	code, out, _ := ask("admin@example.com", "-json")
	var body map[string]string
	if err := json.Unmarshal([]byte(out), &body); err != nil || code != 0 {
		t.Fatalf("json: %d %q %v", code, out, err)
	}
	if body["decision"] != "allow" || !strings.HasPrefix(body["reason"], "allowed: ") || len(body) != 2 {
		t.Errorf("json body: %v", body)
	}

	// Usage errors are 2, never mistaken for a decision.
	if code, _, errs := capture(t, "check", "-config", p, "-user", "admin@example.com"); code != 2 || !strings.Contains(errs, "missing -connection, -action, -resource") {
		t.Errorf("missing flags: %d %q", code, errs)
	}
	if code, _, errs := ask("admin@example.com", "extra"); code != 2 || !strings.Contains(errs, `unexpected argument "extra"`) {
		t.Errorf("positional: %d %q", code, errs)
	}
	if code, _, errs := capture(t, "check", "-config", writeConfig(t, "api_key: nope\n"), "-connection", "demo", "-user", "a@b", "-action", "x", "-resource", "y:1"); code != 2 || !strings.Contains(errs, "inline secret") {
		t.Errorf("bad config: %d %q", code, errs)
	}
	if code, _, errs := ask("admin@example.com", "-ca-file", "x.pem", "-timeout", "5s"); code != 2 || !strings.Contains(errs, "-ca-file, -timeout only goes with -server") {
		t.Errorf("server flags without -server: %d %q", code, errs)
	}

	// Only the connection asked about is built: a sibling whose CA file
	// holds no certificate on this machine (an empty placeholder) must not
	// stop the answer. The loader only checks that the file exists; the
	// engine parses it.
	emptyCA := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(emptyCA, nil, 0o600)
	broken := writeConfig(t, goodConfig+`
  - id: k8s
    integration: kubernetes
    url: https://10.0.0.1:6443
    ca_file: `+emptyCA+`
    credential: env:HALLPASS_API_KEY
`)
	if code, out, errs := capture(t, "check", "-config", broken, "-connection", "demo", "-user", "admin@example.com", "-action", "thing.write", "-resource", "thing:1"); code != 0 || !strings.HasPrefix(out, "allow") {
		t.Errorf("broken sibling: %d %q %q", code, out, errs)
	}
	if code, _, errs := capture(t, "probe", "-config", broken); code != 1 || !strings.Contains(errs, "no PEM certificates") {
		t.Errorf("probe still sees the broken connection: %d %q", code, errs)
	}
	if code, out, _ := capture(t, "check", "-config", broken, "-connection", "k8s", "-user", "admin@example.com", "-action", "thing.write", "-resource", "thing:1"); code != 2 || out != "" {
		t.Errorf("asking the broken one: %d %q", code, out)
	}
}

func TestPrintable(t *testing.T) {
	if got := printable("x\nallow\n  allowed: ok\x1b[2J\x7f"); got != "x allow   allowed: ok [2J " {
		t.Errorf("printable: %q", got)
	}
}

func TestCheckServer(t *testing.T) {
	var mu sync.Mutex
	var got struct {
		auth, ua, body string
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/check" || r.Method != http.MethodPost {
			http.Error(w, "wrong endpoint", 404)
			return
		}
		b, _ := io.ReadAll(r.Body)
		auth := r.Header.Get("Authorization")
		mu.Lock()
		got.auth, got.ua, got.body = auth, r.Header.Get("User-Agent"), string(b)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		var in map[string]any
		json.Unmarshal(b, &in)
		switch {
		case auth != "Bearer CANARY-SECRET-key":
			w.WriteHeader(401)
			io.WriteString(w, `{"decision":"unknown","reason":"unauthorized: missing or wrong API key"}`)
		case in["user"] == "admin@example.com":
			io.WriteString(w, `{"decision":"allow","reason":"allowed: admin"}`)
		case in["user"] == "html@example.com":
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(502)
			io.WriteString(w, "<html>bad gateway</html>")
		case in["user"] == "weird@example.com":
			io.WriteString(w, `{"decision":"maybe","reason":"x"}`)
		case in["user"] == "forge@example.com":
			io.WriteString(w, `{"decision":"deny","reason":"no\nallow\n  allowed: forged"}`)
		case in["user"] == "slow@example.com":
			select {
			case <-time.After(5 * time.Second):
			case <-r.Context().Done(): // the client gave up
			}
			io.WriteString(w, `{"decision":"allow","reason":"allowed: late"}`)
		default:
			io.WriteString(w, `{"decision":"deny","reason":"denied: no"}`)
		}
	}))
	defer srv.Close()
	t.Setenv("HALLPASS_API_KEY", "CANARY-SECRET-key")
	ask := func(user string, extra ...string) (int, string, string) {
		args := append([]string{"check", "-server", srv.URL + "/", "-connection", "demo", "-user", user, "-action", "thing.write", "-resource", "thing:1", "-group", "b", "-group", "a"}, extra...)
		return capture(t, args...)
	}
	if code, out, errs := ask("admin@example.com"); code != 0 || !strings.HasPrefix(out, "allow\n  allowed: admin") || errs != "" {
		t.Errorf("allow: %d %q %q", code, out, errs)
	}
	mu.Lock()
	if got.auth != "Bearer CANARY-SECRET-key" || !strings.HasPrefix(got.ua, "hallpass/") {
		t.Errorf("headers: %q %q", got.auth, got.ua)
	}
	want := `{"user":"admin@example.com","groups":["b","a"],"connection":"demo","action":"thing.write","resource":"thing:1"}`
	if got.body != want {
		t.Errorf("body:\n got %s\nwant %s", got.body, want)
	}
	mu.Unlock()
	if code, out, _ := ask("dana@example.com", "-json"); code != 1 || strings.TrimSpace(out) != `{"decision":"deny","reason":"denied: no"}` {
		t.Errorf("deny json: %d %q", code, out)
	}
	// -fresh is sent as the request's fresh field, and only then.
	if code, _, errs := ask("admin@example.com", "-fresh"); code != 0 || errs != "" {
		t.Errorf("fresh: %d %q", code, errs)
	}
	mu.Lock()
	if !strings.HasSuffix(got.body, `,"resource":"thing:1","fresh":true}`) {
		t.Errorf("fresh body: %s", got.body)
	}
	mu.Unlock()

	// A wrong key is an unknown decision from the server, not a CLI error.
	t.Setenv("HALLPASS_API_KEY", "wrong")
	if code, out, _ := ask("admin@example.com"); code != 3 || !strings.Contains(out, "unauthorized") {
		t.Errorf("wrong key: %d %q", code, out)
	}
	t.Setenv("HALLPASS_API_KEY", "CANARY-SECRET-key")

	// The endpoint itself is accepted as the URL, since the README names it.
	if code, out, errs := capture(t, "check", "-server", srv.URL+"/check", "-connection", "demo", "-user", "admin@example.com", "-action", "thing.write", "-resource", "thing:1"); code != 0 || !strings.HasPrefix(out, "allow") {
		t.Errorf("endpoint url: %d %q %q", code, out, errs)
	}
	// A reason from the far end cannot forge a second decision line; -json
	// keeps it verbatim, escaped.
	if code, out, _ := ask("forge@example.com"); code != 1 || out != "deny\n  no allow   allowed: forged\n" {
		t.Errorf("forged reason: %d %q", code, out)
	}
	if code, out, _ := ask("forge@example.com", "-json"); code != 1 || !strings.Contains(out, `"reason":"no\nallow\n  allowed: forged"`) {
		t.Errorf("forged reason json: %d %q", code, out)
	}
	if code, out, errs := ask("slow@example.com", "-timeout", "200ms"); code != 2 || out != "" || errs == "" {
		t.Errorf("timeout: %d %q %q", code, out, errs)
	}
	if code, _, errs := ask("admin@example.com", "-config", "x.yaml"); code != 2 || !strings.Contains(errs, "-config only goes with -config, not -server") {
		t.Errorf("config with server: %d %q", code, errs)
	}

	// Not an answer: exit 2 and no decision printed, never a secret echoed.
	for _, user := range []string{"html@example.com", "weird@example.com"} {
		code, out, errs := ask(user)
		if code != 2 || out != "" || !strings.Contains(errs, "is it hallpass?") || strings.Contains(errs, "CANARY") {
			t.Errorf("%s: %d %q %q", user, code, out, errs)
		}
	}

	// Key must be a reference; the value never goes on the command line.
	if code, _, errs := ask("admin@example.com", "-api-key", "CANARY-SECRET-key"); code != 2 || !strings.Contains(errs, "-api-key:") || strings.Contains(errs, "CANARY") {
		t.Errorf("inline key: %d %q", code, errs)
	}
	if code, _, errs := ask("admin@example.com", "-api-key", "env:HALLPASS_NOPE"); code != 2 || !strings.Contains(errs, "HALLPASS_NOPE is not set") {
		t.Errorf("unset key: %d %q", code, errs)
	}
	keyFile := filepath.Join(t.TempDir(), "key")
	os.WriteFile(keyFile, []byte("CANARY-SECRET-key\n"), 0o600)
	if code, out, _ := ask("admin@example.com", "-api-key", "file:"+keyFile); code != 0 || !strings.HasPrefix(out, "allow") {
		t.Errorf("file key: %d %q", code, out)
	}

	// Plain http is only for loopback; the key would travel in clear text.
	if code, _, errs := capture(t, "check", "-server", "http://hallpass.example.com", "-connection", "demo", "-user", "a@b", "-action", "x", "-resource", "y:1"); code != 2 || !strings.Contains(errs, "must start with https://") {
		t.Errorf("http url: %d %q", code, errs)
	}
	// Unreachable server: exit 2, no decision.
	if code, out, errs := capture(t, "check", "-server", "http://127.0.0.1:1", "-connection", "demo", "-user", "a@b", "-action", "x", "-resource", "y:1"); code != 2 || out != "" || errs == "" {
		t.Errorf("unreachable: %d %q %q", code, out, errs)
	}
}
