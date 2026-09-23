package httpx

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/roee-hersh/hallpass/internal/integration"
)

const canary = "CANARY-SECRET-httpx"

func newTestClient(t *testing.T, srv *httptest.Server, logs *bytes.Buffer) *Client {
	t.Helper()
	pool := srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	hc, err := NewHTTPClient(Options{RootCAs: pool, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return &Client{
		HTTP:   hc,
		Base:   srv.URL,
		Logger: slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Sleep:  func(context.Context, time.Duration) error { return nil },
	}
}

func TestGetJSONAndNoBodyInLogs(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+canary {
			w.WriteHeader(401)
			return
		}
		if !strings.HasPrefix(r.UserAgent(), "hallpass/") {
			t.Errorf("user agent %q", r.UserAgent())
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true,"secret":"` + canary + `-body"}`))
	}))
	defer srv.Close()
	var logs bytes.Buffer
	c := newTestClient(t, srv, &logs)
	c.Auth = BearerAuth(func(context.Context) (string, error) { return canary, nil })
	var out struct{ OK bool }
	resp, err := c.GetJSON(context.Background(), "/x?a=b", url.Values{"token": {canary + "-q"}}, &out)
	if err != nil || !out.OK || resp.Status != 200 {
		t.Fatal(err, out, resp)
	}
	if strings.Contains(logs.String(), canary) {
		t.Fatalf("log leaked: %s", logs.String())
	}
	if !strings.Contains(logs.String(), `"path":"/x"`) {
		t.Fatalf("log missing path: %s", logs.String())
	}
}

func TestStatusErrorAndClassify(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		switch r.URL.Path {
		case "/401":
			w.WriteHeader(401)
		case "/403":
			w.WriteHeader(403)
			w.Write([]byte(`{"message":"` + canary + `"}`))
		case "/429":
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(429)
		case "/429long":
			w.Header().Set("Retry-After", "120")
			w.WriteHeader(429)
		case "/503":
			w.WriteHeader(503)
		case "/500post":
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()
	c := newTestClient(t, srv, &bytes.Buffer{})
	ctx := context.Background()

	_, err := c.Do(ctx, &Request{Path: "/401"})
	if Classify(err).Code != integration.CodeCredentialRejected {
		t.Errorf("401 -> %v", Classify(err))
	}
	calls.Store(0)
	_, err = c.Do(ctx, &Request{Path: "/403"})
	if Status(err) != 403 || calls.Load() != 1 {
		t.Errorf("403 status=%d calls=%d", Status(err), calls.Load())
	}
	var se *StatusError
	if !errors.As(err, &se) || !strings.Contains(se.Snippet, canary) {
		t.Error("snippet not kept for the integration")
	}
	if strings.Contains(se.Error(), canary) {
		t.Error("Error() leaked the body")
	}
	calls.Store(0)
	_, err = c.Do(ctx, &Request{Path: "/429"})
	if Classify(err).Code != integration.CodeUpstreamRateLimit || calls.Load() != 3 {
		t.Errorf("429: %v calls=%d", Classify(err), calls.Load())
	}
	calls.Store(0)
	_, err = c.Do(ctx, &Request{Path: "/429long"})
	if Classify(err).Code != integration.CodeUpstreamRateLimit || calls.Load() != 1 {
		t.Errorf("429 long: %v calls=%d", Classify(err), calls.Load())
	}
	calls.Store(0)
	_, err = c.Do(ctx, &Request{Path: "/503"})
	if Classify(err).Code != integration.CodeUpstreamError || calls.Load() != 3 {
		t.Errorf("503: %v calls=%d", Classify(err), calls.Load())
	}
	calls.Store(0)
	_, err = c.Do(ctx, &Request{Method: "POST", Path: "/500post", JSON: map[string]int{"a": 1}})
	if Classify(err).Code != integration.CodeUpstreamError || calls.Load() != 1 {
		t.Errorf("POST 500 retried: calls=%d", calls.Load())
	}
	resp, err := c.Do(ctx, &Request{Path: "/403", Accept4xx: true})
	if err != nil || resp.Status != 403 {
		t.Errorf("Accept4xx: %v", err)
	}
}

func TestTimeoutAndBodyCap(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/slow":
			select {
			case <-r.Context().Done():
			case <-time.After(3 * time.Second):
			}
		case "/big":
			w.Write(bytes.Repeat([]byte("x"), 2048))
		}
	}))
	defer srv.Close()
	c := newTestClient(t, srv, &bytes.Buffer{})
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := c.Do(ctx, &Request{Path: "/slow"})
	if Classify(err).Code != integration.CodeUpstreamTimeout {
		t.Errorf("timeout -> %v", Classify(err))
	}
	c.MaxBody = 1024
	_, err = c.Do(context.Background(), &Request{Path: "/big"})
	if !errors.Is(err, ErrBodyTooLarge) {
		t.Errorf("big -> %v", err)
	}
}

func TestNoRedirects(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://evil.example/", 302)
	}))
	defer srv.Close()
	c := newTestClient(t, srv, &bytes.Buffer{})
	resp, err := c.Do(context.Background(), &Request{Path: "/"})
	if err != nil || resp.Status != 302 {
		t.Fatal(resp, err)
	}
}

func TestCAFileAndTLSMin(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("{}")) }))
	defer srv.Close()
	pemPath := filepath.Join(t.TempDir(), "ca.pem")
	cert := srv.Certificate()
	pemData := "-----BEGIN CERTIFICATE-----\n" + base64Lines(cert.Raw) + "-----END CERTIFICATE-----\n"
	if err := os.WriteFile(pemPath, []byte(pemData), 0o600); err != nil {
		t.Fatal(err)
	}
	hc, err := NewHTTPClient(Options{CAFile: pemPath})
	if err != nil {
		t.Fatal(err)
	}
	c := &Client{HTTP: hc, Base: srv.URL}
	if _, err := c.Do(context.Background(), &Request{Path: "/"}); err != nil {
		t.Fatalf("with ca_file: %v", err)
	}
	hc2, _ := NewHTTPClient(Options{})
	c2 := &Client{HTTP: hc2, Base: srv.URL}
	if _, err := c2.Do(context.Background(), &Request{Path: "/"}); err == nil {
		t.Fatal("system roots accepted the test certificate")
	}
	if _, err := NewHTTPClient(Options{CAFile: filepath.Join(t.TempDir(), "missing")}); err == nil {
		t.Fatal("missing ca_file accepted")
	}
	if _, err := NewHTTPClient(Options{ProxyURL: "socks5://x"}); err == nil {
		t.Fatal("bad proxy accepted")
	}
}

func base64Lines(b []byte) string {
	const enc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var sb strings.Builder
	var out []byte
	for i := 0; i < len(b); i += 3 {
		var n uint32
		rem := len(b) - i
		for j := 0; j < 3; j++ {
			n <<= 8
			if j < rem {
				n |= uint32(b[i+j])
			}
		}
		for j := 0; j < 4; j++ {
			if j <= rem {
				out = append(out, enc[(n>>(18-6*j))&63])
			} else {
				out = append(out, '=')
			}
		}
	}
	for i := 0; i < len(out); i += 64 {
		end := i + 64
		if end > len(out) {
			end = len(out)
		}
		sb.Write(out[i:end])
		sb.WriteByte('\n')
	}
	return sb.String()
}

func TestLinkNextAndPaginate(t *testing.T) {
	h := http.Header{}
	h.Add("Link", `<https://api.example/x?page=2>; rel="next", <https://api.example/x?page=9>; rel="last"`)
	if LinkNext(h) != "https://api.example/x?page=2" {
		t.Fatal(LinkNext(h))
	}
	if LinkNext(http.Header{}) != "" {
		t.Fatal("empty")
	}
	var pages atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pages.Add(1)
		w.Header().Set("Link", "<"+"https://"+r.Host+"/p>; rel=\"next\"")
		w.Write([]byte("[]"))
	}))
	defer srv.Close()
	c := newTestClient(t, srv, &bytes.Buffer{})
	err := c.Paginate(context.Background(), &Request{Path: "/p"}, func(r *Response) (*Request, error) {
		if n := LinkNext(r.Header); n != "" {
			return &Request{Path: n}, nil
		}
		return nil, nil
	})
	if !errors.Is(err, ErrTooManyPages) || pages.Load() != MaxPages {
		t.Fatalf("err=%v pages=%d", err, pages.Load())
	}
}

func TestNextLinkStaysWithinBase(t *testing.T) {
	c := &Client{Base: "https://gitlab.example/api/v4"}
	link := func(u string) http.Header {
		h := http.Header{}
		h.Set("Link", "<"+u+">; rel=\"next\"")
		return h
	}
	for _, ok := range []string{
		"https://gitlab.example/api/v4/projects/1/protected_branches?page=2",
		"https://GITLAB.example/api/v4/x",
		"/api/v4/x?page=2",
	} {
		if got, err := c.NextLink(link(ok)); err != nil || got == "" {
			t.Errorf("%s: got %q err %v", ok, got, err)
		}
	}
	for _, bad := range []string{
		"https://evil.example/api/v4/x",
		"http://gitlab.example/api/v4/x",
		"https://gitlab.example/oauth/token",
		"https://gitlab.example/api/v4x",
		"https://" + canary + "@gitlab.example/api/v4/x",
		"https://gitlab.example:8443/api/v4/x",
	} {
		got, err := c.NextLink(link(bad))
		if err == nil || got != "" {
			t.Errorf("%s: got %q err %v", bad, got, err)
		}
		if err != nil && strings.Contains(err.Error(), canary) {
			t.Errorf("error leaks userinfo: %v", err)
		}
	}
	if got, err := c.NextLink(http.Header{}); err != nil || got != "" {
		t.Errorf("no header: %q %v", got, err)
	}
}

func TestRetryAfterDate(t *testing.T) {
	h := http.Header{}
	h.Set("Retry-After", time.Now().Add(3*time.Second).UTC().Format(http.TimeFormat))
	if d := retryAfter(h); d <= 0 || d > 4*time.Second {
		t.Fatal(d)
	}
	h.Set("Retry-After", "garbage")
	if retryAfter(h) != 0 {
		t.Fatal("garbage")
	}
}

func TestRedact(t *testing.T) {
	if s := redactURL("https://u:" + canary + "@h/p?token=" + canary); strings.Contains(s, canary) {
		t.Fatal(s)
	}
	e := &url.Error{Op: "Get", URL: "https://h/p?token=" + canary, Err: errors.New("x")}
	if strings.Contains(redactErr(e), canary) {
		t.Fatal("redactErr")
	}
	if PathEscape("a/b c") != "a%2Fb%20c" {
		t.Fatal(PathEscape("a/b c"))
	}
}

func TestTransportTimeoutsFollowOption(t *testing.T) {
	// A long per-connection timeout must not be capped by a fixed header
	// wait; connect and handshake stay bounded by min(5s, timeout).
	tr, err := NewTransport(Options{Timeout: 12 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if tr.ResponseHeaderTimeout != 0 && tr.ResponseHeaderTimeout < 12*time.Second {
		t.Errorf("ResponseHeaderTimeout %v caps a 12s timeout", tr.ResponseHeaderTimeout)
	}
	if tr.TLSHandshakeTimeout != 5*time.Second {
		t.Errorf("TLSHandshakeTimeout %v, want 5s for a 12s timeout", tr.TLSHandshakeTimeout)
	}
	tr, err = NewTransport(Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if tr.TLSHandshakeTimeout != 2*time.Second {
		t.Errorf("TLSHandshakeTimeout %v, want 2s for a 2s timeout", tr.TLSHandshakeTimeout)
	}
	tr, err = NewTransport(Options{})
	if err != nil {
		t.Fatal(err)
	}
	if tr.ResponseHeaderTimeout != 0 && tr.ResponseHeaderTimeout < integration.DefaultTimeout {
		t.Errorf("ResponseHeaderTimeout %v caps the default timeout", tr.ResponseHeaderTimeout)
	}
}

func TestSlowHeadersWithinTimeout(t *testing.T) {
	// The upstream answers after 1.5 s. A connection whose timeout is 3 s
	// must get the response; one whose timeout is 500 ms must time out.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			return
		case <-time.After(1500 * time.Millisecond):
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	pool := srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	for _, tc := range []struct {
		timeout time.Duration
		ok      bool
	}{{3 * time.Second, true}, {500 * time.Millisecond, false}} {
		hc, err := NewHTTPClient(Options{RootCAs: pool, Timeout: tc.timeout})
		if err != nil {
			t.Fatal(err)
		}
		c := &Client{HTTP: hc, Base: srv.URL, Sleep: func(context.Context, time.Duration) error { return nil }}
		var out struct{ OK bool }
		_, err = c.GetJSON(context.Background(), "/", nil, &out)
		if tc.ok && (err != nil || !out.OK) {
			t.Errorf("timeout %v: %v (ok=%v)", tc.timeout, err, out.OK)
		}
		if !tc.ok && Classify(err).Code != integration.CodeUpstreamTimeout {
			t.Errorf("timeout %v: got %v, want upstream_timeout", tc.timeout, Classify(err))
		}
	}
}

// Every completed response is recorded as evidence on the context's
// recorder: method, path, status and the ETag or the body's hash. The
// query, the headers and the body stay out, and a token exchange made from
// Auth is not recorded at all.
func TestEvidence(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			w.Write([]byte(`{"access_token":"` + canary + `-token"}`))
		case "/etag":
			w.Header().Set("ETag", `W/"v7"`)
			w.Write([]byte(`{"a":1}`))
		case "/badetag":
			w.Header().Set("ETag", strings.Repeat("x", 200))
			w.Write([]byte(`{"a":1}`))
		case "/plain":
			w.Write([]byte(`{"secret":"` + canary + `-body"}`))
		case "/empty":
			w.WriteHeader(204)
		case "/denied":
			w.WriteHeader(403)
			w.Write([]byte(`{"message":"no"}`))
		}
	}))
	defer srv.Close()
	c := newTestClient(t, srv, &bytes.Buffer{})
	// Auth fetches a token through a plain client, as integrations do.
	plain := newTestClient(t, srv, &bytes.Buffer{})
	c.Auth = BearerAuth(func(ctx context.Context) (string, error) {
		var tok struct {
			AccessToken string `json:"access_token"`
		}
		if _, err := plain.PostJSON(ctx, "/token", map[string]string{}, &tok, true); err != nil {
			return "", err
		}
		return tok.AccessToken, nil
	})
	ctx, rec := integration.WithRecorder(context.Background())
	for _, p := range []string{"/etag", "/badetag", "/plain", "/empty"} {
		if _, err := c.Do(ctx, &Request{Path: p + "?token=" + canary + "-q", Header: http.Header{"X-Secret": {canary + "-h"}}}); err != nil {
			t.Fatal(p, err)
		}
	}
	if _, err := c.Do(ctx, &Request{Path: "/denied"}); Status(err) != 403 {
		t.Fatal(err)
	}
	ev := rec.Evidence()
	if ev == nil || len(ev.Upstream) != 5 {
		t.Fatalf("%+v", ev)
	}
	sum := sha256.Sum256([]byte(`{"a":1}`))
	want := []integration.Call{
		{Method: "GET", Path: "/etag", Status: 200, ETag: `W/"v7"`},
		{Method: "GET", Path: "/badetag", Status: 200, SHA256: hex.EncodeToString(sum[:])},
		{Method: "GET", Path: "/plain", Status: 200, SHA256: func() string {
			s := sha256.Sum256([]byte(`{"secret":"` + canary + `-body"}`))
			return hex.EncodeToString(s[:])
		}()},
		{Method: "GET", Path: "/empty", Status: 204},
		{Method: "GET", Path: "/denied", Status: 403, SHA256: func() string {
			s := sha256.Sum256([]byte(`{"message":"no"}`))
			return hex.EncodeToString(s[:])
		}()},
	}
	for i, w := range want {
		if ev.Upstream[i] != w {
			t.Errorf("call %d:\n got %+v\nwant %+v", i, ev.Upstream[i], w)
		}
	}
	b, _ := json.Marshal(ev)
	if strings.Contains(string(b), canary) || strings.Contains(string(b), "token") {
		t.Fatalf("evidence leaked: %s", b)
	}
	// A request that never got a response leaves no evidence.
	srv.Close()
	rec2ctx, rec2 := integration.WithRecorder(context.Background())
	c.Do(rec2ctx, &Request{Path: "/plain"})
	if rec2.Evidence() != nil {
		t.Fatalf("evidence for a failed transport: %+v", rec2.Evidence())
	}
}
