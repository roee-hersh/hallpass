// Package httpx is the one HTTP client every integration uses.
//
// It builds a per-connection transport (TLS 1.2+, private CA, proxy, server
// name), never follows redirects, caps response bodies, retries only
// idempotent calls with jittered backoff, honours Retry-After, and never logs
// request or response bodies.
package httpx

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/roee-hersh/hallpass/internal/integration"
)

// Version is stamped into the User-Agent header. main sets it from the build.
var Version = "dev"

// MaxBody is the response size cap. Larger bodies are an error.
const MaxBody = 10 << 20

// MaxPages caps pagination loops.
const MaxPages = 50

// Options build a transport for one connection.
type Options struct {
	// CAFile, when set, replaces the system roots.
	CAFile string
	// TLSServerName overrides the name verified against the certificate,
	// for systems addressed by IP.
	TLSServerName string
	// ProxyURL routes requests through an HTTP(S) proxy. Empty means the
	// environment proxy settings.
	ProxyURL string
	// Timeout bounds one whole request including retries. Zero means 8 s.
	Timeout time.Duration
	// RootCAs lets tests inject a pool directly.
	RootCAs *x509.CertPool
}

// NewTransport builds an *http.Transport from Options.
func NewTransport(o Options) (*http.Transport, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if o.RootCAs != nil {
		tlsCfg.RootCAs = o.RootCAs
	} else if o.CAFile != "" {
		pem, err := os.ReadFile(o.CAFile)
		if err != nil {
			return nil, fmt.Errorf("ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ca_file %s: no PEM certificates found", o.CAFile)
		}
		tlsCfg.RootCAs = pool
	}
	if o.TLSServerName != "" {
		tlsCfg.ServerName = o.TLSServerName
	}
	t := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:       tlsCfg,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		ExpectContinueTimeout: time.Second,
		MaxIdleConns:          20,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	if o.ProxyURL != "" {
		pu, err := url.Parse(o.ProxyURL)
		if err != nil || (pu.Scheme != "http" && pu.Scheme != "https") || pu.Host == "" {
			return nil, fmt.Errorf("proxy_url %q must be an http:// or https:// URL", o.ProxyURL)
		}
		t.Proxy = http.ProxyURL(pu)
	}
	return t, nil
}

// NewHTTPClient builds a plain *http.Client that never follows redirects.
func NewHTTPClient(o Options) (*http.Client, error) {
	t, err := NewTransport(o)
	if err != nil {
		return nil, err
	}
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = integration.DefaultTimeout
	}
	return &http.Client{
		Transport: t,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

// Client wraps an *http.Client with the conventions integrations need.
type Client struct {
	HTTP *http.Client
	// Base is prepended to relative request paths.
	Base string
	// Auth adds credentials to each request. It runs before every attempt so
	// a refreshed token is picked up on retry.
	Auth func(ctx context.Context, r *http.Request) error
	// Logger receives one debug line per call: method, host, path, status,
	// duration. Never bodies or headers.
	Logger *slog.Logger
	// Retries is the number of extra attempts for idempotent calls (default 2).
	Retries int
	// MaxBody caps the body size (default MaxBody).
	MaxBody int64
	// Sleep is replaced in tests.
	Sleep func(context.Context, time.Duration) error
	// UserAgent overrides the default.
	UserAgent string
}

// Request is one call.
type Request struct {
	Method string
	// Path is absolute (https://...) or relative to Client.Base.
	Path   string
	Query  url.Values
	Header http.Header
	// Body is sent as-is. JSON sets Body and Content-Type from a value.
	Body []byte
	JSON any
	// Form sets Body and Content-Type from URL-encoded values.
	Form url.Values
	// Idempotent overrides the method-based default (GET/HEAD/OPTIONS).
	Idempotent *bool
	// Accept4xx keeps 4xx responses from becoming errors.
	Accept4xx bool
}

// Response is what Do returns for any HTTP status.
type Response struct {
	Status int
	Header http.Header
	Body   []byte
}

// JSON decodes the body into v.
func (r *Response) JSON(v any) error {
	if len(bytes.TrimSpace(r.Body)) == 0 {
		return errors.New("empty body")
	}
	dec := json.NewDecoder(bytes.NewReader(r.Body))
	dec.UseNumber()
	return dec.Decode(v)
}

// StatusError is returned for 4xx and 5xx responses (unless Accept4xx).
type StatusError struct {
	Status int
	Method string
	URL    string
	// Snippet is the first bytes of the body, for the integration's own
	// classification. It must not be copied into a decision text verbatim.
	Snippet string
	Header  http.Header
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("%s %s: HTTP %d", e.Method, redactURL(e.URL), e.Status)
}

// RetryAfter parses the Retry-After header (seconds or HTTP date).
func (e *StatusError) RetryAfter() time.Duration { return retryAfter(e.Header) }

// ErrBodyTooLarge is returned when the response exceeds MaxBody.
var ErrBodyTooLarge = errors.New("response body exceeds size limit")

func (c *Client) sleep(ctx context.Context, d time.Duration) error {
	if c.Sleep != nil {
		return c.Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (c *Client) build(ctx context.Context, r *Request) (*http.Request, error) {
	u := r.Path
	if !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://") {
		if c.Base == "" {
			return nil, fmt.Errorf("relative path %q with no base URL", r.Path)
		}
		u = strings.TrimRight(c.Base, "/") + "/" + strings.TrimLeft(r.Path, "/")
	}
	if len(r.Query) > 0 {
		sep := "?"
		if strings.Contains(u, "?") {
			sep = "&"
		}
		u += sep + r.Query.Encode()
	}
	var body io.Reader
	var ctype string
	switch {
	case r.JSON != nil:
		b, err := json.Marshal(r.JSON)
		if err != nil {
			return nil, err
		}
		body, ctype = bytes.NewReader(b), "application/json"
	case r.Form != nil:
		body, ctype = strings.NewReader(r.Form.Encode()), "application/x-www-form-urlencoded"
	case r.Body != nil:
		body = bytes.NewReader(r.Body)
	}
	method := r.Method
	if method == "" {
		method = http.MethodGet
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, err
	}
	for k, vs := range r.Header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if ctype != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", ctype)
	}
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "application/json")
	}
	ua := c.UserAgent
	if ua == "" {
		ua = "hallpass/" + Version
	}
	req.Header.Set("User-Agent", ua)
	if c.Auth != nil {
		if err := c.Auth(ctx, req); err != nil {
			return nil, err
		}
	}
	return req, nil
}

func (r *Request) idempotent() bool {
	if r.Idempotent != nil {
		return *r.Idempotent
	}
	switch r.Method {
	case "", http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	return false
}

// Do performs the request. Retries happen only for idempotent requests on
// connection errors, 502/503/504 and 429 with a short Retry-After.
func (c *Client) Do(ctx context.Context, r *Request) (*Response, error) {
	if ctx == nil {
		return nil, errors.New("nil context")
	}
	retries := c.Retries
	if retries == 0 {
		retries = 2
	}
	if !r.idempotent() {
		retries = 0
	}
	var lastErr error
	for attempt := 0; ; attempt++ {
		resp, err := c.once(ctx, r)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if attempt >= retries || !retryable(err) {
			return resp, err
		}
		wait := backoff(attempt)
		var se *StatusError
		if errors.As(err, &se) {
			if ra := se.RetryAfter(); ra > 0 {
				if ra > 5*time.Second {
					return resp, err
				}
				wait = ra
			}
		}
		if err := c.sleep(ctx, wait); err != nil {
			return nil, lastErr
		}
	}
}

func (c *Client) once(ctx context.Context, r *Request) (*Response, error) {
	req, err := c.build(ctx, r)
	if err != nil {
		return nil, err
	}
	start := time.Now()
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	res, err := hc.Do(req)
	if err != nil {
		c.logCall(req, 0, start, err)
		return nil, &transportError{err: err}
	}
	defer res.Body.Close()
	max := c.MaxBody
	if max <= 0 {
		max = MaxBody
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, max+1))
	if err != nil {
		c.logCall(req, res.StatusCode, start, err)
		return nil, &transportError{err: err}
	}
	if int64(len(body)) > max {
		c.logCall(req, res.StatusCode, start, ErrBodyTooLarge)
		return nil, ErrBodyTooLarge
	}
	c.logCall(req, res.StatusCode, start, nil)
	out := &Response{Status: res.StatusCode, Header: res.Header, Body: body}
	if res.StatusCode >= 400 && !(r.Accept4xx && res.StatusCode < 500) {
		return out, &StatusError{
			Status:  res.StatusCode,
			Method:  req.Method,
			URL:     req.URL.String(),
			Snippet: snippet(body),
			Header:  res.Header,
		}
	}
	return out, nil
}

func (c *Client) logCall(req *http.Request, status int, start time.Time, err error) {
	if c.Logger == nil {
		return
	}
	attrs := []any{
		"method", req.Method, "host", req.URL.Host, "path", req.URL.Path,
		"status", status, "duration_ms", time.Since(start).Milliseconds(),
	}
	if err != nil {
		attrs = append(attrs, "error", redactErr(err))
	}
	c.Logger.Debug("http", attrs...)
}

type transportError struct{ err error }

func (t *transportError) Error() string { return "transport: " + redactErr(t.err) }
func (t *transportError) Unwrap() error { return t.err }
func (t *transportError) Timeout() bool {
	var ne net.Error
	return errors.As(t.err, &ne) && ne.Timeout()
}

func retryable(err error) bool {
	var se *StatusError
	if errors.As(err, &se) {
		switch se.Status {
		case 429, 502, 503, 504:
			return true
		}
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrBodyTooLarge) {
		return false
	}
	var te *transportError
	if errors.As(err, &te) {
		// Connection resets, refused connections and DNS hiccups are worth
		// one more try. Client-side timeouts are not: the budget is spent.
		return !te.Timeout()
	}
	return false
}

func backoff(attempt int) time.Duration {
	base := 200 * time.Millisecond << uint(attempt)
	if base > 2*time.Second {
		base = 2 * time.Second
	}
	jitter := time.Duration(rand.Int64N(int64(base) / 2))
	return base/2 + jitter
}

func retryAfter(h http.Header) time.Duration {
	v := strings.TrimSpace(h.Get("Retry-After"))
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs < 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		d := time.Until(t)
		if d < 0 {
			return 0
		}
		return d
	}
	return 0
}

func snippet(b []byte) string {
	const n = 256
	s := string(bytes.ToValidUTF8(b, nil))
	if len(s) > n {
		s = s[:n]
	}
	return s
}

// redactURL strips query strings and userinfo, which may carry tokens.
func redactURL(s string) string {
	u, err := url.Parse(s)
	if err != nil {
		return "<url>"
	}
	u.RawQuery = ""
	u.Fragment = ""
	u.User = nil
	return u.String()
}

// redactErr strips URLs inside transport errors, which can carry query
// parameters, and keeps the message short.
func redactErr(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Op + " " + redactURL(ue.URL) + ": " + ue.Err.Error()
	}
	return err.Error()
}

// Classify turns a transport or status error into an *integration.Error with
// the right code: timeout, rate limit, 401 -> credential_rejected, 5xx ->
// upstream_error. Other 4xx are returned as upstream_error too; integrations
// that need finer handling of 403/404 inspect *StatusError first.
func Classify(err error) *integration.Error {
	if err == nil {
		return nil
	}
	var ie *integration.Error
	if errors.As(err, &ie) {
		return ie
	}
	var se *StatusError
	if errors.As(err, &se) {
		switch {
		case se.Status == 401:
			return integration.Wrap(integration.CodeCredentialRejected, err, "the connection's credential was rejected (HTTP 401)")
		case se.Status == 429:
			return integration.Wrap(integration.CodeUpstreamRateLimit, err, "rate limited by the upstream system")
		case se.Status >= 500:
			return integration.Wrap(integration.CodeUpstreamError, err, "upstream returned HTTP %d", se.Status)
		default:
			return integration.Wrap(integration.CodeUpstreamError, err, "upstream returned HTTP %d", se.Status)
		}
	}
	if errors.Is(err, ErrBodyTooLarge) {
		return integration.Wrap(integration.CodeUpstreamError, err, "upstream response too large")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return integration.Wrap(integration.CodeUpstreamTimeout, err, "upstream call timed out")
	}
	var te *transportError
	if errors.As(err, &te) {
		if te.Timeout() {
			return integration.Wrap(integration.CodeUpstreamTimeout, err, "upstream call timed out")
		}
		return integration.Wrap(integration.CodeUpstreamError, err, "could not reach the upstream system")
	}
	return integration.Wrap(integration.CodeUpstreamError, err, "upstream call failed")
}

// Status returns the HTTP status carried by err, or 0. An error that has
// already been classified into an *integration.Error reports 0, so a
// failure from an earlier stage (a token exchange, a lookup inside Auth) is
// never mistaken for a status of the call at hand.
func Status(err error) int {
	var ie *integration.Error
	if errors.As(err, &ie) {
		return 0
	}
	var se *StatusError
	if errors.As(err, &se) {
		return se.Status
	}
	return 0
}

// GetJSON is Do + JSON decode for a GET.
func (c *Client) GetJSON(ctx context.Context, path string, q url.Values, out any) (*Response, error) {
	resp, err := c.Do(ctx, &Request{Method: http.MethodGet, Path: path, Query: q})
	if err != nil {
		return resp, err
	}
	if out != nil {
		if err := resp.JSON(out); err != nil {
			return resp, fmt.Errorf("decode %s: %w", redactURL(path), err)
		}
	}
	return resp, nil
}

// PostJSON is Do + JSON decode for a POST with a JSON body. POST is not
// retried unless idempotent is set.
func (c *Client) PostJSON(ctx context.Context, path string, in, out any, idempotent bool) (*Response, error) {
	resp, err := c.Do(ctx, &Request{Method: http.MethodPost, Path: path, JSON: in, Idempotent: &idempotent})
	if err != nil {
		return resp, err
	}
	if out != nil {
		if err := resp.JSON(out); err != nil {
			return resp, fmt.Errorf("decode %s: %w", redactURL(path), err)
		}
	}
	return resp, nil
}

// LinkNext extracts the rel="next" URL from an RFC 8288 Link header.
func LinkNext(h http.Header) string {
	for _, link := range h.Values("Link") {
		for _, part := range strings.Split(link, ",") {
			seg := strings.Split(strings.TrimSpace(part), ";")
			if len(seg) < 2 {
				continue
			}
			u := strings.TrimSpace(seg[0])
			if !strings.HasPrefix(u, "<") || !strings.HasSuffix(u, ">") {
				continue
			}
			for _, p := range seg[1:] {
				p = strings.TrimSpace(p)
				if p == `rel="next"` || p == "rel=next" {
					return strings.TrimSuffix(strings.TrimPrefix(u, "<"), ">")
				}
			}
		}
	}
	return ""
}

// NextLink returns the rel="next" URL of an RFC 8288 Link header when it
// stays within the client's base URL, "" when there is none, and an error
// when the upstream points elsewhere: the client attaches its credential
// to every request, so a next link on another host would carry the
// credential there.
func (c *Client) NextLink(h http.Header) (string, error) {
	next := LinkNext(h)
	if next == "" {
		return "", nil
	}
	if !c.within(next) {
		return "", fmt.Errorf("next page link %s is outside the client's base URL", redactURL(next))
	}
	return next, nil
}

// within reports whether rawURL is a page under c.Base: same scheme and
// host, and a path under the base path. A relative path always is.
func (c *Client) within(rawURL string) bool {
	if !strings.HasPrefix(rawURL, "https://") && !strings.HasPrefix(rawURL, "http://") {
		return true
	}
	base, err := url.Parse(c.Base)
	if err != nil || base.Host == "" {
		return false
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.User != nil {
		return false
	}
	if u.Scheme != base.Scheme || !strings.EqualFold(u.Host, base.Host) {
		return false
	}
	prefix := strings.TrimRight(base.Path, "/")
	return u.Path == prefix || strings.HasPrefix(u.Path, prefix+"/")
}

// ErrTooManyPages is returned when pagination exceeds MaxPages.
var ErrTooManyPages = errors.New("pagination exceeded the page limit")

// Paginate runs req, calls page with each response, and follows the request
// page returns until it returns nil. It stops with ErrTooManyPages after
// MaxPages pages.
func (c *Client) Paginate(ctx context.Context, req *Request, page func(*Response) (*Request, error)) error {
	for n := 0; req != nil; n++ {
		if n >= MaxPages {
			return ErrTooManyPages
		}
		resp, err := c.Do(ctx, req)
		if err != nil {
			return err
		}
		req, err = page(resp)
		if err != nil {
			return err
		}
	}
	return nil
}

// PathEscape escapes one path segment. Slashes are encoded, so the value
// cannot climb out of its position in a path template.
func PathEscape(s string) string { return url.PathEscape(s) }

// BearerAuth returns an Auth func that sets a static bearer token.
func BearerAuth(token func(ctx context.Context) (string, error)) func(context.Context, *http.Request) error {
	return func(ctx context.Context, r *http.Request) error {
		t, err := token(ctx)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+t)
		return nil
	}
}

// BasicAuth returns an Auth func that sets HTTP basic credentials.
func BasicAuth(user string, password func(ctx context.Context) (string, error)) func(context.Context, *http.Request) error {
	return func(ctx context.Context, r *http.Request) error {
		p, err := password(ctx)
		if err != nil {
			return err
		}
		r.SetBasicAuth(user, p)
		return nil
	}
}

// HeaderAuth returns an Auth func that sets one header to a secret value.
func HeaderAuth(name string, value func(ctx context.Context) (string, error)) func(context.Context, *http.Request) error {
	return func(ctx context.Context, r *http.Request) error {
		v, err := value(ctx)
		if err != nil {
			return err
		}
		r.Header.Set(name, v)
		return nil
	}
}
