// Package server exposes the engine over HTTP: POST /check and GET /healthz.
package server

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/roee-hersh/hallpass/internal/engine"
	"github.com/roee-hersh/hallpass/internal/integration"
	"github.com/roee-hersh/hallpass/internal/secret"
)

// MaxRequestBody bounds a /check body.
const MaxRequestBody = 64 << 10

// Checker is what the server needs from the engine.
type Checker interface {
	Check(ctx context.Context, req engine.Request) engine.Result
}

// Server is the HTTP handler.
type Server struct {
	checker Checker
	apiKey  secret.Secret
	logger  *slog.Logger
	mux     *http.ServeMux
}

// New builds the handler.
func New(c Checker, apiKey secret.Secret, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	s := &Server{checker: c, apiKey: apiKey, logger: logger, mux: http.NewServeMux()}
	s.mux.HandleFunc("/check", s.check)
	s.mux.HandleFunc("/healthz", s.healthz)
	return s
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rw := &statusWriter{ResponseWriter: w, status: 200}
	s.mux.ServeHTTP(rw, r)
	s.logger.Info("request", "method", r.Method, "path", r.URL.Path, "status", rw.status, "duration_ms", time.Since(start).Milliseconds(), "remote", remoteIP(r))
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// CheckBody is the wire request of POST /check. The command's -server mode
// sends it, so the two never drift apart.
type CheckBody struct {
	User       string   `json:"user"`
	Groups     []string `json:"groups,omitempty"`
	Connection string   `json:"connection"`
	Action     string   `json:"action"`
	Resource   string   `json:"resource"`
	// Fresh asks for an answer straight from the upstream system instead
	// of the caches. For a caller about to do something destructive.
	Fresh bool `json:"fresh,omitempty"`
}

// CheckResponse is the wire response of POST /check.
type CheckResponse struct {
	Decision integration.Outcome `json:"decision"`
	Reason   string              `json:"reason"`
}

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(`{"status":"ok"}` + "\n"))
}

func (s *Server) check(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeDecision(w, http.StatusMethodNotAllowed, integration.UnknownDecision(integration.CodeInvalidRequest, "use POST"))
		return
	}
	if !s.authorized(r) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="hallpass"`)
		writeDecision(w, http.StatusUnauthorized, integration.UnknownDecision(integration.CodeUnauthorized, "missing or wrong API key"))
		return
	}
	// The body is always parsed as JSON; the Content-Type header is not
	// checked so that `curl -d` works without extra flags.
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxRequestBody+1))
	if err != nil {
		writeDecision(w, http.StatusBadRequest, integration.UnknownDecision(integration.CodeInvalidRequest, "could not read body"))
		return
	}
	if len(body) > MaxRequestBody {
		writeDecision(w, http.StatusRequestEntityTooLarge, integration.UnknownDecision(integration.CodeInvalidRequest, "body larger than %d bytes", MaxRequestBody))
		return
	}
	var in CheckBody
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		writeDecision(w, http.StatusBadRequest, integration.UnknownDecision(integration.CodeInvalidRequest, "invalid JSON: %s", jsonErr(err)))
		return
	}
	if dec.More() {
		writeDecision(w, http.StatusBadRequest, integration.UnknownDecision(integration.CodeInvalidRequest, "invalid JSON: trailing data"))
		return
	}
	res := s.checker.Check(r.Context(), engine.Request{
		User:       in.User,
		Groups:     in.Groups,
		Connection: in.Connection,
		Action:     in.Action,
		Resource:   in.Resource,
		Fresh:      in.Fresh,
		Remote:     remoteIP(r),
	})
	writeDecision(w, res.Status, res.Decision)
}

// jsonErr keeps decoder messages, which may echo body fragments, short and
// free of the body itself.
func jsonErr(err error) string {
	var se *json.SyntaxError
	if errors.As(err, &se) || errors.Is(err, io.ErrUnexpectedEOF) {
		return "syntax error"
	}
	var ute *json.UnmarshalTypeError
	if errors.As(err, &ute) {
		return "wrong type for field " + ute.Field
	}
	msg := err.Error()
	if strings.HasPrefix(msg, "json: unknown field ") {
		return msg[len("json: "):]
	}
	if errors.Is(err, io.EOF) {
		return "empty body"
	}
	return "malformed body"
}

func writeDecision(w http.ResponseWriter, status int, d integration.Decision) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(CheckResponse{Decision: d.Outcome, Reason: d.Reason()})
}

func (s *Server) authorized(r *http.Request) bool {
	want, err := s.apiKey.Get()
	if err != nil {
		s.logger.Error("api key unavailable", "error", err.Error())
		return false
	}
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) < len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return false
	}
	got := strings.TrimSpace(h[len(prefix):])
	return subtle.ConstantTimeCompare([]byte(got), want) == 1
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
