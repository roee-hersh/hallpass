package integration

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/roee-hersh/hallpass/internal/catalog"
)

func TestOutcomeOf(t *testing.T) {
	if OutcomeOf(CodeAllowed) != Allow || OutcomeOf(CodeDenied) != Deny || OutcomeOf(CodeUserNotFound) != Deny {
		t.Fatal("wrong outcomes")
	}
	for _, c := range []Code{CodeUserAmbiguous, CodeUpstreamTimeout, CodeUpstreamError, CodeUpstreamRateLimit, CodeCredentialRejected, CodeResourceNotVisible, CodeUnsupported, CodeInvalidRequest, CodeUnknownConnection, CodeUnknownAction, CodeUnauthorized} {
		if OutcomeOf(c) != Unknown {
			t.Errorf("%s should be unknown", c)
		}
	}
	if d := UnknownDecision(CodeAllowed, "x"); d.Code != CodeUnsupported {
		t.Error("UnknownDecision must not allow")
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "t" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestToDecision(t *testing.T) {
	cases := []struct {
		err  error
		code Code
	}{
		{UserNotFound("no account"), CodeUserNotFound},
		{Wrap(CodeCredentialRejected, errors.New("401"), "bot rejected"), CodeCredentialRejected},
		{context.DeadlineExceeded, CodeUpstreamTimeout},
		{&net.OpError{Err: timeoutErr{}}, CodeUpstreamTimeout},
		{errors.New("boom"), CodeUpstreamError},
		{context.Canceled, CodeUpstreamError},
	}
	for _, c := range cases {
		d := ToDecision(c.err)
		if d.Code != c.code || d.Outcome != OutcomeOf(c.code) {
			t.Errorf("%v -> %+v", c.err, d)
		}
	}
	d := ToDecision(Wrap(CodeUpstreamError, errors.New("CANARY-SECRET-xyz"), "failed"))
	if d.Reason() != "upstream_error: failed" {
		t.Errorf("cause leaked into reason: %q", d.Reason())
	}
}

type stub struct {
	fields  []Field
	actions []catalog.Action
}

func (s stub) Name() string                                             { return "stub" }
func (s stub) Fields() []Field                                          { return s.fields }
func (s stub) Actions() []catalog.Action                                { return s.actions }
func (s stub) New(context.Context, *Settings, Deps) (Connection, error) { return nil, nil }
func (s stub) MatchAction(name string) (catalog.Action, bool) {
	if len(name) > 4 && name[:4] == "raw:" {
		return catalog.Action{Name: name}, true
	}
	return catalog.Action{}, false
}

func TestRegistry(t *testing.T) {
	r := NewRegistry()
	r.Register(stub{
		fields:  []Field{URLField(true, "u"), CredentialField(true, "c"), {Name: "namespace", Default: "argocd"}},
		actions: []catalog.Action{{Name: "a.b"}, {Name: "raw:<verb>:<resource>", Pattern: true}},
	})
	i, ok := r.Lookup("stub")
	if !ok {
		t.Fatal("not found")
	}
	if _, ok := FindAction(i, "a.b"); !ok {
		t.Error("exact action")
	}
	if _, ok := FindAction(i, "raw:get:pods"); !ok {
		t.Error("pattern action")
	}
	if _, ok := FindAction(i, "raw:<verb>:<resource>"); !ok {
		t.Error("pattern name matched by matcher")
	}
	if _, ok := FindAction(i, "nope"); ok {
		t.Error("unknown action found")
	}
	bad := []stub{
		{fields: []Field{{Name: "id"}}},
		{fields: []Field{{Name: "Bad"}}},
		{fields: []Field{{Name: "x"}, {Name: "x"}}},
		{fields: []Field{{Name: "k8s", Ref: "kubernetes"}}},
		{fields: []Field{{Name: "tok", Secret: true, Default: "x"}}},
		{actions: []catalog.Action{{Name: "a"}, {Name: "a"}}},
		{actions: []catalog.Action{{Name: "bad action"}}},
	}
	for n, b := range bad {
		if err := NewRegistry().register(b); err == nil {
			t.Errorf("bad %d accepted", n)
		}
	}
	if err := r.register(stub{}); err == nil {
		t.Error("duplicate accepted")
	}
	if len(r.Names()) != 1 {
		t.Error(r.Names())
	}
}

func TestSettings(t *testing.T) {
	s := NewSettings("a", "stub", map[string]string{"x": "true", "y": "no"}, nil)
	if !s.Bool("x", false) || s.Bool("y", true) || !s.Bool("z", true) {
		t.Error("bool")
	}
	if s.EffectiveTimeout() != DefaultTimeout {
		t.Error("timeout default")
	}
	s.Timeout = time.Second
	if s.EffectiveTimeout() != time.Second {
		t.Error("timeout")
	}
	if len(s.Keys()) != 2 || s.Keys()[0] != "x" {
		t.Error(s.Keys())
	}
}

func TestValidateHTTPSURL(t *testing.T) {
	for _, ok := range []string{
		"", "https://x", "http://localhost:8080", "http://localhost", "http://127.0.0.1:1",
		"http://127.0.0.1", "http://127.1.2.3/api", "http://[::1]:9", "http://[::1]",
	} {
		if err := ValidateHTTPSURL(ok); err != nil {
			t.Error(ok, err)
		}
	}
	for _, bad := range []string{
		"http://example.com", "https://x/?a=b", "https://x/#f", "ftp://x", "https://x y",
		// Loopback lookalikes: the host is not loopback, so a credential would
		// travel in clear text to wherever DNS points.
		"http://localhost.example.com", "http://localhostx", "http://localhost.evil:8080",
		"http://127.0.0.1.evil.com", "http://127.0.0.1x", "http://[::1].evil.com",
		"http://localhost@evil.com", "http://10.0.0.1", "http://[::2]", "https://u:p@x",
	} {
		if err := ValidateHTTPSURL(bad); err == nil {
			t.Error(bad, "accepted")
		}
	}
}
