package integration

import (
	"context"
	"errors"
	"fmt"
	"net"
)

// Outcome is the answer to a check.
type Outcome string

const (
	Allow   Outcome = "allow"
	Deny    Outcome = "deny"
	Unknown Outcome = "unknown"
)

// Code is a stable, machine-readable reason. The set is closed; integrations
// pick from it and never invent new ones.
type Code string

const (
	CodeAllowed            Code = "allowed"
	CodeDenied             Code = "denied"
	CodeUserNotFound       Code = "user_not_found"
	CodeUserAmbiguous      Code = "user_ambiguous"
	CodeUpstreamTimeout    Code = "upstream_timeout"
	CodeUpstreamError      Code = "upstream_error"
	CodeUpstreamRateLimit  Code = "upstream_rate_limited"
	CodeCredentialRejected Code = "credential_rejected"
	CodeResourceNotVisible Code = "resource_not_visible"
	CodeUnsupported        Code = "unsupported"
	CodeInvalidRequest     Code = "invalid_request"
	CodeUnknownConnection  Code = "unknown_connection"
	CodeUnknownAction      Code = "unknown_action"
	CodeUnauthorized       Code = "unauthorized"
)

// OutcomeOf maps a code to the only outcome it may carry. Allowed is allow,
// denied and user_not_found are deny, everything else is unknown.
func OutcomeOf(c Code) Outcome {
	switch c {
	case CodeAllowed:
		return Allow
	case CodeDenied, CodeUserNotFound:
		return Deny
	default:
		return Unknown
	}
}

// Decision is what a Connection returns from Check.
type Decision struct {
	Outcome Outcome
	Code    Code
	// Text is a short human-readable explanation. It must not contain secrets.
	Text string
	// Evidence is what the upstream system said when the decision was
	// computed. The engine fills it from the calls httpx recorded;
	// integrations leave it nil.
	Evidence *Evidence
}

// Reason renders "<code>: <text>", the wire form of the reason field.
func (d Decision) Reason() string {
	if d.Text == "" {
		return string(d.Code)
	}
	return string(d.Code) + ": " + d.Text
}

// Allowed builds an allow decision.
func Allowed(format string, args ...any) Decision {
	return Decision{Outcome: Allow, Code: CodeAllowed, Text: fmt.Sprintf(format, args...)}
}

// Denied builds a deny decision. The upstream system positively said no.
func Denied(format string, args ...any) Decision {
	return Decision{Outcome: Deny, Code: CodeDenied, Text: fmt.Sprintf(format, args...)}
}

// UnknownDecision builds an unknown decision with the given code.
// Codes whose outcome is not unknown are coerced to unsupported.
func UnknownDecision(code Code, format string, args ...any) Decision {
	if OutcomeOf(code) != Unknown {
		code = CodeUnsupported
	}
	return Decision{Outcome: Unknown, Code: code, Text: fmt.Sprintf(format, args...)}
}

// Unsupported is UnknownDecision with CodeUnsupported.
func Unsupported(format string, args ...any) Decision {
	return UnknownDecision(CodeUnsupported, format, args...)
}

// Error is an error that carries a decision code. Integrations return it from
// ResolveIdentity and Check when they cannot evaluate; the engine turns it
// into the matching decision. Wrapping keeps the cause for logs.
type Error struct {
	Code Code
	Text string
	Err  error
}

func (e *Error) Error() string {
	s := string(e.Code)
	if e.Text != "" {
		s += ": " + e.Text
	}
	if e.Err != nil {
		s += " (" + e.Err.Error() + ")"
	}
	return s
}

func (e *Error) Unwrap() error { return e.Err }

// Decision converts the error into a decision.
func (e *Error) Decision() Decision {
	return Decision{Outcome: OutcomeOf(e.Code), Code: e.Code, Text: e.Text}
}

// Errorf builds an *Error.
func Errorf(code Code, format string, args ...any) *Error {
	return &Error{Code: code, Text: fmt.Sprintf(format, args...)}
}

// Wrap builds an *Error around a cause.
func Wrap(code Code, err error, format string, args ...any) *Error {
	return &Error{Code: code, Text: fmt.Sprintf(format, args...), Err: err}
}

// UserNotFound is the error for an email with no account.
func UserNotFound(format string, args ...any) *Error {
	return Errorf(CodeUserNotFound, format, args...)
}

// UserAmbiguous is the error for an email that matches several accounts.
func UserAmbiguous(format string, args ...any) *Error {
	return Errorf(CodeUserAmbiguous, format, args...)
}

// ToDecision converts any error into a decision. *Error keeps its code;
// deadline and timeout errors become upstream_timeout; everything else is
// upstream_error. The wrapped cause is never put into the text.
func ToDecision(err error) Decision {
	var ie *Error
	if errors.As(err, &ie) {
		return ie.Decision()
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return UnknownDecision(CodeUpstreamTimeout, "upstream call timed out")
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return UnknownDecision(CodeUpstreamTimeout, "upstream call timed out")
	}
	if errors.Is(err, context.Canceled) {
		return UnknownDecision(CodeUpstreamError, "request cancelled")
	}
	return UnknownDecision(CodeUpstreamError, "upstream call failed")
}
