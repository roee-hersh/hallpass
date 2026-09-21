// Package secret holds credential material that must never be printed.
//
// A Secret is created from a reference such as "env:NAME" or "file:/path".
// The value is resolved on every Get call, so a rotated file (for example a
// projected Kubernetes ServiceAccount token) keeps working without a restart.
// String, MarshalJSON, Format and LogValue always produce "[REDACTED]".
package secret

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
)

// Redacted is the only text a Secret ever prints.
const Redacted = "[REDACTED]"

// Secret is a reference to credential material.
// The zero value is empty and Get returns ErrEmpty.
type Secret struct {
	kind string // "env", "file", "literal" or "" (empty)
	ref  string // env var name, file path or the literal itself
}

// ErrEmpty is returned by Get on the zero Secret.
var ErrEmpty = errors.New("secret: empty")

// Parse turns a config reference into a Secret.
// Accepted forms: "env:NAME" and "file:/path". Anything else is rejected so a
// plain credential can never be written into the config file by mistake.
func Parse(ref string) (Secret, error) {
	switch {
	case strings.HasPrefix(ref, "env:"):
		name := strings.TrimPrefix(ref, "env:")
		if name == "" || strings.ContainsAny(name, " \t=") {
			return Secret{}, fmt.Errorf("secret: invalid environment variable name in %q", ref)
		}
		return Secret{kind: "env", ref: name}, nil
	case strings.HasPrefix(ref, "file:"):
		path := strings.TrimPrefix(ref, "file:")
		if path == "" {
			return Secret{}, fmt.Errorf("secret: empty file path in %q", ref)
		}
		return Secret{kind: "file", ref: path}, nil
	case ref == "":
		return Secret{}, errors.New("secret: empty reference")
	default:
		return Secret{}, errors.New("secret: value must be a reference of the form env:NAME or file:/path, not an inline secret")
	}
}

// MustParse is Parse for tests and constants; it panics on error.
func MustParse(ref string) Secret {
	s, err := Parse(ref)
	if err != nil {
		panic(err)
	}
	return s
}

// Literal wraps an in-memory value. It exists for tests and for values that
// arrive from somewhere other than the config file (an exchanged token, for
// example). Config loading never produces a literal Secret.
func Literal(value string) Secret {
	return Secret{kind: "literal", ref: value}
}

// IsZero reports whether the Secret holds no reference.
func (s Secret) IsZero() bool { return s.kind == "" }

// Ref describes where the secret comes from without revealing it,
// for example "env:JIRA_TOKEN" or "file:/secrets/token".
// A literal Secret reports "literal".
func (s Secret) Ref() string {
	switch s.kind {
	case "env", "file":
		return s.kind + ":" + s.ref
	case "literal":
		return "literal"
	default:
		return ""
	}
}

// Get resolves the secret. File secrets are read on every call and trailing
// whitespace is trimmed, matching how tokens are usually mounted.
func (s Secret) Get() ([]byte, error) {
	switch s.kind {
	case "env":
		v, ok := os.LookupEnv(s.ref)
		if !ok {
			return nil, fmt.Errorf("secret: environment variable %s is not set", s.ref)
		}
		if v == "" {
			return nil, fmt.Errorf("secret: environment variable %s is empty", s.ref)
		}
		return []byte(v), nil
	case "file":
		b, err := os.ReadFile(s.ref)
		if err != nil {
			return nil, fmt.Errorf("secret: read %s: %w", s.ref, err)
		}
		b = bytes.TrimRight(b, " \t\r\n")
		if len(b) == 0 {
			return nil, fmt.Errorf("secret: file %s is empty", s.ref)
		}
		return b, nil
	case "literal":
		return []byte(s.ref), nil
	default:
		return nil, ErrEmpty
	}
}

// GetString is Get as a string.
func (s Secret) GetString() (string, error) {
	b, err := s.Get()
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// String implements fmt.Stringer and never reveals the value.
func (s Secret) String() string { return Redacted }

// GoString keeps %#v from printing the struct fields.
func (s Secret) GoString() string { return "secret.Secret{" + Redacted + "}" }

// Format keeps every fmt verb from printing the struct fields.
func (s Secret) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(Redacted)) }

// MarshalJSON keeps encoding/json from printing the value.
func (s Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + Redacted + `"`), nil }

// MarshalText keeps text encoders (YAML, logs) from printing the value.
func (s Secret) MarshalText() ([]byte, error) { return []byte(Redacted), nil }

// LogValue keeps log/slog from printing the value.
func (s Secret) LogValue() slog.Value { return slog.StringValue(Redacted) }
