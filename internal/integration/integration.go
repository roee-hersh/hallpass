// Package integration defines what every integration implements and what the
// framework gives it.
//
// Vocabulary: an Integration is the product (kubernetes, jira). A Connection
// is one configured system of that product (one cluster, one Jira site).
package integration

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/roee-hersh/hallpass/internal/catalog"
	"github.com/roee-hersh/hallpass/internal/secret"
)

// Integration is the product.
type Integration interface {
	// Name is the value of the "integration" config key, lowercase.
	Name() string
	// Fields lists every config key this integration accepts besides the
	// common ones (id, integration, ca_file, tls_server_name, proxy_url, timeout).
	Fields() []Field
	// Actions lists what callers may ask about.
	Actions() []catalog.Action
	// New builds one connection from validated settings.
	New(ctx context.Context, s *Settings, d Deps) (Connection, error)
}

// Connection is one configured system.
type Connection interface {
	// ResolveIdentity maps the caller's user to the system's own account.
	// Return *Error with CodeUserNotFound or CodeUserAmbiguous when the
	// mapping fails; other errors mean the lookup itself failed.
	ResolveIdentity(ctx context.Context, u User) (Identity, error)
	// Check answers one question. It must return deny only when the system
	// positively says no. A returned error is turned into an unknown decision.
	Check(ctx context.Context, r CheckRequest) (Decision, error)
	// Probe verifies the credential and permissions without a user.
	Probe(ctx context.Context) (ProbeResult, error)
}

// ActionMatcher is optionally implemented by integrations whose action names
// are patterns (raw:<verb>:<resource>, app.action/<g>/<k>/<n>). It is consulted
// only when an exact match in Actions fails.
type ActionMatcher interface {
	MatchAction(name string) (catalog.Action, bool)
}

// User is what the caller sent.
type User struct {
	Email  string
	Groups []string
}

// Identity is the resolved account in the third-party system.
type Identity struct {
	// ID is the system's identifier (accountId, login, user id, username).
	ID string
	// Display is a short human-readable label for logs and reasons.
	Display string
	// Attrs carries small string facts (for example "is_admin"="true").
	Attrs map[string]string
	// Groups are group identifiers the system reported, if any.
	Groups []string
	// Native optionally keeps the integration's own decoded record.
	// It is cached, so it must be treated as read-only.
	Native any
}

// Attr returns one attribute or "".
func (i Identity) Attr(k string) string {
	if i.Attrs == nil {
		return ""
	}
	return i.Attrs[k]
}

// CheckRequest is one question for a Connection.
type CheckRequest struct {
	User     User
	Identity Identity
	Action   catalog.Action
	// ActionName is the caller's exact action string (matters for patterns).
	ActionName string
	Resource   catalog.Resource
}

// ProbeResult is what a successful probe reports.
type ProbeResult struct {
	// Summary is one line, for example "authenticated as bot@acme.com".
	Summary string
	// Warnings lists non-fatal findings such as an over-privileged credential.
	Warnings []string
}

// Field describes one config key an integration accepts.
type Field struct {
	Name     string
	Required bool
	// Secret fields must be env: or file: references.
	Secret bool
	// Ref names another integration; the value must be the id of a
	// connection of that integration. Used for keys ending in _connection.
	Ref string
	// Default applies when the key is absent.
	Default string
	// Enum restricts the accepted values.
	Enum []string
	// Description is one line for `hallpass catalog`.
	Description string
	// Validate optionally checks the value. It runs after Enum.
	Validate func(v string) error
}

// Common field constructors used by most integrations.

// URLField is the base URL of the system.
func URLField(required bool, desc string) Field {
	return Field{Name: "url", Required: required, Description: desc, Validate: ValidateHTTPSURL}
}

// CredentialField is the bot credential.
func CredentialField(required bool, desc string) Field {
	return Field{Name: "credential", Required: required, Secret: true, Description: desc}
}

// ConnectionRefField references a connection of another integration.
func ConnectionRefField(name, integration string, required bool, desc string) Field {
	return Field{Name: name, Ref: integration, Required: required, Description: desc}
}

var fieldNameRe = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// ValidateFields checks an integration's field declarations at registration.
func ValidateFields(fields []Field) error {
	seen := map[string]bool{}
	for _, f := range fields {
		if !fieldNameRe.MatchString(f.Name) {
			return fmt.Errorf("field %q: name must match %s", f.Name, fieldNameRe)
		}
		if seen[f.Name] {
			return fmt.Errorf("field %q declared twice", f.Name)
		}
		seen[f.Name] = true
		if CommonFields[f.Name] {
			return fmt.Errorf("field %q is a common field and may not be redeclared", f.Name)
		}
		if f.Ref != "" && !strings.HasSuffix(f.Name, "_connection") {
			return fmt.Errorf("field %q references a connection so its name must end in _connection", f.Name)
		}
		if f.Secret && f.Default != "" {
			return fmt.Errorf("field %q: secret fields cannot have defaults", f.Name)
		}
	}
	return nil
}

// CommonFields are accepted on every connection and handled by the framework.
var CommonFields = map[string]bool{
	"id": true, "integration": true,
	"ca_file": true, "tls_server_name": true, "proxy_url": true, "timeout": true,
}

// ValidateHTTPSURL accepts https:// URLs with no query, fragment or userinfo.
// Plain http:// is allowed only when the host is exactly "localhost" or a
// loopback IP address (127.0.0.0/8, ::1), for local testing; a name that
// merely starts with "localhost" or "127.0.0.1" resolves wherever DNS says
// and would carry the credential in clear text, so it is rejected.
func ValidateHTTPSURL(v string) error {
	if v == "" {
		return nil
	}
	if strings.ContainsAny(v, " \t\r\n#?") {
		return fmt.Errorf("url %q must not contain whitespace, '?' or '#'", v)
	}
	u, err := url.Parse(v)
	if err != nil {
		return fmt.Errorf("url %q: %v", v, err)
	}
	if u.User != nil {
		return fmt.Errorf("url %q must not contain userinfo", v)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if isLoopbackHost(u.Hostname()) {
			return nil
		}
	}
	return fmt.Errorf("url %q must start with https://", v)
}

// isLoopbackHost reports whether host is "localhost" or a loopback IP.
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Settings are the validated config values of one connection.
type Settings struct {
	ID          string
	Integration string

	// Common transport options.
	CAFile        string
	TLSServerName string
	ProxyURL      string
	Timeout       time.Duration

	values  map[string]string
	secrets map[string]secret.Secret
}

// NewSettings builds Settings. Tests and the config loader use it.
func NewSettings(id, integration string, values map[string]string, secrets map[string]secret.Secret) *Settings {
	s := &Settings{ID: id, Integration: integration, values: map[string]string{}, secrets: map[string]secret.Secret{}}
	for k, v := range values {
		s.values[k] = v
	}
	for k, v := range secrets {
		s.secrets[k] = v
	}
	return s
}

// Get returns a non-secret value (defaults already applied) or "".
func (s *Settings) Get(key string) string { return s.values[key] }

// Has reports whether a non-secret key was set (or defaulted).
func (s *Settings) Has(key string) bool { _, ok := s.values[key]; return ok }

// Bool parses a "true"/"false" value; absent means def.
func (s *Settings) Bool(key string, def bool) bool {
	switch strings.ToLower(s.values[key]) {
	case "true", "yes", "1":
		return true
	case "false", "no", "0":
		return false
	default:
		return def
	}
}

// Secret returns a secret reference; the zero Secret when absent.
func (s *Settings) Secret(key string) secret.Secret { return s.secrets[key] }

// Keys lists the set non-secret keys, sorted.
func (s *Settings) Keys() []string {
	ks := make([]string, 0, len(s.values))
	for k := range s.values {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// Deps is what the framework hands to Integration.New.
type Deps struct {
	Logger *slog.Logger
	// Connection returns another built connection by id. Only ids named in a
	// Ref field of this integration are resolvable.
	Connection func(id string) (Connection, error)
	// HTTPClient builds a client from the connection's transport settings.
	HTTPClient func(s *Settings) (*http.Client, error)
	// Now is the clock. Tests replace it.
	Now func() time.Time
}

// DefaultTimeout applies when a connection sets none.
const DefaultTimeout = 8 * time.Second

// EffectiveTimeout returns the connection's timeout or the default.
func (s *Settings) EffectiveTimeout() time.Duration {
	if s.Timeout > 0 {
		return s.Timeout
	}
	return DefaultTimeout
}
