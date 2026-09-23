// Package vault checks what an identity may do in HashiCorp Vault.
//
// hallpass authenticates with a token or an AppRole, finds the identity
// entity whose alias on the configured auth mount is the user's email,
// collects the ACL policies attached to the entity, its groups and the
// auth mount's roles (declared in the connection), reads each policy and
// evaluates the requested path and capability with Vault's own rules:
// the most specific matching path wins, deny beats everything, "+" spans
// one segment and a trailing "*" any suffix. Parameter constraints,
// wrapping requirements, unresolvable templates and Sentinel policies
// answer unknown. Nothing is written.
package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/roee-hersh/hallpass/internal/authx"
	"github.com/roee-hersh/hallpass/internal/cache"
	"github.com/roee-hersh/hallpass/internal/httpx"
	"github.com/roee-hersh/hallpass/internal/integration"
)

const (
	authToken   = "token"
	authAppRole = "approle"

	// cacheTTL is how long policies, groups, mounts and the auth accessor
	// are kept.
	cacheTTL = 5 * time.Minute
)

// Integration is the vault product.
type Integration struct{}

// Name is "vault".
func (Integration) Name() string { return "vault" }

// Fields of a vault connection.
func (Integration) Fields() []integration.Field {
	return []integration.Field{
		integration.URLField(true, "the Vault address, e.g. https://vault.example.com:8200"),
		{Name: "auth_mode", Default: authToken, Enum: []string{authToken, authAppRole},
			Description: "token: credential is a Vault token; approle: credential is the secret_id, role_id names the role"},
		{Name: "role_id", Description: "approle: the role_id"},
		{Name: "approle_mount", Default: "approle", Description: "approle: the auth mount path"},
		integration.CredentialField(true, "the token or the AppRole secret_id"),
		{Name: "namespace", Description: "the Vault Enterprise namespace, sent as X-Vault-Namespace"},
		{Name: "alias_mount", Required: true, Description: "the auth mount whose aliases carry the users' emails, e.g. oidc/ or ldap/"},
		{Name: "token_policies", Description: "comma-separated policies every login through alias_mount receives (the auth role's token_policies), which are not visible on the entity"},
	}
}

var (
	mountRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*(/[A-Za-z0-9_.-]+)*/?$`)
	nameRe  = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.@-]{0,127}$`)
	idRe    = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
)

// New builds a connection. It touches no network.
func (Integration) New(_ context.Context, s *integration.Settings, d integration.Deps) (integration.Connection, error) {
	hc, err := d.HTTPClient(s)
	if err != nil {
		return nil, err
	}
	base := strings.TrimRight(strings.TrimSpace(s.Get("url")), "/")
	if !strings.HasPrefix(base, "https://") && !strings.HasPrefix(base, "http://") {
		return nil, errors.New("url is required and must be an http(s) URL")
	}
	if s.Secret("credential").IsZero() {
		return nil, errors.New("credential is required")
	}
	c := &Connection{
		aliasMount: strings.TrimSpace(s.Get("alias_mount")),
		namespace:  strings.TrimSpace(s.Get("namespace")),
		now:        d.Now,
		policies:   cache.New[string, []rule](0),
		groups:     cache.New[string, group](0),
		misc:       cache.New[string, map[string]json.RawMessage](0),
	}
	if c.now == nil {
		c.now = time.Now
	}
	c.policies.SetClock(c.now)
	c.groups.SetClock(c.now)
	c.misc.SetClock(c.now)
	if !mountRe.MatchString(c.aliasMount) {
		return nil, errors.New("alias_mount is required and must be an auth mount path such as oidc/")
	}
	c.aliasMount = strings.TrimSuffix(c.aliasMount, "/") + "/"
	if c.namespace != "" && !mountRe.MatchString(c.namespace) {
		return nil, errors.New("namespace must be a namespace path such as admin/ or team/child")
	}
	for _, p := range strings.Split(s.Get("token_policies"), ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !nameRe.MatchString(p) {
			return nil, fmt.Errorf("token_policies: %q is not a policy name", p)
		}
		c.tokenPolicies = append(c.tokenPolicies, p)
	}
	cred := s.Secret("credential")
	plain := &httpx.Client{HTTP: hc, Base: base + "/v1", Logger: d.Logger, Auth: c.namespaceHeader}
	switch s.Get("auth_mode") {
	case "", authToken:
		c.tokens = &authx.TokenSource{Now: c.now, Fetch: func(context.Context) (authx.Token, error) {
			t, err := cred.GetString()
			if err != nil {
				return authx.Token{}, err
			}
			return authx.Token{Value: strings.TrimSpace(t)}, nil
		}}
	case authAppRole:
		roleID := strings.TrimSpace(s.Get("role_id"))
		if !idRe.MatchString(roleID) {
			return nil, errors.New("role_id is required in auth_mode approle")
		}
		mount := strings.Trim(strings.TrimSpace(s.Get("approle_mount")), "/")
		if mount == "" {
			mount = "approle"
		}
		if !mountRe.MatchString(mount) {
			return nil, errors.New("approle_mount must be a mount path")
		}
		loginPath := "/auth/" + mount + "/login"
		c.relogin = true
		c.tokens = &authx.TokenSource{Now: c.now, Fetch: func(ctx context.Context) (authx.Token, error) {
			secret, err := cred.GetString()
			if err != nil {
				return authx.Token{}, err
			}
			var body struct {
				Auth struct {
					ClientToken   string `json:"client_token"`
					LeaseDuration int64  `json:"lease_duration"`
				} `json:"auth"`
			}
			resp, err := plain.Do(ctx, &httpx.Request{Method: http.MethodPost, Path: loginPath, JSON: map[string]string{"role_id": roleID, "secret_id": strings.TrimSpace(secret)}})
			if err != nil {
				return authx.Token{}, &authx.TokenError{Status: httpx.Status(err), Code: "approle_login_failed"}
			}
			if err := resp.JSON(&body); err != nil || body.Auth.ClientToken == "" {
				return authx.Token{}, &authx.TokenError{Status: resp.Status, Code: "approle_login_no_token"}
			}
			tok := authx.Token{Value: body.Auth.ClientToken}
			if body.Auth.LeaseDuration > 0 {
				tok.Expiry = c.now().Add(time.Duration(body.Auth.LeaseDuration) * time.Second)
			}
			return tok, nil
		}}
	default:
		return nil, fmt.Errorf("auth_mode %q must be token or approle", s.Get("auth_mode"))
	}
	c.api = &httpx.Client{HTTP: hc, Base: base + "/v1", Logger: d.Logger, Auth: func(ctx context.Context, r *http.Request) error {
		tok, err := c.tokens.Get(ctx)
		if err != nil {
			return err
		}
		r.Header.Set("X-Vault-Token", tok)
		return c.namespaceHeader(ctx, r)
	}}
	return c, nil
}

// Connection is one Vault (namespace).
type Connection struct {
	api           *httpx.Client
	tokens        *authx.TokenSource
	aliasMount    string
	namespace     string
	tokenPolicies []string
	// relogin is set in approle mode, where a 403 may mean an expired token.
	relogin bool
	now     func() time.Time

	policies *cache.TTL[string, []rule]
	groups   *cache.TTL[string, group]
	// misc caches the sys/auth and sys/mounts listings under their paths.
	misc *cache.TTL[string, map[string]json.RawMessage]
}

func (c *Connection) namespaceHeader(_ context.Context, r *http.Request) error {
	if c.namespace != "" {
		r.Header.Set("X-Vault-Namespace", c.namespace)
	}
	return nil
}

// --- transport --------------------------------------------------------------

// vaultError is the body Vault sends with 4xx/5xx.
type vaultError struct {
	Errors []string `json:"errors"`
}

// classify maps an API error. notFound builds the error for a 404, which
// Vault also answers when the token may not see the path.
func classify(err error, what string, notFound func() error) error {
	var te *authx.TokenError
	if errors.As(err, &te) {
		switch {
		case te.Status == 0:
			return integration.Wrap(integration.CodeCredentialRejected, err, "the credential could not be read")
		case te.Status == 400 || te.Status == 403:
			return integration.Wrap(integration.CodeCredentialRejected, err, "Vault rejected the AppRole login (HTTP %d)", te.Status)
		case te.Status == 429:
			return integration.Wrap(integration.CodeUpstreamRateLimit, err, "Vault rate limited the AppRole login")
		}
		return integration.Wrap(integration.CodeUpstreamError, err, "the AppRole login failed (HTTP %d)", te.Status)
	}
	switch httpx.Status(err) {
	case 403:
		return integration.Wrap(integration.CodeCredentialRejected, err, "Vault refused to %s (permission denied): hallpass's token lacks the capability", what)
	case 404:
		if notFound != nil {
			return notFound()
		}
		return integration.Wrap(integration.CodeUpstreamError, err, "Vault has no %s endpoint (HTTP 404)", what)
	case 400:
		return integration.Wrap(integration.CodeInvalidRequest, err, "Vault rejected the request to %s (HTTP 400)", what)
	case 412:
		return integration.Wrap(integration.CodeUpstreamError, err, "Vault answered 412 (eventual consistency); retry")
	case 501, 503:
		return integration.Wrap(integration.CodeUpstreamError, err, "Vault is sealed, not initialised or under maintenance (HTTP %d)", httpx.Status(err))
	}
	return httpx.Classify(err)
}

// data performs one request and decodes the response's data object.
// noContent is set when Vault answered 204.
func (c *Connection) data(ctx context.Context, method, path string, body any, out any) (noContent bool, err error) {
	req := &httpx.Request{Method: method, Path: path}
	if body != nil {
		req.JSON = body
		idem := true
		req.Idempotent = &idem
	}
	resp, err := c.api.Do(ctx, req)
	if httpx.Status(err) == 403 && c.relogin {
		// An AppRole token that expired or was revoked: log in again once.
		c.tokens.Invalidate()
		resp, err = c.api.Do(ctx, req)
	}
	if err != nil {
		return false, err
	}
	if resp.Status == 204 || len(strings.TrimSpace(string(resp.Body))) == 0 {
		return true, nil
	}
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := resp.JSON(&env); err != nil {
		return false, integration.Wrap(integration.CodeUpstreamError, err, "Vault's response was not JSON")
	}
	if len(env.Data) == 0 || string(env.Data) == "null" {
		// Some endpoints answer without the data envelope.
		if err := resp.JSON(out); err != nil {
			return false, integration.Wrap(integration.CodeUpstreamError, err, "Vault's response carried no data")
		}
		return false, nil
	}
	if err := json.Unmarshal(env.Data, out); err != nil {
		return false, integration.Wrap(integration.CodeUpstreamError, err, "Vault's data could not be decoded")
	}
	return false, nil
}

// listing reads sys/auth or sys/mounts, cached.
func (c *Connection) listing(ctx context.Context, path string) (map[string]json.RawMessage, error) {
	return c.misc.Do(ctx, path, func(ctx context.Context) (map[string]json.RawMessage, time.Duration, error) {
		var out map[string]json.RawMessage
		if _, err := c.data(ctx, http.MethodGet, path, nil, &out); err != nil {
			return nil, 0, classify(err, "read "+path, nil)
		}
		return out, cacheTTL, nil
	})
}

// --- identity ---------------------------------------------------------------

type entity struct {
	ID                string            `json:"id"`
	Name              string            `json:"name"`
	Disabled          *bool             `json:"disabled"`
	Policies          []string          `json:"policies"`
	GroupIDs          []string          `json:"group_ids"`
	InheritedGroupIDs []string          `json:"inherited_group_ids"`
	Metadata          map[string]string `json:"metadata"`
	Aliases           []struct {
		ID            string            `json:"id"`
		Name          string            `json:"name"`
		MountAccessor string            `json:"mount_accessor"`
		Metadata      map[string]string `json:"metadata"`
	} `json:"aliases"`
}

type group struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Type     string   `json:"type"`
	Policies []string `json:"policies"`
}

// accessor resolves the alias mount's accessor from sys/auth.
func (c *Connection) accessor(ctx context.Context) (string, error) {
	mounts, err := c.listing(ctx, "/sys/auth")
	if err != nil {
		return "", err
	}
	raw, ok := mounts[c.aliasMount]
	if !ok {
		return "", integration.Errorf(integration.CodeInvalidRequest, "alias_mount %s is not an enabled auth method", c.aliasMount)
	}
	var m struct {
		Accessor string `json:"accessor"`
	}
	if err := json.Unmarshal(raw, &m); err != nil || m.Accessor == "" {
		return "", integration.Errorf(integration.CodeUpstreamError, "sys/auth reports no accessor for %s", c.aliasMount)
	}
	return m.Accessor, nil
}

// ResolveIdentity finds the entity whose alias on the alias mount is the
// email, then its groups. The identity's groups are group ids; attributes
// carry what policy templates may need.
func (c *Connection) ResolveIdentity(ctx context.Context, u integration.User) (integration.Identity, error) {
	email := strings.ToLower(strings.TrimSpace(u.Email))
	if !integration.IsEmail(email) {
		return integration.Identity{}, integration.Errorf(integration.CodeInvalidRequest, "user email %q is not an address", email)
	}
	acc, err := c.accessor(ctx)
	if err != nil {
		return integration.Identity{}, err
	}
	var found struct {
		ID string `json:"id"`
	}
	none, err := c.data(ctx, http.MethodPost, "/identity/lookup/entity", map[string]string{"alias_name": email, "alias_mount_accessor": acc}, &found)
	if err != nil {
		return integration.Identity{}, classify(err, "look up the entity", nil)
	}
	// UNVERIFIED: the lookup answers 204 when nothing matches; an empty
	// data object is taken as no match too.
	if none || found.ID == "" {
		return integration.Identity{}, integration.UserNotFound("no Vault entity has an alias %s on %s", email, c.aliasMount)
	}
	if !idRe.MatchString(found.ID) {
		return integration.Identity{}, integration.Errorf(integration.CodeUpstreamError, "Vault returned an entity id of an unexpected shape")
	}
	var e entity
	if _, err := c.data(ctx, http.MethodGet, "/identity/entity/id/"+found.ID, nil, &e); err != nil {
		return integration.Identity{}, classify(err, "read the entity", func() error {
			return integration.Errorf(integration.CodeUpstreamError, "entity %s vanished between lookup and read", found.ID)
		})
	}
	id := integration.Identity{ID: found.ID, Display: email, Attrs: map[string]string{
		"entity_name": e.Name,
		"disabled":    "unknown",
	}}
	if e.Disabled != nil {
		id.Attrs["disabled"] = fmt.Sprint(*e.Disabled)
	}
	for k, v := range e.Metadata {
		id.Attrs["meta:"+k] = v
	}
	for _, a := range e.Aliases {
		id.Attrs["alias:"+a.MountAccessor+":id"] = a.ID
		id.Attrs["alias:"+a.MountAccessor+":name"] = a.Name
		for k, v := range a.Metadata {
			id.Attrs["alias:"+a.MountAccessor+":meta:"+k] = v
		}
	}
	policies := map[string]bool{}
	for _, p := range e.Policies {
		policies[p] = true
	}
	seen := map[string]bool{}
	for _, gid := range append(append([]string{}, e.GroupIDs...), e.InheritedGroupIDs...) {
		if gid == "" || seen[gid] || !idRe.MatchString(gid) {
			continue
		}
		seen[gid] = true
		g, err := c.group(ctx, gid)
		if err != nil {
			return integration.Identity{}, err
		}
		id.Groups = append(id.Groups, gid)
		id.Attrs["group:"+gid] = g.Name
		for _, p := range g.Policies {
			policies[p] = true
		}
	}
	sort.Strings(id.Groups)
	names := make([]string, 0, len(policies))
	for p := range policies {
		names = append(names, p)
	}
	sort.Strings(names)
	id.Attrs["policies"] = strings.Join(names, ",")
	return id, nil
}

// group reads one identity group, cached.
func (c *Connection) group(ctx context.Context, gid string) (group, error) {
	return c.groups.Do(ctx, gid, func(ctx context.Context) (group, time.Duration, error) {
		var g group
		if _, err := c.data(ctx, http.MethodGet, "/identity/group/id/"+gid, nil, &g); err != nil {
			return group{}, 0, classify(err, "read group "+gid, func() error {
				return integration.Errorf(integration.CodeUpstreamError, "group %s is a member of the entity but cannot be read", gid)
			})
		}
		return g, cacheTTL, nil
	})
}

// --- policies ---------------------------------------------------------------

// policy reads and parses one ACL policy, cached. A policy Vault does not
// have contributes no rules (a token may name a missing policy).
func (c *Connection) policy(ctx context.Context, name string, tc *templateContext) ([]rule, bool, error) {
	if !nameRe.MatchString(name) {
		return nil, false, integration.Errorf(integration.CodeUpstreamError, "policy name %q has an unexpected shape", name)
	}
	src, err := c.policies.Do(ctx, name, func(ctx context.Context) ([]rule, time.Duration, error) {
		var body struct {
			Policy string `json:"policy"`
			Rules  string `json:"rules"`
		}
		none, err := c.data(ctx, http.MethodGet, "/sys/policies/acl/"+name, nil, &body)
		if err != nil {
			return nil, 0, classify(err, "read policy "+name, func() error { return errMissingPolicy })
		}
		if none {
			return nil, 0, errMissingPolicy
		}
		// UNVERIFIED: the policy text sits under data.policy; the docs'
		// sample shows it at the top level, which data() also reads.
		text := body.Policy
		if text == "" {
			text = body.Rules
		}
		// Parsed once without templates to validate; templates are
		// resolved per identity below.
		if _, err := parsePolicy(name, text, nil); err != nil {
			return nil, 0, integration.Wrap(integration.CodeUnsupported, err, "policy %s uses syntax hallpass does not parse", name)
		}
		return []rule{{pattern: text}}, cacheTTL, nil
	})
	if errors.Is(err, errMissingPolicy) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	rules, err := parsePolicy(name, src[0].pattern, tc)
	if err != nil {
		return nil, false, integration.Wrap(integration.CodeUnsupported, err, "policy %s uses syntax hallpass does not parse", name)
	}
	return rules, true, nil
}

var errMissingPolicy = errors.New("policy does not exist")

// --- checks -----------------------------------------------------------------

// kvVersion reports the KV version of a mount from sys/mounts: 1, 2, or an
// error when the mount is missing or not a KV engine.
func (c *Connection) kvVersion(ctx context.Context, mount string) (int, error) {
	mounts, err := c.listing(ctx, "/sys/mounts")
	if err != nil {
		return 0, err
	}
	raw, ok := mounts[mount+"/"]
	if !ok {
		return 0, integration.Errorf(integration.CodeResourceNotVisible, "no secrets engine is mounted at %s/ (or hallpass cannot list mounts)", mount)
	}
	var m struct {
		Type    string `json:"type"`
		Options struct {
			Version string `json:"version"`
		} `json:"options"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return 0, integration.Wrap(integration.CodeUpstreamError, err, "sys/mounts entry for %s could not be decoded", mount)
	}
	if m.Type != "kv" && m.Type != "generic" {
		return 0, integration.Errorf(integration.CodeUnsupported, "the engine at %s/ is %s, not kv; use path: with raw: capabilities", mount, m.Type)
	}
	if m.Options.Version == "2" {
		return 2, nil
	}
	return 1, nil
}

// Check answers one question.
func (c *Connection) Check(ctx context.Context, r integration.CheckRequest) (integration.Decision, error) {
	t, err := parseTarget(r.ActionName, r.Resource)
	if err != nil {
		return integration.Decision{}, err
	}
	id := r.Identity
	who := id.Display
	if id.Attr("disabled") == "true" {
		return integration.Denied("entity %s (%s) is disabled", id.Attr("entity_name"), who), nil
	}
	// The API path the request goes to.
	apiPath := t.path
	if t.kind == "kv" {
		version, err := c.kvVersion(ctx, t.mount)
		if err != nil {
			return integration.ToDecision(err), nil
		}
		switch {
		case version == 2 && t.action.kv2 != "":
			apiPath = t.mount + "/" + t.action.kv2 + "/" + t.key
		case version == 1 && (t.action.name == "secret.destroy" || t.action.name == "secret.metadata"):
			return integration.Unsupported("%s is a KV v2 question and %s/ is a KV v1 mount", t.action.name, t.mount), nil
		}
	}
	matchPath := apiPath
	if t.action.list {
		matchPath += "/"
	}
	// The policies: entity, groups, the auth role's, and default.
	// UNVERIFIED: default is attached to every token unless the auth
	// method excludes it; it is assumed attached.
	names := map[string]bool{"default": true}
	for _, p := range strings.Split(id.Attr("policies"), ",") {
		if p != "" {
			names[p] = true
		}
	}
	for _, p := range c.tokenPolicies {
		names[p] = true
	}
	if names["root"] {
		return integration.Allowed("%s holds the root policy, which allows everything", who), nil
	}
	tc := templateContextOf(id)
	var rules []rule
	var read []string
	for _, name := range sortedKeys(names) {
		rs, ok, err := c.policy(ctx, name, tc)
		if err != nil {
			return integration.ToDecision(err), nil
		}
		if ok {
			read = append(read, name)
			rules = append(rules, rs...)
		}
	}
	need := strings.Join(t.action.need, "+")
	ev := evaluate(rules, matchPath, t.action.need)
	if len(t.action.need) == 2 {
		// A write is create or update depending on whether the secret
		// exists; both must agree for a definite answer.
		a, b := evaluate(rules, matchPath, t.action.need[:1]), evaluate(rules, matchPath, t.action.need[1:])
		switch {
		case a.outcome == b.outcome:
			ev = a
			if b.outcome == "deny" && a.pattern != "" {
				ev.reason = fmt.Sprintf("policy path %q grants neither create nor update", a.pattern)
			}
		case a.outcome == "unknown":
			ev = a
		case b.outcome == "unknown":
			ev = b
		default:
			ev = evaluation{outcome: "unknown", pattern: a.pattern, reason: fmt.Sprintf("policy path %q grants %s but not %s, so the write succeeds only if the secret %s", a.pattern, granted(a, b), denied(a, b), exists(a))}
		}
	}
	switch ev.outcome {
	case "allow":
		return integration.Allowed("policy %s grants %s on %q, covering %s (%s)", strings.Join(ev.policies, ", "), need, ev.pattern, apiPath, who), nil
	case "deny":
		if ev.pattern == "" {
			return integration.Denied("no path in %s's policies (%s) matches %s; %s is denied", who, strings.Join(read, ", "), matchPath, need), nil
		}
		return integration.Denied("%s for %s: %s (policies %s)", need, who, ev.reason, strings.Join(ev.policies, ", ")), nil
	}
	return integration.Unsupported("%s for %s on %s: %s", need, who, apiPath, ev.reason), nil
}

// granted, denied and exists word the mixed create/update answer.
func granted(a, b evaluation) string {
	if a.outcome == "allow" {
		return "create"
	}
	return "update"
}

func denied(a, b evaluation) string {
	if a.outcome == "allow" {
		return "update"
	}
	return "create"
}

func exists(a evaluation) string {
	if a.outcome == "allow" {
		return "does not exist yet"
	}
	return "already exists"
}

// templateContextOf rebuilds the template context from identity attributes.
func templateContextOf(id integration.Identity) *templateContext {
	tc := &templateContext{entityID: id.ID, entityName: id.Attr("entity_name"), metadata: map[string]string{}, aliases: map[string]alias{}, groupNames: map[string]string{}, groupIDs: map[string]string{}}
	for k, v := range id.Attrs {
		switch {
		case strings.HasPrefix(k, "meta:"):
			tc.metadata[strings.TrimPrefix(k, "meta:")] = v
		case strings.HasPrefix(k, "group:"):
			gid := strings.TrimPrefix(k, "group:")
			tc.groupNames[gid] = v
			tc.groupIDs[v] = gid
		case strings.HasPrefix(k, "alias:"):
			rest := strings.TrimPrefix(k, "alias:")
			acc, field, ok := strings.Cut(rest, ":")
			if !ok {
				continue
			}
			a := tc.aliases[acc]
			if a.metadata == nil {
				a.metadata = map[string]string{}
			}
			switch {
			case field == "id":
				a.id = v
			case field == "name":
				a.name = v
			case strings.HasPrefix(field, "meta:"):
				a.metadata[strings.TrimPrefix(field, "meta:")] = v
			}
			tc.aliases[acc] = a
		}
	}
	return tc
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// --- probe ------------------------------------------------------------------

// Probe looks the token up and resolves the alias mount's accessor.
func (c *Connection) Probe(ctx context.Context) (integration.ProbeResult, error) {
	var self struct {
		DisplayName string   `json:"display_name"`
		Policies    []string `json:"policies"`
		EntityID    string   `json:"entity_id"`
	}
	if _, err := c.data(ctx, http.MethodGet, "/auth/token/lookup-self", nil, &self); err != nil {
		return integration.ProbeResult{}, classify(err, "look up its own token", nil)
	}
	acc, err := c.accessor(ctx)
	if err != nil {
		return integration.ProbeResult{}, err
	}
	res := integration.ProbeResult{Summary: fmt.Sprintf("authenticated as %s with policies %s; alias mount %s has accessor %s", orEmpty(self.DisplayName, "a token"), strings.Join(self.Policies, ", "), c.aliasMount, acc)}
	for _, p := range self.Policies {
		if p == "root" {
			res.Warnings = append(res.Warnings, "hallpass's token holds the root policy; a token with read on identity/*, sys/policies/acl/*, sys/auth and sys/mounts suffices")
		}
	}
	if len(c.tokenPolicies) == 0 {
		res.Warnings = append(res.Warnings, "token_policies is empty: policies the auth role attaches at login are not visible on entities and are not evaluated")
	}
	res.Warnings = append(res.Warnings, "Sentinel policies, parameter constraints and wrapping requirements are not evaluated")
	return res, nil
}

func orEmpty(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
