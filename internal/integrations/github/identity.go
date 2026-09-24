package github

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/roee-hersh/hallpass/internal/cache"
	"github.com/roee-hersh/hallpass/internal/httpx"
	"github.com/roee-hersh/hallpass/internal/integration"
)

// Identity modes.
const (
	modeSAML     = "saml"
	modeTemplate = "template"
	modeMapFile  = "map_file"
)

const (
	// samlCacheTTL is how long the full external-identity map is reused.
	samlCacheTTL = 10 * time.Minute
	// A fresh check uses the map for as long as anyone: it is an
	// organization's whole identity listing, paged, and a link between an
	// address and a login is not what a fresh check is about; the
	// permission read that follows is always live.
	// mapFileTTL is the shortest interval between two reads of user_map_file.
	mapFileTTL = 60 * time.Second
)

// samlMaxIdentities caps the map built by the paginated fallback. A variable
// so tests can exercise the truncated path.
var samlMaxIdentities = 5000

// samlFetchHook runs at the start of every identity listing. Tests set it
// to inject failures such as a panic; it is nil in production.
var samlFetchHook func()

// validEmail is a shape check only. The email goes into a GraphQL variable
// (JSON, so no injection) or a file lookup; this keeps garbage out of both.
func validEmail(s string) bool {
	if len(s) == 0 || len(s) > 254 {
		return false
	}
	local, domain, ok := strings.Cut(s, "@")
	if !ok || local == "" || domain == "" || strings.Contains(domain, "@") {
		return false
	}
	for _, c := range s {
		if c <= 0x20 || c == 0x7f || c == '"' || c == '\'' || c == '\\' || c == '/' {
			return false
		}
	}
	return true
}

// ResolveIdentity maps an email to a GitHub login by the configured mode.
func (c *Connection) ResolveIdentity(ctx context.Context, u integration.User) (integration.Identity, error) {
	email := strings.TrimSpace(u.Email)
	if !validEmail(email) {
		return integration.Identity{}, integration.Errorf(integration.CodeInvalidRequest, "email %q is not a valid address", u.Email)
	}
	var login string
	var err error
	switch c.mode {
	case modeSAML:
		login, err = c.resolveSAML(ctx, email)
	case modeTemplate:
		login, err = c.resolveTemplate(ctx, email)
	case modeMapFile:
		login, err = c.resolveMapFile(email)
	default:
		return integration.Identity{}, integration.Errorf(integration.CodeUnsupported, "identity_mode %q is not supported", c.mode)
	}
	if err != nil {
		return integration.Identity{}, err
	}
	if !validLogin(login) {
		return integration.Identity{}, integration.Errorf(integration.CodeUnsupported, "identity mode %s produced %q, which is not a GitHub login", c.mode, login)
	}
	return integration.Identity{ID: login, Display: login, Attrs: map[string]string{"identity_mode": c.mode}}, nil
}

// --- saml -------------------------------------------------------------------

const samlLookupQuery = `query($org:String!,$email:String!){ organization(login:$org){ samlIdentityProvider { externalIdentities(first:5, userName:$email){ nodes { user { login } samlIdentity { nameId username } scimIdentity { username } } } } } }`

const samlPageQuery = `query($org:String!,$cursor:String){ organization(login:$org){ samlIdentityProvider { externalIdentities(first:100, after:$cursor){ pageInfo { hasNextPage endCursor } nodes { user { login } samlIdentity { nameId username } scimIdentity { username } } } } } }`

type externalIdentity struct {
	User *struct {
		Login string `json:"login"`
	} `json:"user"`
	SAMLIdentity *struct {
		NameID   string `json:"nameId"`
		Username string `json:"username"`
	} `json:"samlIdentity"`
	SCIMIdentity *struct {
		Username string `json:"username"`
	} `json:"scimIdentity"`
}

type samlData struct {
	Organization *struct {
		SAMLIdentityProvider *struct {
			ExternalIdentities struct {
				PageInfo struct {
					HasNextPage bool   `json:"hasNextPage"`
					EndCursor   string `json:"endCursor"`
				} `json:"pageInfo"`
				Nodes []externalIdentity `json:"nodes"`
			} `json:"externalIdentities"`
		} `json:"samlIdentityProvider"`
	} `json:"organization"`
}

// samlEntry is one cached identity: login "" means the identity is not
// linked to a GitHub account; conflict means the address belongs to
// identities linked to different accounts.
type samlEntry struct {
	login    string
	conflict bool
}

// errNoSAML is returned when the organization has no SAML identity provider.
var errNoSAML = integration.Errorf(integration.CodeUnsupported,
	"organization has no SAML identity provider; use identity_mode template or map_file")

func (c *Connection) resolveSAML(ctx context.Context, email string) (string, error) {
	var data samlData
	if err := c.graphql(ctx, samlLookupQuery, map[string]any{"org": c.org, "email": email}, &data); err != nil {
		return "", err
	}
	if data.Organization == nil {
		return "", integration.Errorf(integration.CodeCredentialRejected, "organization %s is not visible to the app", c.org)
	}
	if data.Organization.SAMLIdentityProvider == nil {
		return "", errNoSAML
	}
	nodes := matchingIdentities(data.Organization.SAMLIdentityProvider.ExternalIdentities.Nodes, email)
	if len(nodes) > 0 {
		return pickIdentity(nodes, email)
	}
	// userName did not match: the IdP may send an email only as nameId.
	// Build (or reuse) the full map and look the address up there.
	idx, err := c.samlMap(ctx)
	if err != nil {
		return "", err
	}
	e, ok := idx.entries[strings.ToLower(email)]
	if !ok {
		if idx.truncated {
			return "", integration.Errorf(integration.CodeUnsupported, "no SAML identity in %s for %s in the first %d identities; identity list truncated", c.org, email, idx.total)
		}
		return "", integration.UserNotFound("no SAML identity in %s for %s", c.org, email)
	}
	if e.conflict {
		return "", integration.UserAmbiguous("SAML identity %s is linked to several GitHub accounts", email)
	}
	if e.login == "" {
		return "", integration.Errorf(integration.CodeUnsupported, "SAML identity for %s is not linked to a GitHub account", email)
	}
	return e.login, nil
}

// matchingIdentities keeps the nodes whose SAML nameId, SAML username or
// SCIM username equals the email case-insensitively. GitHub's userName
// filter is not trusted to have matched exactly.
func matchingIdentities(nodes []externalIdentity, email string) []externalIdentity {
	var out []externalIdentity
	for _, n := range nodes {
		if identityMatches(n, email) {
			out = append(out, n)
		}
	}
	return out
}

func identityMatches(n externalIdentity, email string) bool {
	if n.SAMLIdentity != nil && (strings.EqualFold(n.SAMLIdentity.NameID, email) || strings.EqualFold(n.SAMLIdentity.Username, email)) {
		return true
	}
	return n.SCIMIdentity != nil && strings.EqualFold(n.SCIMIdentity.Username, email)
}

// pickIdentity chooses among the identities that match the email: the
// linked login when there is exactly one; several different logins is
// ambiguous; only unlinked ones is unsupported.
func pickIdentity(nodes []externalIdentity, email string) (string, error) {
	var logins []string
	for _, n := range nodes {
		if n.User != nil && n.User.Login != "" {
			logins = append(logins, n.User.Login)
		}
	}
	switch len(logins) {
	case 0:
		return "", integration.Errorf(integration.CodeUnsupported, "SAML identity for %s is not linked to a GitHub account", email)
	case 1:
		return logins[0], nil
	}
	for _, l := range logins[1:] {
		if !strings.EqualFold(l, logins[0]) {
			return "", integration.UserAmbiguous("SAML identity %s is linked to several GitHub accounts", email)
		}
	}
	return logins[0], nil
}

// samlIndex is the address -> entry map of every external identity, with
// whether the listing stopped before the end (a miss is then not a deny).
type samlIndex struct {
	entries   map[string]samlEntry
	truncated bool
	total     int
}

// samlMap returns the index of every external identity, loading it at most
// every samlCacheTTL. Concurrent callers share one fetch (cache.TTL.Do: it
// runs on a context detached from the first caller's cancellation, so a
// waiter is never failed by the leader going away). A panic in the listing
// becomes an unknown decision for everyone waiting on it rather than
// unwinding through the engine, which logs it with its stack.
func (c *Connection) samlMap(ctx context.Context) (*samlIndex, error) {
	idx, err := c.saml.Do(ctx, struct{}{}, func(ctx context.Context) (*samlIndex, time.Duration, error) {
		idx, err := c.fetchSAMLMap(ctx)
		return idx, samlCacheTTL, err
	})
	var pe *cache.PanicError
	if errors.As(err, &pe) {
		return nil, integration.Wrap(integration.CodeUpstreamError, pe, "the SAML identity listing failed unexpectedly")
	}
	return idx, err
}

// fetchSAMLMap lists every external identity. Two linked identities that
// carry the same address for different logins mark the address as
// conflicting, so a lookup is ambiguous rather than whichever came last.
func (c *Connection) fetchSAMLMap(ctx context.Context) (*samlIndex, error) {
	if samlFetchHook != nil {
		samlFetchHook()
	}
	idx := &samlIndex{entries: map[string]samlEntry{}}
	m := idx.entries
	var cursor *string
	total := 0
	for page := 0; page < httpx.MaxPages; page++ {
		vars := map[string]any{"org": c.org}
		if cursor != nil {
			vars["cursor"] = *cursor
		}
		var data samlData
		if err := c.graphql(ctx, samlPageQuery, vars, &data); err != nil {
			return nil, err
		}
		if data.Organization == nil || data.Organization.SAMLIdentityProvider == nil {
			return nil, errNoSAML
		}
		ids := data.Organization.SAMLIdentityProvider.ExternalIdentities
		for _, n := range ids.Nodes {
			total++
			e := samlEntry{}
			if n.User != nil {
				e.login = n.User.Login
			}
			for _, v := range identityEmails(n) {
				prev, dup := m[v]
				switch {
				case !dup:
					m[v] = e
				case prev.conflict || e.login == "":
					// Keep the conflict, or the linked entry over an unlinked one.
				case prev.login == "":
					m[v] = e
				case !strings.EqualFold(prev.login, e.login):
					m[v] = samlEntry{conflict: true}
				}
			}
		}
		idx.total = total
		if !ids.PageInfo.HasNextPage {
			return idx, nil
		}
		if total >= samlMaxIdentities {
			c.logger.Warn("github: SAML identity listing stopped at the identity limit", "organization", c.org, "identities", total)
			idx.truncated = true
			return idx, nil
		}
		next := ids.PageInfo.EndCursor
		if next == "" {
			c.logger.Warn("github: SAML identity listing reported a next page without a cursor", "organization", c.org)
			idx.truncated = true
			return idx, nil
		}
		cursor = &next
	}
	c.logger.Warn("github: SAML identity listing stopped at the page limit", "organization", c.org, "identities", total)
	idx.truncated = true
	return idx, nil
}

// identityEmails returns the address-shaped values of an identity, lowercased.
func identityEmails(n externalIdentity) []string {
	var out []string
	add := func(v string) {
		if strings.Contains(v, "@") {
			out = append(out, strings.ToLower(v))
		}
	}
	if n.SAMLIdentity != nil {
		add(n.SAMLIdentity.NameID)
		add(n.SAMLIdentity.Username)
	}
	if n.SCIMIdentity != nil {
		add(n.SCIMIdentity.Username)
	}
	return out
}

// --- template ---------------------------------------------------------------

type userRecord struct {
	Login string `json:"login"`
	Type  string `json:"type"`
}

func (c *Connection) resolveTemplate(ctx context.Context, email string) (string, error) {
	domain := integration.EmailDomain(email)
	if domain == "" || !c.emailDomains[domain] {
		return "", integration.Errorf(integration.CodeUnsupported, "email domain %s is not in email_domains; login_template is not applied to it", domain)
	}
	login := c.template.Render(email)
	if !validLogin(login) {
		return "", integration.UserNotFound("login_template renders %s to %q, which is not a GitHub login", email, login)
	}
	var u userRecord
	if _, err := c.get(ctx, "/users/"+httpx.PathEscape(login), &u); err != nil {
		if apiStatus(err) == http.StatusNotFound {
			return "", integration.UserNotFound("no GitHub user %s (from login_template) for %s", login, email)
		}
		return "", c.classify(err, "look up user "+login)
	}
	if u.Type != "" && u.Type != "User" {
		return "", integration.UserNotFound("%s (from login_template) is a GitHub %s, not a user", login, strings.ToLower(u.Type))
	}
	if u.Login != "" {
		login = u.Login
	}
	return login, nil
}

// --- map_file ---------------------------------------------------------------

func (c *Connection) resolveMapFile(email string) (string, error) {
	m, err := c.userMap()
	if err != nil {
		return "", err
	}
	login, ok := m[strings.ToLower(email)]
	if !ok {
		return "", integration.UserNotFound("%s is not in user_map_file", email)
	}
	return login, nil
}

// userMap returns the parsed user_map_file, re-reading it at most every
// mapFileTTL. A failed re-read keeps the previous map.
func (c *Connection) userMap() (map[string]string, error) {
	c.mapMu.Lock()
	defer c.mapMu.Unlock()
	now := c.now()
	if c.mapEntries != nil && now.Sub(c.mapRead) < mapFileTTL {
		return c.mapEntries, nil
	}
	m, err := readUserMap(c.mapFile)
	if err != nil {
		if c.mapEntries != nil {
			c.logger.Warn("github: user_map_file could not be re-read; keeping the previous map", "error", err.Error())
			c.mapRead = now
			return c.mapEntries, nil
		}
		return nil, integration.Wrap(integration.CodeUpstreamError, err, "user_map_file could not be read")
	}
	c.mapEntries, c.mapRead = m, now
	return m, nil
}

// readUserMap parses lines of "email login" or "email=login"; "#" starts a
// comment. Emails are lowercased; a login that is not a GitHub login is an
// error so a typo is caught rather than silently denying one user.
func readUserMap(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	m := map[string]string{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var email, login string
		if e, l, ok := strings.Cut(line, "="); ok {
			email, login = strings.TrimSpace(e), strings.TrimSpace(l)
		} else {
			fields := strings.Fields(line)
			if len(fields) != 2 {
				return nil, fmt.Errorf("%s:%d: expected \"email login\" or \"email=login\"", path, n)
			}
			email, login = fields[0], fields[1]
		}
		if !validEmail(email) {
			return nil, fmt.Errorf("%s:%d: %q is not an email address", path, n, email)
		}
		if !validLogin(login) {
			return nil, fmt.Errorf("%s:%d: %q is not a GitHub login", path, n, login)
		}
		m[strings.ToLower(email)] = login
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return m, nil
}
