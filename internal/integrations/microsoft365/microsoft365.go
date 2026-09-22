// Package microsoft365 checks Entra ID, Teams, OneDrive/SharePoint and
// Exchange facts through Microsoft Graph.
//
// hallpass authenticates as an app registration with read-only application
// permissions (client credentials, with a client secret or a certificate),
// resolves the caller's email to an Entra user and asks Graph about group
// membership, directory roles, team and channel membership and drive item
// permissions. Exchange delegation (Send As, Send on Behalf, Full Access)
// has no Graph API and is always unknown. Nothing is persisted.
package microsoft365

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/roee-hersh/hallpass/internal/authx"
	"github.com/roee-hersh/hallpass/internal/httpx"
	"github.com/roee-hersh/hallpass/internal/integration"
)

const (
	defaultAuthority = "https://login.microsoftonline.com"
	defaultGraph     = "https://graph.microsoft.com"
	assertionTTL     = 5 * time.Minute
	// checkBatch is the maximum number of ids checkMemberGroups accepts.
	checkBatch = 20
	userSelect = "id,userPrincipalName,mail,accountEnabled,userType,displayName"
)

// Integration is the microsoft365 product.
type Integration struct{}

// Name is "microsoft365".
func (Integration) Name() string { return "microsoft365" }

// Fields of a microsoft365 connection.
func (Integration) Fields() []integration.Field {
	return []integration.Field{
		{Name: "tenant_id", Required: true, Validate: validateTenant,
			Description: "Entra tenant: a GUID or a verified domain such as contoso.onmicrosoft.com"},
		{Name: "client_id", Required: true, Validate: validateGUID,
			Description: "application (client) id of the app registration"},
		integration.CredentialField(true, "client secret, or the PEM private key when certificate_file is set"),
		{Name: "certificate_file", Description: "path to the PEM public certificate; when set hallpass authenticates with a certificate assertion"},
		{Name: "authority_url", Default: defaultAuthority, Validate: integration.ValidateHTTPSURL,
			Description: "Entra authority; national clouds use login.microsoftonline.us or login.chinacloudapi.cn"},
		{Name: "url", Default: defaultGraph, Validate: integration.ValidateHTTPSURL,
			Description: "Microsoft Graph endpoint; national clouds use graph.microsoft.us, dod-graph.microsoft.us or microsoftgraph.chinacloudapi.cn"},
	}
}

var domainRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?)+$`)

func validateTenant(v string) error {
	if guidRe.MatchString(v) || domainRe.MatchString(v) {
		return nil
	}
	return errors.New("must be a GUID or a domain name")
}

func validateGUID(v string) error {
	if guidRe.MatchString(v) {
		return nil
	}
	return errors.New("must be a GUID")
}

// New builds a connection. It touches no network.
func (Integration) New(_ context.Context, s *integration.Settings, d integration.Deps) (integration.Connection, error) {
	hc, err := d.HTTPClient(s)
	if err != nil {
		return nil, err
	}
	if s.Secret("credential").IsZero() {
		return nil, errors.New("credential is required")
	}
	c := &Connection{
		settings: s,
		tenant:   s.Get("tenant_id"),
		clientID: s.Get("client_id"),
		certFile: s.Get("certificate_file"),
		now:      d.Now,
	}
	if c.tenant == "" {
		return nil, errors.New("tenant_id is required")
	}
	if err := validateTenant(c.tenant); err != nil {
		return nil, fmt.Errorf("tenant_id: %w", err)
	}
	if err := validateGUID(c.clientID); err != nil {
		return nil, fmt.Errorf("client_id: %w", err)
	}
	if c.now == nil {
		c.now = time.Now
	}
	authority := strings.TrimRight(s.Get("authority_url"), "/")
	if authority == "" {
		authority = defaultAuthority
	}
	graph := strings.TrimRight(s.Get("url"), "/")
	if graph == "" {
		graph = defaultGraph
	}
	c.tokenURL = authority + "/" + httpx.PathEscape(c.tenant) + "/oauth2/v2.0/token"
	c.scope = graph + "/.default"
	c.plain = &httpx.Client{HTTP: hc, Logger: d.Logger}
	c.tokens = &authx.TokenSource{Fetch: c.fetchToken, Now: c.now}
	c.graph = &httpx.Client{HTTP: hc, Base: graph, Logger: d.Logger, Auth: httpx.BearerAuth(c.tokens.Get)}
	return c, nil
}

// Connection is one Entra tenant reached through one app registration.
type Connection struct {
	settings *integration.Settings
	tenant   string
	clientID string
	certFile string
	tokenURL string
	scope    string
	now      func() time.Time

	plain  *httpx.Client // token endpoint
	graph  *httpx.Client // Graph, bearer
	tokens *authx.TokenSource
}

// --- authentication ---------------------------------------------------------

// fetchToken runs the client credentials grant, with the secret or with a
// PS256 certificate assertion when certificate_file is set.
func (c *Connection) fetchToken(ctx context.Context) (authx.Token, error) {
	cred := c.settings.Secret("credential")
	if c.certFile == "" {
		fetch := authx.ClientCredentials(c.plain, c.tokenURL, c.clientID, func(context.Context) (string, error) { return cred.GetString() }, c.scope)
		return fetch(ctx)
	}
	fetch := authx.ClientAssertion(c.plain, c.tokenURL, c.clientID, c.assertion, c.scope)
	return fetch(ctx)
}

// assertion signs the certificate credential JWT: PS256 with the x5t#S256
// thumbprint of the certificate, audience = the token endpoint.
func (c *Connection) assertion(context.Context) (string, error) {
	certPEM, err := os.ReadFile(c.certFile)
	if err != nil {
		return "", integration.Wrap(integration.CodeCredentialRejected, err, "certificate_file could not be read")
	}
	cert, err := authx.ParseCertificate(certPEM)
	if err != nil {
		return "", integration.Wrap(integration.CodeCredentialRejected, err, "certificate_file is not a PEM certificate")
	}
	keyPEM, err := c.settings.Secret("credential").GetString()
	if err != nil {
		return "", integration.Wrap(integration.CodeCredentialRejected, err, "the private key could not be read")
	}
	key, err := authx.ParseRSAPrivateKey([]byte(keyPEM))
	if err != nil {
		return "", integration.Wrap(integration.CodeCredentialRejected, err, "credential is not a PEM RSA private key")
	}
	jti, err := authx.NewJTI()
	if err != nil {
		return "", err
	}
	now := c.now()
	// UNVERIFIED: whether Entra still accepts RS256 with the legacy x5t
	// header; only PS256 + x5t#S256 is implemented.
	claims := authx.StandardClaims{
		Aud: c.tokenURL, Iss: c.clientID, Sub: c.clientID, Jti: jti,
		Nbf: authx.Unix(now), Iat: authx.Unix(now), Exp: authx.Unix(now.Add(assertionTTL)),
	}
	return authx.SignJWT(key, authx.Header{Alg: authx.PS256, X5tS: authx.CertThumbprintSHA256(cert)}, claims)
}

// classifyToken maps a token endpoint failure. A 429 or 5xx from the
// endpoint is transient, not a credential problem.
func classifyToken(err error) *integration.Error {
	var te *authx.TokenError
	if errors.As(err, &te) {
		switch {
		case te.Status == 429:
			return integration.Wrap(integration.CodeUpstreamRateLimit, err, "the token endpoint rate limited hallpass")
		case te.Status >= 500:
			return integration.Wrap(integration.CodeUpstreamError, err, "the token endpoint failed (HTTP %d)", te.Status)
		}
	}
	return authx.ClassifyTokenError(err)
}

// --- Graph transport --------------------------------------------------------

// graphError is the body Graph sends with 4xx/5xx.
type graphError struct {
	Error struct {
		Code string `json:"code"`
	} `json:"error"`
}

// do performs one Graph call. A 401 invalidates the cached token and the
// call is retried once. 403 means hallpass lacks an application permission.
// notFound builds the error for a 404, which depends on context.
func (c *Connection) do(ctx context.Context, req *httpx.Request, notFound func() error) (*httpx.Response, error) {
	resp, err := c.graph.Do(ctx, req)
	if httpx.Status(err) == 401 {
		c.tokens.Invalidate()
		resp, err = c.graph.Do(ctx, req)
	}
	if err == nil {
		return resp, nil
	}
	var te *authx.TokenError
	if errors.As(err, &te) {
		return nil, classifyToken(err)
	}
	switch httpx.Status(err) {
	case 404:
		if notFound != nil {
			return nil, notFound()
		}
	case 403:
		code := errorCode(err)
		if code == "Authorization_RequestDenied" {
			return nil, integration.Wrap(integration.CodeCredentialRejected, err, "the app registration lacks an application permission for this call (Authorization_RequestDenied)")
		}
		return nil, integration.Wrap(integration.CodeCredentialRejected, err, "Graph refused the call (HTTP 403)")
	}
	return nil, httpx.Classify(err)
}

// errorCode extracts error.code from a Graph error body snippet. The message
// is never used.
func errorCode(err error) string {
	var se *httpx.StatusError
	if !errors.As(err, &se) {
		return ""
	}
	var ge graphError
	if json.Unmarshal([]byte(se.Snippet), &ge) != nil {
		// The snippet may be cut; try the code alone.
		i := strings.Index(se.Snippet, `"code"`)
		if i < 0 {
			return ""
		}
		rest := se.Snippet[i+len(`"code"`):]
		rest = strings.TrimLeft(rest, " :")
		if !strings.HasPrefix(rest, `"`) {
			return ""
		}
		rest = rest[1:]
		if j := strings.Index(rest, `"`); j >= 0 {
			return rest[:j]
		}
		return ""
	}
	return ge.Error.Code
}

func (c *Connection) getJSON(ctx context.Context, path string, header http.Header, out any, notFound func() error) error {
	resp, err := c.do(ctx, &httpx.Request{Method: http.MethodGet, Path: path, Header: header}, notFound)
	if err != nil {
		return err
	}
	if out != nil {
		if err := resp.JSON(out); err != nil {
			return integration.Wrap(integration.CodeUpstreamError, err, "Graph returned an unreadable response")
		}
	}
	return nil
}

// listPage is one page of a Graph collection.
type listPage struct {
	Value    []json.RawMessage `json:"value"`
	NextLink string            `json:"@odata.nextLink"`
}

// list fetches every page of a collection. Graph's nextLink is absolute.
func (c *Connection) list(ctx context.Context, path string, header http.Header, notFound func() error) ([]json.RawMessage, error) {
	var out []json.RawMessage
	for n := 0; path != ""; n++ {
		if n >= httpx.MaxPages {
			return nil, integration.Wrap(integration.CodeUpstreamError, httpx.ErrTooManyPages, "the Graph collection has too many pages")
		}
		var page listPage
		if err := c.getJSON(ctx, path, header, &page, notFound); err != nil {
			return nil, err
		}
		out = append(out, page.Value...)
		path = page.NextLink
		if path != "" && !strings.HasPrefix(path, c.graph.Base+"/") {
			return nil, integration.Errorf(integration.CodeUpstreamError, "Graph returned a nextLink outside the connection's url")
		}
	}
	return out, nil
}

// queryEscape encodes an OData literal for a query string. Spaces become
// %20 rather than '+', which OData parsers do not always decode.
func queryEscape(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

// odataString quotes a string literal for $filter: ' is doubled.
func odataString(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func resourceNotVisible(what string) func() error {
	return func() error {
		return integration.Errorf(integration.CodeResourceNotVisible, "%s was not found or is not visible to hallpass", what)
	}
}

// --- identity ---------------------------------------------------------------

// graphUser is the subset of microsoft.graph.user hallpass reads.
type graphUser struct {
	ID                string `json:"id"`
	UserPrincipalName string `json:"userPrincipalName"`
	Mail              string `json:"mail"`
	AccountEnabled    *bool  `json:"accountEnabled"`
	UserType          string `json:"userType"`
	DisplayName       string `json:"displayName"`
}

// ResolveIdentity finds the Entra user: by UPN or id, then by mail, then by
// proxy address.
func (c *Connection) ResolveIdentity(ctx context.Context, u integration.User) (integration.Identity, error) {
	email := strings.TrimSpace(u.Email)
	if !emailRe.MatchString(email) {
		return integration.Identity{}, integration.Errorf(integration.CodeInvalidRequest, "user email %q is not an address", email)
	}
	var user graphUser
	notFound := errors.New("user not found")
	err := c.getJSON(ctx, "/v1.0/users/"+httpx.PathEscape(email)+"?$select="+userSelect, nil, &user, func() error { return notFound })
	switch {
	case err == nil:
		return identityOf(user), nil
	case !errors.Is(err, notFound):
		return integration.Identity{}, err
	}
	users, err := c.findUsers(ctx, "mail eq "+odataString(email), nil)
	if err != nil {
		return integration.Identity{}, err
	}
	if len(users) == 0 {
		// UNVERIFIED: the proxyAddresses/any filter with ConsistencyLevel
		// eventual and $count=true is documented as an advanced query;
		// whether the smtp: prefix match needs lower-casing is not verified.
		h := http.Header{"ConsistencyLevel": {"eventual"}}
		users, err = c.findUsers(ctx, "proxyAddresses/any(p:p eq "+odataString("smtp:"+email)+")", h)
		if err != nil {
			return integration.Identity{}, err
		}
	}
	switch len(users) {
	case 0:
		return integration.Identity{}, integration.UserNotFound("no Entra user has %s as UPN, mail or proxy address", email)
	case 1:
		return identityOf(users[0]), nil
	default:
		return integration.Identity{}, integration.UserAmbiguous("%d Entra users match %s", len(users), email)
	}
}

func (c *Connection) findUsers(ctx context.Context, filter string, header http.Header) ([]graphUser, error) {
	path := "/v1.0/users?$filter=" + queryEscape(filter) + "&$select=" + userSelect
	if header != nil {
		path += "&$count=true"
	}
	raw, err := c.list(ctx, path, header, nil)
	if err != nil {
		return nil, err
	}
	users := make([]graphUser, 0, len(raw))
	for _, r := range raw {
		var u graphUser
		if err := json.Unmarshal(r, &u); err != nil {
			return nil, integration.Wrap(integration.CodeUpstreamError, err, "Graph returned an unreadable user")
		}
		users = append(users, u)
	}
	return users, nil
}

// identityOf builds the identity. account_enabled is "true", "false" or,
// when Graph did not report accountEnabled at all, "unknown": a missing
// value is never taken as enabled.
func identityOf(u graphUser) integration.Identity {
	enabled := "unknown"
	if u.AccountEnabled != nil {
		enabled = fmt.Sprint(*u.AccountEnabled)
	}
	id := integration.Identity{
		ID:      u.ID,
		Display: u.UserPrincipalName,
		Attrs: map[string]string{
			"upn":             u.UserPrincipalName,
			"mail":            u.Mail,
			"account_enabled": enabled,
			"user_type":       u.UserType,
			"guest":           fmt.Sprint(strings.EqualFold(u.UserType, "Guest")),
		},
		Native: u,
	}
	if id.Display == "" {
		id.Display = u.ID
	}
	return id
}

// --- checks -----------------------------------------------------------------

// Check answers one question.
func (c *Connection) Check(ctx context.Context, r integration.CheckRequest) (integration.Decision, error) {
	t, err := parseRef(r.ActionName, r.Resource)
	if err != nil {
		return integration.Decision{}, err
	}
	if !guidRe.MatchString(r.Identity.ID) {
		return integration.Decision{}, integration.Errorf(integration.CodeInvalidRequest, "identity id is not an Entra object id")
	}
	who := r.Identity.Display
	if r.Identity.Attr("guest") == "true" {
		who += " (guest account)"
	}
	switch r.Identity.Attr("account_enabled") {
	case "true":
	case "false":
		return integration.Denied("%s: account disabled", who), nil
	default:
		return integration.Unsupported("%s: Graph did not report whether the account is enabled", who), nil
	}
	switch r.ActionName {
	case "user.active":
		if !c.isSelf(r.Identity, t.id) {
			return integration.Unsupported("user.active is evaluated for the caller's own account only; %s is another account", t.id), nil
		}
		return integration.Allowed("%s: account enabled", who), nil
	case "group.member":
		return c.checkGroup(ctx, r.Identity, who, t.id)
	case "role.member":
		return c.checkRole(ctx, r.Identity, who, t.id)
	case "team.member", "team.owner":
		return c.checkTeam(ctx, r.ActionName, r.Identity, who, t)
	case "channel.read", "channel.owner", "channel.message.post":
		return c.checkChannel(ctx, r.ActionName, r.Identity, who, t)
	case "file.read", "file.edit", "file.share", "file.delete":
		return c.checkFile(ctx, r.ActionName, r.Identity, who, t)
	case "mail.send_as_self":
		if !c.isSelf(r.Identity, t.id) {
			return integration.Unsupported("mailbox %s is not %s's own; Send As, Send on Behalf and Full Access have no Graph API", t.id, who), nil
		}
		if r.Identity.Attr("mail") == "" {
			// An empty mail attribute does not prove there is no mailbox
			// (unlicensed users, on-premises mailboxes, sync lag).
			return integration.Unsupported("%s has no mail attribute in Entra; whether a mailbox exists is unknown", who), nil
		}
		return integration.Allowed("%s may send from their own mailbox", who), nil
	case "mail.send_as", "mail.send_on_behalf", "mailbox.full_access":
		return integration.Unsupported("Send As, Send on Behalf and Full Access are Exchange delegations with no Graph API; hallpass cannot evaluate %s on mailbox %s", r.ActionName, t.id), nil
	case "calendar.read", "calendar.write":
		return integration.Unsupported("calendar delegation and folder permissions have no application-permission Graph API; hallpass cannot evaluate %s on mailbox %s", r.ActionName, t.id), nil
	}
	return integration.Decision{}, integration.Errorf(integration.CodeInvalidRequest, "unknown action %q", r.ActionName)
}

// isSelf reports whether the resource id names the resolved identity.
func (c *Connection) isSelf(id integration.Identity, res string) bool {
	for _, v := range []string{id.ID, id.Attr("upn"), id.Attr("mail")} {
		if v != "" && strings.EqualFold(v, res) {
			return true
		}
	}
	return false
}

// checkMemberGroups asks Graph which of the given groups the user belongs to,
// transitively, in batches of 20. It returns the matching ids, lower-cased.
func (c *Connection) checkMemberGroups(ctx context.Context, userID string, groupIDs []string) (map[string]bool, error) {
	matched := map[string]bool{}
	for start := 0; start < len(groupIDs); start += checkBatch {
		end := start + checkBatch
		if end > len(groupIDs) {
			end = len(groupIDs)
		}
		var out struct {
			Value []string `json:"value"`
		}
		body := map[string][]string{"groupIds": groupIDs[start:end]}
		resp, err := c.do(ctx, &httpx.Request{Method: http.MethodPost, Path: "/v1.0/users/" + httpx.PathEscape(userID) + "/checkMemberGroups", JSON: body, Idempotent: boolPtr(true)},
			resourceNotVisible("user "+userID))
		if err != nil {
			return nil, err
		}
		if err := resp.JSON(&out); err != nil {
			return nil, integration.Wrap(integration.CodeUpstreamError, err, "Graph returned an unreadable checkMemberGroups response")
		}
		for _, g := range out.Value {
			matched[strings.ToLower(g)] = true
		}
	}
	return matched, nil
}

func boolPtr(b bool) *bool { return &b }

// groupVisibility reads the group's visibility. A 404 is
// resource_not_visible: checkMemberGroups alone cannot tell a group the
// user is not in from a group that does not exist.
func (c *Connection) groupVisibility(ctx context.Context, groupID string) (string, error) {
	var g struct {
		ID         string `json:"id"`
		Visibility string `json:"visibility"`
	}
	// UNVERIFIED: GroupMember.Read.All is documented as sufficient for
	// GET /groups/{id}; visibility is null for security groups and
	// HiddenMembership only for Microsoft 365 groups created that way.
	if err := c.getJSON(ctx, "/v1.0/groups/"+httpx.PathEscape(groupID)+"?$select=id,visibility", nil, &g, resourceNotVisible("group "+groupID)); err != nil {
		return "", err
	}
	return g.Visibility, nil
}

func (c *Connection) checkGroup(ctx context.Context, id integration.Identity, who, groupID string) (integration.Decision, error) {
	visibility, err := c.groupVisibility(ctx, groupID)
	if err != nil {
		return integration.Decision{}, err
	}
	matched, err := c.checkMemberGroups(ctx, id.ID, []string{groupID})
	if err != nil {
		return integration.Decision{}, err
	}
	if matched[strings.ToLower(groupID)] {
		return integration.Allowed("%s is a transitive member of group %s", who, groupID), nil
	}
	if strings.EqualFold(visibility, "HiddenMembership") {
		// UNVERIFIED: without Member.Read.Hidden, checkMemberGroups omits
		// hidden-membership groups rather than failing, so a miss proves
		// nothing.
		return integration.Unsupported("group %s has hidden membership; checkMemberGroups omits it without Member.Read.Hidden, so %s's membership is unknown", groupID, who), nil
	}
	return integration.Denied("%s is not a member of group %s", who, groupID), nil
}

func (c *Connection) checkRole(ctx context.Context, id integration.Identity, who, templateID string) (integration.Decision, error) {
	// UNVERIFIED: the OData cast path transitiveMemberOf/microsoft.graph.directoryRole
	// with $select=roleTemplateId; role-assignable groups are covered by the
	// transitive expansion.
	raw, err := c.list(ctx, "/v1.0/users/"+httpx.PathEscape(id.ID)+"/transitiveMemberOf/microsoft.graph.directoryRole?$select=roleTemplateId", nil, resourceNotVisible("user "+id.ID))
	if err != nil {
		var ie *integration.Error
		if errors.As(err, &ie) && ie.Code == integration.CodeCredentialRejected {
			return integration.Decision{}, integration.Wrap(integration.CodeCredentialRejected, err, "reading directory roles needs RoleManagement.Read.Directory")
		}
		return integration.Decision{}, err
	}
	for _, r := range raw {
		var role struct {
			RoleTemplateID string `json:"roleTemplateId"`
		}
		if json.Unmarshal(r, &role) == nil && strings.EqualFold(role.RoleTemplateID, templateID) {
			return integration.Allowed("%s holds directory role template %s", who, templateID), nil
		}
	}
	return integration.Denied("%s does not hold directory role template %s (eligible PIM assignments are not activated)", who, templateID), nil
}

// conversationMember is a Teams membership record.
type conversationMember struct {
	UserID string   `json:"userId"`
	Roles  []string `json:"roles"`
}

// membership fetches the caller's membership records under a members
// collection. The filter is the documented userId filter, but the result
// is never trusted: only records whose userId is the caller's are kept, so
// an ignored or unsupported filter cannot turn the whole roster into a
// membership.
func (c *Connection) membership(ctx context.Context, collection, userID string, notFound func() error) ([]conversationMember, error) {
	filter := "(microsoft.graph.aadUserConversationMember/userId eq " + odataString(userID) + ")"
	raw, err := c.list(ctx, collection+"?$filter="+queryEscape(filter), nil, notFound)
	if err != nil {
		return nil, err
	}
	out := make([]conversationMember, 0, len(raw))
	for _, r := range raw {
		var m conversationMember
		if err := json.Unmarshal(r, &m); err != nil {
			return nil, integration.Wrap(integration.CodeUpstreamError, err, "Graph returned an unreadable member")
		}
		if !strings.EqualFold(m.UserID, userID) {
			continue
		}
		out = append(out, m)
	}
	return out, nil
}

func hasOwner(ms []conversationMember) bool {
	for _, m := range ms {
		for _, r := range m.Roles {
			if strings.EqualFold(r, "owner") {
				return true
			}
		}
	}
	return false
}

func (c *Connection) checkTeam(ctx context.Context, action string, id integration.Identity, who string, t ref) (integration.Decision, error) {
	ms, err := c.membership(ctx, "/v1.0/teams/"+httpx.PathEscape(t.id)+"/members", id.ID, resourceNotVisible("team "+t.id))
	if err != nil {
		return integration.Decision{}, err
	}
	if len(ms) == 0 {
		return integration.Denied("%s is not a member of team %s", who, t.id), nil
	}
	if action == "team.owner" {
		if hasOwner(ms) {
			return integration.Allowed("%s owns team %s", who, t.id), nil
		}
		return integration.Denied("%s is a member but not an owner of team %s", who, t.id), nil
	}
	return integration.Allowed("%s is a member of team %s", who, t.id), nil
}

type channelInfo struct {
	MembershipType     string `json:"membershipType"`
	ModerationSettings *struct {
		UserNewMessageRestriction string `json:"userNewMessageRestriction"`
	} `json:"moderationSettings"`
}

func (c *Connection) checkChannel(ctx context.Context, action string, id integration.Identity, who string, t ref) (integration.Decision, error) {
	base := "/v1.0/teams/" + httpx.PathEscape(t.id) + "/channels/" + httpx.PathEscape(t.channel)
	notFound := resourceNotVisible(t.describe())
	var ch channelInfo
	if err := c.getJSON(ctx, base, nil, &ch, notFound); err != nil {
		return integration.Decision{}, err
	}
	var ms []conversationMember
	var err error
	kind := strings.ToLower(ch.MembershipType)
	switch kind {
	case "standard":
		ms, err = c.membership(ctx, "/v1.0/teams/"+httpx.PathEscape(t.id)+"/members", id.ID, resourceNotVisible("team "+t.id))
	case "private":
		ms, err = c.membership(ctx, base+"/members", id.ID, notFound)
	case "shared":
		// UNVERIFIED: /allMembers lists direct and team-shared members of a
		// shared channel; the userId filter is assumed to apply there too.
		ms, err = c.membership(ctx, base+"/allMembers", id.ID, notFound)
	case "":
		// A missing membershipType is not assumed to be standard: the team
		// roster would be the wrong answer for a private or shared channel.
		return integration.Unsupported("channel %s reports no membership type; hallpass cannot tell which roster applies", t.channel), nil
	default:
		return integration.Unsupported("channel %s has membership type %q, which hallpass does not model", t.channel, ch.MembershipType), nil
	}
	if err != nil {
		return integration.Decision{}, err
	}
	what := t.describe()
	if len(ms) == 0 {
		return integration.Denied("%s is not a member of %s (%s channel)", who, what, kind), nil
	}
	switch action {
	case "channel.owner":
		if hasOwner(ms) {
			return integration.Allowed("%s owns %s (%s channel)", who, what, kind), nil
		}
		return integration.Denied("%s is a member but not an owner of %s (%s channel)", who, what, kind), nil
	case "channel.message.post":
		if ch.ModerationSettings != nil {
			restr := ch.ModerationSettings.UserNewMessageRestriction
			if restr != "" && !strings.EqualFold(restr, "everyone") {
				return integration.Unsupported("%s restricts new messages to %s; hallpass does not evaluate channel moderation", what, restr), nil
			}
		}
		return integration.Allowed("%s is a member of %s (%s channel); channel moderation settings are not evaluated", who, what, kind), nil
	}
	return integration.Allowed("%s is a member of %s (%s channel)", who, what, kind), nil
}

// --- files ------------------------------------------------------------------

// idRef is one principal inside a Graph identitySet.
type idRef struct {
	ID string `json:"id"`
}

type identitySet struct {
	User      *idRef `json:"user,omitempty"`
	Group     *idRef `json:"group,omitempty"`
	SiteGroup *idRef `json:"siteGroup,omitempty"`
	SiteUser  *idRef `json:"siteUser,omitempty"`
}

type sharingLink struct {
	Scope string `json:"scope"`
}

type drivePermission struct {
	Roles                 []string      `json:"roles"`
	GrantedToV2           *identitySet  `json:"grantedToV2,omitempty"`
	GrantedToIdentitiesV2 []identitySet `json:"grantedToIdentitiesV2,omitempty"`
	Link                  *sharingLink  `json:"link,omitempty"`
}

const (
	levelNone = iota
	levelRead
	levelWrite
	levelOwner
)

// level collapses Graph roles to read/write/owner. SharePoint custom
// permission levels appear as other strings ("sp.full control",
// "sp.views"); they add nothing to the level but are reported as unknown,
// since they may grant more than the recognised roles say.
func level(roles []string) (best int, unknown bool) {
	best = levelNone
	for _, r := range roles {
		l := levelNone
		switch strings.ToLower(r) {
		case "owner":
			l = levelOwner
		case "write":
			l = levelWrite
		case "read":
			l = levelRead
		default:
			unknown = true
		}
		if l > best {
			best = l
		}
	}
	return best, unknown
}

func needed(action string) int {
	switch action {
	case "file.read":
		return levelRead
	case "file.edit":
		return levelWrite
	case "file.delete":
		// UNVERIFIED: write on the item is assumed to include delete; SharePoint
		// "contribute without delete" levels are not distinguishable.
		return levelWrite
	default: // file.share
		return levelOwner
	}
}

func verb(action string) string {
	return strings.TrimPrefix(action, "file.")
}

func (c *Connection) checkFile(ctx context.Context, action string, id integration.Identity, who string, t ref) (integration.Decision, error) {
	what := t.describe()
	notFound := resourceNotVisible(what)
	itemPath := "/v1.0/drives/" + httpx.PathEscape(t.id) + "/items/" + httpx.PathEscape(t.item)
	raw, err := c.list(ctx, itemPath+"/permissions", nil, notFound)
	if err != nil {
		return integration.Decision{}, err
	}
	perms := make([]drivePermission, 0, len(raw))
	for _, r := range raw {
		var p drivePermission
		if err := json.Unmarshal(r, &p); err != nil {
			return integration.Decision{}, integration.Wrap(integration.CodeUpstreamError, err, "Graph returned an unreadable permission")
		}
		perms = append(perms, p)
	}
	need := needed(action)
	guest := id.Attr("guest") == "true"
	direct := levelNone
	orgLink := levelNone
	groupLevels := map[string]int{}
	// groupUnknown marks groups whose grant carries an unrecognised role.
	groupUnknown := map[string]bool{}
	// unknownRole is set when a grant that reaches the caller (directly, via
	// a group they are in, or via a usable organization link) carries a
	// role hallpass does not model; the answer is then unknown, not deny.
	unknownRole := false
	unknownScope := ""
	siteGroup, anonymous, guestOrgLink := false, false, false
	for _, p := range perms {
		l, unk := level(p.Roles)
		sets := append([]identitySet(nil), p.GrantedToIdentitiesV2...)
		if p.GrantedToV2 != nil {
			sets = append(sets, *p.GrantedToV2)
		}
		for _, s := range sets {
			switch {
			case s.User != nil && strings.EqualFold(s.User.ID, id.ID):
				direct = max(direct, l)
				unknownRole = unknownRole || unk
			case s.Group != nil && guidRe.MatchString(s.Group.ID):
				g := strings.ToLower(s.Group.ID)
				groupLevels[g] = max(groupLevels[g], l)
				groupUnknown[g] = groupUnknown[g] || unk
			case s.SiteGroup != nil:
				siteGroup = true
			case s.SiteUser != nil && s.User == nil:
				// A SharePoint-only principal (for example a claims login) that
				// Graph could not map to an Entra user.
				siteGroup = true
			}
		}
		if p.Link != nil {
			switch strings.ToLower(p.Link.Scope) {
			case "organization":
				if guest {
					// UNVERIFIED: "people in your organization" links cannot be
					// redeemed by guest (B2B) accounts, as Microsoft's sharing
					// documentation states; the link is not credited to a guest.
					guestOrgLink = true
					continue
				}
				orgLink = max(orgLink, l)
				unknownRole = unknownRole || unk
			case "anonymous":
				anonymous = true
			case "users":
				// The people the link was sent to are listed in
				// grantedToIdentitiesV2 and handled above.
			default:
				unknownScope = p.Link.Scope
			}
		}
	}
	v := verb(action)
	if direct >= need {
		return integration.Allowed("%s may %s %s: granted directly", who, v, what), nil
	}
	// UNVERIFIED: drives/{id}?$select=owner exposes owner.user.id for
	// OneDrive; SharePoint document libraries report the site (group) instead.
	var drive struct {
		Owner *identitySet `json:"owner"`
	}
	if err := c.getJSON(ctx, "/v1.0/drives/"+httpx.PathEscape(t.id)+"?$select=owner", nil, &drive, func() error { return errDriveNotFound }); err != nil {
		// The item's permissions were readable, so a 404 on the drive
		// itself only means the owner rule cannot apply; the group and link
		// rules still can.
		if !errors.Is(err, errDriveNotFound) {
			return integration.Decision{}, err
		}
	} else if drive.Owner != nil && drive.Owner.User != nil && strings.EqualFold(drive.Owner.User.ID, id.ID) {
		return integration.Allowed("%s may %s %s: owner of the drive", who, v, what), nil
	}
	if len(groupLevels) > 0 {
		ids := make([]string, 0, len(groupLevels))
		for g := range groupLevels {
			ids = append(ids, g)
		}
		matched, err := c.checkMemberGroups(ctx, id.ID, ids)
		if err != nil {
			return integration.Decision{}, err
		}
		viaGroup := levelNone
		for g := range matched {
			viaGroup = max(viaGroup, groupLevels[g])
			unknownRole = unknownRole || groupUnknown[g]
		}
		if viaGroup >= need {
			return integration.Allowed("%s may %s %s: granted to a group they belong to", who, v, what), nil
		}
		direct = max(direct, viaGroup)
	}
	if orgLink >= need {
		return integration.Allowed("%s may %s %s via an organization-wide sharing link", who, v, what), nil
	}
	direct = max(direct, orgLink)
	if unknownRole {
		return integration.Unsupported("%s is granted a role on %s that hallpass does not model (a custom SharePoint permission level); their access is unknown", who, what), nil
	}
	if unknownScope != "" {
		return integration.Unsupported("%s has a sharing link with scope %q, which hallpass does not model; %s's access is unknown", what, unknownScope, who), nil
	}
	if action == "file.share" && direct >= levelRead {
		return integration.Unsupported("%s has %s access to %s but is not an owner; sharing rights depend on site settings", who, levelName(direct), what), nil
	}
	if siteGroup {
		return integration.Unsupported("%s is granted to SharePoint site groups, which Graph cannot expand; %s's access is unknown", what, who), nil
	}
	if anonymous {
		return integration.Unsupported("%s has an anonymous sharing link; %s's own access is unknown", what, who), nil
	}
	if direct >= levelRead {
		return integration.Denied("%s has %s access to %s, which does not include %s", who, levelName(direct), what, v), nil
	}
	if guestOrgLink {
		return integration.Denied("no permission on %s is granted to %s or a group they belong to; its organization-wide sharing link is not usable by guest accounts", what, who), nil
	}
	return integration.Denied("no permission on %s is granted to %s or a group they belong to", what, who), nil
}

// errDriveNotFound marks a 404 on the drive-owner lookup, which is ignored.
var errDriveNotFound = errors.New("drive not found")

func levelName(l int) string {
	switch l {
	case levelOwner:
		return "owner"
	case levelWrite:
		return "write"
	case levelRead:
		return "read"
	}
	return "no"
}

// --- probe ------------------------------------------------------------------

// requiredRoles are the application permissions the checks need.
var requiredRoles = []string{"User.Read.All", "GroupMember.Read.All", "TeamMember.Read.All", "ChannelMember.Read.All", "Files.Read.All"}

// Probe fetches a token, reads the organization and reports the granted
// application permissions.
func (c *Connection) Probe(ctx context.Context) (integration.ProbeResult, error) {
	var org listPage
	if err := c.getJSON(ctx, "/v1.0/organization?$select=id,displayName", nil, &org, nil); err != nil {
		return integration.ProbeResult{}, err
	}
	summary := "authenticated as application " + c.clientID
	if len(org.Value) > 0 {
		var o struct {
			ID          string `json:"id"`
			DisplayName string `json:"displayName"`
		}
		if json.Unmarshal(org.Value[0], &o) == nil {
			summary += fmt.Sprintf(" in Microsoft 365 tenant %q (%s)", o.DisplayName, o.ID)
		}
	}
	res := integration.ProbeResult{Summary: summary}
	roles, err := c.grantedRoles(ctx)
	if err != nil {
		res.Warnings = append(res.Warnings, "could not verify permissions: reading the app's own appRoleAssignments failed")
		return res, nil
	}
	have := map[string]bool{}
	for _, r := range roles {
		have[r] = true
		if strings.Contains(r, ".ReadWrite.") || strings.HasSuffix(r, ".ReadWrite") || !strings.Contains(r, ".Read") {
			res.Warnings = append(res.Warnings, "application permission "+r+" allows writes; hallpass only needs read permissions")
		}
	}
	for _, r := range requiredRoles {
		if !have[r] {
			res.Warnings = append(res.Warnings, "application permission "+r+" is not granted; checks that need it will be unknown (credential_rejected)")
		}
	}
	if have["Files.Read.All"] {
		res.Warnings = append(res.Warnings, "Files.Read.All lets this credential read every file in the tenant; keep the secret tightly held")
	}
	if !have["Member.Read.Hidden"] {
		res.Warnings = append(res.Warnings, "Member.Read.Hidden is not granted; hidden-membership groups are omitted, which can produce a false deny")
	}
	return res, nil
}

// grantedRoles lists the application permission values granted to the app.
func (c *Connection) grantedRoles(ctx context.Context) ([]string, error) {
	// UNVERIFIED: whether an app may read its own service principal and
	// appRoleAssignments with only the permissions listed in the doc;
	// Application.Read.All may be needed, in which case the probe warns.
	raw, err := c.list(ctx, "/v1.0/servicePrincipals?$filter="+queryEscape("appId eq "+odataString(c.clientID))+"&$select=id", nil, nil)
	if err != nil {
		return nil, err
	}
	if len(raw) != 1 {
		return nil, fmt.Errorf("expected one service principal, got %d", len(raw))
	}
	var sp struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(raw[0], &sp); err != nil || !guidRe.MatchString(sp.ID) {
		return nil, errors.New("service principal without an id")
	}
	raw, err = c.list(ctx, "/v1.0/servicePrincipals/"+httpx.PathEscape(sp.ID)+"/appRoleAssignments", nil, nil)
	if err != nil {
		return nil, err
	}
	// Assignments carry role ids; the names live on the resource service
	// principal's appRoles.
	byResource := map[string][]string{}
	for _, r := range raw {
		var a struct {
			AppRoleID  string `json:"appRoleId"`
			ResourceID string `json:"resourceId"`
		}
		if json.Unmarshal(r, &a) == nil && guidRe.MatchString(a.ResourceID) {
			byResource[a.ResourceID] = append(byResource[a.ResourceID], strings.ToLower(a.AppRoleID))
		}
	}
	var out []string
	for resID, roleIDs := range byResource {
		var res struct {
			AppRoles []struct {
				ID    string `json:"id"`
				Value string `json:"value"`
			} `json:"appRoles"`
		}
		if err := c.getJSON(ctx, "/v1.0/servicePrincipals/"+httpx.PathEscape(resID)+"?$select=appRoles", nil, &res, nil); err != nil {
			return nil, err
		}
		names := map[string]string{}
		for _, ar := range res.AppRoles {
			names[strings.ToLower(ar.ID)] = ar.Value
		}
		for _, rid := range roleIDs {
			if v := names[rid]; v != "" {
				out = append(out, v)
			}
		}
	}
	return out, nil
}
