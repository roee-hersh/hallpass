// Package zendesk checks what a team member may do in one Zendesk Support
// account.
//
// hallpass authenticates as an administrator (an API token or an OAuth
// token), finds the user by email and reads the role, the custom role's
// configuration on Enterprise plans or the ticket restriction on other
// plans, and the groups the agent belongs to. Ticket questions read the
// ticket (its group, assignee, requester, organization and status) and
// apply the agent's ticket access. Administrators may do everything, end
// users only see and comment on their own tickets, light agents only see
// and comment privately. Nothing is written.
package zendesk

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/roee-hersh/hallpass/internal/httpx"
	"github.com/roee-hersh/hallpass/internal/integration"
)

const (
	authToken = "token"
	authOAuth = "oauth"

	roleAdmin   = "admin"
	roleAgent   = "agent"
	roleEndUser = "end-user"

	// roleTypeLightAgent is role_type 1.
	roleTypeLightAgent = 1

	// rolesTTL is how long the custom role list is kept.
	rolesTTL = 5 * time.Minute
)

// Integration is the zendesk product.
type Integration struct{}

// Name is "zendesk".
func (Integration) Name() string { return "zendesk" }

// Fields of a zendesk connection.
func (Integration) Fields() []integration.Field {
	return []integration.Field{
		integration.URLField(true, "the account URL, e.g. https://acme.zendesk.com"),
		{Name: "auth_mode", Default: authToken, Enum: []string{authToken, authOAuth},
			Description: "token: an API token with username (HTTP Basic email/token); oauth: an OAuth access token (Bearer)"},
		{Name: "username", Description: "auth_mode token: the email of the administrator the API token acts as"},
		integration.CredentialField(true, "the API token or OAuth access token"),
	}
}

// New builds a connection. It touches no network.
func (Integration) New(_ context.Context, s *integration.Settings, d integration.Deps) (integration.Connection, error) {
	hc, err := d.HTTPClient(s)
	if err != nil {
		return nil, err
	}
	base := strings.TrimRight(s.Get("url"), "/")
	if base == "" {
		return nil, errors.New("url is required")
	}
	if s.Secret("credential").IsZero() {
		return nil, errors.New("credential is required")
	}
	cred := s.Secret("credential")
	token := func(context.Context) (string, error) {
		t, err := cred.GetString()
		if err != nil {
			return "", integration.Wrap(integration.CodeCredentialRejected, err, "the token could not be read")
		}
		return strings.TrimSpace(t), nil
	}
	c := &Connection{now: d.Now}
	if c.now == nil {
		c.now = time.Now
	}
	client := &httpx.Client{HTTP: hc, Base: base, Logger: d.Logger}
	switch s.Get("auth_mode") {
	case "", authToken:
		user := strings.TrimSpace(s.Get("username"))
		if !integration.IsEmail(user) {
			return nil, errors.New("username is required in auth_mode token and must be the administrator's email")
		}
		client.Auth = httpx.BasicAuth(user+"/token", token)
	case authOAuth:
		client.Auth = httpx.BearerAuth(token)
	default:
		return nil, fmt.Errorf("auth_mode %q must be token or oauth", s.Get("auth_mode"))
	}
	c.api = client
	return c, nil
}

// Connection is one Zendesk account.
type Connection struct {
	api *httpx.Client
	now func() time.Time

	mu           sync.Mutex
	roles        map[int64]customRole
	rolesFetched time.Time
}

// --- API transport ----------------------------------------------------------

// classify maps an API error to an integration error. 404 is left to the
// caller.
func classify(err error, what string) *integration.Error {
	switch httpx.Status(err) {
	case 401:
		return integration.Wrap(integration.CodeCredentialRejected, err, "Zendesk rejected hallpass's credential")
	case 403:
		return integration.Wrap(integration.CodeCredentialRejected, err, "Zendesk refused to %s (HTTP 403): hallpass's user lacks the permission; use an administrator", what)
	case 400, 422:
		return integration.Wrap(integration.CodeInvalidRequest, err, "Zendesk rejected the request to %s (HTTP %d)", what, httpx.Status(err))
	}
	return httpx.Classify(err)
}

func (c *Connection) getJSON(ctx context.Context, path string, q url.Values, out any) error {
	_, err := c.api.GetJSON(ctx, path, q, out)
	return err
}

// readError answers for a failed read of a named resource: 404 and 403
// both mean hallpass cannot see it (Zendesk answers 403 for a ticket
// outside its user's ticket access), anything else is classified.
func readError(err error, what fmt.Stringer) (integration.Decision, error) {
	switch httpx.Status(err) {
	case 404:
		return integration.UnknownDecision(integration.CodeResourceNotVisible, "%s does not exist or hallpass cannot see it", what), nil
	case 403:
		// UNVERIFIED: whether a ticket outside the credential's own ticket
		// access answers 403 or 404; both are "not visible".
		return integration.UnknownDecision(integration.CodeResourceNotVisible, "hallpass's Zendesk user may not see %s (HTTP 403); use an administrator", what), nil
	}
	return integration.Decision{}, classify(err, "read "+what.String())
}

// --- identity ---------------------------------------------------------------

// zdUser is the subset of a user hallpass reads.
type zdUser struct {
	ID                  int64   `json:"id"`
	Email               string  `json:"email"`
	Role                string  `json:"role"`
	RoleType            *int    `json:"role_type"`
	CustomRoleID        *int64  `json:"custom_role_id"`
	Active              *bool   `json:"active"`
	Suspended           *bool   `json:"suspended"`
	TicketRestriction   *string `json:"ticket_restriction"`
	OnlyPrivateComments *bool   `json:"only_private_comments"`
	OrganizationID      *int64  `json:"organization_id"`
}

// ResolveIdentity finds the user with the email. The search syntax matches
// more than exact addresses, so the address is compared exactly.
func (c *Connection) ResolveIdentity(ctx context.Context, u integration.User) (integration.Identity, error) {
	email := strings.ToLower(strings.TrimSpace(u.Email))
	if !integration.IsEmail(email) {
		return integration.Identity{}, integration.Errorf(integration.CodeInvalidRequest, "user email %q is not an address", email)
	}
	var body struct {
		Users []zdUser `json:"users"`
	}
	// IsEmail admits no space or quote, so the search term is one email clause.
	if err := c.getJSON(ctx, "/api/v2/users/search", url.Values{"query": {"email:" + email}}, &body); err != nil {
		return integration.Identity{}, classify(err, "search users")
	}
	var matches []zdUser
	for _, usr := range body.Users {
		if strings.EqualFold(usr.Email, email) {
			matches = append(matches, usr)
		}
	}
	switch len(matches) {
	case 0:
		return integration.Identity{}, integration.UserNotFound("no Zendesk user has email %s", email)
	case 1:
	default:
		return integration.Identity{}, integration.UserAmbiguous("%d Zendesk users have email %s", len(matches), email)
	}
	usr := matches[0]
	if usr.ID == 0 || usr.Role == "" {
		return integration.Identity{}, integration.Errorf(integration.CodeUpstreamError, "the user record for %s carries no id or role", email)
	}
	id := integration.Identity{ID: strconv.FormatInt(usr.ID, 10), Display: email, Attrs: map[string]string{
		"role":      usr.Role,
		"active":    boolAttr(usr.Active),
		"suspended": boolAttr(usr.Suspended),
	}}
	if usr.RoleType != nil {
		id.Attrs["role_type"] = strconv.Itoa(*usr.RoleType)
	}
	if usr.CustomRoleID != nil && *usr.CustomRoleID != 0 {
		id.Attrs["custom_role_id"] = strconv.FormatInt(*usr.CustomRoleID, 10)
	}
	if usr.TicketRestriction != nil {
		id.Attrs["ticket_restriction"] = *usr.TicketRestriction
	}
	if usr.OnlyPrivateComments != nil {
		id.Attrs["only_private_comments"] = fmt.Sprint(*usr.OnlyPrivateComments)
	}
	if usr.OrganizationID != nil && *usr.OrganizationID != 0 {
		id.Attrs["organization_id"] = strconv.FormatInt(*usr.OrganizationID, 10)
	}
	if usr.Role == roleAgent || usr.Role == roleAdmin {
		groups, err := c.groupMemberships(ctx, usr.ID)
		if err != nil {
			return integration.Identity{}, classify(err, "list the agent's groups")
		}
		id.Groups = groups
	}
	return id, nil
}

func boolAttr(b *bool) string {
	if b == nil {
		return "unknown"
	}
	return fmt.Sprint(*b)
}

// groupMemberships lists the ids of the groups the agent belongs to,
// following next_page links that stay under the API base.
func (c *Connection) groupMemberships(ctx context.Context, userID int64) ([]string, error) {
	var out []string
	req := &httpx.Request{Path: "/api/v2/users/" + strconv.FormatInt(userID, 10) + "/group_memberships"}
	err := c.api.Paginate(ctx, req, func(resp *httpx.Response) (*httpx.Request, error) {
		var page struct {
			Memberships []struct {
				GroupID int64 `json:"group_id"`
			} `json:"group_memberships"`
			NextPage string `json:"next_page"`
		}
		if err := resp.JSON(&page); err != nil {
			return nil, integration.Wrap(integration.CodeUpstreamError, err, "Zendesk returned an unreadable page")
		}
		for _, m := range page.Memberships {
			if m.GroupID != 0 {
				out = append(out, strconv.FormatInt(m.GroupID, 10))
			}
		}
		if page.NextPage == "" {
			return nil, nil
		}
		if !c.api.Within(page.NextPage) {
			return nil, integration.Errorf(integration.CodeUpstreamError, "Zendesk sent a next page outside its API")
		}
		return &httpx.Request{Path: page.NextPage}, nil
	})
	return out, err
}

// --- roles ------------------------------------------------------------------

// customRole is the subset of a custom role's configuration hallpass reads.
type customRole struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	RoleType      *int   `json:"role_type"`
	Configuration struct {
		TicketAccess         string `json:"ticket_access"`
		TicketEditing        *bool  `json:"ticket_editing"`
		TicketDeletion       *bool  `json:"ticket_deletion"`
		TicketMerge          *bool  `json:"ticket_merge"`
		TicketCommentAccess  string `json:"ticket_comment_access"`
		ModifyClosedTickets  *bool  `json:"modify_closed_tickets"`
		MacroAccess          string `json:"macro_access"`
		ViewAccess           string `json:"view_access"`
		OrganizationEditing  *bool  `json:"organization_editing"`
		EndUserProfileAccess string `json:"end_user_profile_access"`
		ManageBusinessRules  *bool  `json:"manage_business_rules"`
		LightAgent           *bool  `json:"light_agent"`
	} `json:"configuration"`
}

// customRoles lists the account's custom roles, cached for rolesTTL. The
// list is readable by any agent; a single role is not.
func (c *Connection) customRoles(ctx context.Context) (map[int64]customRole, error) {
	c.mu.Lock()
	if c.roles != nil && c.now().Sub(c.rolesFetched) < rolesTTL {
		roles := c.roles
		c.mu.Unlock()
		return roles, nil
	}
	c.mu.Unlock()
	var body struct {
		Roles []customRole `json:"custom_roles"`
	}
	if err := c.getJSON(ctx, "/api/v2/custom_roles", nil, &body); err != nil {
		return nil, err
	}
	roles := map[int64]customRole{}
	for _, r := range body.Roles {
		roles[r.ID] = r
	}
	c.mu.Lock()
	c.roles, c.rolesFetched = roles, c.now()
	c.mu.Unlock()
	return roles, nil
}

// grants is what the user may do, from the role, the custom role or the
// per-agent ticket restriction.
type grants struct {
	admin, endUser, light bool
	// ticketAccess is all, within-groups, within-groups-and-public-groups,
	// within-organization or assigned-only (agents), or requested (end users).
	ticketAccess string
	// The remaining fields are pointers: nil means the plan does not
	// expose the setting, so the answer is unknown.
	ticketEditing, ticketDeletion, ticketMerge, publicComments, modifyClosed *bool
	macroFull, viewFull, orgEditing, businessRules                           *bool
	// endUserProfile is edit, edit-within-org, full, readonly or "" (unknown).
	endUserProfile string
	roleName       string
}

func ptr(b bool) *bool { return &b }

// grantsFor derives the user's grants.
func (c *Connection) grantsFor(ctx context.Context, id integration.Identity) (grants, error) {
	var g grants
	switch id.Attr("role") {
	case roleAdmin:
		g.admin, g.roleName = true, "administrator"
		return g, nil
	case roleEndUser:
		g.endUser, g.roleName, g.ticketAccess = true, "end user", "requested"
		return g, nil
	case roleAgent:
	default:
		return g, integration.Errorf(integration.CodeUnsupported, "%s has role %q, which hallpass does not know", id.Display, id.Attr("role"))
	}
	g.roleName = "agent"
	if id.Attr("role_type") == strconv.Itoa(roleTypeLightAgent) {
		g.light = true
	}
	if crid := id.Attr("custom_role_id"); crid != "" {
		roles, err := c.customRoles(ctx)
		if err != nil {
			return g, classify(err, "list the custom roles")
		}
		rid, _ := strconv.ParseInt(crid, 10, 64)
		role, ok := roles[rid]
		if !ok {
			return g, integration.Errorf(integration.CodeResourceNotVisible, "custom role %s of %s is not among the account's custom roles", crid, id.Display)
		}
		cfg := role.Configuration
		g.roleName = "custom role " + role.Name
		if cfg.LightAgent != nil && *cfg.LightAgent {
			g.light = true
		}
		g.ticketAccess = cfg.TicketAccess
		g.ticketEditing, g.ticketDeletion, g.ticketMerge, g.modifyClosed = cfg.TicketEditing, cfg.TicketDeletion, cfg.TicketMerge, cfg.ModifyClosedTickets
		if cfg.TicketCommentAccess != "" {
			g.publicComments = ptr(cfg.TicketCommentAccess == "public")
		}
		if cfg.MacroAccess != "" {
			g.macroFull = ptr(cfg.MacroAccess == "full")
		}
		if cfg.ViewAccess != "" {
			g.viewFull = ptr(cfg.ViewAccess == "full")
		}
		g.orgEditing, g.businessRules = cfg.OrganizationEditing, cfg.ManageBusinessRules
		g.endUserProfile = cfg.EndUserProfileAccess
		return g, nil
	}
	// Plans without custom roles: the profile's ticket restriction.
	// UNVERIFIED: whether role_type is null or 0 for a plain agent, and
	// whether a light agent's ticket_restriction is null when the profile
	// shows all tickets; both readings are accepted.
	if rt := id.Attr("role_type"); rt != "" && rt != "0" && !g.light {
		return g, integration.Errorf(integration.CodeUnsupported, "%s is an agent of role type %s (chat agent or contributor), whose permissions hallpass does not model", id.Display, rt)
	}
	switch id.Attr("ticket_restriction") {
	case "":
		g.ticketAccess = "all"
	case "groups":
		g.ticketAccess = "within-groups"
	case "organization":
		g.ticketAccess = "within-organization"
	case "assigned":
		g.ticketAccess = "assigned-only"
	case "requested":
		g.ticketAccess = "requested"
	default:
		return g, integration.Errorf(integration.CodeUnsupported, "%s has ticket restriction %q, which hallpass does not know", id.Display, id.Attr("ticket_restriction"))
	}
	if g.light {
		g.ticketEditing, g.publicComments = ptr(false), ptr(false)
	} else {
		g.ticketEditing = ptr(true)
		if v := id.Attr("only_private_comments"); v != "" {
			g.publicComments = ptr(v == "false")
		}
	}
	// An agent with access to all tickets may edit end-user profiles.
	if g.ticketAccess == "all" && !g.light {
		g.endUserProfile = "full"
	} else {
		g.endUserProfile = "readonly"
	}
	return g, nil
}

// --- checks -----------------------------------------------------------------

// Check answers one question.
func (c *Connection) Check(ctx context.Context, r integration.CheckRequest) (integration.Decision, error) {
	t, err := parseTarget(r.ActionName, r.Resource)
	if err != nil {
		return integration.Decision{}, err
	}
	who := r.Identity.Display
	if r.Identity.Attr("active") == "false" {
		return integration.Denied("%s is deleted in Zendesk", who), nil
	}
	if r.Identity.Attr("suspended") == "true" {
		return integration.Denied("%s is suspended in Zendesk", who), nil
	}
	g, err := c.grantsFor(ctx, r.Identity)
	if err != nil {
		return integration.Decision{}, err
	}
	switch t.action.resource {
	case "account":
		return c.checkAccount(t, g, who)
	case "organization":
		return c.checkOrganization(ctx, t, g, who)
	case "user":
		return c.checkUser(ctx, t, g, r.Identity)
	}
	return c.checkTicket(ctx, t, g, r.Identity)
}

// unknownSetting answers for a setting the plan does not expose.
func unknownSetting(who, what string, g grants) integration.Decision {
	return integration.Unsupported("whether %s (%s) may %s is an account setting Zendesk does not expose on plans without custom roles", who, g.roleName, what)
}

func (c *Connection) checkAccount(t target, g grants, who string) (integration.Decision, error) {
	if t.action.name == "account.admin" {
		if g.admin {
			return integration.Allowed("%s is an administrator", who), nil
		}
		return integration.Denied("%s is an %s, not an administrator", who, g.roleName), nil
	}
	if g.admin {
		return integration.Allowed("%s is an administrator, who may %s", who, t.action.desc), nil
	}
	if g.endUser {
		return integration.Denied("%s is an end user", who), nil
	}
	var setting *bool
	switch t.action.name {
	case "macro.manage":
		setting = g.macroFull
	case "view.manage":
		setting = g.viewFull
	case "business_rules.manage":
		setting = g.businessRules
	}
	if setting == nil {
		return unknownSetting(who, t.action.desc, g), nil
	}
	if *setting {
		return integration.Allowed("%s (%s) may %s", who, g.roleName, t.action.desc), nil
	}
	return integration.Denied("%s (%s) may not %s", who, g.roleName, t.action.desc), nil
}

func (c *Connection) checkOrganization(ctx context.Context, t target, g grants, who string) (integration.Decision, error) {
	if err := c.getJSON(ctx, "/api/v2/organizations/"+t.id, nil, nil); err != nil {
		return readError(err, t)
	}
	switch {
	case g.admin:
		return integration.Allowed("%s is an administrator, who may %s", who, t.action.desc), nil
	case g.endUser:
		return integration.Denied("%s is an end user", who), nil
	case g.orgEditing == nil:
		return unknownSetting(who, t.action.desc, g), nil
	case *g.orgEditing:
		return integration.Allowed("%s (%s) may %s", who, g.roleName, t.action.desc), nil
	}
	return integration.Denied("%s (%s) may not %s", who, g.roleName, t.action.desc), nil
}

// checkUser answers user.edit: end-user profiles per the role's
// end_user_profile_access; other team members only for administrators.
func (c *Connection) checkUser(ctx context.Context, t target, g grants, id integration.Identity) (integration.Decision, error) {
	who := id.Display
	var body struct {
		User zdUser `json:"user"`
	}
	if err := c.getJSON(ctx, "/api/v2/users/"+t.id, nil, &body); err != nil {
		return readError(err, t)
	}
	if g.admin {
		return integration.Allowed("%s is an administrator, who may edit any profile", who), nil
	}
	if body.User.Role != roleEndUser {
		if t.id == id.ID {
			return integration.Allowed("%s may edit their own profile", who), nil
		}
		return integration.Denied("%s is a %s and only administrators edit other team members", body.User.Role, who), nil
	}
	if g.endUser {
		if t.id == id.ID {
			return integration.Allowed("%s may edit their own profile", who), nil
		}
		return integration.Denied("%s is an end user and may edit their own profile only", who), nil
	}
	switch g.endUserProfile {
	case "full", "edit":
		return integration.Allowed("%s (%s) may edit end-user profiles", who, g.roleName), nil
	case "edit-within-org":
		mine := id.Attr("organization_id")
		theirs := ""
		if body.User.OrganizationID != nil && *body.User.OrganizationID != 0 {
			theirs = strconv.FormatInt(*body.User.OrganizationID, 10)
		}
		if mine != "" && mine == theirs {
			return integration.Allowed("%s (%s) may edit end users of their own organization, and %s is one", who, g.roleName, t), nil
		}
		return integration.Denied("%s (%s) may edit end users of their own organization only, and %s is not one", who, g.roleName, t), nil
	case "readonly":
		return integration.Denied("%s (%s) may only view end-user profiles", who, g.roleName), nil
	}
	return unknownSetting(who, t.action.desc, g), nil
}

// zdTicket is the subset of a ticket hallpass reads.
type zdTicket struct {
	ID             int64   `json:"id"`
	Status         string  `json:"status"`
	GroupID        *int64  `json:"group_id"`
	AssigneeID     *int64  `json:"assignee_id"`
	RequesterID    *int64  `json:"requester_id"`
	OrganizationID *int64  `json:"organization_id"`
	Collaborators  []int64 `json:"collaborator_ids"`
}

func idOf(p *int64) string {
	if p == nil || *p == 0 {
		return ""
	}
	return strconv.FormatInt(*p, 10)
}

// checkTicket answers the ticket questions: first whether the user can see
// the ticket at all under the role's ticket access, then the action.
func (c *Connection) checkTicket(ctx context.Context, t target, g grants, id integration.Identity) (integration.Decision, error) {
	who := id.Display
	var body struct {
		Ticket zdTicket `json:"ticket"`
	}
	if err := c.getJSON(ctx, "/api/v2/tickets/"+t.id, nil, &body); err != nil {
		return readError(err, t)
	}
	tk := body.Ticket
	if g.admin {
		if t.action.name == "ticket.edit" && tk.Status == "closed" {
			return integration.Denied("%s is closed; closed tickets cannot be edited", t), nil
		}
		return integration.Allowed("%s is an administrator, who may %s", who, t.action.desc), nil
	}
	// Access to the ticket.
	access, err := c.canSee(ctx, g, id, tk)
	if err != nil {
		return integration.Decision{}, err
	}
	if access.Code != integration.CodeAllowed {
		return access, nil
	}
	requester := idOf(tk.RequesterID) == id.ID
	switch t.action.name {
	case "ticket.view":
		return access, nil
	case "ticket.edit":
		if tk.Status == "closed" {
			if g.modifyClosed != nil && *g.modifyClosed {
				return integration.Allowed("%s (%s) may modify closed tickets", who, g.roleName), nil
			}
			return integration.Denied("%s is closed and %s (%s) may not modify closed tickets", t, who, g.roleName), nil
		}
		if g.endUser {
			return integration.Denied("%s is an end user and cannot change ticket properties", who), nil
		}
		if g.light {
			if requester {
				return integration.Allowed("%s is a light agent but requested %s, so may edit it", who, t), nil
			}
			return integration.Denied("%s is a light agent and cannot change ticket properties", who), nil
		}
		if g.ticketEditing == nil {
			return unknownSetting(who, t.action.desc, g), nil
		}
		if *g.ticketEditing {
			return integration.Allowed("%s (%s) may %s and can see %s (%s)", who, g.roleName, t.action.desc, t, access.Text), nil
		}
		return integration.Denied("%s (%s) may not change ticket properties", who, g.roleName), nil
	case "ticket.comment_public":
		if g.endUser {
			return integration.Allowed("%s requested %s and may comment on it", who, t), nil
		}
		if g.light {
			return integration.Denied("%s is a light agent, whose comments are private", who), nil
		}
		if g.publicComments == nil {
			return unknownSetting(who, t.action.desc, g), nil
		}
		if *g.publicComments {
			return integration.Allowed("%s (%s) may comment publicly and can see %s (%s)", who, g.roleName, t, access.Text), nil
		}
		return integration.Denied("%s (%s) may only comment privately", who, g.roleName), nil
	case "ticket.merge", "ticket.delete":
		if g.endUser || g.light {
			return integration.Denied("%s (%s) may not %s", who, g.roleName, t.action.desc), nil
		}
		setting := g.ticketMerge
		if t.action.name == "ticket.delete" {
			setting = g.ticketDeletion
		}
		if setting == nil {
			return unknownSetting(who, t.action.desc, g), nil
		}
		if *setting {
			return integration.Allowed("%s (%s) may %s and can see %s (%s)", who, g.roleName, t.action.desc, t, access.Text), nil
		}
		return integration.Denied("%s (%s) may not %s", who, g.roleName, t.action.desc), nil
	}
	return integration.Decision{}, integration.Errorf(integration.CodeInvalidRequest, "unknown action %q", t.action.name)
}

// canSee decides whether the role's ticket access covers the ticket. The
// text says why, for the action's own text.
func (c *Connection) canSee(ctx context.Context, g grants, id integration.Identity, tk zdTicket) (integration.Decision, error) {
	who := id.Display
	group, assignee, requester, org := idOf(tk.GroupID), idOf(tk.AssigneeID), idOf(tk.RequesterID), idOf(tk.OrganizationID)
	inGroup := group != "" && contains(id.Groups, group)
	switch g.ticketAccess {
	case "all":
		return integration.Allowed("access to all tickets"), nil
	case "within-groups", "within-groups-and-public-groups":
		if inGroup {
			return integration.Allowed("the ticket is in group %s, one of %s's groups", group, who), nil
		}
		if assignee == id.ID || requester == id.ID {
			return integration.Allowed("the ticket is assigned to or requested by %s", who), nil
		}
		if g.ticketAccess == "within-groups-and-public-groups" && group != "" {
			public, err := c.groupIsPublic(ctx, group)
			if err != nil {
				if httpx.Status(err) == 404 {
					return integration.UnknownDecision(integration.CodeResourceNotVisible, "group %s of the ticket does not exist or hallpass cannot see it", group), nil
				}
				return integration.Decision{}, classify(err, "read group "+group)
			}
			if public {
				return integration.Allowed("the ticket is in public group %s", group), nil
			}
		}
		if group == "" {
			return integration.Unsupported("the ticket is in no group and %s (%s) sees tickets of their groups; whether unassigned tickets are visible depends on views hallpass does not read", who, g.roleName), nil
		}
		return integration.Denied("%s (%s) sees tickets of their groups only and the ticket is in group %s", who, g.roleName, group), nil
	case "within-organization":
		mine := id.Attr("organization_id")
		if mine != "" && mine == org {
			return integration.Allowed("the ticket belongs to %s's organization %s", who, org), nil
		}
		if assignee == id.ID || requester == id.ID {
			return integration.Allowed("the ticket is assigned to or requested by %s", who), nil
		}
		// UNVERIFIED: an agent with several organization memberships may
		// see tickets of all of them; only the default organization is
		// compared here, so such an agent may be denied wrongly.
		return integration.Denied("%s (%s) sees tickets of their organization only and the ticket belongs to organization %s", who, g.roleName, orEmpty(org, "none")), nil
	case "assigned-only":
		if assignee == id.ID {
			return integration.Allowed("the ticket is assigned to %s", who), nil
		}
		return integration.Denied("%s (%s) sees assigned tickets only and the ticket is assigned to %s", who, g.roleName, orEmpty(assignee, "nobody")), nil
	case "requested":
		if requester == id.ID {
			return integration.Allowed("%s requested the ticket", who), nil
		}
		for _, cc := range tk.Collaborators {
			if strconv.FormatInt(cc, 10) == id.ID {
				return integration.Allowed("%s is a collaborator on the ticket", who), nil
			}
		}
		return integration.Denied("%s did not request the ticket and is not a collaborator on it", who), nil
	}
	return integration.Unsupported("%s has ticket access %q, which hallpass does not know", who, g.ticketAccess), nil
}

func orEmpty(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// groupIsPublic reads a group's is_public flag.
func (c *Connection) groupIsPublic(ctx context.Context, group string) (bool, error) {
	var body struct {
		Group struct {
			IsPublic *bool `json:"is_public"`
		} `json:"group"`
	}
	if err := c.getJSON(ctx, "/api/v2/groups/"+group, nil, &body); err != nil {
		return false, err
	}
	return body.Group.IsPublic != nil && *body.Group.IsPublic, nil
}

// --- probe ------------------------------------------------------------------

// Probe reads the credential's own user and reports its role.
func (c *Connection) Probe(ctx context.Context) (integration.ProbeResult, error) {
	var body struct {
		User zdUser `json:"user"`
	}
	if err := c.getJSON(ctx, "/api/v2/users/me", nil, &body); err != nil {
		return integration.ProbeResult{}, classify(err, "read its own user")
	}
	if body.User.ID == 0 {
		return integration.ProbeResult{}, integration.Errorf(integration.CodeCredentialRejected, "Zendesk answered the credential with an anonymous user; the token is not valid")
	}
	res := integration.ProbeResult{Summary: fmt.Sprintf("authenticated as %s (%s) at %s", body.User.Email, body.User.Role, c.api.Base)}
	if body.User.Role != roleAdmin {
		res.Warnings = append(res.Warnings, "hallpass's user is not an administrator: tickets and users outside its own access answer unknown")
	}
	res.Warnings = append(res.Warnings, "an API token acts with the full permissions of its user; keep it tightly held")
	return res, nil
}
