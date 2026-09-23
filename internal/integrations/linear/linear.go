// Package linear checks what a member may do in one Linear workspace.
//
// hallpass authenticates with a personal API key or an OAuth token, finds
// the user by email and reads the workspace role (owner, admin, member,
// guest, app), whether the account is active, and the teams the user
// belongs to and owns. Team, issue and project questions read the object
// and apply Linear's visibility rules: members see every public team,
// guests only the teams they joined, private teams only their members.
// Nothing is written.
package linear

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/roee-hersh/hallpass/internal/httpx"
	"github.com/roee-hersh/hallpass/internal/integration"
)

const (
	defaultURL = "https://api.linear.app/graphql"

	authAPIKey = "api_key"
	authOAuth  = "oauth"

	// pageSize is the page size for membership listings.
	pageSize = 100
)

// Integration is the linear product.
type Integration struct{}

// Name is "linear".
func (Integration) Name() string { return "linear" }

// Fields of a linear connection.
func (Integration) Fields() []integration.Field {
	return []integration.Field{
		{Name: "url", Default: defaultURL, Description: "the GraphQL endpoint"},
		{Name: "auth_mode", Default: authAPIKey, Enum: []string{authAPIKey, authOAuth},
			Description: "api_key: a personal API key (sent bare); oauth: an OAuth access token (sent as Bearer)"},
		integration.CredentialField(true, "the API key or OAuth access token; read scope suffices"),
	}
}

// New builds a connection. It touches no network.
func (Integration) New(_ context.Context, s *integration.Settings, d integration.Deps) (integration.Connection, error) {
	hc, err := d.HTTPClient(s)
	if err != nil {
		return nil, err
	}
	u := strings.TrimSpace(s.Get("url"))
	if u == "" {
		u = defaultURL
	}
	if !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://") {
		return nil, errors.New("url must be an http(s) URL")
	}
	if s.Secret("credential").IsZero() {
		return nil, errors.New("credential is required")
	}
	cred := s.Secret("credential")
	prefix := ""
	switch s.Get("auth_mode") {
	case "", authAPIKey:
	case authOAuth:
		prefix = "Bearer "
	default:
		return nil, fmt.Errorf("auth_mode %q must be api_key or oauth", s.Get("auth_mode"))
	}
	c := &Connection{url: u}
	c.api = &httpx.Client{HTTP: hc, Base: u, Logger: d.Logger, Auth: func(_ context.Context, r *http.Request) error {
		t, err := cred.GetString()
		if err != nil {
			return integration.Wrap(integration.CodeCredentialRejected, err, "the credential could not be read")
		}
		t = strings.TrimSpace(t)
		if t == "" {
			return integration.Errorf(integration.CodeCredentialRejected, "the credential is empty")
		}
		if prefix != "" && strings.HasPrefix(t, prefix) {
			prefix = ""
		}
		r.Header.Set("Authorization", prefix+t)
		return nil
	}}
	return c, nil
}

// Connection is one Linear workspace.
type Connection struct {
	api *httpx.Client
	url string
}

// --- GraphQL transport ------------------------------------------------------

// gqlError is one entry of a GraphQL errors array.
type gqlError struct {
	Message    string `json:"message"`
	Extensions struct {
		Type      string `json:"type"`
		UserError bool   `json:"userError"`
	} `json:"extensions"`
}

// errNotFound marks a lookup Linear answered with an entity-not-found
// error; callers turn it into resource_not_visible.
var errNotFound = errors.New("entity not found")

// query runs one GraphQL query and decodes data into out. Linear reports
// most failures as HTTP 200 or 400 with an errors array, and rate limits as
// HTTP 400 with the type "ratelimited".
func (c *Connection) query(ctx context.Context, q string, vars map[string]any, out any) error {
	idem := true
	resp, err := c.api.Do(ctx, &httpx.Request{Method: http.MethodPost, Path: c.url, JSON: map[string]any{"query": q, "variables": vars}, Idempotent: &idem, Accept4xx: true})
	if err != nil {
		return httpx.Classify(err)
	}
	switch {
	case resp.Status == 401:
		return integration.Errorf(integration.CodeCredentialRejected, "Linear rejected hallpass's credential (HTTP 401)")
	case resp.Status == 403:
		return integration.Errorf(integration.CodeCredentialRejected, "Linear refused the request (HTTP 403): the credential lacks the read scope")
	case resp.Status == 429:
		return integration.Errorf(integration.CodeUpstreamRateLimit, "Linear rate limit exhausted (HTTP 429)")
	case resp.Status != 200 && resp.Status != 400:
		return integration.Errorf(integration.CodeUpstreamError, "Linear answered HTTP %d", resp.Status)
	}
	var env struct {
		Data   json.RawMessage `json:"data"`
		Errors []gqlError      `json:"errors"`
	}
	if err := resp.JSON(&env); err != nil {
		return integration.Wrap(integration.CodeUpstreamError, err, "Linear's response was not JSON (HTTP %d)", resp.Status)
	}
	for _, e := range env.Errors {
		switch strings.ToLower(e.Extensions.Type) {
		case "ratelimited", "usage limit exceeded":
			return integration.Errorf(integration.CodeUpstreamRateLimit, "Linear rate limit exhausted")
		case "authentication error":
			return integration.Errorf(integration.CodeCredentialRejected, "Linear rejected hallpass's credential")
		case "forbidden", "feature not accessible":
			return integration.Errorf(integration.CodeCredentialRejected, "Linear refused the query (%s): the credential lacks the read scope or the plan lacks the feature", e.Extensions.Type)
		}
		// UNVERIFIED: the shape of the not-found error; Linear's SDK maps
		// "Entity not found" messages, type "invalid input", to a user error.
		if strings.Contains(strings.ToLower(e.Message), "not found") {
			return errNotFound
		}
	}
	if len(env.Errors) > 0 {
		t := env.Errors[0].Extensions.Type
		if t == "" {
			t = "error"
		}
		if resp.Status == 400 && strings.Contains(strings.ToUpper(string(resp.Body)), "RATELIMITED") {
			return integration.Errorf(integration.CodeUpstreamRateLimit, "Linear rate limit exhausted")
		}
		return integration.Errorf(integration.CodeUpstreamError, "Linear's GraphQL query failed (%s)", t)
	}
	if resp.Status != 200 {
		return integration.Errorf(integration.CodeUpstreamError, "Linear answered HTTP %d without errors", resp.Status)
	}
	if len(env.Data) == 0 || string(env.Data) == "null" {
		return integration.Errorf(integration.CodeUpstreamError, "Linear's response carried no data")
	}
	if err := json.Unmarshal(env.Data, out); err != nil {
		return integration.Wrap(integration.CodeUpstreamError, err, "Linear's data could not be decoded")
	}
	return nil
}

// --- identity ---------------------------------------------------------------

type gqlUser struct {
	ID            string  `json:"id"`
	Email         string  `json:"email"`
	Name          string  `json:"name"`
	Active        bool    `json:"active"`
	Admin         bool    `json:"admin"`
	Owner         bool    `json:"owner"`
	Guest         bool    `json:"guest"`
	App           bool    `json:"app"`
	DisableReason *string `json:"disableReason"`
}

const usersQuery = `query($email: String!) {
  users(filter: { email: { eqIgnoreCase: $email } }, includeDisabled: true, first: 50) {
    nodes { id email name active admin owner guest app disableReason }
  }
}`

const membershipsQuery = `query($id: String!, $first: Int!, $after: String) {
  user(id: $id) {
    teamMemberships(first: $first, after: $after) {
      nodes { owner team { id key } }
      pageInfo { hasNextPage endCursor }
    }
  }
}`

// ResolveIdentity finds the user with the email and lists the teams they
// belong to; the identity's groups are team ids and the attribute
// owned_teams the ids of teams the user owns.
func (c *Connection) ResolveIdentity(ctx context.Context, u integration.User) (integration.Identity, error) {
	email := strings.ToLower(strings.TrimSpace(u.Email))
	if !integration.IsEmail(email) {
		return integration.Identity{}, integration.Errorf(integration.CodeInvalidRequest, "user email %q is not an address", email)
	}
	var data struct {
		Users struct {
			Nodes []gqlUser `json:"nodes"`
		} `json:"users"`
	}
	if err := c.query(ctx, usersQuery, map[string]any{"email": email}, &data); err != nil {
		return integration.Identity{}, c.lookupErr(err, "search users")
	}
	var matches []gqlUser
	for _, usr := range data.Users.Nodes {
		if strings.EqualFold(usr.Email, email) {
			matches = append(matches, usr)
		}
	}
	switch len(matches) {
	case 0:
		return integration.Identity{}, integration.UserNotFound("no Linear user has email %s", email)
	case 1:
	default:
		return integration.Identity{}, integration.UserAmbiguous("%d Linear users have email %s", len(matches), email)
	}
	usr := matches[0]
	if !uuidRe.MatchString(usr.ID) {
		return integration.Identity{}, integration.Errorf(integration.CodeUpstreamError, "Linear returned a user id that is not an id")
	}
	id := integration.Identity{ID: usr.ID, Display: email, Attrs: map[string]string{
		"active": fmt.Sprint(usr.Active),
		"admin":  fmt.Sprint(usr.Admin),
		"owner":  fmt.Sprint(usr.Owner),
		"guest":  fmt.Sprint(usr.Guest),
		"app":    fmt.Sprint(usr.App),
	}}
	if usr.DisableReason != nil && *usr.DisableReason != "" {
		id.Attrs["disable_reason"] = *usr.DisableReason
	}
	var owned []string
	after := any(nil)
	for page := 0; ; page++ {
		if page >= httpx.MaxPages {
			return integration.Identity{}, integration.Errorf(integration.CodeUpstreamError, "%s belongs to more teams than hallpass pages through", email)
		}
		var data struct {
			User struct {
				Memberships struct {
					Nodes []struct {
						Owner bool `json:"owner"`
						Team  struct {
							ID  string `json:"id"`
							Key string `json:"key"`
						} `json:"team"`
					} `json:"nodes"`
					PageInfo struct {
						HasNextPage bool    `json:"hasNextPage"`
						EndCursor   *string `json:"endCursor"`
					} `json:"pageInfo"`
				} `json:"teamMemberships"`
			} `json:"user"`
		}
		if err := c.query(ctx, membershipsQuery, map[string]any{"id": usr.ID, "first": pageSize, "after": after}, &data); err != nil {
			return integration.Identity{}, c.lookupErr(err, "list the user's teams")
		}
		for _, m := range data.User.Memberships.Nodes {
			if m.Team.ID == "" {
				continue
			}
			id.Groups = append(id.Groups, m.Team.ID)
			if m.Owner {
				owned = append(owned, m.Team.ID)
			}
		}
		pi := data.User.Memberships.PageInfo
		if !pi.HasNextPage || pi.EndCursor == nil || *pi.EndCursor == "" {
			break
		}
		after = *pi.EndCursor
	}
	if len(owned) > 0 {
		id.Attrs["owned_teams"] = strings.Join(owned, ",")
	}
	return id, nil
}

// lookupErr classifies an error from an identity query, where not-found
// is an upstream inconsistency rather than a resource question.
func (c *Connection) lookupErr(err error, what string) error {
	if errors.Is(err, errNotFound) {
		return integration.Errorf(integration.CodeUpstreamError, "Linear could not %s: the record vanished between queries", what)
	}
	return err
}

// --- checks -----------------------------------------------------------------

type gqlTeam struct {
	ID         string  `json:"id"`
	Key        string  `json:"key"`
	Name       string  `json:"name"`
	Visibility string  `json:"visibility"`
	ArchivedAt *string `json:"archivedAt"`
}

const teamsQuery = `query($filter: TeamFilter!) {
  teams(filter: $filter, first: 2, includeArchived: true) {
    nodes { id key name visibility archivedAt }
  }
}`

const issueQuery = `query($id: String!) {
  issue(id: $id) {
    id identifier trashed archivedAt
    team { id key name visibility archivedAt }
  }
}`

const projectQuery = `query($id: String!) {
  project(id: $id) {
    id name slugId trashed archivedAt
    teams(first: 50) { nodes { id key name visibility archivedAt } }
  }
}`

// Check answers one question.
func (c *Connection) Check(ctx context.Context, r integration.CheckRequest) (integration.Decision, error) {
	t, err := parseTarget(r.ActionName, r.Resource)
	if err != nil {
		return integration.Decision{}, err
	}
	id := r.Identity
	who := id.Display
	if id.Attr("active") != "true" {
		reason := id.Attr("disable_reason")
		if reason == "" {
			reason = "deactivated"
		}
		return integration.Denied("%s is not an active Linear user (%s)", who, reason), nil
	}
	if t.action.resource == "workspace" {
		return checkWorkspace(t, id), nil
	}
	if id.Attr("app") == "true" {
		return integration.Unsupported("%s is an app user, whose team access hallpass does not model", who), nil
	}
	switch t.action.resource {
	case "team":
		team, err := c.team(ctx, t)
		if err != nil {
			return integration.Decision{}, err
		}
		if team == nil {
			return integration.UnknownDecision(integration.CodeResourceNotVisible, "%s does not exist or hallpass cannot see it", t), nil
		}
		return checkTeam(t, team, id), nil
	case "issue":
		var data struct {
			Issue struct {
				ID         string  `json:"id"`
				Identifier string  `json:"identifier"`
				Trashed    *bool   `json:"trashed"`
				ArchivedAt *string `json:"archivedAt"`
				Team       gqlTeam `json:"team"`
			} `json:"issue"`
		}
		if err := c.query(ctx, issueQuery, map[string]any{"id": t.id}, &data); err != nil {
			if errors.Is(err, errNotFound) {
				return integration.UnknownDecision(integration.CodeResourceNotVisible, "%s does not exist or hallpass cannot see it", t), nil
			}
			return integration.Decision{}, err
		}
		if data.Issue.Team.ID == "" {
			return integration.Decision{}, integration.Errorf(integration.CodeUpstreamError, "Linear returned %s without its team", t)
		}
		if data.Issue.Trashed != nil && *data.Issue.Trashed {
			return integration.Unsupported("%s is in the trash; hallpass does not model access to trashed issues", t), nil
		}
		d := teamAccess(data.Issue.Team, id)
		if d.Code != integration.CodeAllowed {
			return d, nil
		}
		return integration.Allowed("%s may %s: %s", who, t.action.desc, d.Text), nil
	case "project":
		var data struct {
			Project struct {
				ID      string `json:"id"`
				Trashed *bool  `json:"trashed"`
				Teams   struct {
					Nodes []gqlTeam `json:"nodes"`
				} `json:"teams"`
			} `json:"project"`
		}
		if err := c.query(ctx, projectQuery, map[string]any{"id": t.id}, &data); err != nil {
			if errors.Is(err, errNotFound) {
				return integration.UnknownDecision(integration.CodeResourceNotVisible, "%s does not exist or hallpass cannot see it", t), nil
			}
			return integration.Decision{}, err
		}
		if data.Project.Trashed != nil && *data.Project.Trashed {
			return integration.Unsupported("%s is in the trash; hallpass does not model access to trashed projects", t), nil
		}
		return checkProject(t, data.Project.Teams.Nodes, id), nil
	}
	return integration.Decision{}, invalid("unknown action %q", t.action.name)
}

// team reads a team by key or id; nil when there is none.
func (c *Connection) team(ctx context.Context, t target) (*gqlTeam, error) {
	filter := map[string]any{"key": map[string]any{"eq": t.id}}
	if t.byID {
		filter = map[string]any{"id": map[string]any{"eq": t.id}}
	}
	var data struct {
		Teams struct {
			Nodes []gqlTeam `json:"nodes"`
		} `json:"teams"`
	}
	if err := c.query(ctx, teamsQuery, map[string]any{"filter": filter}, &data); err != nil {
		if errors.Is(err, errNotFound) {
			return nil, nil
		}
		return nil, err
	}
	switch len(data.Teams.Nodes) {
	case 0:
		return nil, nil
	case 1:
		team := data.Teams.Nodes[0]
		return &team, nil
	}
	return nil, integration.Errorf(integration.CodeUpstreamError, "Linear returned %d teams for %s", len(data.Teams.Nodes), t)
}

func checkWorkspace(t target, id integration.Identity) integration.Decision {
	who := id.Display
	switch t.action.name {
	case "workspace.owner":
		if id.Attr("owner") == "true" {
			return integration.Allowed("%s is a workspace owner", who)
		}
		return integration.Denied("%s is not a workspace owner", who)
	case "workspace.admin":
		if id.Attr("owner") == "true" {
			return integration.Allowed("%s is a workspace owner", who)
		}
		if id.Attr("admin") == "true" {
			return integration.Allowed("%s is a workspace administrator", who)
		}
		return integration.Denied("%s is neither a workspace administrator nor an owner", who)
	}
	switch {
	case id.Attr("app") == "true":
		return integration.Denied("%s is an app user, not a member", who)
	case id.Attr("guest") == "true":
		return integration.Denied("%s is a guest, limited to the teams they joined", who)
	}
	return integration.Allowed("%s is a full member of the workspace", who)
}

// teamAccess decides whether the user can see the team and its issues.
// The text names the reason for the action's own text.
func teamAccess(team gqlTeam, id integration.Identity) integration.Decision {
	who := id.Display
	label := team.Key
	if label == "" {
		label = team.ID
	}
	if team.ArchivedAt != nil && *team.ArchivedAt != "" {
		return integration.Unsupported("team %s is archived; hallpass does not model access to archived teams", label)
	}
	member := contains(id.Groups, team.ID)
	switch team.Visibility {
	case "public":
		if member {
			return integration.Allowed("%s is a member of public team %s", who, label)
		}
		if id.Attr("guest") == "true" {
			return integration.Denied("%s is a guest and not a member of team %s", who, label)
		}
		return integration.Allowed("team %s is public and %s is a workspace member", label, who)
	case "private":
		if member {
			return integration.Allowed("%s is a member of private team %s", who, label)
		}
		if id.Attr("admin") == "true" || id.Attr("owner") == "true" {
			// UNVERIFIED: whether workspace administrators see the issues
			// of private teams they have not joined.
			return integration.Unsupported("team %s is private and %s is a workspace administrator but not a member; whether administrators see private team content is not something hallpass can read", label, who)
		}
		return integration.Denied("team %s is private and %s is not a member", label, who)
	case "restricted":
		if member {
			return integration.Allowed("%s is a member of restricted team %s", who, label)
		}
		// UNVERIFIED: a restricted team sits inside a private team's
		// boundary; members of the parent may see it.
		return integration.Unsupported("team %s is restricted (inside a private team) and %s is not a member; hallpass does not read the private boundary", label, who)
	}
	return integration.Unsupported("team %s has visibility %q, which hallpass does not know", label, team.Visibility)
}

func checkTeam(t target, team *gqlTeam, id integration.Identity) integration.Decision {
	who := id.Display
	member := contains(id.Groups, team.ID)
	switch t.action.name {
	case "team.view":
		return teamAccess(*team, id)
	case "team.member":
		if member {
			return integration.Allowed("%s is a member of team %s", who, team.Key)
		}
		return integration.Denied("%s is not a member of team %s", who, team.Key)
	}
	// team.admin
	if id.Attr("owner") == "true" || id.Attr("admin") == "true" {
		return integration.Allowed("%s is a workspace administrator, who may manage any team", who)
	}
	if contains(strings.Split(id.Attr("owned_teams"), ","), team.ID) {
		return integration.Allowed("%s is an owner of team %s", who, team.Key)
	}
	if !member {
		return integration.Denied("%s is not a member of team %s", who, team.Key)
	}
	// UNVERIFIED: team owners choose whether all members or only owners
	// manage team settings; the setting is not exposed in the API.
	return integration.Unsupported("%s is a member but not an owner of team %s; whether members may manage its settings is a team setting hallpass cannot read", who, team.Key)
}

// checkProject allows when any of the project's teams is visible to the
// user, denies when all are denied, and is unknown otherwise.
func checkProject(t target, teams []gqlTeam, id integration.Identity) integration.Decision {
	who := id.Display
	if len(teams) == 0 {
		return integration.Unsupported("%s belongs to no team; hallpass cannot tell who sees it", t)
	}
	var unknown *integration.Decision
	denied := 0
	for _, team := range teams {
		d := teamAccess(team, id)
		switch d.Code {
		case integration.CodeAllowed:
			return integration.Allowed("%s may see %s: %s", who, t, d.Text)
		case integration.CodeDenied:
			denied++
		default:
			if unknown == nil {
				dd := d
				unknown = &dd
			}
		}
	}
	if unknown != nil {
		return *unknown
	}
	return integration.Denied("%s cannot see any of the %d team(s) of %s", who, denied, t)
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x && x != "" {
			return true
		}
	}
	return false
}

// --- probe ------------------------------------------------------------------

const viewerQuery = `{ viewer { id email admin owner app } organization { id name urlKey } }`

// Probe reads the credential's own user and the workspace.
func (c *Connection) Probe(ctx context.Context) (integration.ProbeResult, error) {
	var data struct {
		Viewer       gqlUser `json:"viewer"`
		Organization struct {
			Name   string `json:"name"`
			URLKey string `json:"urlKey"`
		} `json:"organization"`
	}
	if err := c.query(ctx, viewerQuery, nil, &data); err != nil {
		return integration.ProbeResult{}, c.lookupErr(err, "read its own user")
	}
	if data.Viewer.ID == "" {
		return integration.ProbeResult{}, integration.Errorf(integration.CodeCredentialRejected, "Linear answered without a viewer; the credential is not valid")
	}
	res := integration.ProbeResult{Summary: fmt.Sprintf("authenticated as %s in workspace %s", data.Viewer.Email, data.Organization.URLKey)}
	if !data.Viewer.Admin && !data.Viewer.Owner {
		res.Warnings = append(res.Warnings, "hallpass's user is not a workspace administrator: private teams it has not joined answer unknown")
	}
	res.Warnings = append(res.Warnings, "a personal API key acts with the full permissions of its user; keep it tightly held")
	return res, nil
}
