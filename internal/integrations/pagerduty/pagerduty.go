// Package pagerduty checks what a user may do in one PagerDuty account.
//
// hallpass authenticates with a read-only General Access REST API key,
// finds the user by email, reads the user's base role and, when the object
// asked about belongs to teams, the user's role on each of those teams.
// Base roles set account-wide access (owner and admin everything, user
// every configuration change and incident action, limited_user incident
// actions and overrides, observer and restricted_access nothing, the two
// stakeholder roles nothing); a team role adds access to the team's
// incidents, services, escalation policies and schedules. Nothing is
// written.
package pagerduty

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/roee-hersh/hallpass/internal/httpx"
	"github.com/roee-hersh/hallpass/internal/integration"
)

const (
	defaultURL = "https://api.pagerduty.com"
	accept     = "application/vnd.pagerduty+json;version=2"
	pageSize   = 100
)

// errorCodeRe finds the numeric code of a PagerDuty error body snippet.
var errorCodeRe = regexp.MustCompile(`"code"\s*:\s*(\d+)`)

// Integration is the pagerduty product.
type Integration struct{}

// Name is "pagerduty".
func (Integration) Name() string { return "pagerduty" }

// Fields of a pagerduty connection.
func (Integration) Fields() []integration.Field {
	return []integration.Field{
		integration.URLField(false, "API URL; default https://api.pagerduty.com, EU accounts https://api.eu.pagerduty.com"),
		integration.CredentialField(true, "a read-only General Access REST API key"),
	}
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
	base := strings.TrimRight(s.Get("url"), "/")
	if base == "" {
		base = defaultURL
	}
	cred := s.Secret("credential")
	c := &Connection{}
	c.api = &httpx.Client{HTTP: hc, Base: base, Logger: d.Logger, Auth: func(_ context.Context, r *http.Request) error {
		t, err := cred.GetString()
		if err != nil {
			return integration.Wrap(integration.CodeCredentialRejected, err, "the API key could not be read")
		}
		r.Header.Set("Authorization", "Token token="+strings.TrimSpace(t))
		r.Header.Set("Accept", accept)
		// The API description declares Content-Type on every call, reads
		// included.
		r.Header.Set("Content-Type", "application/json")
		return nil
	}}
	return c, nil
}

// Connection is one PagerDuty account.
type Connection struct {
	api *httpx.Client
}

// --- API transport ----------------------------------------------------------

func errorCode(err error) string {
	var se *httpx.StatusError
	if !errors.As(err, &se) {
		return ""
	}
	if m := errorCodeRe.FindStringSubmatch(se.Snippet); m != nil {
		return m[1]
	}
	return ""
}

// classify maps an API error to an integration error. 404 is left to the
// caller, who knows what is missing.
func classify(err error, what string) *integration.Error {
	switch httpx.Status(err) {
	case 401:
		return integration.Wrap(integration.CodeCredentialRejected, err, "PagerDuty rejected hallpass's API key")
	case 403:
		return integration.Wrap(integration.CodeCredentialRejected, err, "PagerDuty refused to %s (error %s): the API key may not read it", what, codeOr(errorCode(err), "2010"))
	case 402:
		return integration.Wrap(integration.CodeUnsupported, err, "the account lacks the ability to %s (HTTP 402)", what)
	case 400:
		return integration.Wrap(integration.CodeInvalidRequest, err, "PagerDuty rejected the request to %s (error %s)", what, codeOr(errorCode(err), "2001"))
	}
	return httpx.Classify(err)
}

func codeOr(code, def string) string {
	if code == "" {
		return def
	}
	return code
}

func (c *Connection) getJSON(ctx context.Context, path string, q url.Values, out any) error {
	_, err := c.api.GetJSON(ctx, path, q, out)
	return err
}

// --- identity ---------------------------------------------------------------

// reference is any PagerDuty object reference.
type reference struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Summary string `json:"summary"`
}

// pdUser is the subset of a user hallpass reads.
type pdUser struct {
	ID    string      `json:"id"`
	Name  string      `json:"name"`
	Email string      `json:"email"`
	Role  string      `json:"role"`
	Teams []reference `json:"teams"`
}

// ResolveIdentity finds the user with the email. The search is by name and
// email on PagerDuty's side, so the address is compared exactly.
func (c *Connection) ResolveIdentity(ctx context.Context, u integration.User) (integration.Identity, error) {
	email := strings.ToLower(strings.TrimSpace(u.Email))
	if !integration.IsEmail(email) {
		return integration.Identity{}, integration.Errorf(integration.CodeInvalidRequest, "user email %q is not an address", email)
	}
	var matches []pdUser
	offset := 0
	for n := 0; ; n++ {
		if n >= httpx.MaxPages {
			return integration.Identity{}, integration.Errorf(integration.CodeUpstreamError, "too many users match %s", email)
		}
		var page struct {
			Users []pdUser `json:"users"`
			More  bool     `json:"more"`
		}
		q := url.Values{"query": {email}, "limit": {strconv.Itoa(pageSize)}, "offset": {strconv.Itoa(offset)}, "include[]": {"teams"}}
		if err := c.getJSON(ctx, "/users", q, &page); err != nil {
			return integration.Identity{}, classify(err, "search users")
		}
		for _, usr := range page.Users {
			if strings.EqualFold(usr.Email, email) {
				matches = append(matches, usr)
			}
		}
		// The server may page smaller than asked; advance by what it sent.
		if !page.More || len(page.Users) == 0 {
			break
		}
		offset += len(page.Users)
	}
	switch len(matches) {
	case 0:
		return integration.Identity{}, integration.UserNotFound("no PagerDuty user has email %s", email)
	case 1:
	default:
		return integration.Identity{}, integration.UserAmbiguous("%d PagerDuty users have email %s", len(matches), email)
	}
	usr := matches[0]
	if usr.ID == "" || usr.Role == "" {
		return integration.Identity{}, integration.Errorf(integration.CodeUpstreamError, "the user record for %s carries no id or role", email)
	}
	id := integration.Identity{ID: usr.ID, Display: email, Attrs: map[string]string{"role": usr.Role}}
	for _, t := range usr.Teams {
		if t.ID != "" {
			id.Groups = append(id.Groups, t.ID)
		}
	}
	return id, nil
}

// --- checks -----------------------------------------------------------------

// Check answers one question.
func (c *Connection) Check(ctx context.Context, r integration.CheckRequest) (integration.Decision, error) {
	t, err := parseTarget(r.ActionName, r.Resource)
	if err != nil {
		return integration.Decision{}, err
	}
	role := r.Identity.Attr("role")
	switch role {
	case roleOwner, roleAdmin, roleUser, roleLimitedUser, roleObserver, roleRestricted, roleReadOnly, roleReadOnlyLtd:
	default:
		return integration.Unsupported("%s has base role %q, which hallpass does not know", r.Identity.Display, role), nil
	}
	who := r.Identity.Display
	if t.action.need == needAccountAdmin {
		if role == roleOwner || role == roleAdmin {
			return integration.Allowed("%s is a %s", who, roleName(role)), nil
		}
		return integration.Denied("%s is a %s, not an account owner or global admin", who, roleName(role)), nil
	}
	// The object is read first, whatever the role: a deleted or invisible
	// id is unknown, never an allow.
	teams, err := c.objectTeams(ctx, t)
	if err != nil {
		return decisionFor(err, t)
	}
	if t.action.need == needTeamMember {
		if slices.Contains(r.Identity.Groups, t.id) {
			return integration.Allowed("%s is a member of %s", who, t), nil
		}
		return integration.Denied("%s is not a member of %s", who, t), nil
	}
	// Stakeholders never act.
	if role == roleReadOnly || role == roleReadOnlyLtd {
		return integration.Denied("%s is a %s, a read-only role", who, roleName(role)), nil
	}
	// Account-wide grants of the base role.
	switch {
	case role == roleOwner || role == roleAdmin:
		return integration.Allowed("%s is a %s, which may %s anywhere", who, roleName(role), t.action.desc), nil
	case role == roleUser:
		return integration.Allowed("%s has the Manager base role, which may %s anywhere", who, t.action.desc), nil
	case role == roleLimitedUser && t.action.need == needRespond:
		return integration.Allowed("%s has the Responder base role, which may %s anywhere", who, t.action.desc), nil
	}
	// Everything else depends on a team role on the object's teams. The
	// user record lists the user's teams, so only those are read.
	var mine []string
	for _, team := range teams {
		if slices.Contains(r.Identity.Groups, team) {
			mine = append(mine, team)
		}
	}
	if len(teams) == 0 || len(mine) == 0 {
		if role == roleLimitedUser && t.action.need == needMaintenance {
			return integration.Unsupported("%s has the Responder base role and no team role on %s; whether a Responder may set maintenance windows account-wide is not documented", who, t), nil
		}
		if len(teams) == 0 {
			return integration.Denied("%s has the %s base role and %s belongs to no team that could grant more", who, roleName(role), t), nil
		}
		return integration.Denied("%s has the %s base role and is on none of the teams of %s", who, roleName(role), t), nil
	}
	best := ""
	for _, team := range mine {
		tr, err := c.teamRole(ctx, team, r.Identity.ID)
		if err != nil {
			if httpx.Status(err) == 404 {
				return integration.UnknownDecision(integration.CodeResourceNotVisible, "team %s of %s does not exist or hallpass cannot see it", team, t), nil
			}
			return integration.Decision{}, classify(err, "read the members of team "+team)
		}
		if teamRoleRank(tr) > teamRoleRank(best) {
			best = tr
		}
		if best == teamRoleManager {
			break
		}
	}
	switch t.action.need {
	case needRespond, needMaintenance:
		if best == teamRoleResponder || best == teamRoleManager {
			return integration.Allowed("%s is a team %s on a team of %s, which may %s", who, best, t, t.action.desc), nil
		}
		if role == roleLimitedUser && t.action.need == needMaintenance {
			return integration.Unsupported("%s has the Responder base role and no responder or manager team role on the teams of %s; whether a Responder may set maintenance windows account-wide is not documented", who, t), nil
		}
	case needManage:
		if best == teamRoleManager {
			return integration.Allowed("%s is a team manager on a team of %s, which may %s", who, t, t.action.desc), nil
		}
	}
	if best == "" {
		return integration.Denied("%s has the %s base role and no team role on the teams of %s", who, roleName(role), t), nil
	}
	return integration.Denied("%s has the %s base role and is a team %s on the teams of %s, which may not %s", who, roleName(role), best, t, t.action.desc), nil
}

// decisionFor turns an object lookup error into a decision: a 404 is an
// object hallpass cannot see, everything else is classified.
func decisionFor(err error, t target) (integration.Decision, error) {
	if httpx.Status(err) == 404 {
		return integration.UnknownDecision(integration.CodeResourceNotVisible, "%s does not exist or hallpass cannot see it", t), nil
	}
	return integration.Decision{}, classify(err, "read "+t.String())
}

// exists reads an object without keeping it.
func (c *Connection) exists(ctx context.Context, path string) error {
	var out map[string]any
	return c.getJSON(ctx, path, nil, &out)
}

// objectTeams reads the teams the object belongs to. For an incident they
// are the incident's own teams and its service's.
func (c *Connection) objectTeams(ctx context.Context, t target) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	add := func(refs []reference) {
		for _, r := range refs {
			if r.ID != "" && !seen[r.ID] {
				seen[r.ID] = true
				out = append(out, r.ID)
			}
		}
	}
	switch t.action.resource {
	case "incident":
		var body struct {
			Incident struct {
				Teams   []reference `json:"teams"`
				Service struct {
					ID    string      `json:"id"`
					Type  string      `json:"type"`
					Teams []reference `json:"teams"`
				} `json:"service"`
			} `json:"incident"`
		}
		if err := c.getJSON(ctx, "/incidents/"+httpx.PathEscape(t.id), url.Values{"include[]": {"services"}}, &body); err != nil {
			return nil, err
		}
		add(body.Incident.Teams)
		add(body.Incident.Service.Teams)
		if body.Incident.Service.ID != "" && body.Incident.Service.Type != "service" {
			// The service came as a reference, not expanded; read it.
			var svc struct {
				Service struct {
					Teams []reference `json:"teams"`
				} `json:"service"`
			}
			if err := c.getJSON(ctx, "/services/"+httpx.PathEscape(body.Incident.Service.ID), nil, &svc); err != nil {
				return nil, err
			}
			add(svc.Service.Teams)
		}
	case "service":
		var body struct {
			Service struct {
				Teams []reference `json:"teams"`
			} `json:"service"`
		}
		if err := c.getJSON(ctx, "/services/"+httpx.PathEscape(t.id), nil, &body); err != nil {
			return nil, err
		}
		add(body.Service.Teams)
	case "escalation_policy":
		var body struct {
			Policy struct {
				Teams []reference `json:"teams"`
			} `json:"escalation_policy"`
		}
		if err := c.getJSON(ctx, "/escalation_policies/"+httpx.PathEscape(t.id), nil, &body); err != nil {
			return nil, err
		}
		add(body.Policy.Teams)
	case "schedule":
		var body struct {
			Schedule struct {
				Teams []reference `json:"teams"`
			} `json:"schedule"`
		}
		if err := c.getJSON(ctx, "/schedules/"+httpx.PathEscape(t.id), nil, &body); err != nil {
			return nil, err
		}
		add(body.Schedule.Teams)
	case "team":
		if err := c.exists(ctx, "/teams/"+httpx.PathEscape(t.id)); err != nil {
			return nil, err
		}
		out = []string{t.id}
	}
	return out, nil
}

// teamRole reads the user's role on a team: manager, responder, observer
// or "" for a non-member.
func (c *Connection) teamRole(ctx context.Context, team, userID string) (string, error) {
	offset := 0
	for n := 0; ; n++ {
		if n >= httpx.MaxPages {
			return "", integration.Errorf(integration.CodeUpstreamError, "team %s has too many members to read", team)
		}
		var page struct {
			Members []struct {
				User reference `json:"user"`
				Role string    `json:"role"`
			} `json:"members"`
			More bool `json:"more"`
		}
		q := url.Values{"limit": {strconv.Itoa(pageSize)}, "offset": {strconv.Itoa(offset)}}
		if err := c.getJSON(ctx, "/teams/"+httpx.PathEscape(team)+"/members", q, &page); err != nil {
			return "", err
		}
		for _, m := range page.Members {
			if m.User.ID == userID {
				return m.Role, nil
			}
		}
		if !page.More || len(page.Members) == 0 {
			return "", nil
		}
		offset += len(page.Members)
	}
}

func teamRoleRank(r string) int {
	switch r {
	case teamRoleManager:
		return 3
	case teamRoleResponder:
		return 2
	case teamRoleObserver:
		return 1
	}
	return 0
}

// roleName is the web UI's name for an API base role.
func roleName(role string) string {
	switch role {
	case roleOwner:
		return "Account Owner"
	case roleAdmin:
		return "Global Admin"
	case roleUser:
		return "Manager"
	case roleLimitedUser:
		return "Responder"
	case roleObserver:
		return "Observer"
	case roleRestricted:
		return "Restricted Access user"
	case roleReadOnly:
		return "Full Stakeholder"
	case roleReadOnlyLtd:
		return "Limited Stakeholder"
	}
	return role
}

// --- probe ------------------------------------------------------------------

// Probe verifies the key and reports the account abilities that matter.
func (c *Connection) Probe(ctx context.Context) (integration.ProbeResult, error) {
	var abilities struct {
		Abilities []string `json:"abilities"`
	}
	if err := c.getJSON(ctx, "/abilities", nil, &abilities); err != nil {
		return integration.ProbeResult{}, classify(err, "list the account abilities")
	}
	var users struct {
		Users []pdUser `json:"users"`
	}
	if err := c.getJSON(ctx, "/users", url.Values{"limit": {"1"}}, &users); err != nil {
		return integration.ProbeResult{}, classify(err, "list users")
	}
	has := map[string]bool{}
	for _, a := range abilities.Abilities {
		has[a] = true
	}
	res := integration.ProbeResult{Summary: fmt.Sprintf("API key reads users and abilities at %s (%d abilities)", c.api.Base, len(abilities.Abilities))}
	if !has["teams"] {
		res.Warnings = append(res.Warnings, "the account lacks the teams ability: objects belong to no team, so observer and restricted_access users are denied everything but their base role allows")
	}
	if !has["advanced_permissions"] && !has["permissions_teams"] {
		res.Warnings = append(res.Warnings, "no advanced permissions ability was reported: team roles may not be in effect on this plan (see docs)")
	}
	res.Warnings = append(res.Warnings, "hallpass cannot tell a read-only key from a full one; create the key with \"Read-only API Key\" checked")
	return res, nil
}
