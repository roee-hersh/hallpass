// Package datadog checks what a user may do in one Datadog organization.
//
// hallpass authenticates with an API key and a scoped application key,
// finds the user by email, reads the permissions of the user's roles, and
// for a monitor, dashboard, SLO or notebook reads the asset's restriction
// policy (and the legacy restricted_roles and author fields): a user may
// change such an asset only when a role carries the write permission and
// the asset's restrictions, if any, name the user, one of the user's roles
// or teams, or the whole org. Nothing is written.
package datadog

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
	"time"

	"github.com/roee-hersh/hallpass/internal/cache"
	"github.com/roee-hersh/hallpass/internal/httpx"
	"github.com/roee-hersh/hallpass/internal/integration"
)

const (
	defaultURL = "https://api.datadoghq.com"
	pageSize   = 100
	// permissionsTTL is how long a role's permission list is kept.
	permissionsTTL = 5 * time.Minute
	// maxTeamPages bounds a team membership scan.
	maxTeamPages = 50
)

var uuidRe = regexp.MustCompile(`^[0-9a-fA-F-]{8,64}$`)

// Integration is the datadog product.
type Integration struct{}

// Name is "datadog".
func (Integration) Name() string { return "datadog" }

// Fields of a datadog connection.
func (Integration) Fields() []integration.Field {
	return []integration.Field{
		integration.URLField(false, "API URL of the site; default https://api.datadoghq.com (EU https://api.datadoghq.eu, US3 https://api.us3.datadoghq.com, US5 https://api.us5.datadoghq.com, AP1 https://api.ap1.datadoghq.com)"),
		{Name: "api_key", Required: true, Secret: true, Description: "the organization's API key (DD-API-KEY)"},
		integration.CredentialField(true, "an application key (DD-APPLICATION-KEY) scoped to user_access_read, teams_read and the *_read scope of each asset type asked about"),
	}
}

// New builds a connection. It touches no network.
func (Integration) New(_ context.Context, s *integration.Settings, d integration.Deps) (integration.Connection, error) {
	hc, err := d.HTTPClient(s)
	if err != nil {
		return nil, err
	}
	if s.Secret("credential").IsZero() || s.Secret("api_key").IsZero() {
		return nil, errors.New("api_key and credential are required")
	}
	base := strings.TrimRight(s.Get("url"), "/")
	if base == "" {
		base = defaultURL
	}
	apiKey, appKey := s.Secret("api_key"), s.Secret("credential")
	c := &Connection{now: d.Now, perms: cache.New[string, map[string]bool](0)}
	if c.now == nil {
		c.now = time.Now
	}
	c.perms.SetClock(c.now)
	c.api = &httpx.Client{HTTP: hc, Base: base, Logger: d.Logger, Auth: func(_ context.Context, r *http.Request) error {
		a, err := apiKey.GetString()
		if err != nil {
			return integration.Wrap(integration.CodeCredentialRejected, err, "the API key could not be read")
		}
		k, err := appKey.GetString()
		if err != nil {
			return integration.Wrap(integration.CodeCredentialRejected, err, "the application key could not be read")
		}
		r.Header.Set("DD-API-KEY", strings.TrimSpace(a))
		r.Header.Set("DD-APPLICATION-KEY", strings.TrimSpace(k))
		return nil
	}}
	return c, nil
}

// Connection is one Datadog organization.
type Connection struct {
	api *httpx.Client
	now func() time.Time

	// perms is each role's permission names, kept for permissionsTTL.
	perms *cache.TTL[string, map[string]bool]
}

// --- API transport ----------------------------------------------------------

// classify maps an API error to an integration error. 404 is left to the
// caller, who knows what is missing.
func classify(err error, what string) *integration.Error {
	switch httpx.Status(err) {
	case 401:
		return integration.Wrap(integration.CodeCredentialRejected, err, "Datadog rejected hallpass's API or application key")
	case 403:
		return integration.Wrap(integration.CodeCredentialRejected, err, "Datadog refused to %s (HTTP 403): the API key or application key is invalid, or the application key lacks the scope", what)
	case 400:
		return integration.Wrap(integration.CodeInvalidRequest, err, "Datadog rejected the request to %s (HTTP 400)", what)
	}
	return httpx.Classify(err)
}

func (c *Connection) getJSON(ctx context.Context, path string, q url.Values, out any) error {
	_, err := c.api.GetJSON(ctx, path, q, out)
	return err
}

// --- identity ---------------------------------------------------------------

// ddUser is the subset of a v2 user hallpass reads.
type ddUser struct {
	ID         string `json:"id"`
	Attributes struct {
		Email    string `json:"email"`
		Handle   string `json:"handle"`
		Status   string `json:"status"`
		Disabled *bool  `json:"disabled"`
	} `json:"attributes"`
	Relationships struct {
		Roles struct {
			Data []struct {
				ID string `json:"id"`
			} `json:"data"`
		} `json:"roles"`
	} `json:"relationships"`
}

// ResolveIdentity finds the user with the email. Datadog's filter is a
// substring match on name, handle and email, so the address is compared
// exactly; disabled users are included so they can be denied.
func (c *Connection) ResolveIdentity(ctx context.Context, u integration.User) (integration.Identity, error) {
	email := strings.ToLower(strings.TrimSpace(u.Email))
	if !integration.IsEmail(email) {
		return integration.Identity{}, integration.Errorf(integration.CodeInvalidRequest, "user email %q is not an address", email)
	}
	var matches []ddUser
	for pageNo := 0; ; pageNo++ {
		if pageNo >= httpx.MaxPages {
			return integration.Identity{}, integration.Errorf(integration.CodeUpstreamError, "too many users match %s", email)
		}
		var page struct {
			Data []ddUser `json:"data"`
			Meta struct {
				Page struct {
					TotalFiltered *int64 `json:"total_filtered_count"`
				} `json:"page"`
			} `json:"meta"`
		}
		q := url.Values{"filter": {email}, "filter[status]": {"Active,Pending,Disabled"}, "page[size]": {strconv.Itoa(pageSize)}, "page[number]": {strconv.Itoa(pageNo)}}
		if err := c.getJSON(ctx, "/api/v2/users", q, &page); err != nil {
			return integration.Identity{}, classify(err, "search users")
		}
		for _, usr := range page.Data {
			if strings.EqualFold(usr.Attributes.Email, email) {
				matches = append(matches, usr)
			}
		}
		seen := int64(pageNo*pageSize + len(page.Data))
		if len(page.Data) == 0 || (page.Meta.Page.TotalFiltered != nil && seen >= *page.Meta.Page.TotalFiltered) {
			break
		}
	}
	switch len(matches) {
	case 0:
		return integration.Identity{}, integration.UserNotFound("no Datadog user has email %s", email)
	case 1:
	default:
		return integration.Identity{}, integration.UserAmbiguous("%d Datadog users have email %s", len(matches), email)
	}
	usr := matches[0]
	if usr.ID == "" {
		return integration.Identity{}, integration.Errorf(integration.CodeUpstreamError, "the user record for %s carries no id", email)
	}
	disabled := "unknown"
	if usr.Attributes.Disabled != nil {
		disabled = fmt.Sprint(*usr.Attributes.Disabled)
	}
	id := integration.Identity{ID: usr.ID, Display: email, Attrs: map[string]string{"handle": strings.ToLower(usr.Attributes.Handle), "disabled": disabled, "status": usr.Attributes.Status}}
	for _, r := range usr.Relationships.Roles.Data {
		if r.ID != "" {
			id.Groups = append(id.Groups, r.ID)
		}
	}
	return id, nil
}

// rolePermissions reads a role's permission names, cached for permissionsTTL.
// The map is shared with every caller the entry serves: read-only.
func (c *Connection) rolePermissions(ctx context.Context, role string) (map[string]bool, error) {
	if !uuidRe.MatchString(role) {
		return nil, integration.Errorf(integration.CodeUpstreamError, "role id %q is not an id", role)
	}
	return c.perms.Do(ctx, role, func(ctx context.Context) (map[string]bool, time.Duration, error) {
		var body struct {
			Data []struct {
				Attributes struct {
					Name string `json:"name"`
				} `json:"attributes"`
			} `json:"data"`
		}
		if err := c.getJSON(ctx, "/api/v2/roles/"+httpx.PathEscape(role)+"/permissions", nil, &body); err != nil {
			return nil, 0, err
		}
		names := map[string]bool{}
		for _, p := range body.Data {
			if p.Attributes.Name != "" {
				names[p.Attributes.Name] = true
			}
		}
		return names, permissionsTTL, nil
	})
}

// --- checks -----------------------------------------------------------------

// Check answers one question.
func (c *Connection) Check(ctx context.Context, r integration.CheckRequest) (integration.Decision, error) {
	t, err := parseTarget(r.ActionName, r.Resource)
	if err != nil {
		return integration.Decision{}, err
	}
	who := r.Identity.Display
	switch r.Identity.Attr("disabled") {
	case "false":
	case "true":
		return integration.Denied("%s is disabled in Datadog", who), nil
	default:
		return integration.Unsupported("Datadog did not report whether %s is disabled", who), nil
	}
	if r.Identity.Attr("status") == "Pending" {
		return integration.Denied("%s was invited to Datadog but has not accepted, so cannot act", who), nil
	}
	// The permission: any role of the user carrying it.
	var grantedBy string
	for _, role := range r.Identity.Groups {
		names, err := c.rolePermissions(ctx, role)
		if err != nil {
			if httpx.Status(err) == 404 {
				return integration.UnknownDecision(integration.CodeResourceNotVisible, "role %s of %s does not exist or hallpass cannot see it", role, who), nil
			}
			return integration.Decision{}, classify(err, "read the permissions of role "+role)
		}
		if names[t.permission()] {
			grantedBy = role
			break
		}
	}
	if t.typ == "org" {
		if grantedBy != "" {
			return integration.Allowed("a role of %s carries %s", who, t.permission()), nil
		}
		return integration.Denied("no role of %s carries %s", who, t.permission()), nil
	}
	// The asset exists, and its legacy restrictions.
	asset, err := c.readAsset(ctx, t)
	if err != nil {
		if httpx.Status(err) == 404 {
			return integration.UnknownDecision(integration.CodeResourceNotVisible, "%s does not exist or hallpass cannot see it", t), nil
		}
		return integration.Decision{}, classify(err, "read "+t.String())
	}
	if grantedBy == "" {
		return integration.Denied("no role of %s carries %s, which %s needs", who, t.permission(), t.action.desc), nil
	}
	// The restriction policy, then the legacy fields.
	policy, err := c.restrictionPolicy(ctx, t)
	if err != nil {
		return integration.Decision{}, classify(err, "read the restriction policy of "+t.String())
	}
	if len(policy) > 0 {
		return c.applyPolicy(ctx, t, r.Identity, policy)
	}
	if t.relation() == "editor" && len(asset.restrictedRoles) > 0 {
		for _, role := range asset.restrictedRoles {
			if slices.Contains(r.Identity.Groups, role) {
				return integration.Allowed("a role of %s carries %s and %s is restricted to roles that include it", who, t.permission(), t), nil
			}
		}
		if asset.author != "" && authorIs(asset.author, r.Identity) {
			return integration.Allowed("a role of %s carries %s and %s is the author of %s, which its restricted roles cannot exclude", who, t.permission(), who, t), nil
		}
		return integration.Denied("%s is restricted to %d role(s) that %s does not hold", t, len(asset.restrictedRoles), who), nil
	}
	return integration.Allowed("a role of %s carries %s and %s carries no restriction", who, t.permission(), t), nil
}

// authorIs matches a dashboard's author_handle or a creator email against
// the identity.
func authorIs(author string, id integration.Identity) bool {
	author = strings.ToLower(author)
	return author == id.Attr("handle") || author == strings.ToLower(id.Display)
}

// assetInfo is what the legacy asset endpoints say about restrictions.
type assetInfo struct {
	restrictedRoles []string
	author          string
}

// readAsset reads the asset, proving it exists, and its legacy
// restricted_roles and author where the type has them.
func (c *Connection) readAsset(ctx context.Context, t target) (assetInfo, error) {
	var info assetInfo
	switch t.typ {
	case "monitor":
		var body struct {
			RestrictedRoles []string `json:"restricted_roles"`
			Creator         struct {
				Email  string `json:"email"`
				Handle string `json:"handle"`
			} `json:"creator"`
		}
		if err := c.getJSON(ctx, "/api/v1/monitor/"+httpx.PathEscape(t.id), nil, &body); err != nil {
			return info, err
		}
		info.restrictedRoles = body.RestrictedRoles
		// UNVERIFIED: whether a monitor's creator keeps edit rights under
		// restricted_roles as a dashboard's author does; the monitor
		// documentation speaks of roles only, so the creator is not exempt.
	case "dashboard":
		var body struct {
			RestrictedRoles []string `json:"restricted_roles"`
			AuthorHandle    string   `json:"author_handle"`
		}
		if err := c.getJSON(ctx, "/api/v1/dashboard/"+httpx.PathEscape(t.id), nil, &body); err != nil {
			return info, err
		}
		info.restrictedRoles, info.author = body.RestrictedRoles, body.AuthorHandle
	case "slo":
		if err := c.getJSON(ctx, "/api/v1/slo/"+httpx.PathEscape(t.id), nil, nil); err != nil {
			return info, err
		}
	case "notebook":
		if err := c.getJSON(ctx, "/api/v1/notebooks/"+httpx.PathEscape(t.id), nil, nil); err != nil {
			return info, err
		}
	}
	return info, nil
}

// binding is one relation of a restriction policy.
type binding struct {
	Relation   string   `json:"relation"`
	Principals []string `json:"principals"`
}

// restrictionPolicy reads the asset's restriction policy bindings; an
// asset without a policy has none.
func (c *Connection) restrictionPolicy(ctx context.Context, t target) ([]binding, error) {
	var body struct {
		Data struct {
			Attributes struct {
				Bindings []binding `json:"bindings"`
			} `json:"attributes"`
		} `json:"data"`
	}
	id := assetTypes[t.typ].policyType + ":" + t.id
	if err := c.getJSON(ctx, "/api/v2/restriction_policy/"+httpx.PathEscape(id), nil, &body); err != nil {
		if httpx.Status(err) == 404 {
			return nil, nil
		}
		return nil, err
	}
	return body.Data.Attributes.Bindings, nil
}

// relationRank orders the relations a policy may grant.
func relationRank(rel string) int {
	switch rel {
	case "viewer":
		return 1
	case "editor":
		return 2
	}
	// Type-specific relations above editor (manager, runner, ...) are not
	// modelled; they are ranked with editor so a manager may also edit.
	if rel != "" {
		return 2
	}
	return 0
}

// applyPolicy decides from a restriction policy: the user, one of the
// user's roles or teams, or the whole org must be bound to the relation
// needed or a higher one.
func (c *Connection) applyPolicy(ctx context.Context, t target, id integration.Identity, policy []binding) (integration.Decision, error) {
	need := relationRank(t.relation())
	if need == relationRank("viewer") && !slices.ContainsFunc(policy, func(b binding) bool { return b.Relation == "viewer" }) {
		// UNVERIFIED: a policy that only restricts editing is taken to
		// leave viewing to the permission, as the UI writes an explicit
		// viewer binding for the org when it restricts an asset.
		return integration.Allowed("a role of %s carries %s and the restriction policy of %s restricts editing only", id.Display, t.permission(), t), nil
	}
	var teams []string
	for _, b := range policy {
		if relationRank(b.Relation) < need {
			continue
		}
		for _, p := range b.Principals {
			kind, pid, ok := strings.Cut(p, ":")
			if !ok {
				continue
			}
			switch kind {
			case "org":
				return integration.Allowed("the restriction policy of %s grants %s to the whole org, and a role of %s carries %s", t, b.Relation, id.Display, t.permission()), nil
			case "user":
				if pid == id.ID {
					return integration.Allowed("the restriction policy of %s grants %s to %s, whose role carries %s", t, b.Relation, id.Display, t.permission()), nil
				}
			case "role":
				if slices.Contains(id.Groups, pid) {
					return integration.Allowed("the restriction policy of %s grants %s to a role of %s, which carries %s", t, b.Relation, id.Display, t.permission()), nil
				}
			case "team":
				if uuidRe.MatchString(pid) && !slices.Contains(teams, pid) {
					teams = append(teams, pid)
				}
			}
		}
	}
	for _, team := range teams {
		member, err := c.teamMember(ctx, team, id.ID, id.Display)
		if err != nil {
			if httpx.Status(err) == 404 {
				return integration.UnknownDecision(integration.CodeResourceNotVisible, "team %s named by the restriction policy of %s does not exist or hallpass cannot see it", team, t), nil
			}
			return integration.Decision{}, classify(err, "read the members of team "+team)
		}
		if member {
			return integration.Allowed("the restriction policy of %s grants %s to team %s, of which %s is a member, and a role carries %s", t, t.relation(), team, id.Display, t.permission()), nil
		}
	}
	return integration.Denied("the restriction policy of %s grants %s to none of %s's roles, teams or user", t, t.relation(), id.Display), nil
}

// teamMember reports whether the user is a member of the team.
func (c *Connection) teamMember(ctx context.Context, team, userID, keyword string) (bool, error) {
	for pageNo := 0; pageNo < maxTeamPages; pageNo++ {
		var page struct {
			Data []struct {
				Relationships struct {
					User struct {
						Data struct {
							ID string `json:"id"`
						} `json:"data"`
					} `json:"user"`
				} `json:"relationships"`
			} `json:"data"`
		}
		// The keyword narrows the list to the user's email or name; the id
		// is still compared exactly.
		q := url.Values{"page[size]": {strconv.Itoa(pageSize)}, "page[number]": {strconv.Itoa(pageNo)}, "filter[keyword]": {keyword}}
		if err := c.getJSON(ctx, "/api/v2/team/"+httpx.PathEscape(team)+"/memberships", q, &page); err != nil {
			return false, err
		}
		for _, m := range page.Data {
			if m.Relationships.User.Data.ID == userID {
				return true, nil
			}
		}
		if len(page.Data) == 0 {
			return false, nil
		}
	}
	return false, integration.Errorf(integration.CodeUpstreamError, "team %s has too many members to read", team)
}

// --- probe ------------------------------------------------------------------

// Probe validates the keys and reads one user, which needs
// user_access_read.
func (c *Connection) Probe(ctx context.Context) (integration.ProbeResult, error) {
	var valid struct {
		Valid bool `json:"valid"`
	}
	if err := c.getJSON(ctx, "/api/v1/validate", nil, &valid); err != nil {
		return integration.ProbeResult{}, classify(err, "validate the API key")
	}
	if !valid.Valid {
		return integration.ProbeResult{}, integration.Errorf(integration.CodeCredentialRejected, "Datadog reports the API key as invalid")
	}
	var users struct {
		Data []ddUser `json:"data"`
	}
	if err := c.getJSON(ctx, "/api/v2/users", url.Values{"page[size]": {"1"}}, &users); err != nil {
		return integration.ProbeResult{}, classify(err, "list users (needs user_access_read)")
	}
	res := integration.ProbeResult{Summary: fmt.Sprintf("API key valid and application key reads users at %s", c.api.Base)}
	res.Warnings = append(res.Warnings,
		"the application key also needs teams_read and the *_read scope of each asset type asked about (monitors_read, dashboards_read, slos_read, notebooks_read); an asset it cannot read answers unknown",
		"an unscoped application key carries every permission of its creator; scope it")
	return res, nil
}
