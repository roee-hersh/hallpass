// Package confluence checks Confluence Cloud permissions.
//
// Page and blog post actions go to Confluence's own permission check,
// POST /wiki/rest/api/content/{id}/permission/check, which weighs site,
// space and content restrictions for the given account. Space actions have
// no such call, so hallpass reads the space's permission list
// (GET /wiki/api/v2/spaces/{id}/permissions) and the user's groups and
// matches them itself.
//
// Confluence's user search has no email field, so the caller's email is
// resolved through a jira connection on the same Atlassian site
// (identity_connection). The transport (auth modes, cloud id discovery) is
// the jira package's Site. Confluence Data Center is out of scope.
package confluence

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/roee-hersh/hallpass/internal/catalog"
	"github.com/roee-hersh/hallpass/internal/httpx"
	"github.com/roee-hersh/hallpass/internal/integration"
	"github.com/roee-hersh/hallpass/internal/integrations/jira"
)

// Integration is the confluence product.
type Integration struct{}

// Name is "confluence".
func (Integration) Name() string { return "confluence" }

// Fields of a confluence connection: the Atlassian site keys plus
// identity_connection.
func (Integration) Fields() []integration.Field {
	return append(jira.SiteFields(),
		integration.ConnectionRefField("identity_connection", "jira", false,
			"jira connection on the same Atlassian site, used to look users up by email"),
	)
}

// Actions of the confluence integration.
func (Integration) Actions() []catalog.Action {
	acts := make([]catalog.Action, 0, len(actionList))
	for _, a := range actionList {
		acts = append(acts, catalog.Action{Name: a.name, Description: a.desc})
	}
	return acts
}

// New builds a connection.
func (Integration) New(_ context.Context, s *integration.Settings, d integration.Deps) (integration.Connection, error) {
	site, err := jira.NewSite(s, d, "confluence")
	if err != nil {
		return nil, err
	}
	c := &Connection{site: site}
	if id := s.Get("identity_connection"); id != "" {
		jc, err := d.Connection(id)
		if err != nil {
			return nil, err
		}
		ident, ok := jc.(*jira.Connection)
		if !ok {
			return nil, fmt.Errorf("identity_connection %q is not a jira connection", id)
		}
		c.identity = ident
	}
	return c, nil
}

// Connection is one Confluence Cloud site.
type Connection struct {
	site     *jira.Site
	identity *jira.Connection // nil when identity_connection is unset
}

// noIdentityText is the reason every check answers unknown when no jira
// connection is configured for email lookup.
const noIdentityText = "Confluence cannot look up users by email; set identity_connection to a jira connection on the same site"

// ResolveIdentity maps the caller's email to an accountId through the jira
// connection.
func (c *Connection) ResolveIdentity(ctx context.Context, u integration.User) (integration.Identity, error) {
	if c.identity == nil {
		return integration.Identity{}, integration.Errorf(integration.CodeUnsupported, noIdentityText)
	}
	return c.identity.LookupAccountID(ctx, u.Email)
}

// Check answers one question.
func (c *Connection) Check(ctx context.Context, r integration.CheckRequest) (integration.Decision, error) {
	act, ok := actions[r.ActionName]
	if !ok {
		return integration.Decision{}, integration.Errorf(integration.CodeInvalidRequest, "unknown action %q", r.ActionName)
	}
	res, err := parseResource(r.Resource)
	if err != nil {
		return integration.Decision{}, integration.Errorf(integration.CodeInvalidRequest, "%v", err)
	}
	if res.kind != act.resource {
		return integration.Decision{}, integration.Errorf(integration.CodeInvalidRequest, "%s applies to %s:<%s>, not %s", act.name, act.resource, act.resource.idShape(), r.Resource.Raw)
	}
	who := r.Identity.Display
	if who == "" {
		who = r.Identity.ID
	}
	if res.kind == resSpace {
		return c.checkSpace(ctx, r.Identity.ID, who, act, res.id)
	}
	return c.checkContent(ctx, r.Identity.ID, who, act, res)
}

type permissionCheckRequest struct {
	Subject struct {
		Type       string `json:"type"`
		Identifier string `json:"identifier"`
	} `json:"subject"`
	Operation string `json:"operation"`
}

type permissionCheckResponse struct {
	HasPermission bool              `json:"hasPermission"`
	Errors        []json.RawMessage `json:"errors"`
}

// checkContent asks Confluence directly.
func (c *Connection) checkContent(ctx context.Context, accountID, who string, act action, res resource) (integration.Decision, error) {
	var req permissionCheckRequest
	req.Subject.Type = "user"
	req.Subject.Identifier = accountID
	req.Operation = act.operation
	var out permissionCheckResponse
	path := "/wiki/rest/api/content/" + httpx.PathEscape(res.id) + "/permission/check"
	if _, err := c.site.PostJSON(ctx, path, req, &out, true); err != nil {
		switch httpx.Status(err) {
		case 404:
			return integration.UnknownDecision(integration.CodeResourceNotVisible, "%s %s does not exist or is not visible to hallpass's account", res.kind, res.id), nil
		case 403:
			return integration.Decision{}, integration.Wrap(integration.CodeCredentialRejected, err,
				"hallpass's account may not check other users' permissions; it needs Confluence Administrator (HTTP 403)")
		}
		return integration.Decision{}, httpx.Classify(err)
	}
	if out.HasPermission {
		return integration.Allowed("%s may %s %s %s", who, act.operation, res.kind, res.id), nil
	}
	return integration.Denied("%s may not %s %s %s", who, act.operation, res.kind, res.id), nil
}

type spaceList struct {
	Results []struct {
		ID  string `json:"id"`
		Key string `json:"key"`
	} `json:"results"`
}

type spacePermission struct {
	Principal struct {
		Type string `json:"type"`
		ID   string `json:"id"`
	} `json:"principal"`
	Operation struct {
		Key        string `json:"key"`
		TargetType string `json:"targetType"`
	} `json:"operation"`
}

type spacePermissionPage struct {
	Results []spacePermission `json:"results"`
	Links   struct {
		Next string `json:"next"`
	} `json:"_links"`
}

type groupPage struct {
	Results []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"results"`
	Links struct {
		Next string `json:"next"`
	} `json:"_links"`
}

// checkSpace evaluates a space permission from the space's permission list.
func (c *Connection) checkSpace(ctx context.Context, accountID, who string, act action, key string) (integration.Decision, error) {
	var spaces spaceList
	if _, err := c.site.GetJSON(ctx, "/wiki/api/v2/spaces", url.Values{"keys": {key}}, &spaces); err != nil {
		if httpx.Status(err) == 404 {
			return integration.UnknownDecision(integration.CodeResourceNotVisible, "space %s does not exist or is not visible to hallpass's account", key), nil
		}
		return integration.Decision{}, c.classify(err)
	}
	var spaceID string
	for _, s := range spaces.Results {
		if strings.EqualFold(s.Key, key) {
			spaceID = s.ID
			break
		}
	}
	if spaceID == "" {
		return integration.UnknownDecision(integration.CodeResourceNotVisible, "space %s does not exist or is not visible to hallpass's account", key), nil
	}

	// UNVERIFIED: the operation keys and targetTypes for export, restrict
	// and administer are taken from the specification, not from a live site.
	var groupIDs []string
	unknownTypes := map[string]bool{}
	err := c.paginate(ctx, "/wiki/api/v2/spaces/"+httpx.PathEscape(spaceID)+"/permissions", url.Values{"limit": {"250"}}, func(resp *httpx.Response) (string, error) {
		var page spacePermissionPage
		if err := resp.JSON(&page); err != nil {
			return "", err
		}
		for _, p := range page.Results {
			if p.Operation.Key != act.operation || p.Operation.TargetType != act.target {
				continue
			}
			switch p.Principal.Type {
			case "user":
				if p.Principal.ID == accountID {
					return "", errAllowed
				}
			case "group":
				groupIDs = append(groupIDs, p.Principal.ID)
			default:
				unknownTypes[p.Principal.Type] = true
			}
		}
		return page.Links.Next, nil
	})
	what := fmt.Sprintf("%s (%s/%s) in space %s", act.name, act.operation, act.target, key)
	switch {
	case errors.Is(err, errAllowed):
		return integration.Allowed("%s holds %s directly", who, what), nil
	case err != nil:
		return integration.Decision{}, c.classify(err)
	}

	if len(groupIDs) > 0 {
		member, groupName, err := c.memberOfAny(ctx, accountID, groupIDs)
		if err != nil {
			return integration.Decision{}, c.classify(err)
		}
		if member {
			return integration.Allowed("%s holds %s through group %s", who, what, groupName), nil
		}
	}
	if len(unknownTypes) > 0 {
		types := make([]string, 0, len(unknownTypes))
		for t := range unknownTypes {
			types = append(types, t)
		}
		return integration.Unsupported("%s-based space permissions not evaluated: %s is granted to a principal type hallpass does not model", strings.Join(types, "/"), what), nil
	}
	return integration.Denied("no space permission grants %s to %s or their groups", what, who), nil
}

var errAllowed = errors.New("allowed")

// memberOfAny reports whether the account belongs to one of the groups,
// reading GET /wiki/rest/api/user/memberof page by page.
func (c *Connection) memberOfAny(ctx context.Context, accountID string, groupIDs []string) (bool, string, error) {
	want := map[string]bool{}
	for _, g := range groupIDs {
		want[g] = true
	}
	found := ""
	err := c.paginate(ctx, "/wiki/rest/api/user/memberof", url.Values{"accountId": {accountID}, "limit": {"200"}}, func(resp *httpx.Response) (string, error) {
		var page groupPage
		if err := resp.JSON(&page); err != nil {
			return "", err
		}
		for _, g := range page.Results {
			if want[g.ID] {
				found = g.Name
				if found == "" {
					found = g.ID
				}
				return "", errAllowed
			}
		}
		return page.Links.Next, nil
	})
	if errors.Is(err, errAllowed) {
		return true, found, nil
	}
	return false, "", err
}

// paginate follows _links.next until the page func returns "" or an error.
func (c *Connection) paginate(ctx context.Context, path string, q url.Values, page func(*httpx.Response) (string, error)) error {
	first, err := c.site.Resolve(ctx, path)
	if err != nil {
		return err
	}
	base, err := c.site.Base(ctx)
	if err != nil {
		return err
	}
	return c.site.Client().Paginate(ctx, &httpx.Request{Method: http.MethodGet, Path: first, Query: q}, func(resp *httpx.Response) (*httpx.Request, error) {
		next, err := page(resp)
		if err != nil || next == "" {
			return nil, err
		}
		np := nextPath(next)
		if np == "" {
			return nil, nil
		}
		return &httpx.Request{Method: http.MethodGet, Path: base + np}, nil
	})
}

// nextPath normalises a _links.next value to a site-relative /wiki/... path.
// UNVERIFIED: v1 links are relative to {url}/wiki (/rest/api/...), v2 links
// to the site (/wiki/api/v2/...), and either may be absolute; all three
// shapes are handled.
func nextPath(next string) string {
	next = strings.TrimSpace(next)
	if next == "" {
		return ""
	}
	if strings.HasPrefix(next, "http://") || strings.HasPrefix(next, "https://") {
		u, err := url.Parse(next)
		if err != nil {
			return ""
		}
		next = u.RequestURI()
	}
	if i := strings.Index(next, "/wiki/"); i >= 0 {
		return next[i:]
	}
	if !strings.HasPrefix(next, "/") {
		next = "/" + next
	}
	return "/wiki" + next
}

func (c *Connection) classify(err error) error {
	if httpx.Status(err) == 403 {
		return integration.Wrap(integration.CodeCredentialRejected, err, "hallpass's account may not read space permissions or group memberships (HTTP 403)")
	}
	return httpx.Classify(err)
}

// Probe verifies the credential and reports the identity setup.
func (c *Connection) Probe(ctx context.Context) (integration.ProbeResult, error) {
	var me struct {
		AccountID   string `json:"accountId"`
		DisplayName string `json:"displayName"`
	}
	if _, err := c.site.GetJSON(ctx, "/wiki/rest/api/user/current", nil, &me); err != nil {
		if httpx.Status(err) == 403 {
			return integration.ProbeResult{}, integration.Wrap(integration.CodeCredentialRejected, err, "the credential is valid but may not read its own profile (HTTP 403)")
		}
		return integration.ProbeResult{}, httpx.Classify(err)
	}
	res := integration.ProbeResult{Summary: fmt.Sprintf("authenticated as %s (%s) with auth_mode %s", me.DisplayName, me.AccountID, c.site.Mode)}
	if c.identity == nil {
		res.Warnings = append(res.Warnings, "identity_connection is not set; every check will answer unknown because "+noIdentityText)
	}
	res.Warnings = append(res.Warnings, "checking other users' permissions needs Confluence Administrator on hallpass's account; a plain user gets HTTP 403 (credential_rejected)")
	return res, nil
}
