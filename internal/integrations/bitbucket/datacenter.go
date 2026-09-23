package bitbucket

// Bitbucket Data Center (and Server): /rest/api/latest and the
// branch-permissions plugin. Permissions are listed per grant, so hallpass
// combines the direct, group, project, default, public and global grants
// itself into the user's effective level.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/roee-hersh/hallpass/internal/httpx"
	"github.com/roee-hersh/hallpass/internal/integration"
)

const dcAPI = "/rest/api/latest"

// dcUser is a Data Center user.
type dcUser struct {
	Name         string `json:"name"`
	Slug         string `json:"slug"`
	DisplayName  string `json:"displayName"`
	EmailAddress string `json:"emailAddress"`
	Active       *bool  `json:"active"`
}

// dcList reads every page of a Data Center list (start/limit paging).
func (c *Connection) dcList(ctx context.Context, path string, q url.Values, each func(values []json.RawMessage) error) error {
	if q == nil {
		q = url.Values{}
	}
	q.Set("limit", "100")
	req := &httpx.Request{Path: path, Query: q}
	return c.api.Paginate(ctx, req, func(resp *httpx.Response) (*httpx.Request, error) {
		var page struct {
			Values        []json.RawMessage `json:"values"`
			IsLastPage    *bool             `json:"isLastPage"`
			NextPageStart *int64            `json:"nextPageStart"`
		}
		if err := resp.JSON(&page); err != nil {
			return nil, integration.Wrap(integration.CodeUpstreamError, err, "Bitbucket returned an unreadable page")
		}
		if err := each(page.Values); err != nil {
			return nil, err
		}
		if page.IsLastPage == nil || *page.IsLastPage || page.NextPageStart == nil {
			return nil, nil
		}
		next := url.Values{}
		for k, v := range q {
			next[k] = v
		}
		next.Set("start", strconv.FormatInt(*page.NextPageStart, 10))
		return &httpx.Request{Path: path, Query: next}, nil
	})
}

// --- identity ---------------------------------------------------------------

// dcIdentity finds the user whose email address is the email. The filter is
// a substring match on name and email, so the address is compared exactly.
func (c *Connection) dcIdentity(ctx context.Context, email string) (integration.Identity, error) {
	var matches []dcUser
	err := c.dcList(ctx, dcAPI+"/users", url.Values{"filter": {email}}, func(values []json.RawMessage) error {
		for _, raw := range values {
			var u dcUser
			if err := json.Unmarshal(raw, &u); err != nil {
				return integration.Wrap(integration.CodeUpstreamError, err, "Bitbucket returned an unreadable user")
			}
			if strings.EqualFold(u.EmailAddress, email) {
				matches = append(matches, u)
			}
		}
		return nil
	})
	if err != nil {
		return integration.Identity{}, classify(err, "search users")
	}
	switch len(matches) {
	case 0:
		return integration.Identity{}, integration.UserNotFound("no user has email %s", email)
	case 1:
	default:
		return integration.Identity{}, integration.UserAmbiguous("%d users have email %s", len(matches), email)
	}
	u := matches[0]
	if u.Name == "" {
		return integration.Identity{}, integration.Errorf(integration.CodeUpstreamError, "the user record for %s carries no name", email)
	}
	id := integration.Identity{ID: u.Name, Display: u.Name, Attrs: map[string]string{"slug": u.Slug, "active": "unknown", "groups": "known"}}
	if u.Active != nil {
		id.Attrs["active"] = fmt.Sprint(*u.Active)
	}
	// The groups the user belongs to. Reading them needs LICENSED_USER;
	// without them group grants cannot be resolved and answer unknown.
	err = c.dcList(ctx, dcAPI+"/admin/users/more-members", url.Values{"context": {u.Name}}, func(values []json.RawMessage) error {
		for _, raw := range values {
			var g struct {
				Name string `json:"name"`
			}
			if err := json.Unmarshal(raw, &g); err != nil {
				return integration.Wrap(integration.CodeUpstreamError, err, "Bitbucket returned an unreadable group")
			}
			if g.Name != "" {
				id.Groups = append(id.Groups, g.Name)
			}
		}
		return nil
	})
	if err != nil {
		if httpx.Status(err) == 403 || httpx.Status(err) == 404 {
			id.Attrs["groups"] = "unavailable"
		} else {
			return integration.Identity{}, classify(err, "list the user's groups")
		}
	}
	return id, nil
}

// --- permission grants --------------------------------------------------------

// dcLevel parses REPO_*, PROJECT_* and global permission names.
func dcLevel(p string) level {
	switch p {
	case "REPO_ADMIN", "PROJECT_ADMIN", "ADMIN", "SYS_ADMIN":
		return levelAdmin
	case "REPO_WRITE", "PROJECT_WRITE":
		return levelWrite
	case "REPO_READ", "PROJECT_READ":
		return levelRead
	}
	return levelNone
}

// grantSet is what the grant listings of one scope say about the user.
type grantSet struct {
	level level
	how   string
	// unresolved names grants hallpass could not evaluate that might raise
	// the level: a group grant while the user's groups are unavailable, or
	// the global permissions while they are unreadable.
	unresolved []string
}

// dcGrants reads the user and group permission listings under base
// (a repository, a project, or /admin) and returns the user's highest
// level there.
func (c *Connection) dcGrants(ctx context.Context, base string, id integration.Identity) (grantSet, error) {
	var out grantSet
	err := c.dcList(ctx, base+"/permissions/users", url.Values{"filter": {id.ID}}, func(values []json.RawMessage) error {
		for _, raw := range values {
			var v struct {
				Permission string `json:"permission"`
				User       dcUser `json:"user"`
			}
			if err := json.Unmarshal(raw, &v); err != nil {
				return integration.Wrap(integration.CodeUpstreamError, err, "Bitbucket returned an unreadable grant")
			}
			// The filter is a substring match; only the exact name counts.
			if v.User.Name == id.ID {
				if l := dcLevel(v.Permission); l > out.level {
					out.level, out.how = l, v.Permission+" granted directly"
				}
			}
		}
		return nil
	})
	if err != nil {
		return out, err
	}
	err = c.dcList(ctx, base+"/permissions/groups", nil, func(values []json.RawMessage) error {
		for _, raw := range values {
			var v struct {
				Permission string `json:"permission"`
				Group      struct {
					Name string `json:"name"`
				} `json:"group"`
			}
			if err := json.Unmarshal(raw, &v); err != nil {
				return integration.Wrap(integration.CodeUpstreamError, err, "Bitbucket returned an unreadable grant")
			}
			l := dcLevel(v.Permission)
			if l <= out.level {
				continue
			}
			if id.Attr("groups") == "unavailable" {
				out.unresolved = append(out.unresolved, v.Permission+" of group "+v.Group.Name)
				continue
			}
			for _, g := range id.Groups {
				if g == v.Group.Name {
					out.level, out.how = l, v.Permission+" via group "+v.Group.Name
				}
			}
		}
		return nil
	})
	return out, err
}

// dcGlobal is the user's global level: ADMIN or SYS_ADMIN carry admin
// everywhere. Reading it needs ADMIN; a refusal is reported so the caller
// can answer unknown when it would have mattered.
func (c *Connection) dcGlobal(ctx context.Context, id integration.Identity) (grantSet, bool, error) {
	g, err := c.dcGrants(ctx, dcAPI+"/admin", id)
	if err != nil {
		if httpx.Status(err) == 403 || httpx.Status(err) == 401 {
			return grantSet{}, false, nil
		}
		return grantSet{}, false, classify(err, "read the global permissions")
	}
	if g.level < levelAdmin {
		g.level = levelNone
	}
	return g, true, nil
}

// dcProjectLevel is the user's effective level on a project: direct and
// group grants, the project's default permission, its public flag and the
// global permissions.
func (c *Connection) dcProjectLevel(ctx context.Context, key string, id integration.Identity, need level) (grantSet, bool, error) {
	var project struct {
		Key    string `json:"key"`
		Public bool   `json:"public"`
	}
	base := dcAPI + "/projects/" + httpx.PathEscape(key)
	if err := c.getJSON(ctx, base, nil, &project); err != nil {
		return grantSet{}, false, err
	}
	g, err := c.dcGrants(ctx, base, id)
	if err != nil {
		return grantSet{}, true, err
	}
	if project.Public && g.level < levelRead {
		g.level, g.how = levelRead, "public project"
	}
	// Default permissions: granted to every licensed user.
	for _, p := range []struct {
		name  string
		level level
	}{{"PROJECT_ADMIN", levelAdmin}, {"PROJECT_WRITE", levelWrite}, {"PROJECT_READ", levelRead}} {
		if p.level <= g.level || p.level < need {
			continue
		}
		var out struct {
			Permitted bool `json:"permitted"`
		}
		if err := c.getJSON(ctx, base+"/permissions/"+p.name+"/all", nil, &out); err != nil {
			return grantSet{}, true, err
		}
		if out.Permitted {
			g.level, g.how = p.level, p.name+" is the project default"
			break
		}
	}
	if g.level < levelAdmin {
		global, seen, err := c.dcGlobal(ctx, id)
		if err != nil {
			return grantSet{}, true, err
		}
		switch {
		case global.level == levelAdmin:
			g.level, g.how = levelAdmin, global.how+" globally"
		case !seen && g.level < need:
			g.unresolved = append(g.unresolved, "the global permissions (not readable without ADMIN)")
		default:
			g.unresolved = append(g.unresolved, global.unresolved...)
		}
	}
	return g, true, nil
}

// --- checks -----------------------------------------------------------------

func (c *Connection) dcCheck(ctx context.Context, t target, id integration.Identity) (integration.Decision, error) {
	switch t.action.resource {
	case "workspace":
		return c.dcInstance(ctx, t, id)
	case "project":
		return c.dcProject(ctx, t, id)
	}
	return c.dcRepo(ctx, t, id)
}

func (c *Connection) dcInstance(ctx context.Context, t target, id integration.Identity) (integration.Decision, error) {
	if t.action.role == "member" {
		if id.Attr("active") != "true" {
			return integration.Unsupported("Bitbucket did not report whether %s is active", id.Display), nil
		}
		return integration.Allowed("%s is an active user of the instance", id.Display), nil
	}
	global, seen, err := c.dcGlobal(ctx, id)
	if err != nil {
		return integration.Decision{}, err
	}
	if !seen {
		return integration.Decision{}, integration.Errorf(integration.CodeCredentialRejected, "reading the global permissions needs ADMIN, which hallpass's token lacks")
	}
	if global.level == levelAdmin {
		return integration.Allowed("%s is a global administrator (%s)", id.Display, global.how), nil
	}
	if len(global.unresolved) > 0 {
		return integration.Unsupported("%s holds no global administrator permission directly, and hallpass could not resolve %s (listing the groups of a user needs LICENSED_USER)", id.Display, strings.Join(global.unresolved, ", ")), nil
	}
	return integration.Denied("%s holds no global administrator permission", id.Display), nil
}

// UNVERIFIED: repository creation in a Data Center project is taken to need
// PROJECT_ADMIN; if Bitbucket lets PROJECT_WRITE create repositories, users
// with write are denied repo.create although they could.
const dcRepoCreateLevel = levelAdmin

func (c *Connection) dcProject(ctx context.Context, t target, id integration.Identity) (integration.Decision, error) {
	need := t.action.level
	if t.action.createRepo {
		need = dcRepoCreateLevel
	}
	g, exists, err := c.dcProjectLevel(ctx, t.project, id, need)
	if err != nil {
		if !exists && httpx.Status(err) == 404 {
			return integration.UnknownDecision(integration.CodeResourceNotVisible, "project %s does not exist or hallpass cannot see it", t.project), nil
		}
		return integration.Decision{}, classify(err, "read the permissions of project "+t.project)
	}
	return dcDecide(g, need, id, t), nil
}

func (c *Connection) dcRepo(ctx context.Context, t target, id integration.Identity) (integration.Decision, error) {
	var repo struct {
		Slug   string `json:"slug"`
		Public bool   `json:"public"`
	}
	base := dcAPI + "/projects/" + httpx.PathEscape(t.project) + "/repos/" + httpx.PathEscape(t.repo)
	if err := c.getJSON(ctx, base, nil, &repo); err != nil {
		if httpx.Status(err) == 404 {
			return integration.UnknownDecision(integration.CodeResourceNotVisible, "%s does not exist or hallpass cannot see it", t), nil
		}
		return integration.Decision{}, classify(err, "read "+t.String())
	}
	need := t.action.level
	g, err := c.dcGrants(ctx, base, id)
	if err != nil {
		return integration.Decision{}, classify(err, "read the permissions of "+t.String())
	}
	if repo.Public && g.level < levelRead {
		g.level, g.how = levelRead, "public repository"
	}
	if g.level < need {
		p, _, err := c.dcProjectLevel(ctx, t.project, id, need)
		if err != nil {
			return integration.Decision{}, classify(err, "read the permissions of project "+t.project)
		}
		if p.level > g.level {
			g.level, g.how = p.level, p.how+" on project "+t.project
		}
		g.unresolved = append(g.unresolved, p.unresolved...)
	}
	d := dcDecide(g, need, id, t)
	if d.Code != integration.CodeAllowed || t.branch == "" {
		return d, nil
	}
	return c.dcBranch(ctx, t, id, g)
}

// dcDecide turns a grant set into a decision.
func dcDecide(g grantSet, need level, id integration.Identity, t target) integration.Decision {
	if g.level >= need {
		return integration.Allowed("%s %s on %s: %s", id.Display, describeLevel(g.level, need), t, g.how)
	}
	if len(g.unresolved) > 0 {
		return integration.Unsupported("%s %s on %s as far as hallpass can read, and %s could add more", id.Display, describeLevel(g.level, need), t, strings.Join(g.unresolved, ", "))
	}
	return integration.Denied("%s %s on %s", id.Display, describeLevel(g.level, need), t)
}

// dcRestriction is one ref restriction of the branch-permissions plugin.
type dcRestriction struct {
	ID      int64  `json:"id"`
	Type    string `json:"type"`
	Matcher struct {
		ID        string `json:"id"`
		DisplayID string `json:"displayId"`
		Type      struct {
			ID string `json:"id"`
		} `json:"type"`
	} `json:"matcher"`
	Users  []dcUser `json:"users"`
	Groups []string `json:"groups"`
}

// dcBranch evaluates the ref restrictions on the branch for a user who has
// write. read-only stops pushes and merges, pull-request-only stops direct
// pushes; the listed users and groups are exempt.
func (c *Connection) dcBranch(ctx context.Context, t target, id integration.Identity, g grantSet) (integration.Decision, error) {
	blocking := map[string]bool{"read-only": true}
	if t.action.branch == "push" {
		blocking["pull-request-only"] = true
	}
	var matching []dcRestriction
	var unsupported []string
	seen := map[int64]bool{}
	// Restrictions set on the project apply to every repository in it, so
	// both levels are read; a restriction listed twice counts once.
	project := "/rest/branch-permissions/2.0/projects/" + httpx.PathEscape(t.project)
	collect := func(values []json.RawMessage) error {
		for _, raw := range values {
			var r dcRestriction
			if err := json.Unmarshal(raw, &r); err != nil {
				return integration.Wrap(integration.CodeUpstreamError, err, "Bitbucket returned an unreadable restriction")
			}
			if !blocking[r.Type] || (r.ID != 0 && seen[r.ID]) {
				continue
			}
			seen[r.ID] = true
			switch r.Matcher.Type.ID {
			case "ANY_REF":
				matching = append(matching, r)
			case "BRANCH":
				if r.Matcher.DisplayID == t.branch || r.Matcher.ID == "refs/heads/"+t.branch {
					matching = append(matching, r)
				}
			case "PATTERN":
				matched, ok := refMatch(r.Matcher.ID, t.branch, true)
				if !ok {
					unsupported = append(unsupported, "pattern "+strconv.Quote(r.Matcher.ID))
				} else if matched {
					matching = append(matching, r)
				}
			default:
				// MODEL_BRANCH and MODEL_CATEGORY name branches through the
				// branching model, which hallpass does not read.
				unsupported = append(unsupported, "branching model matcher "+r.Matcher.Type.ID)
			}
		}
		return nil
	}
	err := c.dcList(ctx, project+"/repos/"+httpx.PathEscape(t.repo)+"/restrictions", nil, collect)
	if err == nil {
		err = c.dcList(ctx, project+"/restrictions", nil, collect)
	}
	if err != nil {
		if httpx.Status(err) == 404 {
			return integration.UnknownDecision(integration.CodeResourceNotVisible, "the branch permissions of %s are not visible to hallpass", t), nil
		}
		return integration.Decision{}, classify(err, "read the branch permissions")
	}
	verb := "push to"
	if t.action.branch == "merge" {
		verb = "merge into"
	}
	for _, r := range matching {
		exempt := false
		for _, u := range r.Users {
			if u.Name == id.ID {
				exempt = true
			}
		}
		for _, grp := range r.Groups {
			for _, mine := range id.Groups {
				if grp == mine {
					exempt = true
				}
			}
		}
		if exempt {
			continue
		}
		if len(r.Groups) > 0 && id.Attr("groups") == "unavailable" {
			return integration.Unsupported("a %s restriction on %s exempts group %s and hallpass could not list the groups of %s", r.Type, r.Matcher.DisplayID, strings.Join(r.Groups, ", "), id.Display), nil
		}
		return integration.Denied("a %s restriction on %s stops %s from %s %s", r.Type, r.Matcher.DisplayID, id.Display, verb, t.branch), nil
	}
	if len(unsupported) > 0 {
		return integration.Unsupported("branch permissions on %s use %s, which hallpass cannot evaluate for branch %s", t.project+"/"+t.repo, strings.Join(unsupported, ", "), t.branch), nil
	}
	return integration.Allowed("%s %s on %s: %s, and no branch permission stops %s", id.Display, describeLevel(g.level, t.action.level), t, g.how, t.branch), nil
}

// --- probe ------------------------------------------------------------------

func (c *Connection) dcProbe(ctx context.Context) (integration.ProbeResult, error) {
	var props struct {
		Version     string `json:"version"`
		DisplayName string `json:"displayName"`
	}
	if err := c.getJSON(ctx, dcAPI+"/application-properties", nil, &props); err != nil {
		return integration.ProbeResult{}, classify(err, "read the application properties")
	}
	if err := c.getJSON(ctx, dcAPI+"/users", url.Values{"limit": {"1"}}, nil); err != nil {
		return integration.ProbeResult{}, classify(err, "list users")
	}
	res := integration.ProbeResult{Summary: fmt.Sprintf("%s %s at %s: the token authenticates", props.DisplayName, props.Version, c.api.Base)}
	if err := c.getJSON(ctx, dcAPI+"/admin/permissions/users", url.Values{"limit": {"1"}}, nil); err != nil {
		if httpx.Status(err) == 403 || httpx.Status(err) == 401 {
			res.Warnings = append(res.Warnings, "the token lacks ADMIN: global administrators cannot be recognised and workspace.admin answers unknown")
		} else {
			return integration.ProbeResult{}, classify(err, "read the global permissions")
		}
	}
	res.Warnings = append(res.Warnings, "repository and project permission listings need REPO_ADMIN or PROJECT_ADMIN on each object, or a global ADMIN token; objects the token lacks it on answer unknown")
	return res, nil
}
