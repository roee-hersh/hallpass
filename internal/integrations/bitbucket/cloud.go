package bitbucket

// Bitbucket Cloud (api.bitbucket.org/2.0). Every resource belongs to the
// connection's workspace.

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

// cloudUser is the user object as the workspace endpoints return it.
type cloudUser struct {
	AccountID   string `json:"account_id"`
	UUID        string `json:"uuid"`
	Nickname    string `json:"nickname"`
	DisplayName string `json:"display_name"`
	Email       string `json:"email"`
}

// cloudPage is the pagination envelope of every Cloud list.
type cloudPage[T any] struct {
	Values []T    `json:"values"`
	Next   string `json:"next"`
}

// cloudList reads every page of a Cloud list and hands each page's values
// to each. Pages are followed through the body's next URL, which must stay
// under the API base.
func (c *Connection) cloudList(ctx context.Context, path string, q url.Values, each func(values []json.RawMessage) error) error {
	req := &httpx.Request{Path: path, Query: q}
	return c.api.Paginate(ctx, req, func(resp *httpx.Response) (*httpx.Request, error) {
		var page cloudPage[json.RawMessage]
		if err := resp.JSON(&page); err != nil {
			return nil, integration.Wrap(integration.CodeUpstreamError, err, "Bitbucket returned an unreadable page")
		}
		if err := each(page.Values); err != nil {
			return nil, err
		}
		if page.Next == "" {
			return nil, nil
		}
		if !c.api.Within(page.Next) {
			return nil, integration.Errorf(integration.CodeUpstreamError, "Bitbucket sent a next page outside its API")
		}
		return &httpx.Request{Path: page.Next}, nil
	})
}

// decodeEach unmarshals every raw value into T and calls fn.
func decodeEach[T any](values []json.RawMessage, fn func(T)) error {
	for _, raw := range values {
		var v T
		if err := json.Unmarshal(raw, &v); err != nil {
			return integration.Wrap(integration.CodeUpstreamError, err, "Bitbucket returned an unreadable entry")
		}
		fn(v)
	}
	return nil
}

// --- identity ---------------------------------------------------------------

// cloudIdentity finds the workspace member with the email. Only a workspace
// administrator, an integration or a workspace access token may filter
// members by email.
func (c *Connection) cloudIdentity(ctx context.Context, email string) (integration.Identity, error) {
	// IsEmail admits no quote, so the address cannot escape the IN list.
	q := url.Values{
		"q":      {`user.email IN ("` + email + `")`},
		"fields": {"values.user.email,values.user.account_id,values.user.uuid,values.user.nickname,values.user.display_name,next"},
	}
	var page cloudPage[struct {
		User cloudUser `json:"user"`
	}]
	if err := c.getJSON(ctx, "/2.0/workspaces/"+httpx.PathEscape(c.workspace)+"/members", q, &page); err != nil {
		if httpx.Status(err) == 404 {
			return integration.Identity{}, integration.Wrap(integration.CodeCredentialRejected, err, "workspace %s is not visible to hallpass's token", c.workspace)
		}
		return integration.Identity{}, classify(err, "list the workspace members")
	}
	var matches []cloudUser
	for _, v := range page.Values {
		if strings.EqualFold(v.User.Email, email) {
			matches = append(matches, v.User)
		}
	}
	switch len(matches) {
	case 0:
		return integration.Identity{}, integration.UserNotFound("no member of workspace %s has email %s", c.workspace, email)
	case 1:
	default:
		return integration.Identity{}, integration.UserAmbiguous("%d members of workspace %s have email %s", len(matches), c.workspace, email)
	}
	u := matches[0]
	if u.AccountID == "" {
		return integration.Identity{}, integration.Errorf(integration.CodeUpstreamError, "the member record for %s carries no account id", email)
	}
	display := u.Nickname
	if display == "" {
		display = email
	}
	return integration.Identity{ID: u.AccountID, Display: display, Attrs: map[string]string{"uuid": u.UUID, "email": email}}, nil
}

// --- checks -----------------------------------------------------------------

func (c *Connection) cloudCheck(ctx context.Context, t target, id integration.Identity) (integration.Decision, error) {
	switch t.action.resource {
	case "workspace":
		return c.cloudWorkspace(ctx, t, id)
	case "project":
		return c.cloudProject(ctx, t, id)
	}
	return c.cloudRepo(ctx, t, id)
}

// cloudIsOwner reports whether the user is a workspace owner.
func (c *Connection) cloudIsOwner(ctx context.Context, id integration.Identity) (bool, error) {
	owner := false
	type membership struct {
		Permission string    `json:"permission"`
		User       cloudUser `json:"user"`
	}
	err := c.cloudList(ctx, "/2.0/workspaces/"+httpx.PathEscape(c.workspace)+"/permissions", url.Values{"q": {`permission="owner"`}, "pagelen": {"100"}}, func(values []json.RawMessage) error {
		return decodeEach(values, func(m membership) {
			if m.Permission == "owner" && sameUser(m.User, id) {
				owner = true
			}
		})
	})
	if err != nil {
		return false, classify(err, "list the workspace owners")
	}
	return owner, nil
}

// sameUser matches a Cloud user object against the identity by account id
// or UUID.
func sameUser(u cloudUser, id integration.Identity) bool {
	return u.AccountID == id.ID || (u.UUID != "" && u.UUID == id.Attr("uuid"))
}

func (c *Connection) cloudWorkspace(ctx context.Context, t target, id integration.Identity) (integration.Decision, error) {
	if t.action.role == "member" {
		err := c.getJSON(ctx, "/2.0/workspaces/"+httpx.PathEscape(c.workspace)+"/members/"+httpx.PathEscape(id.ID), nil, nil)
		if httpx.Status(err) == 404 {
			return integration.Denied("%s is not a member of workspace %s", id.Display, c.workspace), nil
		}
		if err != nil {
			return integration.Decision{}, classify(err, "read the membership")
		}
		return integration.Allowed("%s is a member of workspace %s", id.Display, c.workspace), nil
	}
	owner, err := c.cloudIsOwner(ctx, id)
	if err != nil {
		return integration.Decision{}, err
	}
	if owner {
		return integration.Allowed("%s is an owner of workspace %s", id.Display, c.workspace), nil
	}
	return integration.Denied("%s is not an owner of workspace %s", id.Display, c.workspace), nil
}

// cloudProjectLevel is an explicit project permission.
type cloudProjectLevel struct {
	level      level
	createRepo bool
}

func parseCloudProjectPermission(p string) cloudProjectLevel {
	switch p {
	case "admin":
		return cloudProjectLevel{levelAdmin, true}
	case "create-repo":
		return cloudProjectLevel{levelWrite, true}
	case "write":
		return cloudProjectLevel{levelWrite, false}
	case "read":
		return cloudProjectLevel{levelRead, false}
	}
	return cloudProjectLevel{}
}

func (l cloudProjectLevel) satisfies(a action) bool {
	if a.createRepo {
		return l.createRepo
	}
	return l.level >= a.level
}

func (c *Connection) cloudProject(ctx context.Context, t target, id integration.Identity) (integration.Decision, error) {
	base := "/2.0/workspaces/" + httpx.PathEscape(c.workspace) + "/projects/" + httpx.PathEscape(t.project)
	var project struct {
		IsPrivate *bool `json:"is_private"`
	}
	if err := c.getJSON(ctx, base, nil, &project); err != nil {
		if httpx.Status(err) == 404 {
			return integration.UnknownDecision(integration.CodeResourceNotVisible, "project %s does not exist in workspace %s or hallpass cannot see it", t.project, c.workspace), nil
		}
		return integration.Decision{}, classify(err, "read project "+t.project)
	}
	var direct struct {
		Permission string `json:"permission"`
	}
	err := c.getJSON(ctx, base+"/permissions-config/users/"+httpx.PathEscape(id.ID), nil, &direct)
	if err != nil && httpx.Status(err) != 404 {
		return integration.Decision{}, classify(err, "read the project permissions")
	}
	need := t.action.level.String()
	if t.action.createRepo {
		need = "create-repo"
	}
	if l := parseCloudProjectPermission(direct.Permission); l.satisfies(t.action) {
		return integration.Allowed("%s has %s on project %s directly (needs %s)", id.Display, direct.Permission, t.project, need), nil
	}
	if t.action.level == levelRead && !t.action.createRepo && project.IsPrivate != nil && !*project.IsPrivate {
		return integration.Allowed("project %s is public, so %s can read it", t.project, id.Display), nil
	}
	owner, err := c.cloudIsOwner(ctx, id)
	if err != nil {
		return integration.Decision{}, err
	}
	if owner {
		return integration.Allowed("%s is an owner of workspace %s, which carries admin on project %s", id.Display, c.workspace, t.project), nil
	}
	// Group grants: Cloud's API exposes no group membership, so a group
	// that would suffice makes the answer unknown rather than deny.
	var groups []string
	type groupGrant struct {
		Permission string `json:"permission"`
		Group      struct {
			Slug string `json:"slug"`
		} `json:"group"`
	}
	err = c.cloudList(ctx, base+"/permissions-config/groups", url.Values{"pagelen": {"100"}}, func(values []json.RawMessage) error {
		return decodeEach(values, func(g groupGrant) {
			if parseCloudProjectPermission(g.Permission).satisfies(t.action) {
				groups = append(groups, g.Group.Slug)
			}
		})
	})
	if err != nil {
		return integration.Decision{}, classify(err, "read the project group permissions")
	}
	if len(groups) > 0 {
		return integration.Unsupported("group %s grants %s on project %s and Bitbucket Cloud does not tell hallpass who is in it; %s has %s directly", strings.Join(groups, ", "), need, t.project, id.Display, noneOr(direct.Permission)), nil
	}
	return integration.Denied("%s has %s on project %s, needs %s", id.Display, noneOr(direct.Permission), t.project, need), nil
}

func noneOr(p string) string {
	if p == "" {
		return "none"
	}
	return p
}

func parseCloudLevel(p string) level {
	switch p {
	case "admin":
		return levelAdmin
	case "write":
		return levelWrite
	case "read":
		return levelRead
	}
	return levelNone
}

// cloudRepoLevel reads the user's effective permission on the repository:
// the highest of direct, group and project grants, as Bitbucket computes
// it. The list is filtered by account id; a Bitbucket that rejects the
// filter is read whole.
func (c *Connection) cloudRepoLevel(ctx context.Context, slug string, id integration.Identity) (level, error) {
	path := "/2.0/workspaces/" + httpx.PathEscape(c.workspace) + "/permissions/repositories/" + httpx.PathEscape(slug)
	found := levelNone
	type grant struct {
		Permission string    `json:"permission"`
		User       cloudUser `json:"user"`
	}
	read := func(q url.Values) error {
		return c.cloudList(ctx, path, q, func(values []json.RawMessage) error {
			return decodeEach(values, func(g grant) {
				if sameUser(g.User, id) {
					if l := parseCloudLevel(g.Permission); l > found {
						found = l
					}
				}
			})
		})
	}
	// UNVERIFIED: the filter grammar for a single user; the spec says the
	// list "may be filtered by user" and documents q=permission>"read".
	err := read(url.Values{"q": {`user.account_id="` + id.ID + `"`}, "pagelen": {"100"}})
	if httpx.Status(err) == 400 {
		err = read(url.Values{"pagelen": {"100"}})
	}
	return found, err
}

// cloudRepo answers a repository question.
func (c *Connection) cloudRepo(ctx context.Context, t target, id integration.Identity) (integration.Decision, error) {
	var repo struct {
		IsPrivate *bool `json:"is_private"`
		Project   struct {
			Key string `json:"key"`
		} `json:"project"`
	}
	repoPath := "/2.0/repositories/" + httpx.PathEscape(c.workspace) + "/" + httpx.PathEscape(t.repo)
	if err := c.getJSON(ctx, repoPath, nil, &repo); err != nil {
		if httpx.Status(err) == 404 {
			return integration.UnknownDecision(integration.CodeResourceNotVisible, "repository %s does not exist in workspace %s or hallpass cannot see it", t.repo, c.workspace), nil
		}
		return integration.Decision{}, classify(err, "read repository "+t.repo)
	}
	have, err := c.cloudRepoLevel(ctx, t.repo, id)
	if err != nil {
		if httpx.Status(err) == 404 {
			return integration.UnknownDecision(integration.CodeResourceNotVisible, "the permissions of repository %s are not visible to hallpass", t.repo), nil
		}
		return integration.Decision{}, classify(err, "read the repository permissions")
	}
	how := "effective permission"
	if have == levelNone {
		owner, err := c.cloudIsOwner(ctx, id)
		if err != nil {
			return integration.Decision{}, err
		}
		switch {
		case owner:
			have, how = levelAdmin, "workspace owner"
		case repo.IsPrivate != nil && !*repo.IsPrivate:
			have, how = levelRead, "public repository"
		}
	}
	need := t.action.level
	if have < need {
		return integration.Denied("%s %s on %s (%s)", id.Display, describeLevel(have, need), t, how), nil
	}
	if t.branch == "" {
		return integration.Allowed("%s %s on %s (%s)", id.Display, describeLevel(have, need), t, how), nil
	}
	return c.cloudBranch(ctx, t, id, have, how)
}

// cloudRestriction is one branch restriction.
type cloudRestriction struct {
	Kind            string      `json:"kind"`
	BranchMatchKind string      `json:"branch_match_kind"`
	BranchType      string      `json:"branch_type"`
	Pattern         string      `json:"pattern"`
	Users           []cloudUser `json:"users"`
	Groups          []struct {
		Slug string `json:"slug"`
	} `json:"groups"`
}

// cloudBranch evaluates the push or merge restrictions on the branch for a
// user who already has write.
func (c *Connection) cloudBranch(ctx context.Context, t target, id integration.Identity, have level, how string) (integration.Decision, error) {
	kind := "push"
	if t.action.branch == "merge" {
		kind = "restrict_merges"
	}
	var matching []cloudRestriction
	var unsupported []string
	path := "/2.0/repositories/" + httpx.PathEscape(c.workspace) + "/" + httpx.PathEscape(t.repo) + "/branch-restrictions"
	err := c.cloudList(ctx, path, url.Values{"kind": {kind}, "pagelen": {"100"}}, func(values []json.RawMessage) error {
		return decodeEach(values, func(r cloudRestriction) {
			if r.Kind != kind {
				return
			}
			switch r.BranchMatchKind {
			case "branching_model":
				// Which branches are "production" or "release" is the
				// repository's branching model, which hallpass does not read.
				unsupported = append(unsupported, "branching model "+r.BranchType)
			default:
				matched, ok := refMatch(r.Pattern, t.branch, false)
				if !ok {
					unsupported = append(unsupported, "pattern "+strconv.Quote(r.Pattern))
				} else if matched {
					matching = append(matching, r)
				}
			}
		})
	})
	if err != nil {
		if httpx.Status(err) == 404 {
			return integration.UnknownDecision(integration.CodeResourceNotVisible, "the branch restrictions of repository %s are not visible to hallpass", t.repo), nil
		}
		return integration.Decision{}, classify(err, "read the branch restrictions")
	}
	verb := "push to"
	if kind != "push" {
		verb = "merge into"
	}
	for _, r := range matching {
		exempt := false
		for _, u := range r.Users {
			if sameUser(u, id) {
				exempt = true
			}
		}
		if exempt {
			continue
		}
		if len(r.Groups) > 0 {
			var slugs []string
			for _, g := range r.Groups {
				slugs = append(slugs, g.Slug)
			}
			return integration.Unsupported("a %s restriction on %s matches %s and exempts group %s, whose members Bitbucket Cloud does not tell hallpass; %s is not exempted by name", kind, strconv.Quote(r.Pattern), t.branch, strings.Join(slugs, ", "), id.Display), nil
		}
		return integration.Denied("a %s restriction on %s stops %s from %s %s (only the listed users may)", kind, strconv.Quote(r.Pattern), id.Display, verb, t.branch), nil
	}
	if len(unsupported) > 0 {
		return integration.Unsupported("%s restrictions on %s use %s, which hallpass cannot evaluate for branch %s", kind, t.repo, strings.Join(unsupported, ", "), t.branch), nil
	}
	return integration.Allowed("%s %s on %s (%s) and no %s restriction stops %s", id.Display, describeLevel(have, t.action.level), t, how, kind, t.branch), nil
}

// --- probe ------------------------------------------------------------------

func (c *Connection) cloudProbe(ctx context.Context) (integration.ProbeResult, error) {
	var ws struct {
		Slug string `json:"slug"`
	}
	if err := c.getJSON(ctx, "/2.0/workspaces/"+httpx.PathEscape(c.workspace), nil, &ws); err != nil {
		if httpx.Status(err) == 404 {
			return integration.ProbeResult{}, integration.Wrap(integration.CodeCredentialRejected, err, "workspace %s is not visible to hallpass's token", c.workspace)
		}
		return integration.ProbeResult{}, classify(err, "read the workspace")
	}
	var page cloudPage[struct{}]
	q := url.Values{"q": {`user.email IN ("probe@example.invalid")`}, "fields": {"values.user.email,values.user.account_id"}}
	if err := c.getJSON(ctx, "/2.0/workspaces/"+httpx.PathEscape(c.workspace)+"/members", q, &page); err != nil {
		if st := httpx.Status(err); st == 401 || st == 403 || st == 400 {
			return integration.ProbeResult{}, integration.Wrap(integration.CodeCredentialRejected, err, "the token cannot filter workspace members by email (HTTP %d); it must be a workspace access token or belong to a workspace administrator", st)
		}
		return integration.ProbeResult{}, classify(err, "filter members by email")
	}
	res := integration.ProbeResult{Summary: fmt.Sprintf("workspace %s: members can be looked up by email", ws.Slug)}
	res.Warnings = append(res.Warnings,
		"repository permissions and branch restrictions are readable only with admin on the repository (repository:admin scope); repositories the token lacks it on answer unknown",
		"Bitbucket Cloud exposes no group membership: a project or branch grant that comes only through a group answers unknown")
	return res, nil
}
