// Package gitlab checks GitLab project and group permissions.
//
// hallpass resolves the caller's email to a GitLab account (four identity
// modes, see Fields), reads the account's effective membership of the project
// or group with the members/all endpoint, and maps the access level to the
// asked action with an exact level set per action. For repo.push and mr.merge
// it also reads the project's protected-branch rules: on a named branch it
// evaluates them, without one it answers unknown when any exist.
// The token is read-only (read_api) and nothing is written.
package gitlab

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/roee-hersh/hallpass/internal/httpx"
	"github.com/roee-hersh/hallpass/internal/integration"
)

const (
	defaultURL      = "https://gitlab.com"
	defaultTemplate = "{local}"

	modeAdminSearch     = "admin_search"
	modeEnterpriseUsers = "enterprise_users"
	modeSAML            = "saml"
	modeTemplate        = "template"

	// searchPerPage and searchMaxPages bound the admin_search listing: a
	// search that fills searchMaxPages pages without an exact match answers
	// unknown rather than user_not_found.
	searchPerPage  = 100
	searchMaxPages = 5
)

// inactiveStates are the account states GitLab uses for accounts that may
// not sign in. Any other non-active state is not evaluable.
var inactiveStates = map[string]bool{
	"blocked":                  true,
	"deactivated":              true,
	"ldap_blocked":             true,
	"banned":                   true,
	"blocked_pending_approval": true,
}

// Integration is the gitlab product.
type Integration struct{}

// Name is "gitlab".
func (Integration) Name() string { return "gitlab" }

// Fields of a gitlab connection.
func (Integration) Fields() []integration.Field {
	u := integration.URLField(false, "GitLab URL, default https://gitlab.com; the API is used at {url}/api/v4")
	u.Default = defaultURL
	return []integration.Field{
		u,
		integration.CredentialField(true, "personal access token with the read_api scope: an administrator's on self-managed, a top-level group Owner's on GitLab.com"),
		{Name: "identity_mode", Default: modeAdminSearch,
			Enum:        []string{modeAdminSearch, modeEnterpriseUsers, modeSAML, modeTemplate},
			Description: "how the email is mapped to an account: admin_search (GET /users?search, needs an administrator's token), enterprise_users (GitLab.com enterprise users of the group), saml (the group's SAML identities, NameID must be the email), template (username derived with username_template)"},
		{Name: "group", Validate: validateGroup,
			Description: "top-level group path; required for identity_mode enterprise_users and saml"},
		{Name: "username_template", Default: defaultTemplate, Validate: integration.ValidateTemplate,
			Description: "username derivation for identity_mode template: placeholders {email}, {local}, {domain}, default {local}"},
		{Name: "email_domains", Validate: integration.ValidateEmailDomains,
			Description: "comma-separated email domains (acme.com,acme.io) whose users may be mapped by identity_mode template; required in that mode, any other domain answers unknown"},
	}
}

func validateGroup(v string) error {
	if v == "" {
		return nil
	}
	return validatePath(v)
}

// New builds a connection. It does not touch the network.
func (Integration) New(_ context.Context, s *integration.Settings, d integration.Deps) (integration.Connection, error) {
	hc, err := d.HTTPClient(s)
	if err != nil {
		return nil, err
	}
	cred := s.Secret("credential")
	if cred.IsZero() {
		return nil, errors.New("credential is required")
	}
	mode := s.Get("identity_mode")
	if mode == "" {
		mode = modeAdminSearch
	}
	switch mode {
	case modeAdminSearch, modeEnterpriseUsers, modeSAML, modeTemplate:
	default:
		return nil, fmt.Errorf("identity_mode %q is not one of admin_search, enterprise_users, saml, template", mode)
	}
	group := s.Get("group")
	if (mode == modeEnterpriseUsers || mode == modeSAML) && group == "" {
		return nil, fmt.Errorf("group is required when identity_mode is %s", mode)
	}
	if err := validateGroup(group); err != nil {
		return nil, fmt.Errorf("group: %w", err)
	}
	tplText := s.Get("username_template")
	if tplText == "" {
		tplText = defaultTemplate
	}
	tpl, err := integration.ParseTemplate(tplText)
	if err != nil {
		return nil, fmt.Errorf("username_template: %w", err)
	}
	var domains map[string]bool
	if raw := s.Get("email_domains"); raw != "" {
		list, err := integration.ParseEmailDomains(raw)
		if err != nil {
			return nil, fmt.Errorf("email_domains: %w", err)
		}
		domains = make(map[string]bool, len(list))
		for _, d := range list {
			domains[d] = true
		}
	}
	if mode == modeTemplate && len(domains) == 0 {
		return nil, errors.New("email_domains is required when identity_mode is template: the template maps any email's local part to an account, so the domains that may be mapped must be listed")
	}
	base := s.Get("url")
	if base == "" {
		base = defaultURL
	}
	c := &Connection{
		mode:     mode,
		group:    group,
		template: tpl,
		domains:  domains,
		now:      d.Now,
	}
	if c.now == nil {
		c.now = time.Now
	}
	c.client = &httpx.Client{
		HTTP:   hc,
		Base:   strings.TrimRight(base, "/") + "/api/v4",
		Logger: d.Logger,
		Auth:   httpx.HeaderAuth("PRIVATE-TOKEN", func(context.Context) (string, error) { return cred.GetString() }),
	}
	return c, nil
}

// Connection is one GitLab instance (gitlab.com or self-managed).
type Connection struct {
	client   *httpx.Client
	mode     string
	group    string
	template integration.Template
	// domains is the email_domains allow-list (template mode), lowercase.
	domains map[string]bool
	now     func() time.Time
}

// user is the subset of a GitLab user record hallpass reads. email,
// is_admin, external and emails are present only for administrators' tokens.
type user struct {
	ID          int64  `json:"id"`
	Username    string `json:"username"`
	State       string `json:"state"`
	Email       string `json:"email"`
	PublicEmail string `json:"public_email"`
	Bot         bool   `json:"bot"`
	IsAdmin     *bool  `json:"is_admin"`
	External    *bool  `json:"external"`
	// Emails are the account's secondary emails.
	// UNVERIFIED: that a user record of the search listing carries an
	// "emails" array, and its shape; both a bare string and an object with
	// "email" and "confirmed_at" are accepted.
	Emails []secondaryEmail `json:"emails"`
}

// secondaryEmail is one entry of a user's emails array. confirmed reports
// whether the entry may be trusted: true when confirmed_at is absent or
// non-null, false when it is present and null.
type secondaryEmail struct {
	email     string
	confirmed bool
}

func (e *secondaryEmail) UnmarshalJSON(b []byte) error {
	var str string
	if err := json.Unmarshal(b, &str); err == nil {
		*e = secondaryEmail{email: str, confirmed: true}
		return nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(b, &obj); err != nil {
		return err
	}
	out := secondaryEmail{confirmed: true}
	if raw, ok := obj["email"]; ok {
		if err := json.Unmarshal(raw, &out.email); err != nil {
			return fmt.Errorf("emails[].email: %w", err)
		}
	}
	if raw, ok := obj["confirmed_at"]; ok && string(raw) == "null" {
		out.confirmed = false
	}
	*e = out
	return nil
}

func (u user) identity() integration.Identity {
	attrs := map[string]string{
		"state":    u.State,
		"username": u.Username,
		"bot":      strconv.FormatBool(u.Bot),
	}
	if u.IsAdmin != nil {
		attrs["is_admin"] = strconv.FormatBool(*u.IsAdmin)
	}
	if u.External != nil {
		attrs["external"] = strconv.FormatBool(*u.External)
	}
	return integration.Identity{ID: strconv.FormatInt(u.ID, 10), Display: u.Username, Attrs: attrs}
}

// domainAllowed reports whether the email's domain is in email_domains.
func (c *Connection) domainAllowed(email string) bool {
	d := integration.EmailDomain(email)
	return d != "" && c.domains[d]
}

// Username applies the template to an email (identity_mode template).
func (c *Connection) Username(email string) string { return c.template.Render(email) }

// ResolveIdentity maps the email to a GitLab account by the configured mode.
func (c *Connection) ResolveIdentity(ctx context.Context, u integration.User) (integration.Identity, error) {
	email := strings.TrimSpace(u.Email)
	if email == "" || strings.ContainsAny(email, " \t\r\n") {
		return integration.Identity{}, integration.Errorf(integration.CodeInvalidRequest, "email is empty or contains whitespace")
	}
	var (
		found user
		err   error
	)
	switch c.mode {
	case modeAdminSearch:
		found, err = c.adminSearch(ctx, email)
	case modeEnterpriseUsers:
		found, err = c.enterpriseUser(ctx, email)
	case modeSAML:
		found, err = c.samlIdentity(ctx, email)
	case modeTemplate:
		if !c.domainAllowed(email) {
			return integration.Identity{}, integration.Errorf(integration.CodeUnsupported, "domain not allowed for template identities: %s is not in email_domains", email)
		}
		found, err = c.byUsername(ctx, c.Username(email))
		// The template only guesses a username; when the account's email is
		// visible it must be the caller's, else the guess is wrong.
		if err == nil && found.Email != "" && !strings.EqualFold(found.Email, email) {
			err = integration.UserNotFound("the account %s derived from %s has a different email", found.Username, email)
		}
	default:
		return integration.Identity{}, fmt.Errorf("unreachable: identity_mode %q", c.mode)
	}
	if err != nil {
		return integration.Identity{}, err
	}
	return found.identity(), nil
}

// adminSearch lists GET /users?search=<email> page by page (searchPerPage
// per page, at most searchMaxPages pages) and picks the exact match. The
// search is fuzzy on GitLab's side, so a common local part can return more
// candidates than hallpass will read; then the answer is unknown.
func (c *Connection) adminSearch(ctx context.Context, email string) (user, error) {
	var users []user
	full := true
	for page := 1; page <= searchMaxPages && full; page++ {
		var batch []user
		q := url.Values{"search": {email}, "per_page": {strconv.Itoa(searchPerPage)}, "page": {strconv.Itoa(page)}}
		if _, err := c.client.GetJSON(ctx, "/users", q, &batch); err != nil {
			return user{}, c.classify(err, "search users")
		}
		users = append(users, batch...)
		full = len(batch) >= searchPerPage
	}
	found, err := matchEmail(users, email, "the token's user is not an administrator, so private emails are not searchable; use an administrator's token or another identity_mode")
	if err != nil && full && integration.ToDecision(err).Code == integration.CodeUserNotFound {
		return user{}, integration.Errorf(integration.CodeUnsupported, "too many candidates: the search for %s filled %d pages of %d users without an exact match", email, searchMaxPages, searchPerPage)
	}
	return found, err
}

func (c *Connection) enterpriseUser(ctx context.Context, email string) (user, error) {
	var users []user
	path := "/groups/" + httpx.PathEscape(c.group) + "/enterprise_users"
	if _, err := c.client.GetJSON(ctx, path, url.Values{"search": {email}, "per_page": {"100"}}, &users); err != nil {
		return user{}, c.classifyGroup(err, "list enterprise users of")
	}
	return matchEmail(users, email, "the enterprise users of group "+c.group+" carry no email; the token must belong to an Owner of the group")
}

// matchEmail picks the one user whose email (or, absent that, public_email)
// or one of whose confirmed secondary emails equals the searched email,
// ignoring case. Never a substring match.
func matchEmail(users []user, email, noEmailHint string) (user, error) {
	var matches []user
	comparable := false
	for _, u := range users {
		e := u.Email
		if e == "" {
			e = u.PublicEmail
		}
		matched := false
		if e != "" {
			comparable = true
			matched = strings.EqualFold(e, email)
		}
		for _, sec := range u.Emails {
			if sec.email == "" {
				continue
			}
			comparable = true
			if sec.confirmed && strings.EqualFold(sec.email, email) {
				matched = true
			}
		}
		if matched {
			matches = append(matches, u)
		}
	}
	switch {
	case len(matches) == 1:
		return matches[0], nil
	case len(matches) > 1:
		return user{}, integration.UserAmbiguous("%d GitLab accounts have the email %s", len(matches), email)
	case len(users) > 0 && !comparable:
		return user{}, integration.Errorf(integration.CodeUnsupported, "%s", noEmailHint)
	}
	return user{}, integration.UserNotFound("no GitLab account has the email %s", email)
}

type samlIdentity struct {
	ExternUID string `json:"extern_uid"`
	UserID    int64  `json:"user_id"`
}

func (c *Connection) samlIdentity(ctx context.Context, email string) (user, error) {
	var matches []int64
	req := &httpx.Request{Method: http.MethodGet, Path: "/groups/" + httpx.PathEscape(c.group) + "/saml/identities", Query: url.Values{"per_page": {"100"}}}
	err := c.client.Paginate(ctx, req, func(resp *httpx.Response) (*httpx.Request, error) {
		var page []samlIdentity
		if err := resp.JSON(&page); err != nil {
			return nil, fmt.Errorf("decode saml identities: %w", err)
		}
		for _, id := range page {
			if strings.EqualFold(id.ExternUID, email) {
				matches = append(matches, id.UserID)
			}
		}
		next, err := c.client.NextLink(resp.Header)
		if err != nil {
			return nil, integration.Wrap(integration.CodeUpstreamError, err, "GitLab returned a next page link outside the connection's url")
		}
		if next != "" {
			return &httpx.Request{Method: http.MethodGet, Path: next}, nil
		}
		return nil, nil
	})
	if err != nil {
		return user{}, c.classifyGroup(err, "list SAML identities of")
	}
	switch {
	case len(matches) == 0:
		return user{}, integration.UserNotFound("no SAML identity in group %s has the NameID %s", c.group, email)
	case len(matches) > 1:
		return user{}, integration.UserAmbiguous("%d SAML identities in group %s have the NameID %s", len(matches), c.group, email)
	}
	var u user
	if _, err := c.client.GetJSON(ctx, "/users/"+strconv.FormatInt(matches[0], 10), nil, &u); err != nil {
		if httpx.Status(err) == 404 {
			return user{}, integration.UserNotFound("SAML identity %s points at user %d, which no longer exists", email, matches[0])
		}
		return user{}, c.classify(err, "read user")
	}
	return u, nil
}

func (c *Connection) byUsername(ctx context.Context, username string) (user, error) {
	var users []user
	if _, err := c.client.GetJSON(ctx, "/users", url.Values{"username": {username}}, &users); err != nil {
		return user{}, c.classify(err, "look up username")
	}
	switch {
	case len(users) == 0:
		return user{}, integration.UserNotFound("no GitLab account has the username %s", username)
	case len(users) > 1:
		return user{}, integration.UserAmbiguous("%d GitLab accounts have the username %s", len(users), username)
	}
	return users[0], nil
}

// classify maps an error from a call the token should always be allowed to
// make. 403 means the token lacks the right.
func (c *Connection) classify(err error, what string) error {
	if httpx.Status(err) == 403 {
		return integration.Wrap(integration.CodeCredentialRejected, err, "the token may not %s (HTTP 403)", what)
	}
	return httpx.Classify(err)
}

// classifyGroup maps an error from a group-scoped identity call.
func (c *Connection) classifyGroup(err error, what string) error {
	switch httpx.Status(err) {
	case 403:
		return integration.Wrap(integration.CodeCredentialRejected, err, "the token may not %s group %s (HTTP 403); it must belong to an Owner of the group", what, c.group)
	case 404:
		return integration.Wrap(integration.CodeResourceNotVisible, err, "group %s is not visible to the token (HTTP 404)", c.group)
	}
	return httpx.Classify(err)
}

// membership is the effective membership of a user in a project or group.
type membership struct {
	found bool
	level int
	state string
	// customRole is the custom role name when the membership has one.
	customRole   string
	customRoleID int64
}

type memberRecord struct {
	AccessLevel int    `json:"access_level"`
	State       string `json:"state"`
	MemberRole  *struct {
		ID   int64  `json:"id"`
		Name string `json:"name"`
	} `json:"member_role"`
}

// member reads GET /<projects|groups>/:id/members/all/:user_id.
// 404 means "not a member", or that the project or group is not visible;
// the caller tells the two apart by reading the record (see read).
func (c *Connection) member(ctx context.Context, scope, id, userID string) (membership, error) {
	path := "/" + scope + "s/" + httpx.PathEscape(id) + "/members/all/" + httpx.PathEscape(userID)
	var rec memberRecord
	if _, err := c.client.GetJSON(ctx, path, nil, &rec); err != nil {
		switch httpx.Status(err) {
		case 404:
			return membership{}, nil
		case 403:
			return membership{}, integration.Wrap(integration.CodeCredentialRejected, err, "the token may not read the members of %s %s (HTTP 403)", scope, id)
		}
		return membership{}, httpx.Classify(err)
	}
	m := membership{found: true, level: rec.AccessLevel, state: rec.State}
	if rec.MemberRole != nil {
		m.customRole, m.customRoleID = rec.MemberRole.Name, rec.MemberRole.ID
		if m.customRole == "" {
			m.customRole = "id " + strconv.FormatInt(rec.MemberRole.ID, 10)
		}
	}
	return m, nil
}

// resource is what hallpass reads of a project or group record.
type resource struct {
	Visibility string `json:"visibility"`
	// IssuesAccessLevel is "disabled", "private" or "enabled" on projects.
	IssuesAccessLevel string `json:"issues_access_level"`
	// IssuesEnabled is the older boolean form of the same setting.
	IssuesEnabled *bool `json:"issues_enabled"`
}

// issuesDisabled reports whether the project has the issues feature off.
func (r resource) issuesDisabled() bool {
	return r.IssuesAccessLevel == "disabled" || (r.IssuesEnabled != nil && !*r.IssuesEnabled)
}

// read reads the project or group record. A 404 means the token cannot see
// it.
func (c *Connection) read(ctx context.Context, t target) (resource, error) {
	var out resource
	if _, err := c.client.GetJSON(ctx, "/"+t.scope+"s/"+httpx.PathEscape(t.id), nil, &out); err != nil {
		switch httpx.Status(err) {
		case 404:
			return resource{}, integration.Wrap(integration.CodeResourceNotVisible, err, "%s %s is not visible to the token (HTTP 404)", t.scope, t.id)
		case 403:
			return resource{}, integration.Wrap(integration.CodeCredentialRejected, err, "the token may not read %s %s (HTTP 403)", t.scope, t.id)
		}
		return resource{}, httpx.Classify(err)
	}
	return out, nil
}

// Check evaluates one action against the user's effective access level.
func (c *Connection) Check(ctx context.Context, r integration.CheckRequest) (integration.Decision, error) {
	spec, ok := actions[r.Action.Name]
	if !ok {
		return integration.Decision{}, integration.Errorf(integration.CodeUnknownAction, "gitlab has no action %q", r.Action.Name)
	}
	t, err := parseTarget(spec, r.Resource)
	if err != nil {
		return integration.Decision{}, integration.Errorf(integration.CodeInvalidRequest, "%v", err)
	}
	who := r.Identity.Display
	if who == "" {
		who = "user " + r.Identity.ID
	}
	switch state := r.Identity.Attr("state"); {
	case state == "active":
	case state == "":
		return integration.Unsupported("GitLab account %s has no state in the record the token can see", who), nil
	case inactiveStates[state]:
		return integration.Denied("GitLab account %s is %s", who, state), nil
	default:
		return integration.Unsupported("GitLab account %s is in state %q, which hallpass does not know", who, state), nil
	}
	if r.Identity.Attr("bot") == "true" {
		return integration.Denied("GitLab account %s is a bot account", who), nil
	}

	m, err := c.member(ctx, t.scope, t.id, r.Identity.ID)
	if err != nil {
		return integration.Decision{}, err
	}
	if !m.found {
		return c.checkNonMember(ctx, spec, t, r.Identity, who)
	}
	if m.state != "active" && m.state != "" {
		return integration.Denied("the membership of %s in %s %s is %s", who, t.scope, t.id, m.state), nil
	}
	role := levelName(m.level)
	if m.customRole != "" {
		role = fmt.Sprintf("custom role %q (base %s)", m.customRole, levelName(m.level))
	}

	if spec.branch != "" {
		rules, err := c.protectedBranches(ctx, t)
		if err != nil {
			return integration.Decision{}, err
		}
		if t.branch == "" && len(rules) > 0 {
			// The level alone cannot answer: a protected branch may restrict
			// (Maintainers only) or widen (a named user) what the level says.
			return integration.Unsupported("project %s has %d protected-branch rules, which decide %s per branch; add @branch to the resource", t.id, len(rules), spec.name), nil
		}
		var matched []protectedBranch
		for _, pb := range rules {
			if matchWildcard(pb.Name, t.branch) {
				matched = append(matched, pb)
			}
		}
		if len(matched) > 0 {
			return c.checkProtected(ctx, r, spec, t, m, matched, who, role), nil
		}
	}

	switch {
	case spec.grants(m.level):
		return integration.Allowed("%s has %s access to %s %s, which grants %s", who, role, t.scope, t.id, spec.name), nil
	case spec.isConditional(m.level):
		return integration.Unsupported("%s has %s access to %s %s; at that level %s depends on approval rules hallpass does not evaluate", who, role, t.scope, t.id, spec.name), nil
	case m.customRole != "":
		return integration.Unsupported("%s has %s on %s %s; the base level does not grant %s but a custom role can add abilities hallpass cannot see", who, role, t.scope, t.id, spec.name), nil
	}
	return integration.Denied("%s has %s access to %s %s; %s needs %s", who, role, t.scope, t.id, spec.name, levelNames(spec.levels)), nil
}

// checkNonMember answers for an account with no membership of the project
// or group: administrators, the project's visibility and its issue settings
// decide.
func (c *Connection) checkNonMember(ctx context.Context, spec actionSpec, t target, id integration.Identity, who string) (integration.Decision, error) {
	res, err := c.read(ctx, t)
	if err != nil {
		return integration.Decision{}, err
	}
	vis := res.Visibility
	if spec.name == "issue.create" && res.issuesDisabled() {
		return integration.Denied("issues are disabled on project %s, so no one can create one", t.id), nil
	}
	if id.Attr("is_admin") == "true" {
		return integration.Allowed("%s is an instance administrator, which grants %s on every %s", who, spec.name, t.scope), nil
	}
	if spec.name == "issue.create" && res.IssuesAccessLevel == "private" {
		return integration.Denied("%s is not a member of project %s and its issues are restricted to project members", who, t.id), nil
	}
	if spec.grantsNonMember(vis) {
		if vis == "internal" {
			// External users cannot see internal projects.
			switch id.Attr("external") {
			case "true":
				return integration.Denied("%s is not a member of %s %s, and as an external user cannot see %s projects", who, t.scope, t.id, vis), nil
			case "false":
			default:
				return integration.Unsupported("%s is not a member of %s %s; the %s is %s, which external users cannot see, and the token cannot tell whether the account is external", who, t.scope, t.id, t.scope, vis), nil
			}
		}
		return integration.Allowed("%s is not a member of %s %s, but the %s is %s and %s is open to every signed-in user", who, t.scope, t.id, t.scope, vis, spec.name), nil
	}
	return integration.Denied("%s is not a member of %s %s (%s); %s needs %s", who, t.scope, t.id, vis, spec.name, levelNames(spec.levels)), nil
}

// accessEntry is one "allowed to push/merge" entry of a protected branch.
type accessEntry struct {
	AccessLevel  int   `json:"access_level"`
	UserID       int64 `json:"user_id"`
	GroupID      int64 `json:"group_id"`
	MemberRoleID int64 `json:"member_role_id"`
	DeployKeyID  int64 `json:"deploy_key_id"`
}

type protectedBranch struct {
	Name              string        `json:"name"`
	PushAccessLevels  []accessEntry `json:"push_access_levels"`
	MergeAccessLevels []accessEntry `json:"merge_access_levels"`
}

// protectedBranches lists the project's protected-branch rules.
func (c *Connection) protectedBranches(ctx context.Context, t target) ([]protectedBranch, error) {
	var out []protectedBranch
	req := &httpx.Request{Method: http.MethodGet, Path: "/projects/" + httpx.PathEscape(t.id) + "/protected_branches", Query: url.Values{"per_page": {"100"}}}
	err := c.client.Paginate(ctx, req, func(resp *httpx.Response) (*httpx.Request, error) {
		var page []protectedBranch
		if err := resp.JSON(&page); err != nil {
			return nil, fmt.Errorf("decode protected branches: %w", err)
		}
		out = append(out, page...)
		next, err := c.client.NextLink(resp.Header)
		if err != nil {
			return nil, integration.Wrap(integration.CodeUpstreamError, err, "GitLab returned a next page link outside the connection's url")
		}
		if next != "" {
			return &httpx.Request{Method: http.MethodGet, Path: next}, nil
		}
		return nil, nil
	})
	if err != nil {
		switch httpx.Status(err) {
		case 403:
			// UNVERIFIED: the minimum role needed to list protected branches.
			return nil, integration.Wrap(integration.CodeCredentialRejected, err, "the token may not list the protected branches of project %s (HTTP 403)", t.id)
		case 404:
			return nil, integration.Wrap(integration.CodeResourceNotVisible, err, "project %s is not visible to the token (HTTP 404)", t.id)
		}
		return nil, httpx.Classify(err)
	}
	return out, nil
}

// checkProtected evaluates the matching protected-branch rules. An entry
// allows the user when it names the user, a group the user belongs to, a
// role level the user's level reaches, or Admins for a known administrator.
// The most permissive entry wins across every matching rule.
// UNVERIFIED: how GitLab combines several rules matching one branch; every
// matching rule's entries are pooled here.
func (c *Connection) checkProtected(ctx context.Context, r integration.CheckRequest, spec actionSpec, t target, m membership, rules []protectedBranch, who, role string) integration.Decision {
	userID, _ := strconv.ParseInt(r.Identity.ID, 10, 64)
	var entries []accessEntry
	var names []string
	for _, pb := range rules {
		names = append(names, pb.Name)
		if spec.branch == branchPush {
			entries = append(entries, pb.PushAccessLevels...)
		} else {
			entries = append(entries, pb.MergeAccessLevels...)
		}
	}
	rule := fmt.Sprintf("protected branch rule %s of project %s", strings.Join(names, ", "), t.id)
	verb := "push to"
	if spec.branch == branchMerge {
		verb = "merge into"
	}
	anyone := false
	var unresolved []string
	for _, e := range entries {
		switch {
		case e.DeployKeyID != 0:
			// A deploy key may push, but it is never the user; the entry's
			// access_level describes the key, not a role.
			anyone = true
		case e.UserID != 0:
			anyone = true
			if e.UserID == userID {
				return integration.Allowed("%s may %s branch %s: %s names the user", who, verb, t.branch, rule)
			}
		case e.GroupID != 0:
			anyone = true
			in, err := c.groupHas(ctx, e.GroupID, r.Identity.ID)
			if err != nil {
				unresolved = append(unresolved, fmt.Sprintf("group %d could not be resolved", e.GroupID))
				continue
			}
			if in {
				return integration.Allowed("%s may %s branch %s: %s names group %d, which the user belongs to", who, verb, t.branch, rule, e.GroupID)
			}
		case e.MemberRoleID != 0:
			// UNVERIFIED: an entry naming a custom role is taken to match a
			// member holding that exact custom role.
			anyone = true
			if m.customRoleID == e.MemberRoleID {
				return integration.Allowed("%s may %s branch %s: %s names the user's custom role", who, verb, t.branch, rule)
			}
			unresolved = append(unresolved, fmt.Sprintf("custom role %d is not the user's", e.MemberRoleID))
		case e.AccessLevel == levelNone:
			// "No one".
		case e.AccessLevel == levelAdmin:
			anyone = true
			switch r.Identity.Attr("is_admin") {
			case "true":
				return integration.Allowed("%s may %s branch %s: %s allows administrators", who, verb, t.branch, rule)
			case "false":
			default:
				unresolved = append(unresolved, "the rule allows administrators and the user's administrator status is unknown")
			}
		default:
			anyone = true
			if m.level >= e.AccessLevel && m.level >= levelDeveloper {
				return integration.Allowed("%s may %s branch %s: %s allows %s and up, and the user has %s access", who, verb, t.branch, rule, levelName(e.AccessLevel), role)
			}
		}
	}
	if !anyone {
		return integration.Denied("no one may %s branch %s: %s allows no one", verb, t.branch, rule)
	}
	if len(unresolved) > 0 {
		return integration.Unsupported("%s is not clearly allowed to %s branch %s by %s: %s", who, verb, t.branch, rule, strings.Join(unresolved, "; "))
	}
	if m.customRole != "" {
		return integration.Unsupported("%s has %s on project %s; no entry of %s matches the base level but a custom role can add abilities hallpass cannot see", who, role, t.id, rule)
	}
	return integration.Denied("%s has %s access to project %s, and no entry of %s allows that user to %s branch %s", who, role, t.id, rule, verb, t.branch)
}

// groupHas reports whether the user is a member of the group (200), is not
// (404), or could not be resolved (any other failure).
func (c *Connection) groupHas(ctx context.Context, groupID int64, userID string) (bool, error) {
	path := "/groups/" + strconv.FormatInt(groupID, 10) + "/members/all/" + httpx.PathEscape(userID)
	var rec memberRecord
	if _, err := c.client.GetJSON(ctx, path, nil, &rec); err != nil {
		if httpx.Status(err) == 404 {
			return false, nil
		}
		return false, err
	}
	return rec.State == "" || rec.State == "active", nil
}

// Probe verifies the token, reports whose it is and warns about scopes.
func (c *Connection) Probe(ctx context.Context) (integration.ProbeResult, error) {
	var me user
	if _, err := c.client.GetJSON(ctx, "/user", nil, &me); err != nil {
		return integration.ProbeResult{}, c.classify(err, "read its own user")
	}
	res := integration.ProbeResult{}
	summary := "authenticated as " + me.Username
	isAdmin := me.IsAdmin != nil && *me.IsAdmin
	if isAdmin {
		summary += " (administrator)"
	}
	if me.Bot {
		summary += " (bot)"
	}
	if c.mode == modeAdminSearch && !isAdmin {
		res.Warnings = append(res.Warnings, "identity_mode admin_search needs an administrator's token: this token's user is not an administrator, so private emails are not searchable and most users will answer user_not_found")
	}

	// UNVERIFIED: the path /personal_access_tokens/self.
	var tok struct {
		Scopes    []string `json:"scopes"`
		ExpiresAt string   `json:"expires_at"`
		Active    *bool    `json:"active"`
	}
	if _, err := c.client.GetJSON(ctx, "/personal_access_tokens/self", nil, &tok); err != nil {
		switch httpx.Status(err) {
		case 403, 404:
			res.Warnings = append(res.Warnings, "could not verify the token's scopes (the token endpoint answered HTTP "+strconv.Itoa(httpx.Status(err))+"); make sure it has read_api and nothing broader")
		default:
			return integration.ProbeResult{}, c.classify(err, "read its own token")
		}
	} else {
		scopes := map[string]bool{}
		for _, s := range tok.Scopes {
			scopes[s] = true
		}
		if !scopes["read_api"] && !scopes["api"] {
			res.Warnings = append(res.Warnings, "the token lacks the read_api scope; API calls will be refused")
		}
		var broad []string
		for _, s := range []string{"api", "write_repository", "sudo", "admin_mode", "write_registry", "create_runner", "manage_runner"} {
			if scopes[s] {
				broad = append(broad, s)
			}
		}
		if len(broad) > 0 {
			res.Warnings = append(res.Warnings, "the token has scopes broader than read_api ("+strings.Join(broad, ", ")+"); hallpass only reads")
		}
		if tok.ExpiresAt != "" {
			if exp, err := time.Parse("2006-01-02", tok.ExpiresAt); err == nil {
				if left := exp.Sub(c.now()); left < 14*24*time.Hour {
					res.Warnings = append(res.Warnings, "the token expires on "+tok.ExpiresAt)
				}
			}
		}
	}

	if c.group != "" {
		var g struct {
			FullPath string `json:"full_path"`
		}
		if _, err := c.client.GetJSON(ctx, "/groups/"+httpx.PathEscape(c.group), nil, &g); err != nil {
			return integration.ProbeResult{}, c.classifyGroup(err, "read")
		}
		summary += ", group " + c.group + " visible"
	}
	res.Summary = summary
	return res, nil
}
