// Package gitlab checks GitLab project and group permissions.
//
// hallpass resolves the caller's email to a GitLab account (four identity
// modes, see Fields), reads the account's effective membership of the project
// or group with the members/all endpoint, and maps the access level to the
// asked action with an exact level set per action. For repo.push and mr.merge
// on a named branch it also evaluates the project's protected-branch rules.
// The token is read-only (read_api) and nothing is written.
package gitlab

import (
	"context"
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
)

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
		{Name: "username_template", Default: defaultTemplate, Validate: validateTemplate,
			Description: "username derivation for identity_mode template: placeholders {email}, {local}, {domain}, default {local}"},
	}
}

func validateGroup(v string) error {
	if v == "" {
		return nil
	}
	return validatePath(v)
}

func validateTemplate(v string) error {
	if !strings.Contains(v, "{email}") && !strings.Contains(v, "{local}") {
		return errors.New("must contain {email} or {local}, otherwise every user gets the same username")
	}
	for _, ph := range placeholders(v) {
		switch ph {
		case "email", "local", "domain":
		default:
			return fmt.Errorf("unknown placeholder {%s}; use {email}, {local} or {domain}", ph)
		}
	}
	return nil
}

func placeholders(tpl string) []string {
	var out []string
	for {
		i := strings.Index(tpl, "{")
		if i < 0 {
			return out
		}
		j := strings.Index(tpl[i:], "}")
		if j < 0 {
			return out
		}
		out = append(out, tpl[i+1:i+j])
		tpl = tpl[i+j+1:]
	}
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
	tpl := s.Get("username_template")
	if tpl == "" {
		tpl = defaultTemplate
	}
	if err := validateTemplate(tpl); err != nil {
		return nil, fmt.Errorf("username_template: %w", err)
	}
	base := s.Get("url")
	if base == "" {
		base = defaultURL
	}
	c := &Connection{
		mode:     mode,
		group:    group,
		template: tpl,
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
	template string
	now      func() time.Time
}

// user is the subset of a GitLab user record hallpass reads. email and
// is_admin are present only for administrators' tokens.
type user struct {
	ID          int64  `json:"id"`
	Username    string `json:"username"`
	State       string `json:"state"`
	Email       string `json:"email"`
	PublicEmail string `json:"public_email"`
	Bot         bool   `json:"bot"`
	IsAdmin     *bool  `json:"is_admin"`
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
	return integration.Identity{ID: strconv.FormatInt(u.ID, 10), Display: u.Username, Attrs: attrs}
}

// Username applies the template to an email (identity_mode template).
func (c *Connection) Username(email string) string {
	local, domain, _ := strings.Cut(email, "@")
	r := strings.NewReplacer("{email}", email, "{local}", local, "{domain}", domain)
	return r.Replace(c.template)
}

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
		found, err = c.byUsername(ctx, c.Username(email))
	default:
		return integration.Identity{}, fmt.Errorf("unreachable: identity_mode %q", c.mode)
	}
	if err != nil {
		return integration.Identity{}, err
	}
	return found.identity(), nil
}

func (c *Connection) adminSearch(ctx context.Context, email string) (user, error) {
	var users []user
	if _, err := c.client.GetJSON(ctx, "/users", url.Values{"search": {email}, "per_page": {"100"}}, &users); err != nil {
		return user{}, c.classify(err, "search users")
	}
	return matchEmail(users, email, "the token's user is not an administrator, so private emails are not searchable; use an administrator's token or another identity_mode")
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
// equals the searched email, ignoring case.
func matchEmail(users []user, email, noEmailHint string) (user, error) {
	var matches []user
	comparable := false
	for _, u := range users {
		e := u.Email
		if e == "" {
			e = u.PublicEmail
		}
		if e == "" {
			continue
		}
		comparable = true
		if strings.EqualFold(e, email) {
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
		if next := httpx.LinkNext(resp.Header); next != "" {
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
// the caller tells the two apart with visibility.
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

// visibility reads the project or group and returns its visibility. A 404
// means the token cannot see it.
func (c *Connection) visibility(ctx context.Context, t target) (string, error) {
	var out struct {
		Visibility string `json:"visibility"`
	}
	if _, err := c.client.GetJSON(ctx, "/"+t.scope+"s/"+httpx.PathEscape(t.id), nil, &out); err != nil {
		switch httpx.Status(err) {
		case 404:
			return "", integration.Wrap(integration.CodeResourceNotVisible, err, "%s %s is not visible to the token (HTTP 404)", t.scope, t.id)
		case 403:
			return "", integration.Wrap(integration.CodeCredentialRejected, err, "the token may not read %s %s (HTTP 403)", t.scope, t.id)
		}
		return "", httpx.Classify(err)
	}
	return out.Visibility, nil
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
	if state := r.Identity.Attr("state"); state != "active" {
		if state == "" {
			state = "of unknown state"
		}
		return integration.Denied("GitLab account %s is %s", who, state), nil
	}
	if r.Identity.Attr("bot") == "true" {
		return integration.Denied("GitLab account %s is a bot account", who), nil
	}

	m, err := c.member(ctx, t.scope, t.id, r.Identity.ID)
	if err != nil {
		return integration.Decision{}, err
	}
	if !m.found {
		vis, err := c.visibility(ctx, t)
		if err != nil {
			return integration.Decision{}, err
		}
		if spec.grantsNonMember(vis) {
			return integration.Allowed("%s is not a member of %s %s, but the %s is %s and %s is open to every signed-in user", who, t.scope, t.id, t.scope, vis, spec.name), nil
		}
		return integration.Denied("%s is not a member of %s %s (%s); %s needs %s", who, t.scope, t.id, vis, spec.name, levelNames(spec.levels)), nil
	}
	if m.state != "active" && m.state != "" {
		return integration.Denied("the membership of %s in %s %s is %s", who, t.scope, t.id, m.state), nil
	}
	role := levelName(m.level)
	if m.customRole != "" {
		role = fmt.Sprintf("custom role %q (base %s)", m.customRole, levelName(m.level))
	}

	if t.branch != "" && spec.branch != "" {
		rules, err := c.protectedBranches(ctx, t)
		if err != nil {
			return integration.Decision{}, err
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

// accessEntry is one "allowed to push/merge" entry of a protected branch.
type accessEntry struct {
	AccessLevel  int   `json:"access_level"`
	UserID       int64 `json:"user_id"`
	GroupID      int64 `json:"group_id"`
	MemberRoleID int64 `json:"member_role_id"`
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
		if next := httpx.LinkNext(resp.Header); next != "" {
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
