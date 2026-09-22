package aws

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/roee-hersh/hallpass/internal/authx"
	"github.com/roee-hersh/hallpass/internal/integration"
)

// principal is one IAM principal the user may act as.
type principal struct {
	ARN string
	// Kind and Name are for decision texts: "permission set AdminAccess",
	// "role Deployer", "user dana".
	Kind, Name string
}

func (p principal) String() string { return p.Kind + " " + p.Name }

// native is Identity.Native: the candidate principals and, for Identity
// Center, the permission set names and the ones with no provisioned role.
type native struct {
	Principals     []principal
	PermissionSets []string
	// Missing lists assigned permission sets whose AWSReservedSSO role was
	// not found in the account (not yet provisioned, or recreated).
	Missing []string
}

const (
	ssoPathPrefix = "/aws-reserved/sso.amazonaws.com/"
	roleListTTL   = 10 * time.Minute
	roleMapReread = 60 * time.Second
	maxPages      = 50
)

var iamUserNameRe = regexp.MustCompile(`^[\w+=,.@-]{1,64}$`)

// ResolveIdentity maps the email to IAM principals by the configured mode.
// The result is cached by the engine (identity_cache_seconds, keyed by
// email and groups), not here.
func (c *Connection) ResolveIdentity(ctx context.Context, u integration.User) (integration.Identity, error) {
	email := strings.TrimSpace(u.Email)
	if email == "" || !strings.Contains(email, "@") {
		return integration.Identity{}, integration.UserNotFound("%q is not an email address", u.Email)
	}
	switch c.mode {
	case "static_map":
		// The map is re-read every 60 s, so the roles are looked up again in
		// Check from the request's groups rather than carried in the identity.
		arns, err := c.roleMap.lookup(email, u.Groups)
		if err != nil {
			return integration.Identity{}, err
		}
		if len(arns) == 0 {
			return integration.Identity{}, integration.UserNotFound("%s and its groups are not in role_map_file", email)
		}
		return integration.Identity{ID: strings.ToLower(email), Display: email}, nil
	case "iam_user":
		return c.resolveIAMUser(ctx, email)
	default:
		return c.resolveIdentityCenter(ctx, email)
	}
}

// Identity Center

type icUser struct {
	UserID      string `json:"UserId"`
	UserName    string `json:"UserName"`
	DisplayName string `json:"DisplayName"`
	// UNVERIFIED: DescribeUser is not documented to return a status field;
	// when a UserStatus of "DISABLED" is present the user is denied everything.
	UserStatus string `json:"UserStatus"`
}

func (c *Connection) resolveIdentityCenter(ctx context.Context, email string) (integration.Identity, error) {
	userID, err := c.getUserID(ctx, email)
	if err != nil {
		return integration.Identity{}, err
	}
	var user icUser
	if err := c.identityStore.JSON11(ctx, "AWSIdentityStore.DescribeUser", map[string]any{"IdentityStoreId": c.identityStoreID, "UserId": userID}, &user); err != nil {
		return integration.Identity{}, classify(err, "DescribeUser")
	}
	groups, err := c.listGroups(ctx, userID)
	if err != nil {
		return integration.Identity{}, err
	}
	// Assignments for the user and for each group are unioned.
	// UNVERIFIED: whether ListAccountAssignmentsForPrincipal for a USER
	// already includes assignments inherited through groups.
	psSet := map[string]bool{}
	var psARNs []string
	add := func(arns []string) {
		for _, a := range arns {
			if !psSet[a] {
				psSet[a] = true
				psARNs = append(psARNs, a)
			}
		}
	}
	arns, err := c.listAssignments(ctx, userID, "USER")
	if err != nil {
		return integration.Identity{}, err
	}
	add(arns)
	for _, g := range groups {
		arns, err := c.listAssignments(ctx, g, "GROUP")
		if err != nil {
			return integration.Identity{}, err
		}
		add(arns)
	}
	sort.Strings(psARNs)
	nat := &native{}
	var principals []principal
	if len(psARNs) > 0 {
		roles, err := c.ssoRoles(ctx)
		if err != nil {
			return integration.Identity{}, err
		}
		for _, arn := range psARNs {
			name, err := c.permissionSetName(ctx, arn)
			if err != nil {
				return integration.Identity{}, err
			}
			nat.PermissionSets = append(nat.PermissionSets, name)
			roleARN, ok := matchSSORole(roles, name)
			if !ok {
				nat.Missing = append(nat.Missing, name)
				continue
			}
			principals = append(principals, principal{ARN: roleARN, Kind: "permission set", Name: name})
		}
	}
	nat.Principals = principals
	display := user.UserName
	if display == "" {
		display = email
	}
	attrs := map[string]string{"user_name": user.UserName}
	if user.UserStatus != "" {
		attrs["user_status"] = user.UserStatus
	}
	return integration.Identity{ID: userID, Display: display, Attrs: attrs, Groups: groups, Native: nat}, nil
}

// getUserID looks the email up as emails.value, then as userName.
func (c *Connection) getUserID(ctx context.Context, email string) (string, error) {
	for _, path := range []string{"emails.value", "userName"} {
		in := map[string]any{
			"IdentityStoreId": c.identityStoreID,
			"AlternateIdentifier": map[string]any{
				"UniqueAttribute": map[string]any{"AttributePath": path, "AttributeValue": email},
			},
		}
		var out struct {
			UserID string `json:"UserId"`
		}
		err := c.identityStore.JSON11(ctx, "AWSIdentityStore.GetUserId", in, &out)
		if err == nil {
			if out.UserID == "" {
				return "", integration.Errorf(integration.CodeUpstreamError, "GetUserId returned no UserId")
			}
			return out.UserID, nil
		}
		if awsCode(err) == "ResourceNotFoundException" {
			continue
		}
		return "", classify(err, "GetUserId")
	}
	return "", integration.UserNotFound("no Identity Center user has email or username %s", email)
}

func (c *Connection) listGroups(ctx context.Context, userID string) ([]string, error) {
	var groups []string
	token := ""
	for page := 0; ; page++ {
		if page >= maxPages {
			return nil, integration.Errorf(integration.CodeUpstreamError, "ListGroupMembershipsForMember: too many pages")
		}
		in := map[string]any{"IdentityStoreId": c.identityStoreID, "MemberId": map[string]any{"UserId": userID}}
		if token != "" {
			in["NextToken"] = token
		}
		var out struct {
			GroupMemberships []struct {
				GroupID string `json:"GroupId"`
			} `json:"GroupMemberships"`
			NextToken string `json:"NextToken"`
		}
		if err := c.identityStore.JSON11(ctx, "AWSIdentityStore.ListGroupMembershipsForMember", in, &out); err != nil {
			return nil, classify(err, "ListGroupMembershipsForMember")
		}
		for _, m := range out.GroupMemberships {
			if m.GroupID != "" {
				groups = append(groups, m.GroupID)
			}
		}
		if out.NextToken == "" {
			break
		}
		token = out.NextToken
	}
	sort.Strings(groups)
	return groups, nil
}

func (c *Connection) listAssignments(ctx context.Context, principalID, principalType string) ([]string, error) {
	var arns []string
	token := ""
	for page := 0; ; page++ {
		if page >= maxPages {
			return nil, integration.Errorf(integration.CodeUpstreamError, "ListAccountAssignmentsForPrincipal: too many pages")
		}
		in := map[string]any{
			"InstanceArn":   c.ssoInstanceARN,
			"PrincipalId":   principalID,
			"PrincipalType": principalType,
			"Filter":        map[string]any{"AccountId": c.accountID},
		}
		if token != "" {
			in["NextToken"] = token
		}
		var out struct {
			AccountAssignments []struct {
				AccountID        string `json:"AccountId"`
				PermissionSetArn string `json:"PermissionSetArn"`
			} `json:"AccountAssignments"`
			NextToken string `json:"NextToken"`
		}
		if err := c.ssoAdmin.JSON11(ctx, "SWBExternalService.ListAccountAssignmentsForPrincipal", in, &out); err != nil {
			return nil, classify(err, "ListAccountAssignmentsForPrincipal")
		}
		for _, a := range out.AccountAssignments {
			// The filter should already restrict to the account; check
			// anyway. A row must name this account exactly: rows for other
			// accounts or with no AccountId are not assignments here.
			if a.PermissionSetArn != "" && a.AccountID == c.accountID {
				arns = append(arns, a.PermissionSetArn)
			}
		}
		if out.NextToken == "" {
			break
		}
		token = out.NextToken
	}
	return arns, nil
}

func (c *Connection) permissionSetName(ctx context.Context, arn string) (string, error) {
	return c.psNames.Do(ctx, arn, func(ctx context.Context) (string, time.Duration, error) {
		var out struct {
			PermissionSet struct {
				Name string `json:"Name"`
			} `json:"PermissionSet"`
		}
		in := map[string]any{"InstanceArn": c.ssoInstanceARN, "PermissionSetArn": arn}
		if err := c.ssoAdmin.JSON11(ctx, "SWBExternalService.DescribePermissionSet", in, &out); err != nil {
			return "", 0, classify(err, "DescribePermissionSet")
		}
		if out.PermissionSet.Name == "" {
			return "", 0, integration.Errorf(integration.CodeUpstreamError, "DescribePermissionSet returned no name")
		}
		return out.PermissionSet.Name, roleListTTL, nil
	})
}

// ssoRole is one AWSReservedSSO_* role in the account.
type ssoRole struct {
	Name string `xml:"RoleName"`
	ARN  string `xml:"Arn"`
	Path string `xml:"Path"`
}

// ssoRoles lists the account's Identity Center roles, cached for 10 minutes.
func (c *Connection) ssoRoles(ctx context.Context) ([]ssoRole, error) {
	return c.roles.Do(ctx, "sso", func(ctx context.Context) ([]ssoRole, time.Duration, error) {
		roles, err := c.listSSORoles(ctx)
		return roles, roleListTTL, err
	})
}

// listSSORoles is iam:ListRoles under the SSO path prefix, every page.
// UNVERIFIED: roles may sit under /aws-reserved/sso.amazonaws.com/<region>/
// as well; PathPrefix matching is a prefix match so both are returned.
func (c *Connection) listSSORoles(ctx context.Context) ([]ssoRole, error) {
	var roles []ssoRole
	marker := ""
	for page := 0; ; page++ {
		if page >= maxPages {
			return nil, integration.Errorf(integration.CodeUpstreamError, "ListRoles: too many pages")
		}
		params := authx.QueryParams{"PathPrefix": ssoPathPrefix, "MaxItems": 1000}
		if marker != "" {
			params["Marker"] = marker
		}
		var out struct {
			Result struct {
				Roles       []ssoRole `xml:"Roles>member"`
				IsTruncated bool      `xml:"IsTruncated"`
				Marker      string    `xml:"Marker"`
			} `xml:"ListRolesResult"`
		}
		if err := c.iam.Query(ctx, "ListRoles", iamVersion, params, &out); err != nil {
			return nil, classify(err, "ListRoles")
		}
		roles = append(roles, out.Result.Roles...)
		if !out.Result.IsTruncated || out.Result.Marker == "" {
			break
		}
		marker = out.Result.Marker
	}
	return roles, nil
}

// matchSSORole finds the role provisioned for a permission set. The match is
// anchored: AWSReservedSSO_<name>_<16 hex>, nothing else.
func matchSSORole(roles []ssoRole, permissionSet string) (string, bool) {
	re := regexp.MustCompile(`^AWSReservedSSO_` + regexp.QuoteMeta(permissionSet) + `_[0-9a-f]{16}$`)
	for _, r := range roles {
		if re.MatchString(r.Name) && r.ARN != "" {
			return r.ARN, true
		}
	}
	return "", false
}

// IAM user

func (c *Connection) resolveIAMUser(ctx context.Context, email string) (integration.Identity, error) {
	local, _, _ := strings.Cut(email, "@")
	var candidates []string
	if iamUserNameRe.MatchString(local) {
		candidates = append(candidates, local)
	}
	if iamUserNameRe.MatchString(email) {
		candidates = append(candidates, email)
	}
	for _, name := range candidates {
		var out struct {
			Result struct {
				User struct {
					ARN      string `xml:"Arn"`
					UserName string `xml:"UserName"`
					UserID   string `xml:"UserId"`
				} `xml:"User"`
			} `xml:"GetUserResult"`
		}
		err := c.iam.Query(ctx, "GetUser", iamVersion, authx.QueryParams{"UserName": name}, &out)
		if err == nil {
			u := out.Result.User
			if u.ARN == "" {
				return integration.Identity{}, integration.Errorf(integration.CodeUpstreamError, "GetUser returned no ARN")
			}
			id := u.UserID
			if id == "" {
				id = u.UserName
			}
			nat := &native{Principals: []principal{{ARN: u.ARN, Kind: "user", Name: u.UserName}}}
			return integration.Identity{ID: id, Display: u.UserName, Attrs: map[string]string{"arn": u.ARN}, Native: nat}, nil
		}
		if awsCode(err) == "NoSuchEntity" {
			continue
		}
		return integration.Identity{}, classify(err, "GetUser")
	}
	return integration.Identity{}, integration.UserNotFound("no IAM user named %s or %s in account %s", local, email, c.accountID)
}

// Static map

// roleMap is the static_map file: "<email-or-group> <role-arn>" per line,
// "#" comments, matched case-insensitively. It is re-read at most every
// 60 seconds; a re-read failure keeps the last good map.
type roleMap struct {
	path   string
	now    func() time.Time
	logf   func(msg string, args ...any)
	mu     sync.Mutex
	items  map[string][]string
	loaded time.Time
}

func newRoleMap(path string, now func() time.Time, logf func(string, ...any)) (*roleMap, error) {
	m := &roleMap{path: path, now: now, logf: logf}
	items, err := m.read()
	if err != nil {
		return nil, err
	}
	m.items, m.loaded = items, now()
	return m, nil
}

func (m *roleMap) read() (map[string][]string, error) {
	f, err := os.Open(m.path)
	if err != nil {
		return nil, fmt.Errorf("role_map_file: %w", err)
	}
	defer f.Close()
	items := map[string][]string{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("role_map_file %s line %d: want \"<email-or-group> <role-arn>\"", m.path, n)
		}
		if err := authx.ValidateRoleARN(fields[1]); err != nil {
			return nil, fmt.Errorf("role_map_file %s line %d: %v", m.path, n, err)
		}
		key := strings.ToLower(fields[0])
		items[key] = appendUnique(items[key], fields[1])
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("role_map_file %s: %w", m.path, err)
	}
	return items, nil
}

// lookup returns the union of the role ARNs mapped to the email and to any
// of the groups, in file order of first appearance.
func (m *roleMap) lookup(email string, groups []string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.now().Sub(m.loaded) >= roleMapReread {
		items, err := m.read()
		if err != nil {
			if m.items == nil {
				return nil, integration.Wrap(integration.CodeUpstreamError, err, "role_map_file could not be read")
			}
			m.logf("role_map_file re-read failed; keeping the previous map", "path", m.path, "error", err.Error())
		} else {
			m.items = items
		}
		m.loaded = m.now()
	}
	var out []string
	out = append(out, m.items[strings.ToLower(email)]...)
	for _, g := range groups {
		for _, arn := range m.items[strings.ToLower(g)] {
			out = appendUnique(out, arn)
		}
	}
	return out, nil
}

func appendUnique(xs []string, x string) []string {
	for _, v := range xs {
		if v == x {
			return xs
		}
	}
	return append(xs, x)
}

// awsCode returns the AWS error code carried by err, or "".
func awsCode(err error) string {
	var ae *authx.AWSError
	if errors.As(err, &ae) {
		return ae.Code
	}
	return ""
}

// classify maps a failed AWS call to an *integration.Error, naming the call.
func classify(err error, op string) error {
	ie := authx.ClassifyAWSError(err)
	if ie == nil {
		return nil
	}
	return &integration.Error{Code: ie.Code, Text: op + ": " + ie.Text, Err: ie.Err}
}
