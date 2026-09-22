// Package aws checks permissions with iam:SimulatePrincipalPolicy.
//
// One connection is one AWS account. hallpass assumes a read-only role in
// that account, maps the caller's email to the IAM principals the user can
// act as (the AWSReservedSSO roles of their Identity Center permission sets,
// a static email/group -> role map, or an IAM user) and asks IAM to simulate
// the requested action on the requested ARN for each principal. IAM
// evaluates identity policies, permissions boundaries and SCPs; nothing is
// written.
package aws

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/roee-hersh/hallpass/internal/authx"
	"github.com/roee-hersh/hallpass/internal/cache"
	"github.com/roee-hersh/hallpass/internal/httpx"
	"github.com/roee-hersh/hallpass/internal/integration"
	"github.com/roee-hersh/hallpass/internal/secret"
)

const (
	iamVersion = "2010-05-08"
	stsVersion = "2011-06-15"
)

var (
	accountIDRe       = regexp.MustCompile(`^[0-9]{12}$`)
	regionRe          = regexp.MustCompile(`^[a-z]{2}(-gov)?-[a-z]+-[0-9]$`)
	identityStoreIDRe = regexp.MustCompile(`^d-[0-9a-f]{10}$`)
	ssoInstanceARNRe  = regexp.MustCompile(`^arn:aws[a-z-]*:sso:::instance/(sso)?ins-[0-9a-f]{16}$`)
	sessionNameRe     = regexp.MustCompile(`^[\w+=,.@-]{2,64}$`)
	contextKeyRe      = regexp.MustCompile(`^[A-Za-z0-9:_/.@-]{1,256}$`)
)

// testEndpoints, when non-nil, replaces the AWS endpoints. Keys: sts, iam,
// identitystore, sso, imds. Tests set it so one fake server serves them all.
var testEndpoints map[string]string

func endpoint(name, def string) string {
	if testEndpoints != nil {
		if v, ok := testEndpoints[name]; ok {
			return v
		}
	}
	return def
}

// Integration is the aws product.
type Integration struct{}

// Name is "aws".
func (Integration) Name() string { return "aws" }

// Fields of an aws connection.
func (Integration) Fields() []integration.Field {
	return []integration.Field{
		{Name: "account_id", Required: true, Validate: matchRe(accountIDRe, "a 12-digit account id"),
			Description: "the AWS account this connection answers for"},
		{Name: "role_arn", Required: true, Validate: authx.ValidateRoleARN,
			Description: "hallpass's read-only role in that account (iam:SimulatePrincipalPolicy, iam:ListRoles)"},
		{Name: "external_id", Description: "ExternalId sent with every AssumeRole"},
		{Name: "partition", Default: "aws", Enum: []string{"aws", "aws-us-gov", "aws-cn"}, Description: "AWS partition"},
		{Name: "region", Required: true, Validate: matchRe(regionRe, "a region such as eu-west-1"),
			Description: "region for the STS endpoint, e.g. eu-west-1"},
		integration.CredentialField(true, "JSON {access_key_id, secret_access_key, session_token?} or the value ambient:auto|container|web_identity|imds"),
		{Name: "identity_mode", Default: "identity_center", Enum: []string{"identity_center", "static_map", "iam_user"},
			Description: "how an email becomes IAM principals"},
		{Name: "identity_center_role_arn", Validate: authx.ValidateRoleARN,
			Description: "identity_center: hallpass's read role in the Identity Center management or delegated account"},
		{Name: "identity_center_region", Validate: matchRe(regionRe, "a region such as eu-west-1"),
			Description: "identity_center: the region Identity Center is enabled in"},
		{Name: "identity_store_id", Validate: matchRe(identityStoreIDRe, "d-<10 hex digits>"),
			Description: "identity_center: the identity store id"},
		{Name: "sso_instance_arn", Validate: matchRe(ssoInstanceARNRe, "arn:aws:sso:::instance/ssoins-<16 hex digits>"),
			Description: "identity_center: the Identity Center instance ARN"},
		{Name: "role_map_file", Description: "static_map: file of \"<email-or-group> <role-arn>\" lines, # comments; re-read every 60 s"},
		{Name: "context_entries", Validate: func(v string) error { _, err := parseContextEntries(v); return err },
			Description: "condition context for the simulation: key=type:value;..., e.g. aws:MultiFactorAuthPresent=boolean:true;aws:SourceIp=ip:10.0.0.1"},
		{Name: "implicit_deny_as", Default: "deny", Enum: []string{"deny", "unknown"},
			Description: "what an implicitDeny (no matching statement) answers"},
		{Name: "session_name", Default: "hallpass", Validate: matchRe(sessionNameRe, "2-64 characters of [A-Za-z0-9+=,.@_-]"),
			Description: "RoleSessionName for AssumeRole"},
	}
}

func matchRe(re *regexp.Regexp, want string) func(string) error {
	return func(v string) error {
		if !re.MatchString(v) {
			return fmt.Errorf("%q must be %s", v, want)
		}
		return nil
	}
}

// contextEntry is one condition key for the simulation.
type contextEntry struct {
	Key    string
	Type   string
	Values []string
}

var contextTypes = map[string]string{
	"string": "string", "stringlist": "stringList", "numeric": "numeric", "boolean": "boolean",
	"ip": "ip", "binary": "binary", "date": "date",
}

// parseContextEntries parses key=type:value;key=type:value. stringList
// values are comma separated.
func parseContextEntries(v string) ([]contextEntry, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, nil
	}
	var out []contextEntry
	seen := map[string]bool{}
	for _, part := range strings.Split(v, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key, rest, ok := strings.Cut(part, "=")
		if !ok {
			return nil, fmt.Errorf("context entry %q must be key=type:value", part)
		}
		key = strings.TrimSpace(key)
		if !contextKeyRe.MatchString(key) {
			return nil, fmt.Errorf("context key %q is not a valid condition key", key)
		}
		if seen[key] {
			return nil, fmt.Errorf("context key %q given twice", key)
		}
		seen[key] = true
		typ, val, ok := strings.Cut(rest, ":")
		if !ok {
			return nil, fmt.Errorf("context entry %q must be key=type:value with type one of string, stringList, numeric, boolean, ip, binary, date", part)
		}
		canon, ok := contextTypes[strings.ToLower(strings.TrimSpace(typ))]
		if !ok {
			return nil, fmt.Errorf("context type %q must be one of string, stringList, numeric, boolean, ip, binary, date", typ)
		}
		var values []string
		if canon == "stringList" {
			for _, s := range strings.Split(val, ",") {
				values = append(values, strings.TrimSpace(s))
			}
		} else {
			values = []string{strings.TrimSpace(val)}
		}
		out = append(out, contextEntry{Key: key, Type: canon, Values: values})
	}
	return out, nil
}

// New builds a connection. It reads role_map_file (static_map) but never the
// network.
func (Integration) New(_ context.Context, s *integration.Settings, d integration.Deps) (integration.Connection, error) {
	hc, err := d.HTTPClient(s)
	if err != nil {
		return nil, err
	}
	cred := s.Secret("credential")
	if cred.IsZero() {
		return nil, errors.New("credential is required")
	}
	now := d.Now
	if now == nil {
		now = time.Now
	}
	logger := d.Logger
	if logger == nil {
		logger = slog.Default()
	}
	c := &Connection{
		settings:       s,
		logger:         logger,
		accountID:      s.Get("account_id"),
		partition:      s.Get("partition"),
		region:         s.Get("region"),
		mode:           s.Get("identity_mode"),
		implicitDenyAs: s.Get("implicit_deny_as"),
		sessionName:    s.Get("session_name"),
	}
	if c.partition == "" {
		c.partition = "aws"
	}
	if c.mode == "" {
		c.mode = "identity_center"
	}
	if c.implicitDenyAs == "" {
		c.implicitDenyAs = "deny"
	}
	if c.sessionName == "" {
		c.sessionName = "hallpass"
	}
	if !accountIDRe.MatchString(c.accountID) {
		return nil, errors.New("account_id must be 12 digits")
	}
	if !regionRe.MatchString(c.region) {
		return nil, errors.New("region is required")
	}
	roleARN := s.Get("role_arn")
	if err := authx.ValidateRoleARN(roleARN); err != nil {
		return nil, fmt.Errorf("role_arn: %w", err)
	}
	if a := arnField(roleARN, 4); a != c.accountID {
		return nil, fmt.Errorf("role_arn is in account %s but account_id is %s; IAM simulation only works inside the account", a, c.accountID)
	}
	if p := arnField(roleARN, 1); p != c.partition {
		return nil, fmt.Errorf("role_arn is in partition %s but partition is %s", p, c.partition)
	}
	if c.contextEntries, err = parseContextEntries(s.Get("context_entries")); err != nil {
		return nil, err
	}
	externalID := s.Get("external_id")

	c.plain = &httpx.Client{HTTP: hc, Logger: logger}
	stsEndpoint := endpoint("sts", authx.RegionalEndpoint(c.partition, "sts", c.region))
	base := &baseProvider{
		secret:   cred,
		plain:    c.plain,
		sts:      &authx.STSClient{HTTP: c.plain, Endpoint: stsEndpoint, Region: c.region},
		imdsBase: endpoint("imds", ""),
	}
	stsClient := &authx.STSClient{HTTP: c.plain, Endpoint: stsEndpoint, Region: c.region, Creds: base}
	c.accountCreds = authx.AssumeRoleProvider(stsClient, roleARN, c.sessionName, externalID)
	c.accountCreds.Now = now
	iamEndpoint, iamRegion := authx.IAMEndpoint(c.partition)
	c.iam = &authx.AWSClient{HTTP: c.plain, Endpoint: endpoint("iam", iamEndpoint), Region: iamRegion, Service: "iam", Creds: c.accountCreds}
	c.sts = &authx.AWSClient{HTTP: c.plain, Endpoint: stsEndpoint, Region: c.region, Service: "sts", Creds: c.accountCreds}

	switch c.mode {
	case "identity_center":
		icRole := s.Get("identity_center_role_arn")
		icRegion := s.Get("identity_center_region")
		c.identityStoreID = s.Get("identity_store_id")
		c.ssoInstanceARN = s.Get("sso_instance_arn")
		switch {
		case icRole == "":
			return nil, errors.New("identity_center_role_arn is required for identity_mode identity_center")
		case !regionRe.MatchString(icRegion):
			return nil, errors.New("identity_center_region is required for identity_mode identity_center")
		case !identityStoreIDRe.MatchString(c.identityStoreID):
			return nil, errors.New("identity_store_id is required for identity_mode identity_center")
		case !ssoInstanceARNRe.MatchString(c.ssoInstanceARN):
			return nil, errors.New("sso_instance_arn is required for identity_mode identity_center")
		}
		if err := authx.ValidateRoleARN(icRole); err != nil {
			return nil, fmt.Errorf("identity_center_role_arn: %w", err)
		}
		c.icCreds = authx.AssumeRoleProvider(stsClient, icRole, c.sessionName, externalID)
		c.icCreds.Now = now
		c.identityStore = &authx.AWSClient{HTTP: c.plain, Endpoint: endpoint("identitystore", authx.RegionalEndpoint(c.partition, "identitystore", icRegion)),
			Region: icRegion, Service: "identitystore", Creds: c.icCreds}
		c.ssoAdmin = &authx.AWSClient{HTTP: c.plain, Endpoint: endpoint("sso", authx.RegionalEndpoint(c.partition, "sso", icRegion)),
			Region: icRegion, Service: "sso", Creds: c.icCreds}
	case "static_map":
		path := s.Get("role_map_file")
		if path == "" {
			return nil, errors.New("role_map_file is required for identity_mode static_map")
		}
		if _, err := os.Stat(path); err != nil {
			return nil, fmt.Errorf("role_map_file: %w", err)
		}
		c.roleMap, err = newRoleMap(path, now, func(msg string, args ...any) { logger.Warn(msg, args...) })
		if err != nil {
			return nil, err
		}
	case "iam_user":
	default:
		return nil, fmt.Errorf("identity_mode %q is not one of identity_center, static_map, iam_user", c.mode)
	}
	c.identities = cache.New[string, integration.Identity](0)
	c.identities.SetClock(now)
	c.roles = cache.New[string, []ssoRole](1)
	c.roles.SetClock(now)
	c.psNames = cache.New[string, string](0)
	c.psNames.SetClock(now)
	return c, nil
}

// Connection is one AWS account.
type Connection struct {
	settings       *integration.Settings
	logger         *slog.Logger
	accountID      string
	partition      string
	region         string
	mode           string
	implicitDenyAs string
	sessionName    string
	contextEntries []contextEntry

	plain        *httpx.Client
	accountCreds *authx.CachedProvider // the role in the account
	icCreds      *authx.CachedProvider // the Identity Center role

	iam           *authx.AWSClient
	sts           *authx.AWSClient
	identityStore *authx.AWSClient
	ssoAdmin      *authx.AWSClient

	identityStoreID string
	ssoInstanceARN  string
	roleMap         *roleMap

	identities *cache.TTL[string, integration.Identity]
	roles      *cache.TTL[string, []ssoRole]
	psNames    *cache.TTL[string, string]
}

// baseProvider yields the credential the connection starts from: either
// static keys from the secret's JSON or an ambient source named by an
// "ambient:<mode>" secret value. The secret is read on every refresh.
type baseProvider struct {
	secret   secret.Secret
	plain    *httpx.Client
	sts      *authx.STSClient
	imdsBase string

	mu      sync.Mutex
	mode    string
	ambient authx.CredentialProvider
}

func (b *baseProvider) Credentials(ctx context.Context) (authx.AWSCredentials, error) {
	raw, err := b.secret.Get()
	if err != nil {
		return authx.AWSCredentials{}, err
	}
	v := strings.TrimSpace(string(raw))
	if mode, ok := strings.CutPrefix(v, "ambient:"); ok {
		b.mu.Lock()
		if b.ambient == nil || b.mode != mode {
			p, err := authx.AmbientProvider(mode, authx.OSEnv, b.plain, b.sts, b.imdsBase)
			if err != nil {
				b.mu.Unlock()
				return authx.AWSCredentials{}, err
			}
			b.ambient, b.mode = p, mode
		}
		p := b.ambient
		b.mu.Unlock()
		return p.Credentials(ctx)
	}
	creds, err := authx.StaticFromJSON(raw)
	if err != nil {
		// The cause could echo part of the secret; keep it out.
		return authx.AWSCredentials{}, errors.New("credential must be JSON with access_key_id and secret_access_key, or ambient:<mode>")
	}
	return creds, nil
}

// Check simulates the action for every candidate principal.
func (c *Connection) Check(ctx context.Context, r integration.CheckRequest) (integration.Decision, error) {
	action, err := resolveAction(r.ActionName)
	if err != nil {
		return integration.Decision{}, integration.Errorf(integration.CodeInvalidRequest, "%v", err)
	}
	resource, err := parseResource(r.Resource, c.partition)
	if err != nil {
		return integration.Decision{}, integration.Errorf(integration.CodeInvalidRequest, "%v", err)
	}
	what := action + " on " + resource
	if acct := arnField(resource, 4); resource != "*" && acct != "" && acct != c.accountID {
		return integration.Unsupported("%s is in account %s, not %s; cross-account access depends on the resource policy, which hallpass cannot see", resource, acct, c.accountID), nil
	}
	if r.Identity.Attr("user_status") == "DISABLED" {
		return integration.Denied("%s is disabled in IAM Identity Center", r.Identity.Display), nil
	}

	var principals []principal
	var missing []string
	switch c.mode {
	case "static_map":
		arns, err := c.roleMap.lookup(r.User.Email, r.User.Groups)
		if err != nil {
			return integration.Decision{}, err
		}
		if len(arns) == 0 {
			return integration.Decision{}, integration.UserNotFound("%s and its groups are not in role_map_file", r.User.Email)
		}
		for _, arn := range arns {
			principals = append(principals, principal{ARN: arn, Kind: "role", Name: roleName(arn)})
		}
	default:
		nat, _ := r.Identity.Native.(*native)
		if nat == nil {
			return integration.Decision{}, integration.Errorf(integration.CodeUpstreamError, "identity carries no principals")
		}
		principals, missing = nat.Principals, nat.Missing
		if c.mode == "identity_center" && len(nat.PermissionSets) == 0 {
			return integration.Denied("%s has no permission set assigned in account %s", r.Identity.Display, c.accountID), nil
		}
	}
	if len(principals) == 0 {
		if len(missing) > 0 {
			return integration.UnknownDecision(integration.CodeResourceNotVisible, "permission set %s is assigned but its role is not provisioned in account %s", strings.Join(missing, ", "), c.accountID), nil
		}
		return integration.Decision{}, integration.Errorf(integration.CodeUpstreamError, "no principal to simulate")
	}

	var results []simResult
	for _, p := range principals {
		res, err := c.simulate(ctx, p, action, resource)
		if err != nil {
			if awsCode(err) == "NoSuchEntity" {
				c.identities.Delete(strings.ToLower(r.User.Email))
				c.roles.Delete("sso")
				return integration.UnknownDecision(integration.CodeResourceNotVisible, "%s (%s) no longer exists; the role vanished and the cache will refresh", p, p.ARN), nil
			}
			if awsCode(err) == "PolicyEvaluation" {
				return integration.Unsupported("IAM could not evaluate the policies of %s", p), nil
			}
			return integration.Decision{}, classify(err, "SimulatePrincipalPolicy")
		}
		if res.decision == "allowed" {
			return integration.Allowed("%s allows %s", p, what), nil
		}
		results = append(results, res)
	}

	// Nothing allowed. Missing context first: the answer depends on it.
	var keys []string
	seen := map[string]bool{}
	for _, res := range results {
		for _, k := range res.missing {
			if !seen[k] {
				seen[k] = true
				keys = append(keys, k)
			}
		}
	}
	if len(keys) > 0 {
		sort.Strings(keys)
		return integration.Unsupported("the answer for %s depends on condition keys %s; set context_entries on the connection", what, strings.Join(keys, ", ")), nil
	}
	if len(missing) > 0 {
		return integration.UnknownDecision(integration.CodeResourceNotVisible, "permission set %s is assigned but its role is not provisioned in account %s", strings.Join(missing, ", "), c.accountID), nil
	}
	names := make([]string, 0, len(results))
	explicit := true
	var notes []string
	for _, res := range results {
		names = append(names, res.principal.String())
		if res.decision != "explicitDeny" {
			explicit = false
		}
		if res.scpDenied && !contains(notes, "denied by SCP") {
			notes = append(notes, "denied by SCP")
		}
		if res.boundaryDenied && !contains(notes, "blocked by the permissions boundary") {
			notes = append(notes, "blocked by the permissions boundary")
		}
	}
	suffix := ""
	if len(notes) > 0 {
		suffix = " (" + strings.Join(notes, "; ") + ")"
	}
	if !explicit && c.implicitDenyAs == "unknown" {
		return integration.Unsupported("no policy of %s allows %s (implicit deny)%s", strings.Join(names, ", "), what, suffix), nil
	}
	if explicit {
		return integration.Denied("%s explicitly deny %s%s", strings.Join(names, ", "), what, suffix), nil
	}
	return integration.Denied("no policy of %s allows %s%s", strings.Join(names, ", "), what, suffix), nil
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func roleName(arn string) string {
	res := arnField(arn, 5)
	if i := strings.LastIndex(res, "/"); i >= 0 {
		return res[i+1:]
	}
	return res
}

// simResult is the outcome of one SimulatePrincipalPolicy for one principal.
type simResult struct {
	principal      principal
	decision       string // allowed, implicitDeny, explicitDeny
	missing        []string
	scpDenied      bool
	boundaryDenied bool
}

type evalResult struct {
	ActionName   string   `xml:"EvalActionName"`
	Decision     string   `xml:"EvalDecision"`
	ResourceName string   `xml:"EvalResourceName"`
	Missing      []string `xml:"MissingContextValues>member"`
	Org          struct {
		Allowed *bool `xml:"AllowedByOrganizations"`
	} `xml:"OrganizationsDecisionDetail"`
	Boundary struct {
		Allowed *bool `xml:"AllowedByPermissionsBoundary"`
	} `xml:"PermissionsBoundaryDecisionDetail"`
	Resources []struct {
		Name     string   `xml:"EvalResourceName"`
		Decision string   `xml:"EvalResourceDecision"`
		Missing  []string `xml:"MissingContextValues>member"`
	} `xml:"ResourceSpecificResults>member"`
}

type simulateResponse struct {
	Result struct {
		Results     []evalResult `xml:"EvaluationResults>member"`
		IsTruncated bool         `xml:"IsTruncated"`
		Marker      string       `xml:"Marker"`
	} `xml:"SimulatePrincipalPolicyResult"`
}

// simulate runs iam:SimulatePrincipalPolicy for one principal, all pages.
func (c *Connection) simulate(ctx context.Context, p principal, action, resource string) (simResult, error) {
	out := simResult{principal: p, decision: "implicitDeny"}
	marker := ""
	var results []evalResult
	for page := 0; ; page++ {
		if page >= maxPages {
			return out, integration.Errorf(integration.CodeUpstreamError, "SimulatePrincipalPolicy: too many pages")
		}
		params := authx.QueryParams{
			"PolicySourceArn": p.ARN,
			"ActionNames":     []string{action},
			"MaxItems":        100,
		}
		// UNVERIFIED: for "*" ResourceArns is omitted and IAM's documented
		// default ("*") relied on, rather than sending "*" as an ARN.
		if resource != "*" {
			params["ResourceArns"] = []string{resource}
		}
		for i, e := range c.contextEntries {
			pfx := "ContextEntries.member." + strconv.Itoa(i+1)
			params[pfx+".ContextKeyName"] = e.Key
			params[pfx+".ContextKeyType"] = e.Type
			for j, v := range e.Values {
				params[pfx+".ContextKeyValues.member."+strconv.Itoa(j+1)] = v
			}
		}
		if marker != "" {
			params["Marker"] = marker
		}
		var resp simulateResponse
		if err := c.iam.Query(ctx, "SimulatePrincipalPolicy", iamVersion, params, &resp); err != nil {
			return out, err
		}
		results = append(results, resp.Result.Results...)
		if !resp.Result.IsTruncated || resp.Result.Marker == "" {
			break
		}
		marker = resp.Result.Marker
	}
	found := false
	for _, r := range results {
		if r.ActionName != "" && r.ActionName != action {
			continue
		}
		found = true
		out.decision = r.Decision
		out.missing = append(out.missing, r.Missing...)
		if r.Org.Allowed != nil && !*r.Org.Allowed {
			out.scpDenied = true
		}
		if r.Boundary.Allowed != nil && !*r.Boundary.Allowed {
			out.boundaryDenied = true
		}
		// Prefer the per-resource verdict for the requested resource.
		for _, rr := range r.Resources {
			if rr.Name == resource || (resource == "*" && len(r.Resources) == 1) {
				if rr.Decision != "" {
					out.decision = rr.Decision
				}
				out.missing = append(out.missing, rr.Missing...)
			}
		}
	}
	if !found {
		return out, integration.Errorf(integration.CodeUpstreamError, "SimulatePrincipalPolicy returned no result for %s", action)
	}
	switch out.decision {
	case "allowed", "explicitDeny", "implicitDeny":
	default:
		return out, integration.Errorf(integration.CodeUpstreamError, "SimulatePrincipalPolicy returned an unknown decision")
	}
	return out, nil
}

// Probe verifies the assumed role, lists the account's Identity Center roles
// and, in identity_center mode, checks the instance against the config.
func (c *Connection) Probe(ctx context.Context) (integration.ProbeResult, error) {
	var ident struct {
		Result struct {
			Arn     string `xml:"Arn"`
			Account string `xml:"Account"`
		} `xml:"GetCallerIdentityResult"`
	}
	if err := c.sts.Query(ctx, "GetCallerIdentity", stsVersion, nil, &ident); err != nil {
		return integration.ProbeResult{}, classify(err, "GetCallerIdentity")
	}
	var res integration.ProbeResult
	if ident.Result.Account != "" && ident.Result.Account != c.accountID {
		res.Warnings = append(res.Warnings, fmt.Sprintf("the assumed role is in account %s, not account_id %s", ident.Result.Account, c.accountID))
	}
	roles, err := c.listSSORoles(ctx)
	if err != nil {
		return integration.ProbeResult{}, err
	}
	res.Summary = fmt.Sprintf("authenticated as %s; %d AWSReservedSSO roles in account %s", ident.Result.Arn, len(roles), c.accountID)
	if c.mode == "identity_center" {
		var out struct {
			Instances []struct {
				InstanceArn     string `json:"InstanceArn"`
				IdentityStoreID string `json:"IdentityStoreId"`
			} `json:"Instances"`
		}
		if err := c.ssoAdmin.JSON11(ctx, "SWBExternalService.ListInstances", map[string]any{}, &out); err != nil {
			return integration.ProbeResult{}, classify(err, "ListInstances")
		}
		matched := false
		for _, in := range out.Instances {
			if in.InstanceArn != c.ssoInstanceARN {
				continue
			}
			matched = true
			if in.IdentityStoreID != c.identityStoreID {
				res.Warnings = append(res.Warnings, fmt.Sprintf("sso_instance_arn has identity store %s but identity_store_id is %s", in.IdentityStoreID, c.identityStoreID))
			}
		}
		if !matched {
			res.Warnings = append(res.Warnings, fmt.Sprintf("sso:ListInstances did not list sso_instance_arn %s (%d instances visible)", c.ssoInstanceARN, len(out.Instances)))
		}
		if len(roles) == 0 {
			res.Warnings = append(res.Warnings, "no AWSReservedSSO roles in the account; every user will be denied until a permission set is provisioned")
		}
	}
	res.Warnings = append(res.Warnings, "iam:SimulatePrincipalPolicy discloses information about the permissions granted to other users; this is inherent to how hallpass checks")
	return res, nil
}
