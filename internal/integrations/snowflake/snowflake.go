// Package snowflake checks what a user may do in a Snowflake account.
//
// hallpass authenticates as a service user with a key pair through the SQL
// REST API, finds the user with SHOW USERS, lists the roles granted to the
// user with SHOW GRANTS TO USER and walks the role hierarchy with SHOW
// GRANTS TO ROLE, then looks for the privilege the question needs on the
// object (OWNERSHIP counts), and for USAGE on the object's database and
// schema. Only SHOW commands run, which need no warehouse. Nothing is
// written.
package snowflake

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/roee-hersh/hallpass/internal/authx"
	"github.com/roee-hersh/hallpass/internal/cache"
	"github.com/roee-hersh/hallpass/internal/httpx"
	"github.com/roee-hersh/hallpass/internal/integration"
)

const (
	// jwtLifetime is the key-pair token's validity; Snowflake accepts up
	// to an hour.
	jwtLifetime = 50 * time.Minute
	// statementTimeout is the seconds a SHOW command may take.
	statementTimeout = 30
	// grantsTTL is how long a role's grants are kept.
	grantsTTL = 2 * time.Minute
	// maxRoles bounds the role hierarchy walk.
	maxRoles = 500
	// userPage is the SHOW USERS page size.
	userPage = 10000
	// maxUserPages bounds the SHOW USERS scan.
	maxUserPages = 20
)

// Integration is the snowflake product.
type Integration struct{}

// Name is "snowflake".
func (Integration) Name() string { return "snowflake" }

// Fields of a snowflake connection.
func (Integration) Fields() []integration.Field {
	return []integration.Field{
		{Name: "account", Required: true, Description: "the account identifier, e.g. myorg-myaccount (or the legacy locator xy12345.us-east-1)"},
		{Name: "user", Required: true, Description: "the service user hallpass authenticates as"},
		integration.CredentialField(true, "the user's RSA private key (PEM, unencrypted) for key-pair authentication"),
		{Name: "role", Description: "the role to run as; it needs MANAGE GRANTS (or SECURITYADMIN) to see other users' grants"},
		{Name: "url", Description: "the account URL, default https://<account>.snowflakecomputing.com"},
	}
}

var (
	accountRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$`)
)

// New builds a connection. It touches no network.
func (Integration) New(_ context.Context, s *integration.Settings, d integration.Deps) (integration.Connection, error) {
	hc, err := d.HTTPClient(s)
	if err != nil {
		return nil, err
	}
	account := strings.TrimSpace(s.Get("account"))
	if !accountRe.MatchString(account) {
		return nil, errors.New("account is required and must be an account identifier")
	}
	user, err := parseIdentifier(strings.TrimSpace(s.Get("user")))
	if err != nil {
		return nil, fmt.Errorf("user: %w", err)
	}
	if s.Secret("credential").IsZero() {
		return nil, errors.New("credential (the private key) is required")
	}
	c := &Connection{user: user, now: d.Now, grants: cache.New[string, []grant](0)}
	if c.now == nil {
		c.now = time.Now
	}
	c.grants.SetClock(c.now)
	if r := strings.TrimSpace(s.Get("role")); r != "" {
		if c.role, err = parseIdentifier(r); err != nil {
			return nil, fmt.Errorf("role: %w", err)
		}
	}
	base := strings.TrimRight(strings.TrimSpace(s.Get("url")), "/")
	if base == "" {
		base = "https://" + strings.ToLower(account) + ".snowflakecomputing.com"
	}
	if !strings.HasPrefix(base, "https://") && !strings.HasPrefix(base, "http://") {
		return nil, errors.New("url must be an http(s) URL")
	}
	cred := s.Secret("credential")
	// The iss and sub claims name the account and user the way the
	// official drivers do: upper case, the legacy locator cut at its first
	// dot (a .global locator at its first dash).
	acct := account
	if strings.Contains(acct, ".global") {
		acct, _, _ = strings.Cut(acct, "-")
	} else {
		acct, _, _ = strings.Cut(acct, ".")
	}
	subject := strings.ToUpper(acct) + "." + strings.ToUpper(user)
	c.tokens = &authx.TokenSource{Now: c.now, Fetch: func(context.Context) (authx.Token, error) {
		pem, err := cred.GetString()
		if err != nil {
			return authx.Token{}, integration.Wrap(integration.CodeCredentialRejected, err, "the private key could not be read")
		}
		key, err := authx.ParseRSAPrivateKey([]byte(pem))
		if err != nil {
			return authx.Token{}, integration.Wrap(integration.CodeCredentialRejected, err, "the credential is not an unencrypted RSA private key in PEM")
		}
		now := c.now()
		claims := authx.StandardClaims{
			Iss: subject + "." + fingerprint(&key.PublicKey),
			Sub: subject,
			Iat: authx.Unix(now),
			Exp: authx.Unix(now.Add(jwtLifetime)),
		}
		jwt, err := authx.SignJWT(key, authx.Header{Alg: authx.RS256}, claims)
		if err != nil {
			return authx.Token{}, integration.Wrap(integration.CodeCredentialRejected, err, "the key-pair token could not be signed")
		}
		return authx.Token{Value: jwt, Expiry: now.Add(jwtLifetime)}, nil
	}}
	c.api = &httpx.Client{HTTP: hc, Base: base, Logger: d.Logger, Auth: func(ctx context.Context, r *http.Request) error {
		tok, err := c.tokens.Get(ctx)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+tok)
		r.Header.Set("X-Snowflake-Authorization-Token-Type", "KEYPAIR_JWT")
		return nil
	}}
	return c, nil
}

// fingerprint is SHA256:<base64 of the SHA-256 of the public key's DER>.
func fingerprint(pub *rsa.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "SHA256:"
	}
	sum := sha256.Sum256(der)
	return "SHA256:" + base64.StdEncoding.EncodeToString(sum[:])
}

// Connection is one Snowflake account.
type Connection struct {
	api    *httpx.Client
	tokens *authx.TokenSource
	user   string
	role   string
	now    func() time.Time
	// grants caches SHOW GRANTS TO ROLE per role.
	grants *cache.TTL[string, []grant]
}

// --- SQL API ----------------------------------------------------------------

// resultSet is the SQL API's response to a completed statement.
type resultSet struct {
	Code            string     `json:"code"`
	SQLState        string     `json:"sqlState"`
	Message         string     `json:"message"`
	StatementHandle string     `json:"statementHandle"`
	Data            [][]string `json:"data"`
	Meta            struct {
		NumRows int `json:"numRows"`
		RowType []struct {
			Name string `json:"name"`
		} `json:"rowType"`
		PartitionInfo []struct {
			RowCount int `json:"rowCount"`
		} `json:"partitionInfo"`
	} `json:"resultSetMetaData"`
}

// row is one result row by lower-cased column name.
type row map[string]string

func (r row) get(k string) string { return r[strings.ToLower(k)] }

// sqlFailure is Snowflake's 422 body.
type sqlFailure struct {
	Code     string `json:"code"`
	SQLState string `json:"sqlState"`
	Message  string `json:"message"`
}

// errNotVisible marks a statement Snowflake refused because the object
// does not exist or hallpass's role may not see it.
var errNotVisible = errors.New("object not visible")

// run executes one statement and returns its rows. Statements here are
// SHOW commands built from validated identifiers.
func (c *Connection) run(ctx context.Context, statement string) ([]row, error) {
	body := map[string]any{"statement": statement, "timeout": statementTimeout}
	if c.role != "" {
		body["role"] = c.role
	}
	idem := true
	resp, err := c.api.Do(ctx, &httpx.Request{Method: http.MethodPost, Path: "/api/v2/statements", JSON: body, Idempotent: &idem, Accept4xx: true})
	if err != nil {
		var ie *integration.Error
		if errors.As(err, &ie) {
			return nil, err
		}
		return nil, httpx.Classify(err)
	}
	for attempt := 0; resp.Status == 202; attempt++ {
		// The statement is still running: poll its handle.
		var status struct {
			StatementHandle string `json:"statementHandle"`
		}
		if err := resp.JSON(&status); err != nil || !handleRe.MatchString(status.StatementHandle) {
			return nil, integration.Errorf(integration.CodeUpstreamError, "Snowflake accepted the statement without a usable handle")
		}
		if attempt >= 10 {
			return nil, integration.Errorf(integration.CodeUpstreamTimeout, "the SHOW command did not finish in time")
		}
		select {
		case <-ctx.Done():
			return nil, integration.Wrap(integration.CodeUpstreamTimeout, ctx.Err(), "the SHOW command did not finish in time")
		case <-time.After(time.Duration(200*(attempt+1)) * time.Millisecond):
		}
		resp, err = c.api.Do(ctx, &httpx.Request{Path: "/api/v2/statements/" + status.StatementHandle, Accept4xx: true})
		if err != nil {
			return nil, httpx.Classify(err)
		}
	}
	switch resp.Status {
	case 200:
	case 401:
		return nil, integration.Errorf(integration.CodeCredentialRejected, "Snowflake rejected the key-pair token (HTTP 401): check account, user and the public key registered on the user")
	case 403:
		return nil, integration.Errorf(integration.CodeCredentialRejected, "Snowflake refused the request (HTTP 403)")
	case 429:
		return nil, integration.Errorf(integration.CodeUpstreamRateLimit, "Snowflake throttled the request (HTTP 429)")
	case 408:
		return nil, integration.Errorf(integration.CodeUpstreamTimeout, "the SHOW command exceeded Snowflake's timeout")
	case 422:
		var f sqlFailure
		if err := resp.JSON(&f); err != nil {
			return nil, integration.Errorf(integration.CodeUpstreamError, "the statement failed (HTTP 422)")
		}
		return nil, classifySQL(f)
	default:
		return nil, integration.Errorf(integration.CodeUpstreamError, "Snowflake answered HTTP %d", resp.Status)
	}
	var rs resultSet
	if err := resp.JSON(&rs); err != nil {
		return nil, integration.Wrap(integration.CodeUpstreamError, err, "the result set was not JSON")
	}
	rows, err := rs.rows()
	if err != nil {
		return nil, err
	}
	for part := 1; part < len(rs.Meta.PartitionInfo); part++ {
		if !handleRe.MatchString(rs.StatementHandle) {
			return nil, integration.Errorf(integration.CodeUpstreamError, "the result set has partitions but no usable handle")
		}
		if part > httpx.MaxPages {
			return nil, integration.Errorf(integration.CodeUpstreamError, "the result set has more partitions than hallpass reads")
		}
		var more resultSet
		if _, err := c.api.GetJSON(ctx, "/api/v2/statements/"+rs.StatementHandle, map[string][]string{"partition": {fmt.Sprint(part)}}, &more); err != nil {
			return nil, httpx.Classify(err)
		}
		more.Meta.RowType = rs.Meta.RowType
		next, err := more.rows()
		if err != nil {
			return nil, err
		}
		rows = append(rows, next...)
	}
	return rows, nil
}

var handleRe = regexp.MustCompile(`^[0-9a-fA-F-]{36}$`)

// rows turns the positional data into rows keyed by column name.
func (rs *resultSet) rows() ([]row, error) {
	cols := make([]string, len(rs.Meta.RowType))
	for i, c := range rs.Meta.RowType {
		cols[i] = strings.ToLower(c.Name)
	}
	out := make([]row, 0, len(rs.Data))
	for _, d := range rs.Data {
		if len(d) != len(cols) {
			return nil, integration.Errorf(integration.CodeUpstreamError, "a result row has %d cells for %d columns", len(d), len(cols))
		}
		r := row{}
		for i, v := range d {
			r[cols[i]] = v
		}
		out = append(out, r)
	}
	return out, nil
}

// classifySQL maps a statement failure by its Snowflake error code. The
// message may echo identifiers, so only the code reaches the text.
func classifySQL(f sqlFailure) error {
	switch f.Code {
	case "002003", "002043", "090105":
		// Object does not exist or not authorized; not authorized to view.
		return errNotVisible
	case "003001", "001003":
		return integration.Errorf(integration.CodeCredentialRejected, "hallpass's role lacks the privilege for the command (Snowflake error %s); it needs MANAGE GRANTS", f.Code)
	case "390144", "390142", "390143", "390318":
		return integration.Errorf(integration.CodeCredentialRejected, "Snowflake rejected the key-pair token (error %s)", f.Code)
	case "000630", "000604":
		return integration.Errorf(integration.CodeUpstreamTimeout, "the statement was cancelled or timed out (error %s)", f.Code)
	}
	return integration.Errorf(integration.CodeUpstreamError, "the statement failed (Snowflake error %s, SQL state %s)", orEmpty(f.Code, "unknown"), orEmpty(f.SQLState, "unknown"))
}

func orEmpty(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// --- identity ---------------------------------------------------------------

// ResolveIdentity finds the user by email: first SHOW USERS LIKE the
// address (SCIM-provisioned users are named by their address), then a scan
// of SHOW USERS matching email and login_name. The identity's groups are
// the roles granted directly to the user.
func (c *Connection) ResolveIdentity(ctx context.Context, u integration.User) (integration.Identity, error) {
	email := strings.ToLower(strings.TrimSpace(u.Email))
	if !integration.IsEmail(email) {
		return integration.Identity{}, integration.Errorf(integration.CodeInvalidRequest, "user email %q is not an address", email)
	}
	match := func(r row) bool {
		return strings.EqualFold(r.get("name"), email) || strings.EqualFold(r.get("login_name"), email) || strings.EqualFold(r.get("email"), email)
	}
	rows, err := c.run(ctx, "SHOW USERS LIKE "+likeLiteral(email))
	if err != nil {
		return integration.Identity{}, c.identityErr(err, "list users")
	}
	var found []row
	for _, r := range rows {
		if match(r) {
			found = append(found, r)
		}
	}
	if len(found) == 0 {
		// Users named otherwise: scan by email and login name, page by page.
		after := ""
		for page := 0; page < maxUserPages; page++ {
			stmt := fmt.Sprintf("SHOW USERS LIMIT %d", userPage)
			if after != "" {
				stmt += " FROM " + stringLiteral(after)
			}
			rows, err := c.run(ctx, stmt)
			if err != nil {
				return integration.Identity{}, c.identityErr(err, "list users")
			}
			for _, r := range rows {
				if match(r) {
					found = append(found, r)
				}
			}
			if len(rows) < userPage {
				break
			}
			after = rows[len(rows)-1].get("name")
			if after == "" {
				break
			}
		}
	}
	switch len(found) {
	case 0:
		return integration.Identity{}, integration.UserNotFound("no Snowflake user is named %s or has it as login name or email", email)
	case 1:
	default:
		return integration.Identity{}, integration.UserAmbiguous("%d Snowflake users have %s as name, login name or email", len(found), email)
	}
	usr := found[0]
	name := usr.get("name")
	if name == "" {
		return integration.Identity{}, integration.Errorf(integration.CodeUpstreamError, "SHOW USERS returned a user without a name")
	}
	id := integration.Identity{ID: name, Display: email, Attrs: map[string]string{
		"login_name":              usr.get("login_name"),
		"disabled":                strings.ToLower(orEmpty(usr.get("disabled"), "unknown")),
		"default_role":            usr.get("default_role"),
		"default_secondary_roles": usr.get("default_secondary_roles"),
		"type":                    usr.get("type"),
	}}
	roles, err := c.userRoles(ctx, name)
	if err != nil {
		return integration.Identity{}, err
	}
	id.Groups = roles
	return id, nil
}

// identityErr maps a failure of the user listing.
func (c *Connection) identityErr(err error, what string) error {
	if errors.Is(err, errNotVisible) {
		return integration.Errorf(integration.CodeCredentialRejected, "hallpass's role may not %s; it needs MANAGE GRANTS", what)
	}
	return err
}

// userRoles lists the roles granted directly to the user. SHOW GRANTS TO
// USER historically has a role column; since the 2025_01 change bundle it
// is shaped like SHOW GRANTS TO ROLE (privilege USAGE, granted_on ROLE,
// name). UNVERIFIED: the exact columns of the new shape; both are read.
func (c *Connection) userRoles(ctx context.Context, name string) ([]string, error) {
	rows, err := c.run(ctx, "SHOW GRANTS TO USER "+quote(name))
	if err != nil {
		if errors.Is(err, errNotVisible) {
			return nil, integration.Errorf(integration.CodeCredentialRejected, "hallpass's role may not read the grants of user %s; it needs MANAGE GRANTS", quote(name))
		}
		return nil, err
	}
	seen := map[string]bool{}
	var roles []string
	for _, r := range rows {
		role := r.get("role")
		if role == "" && strings.EqualFold(r.get("granted_on"), "ROLE") {
			role = r.get("name")
		}
		if role == "" || seen[role] {
			continue
		}
		seen[role] = true
		roles = append(roles, role)
	}
	sort.Strings(roles)
	return roles, nil
}

// --- grants -----------------------------------------------------------------

// grant is one SHOW GRANTS TO ROLE row.
type grant struct {
	privilege, grantedOn, name, grantedBy string
}

// roleGrants reads SHOW GRANTS TO ROLE (or DATABASE ROLE), cached.
func (c *Connection) roleGrants(ctx context.Context, role string, database bool) ([]grant, error) {
	key := "R:" + role
	stmt := "SHOW GRANTS TO ROLE " + quote(role)
	if database {
		parts, err := splitName(role)
		if err != nil || len(parts) != 2 {
			return nil, integration.Errorf(integration.CodeUpstreamError, "database role %q is not <database>.<role>", role)
		}
		key = "D:" + role
		// UNVERIFIED: the name column spells database roles as
		// <database>.<role>; both parts are re-quoted.
		stmt = "SHOW GRANTS TO DATABASE ROLE " + quote(parts[0]) + "." + quote(parts[1])
	}
	return c.grants.Do(ctx, key, func(ctx context.Context) ([]grant, time.Duration, error) {
		rows, err := c.run(ctx, stmt)
		if err != nil {
			if errors.Is(err, errNotVisible) {
				return nil, 0, integration.Errorf(integration.CodeResourceNotVisible, "role %s is granted but hallpass's role may not read its grants; it needs MANAGE GRANTS", quote(role))
			}
			return nil, 0, err
		}
		out := make([]grant, 0, len(rows))
		for _, r := range rows {
			out = append(out, grant{privilege: strings.ToUpper(r.get("privilege")), grantedOn: strings.ToUpper(r.get("granted_on")), name: r.get("name"), grantedBy: r.get("granted_by")})
		}
		return out, grantsTTL, nil
	})
}

// holding is a privilege found on the object: which role holds it and by
// which chain of roles the user reaches it.
type holding struct {
	privilege string
	role      string
	chain     []string
}

// walk collects the grants reachable from the user's roles through the
// role hierarchy. It returns every grant with the role chain it came by.
func (c *Connection) walk(ctx context.Context, roles []string) ([]holding, map[string][]string, error) {
	type item struct {
		role     string
		database bool
		chain    []string
	}
	queue := make([]item, 0, len(roles))
	for _, r := range roles {
		queue = append(queue, item{role: r, chain: []string{r}})
	}
	visited := map[string]bool{}
	reach := map[string][]string{} // role -> chain
	var holdings []holding
	for len(queue) > 0 {
		it := queue[0]
		queue = queue[1:]
		key := it.role
		if it.database {
			key = "DB:" + it.role
		}
		if visited[key] {
			continue
		}
		if len(visited) >= maxRoles {
			return nil, nil, integration.Errorf(integration.CodeUnsupported, "the role hierarchy has more than %d roles; hallpass stops walking it", maxRoles)
		}
		visited[key] = true
		reach[key] = it.chain
		grants, err := c.roleGrants(ctx, it.role, it.database)
		if err != nil {
			return nil, nil, err
		}
		for _, g := range grants {
			switch {
			case g.grantedOn == "ROLE" && g.privilege == "USAGE":
				queue = append(queue, item{role: g.name, chain: append(append([]string{}, it.chain...), g.name)})
			case g.grantedOn == "DATABASE_ROLE" && g.privilege == "USAGE":
				queue = append(queue, item{role: g.name, database: true, chain: append(append([]string{}, it.chain...), g.name)})
			default:
				holdings = append(holdings, holding{privilege: g.privilege, role: it.role, chain: it.chain})
				holdings[len(holdings)-1].chain = it.chain
				// Keep the object with the holding.
				holdings[len(holdings)-1] = holding{privilege: g.privilege + "\x00" + g.grantedOn + "\x00" + g.name, role: it.role, chain: it.chain}
			}
		}
	}
	return holdings, reach, nil
}

// split unpacks the packed privilege/grantedOn/name of a holding.
func (h holding) split() (privilege, grantedOn string, name []string) {
	parts := strings.SplitN(h.privilege, "\x00", 3)
	if len(parts) != 3 {
		return h.privilege, "", nil
	}
	n, err := splitName(parts[2])
	if err != nil {
		return parts[0], parts[1], nil
	}
	resolved := make([]string, 0, len(n))
	for _, p := range n {
		id, err := parseIdentifier(p)
		if err != nil {
			return parts[0], parts[1], nil
		}
		resolved = append(resolved, id)
	}
	return parts[0], parts[1], resolved
}

// --- checks -----------------------------------------------------------------

// Check answers one question.
func (c *Connection) Check(ctx context.Context, r integration.CheckRequest) (integration.Decision, error) {
	t, err := parseTarget(r.ActionName, r.Resource)
	if err != nil {
		return integration.Decision{}, err
	}
	id := r.Identity
	who := id.Display
	switch id.Attr("disabled") {
	case "false":
	case "true":
		return integration.Denied("user %s (%s) is disabled", quote(id.ID), who), nil
	default:
		return integration.Unsupported("SHOW USERS did not report whether %s is disabled", quote(id.ID)), nil
	}
	if len(id.Groups) == 0 {
		return integration.Denied("no role is granted to user %s (%s)", quote(id.ID), who), nil
	}
	holdings, reach, err := c.walk(ctx, id.Groups)
	if err != nil {
		return integration.ToDecision(err), nil
	}
	if t.action.name == "role.use" {
		if chain, ok := reach[t.name[0]]; ok {
			return integration.Allowed("role %s is granted to %s %s", quote(t.name[0]), who, via(chain)), nil
		}
		return integration.Denied("role %s is not granted to %s, directly or through the %d role(s) they hold", quote(t.name[0]), who, len(reach)), nil
	}
	kind := kinds[t.kind]
	// The privilege on the object itself.
	found := find(holdings, kind.grantedOn, t.name, t.action.privileges)
	if found == nil {
		return integration.Denied("none of the %d role(s) %s holds carries %s on %s (or the object does not exist)", len(reach), who, strings.Join(t.action.privileges, " or "), t), nil
	}
	// USAGE on the parents: the database, and the schema for objects in one.
	// UNVERIFIED: standard Snowflake behaviour, not quoted from the docs.
	if kind.parts >= 2 {
		if p := find(holdings, []string{"DATABASE"}, t.name[:1], []string{"USAGE"}); p == nil {
			return integration.Denied("%s holds %s on %s but no role holds USAGE on database %s", who, found.privilege, t, quote(t.name[0])), nil
		}
	}
	if kind.parts >= 3 {
		if p := find(holdings, []string{"SCHEMA"}, t.name[:2], []string{"USAGE"}); p == nil {
			return integration.Denied("%s holds %s on %s but no role holds USAGE on schema %s", who, found.privilege, t, quoteName(t.name[:2])), nil
		}
	}
	return integration.Allowed("role %s holds %s on %s; %s has it %s", quote(found.role), found.privilege, t, who, via(found.chain)), nil
}

// find returns the first holding of one of the privileges (or OWNERSHIP)
// on an object of one of the kinds with the name.
func find(holdings []holding, grantedOn []string, name []string, privileges []string) *holding {
	for i := range holdings {
		priv, on, n := holdings[i].split()
		okKind := false
		for _, k := range grantedOn {
			if on == k {
				okKind = true
			}
		}
		if !okKind {
			continue
		}
		if len(name) > 0 && !sameName(n, name) {
			continue
		}
		if len(name) == 0 && len(n) != 0 && on != "ACCOUNT" {
			continue
		}
		if priv == "OWNERSHIP" {
			h := holdings[i]
			h.privilege = "OWNERSHIP"
			return &h
		}
		for _, p := range privileges {
			if priv == p {
				h := holdings[i]
				h.privilege = p
				return &h
			}
		}
	}
	return nil
}

// via words a role chain.
func via(chain []string) string {
	if len(chain) <= 1 {
		return "directly"
	}
	q := make([]string, len(chain))
	for i, r := range chain {
		q[i] = quote(r)
	}
	return "through " + strings.Join(q, " -> ")
}

// --- probe ------------------------------------------------------------------

// Probe lists hallpass's own grants and warns when MANAGE GRANTS is absent.
func (c *Connection) Probe(ctx context.Context) (integration.ProbeResult, error) {
	roles, err := c.userRoles(ctx, c.user)
	if err != nil {
		return integration.ProbeResult{}, err
	}
	res := integration.ProbeResult{Summary: fmt.Sprintf("authenticated as %s with roles %s", quote(c.user), strings.Join(roles, ", "))}
	holdings, _, err := c.walk(ctx, roles)
	if err != nil {
		return integration.ProbeResult{}, err
	}
	if find(holdings, []string{"ACCOUNT"}, nil, []string{"MANAGE GRANTS"}) == nil {
		res.Warnings = append(res.Warnings, "none of hallpass's roles holds MANAGE GRANTS: SHOW GRANTS on other users and roles answers only for objects hallpass's role can see")
	}
	res.Warnings = append(res.Warnings, "the answer is the union of every role granted to the user; a session activates one primary role plus secondary roles")
	return res, nil
}
