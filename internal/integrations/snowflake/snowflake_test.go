package snowflake

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/roee-hersh/hallpass/internal/authx"
	"github.com/roee-hersh/hallpass/internal/integration"
	"github.com/roee-hersh/hallpass/internal/integration/itest"
	"github.com/roee-hersh/hallpass/internal/secret"
)

var (
	keyOnce sync.Once
	testKey *rsa.PrivateKey
	testPEM string
)

func signingKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	keyOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		testKey = k
		der, _ := x509.MarshalPKCS8PrivateKey(k)
		testPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	})
	return testKey, testPEM
}

var (
	dana = integration.User{Email: "dana@example.com"} // DANA: ANALYST
	bob  = integration.User{Email: "bob@example.com"}  // named by email: DEV (owns DEV.PLAY), inherits READER
	ops  = integration.User{Email: "ops@example.com"}  // OPS: OPS_ADMIN -> DEV -> READER, database role PROD.DBROLE
	none = integration.User{Email: "none@example.com"} // NOROLE
)

type fakeUser struct {
	name, login, email string
	disabled           bool
	roles              []string
}

type fake struct {
	t  *testing.T
	mu sync.Mutex

	pub        *rsa.PublicKey
	users      []fakeUser
	roleGrants map[string][][4]string // role -> rows of privilege, granted_on, name, granted_by
	dbRoles    map[string][][4]string // "DB"."ROLE" -> rows
	hidden     map[string]bool        // roles hallpass's role may not see
	newShape   bool                   // SHOW GRANTS TO USER in the 2025 shape
	statements []string
	status     int
	pending    int // answer this many statements with 202 first
	partitions int // split result sets into this many partitions
	results    map[string]resultSet
}

func newFake(t *testing.T) *fake {
	return &fake{t: t, partitions: 1, results: map[string]resultSet{},
		users: []fakeUser{
			{"HALLPASS", "hallpass", "", false, []string{"SECADMIN"}},
			{"DANA", "dana@example.com", "dana@example.com", false, []string{"ANALYST"}},
			{"bob@example.com", "bob@example.com", "bob@example.com", false, []string{"DEV"}},
			{"OPS", "ops", "ops@example.com", false, []string{"OPS_ADMIN"}},
			{"OFF", "off", "off@example.com", true, []string{"ANALYST"}},
			{"NOROLE", "norole", "none@example.com", false, nil},
			{"DUP1", "dup1", "dup@example.com", false, nil},
			{"DUP2", "dup@example.com", "other@example.com", false, nil},
			{"TWICE1", "twice1", "twice@example.com", false, nil},
			{"TWICE2", "twice2", "twice@example.com", false, nil},
			// An email that contains another; matching is exact.
			{"DANAAU", "danaau", "dana@example.com.au", false, []string{"OPS_ADMIN"}},
		},
		roleGrants: map[string][][4]string{
			"ANALYST": {
				{"USAGE", "DATABASE", "PROD", "SYSADMIN"},
				{"USAGE", "SCHEMA", "PROD.SALES", "SYSADMIN"},
				{"SELECT", "TABLE", "PROD.SALES.ORDERS", "SYSADMIN"},
				{"SELECT", "VIEW", "PROD.SALES.V_ORDERS", "SYSADMIN"},
				{"SELECT", "TABLE", `PROD.SALES."Mixed Case"`, "SYSADMIN"},
				{"SELECT", "TABLE", "PROD.HR.SALARIES", "SYSADMIN"}, // no USAGE on PROD.HR
				{"USAGE", "WAREHOUSE", "ANALYTICS_WH", "SYSADMIN"},
			},
			"DEV": {
				{"USAGE", "DATABASE", "DEV", "SYSADMIN"},
				{"OWNERSHIP", "SCHEMA", "DEV.PLAY", "SYSADMIN"},
				{"INSERT", "TABLE", "DEV.PLAY.T", "SYSADMIN"},
				{"USAGE", "ROLE", "READER", "SECURITYADMIN"},
			},
			"READER": {
				{"USAGE", "DATABASE", "DEV", "SYSADMIN"},
				{"USAGE", "SCHEMA", "DEV.PLAY", "SYSADMIN"},
				{"SELECT", "TABLE", "DEV.PLAY.T", "SYSADMIN"},
				{"USAGE", "ROLE", `"mixed role"`, "SECURITYADMIN"},
			},
			"mixed role": {
				{"USAGE", "WAREHOUSE", "SMALL_WH", "SYSADMIN"},
			},
			"OPS_ADMIN": {
				{"USAGE", "ROLE", "DEV", "SECURITYADMIN"},
				{"OPERATE", "WAREHOUSE", "ANALYTICS_WH", "SYSADMIN"},
				{"MODIFY", "WAREHOUSE", "ANALYTICS_WH", "SYSADMIN"},
				{"CREATE DATABASE", "ACCOUNT", "MYORG-MYACCOUNT", "SYSADMIN"},
				{"USAGE", "DATABASE_ROLE", "PROD.DBROLE", "SYSADMIN"},
				{"USAGE", "ROLE", "OPS_ADMIN", "SECURITYADMIN"}, // a cycle, must not loop
			},
			"SECADMIN": {
				{"MANAGE GRANTS", "ACCOUNT", "MYORG-MYACCOUNT", "ACCOUNTADMIN"},
			},
			"PUBLIC": {
				{"USAGE", "DATABASE", "PUB", "SYSADMIN"},
			},
		},
		dbRoles: map[string][][4]string{
			`"PROD"."DBROLE"`: {
				{"USAGE", "DATABASE", "PROD", "SYSADMIN"},
				{"USAGE", "SCHEMA", "PROD.SALES", "SYSADMIN"},
				{"SELECT", "TABLE", "PROD.SALES.ORDERS", "SYSADMIN"},
			},
		},
		hidden: map[string]bool{},
	}
}

func write(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func sqlErr(w http.ResponseWriter, code string) {
	write(w, 422, map[string]any{"code": code, "sqlState": "42501", "message": "SQL access control error: " + itest.Canary, "statementHandle": "01b0f0f0-0000-0000-0000-000000000001", "createdOn": 1700000000000, "statementStatusUrl": "/api/v2/statements/x"})
}

// table builds a result set from column names and rows.
func table(cols []string, rows [][]string) resultSet {
	var rs resultSet
	rs.Code, rs.SQLState, rs.Message = "090001", "00000", "Statement executed successfully."
	rs.StatementHandle = "01b0f0f0-0000-0000-0000-000000000002"
	for _, c := range cols {
		rs.Meta.RowType = append(rs.Meta.RowType, struct {
			Name string `json:"name"`
		}{c})
	}
	rs.Data = rows
	rs.Meta.NumRows = len(rows)
	return rs
}

func (f *fake) verifyJWT(r *http.Request) bool {
	if r.Header.Get("X-Snowflake-Authorization-Token-Type") != "KEYPAIR_JWT" {
		return false
	}
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || authx.Verify(f.pub, authx.RS256, []byte(parts[0]+"."+parts[1]), sig) != nil {
		return false
	}
	var claims struct {
		Iss, Sub string
		Exp, Iat int64
	}
	if err := authx.DecodeJWTClaims(tok, &claims); err != nil {
		return false
	}
	fp := fingerprint(f.pub)
	if claims.Sub != "MYORG-MYACCOUNT.HALLPASS" || claims.Iss != "MYORG-MYACCOUNT.HALLPASS."+fp || claims.Exp <= claims.Iat {
		f.t.Errorf("jwt claims %+v", claims)
		return false
	}
	return true
}

var (
	likeRe    = regexp.MustCompile(`^SHOW USERS LIKE '(.*)'$`)
	limitRe   = regexp.MustCompile(`^SHOW USERS LIMIT (\d+)(?: FROM '(.*)')?$`)
	toUserRe  = regexp.MustCompile(`^SHOW GRANTS TO USER "((?:[^"]|"")+)"$`)
	toRoleRe  = regexp.MustCompile(`^SHOW GRANTS TO ROLE "((?:[^"]|"")+)"$`)
	toDBRole  = regexp.MustCompile(`^SHOW GRANTS TO DATABASE ROLE ("(?:[^"]|"")+"\."(?:[^"]|"")+")$`)
	userCols  = []string{"name", "created_on", "login_name", "display_name", "first_name", "last_name", "email", "mins_to_unlock", "days_to_expiry", "comment", "disabled", "must_change_password", "snowflake_lock", "default_warehouse", "default_namespace", "default_role", "default_secondary_roles", "ext_authn_duo", "ext_authn_uid", "mins_to_bypass_mfa", "owner", "last_success_login", "expires_at_time", "locked_until_time", "has_password", "has_rsa_public_key", "type"}
	grantCols = []string{"created_on", "privilege", "granted_on", "name", "granted_to", "grantee_name", "grant_option", "granted_by_role_type", "granted_by"}
)

func unquoteSQL(s string) string {
	return strings.ReplaceAll(strings.Trim(s, `"`), `""`, `"`)
}

func (f *fake) userRow(u fakeUser) []string {
	r := make([]string, len(userCols))
	for i, c := range userCols {
		switch c {
		case "name":
			r[i] = u.name
		case "login_name":
			r[i] = u.login
		case "email":
			r[i] = u.email
		case "disabled":
			r[i] = fmt.Sprint(u.disabled)
		case "default_role":
			if len(u.roles) > 0 {
				r[i] = u.roles[0]
			}
		case "default_secondary_roles":
			r[i] = `["ALL"]`
		case "comment", "display_name":
			r[i] = itest.Canary
		case "type":
			r[i] = "PERSON"
		default:
			r[i] = "null"
		}
	}
	return r
}

func (f *fake) execute(stmt string) (resultSet, string) {
	switch {
	case likeRe.MatchString(stmt):
		pat := likeRe.FindStringSubmatch(stmt)[1]
		// In SQL text the LIKE escapes are \\_ and \\% and a literal
		// backslash is \\\\.
		pat = strings.NewReplacer(`\\%`, "%", `\\_`, "_", `''`, "'", `\\\\`, `\`).Replace(pat)
		var rows [][]string
		for _, u := range f.users {
			if strings.EqualFold(u.name, pat) {
				rows = append(rows, f.userRow(u))
			}
		}
		return table(userCols, rows), ""
	case limitRe.MatchString(stmt):
		m := limitRe.FindStringSubmatch(stmt)
		var limit int
		fmt.Sscanf(m[1], "%d", &limit)
		after := strings.ReplaceAll(m[2], "''", "'")
		var rows [][]string
		started := after == ""
		for _, u := range f.users {
			if !started {
				if u.name == after {
					started = true
				}
				continue
			}
			rows = append(rows, f.userRow(u))
			if len(rows) >= limit {
				break
			}
		}
		return table(userCols, rows), ""
	case toUserRe.MatchString(stmt):
		name := unquoteSQL(toUserRe.FindStringSubmatch(stmt)[1])
		for _, u := range f.users {
			if u.name != name {
				continue
			}
			var rows [][]string
			for _, r := range u.roles {
				if f.newShape {
					rows = append(rows, []string{"2026-01-01", "USAGE", "ROLE", r, "USER", u.name, "false", "ROLE", "SECURITYADMIN"})
				} else {
					rows = append(rows, []string{"2026-01-01", r, "USER", u.name, "SECURITYADMIN"})
				}
			}
			if f.newShape {
				return table(grantCols, rows), ""
			}
			return table([]string{"created_on", "role", "granted_to", "grantee_name", "granted_by"}, rows), ""
		}
		return resultSet{}, "002003"
	case toRoleRe.MatchString(stmt):
		role := unquoteSQL(toRoleRe.FindStringSubmatch(stmt)[1])
		grants, ok := f.roleGrants[role]
		if !ok || f.hidden[role] {
			return resultSet{}, "002003"
		}
		var rows [][]string
		for _, g := range grants {
			rows = append(rows, []string{"2026-01-01", g[0], g[1], g[2], "ROLE", role, "false", "ROLE", g[3]})
		}
		return table(grantCols, rows), ""
	case toDBRole.MatchString(stmt):
		grants, ok := f.dbRoles[toDBRole.FindStringSubmatch(stmt)[1]]
		if !ok {
			return resultSet{}, "002003"
		}
		var rows [][]string
		for _, g := range grants {
			rows = append(rows, []string{"2026-01-01", g[0], g[1], g[2], "DATABASE_ROLE", "PROD.DBROLE", "false", "ROLE", g[3]})
		}
		return table(grantCols, rows), ""
	}
	f.t.Errorf("fake: unexpected statement %q", stmt)
	return resultSet{}, "000001"
}

func (f *fake) api(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.verifyJWT(r) {
		write(w, 401, map[string]any{"code": "390144", "message": "JWT token is invalid. " + itest.Canary, "sqlState": "08001"})
		return
	}
	if f.status != 0 {
		write(w, f.status, map[string]any{"code": "000000", "message": itest.Canary})
		return
	}
	p := r.URL.Path
	switch {
	case p == "/api/v2/statements" && r.Method == http.MethodPost:
		var body struct {
			Statement string `json:"statement"`
			Timeout   int    `json:"timeout"`
			Role      string `json:"role"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			f.t.Errorf("bad body: %v", err)
		}
		if body.Role != "SECADMIN" {
			f.t.Errorf("statement without the configured role: %+v", body)
		}
		f.statements = append(f.statements, body.Statement)
		rs, code := f.execute(body.Statement)
		if code != "" {
			sqlErr(w, code)
			return
		}
		handle := fmt.Sprintf("01b0f0f0-0000-0000-0000-%012d", len(f.statements))
		rs.StatementHandle = handle
		f.results[handle] = rs // the full result; views are cut per request
		if f.pending > 0 {
			f.pending--
			write(w, 202, map[string]any{"code": "333334", "sqlState": "00000", "message": "Asynchronous execution in progress.", "statementHandle": handle, "createdOn": 1700000000000, "statementStatusUrl": "/api/v2/statements/" + handle})
			return
		}
		write(w, 200, f.partition(rs, 0))
	case strings.HasPrefix(p, "/api/v2/statements/") && r.Method == http.MethodGet:
		handle := strings.TrimPrefix(p, "/api/v2/statements/")
		rs, ok := f.results[handle]
		if !ok {
			write(w, 404, map[string]any{"code": "000000", "message": itest.Canary})
			return
		}
		n := 0
		if part := r.URL.Query().Get("partition"); part != "" {
			fmt.Sscanf(part, "%d", &n)
		}
		page := f.partition(rs, n)
		if n > 0 {
			page.Meta.RowType = nil
		}
		write(w, 200, page)
	default:
		f.t.Errorf("fake: no route for %s %s", r.Method, p)
		write(w, 404, map[string]any{"message": itest.Canary})
	}
}

// partition returns partition n of a result set: the whole set when the
// fake is not partitioning or the set is small, else its n-th slice with
// the partition table attached.
func (f *fake) partition(rs resultSet, n int) resultSet {
	if f.partitions <= 1 || len(rs.Data) < f.partitions {
		return rs
	}
	per := (len(rs.Data) + f.partitions - 1) / f.partitions
	page := rs
	page.Meta.PartitionInfo = nil
	for i := 0; i < f.partitions; i++ {
		lo, hi := i*per, (i+1)*per
		if hi > len(rs.Data) {
			hi = len(rs.Data)
		}
		page.Meta.PartitionInfo = append(page.Meta.PartitionInfo, struct {
			RowCount int `json:"rowCount"`
		}{hi - lo})
	}
	lo, hi := n*per, (n+1)*per
	if hi > len(rs.Data) {
		hi = len(rs.Data)
	}
	if lo > hi {
		lo = hi
	}
	page.Data = rs.Data[lo:hi]
	return page
}

func newServer(t *testing.T) (*itest.Server, *fake) {
	t.Helper()
	srv := itest.NewServer(t)
	srv.UseSpec(itest.SpecFromEnv(t, "snowflake-sqlapi"), itest.SpecOptions{AllowQuery: []string{"partition"}})
	f := newFake(t)
	key, _ := signingKey(t)
	f.pub = &key.PublicKey
	srv.Handle("", "/api/*", f.api)
	return srv, f
}

func setup(t *testing.T) (*itest.Server, *fake, integration.Connection) {
	t.Helper()
	srv, f := newServer(t)
	deps, _ := itest.Deps(t, srv)
	_, pemKey := signingKey(t)
	s := itest.Settings("sf", "snowflake", map[string]string{"account": "myorg-myaccount", "user": "hallpass", "role": "secadmin", "url": srv.URL},
		map[string]secret.Secret{"credential": secret.Literal(pemKey)})
	c, err := (Integration{}).New(context.Background(), s, deps)
	if err != nil {
		t.Fatal(err)
	}
	return srv, f, c
}

func check(t *testing.T, c integration.Connection, u integration.User, action, resource string) integration.Decision {
	t.Helper()
	return itest.Check(t, c, Integration{}, u, action, resource)
}

func expect(t *testing.T, d integration.Decision, code integration.Code, text string) {
	t.Helper()
	itest.ExpectCode(t, d, code)
	if text != "" && !strings.Contains(d.Text, text) {
		t.Errorf("text %q does not contain %q", d.Text, text)
	}
	itest.AssertNoCanary(t, d.Text)
}

// --- the action table -------------------------------------------------------

func TestAction_table_select_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, dana, "table.select", "table:prod.sales.orders"), integration.CodeAllowed, `role "ANALYST" holds SELECT on table "PROD"."SALES"."ORDERS"; dana@example.com has it directly`)
	// A view, and a quoted case-sensitive name.
	expect(t, check(t, c, dana, "table.select", "table:PROD.SALES.V_ORDERS"), integration.CodeAllowed, "")
	expect(t, check(t, c, dana, "table.select", `table:prod.sales."Mixed Case"`), integration.CodeAllowed, `"Mixed Case"`)
	// Through the role hierarchy: bob -> DEV -> READER.
	expect(t, check(t, c, bob, "table.select", "table:dev.play.t"), integration.CodeAllowed, `through "DEV" -> "READER"`)
	// Through a database role: OPS -> OPS_ADMIN -> PROD.DBROLE.
	expect(t, check(t, c, ops, "table.select", "table:prod.sales.orders"), integration.CodeAllowed, `through "OPS_ADMIN" -> "PROD"."DBROLE"`)
}
func TestAction_table_select_deny(t *testing.T) {
	_, _, c := setup(t)
	// ANALYST and PUBLIC.
	expect(t, check(t, c, dana, "table.select", "table:dev.play.t"), integration.CodeDenied, "none of the 2 role(s) dana@example.com holds carries SELECT")
	// SELECT without USAGE on the schema.
	expect(t, check(t, c, dana, "table.select", "table:prod.hr.salaries"), integration.CodeDenied, `no role holds USAGE on schema "PROD"."HR"`)
	// Case matters for quoted names.
	expect(t, check(t, c, dana, "table.select", `table:prod.sales."mixed case"`), integration.CodeDenied, "")
	// Only PUBLIC, which every user holds.
	expect(t, check(t, c, none, "table.select", "table:prod.sales.orders"), integration.CodeDenied, "none of the 1 role(s)")
}
func TestAction_table_insert_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, bob, "table.insert", "table:dev.play.t"), integration.CodeAllowed, "INSERT")
}
func TestAction_table_insert_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, dana, "table.insert", "table:prod.sales.orders"), integration.CodeDenied, "")
	// READER alone has SELECT only; ops reaches DEV, which has INSERT.
	expect(t, check(t, c, ops, "table.insert", "table:dev.play.t"), integration.CodeAllowed, `through "OPS_ADMIN" -> "DEV"`)
}
func TestAction_table_update_allow(t *testing.T) {
	_, f, c := setup(t)
	f.mu.Lock()
	f.roleGrants["DEV"] = append(f.roleGrants["DEV"], [4]string{"UPDATE", "TABLE", "DEV.PLAY.T", "SYSADMIN"})
	f.mu.Unlock()
	expect(t, check(t, c, bob, "table.update", "table:dev.play.t"), integration.CodeAllowed, "UPDATE")
}
func TestAction_table_update_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, bob, "table.update", "table:dev.play.t"), integration.CodeDenied, "")
}
func TestAction_table_delete_allow(t *testing.T) {
	_, f, c := setup(t)
	f.mu.Lock()
	// OWNERSHIP of the table answers everything on it.
	f.roleGrants["DEV"] = append(f.roleGrants["DEV"], [4]string{"OWNERSHIP", "TABLE", "DEV.PLAY.OWNED", "SYSADMIN"})
	f.mu.Unlock()
	expect(t, check(t, c, bob, "table.delete", "table:dev.play.owned"), integration.CodeAllowed, "OWNERSHIP")
}
func TestAction_table_delete_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, bob, "table.delete", "table:dev.play.t"), integration.CodeDenied, "")
}
func TestAction_table_truncate_allow(t *testing.T) {
	_, f, c := setup(t)
	f.mu.Lock()
	f.roleGrants["DEV"] = append(f.roleGrants["DEV"], [4]string{"TRUNCATE", "TABLE", "DEV.PLAY.T", "SYSADMIN"})
	f.mu.Unlock()
	expect(t, check(t, c, bob, "table.truncate", "table:dev.play.t"), integration.CodeAllowed, "")
}
func TestAction_table_truncate_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, bob, "table.truncate", "table:dev.play.t"), integration.CodeDenied, "")
}
func TestAction_schema_usage_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, dana, "schema.usage", "schema:prod.sales"), integration.CodeAllowed, "USAGE")
	// The owner of the schema.
	expect(t, check(t, c, bob, "schema.usage", "schema:dev.play"), integration.CodeAllowed, "OWNERSHIP")
}
func TestAction_schema_usage_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, dana, "schema.usage", "schema:prod.hr"), integration.CodeDenied, "")
	expect(t, check(t, c, bob, "schema.usage", "schema:prod.sales"), integration.CodeDenied, "")
}
func TestAction_schema_create_table_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, bob, "schema.create_table", "schema:dev.play"), integration.CodeAllowed, "OWNERSHIP")
}
func TestAction_schema_create_table_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, dana, "schema.create_table", "schema:prod.sales"), integration.CodeDenied, "")
}
func TestAction_schema_create_view_allow(t *testing.T) {
	_, f, c := setup(t)
	f.mu.Lock()
	f.roleGrants["ANALYST"] = append(f.roleGrants["ANALYST"], [4]string{"CREATE VIEW", "SCHEMA", "PROD.SALES", "SYSADMIN"})
	f.mu.Unlock()
	expect(t, check(t, c, dana, "schema.create_view", "schema:prod.sales"), integration.CodeAllowed, "CREATE VIEW")
}
func TestAction_schema_create_view_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, dana, "schema.create_view", "schema:prod.sales"), integration.CodeDenied, "")
}
func TestAction_database_usage_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, dana, "database.usage", "database:prod"), integration.CodeAllowed, "")
}
func TestAction_database_usage_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, dana, "database.usage", "database:dev"), integration.CodeDenied, "")
}
func TestPublicRole(t *testing.T) {
	_, _, c := setup(t)
	// A grant to PUBLIC reaches a user with no role of their own.
	expect(t, check(t, c, none, "database.usage", "database:pub"), integration.CodeAllowed, `role "PUBLIC" holds USAGE`)
	expect(t, check(t, c, none, "role.use", "role:public"), integration.CodeAllowed, "")
}
func TestAction_database_create_schema_allow(t *testing.T) {
	_, f, c := setup(t)
	f.mu.Lock()
	f.roleGrants["DEV"] = append(f.roleGrants["DEV"], [4]string{"CREATE SCHEMA", "DATABASE", "DEV", "SYSADMIN"})
	f.mu.Unlock()
	expect(t, check(t, c, bob, "database.create_schema", "database:dev"), integration.CodeAllowed, "")
}
func TestAction_database_create_schema_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, bob, "database.create_schema", "database:dev"), integration.CodeDenied, "")
}
func TestAction_warehouse_usage_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, dana, "warehouse.usage", "warehouse:analytics_wh"), integration.CodeAllowed, "")
}
func TestAction_warehouse_usage_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, bob, "warehouse.usage", "warehouse:analytics_wh"), integration.CodeDenied, "")
	expect(t, check(t, c, ops, "warehouse.usage", "warehouse:analytics_wh"), integration.CodeDenied, "")
}
func TestAction_warehouse_operate_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, ops, "warehouse.operate", "warehouse:analytics_wh"), integration.CodeAllowed, "OPERATE")
}
func TestAction_warehouse_operate_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, dana, "warehouse.operate", "warehouse:analytics_wh"), integration.CodeDenied, "")
}
func TestAction_warehouse_modify_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, ops, "warehouse.modify", "warehouse:analytics_wh"), integration.CodeAllowed, "")
}
func TestAction_warehouse_modify_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, dana, "warehouse.modify", "warehouse:analytics_wh"), integration.CodeDenied, "")
}
func TestAction_role_use_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, dana, "role.use", "role:analyst"), integration.CodeAllowed, "directly")
	expect(t, check(t, c, ops, "role.use", "role:reader"), integration.CodeAllowed, `through "OPS_ADMIN" -> "DEV" -> "READER"`)
}
func TestQuotedRoleName(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, bob, "role.use", `role:"mixed role"`), integration.CodeAllowed, `"mixed role"`)
	expect(t, check(t, c, bob, "warehouse.usage", "warehouse:small_wh"), integration.CodeAllowed, `role "mixed role"`)
	expect(t, check(t, c, bob, "role.use", "role:mixed_role"), integration.CodeDenied, "")
}

func TestAction_role_use_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, dana, "role.use", "role:dev"), integration.CodeDenied, "not granted")
}
func TestAction_account_create_database_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, ops, "account.create_database", "account"), integration.CodeAllowed, "CREATE DATABASE")
}
func TestAction_account_create_database_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, dana, "account.create_database", "account"), integration.CodeDenied, "")
}
func TestAction_account_manage_grants_allow(t *testing.T) {
	_, f, c := setup(t)
	f.mu.Lock()
	f.roleGrants["OPS_ADMIN"] = append(f.roleGrants["OPS_ADMIN"], [4]string{"MANAGE GRANTS", "ACCOUNT", "MYORG-MYACCOUNT", "ACCOUNTADMIN"})
	f.mu.Unlock()
	expect(t, check(t, c, ops, "account.manage_grants", "account"), integration.CodeAllowed, "")
}
func TestAction_account_manage_grants_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, ops, "account.manage_grants", "account"), integration.CodeDenied, "")
}

func TestRawPrivileges(t *testing.T) {
	_, f, c := setup(t)
	f.mu.Lock()
	f.roleGrants["ANALYST"] = append(f.roleGrants["ANALYST"], [4]string{"REFERENCES", "TABLE", "PROD.SALES.ORDERS", "SYSADMIN"}, [4]string{"CREATE STAGE", "SCHEMA", "PROD.SALES", "SYSADMIN"})
	f.mu.Unlock()
	expect(t, check(t, c, dana, "raw:REFERENCES", "table:prod.sales.orders"), integration.CodeAllowed, "REFERENCES")
	expect(t, check(t, c, dana, "raw:CREATE_STAGE", "schema:prod.sales"), integration.CodeAllowed, "CREATE STAGE")
	expect(t, check(t, c, dana, "raw:MONITOR", "warehouse:analytics_wh"), integration.CodeDenied, "")
	expect(t, check(t, c, dana, "raw:USAGE", "role:analyst"), integration.CodeInvalidRequest, "role.use")
	for _, bad := range []string{"raw:OWNERSHIP", "raw:select", "raw:CREATE__STAGE", "raw:CREATE STAGE", "raw:X", "raw:"} {
		if _, ok := (Integration{}).MatchAction(bad); ok {
			t.Errorf("%q accepted", bad)
		}
	}
}

// --- identity ---------------------------------------------------------------

func TestIdentity(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, integration.User{Email: "nobody@example.com"}, "database.usage", "database:prod"), integration.CodeUserNotFound, "no Snowflake user")
	// DUP2 has the address as login name, DUP1 only as email: the login
	// name, set by the user's owner, wins.
	if id, err := c.ResolveIdentity(context.Background(), integration.User{Email: "dup@example.com"}); err != nil || id.ID != "DUP2" {
		t.Errorf("dup resolved to %+v, %v", id, err)
	}
	expect(t, check(t, c, integration.User{Email: "twice@example.com"}, "database.usage", "database:prod"), integration.CodeUserAmbiguous, "2 Snowflake users")
	expect(t, check(t, c, integration.User{Email: "off@example.com"}, "database.usage", "database:prod"), integration.CodeDenied, "disabled")
	expect(t, check(t, c, integration.User{Email: "not an email"}, "database.usage", "database:prod"), integration.CodeInvalidRequest, "")
	// dana@example.com.au must not match dana@example.com.
	expect(t, check(t, c, dana, "warehouse.operate", "warehouse:analytics_wh"), integration.CodeDenied, "")
}

func TestIdentityLookupStatements(t *testing.T) {
	_, f, c := setup(t)
	// bob is named by the address: one LIKE, no scan.
	check(t, c, bob, "database.usage", "database:dev")
	f.mu.Lock()
	stmts := append([]string{}, f.statements...)
	f.mu.Unlock()
	if len(stmts) < 2 || stmts[0] != `SHOW USERS LIKE 'bob@example.com'` || stmts[1] != `SHOW GRANTS TO USER "bob@example.com"` {
		t.Errorf("statements %q", stmts)
	}
	// dana is found by the scan; the LIKE escapes wildcards.
	f.mu.Lock()
	f.statements = nil
	f.mu.Unlock()
	check(t, c, integration.User{Email: "d_a%a@example.com"}, "database.usage", "database:dev")
	f.mu.Lock()
	stmts = append([]string{}, f.statements...)
	f.mu.Unlock()
	if len(stmts) < 2 || stmts[0] != `SHOW USERS LIKE 'd\\_a\\%a@example.com'` || stmts[1] != "SHOW USERS LIMIT 10000" {
		t.Errorf("statements %q", stmts)
	}
}

func TestIdentityAttrs(t *testing.T) {
	_, _, c := setup(t)
	id, err := c.ResolveIdentity(context.Background(), dana)
	if err != nil {
		t.Fatal(err)
	}
	if id.ID != "DANA" || id.Attr("disabled") != "false" || id.Attr("default_role") != "ANALYST" || len(id.Groups) != 1 || id.Groups[0] != "ANALYST" {
		t.Errorf("identity %+v", id)
	}
	for k, v := range id.Attrs {
		itest.AssertNoCanary(t, k+"="+v)
	}
}

func TestNewGrantShape(t *testing.T) {
	_, f, c := setup(t)
	f.mu.Lock()
	f.newShape = true
	f.mu.Unlock()
	expect(t, check(t, c, dana, "table.select", "table:prod.sales.orders"), integration.CodeAllowed, "")
}

func TestUserScanPaging(t *testing.T) {
	_, f, c := setup(t)
	f.mu.Lock()
	for i := 0; i < userPage+5; i++ {
		f.users = append(f.users, fakeUser{name: fmt.Sprintf("U%06d", i), login: fmt.Sprintf("u%06d", i)})
	}
	f.users = append(f.users, fakeUser{name: "LAST", login: "last", email: "last@example.com", roles: []string{"ANALYST"}})
	f.mu.Unlock()
	expect(t, check(t, c, integration.User{Email: "last@example.com"}, "database.usage", "database:prod"), integration.CodeAllowed, "")
	f.mu.Lock()
	pages := 0
	for _, s := range f.statements {
		if strings.HasPrefix(s, "SHOW USERS LIMIT") {
			pages++
		}
	}
	f.mu.Unlock()
	if pages != 2 {
		t.Errorf("%d scan pages, want 2", pages)
	}
}

func TestCallerGroupsIgnored(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, integration.User{Email: "none@example.com", Groups: []string{"ANALYST", "ACCOUNTADMIN"}}, "database.usage", "database:prod"), integration.CodeDenied, "")
}

// --- transport --------------------------------------------------------------

func TestHiddenRole(t *testing.T) {
	_, f, c := setup(t)
	f.mu.Lock()
	f.hidden["READER"] = true
	f.mu.Unlock()
	expect(t, check(t, c, bob, "table.select", "table:dev.play.t"), integration.CodeResourceNotVisible, `role "READER" is granted but hallpass's role may not read its grants`)
}

func TestInsufficientPrivileges(t *testing.T) {
	srv, _, c := setup(t)
	srv.Handle("POST", "/api/v2/statements", func(w http.ResponseWriter, r *http.Request) { sqlErr(w, "003001") })
	expect(t, check(t, c, dana, "database.usage", "database:prod"), integration.CodeCredentialRejected, "MANAGE GRANTS")
}

func TestAsyncAndPartitions(t *testing.T) {
	srv, f, c := setup(t)
	f.mu.Lock()
	f.pending = 2
	f.partitions = 3
	f.mu.Unlock()
	expect(t, check(t, c, dana, "table.select", "table:prod.sales.orders"), integration.CodeAllowed, "")
	polls, parts := 0, 0
	for _, call := range srv.Calls() {
		if call.Method == http.MethodGet {
			if call.Query.Get("partition") != "" {
				parts++
			} else {
				polls++
			}
		}
	}
	if polls != 2 || parts < 2 {
		t.Errorf("%d polls and %d partition reads", polls, parts)
	}
}

func TestGrantsAreCached(t *testing.T) {
	_, f, c := setup(t)
	check(t, c, ops, "table.select", "table:prod.sales.orders")
	check(t, c, ops, "warehouse.operate", "warehouse:analytics_wh")
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, s := range f.statements {
		if strings.HasPrefix(s, "SHOW GRANTS TO ROLE") || strings.HasPrefix(s, "SHOW GRANTS TO DATABASE ROLE") {
			n++
		}
	}
	// OPS_ADMIN, DEV, READER, "mixed role", PROD.DBROLE and PUBLIC once each.
	if n != 6 {
		t.Errorf("%d role grant listings, want 6 (cached)", n)
	}
}

func TestInvalidRequests(t *testing.T) {
	_, _, c := setup(t)
	for _, tc := range [][2]string{
		{"table.select", "table:orders"}, {"table.select", "table:prod.sales"}, {"table.select", "table:prod.sales.orders.x"},
		{"table.select", `table:prod.sales."unterminated`}, {"table.select", `table:prod.sales.""`}, {"table.select", "table:prod.sales.or ders"},
		{"table.select", "table:prod.sales.orders?x=1"}, {"table.select", "table:1abc.sales.orders"}, {"table.select", "schema:prod.sales"},
		{"schema.usage", "database:prod"}, {"account.create_database", "account:x"}, {"role.use", "role:a.b"},
		{"table.select", "table:prod.sales.o;drop"}, {"table.select", `table:prod.sales."a"b"`},
	} {
		d := check(t, c, dana, tc[0], tc[1])
		if d.Code != integration.CodeInvalidRequest {
			t.Errorf("%s %s: %s %s", tc[0], tc[1], d.Code, d.Text)
		}
	}
}

func TestIdentifiers(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		ok       bool
	}{
		{"orders", "ORDERS", true}, {"_x$1", "_X$1", true}, {`"Mixed Case"`, "Mixed Case", true}, {`"a""b"`, `a"b`, true},
		{`"a"b"`, "", false}, {`""`, "", false}, {"1abc", "", false}, {"a-b", "", false}, {"a b", "", false}, {"", "", false},
	} {
		got, err := parseIdentifier(tc.in)
		if (err == nil) != tc.ok || got != tc.want {
			t.Errorf("parseIdentifier(%q) = %q, %v", tc.in, got, err)
		}
	}
	if quote(`a"b`) != `"a""b"` || quoteName([]string{"A", "b c"}) != `"A"."b c"` {
		t.Error("quoting")
	}
	if likeLiteral(`d_a%a'\b`) != `'d\\_a\\%a''\\\\b'` {
		t.Errorf("likeLiteral %q", likeLiteral(`d_a%a'\b`))
	}
}

func TestFailures(t *testing.T) {
	srv, _, c := setup(t)
	itest.FailureCases(t, srv, func() integration.Decision { return check(t, c, dana, "database.usage", "database:prod") })
}

func TestBadKey(t *testing.T) {
	srv, _ := newServer(t)
	deps, _ := itest.Deps(t, srv)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKCS8PrivateKey(other)
	otherPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	s := itest.Settings("sf", "snowflake", map[string]string{"account": "myorg-myaccount", "user": "hallpass", "role": "secadmin", "url": srv.URL}, map[string]secret.Secret{"credential": secret.Literal(otherPEM)})
	c, err := (Integration{}).New(context.Background(), s, deps)
	if err != nil {
		t.Fatal(err)
	}
	// The fake reports the claims mismatch as a test error only when the
	// signature verifies; a foreign key fails the signature first.
	expect(t, check(t, c, dana, "database.usage", "database:prod"), integration.CodeCredentialRejected, "key-pair token")
	s = itest.Settings("sf", "snowflake", map[string]string{"account": "myorg-myaccount", "user": "hallpass", "url": srv.URL}, map[string]secret.Secret{"credential": secret.Literal("not a key")})
	c, err = (Integration{}).New(context.Background(), s, deps)
	if err != nil {
		t.Fatal(err)
	}
	expect(t, check(t, c, dana, "database.usage", "database:prod"), integration.CodeCredentialRejected, "RSA private key")
}

func TestNewValidation(t *testing.T) {
	srv := itest.NewServer(t)
	deps, _ := itest.Deps(t, srv)
	for _, tc := range []struct {
		values map[string]string
		secret bool
	}{
		{map[string]string{"account": "myorg-myaccount", "user": "hallpass"}, false},
		{map[string]string{"user": "hallpass"}, true},
		{map[string]string{"account": "myorg-myaccount"}, true},
		{map[string]string{"account": "myorg-myaccount", "user": "bad user"}, true},
		{map[string]string{"account": "myorg-myaccount", "user": "hallpass", "role": "1bad"}, true},
		{map[string]string{"account": "bad account", "user": "hallpass"}, true},
		{map[string]string{"account": "myorg-myaccount", "user": "hallpass", "url": "ftp://x"}, true},
		{map[string]string{"account": "myorg-myaccount", "user": "hallpass", "url": "http://proxy.internal"}, true},
		{map[string]string{"account": "myorg-myaccount", "user": "hallpass", "url": "https://u:p@host"}, true},
	} {
		secrets := map[string]secret.Secret{}
		if tc.secret {
			secrets["credential"] = secret.Literal("x")
		}
		if _, err := (Integration{}).New(context.Background(), itest.Settings("sf", "snowflake", tc.values, secrets), deps); err == nil {
			t.Errorf("New(%v, secret=%v) accepted", tc.values, tc.secret)
		}
	}
	// The default URL follows the account.
	if _, err := (Integration{}).New(context.Background(), itest.Settings("sf", "snowflake", map[string]string{"account": "xy12345.us-east-1", "user": "hallpass"}, map[string]secret.Secret{"credential": secret.Literal("x")}), deps); err != nil {
		t.Error(err)
	}
}

func TestProbe(t *testing.T) {
	_, _, c := setup(t)
	res, err := c.Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Summary, `"HALLPASS" with roles SECADMIN`) || len(res.Warnings) != 1 {
		t.Errorf("probe %+v", res)
	}
	itest.AssertNoCanary(t, res.Summary)
	_, f2, c := setup(t)
	f2.mu.Lock()
	f2.roleGrants["SECADMIN"] = nil
	f2.mu.Unlock()
	res, err = c.Probe(context.Background())
	if err != nil || len(res.Warnings) != 2 {
		t.Errorf("probe without MANAGE GRANTS: %+v %v", res, err)
	}
	var ie *integration.Error
	srv, _ := newServer(t)
	deps, _ := itest.Deps(t, srv)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKCS8PrivateKey(other)
	bad, _ := (Integration{}).New(context.Background(), itest.Settings("sf", "snowflake", map[string]string{"account": "myorg-myaccount", "user": "hallpass", "role": "secadmin", "url": srv.URL}, map[string]secret.Secret{"credential": secret.Literal(string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})))}), deps)
	if _, err := bad.Probe(context.Background()); !errors.As(err, &ie) || ie.Code != integration.CodeCredentialRejected {
		t.Errorf("bad key: %v", err)
	}
}

func TestNoSecretInLogs(t *testing.T) {
	srv, _ := newServer(t)
	deps, logs := itest.Deps(t, srv)
	_, pemKey := signingKey(t)
	s := itest.Settings("sf", "snowflake", map[string]string{"account": "myorg-myaccount", "user": "hallpass", "role": "secadmin", "url": srv.URL}, map[string]secret.Secret{"credential": secret.Literal(pemKey)})
	c, err := (Integration{}).New(context.Background(), s, deps)
	if err != nil {
		t.Fatal(err)
	}
	check(t, c, dana, "table.select", "table:prod.sales.orders")
	check(t, c, integration.User{Email: "nobody@example.com"}, "table.select", "table:prod.sales.orders")
	itest.AssertNoCanary(t, logs.String())
	if strings.Contains(logs.String(), "PRIVATE KEY") {
		t.Error("the key reached the log")
	}
}
