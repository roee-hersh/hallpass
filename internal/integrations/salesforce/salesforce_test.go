package salesforce

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/roee-hersh/hallpass/internal/authx"
	"github.com/roee-hersh/hallpass/internal/httpx"
	"github.com/roee-hersh/hallpass/internal/integration"
	"github.com/roee-hersh/hallpass/internal/integration/itest"
	"github.com/roee-hersh/hallpass/internal/secret"
)

// --- test key ---------------------------------------------------------------

var (
	keyOnce sync.Once
	testKey *rsa.PrivateKey
)

func signingKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	keyOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		testKey = k
	})
	return testKey
}

// keySecret is the private key PEM with a canary comment line in front, so
// a leaked credential is caught by the log check.
func keySecret(t *testing.T) secret.Secret {
	t.Helper()
	der := x509.MarshalPKCS1PrivateKey(signingKey(t))
	p := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
	return secret.Literal("# " + itest.Canary + "sf\n" + string(p))
}

// --- fake Salesforce --------------------------------------------------------

const (
	testClientID = "3MVG9consumerKey"
	testUsername = "hallpass@acme.example"
	testAudience = "https://login.salesforce.com"
	testVersion  = "v66.0"

	danaID   = "005000000000001AAA"
	bobID    = "005000000000002AAA"
	ianID    = "005000000000003AAA"
	fredID   = "005000000000004AAA"
	oneilID  = "005000000000005AAA"
	sharedA  = "005000000000006AAA"
	sharedB  = "005000000000007AAA"
	twinA    = "005000000000008AAA"
	twinB    = "005000000000009AAA"
	ambA     = "00500000000000AAAA"
	ambB     = "00500000000000BAAA"
	manyA    = "00500000000000CAAA"
	manyB    = "00500000000000DAAA"
	manyC    = "00500000000000EAAA"
	manyD    = "00500000000000FAAA"
	manyE    = "00500000000000GAAA"
	dupA     = "00500000000000HAAA"
	dupB     = "00500000000000IAAA"
	acctID   = "001000000000001AAA"
	hiddenID = "001000000000009AAA"
	groupID  = "0PG000000000001AAA"
)

var (
	dana  = integration.User{Email: "dana@example.com"}
	bob   = integration.User{Email: "bob@example.com"}
	ian   = integration.User{Email: "ian@example.com"}
	fred  = integration.User{Email: "fred@example.com"}
	oneil = integration.User{Email: "o'neil@example.com"}
)

type sfErr struct {
	status int
	code   string
}

type fakeSF struct {
	t   *testing.T
	srv *itest.Server
	pub *rsa.PublicKey

	mu           sync.Mutex
	instanceURL  string // token response instance_url; "" omits the field
	validTokens  map[string]bool
	tokenCalls   int
	queries      []string
	revokeNext   bool // the next API call answers 401 INVALID_SESSION_ID and forgets the token
	alwaysRevoke bool
	lenientJWT   bool // do not fail the test on a bad assertion
	users        []userRow
	frozen       map[string]bool
	recordAccess map[string]recordAccessRow
	objectPerms  map[string][]objectPermRow
	// sessionObjectPerms are rows granted through session-based or expired
	// assignments: a real org returns them only when the assignment
	// sub-select carries no activation/expiry filter.
	sessionObjectPerms map[string][]objectPermRow
	fieldPerms         map[string][]fieldPermRow
	sysPerms           map[string]map[string]string
	// permSets lists assigned permission sets as Name or ns__Name.
	permSets map[string][]string
	groups   map[string][]string
	// objects are the sObjects whose describe answers 200.
	objects        map[string]bool
	groupStatus    map[string]string
	describeFields []string
	errors         map[string]sfErr
	// rejectAssignmentFilter makes any query whose assignment sub-select
	// filters on HasActivationRequired/ExpirationDate answer 400
	// INVALID_FIELD, like an org whose API version lacks those fields.
	rejectAssignmentFilter bool
	remaining              int
}

var (
	fromRe  = regexp.MustCompile(`FROM (\w+)`)
	whereRe = regexp.MustCompile(`WHERE (\w+) = '((?:[^'\\]|\\.)*)'`)
	permRe  = regexp.MustCompile(`WHERE (Permissions\w+) = true`)
	inRe    = regexp.MustCompile(`IN \(('[^)]*')\)`)
	limitRe = regexp.MustCompile(` LIMIT (\d+)$`)
	// assignFilterRe is the activation/expiry filter every assignment
	// sub-select must carry (finding: session-based and expired assignments
	// must not grant).
	assignFilterRe = regexp.MustCompile(`\(SELECT PermissionSetId FROM PermissionSetAssignment WHERE AssigneeId = '\w+' AND PermissionSet\.HasActivationRequired = false AND \(ExpirationDate = null OR ExpirationDate > (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\)\)`)
	assignLooseRe  = regexp.MustCompile(`\(SELECT PermissionSetId FROM PermissionSetAssignment WHERE AssigneeId = '\w+'\)`)
)

// lit extracts the escaped literal compared to field and unescapes it.
func lit(q, field string) string {
	re := regexp.MustCompile(regexp.QuoteMeta(field) + ` = '((?:[^'\\]|\\.)*)'`)
	m := re.FindStringSubmatch(q)
	if m == nil {
		return ""
	}
	return unescape(m[1])
}

func unescape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
			switch s[i] {
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			case 't':
				b.WriteByte('\t')
			default:
				b.WriteByte(s[i])
			}
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func newFake(t *testing.T) *fakeSF {
	t.Helper()
	srv := itest.NewServer(t)
	f := &fakeSF{
		t:           t,
		srv:         srv,
		pub:         &signingKey(t).PublicKey,
		instanceURL: srv.URL + "/inst",
		validTokens: map[string]bool{},
		users: []userRow{
			{ID: "005000000000000AAA", IsActive: true, Username: testUsername, Email: testUsername, UserType: "Standard", Name: "hallpass"},
			{ID: danaID, IsActive: true, Username: "dana@example.com", Email: "dana@example.com", FederationIdentifier: "dana", UserType: "Standard", Name: "Dana"},
			{ID: bobID, IsActive: true, Username: "bob@example.com", Email: "bob@example.com", FederationIdentifier: "bob", UserType: "Standard", Name: "Bob"},
			{ID: ianID, IsActive: false, Username: "ian@example.com", Email: "ian@example.com", UserType: "Standard", Name: "Ian"},
			{ID: fredID, IsActive: true, Username: "fred@example.com", Email: "fred@example.com", UserType: "Standard", Name: "Fred"},
			{ID: oneilID, IsActive: true, Username: "oneil@example.com.acme", Email: "o'neil@example.com", UserType: "Standard", Name: "O'Neil"},
			// shared: two rows, the one whose Username is the email wins.
			{ID: sharedA, IsActive: true, Username: "shared@example.com.portal", Email: "shared@example.com", UserType: "CspLitePortal", Name: "Shared portal"},
			{ID: sharedB, IsActive: true, Username: "shared@example.com", Email: "shared@example.com", UserType: "Standard", Name: "Shared"},
			// twin: two rows, only one active Standard.
			{ID: twinA, IsActive: false, Username: "twin@example.com.old", Email: "twin@example.com", UserType: "Standard", Name: "Twin old"},
			{ID: twinB, IsActive: true, Username: "twin@example.com.new", Email: "twin@example.com", UserType: "Standard", Name: "Twin new"},
			// amb: two active Standard rows, neither username matches.
			{ID: ambA, IsActive: true, Username: "amb1@example.com", Email: "amb@example.com", UserType: "Standard", Name: "Amb 1"},
			{ID: ambB, IsActive: true, Username: "amb2@example.com", Email: "amb@example.com", UserType: "Standard", Name: "Amb 2"},
			// many: five rows share the email; only one is an active Standard
			// user, but the query limit is reached so nothing may be picked.
			{ID: manyA, IsActive: true, Username: "many1@example.com", Email: "many@example.com", UserType: "Standard", Name: "Many 1"},
			{ID: manyB, IsActive: false, Username: "many2@example.com", Email: "many@example.com", UserType: "Standard", Name: "Many 2"},
			{ID: manyC, IsActive: true, Username: "many3@example.com", Email: "many@example.com", UserType: "CspLitePortal", Name: "Many 3"},
			{ID: manyD, IsActive: false, Username: "many4@example.com", Email: "many@example.com", UserType: "Standard", Name: "Many 4"},
			{ID: manyE, IsActive: true, Username: "many5@example.com", Email: "many@example.com", UserType: "Guest", Name: "Many 5"},
			// dup: two rows with the same Username, which Salesforce should
			// never allow; the exact lookup must not pick one.
			{ID: dupA, IsActive: true, Username: "dup@example.com", Email: "dup-a@example.com", UserType: "Standard", Name: "Dup A"},
			{ID: dupB, IsActive: true, Username: "dup@example.com", Email: "dup-b@example.com", UserType: "Standard", Name: "Dup B"},
		},
		frozen: map[string]bool{fredID: true},
		recordAccess: map[string]recordAccessRow{
			danaID + "|" + acctID: {RecordID: acctID, HasReadAccess: true, HasEditAccess: true, HasDeleteAccess: true, HasTransferAccess: true, HasAllAccess: true, MaxAccessLevel: "All"},
			bobID + "|" + acctID:  {RecordID: acctID, HasReadAccess: true, MaxAccessLevel: "Read"},
		},
		objectPerms: map[string][]objectPermRow{
			danaID + "|Account": {{PermissionsRead: true, PermissionsCreate: true, PermissionsEdit: true, PermissionsDelete: true, PermissionsViewAllRecords: true, PermissionsModifyAllRecords: true, Parent: parentRef{IsOwnedByProfile: true, Name: "Sales"}}},
			bobID + "|Account": {
				{PermissionsRead: true, Parent: parentRef{IsOwnedByProfile: true, Name: "Minimum Access"}},
				{Parent: parentRef{Name: "Empty_Set"}},
			},
		},
		sessionObjectPerms: map[string][]objectPermRow{
			// Bob's session-based set grants Edit only while activated, and
			// an expired assignment grants Delete: neither is in force.
			bobID + "|Account": {
				{PermissionsRead: true, PermissionsEdit: true, Parent: parentRef{Name: "Session_Editors"}},
				{PermissionsRead: true, PermissionsDelete: true, Parent: parentRef{Name: "Expired_Deleters"}},
			},
			bobID + "|Invoice__c": {{PermissionsRead: true, Parent: parentRef{Name: "Session_Invoices"}}},
		},
		objects: map[string]bool{"Account": true, "Invoice__c": true, "Contact": true},
		fieldPerms: map[string][]fieldPermRow{
			danaID + "|Account.Rating": {{PermissionsRead: true, PermissionsEdit: true, Parent: parentRef{IsOwnedByProfile: true, Name: "Sales"}}},
			bobID + "|Account.Rating":  {{PermissionsRead: true, Parent: parentRef{Name: "Readers"}}},
			bobID + "|Account.Secret__c": {
				{Parent: parentRef{IsOwnedByProfile: true, Name: "Minimum Access"}},
			},
		},
		sysPerms: map[string]map[string]string{
			danaID: {"PermissionsApiEnabled": "Sales", "PermissionsViewSetup": "Sales"},
			bobID:  {"PermissionsApiEnabled": "Minimum Access"},
		},
		permSets:       map[string][]string{danaID: {"Sales_Ops", "acme__Billing"}, bobID: {"Billing"}},
		groups:         map[string][]string{},
		groupStatus:    map[string]string{groupID: "Updated"},
		describeFields: []string{"Id", "Name", "IsOwnedByProfile", "PermissionsApiEnabled", "PermissionsViewSetup", "PermissionsModifyAllData"},
		errors:         map[string]sfErr{},
		remaining:      14000,
	}
	srv.Handle("POST", "/services/oauth2/token", f.handleToken)
	srv.Handle("GET", "/services/data/*", f.handleAPI)
	srv.Handle("GET", "/inst/services/data/*", f.handleAPI)
	return f
}

func writeSFError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintf(w, `[{"message":"%smessage for %s","errorCode":"%s"}]`, itest.Canary, code, code)
}

func (f *fakeSF) verifyJWT(a string) error {
	parts := strings.Split(a, ".")
	if len(parts) != 3 {
		return fmt.Errorf("assertion has %d parts", len(parts))
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return err
	}
	var hdr struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return err
	}
	if hdr.Alg != "RS256" {
		return fmt.Errorf("alg %s", hdr.Alg)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return err
	}
	if err := authx.Verify(f.pub, authx.RS256, []byte(parts[0]+"."+parts[1]), sig); err != nil {
		return fmt.Errorf("signature: %w", err)
	}
	var claims authx.StandardClaims
	if err := authx.DecodeJWTClaims(a, &claims); err != nil {
		return err
	}
	if claims.Iss != testClientID || claims.Sub != testUsername || claims.Aud != testAudience {
		return fmt.Errorf("claims iss=%q sub=%q aud=%q", claims.Iss, claims.Sub, claims.Aud)
	}
	now := time.Now().Unix()
	if claims.Exp <= now || claims.Exp > now+180+5 {
		return fmt.Errorf("exp %d is not within 3 minutes of now %d", claims.Exp, now)
	}
	return nil
}

func (f *fakeSF) handleToken(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	f.mu.Lock()
	f.tokenCalls++
	n := f.tokenCalls
	inst := f.instanceURL
	f.mu.Unlock()
	fail := func(code string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(400)
		fmt.Fprintf(w, `{"error":"%s","error_description":"%sdescription"}`, code, itest.Canary)
	}
	if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		f.t.Errorf("token request content type %q", r.Header.Get("Content-Type"))
	}
	switch r.Form.Get("grant_type") {
	case "urn:ietf:params:oauth:grant-type:jwt-bearer":
		if err := f.verifyJWT(r.Form.Get("assertion")); err != nil {
			f.mu.Lock()
			lenient := f.lenientJWT
			f.mu.Unlock()
			if !lenient {
				f.t.Errorf("assertion: %v", err)
			}
			fail("invalid_grant")
			return
		}
	case "client_credentials":
		if r.Form.Get("client_id") != testClientID || r.Form.Get("client_secret") != itest.Canary+"consumer" {
			fail("invalid_client")
			return
		}
	default:
		fail("unsupported_grant_type")
		return
	}
	tok := itest.Canary + "tok" + fmt.Sprint(n)
	f.mu.Lock()
	f.validTokens[tok] = true
	f.mu.Unlock()
	body := map[string]any{"access_token": tok, "id": "https://login.salesforce.com/id/00D/005", "token_type": "Bearer", "issued_at": "1700000000000", "scope": "api"}
	if inst != "" {
		body["instance_url"] = inst
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

func (f *fakeSF) handleAPI(w http.ResponseWriter, r *http.Request) {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	f.mu.Lock()
	valid := f.validTokens[tok]
	if valid && (f.revokeNext || f.alwaysRevoke) {
		delete(f.validTokens, tok)
		f.revokeNext = false
		valid = false
	}
	f.mu.Unlock()
	if !valid {
		writeSFError(w, 401, "INVALID_SESSION_ID")
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/inst")
	rest := strings.TrimPrefix(path, "/services/data/"+testVersion)
	if rest == path {
		f.t.Errorf("unexpected API version in %s", r.URL.Path)
		writeSFError(w, 404, "NOT_FOUND")
		return
	}
	switch rest {
	case "/query":
		f.handleQuery(w, r)
	case "/limits":
		f.mu.Lock()
		rem := f.remaining
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"DailyApiRequests":{"Max":15000,"Remaining":%d},"DailyBulkApiBatches":{"Max":15000,"Remaining":15000}}`, rem)
	case "/sobjects/PermissionSet/describe":
		f.mu.Lock()
		fields := f.describeFields
		f.mu.Unlock()
		var out []map[string]any
		for _, n := range fields {
			out = append(out, map[string]any{"name": n, "type": "boolean"})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"name": "PermissionSet", "fields": out})
	default:
		if name, ok := strings.CutPrefix(rest, "/sobjects/"); ok && strings.HasSuffix(name, "/describe") {
			name = strings.TrimSuffix(name, "/describe")
			f.mu.Lock()
			e, failing := f.errors["describe:"+name]
			exists := f.objects[name]
			f.mu.Unlock()
			switch {
			case failing:
				writeSFError(w, e.status, e.code)
			case exists:
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"name": name, "queryable": true, "fields": []any{}})
			default:
				writeSFError(w, 404, "NOT_FOUND")
			}
			return
		}
		writeSFError(w, 404, "NOT_FOUND")
	}
}

// describeCalls counts the sObject describes of name.
func (f *fakeSF) describeCalls(name string) int {
	n := 0
	for _, call := range f.srv.Calls() {
		if strings.HasSuffix(call.Path, "/sobjects/"+name+"/describe") {
			n++
		}
	}
	return n
}

// checkAssignmentFilter enforces the finding on the assignment sub-select:
// the query carries the activation/expiry filter with a current timestamp,
// or (when the org is set to reject it) it is the loose form of a retry.
// It reports whether the query is loose.
func (f *fakeSF) checkAssignmentFilter(w http.ResponseWriter, q string) (loose, failed bool) {
	if !strings.Contains(q, "(SELECT PermissionSetId FROM PermissionSetAssignment") {
		return false, false
	}
	if m := assignFilterRe.FindStringSubmatch(q); m != nil {
		if f.rejectAssignmentFilter {
			writeSFError(w, 400, "INVALID_FIELD")
			return false, true
		}
		ts, err := time.Parse("2006-01-02T15:04:05Z", m[1])
		if err != nil || ts.Before(time.Now().Add(-time.Minute)) || ts.After(time.Now().Add(time.Minute)) {
			f.t.Errorf("assignment filter timestamp %q is not now: %s", m[1], q)
		}
		return false, false
	}
	if assignLooseRe.MatchString(q) {
		if !f.rejectAssignmentFilter {
			f.t.Errorf("assignment sub-select lacks the activation/expiry filter: %s", q)
		}
		return true, false
	}
	f.t.Errorf("unrecognised assignment sub-select: %s", q)
	writeSFError(w, 400, "MALFORMED_QUERY")
	return false, true
}

func (f *fakeSF) handleQuery(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queries = append(f.queries, q)
	m := fromRe.FindStringSubmatch(q)
	if m == nil {
		writeSFError(w, 400, "MALFORMED_QUERY")
		return
	}
	obj := m[1]
	if e, ok := f.errors[obj]; ok {
		writeSFError(w, e.status, e.code)
		return
	}
	records := []any{}
	uid := lit(q, "AssigneeId")
	loose, failed := f.checkAssignmentFilter(w, q)
	if failed {
		return
	}
	switch obj {
	case "User":
		wm := whereRe.FindStringSubmatch(q)
		if wm == nil {
			writeSFError(w, 400, "MALFORMED_QUERY")
			return
		}
		field, val := wm[1], unescape(wm[2])
		limit := len(f.users)
		if lm := limitRe.FindStringSubmatch(q); lm != nil {
			fmt.Sscan(lm[1], &limit)
		} else if strings.HasPrefix(q, "SELECT Id, IsActive, Username, Email") {
			f.t.Errorf("identity query without LIMIT: %s", q)
		}
		for _, u := range f.users {
			if len(records) >= limit {
				break
			}
			var have string
			switch field {
			case "Email":
				have = u.Email
			case "Username":
				have = u.Username
			case "FederationIdentifier":
				have = u.FederationIdentifier
			default:
				writeSFError(w, 400, "INVALID_FIELD")
				return
			}
			if have == val {
				records = append(records, u)
			}
		}
	case "UserLogin":
		id := lit(q, "UserId")
		for _, u := range f.users {
			if u.ID == id {
				records = append(records, map[string]any{"IsFrozen": f.frozen[id]})
			}
		}
	case "UserRecordAccess":
		row, ok := f.recordAccess[lit(q, "UserId")+"|"+lit(q, "RecordId")]
		if ok {
			records = append(records, row)
		}
	case "ObjectPermissions":
		key := uid + "|" + lit(q, "SobjectType")
		for _, row := range f.objectPerms[key] {
			records = append(records, row)
		}
		if loose {
			for _, row := range f.sessionObjectPerms[key] {
				records = append(records, row)
			}
		}
	case "FieldPermissions":
		for _, row := range f.fieldPerms[uid+"|"+lit(q, "Field")] {
			records = append(records, row)
		}
	case "PermissionSet":
		pm := permRe.FindStringSubmatch(q)
		if pm == nil {
			writeSFError(w, 400, "MALFORMED_QUERY")
			return
		}
		if parent, ok := f.sysPerms[uid][pm[1]]; ok {
			records = append(records, map[string]any{"Id": "0PS000000000001AAA", "Name": parent, "IsOwnedByProfile": true})
		}
	case "PermissionSetAssignment":
		if strings.Contains(q, "PermissionSetGroupId != null") {
			for _, g := range f.groups[uid] {
				records = append(records, map[string]any{"PermissionSetGroupId": g})
			}
		} else {
			name := lit(q, "PermissionSet.Name")
			want := name
			switch {
			case strings.HasSuffix(q, " AND PermissionSet.NamespacePrefix = null"):
			case lit(q, "PermissionSet.NamespacePrefix") != "":
				want = lit(q, "PermissionSet.NamespacePrefix") + "__" + name
			default:
				f.t.Errorf("permission set query without a NamespacePrefix condition: %s", q)
			}
			for _, n := range f.permSets[uid] {
				if n == want {
					records = append(records, map[string]any{"Id": "0Pa000000000001AAA"})
				}
			}
		}
	case "PermissionSetGroup":
		im := inRe.FindStringSubmatch(q)
		if im == nil {
			writeSFError(w, 400, "MALFORMED_QUERY")
			return
		}
		for _, id := range strings.Split(im[1], ",") {
			id = strings.Trim(id, "'")
			if st, ok := f.groupStatus[id]; ok {
				records = append(records, map[string]any{"Id": id, "DeveloperName": "Group_" + id[len(id)-4:], "Status": st})
			}
		}
	default:
		writeSFError(w, 400, "INVALID_TYPE")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"totalSize": len(records), "done": true, "records": records})
}

func (f *fakeSF) queriesFrom(obj string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, q := range f.queries {
		if m := fromRe.FindStringSubmatch(q); m != nil && m[1] == obj {
			out = append(out, q)
		}
	}
	return out
}

func (f *fakeSF) tokenCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tokenCalls
}

// --- connection helpers -----------------------------------------------------

func baseValues(srvURL string) map[string]string {
	return map[string]string{
		"url":         srvURL,
		"client_id":   testClientID,
		"auth_flow":   flowJWTBearer,
		"username":    testUsername,
		"audience":    testAudience,
		"api_version": testVersion,
		"match_field": matchEmail,
		"token_ttl":   "15m",
	}
}

func newConn(t *testing.T, f *fakeSF, values map[string]string, cred secret.Secret) integration.Connection {
	t.Helper()
	deps, _ := itest.Deps(t, f.srv)
	v := baseValues(f.srv.URL)
	for k, val := range values {
		v[k] = val
	}
	if cred.IsZero() {
		cred = keySecret(t)
	}
	s := itest.Settings("sf", "salesforce", v, map[string]secret.Secret{"credential": cred})
	c, err := Integration{}.New(context.Background(), s, deps)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func setup(t *testing.T) (*fakeSF, integration.Connection) {
	t.Helper()
	f := newFake(t)
	return f, newConn(t, f, nil, secret.Secret{})
}

func check(t *testing.T, c integration.Connection, u integration.User, action, resource string) integration.Decision {
	t.Helper()
	return itest.Check(t, c, Integration{}, u, action, resource)
}

// expectQuery compares one recorded query with want, in which "<assigned>"
// stands for the filtered assignment sub-select (its timestamp is now).
func expectQuery(t *testing.T, qs []string, want string) {
	t.Helper()
	re := regexp.MustCompile("^" + strings.ReplaceAll(regexp.QuoteMeta(want), "<assigned>", assignFilterRe.String()) + "$")
	if len(qs) != 1 || !re.MatchString(qs[0]) {
		t.Errorf("query %q\nwant  %q", qs, want)
	}
}

func expect(t *testing.T, d integration.Decision, code integration.Code, textPart string) {
	t.Helper()
	itest.ExpectCode(t, d, code)
	if textPart != "" && !strings.Contains(d.Text, textPart) {
		t.Errorf("decision text %q does not mention %q", d.Text, textPart)
	}
	if strings.Contains(d.Text, itest.Canary) {
		t.Errorf("decision text leaks an upstream message: %q", d.Text)
	}
}

// --- auth -------------------------------------------------------------------

func TestJWTBearerFlow(t *testing.T) {
	f, c := setup(t)
	expect(t, check(t, c, dana, "record.read", "record:"+acctID), integration.CodeAllowed, "HasReadAccess")
	expect(t, check(t, c, dana, "record.edit", "record:"+acctID), integration.CodeAllowed, "")
	if n := f.tokenCount(); n != 1 {
		t.Errorf("token minted %d times, want 1 (cached)", n)
	}
	var tokenCall itest.Call
	for _, call := range f.srv.Calls() {
		switch {
		case call.Path == "/services/oauth2/token":
			tokenCall = call
		case strings.Contains(call.Path, "/services/data/"):
			if !strings.HasPrefix(call.Path, "/inst/services/data/"+testVersion+"/") {
				t.Errorf("API call %s did not use instance_url and the pinned version", call.Path)
			}
			if call.Query.Get("q") == "" && strings.HasSuffix(call.Path, "/query") {
				t.Errorf("query without q: %s", call.Path)
			}
		}
	}
	if !strings.Contains(string(tokenCall.Body), "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer") || !strings.Contains(string(tokenCall.Body), "assertion=") {
		t.Errorf("token form: %s", tokenCall.Body)
	}
	if strings.Contains(string(tokenCall.Body), "client_secret") {
		t.Error("jwt_bearer sent a client_secret")
	}
}

func TestClientCredentialsFlow(t *testing.T) {
	f := newFake(t)
	c := newConn(t, f, map[string]string{"auth_flow": flowClientCredentials, "username": ""}, itest.Literal("consumer"))
	expect(t, check(t, c, dana, "record.read", "record:"+acctID), integration.CodeAllowed, "")
	body := string(f.srv.Calls()[0].Body)
	if !strings.Contains(body, "grant_type=client_credentials") || !strings.Contains(body, "client_id="+testClientID) || !strings.Contains(body, "client_secret=") {
		t.Errorf("token form: %s", body)
	}
	bad := newConn(t, f, map[string]string{"auth_flow": flowClientCredentials, "username": ""}, itest.Literal("wrong"))
	expect(t, check(t, bad, dana, "record.read", "record:"+acctID), integration.CodeCredentialRejected, "")
	_, err := bad.Probe(context.Background())
	if err == nil || strings.Contains(err.Error(), itest.Canary) {
		t.Errorf("probe with a wrong secret: %v", err)
	}
}

func TestInstanceURLAbsent(t *testing.T) {
	f := newFake(t)
	f.instanceURL = ""
	c := newConn(t, f, nil, secret.Secret{})
	expect(t, check(t, c, dana, "record.read", "record:"+acctID), integration.CodeAllowed, "")
	for _, call := range f.srv.Calls() {
		if strings.HasPrefix(call.Path, "/inst/") {
			t.Errorf("used an instance prefix without instance_url: %s", call.Path)
		}
	}
}

func TestInvalidSessionRemint(t *testing.T) {
	f, c := setup(t)
	expect(t, check(t, c, dana, "record.read", "record:"+acctID), integration.CodeAllowed, "")
	f.mu.Lock()
	f.revokeNext = true
	f.mu.Unlock()
	expect(t, check(t, c, dana, "record.read", "record:"+acctID), integration.CodeAllowed, "")
	if n := f.tokenCount(); n != 2 {
		t.Errorf("token minted %d times, want 2 (one re-mint)", n)
	}
	f.mu.Lock()
	f.alwaysRevoke = true
	f.mu.Unlock()
	expect(t, check(t, c, dana, "record.read", "record:"+acctID), integration.CodeCredentialRejected, "")
	if n := f.tokenCount(); n != 3 {
		t.Errorf("token minted %d times, want 3 (re-mint once, then give up)", n)
	}
}

// --- identity ---------------------------------------------------------------

func TestIdentityEscaping(t *testing.T) {
	f, c := setup(t)
	id, err := c.ResolveIdentity(context.Background(), oneil)
	if err != nil || id.ID != oneilID {
		t.Fatalf("%+v %v", id, err)
	}
	qs := f.queriesFrom("User")
	if len(qs) != 2 || !strings.HasSuffix(qs[0], `WHERE Username = 'o\'neil@example.com' LIMIT 2`) || !strings.HasSuffix(qs[1], `WHERE Email = 'o\'neil@example.com' LIMIT 4`) {
		t.Errorf("user queries: %q", qs)
	}
	for _, q := range qs {
		if !strings.HasPrefix(q, "SELECT Id, IsActive, Username, Email, FederationIdentifier, UserType, Name FROM User WHERE") {
			t.Errorf("user query columns: %q", q)
		}
	}
	if id.Attr(attrActive) != "true" || id.Attr(attrFrozen) != "false" || id.Display != "oneil@example.com.acme" {
		t.Errorf("identity %+v", id)
	}
	for _, bad := range []string{"x' OR 1=1--", "Dana <dana@example.com>", "dana@example.com\n", ""} {
		_, err := c.ResolveIdentity(context.Background(), integration.User{Email: bad})
		if d := integration.ToDecision(err); d.Code != integration.CodeInvalidRequest {
			t.Errorf("email %q -> %s", bad, d.Code)
		}
	}
	if len(f.queriesFrom("User")) != 2 {
		t.Error("an invalid email reached the query")
	}
}

func TestIdentityCases(t *testing.T) {
	_, c := setup(t)
	ctx := context.Background()
	if _, err := c.ResolveIdentity(ctx, integration.User{Email: "nobody@example.com"}); integration.ToDecision(err).Code != integration.CodeUserNotFound {
		t.Errorf("unknown email: %v", err)
	}
	id, err := c.ResolveIdentity(ctx, integration.User{Email: "shared@example.com"})
	if err != nil || id.ID != sharedB {
		t.Errorf("shared email should pick the Username match: %+v %v", id, err)
	}
	id, err = c.ResolveIdentity(ctx, integration.User{Email: "twin@example.com"})
	if err != nil || id.ID != twinB {
		t.Errorf("twin email should pick the single active Standard user: %+v %v", id, err)
	}
	_, err = c.ResolveIdentity(ctx, integration.User{Email: "amb@example.com"})
	if d := integration.ToDecision(err); d.Code != integration.CodeUserAmbiguous || !strings.Contains(d.Text, "FederationIdentifier") {
		t.Errorf("ambiguous email: %v", err)
	}

	f2 := newFake(t)
	byUsername := newConn(t, f2, map[string]string{"match_field": matchUsername}, secret.Secret{})
	id, err = byUsername.ResolveIdentity(ctx, integration.User{Email: "twin@example.com.new"})
	if err != nil || id.ID != twinB {
		t.Errorf("by username: %+v %v", id, err)
	}
	if qs := f2.queriesFrom("User"); !strings.Contains(qs[0], "WHERE Username = 'twin@example.com.new'") {
		t.Errorf("username query: %q", qs[0])
	}
	f3 := newFake(t)
	byFed := newConn(t, f3, map[string]string{"match_field": matchFederationID}, secret.Secret{})
	id, err = byFed.ResolveIdentity(ctx, integration.User{Email: "bob"})
	if err != nil || id.ID != bobID {
		t.Errorf("by federation id: %+v %v", id, err)
	}
	if qs := f3.queriesFrom("User"); !strings.Contains(qs[0], "WHERE FederationIdentifier = 'bob'") {
		t.Errorf("federation query: %q", qs[0])
	}
	if _, err := byFed.ResolveIdentity(ctx, integration.User{Email: "bob\x01"}); integration.ToDecision(err).Code != integration.CodeInvalidRequest {
		t.Errorf("control character accepted: %v", err)
	}
}

func TestInactiveAndFrozen(t *testing.T) {
	f, c := setup(t)
	expect(t, check(t, c, ian, "record.read", "record:"+acctID), integration.CodeDenied, "inactive")
	expect(t, check(t, c, ian, "user.active", "user:ian@example.com"), integration.CodeDenied, "inactive")
	expect(t, check(t, c, fred, "object.read", "object:Account"), integration.CodeDenied, "frozen")
	if qs := f.queriesFrom("UserLogin"); len(qs) != 3 || !strings.Contains(qs[2], "WHERE UserId = '"+fredID+"'") {
		t.Errorf("UserLogin queries: %q", qs)
	}
	if len(f.queriesFrom("UserRecordAccess")) != 0 || len(f.queriesFrom("ObjectPermissions")) != 0 {
		t.Error("an inactive or frozen user still reached the permission query")
	}
}

func TestFrozenCheckSkippedWhenUserLoginMissing(t *testing.T) {
	f, c := setup(t)
	f.errors["UserLogin"] = sfErr{400, "INVALID_TYPE"}
	// The user is still allowed, but the identity records that freezing
	// was not evaluated and user.active says so.
	id, err := c.ResolveIdentity(context.Background(), fred)
	if err != nil || id.Attr(attrFrozen) != frozenUnknown {
		t.Errorf("identity with UserLogin missing: %+v %v", id, err)
	}
	expect(t, check(t, c, fred, "user.active", "user:fred@example.com"), integration.CodeAllowed, "frozen users are not detected")
	// The probe reports the gap by trying the query on the integration user.
	r, err := c.Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, w := range r.Warnings {
		if strings.Contains(w, "frozen users are not detected: UserLogin not queryable") {
			found = true
		}
	}
	if !found {
		t.Errorf("probe warnings %q lack the frozen warning", r.Warnings)
	}
	if qs := f.queriesFrom("UserLogin"); len(qs) == 0 || !strings.Contains(qs[len(qs)-1], "WHERE UserId = '005000000000000AAA'") {
		t.Errorf("probe UserLogin queries: %q", qs)
	}
	f.errors["UserLogin"] = sfErr{403, "INSUFFICIENT_ACCESS"}
	expect(t, check(t, c, fred, "user.active", "user:fred@example.com"), integration.CodeCredentialRejected, "UserLogin")
	if _, err := c.Probe(context.Background()); integration.ToDecision(err).Code != integration.CodeCredentialRejected {
		t.Errorf("probe with UserLogin forbidden: %v", err)
	}
	// With a frozen user the attribute is definite and the check denies.
	delete(f.errors, "UserLogin")
	id, err = c.ResolveIdentity(context.Background(), fred)
	if err != nil || id.Attr(attrFrozen) != frozenTrue {
		t.Errorf("identity of a frozen user: %+v %v", id, err)
	}
	// client_credentials has no username: UserLogin is probed unfiltered.
	f2 := newFake(t)
	f2.errors["UserLogin"] = sfErr{400, "INVALID_FIELD"}
	c2 := newConn(t, f2, map[string]string{"auth_flow": flowClientCredentials, "username": ""}, itest.Literal("consumer"))
	r, err = c2.Probe(context.Background())
	if err != nil || len(r.Warnings) != 2 || !strings.Contains(r.Warnings[0], "frozen users are not detected") {
		t.Errorf("client_credentials probe: %+v %v", r, err)
	}
	if qs := f2.queriesFrom("UserLogin"); len(qs) != 1 || qs[0] != "SELECT IsFrozen FROM UserLogin LIMIT 1" {
		t.Errorf("unfiltered UserLogin probe: %q", qs)
	}
}

// Finding: session-based permission sets and expired time-bound assignments
// must not grant, and when the org cannot filter them out an allow is unknown.
func TestSessionAndExpiredAssignmentsExcluded(t *testing.T) {
	f, c := setup(t)
	// Bob's session-based set grants Edit and his expired assignment
	// Delete; the filtered sub-select hides both.
	expect(t, check(t, c, bob, "object.edit", "object:Account"), integration.CodeDenied, "PermissionsEdit")
	expect(t, check(t, c, bob, "object.delete", "object:Account"), integration.CodeDenied, "PermissionsDelete")
	expect(t, check(t, c, bob, "object.read", "object:Invoice__c"), integration.CodeDenied, "Invoice__c")
	if n := len(f.queriesFrom("ObjectPermissions")); n != 3 {
		t.Errorf("%d ObjectPermissions queries, want 3 (no retry)", n)
	}
	// An org whose API version lacks the filter fields: the loose retry may
	// deny but never allow.
	f.mu.Lock()
	f.rejectAssignmentFilter = true
	f.mu.Unlock()
	f.srv.Reset()
	f.queries = nil
	expect(t, check(t, c, bob, "object.edit", "object:Account"), integration.CodeUnsupported, "could not exclude session-based or expired assignments")
	qs := f.queriesFrom("ObjectPermissions")
	if len(qs) != 2 || !assignFilterRe.MatchString(qs[0]) || !assignLooseRe.MatchString(qs[1]) {
		t.Errorf("fallback queries: %q", qs)
	}
	expect(t, check(t, c, bob, "object.create", "object:Account"), integration.CodeDenied, "PermissionsCreate")
	expect(t, check(t, c, bob, "object.read", "object:Contact"), integration.CodeDenied, "Contact")
	expect(t, check(t, c, dana, "field.read", "field:Account.Rating"), integration.CodeUnsupported, "could not exclude")
	expect(t, check(t, c, bob, "field.edit", "field:Account.Rating"), integration.CodeDenied, "PermissionsEdit")
	expect(t, check(t, c, dana, "system.permission", "permission:PermissionsApiEnabled"), integration.CodeUnsupported, "could not exclude")
	expect(t, check(t, c, bob, "system.permission", "permission:PermissionsViewSetup"), integration.CodeDenied, "PermissionsViewSetup")
	// An INVALID_FIELD that the loose retry also hits is reported as such.
	f.errors["ObjectPermissions"] = sfErr{400, "INVALID_FIELD"}
	expect(t, check(t, c, bob, "object.read", "object:Account"), integration.CodeUnsupported, "INVALID_FIELD")
}

// Finding: the identity lookup is an exact Username match first, then a
// bounded match_field query from which nothing is picked when the bound is
// reached.
func TestIdentityExactUsernameFirst(t *testing.T) {
	f, c := setup(t)
	ctx := context.Background()
	id, err := c.ResolveIdentity(ctx, dana)
	if err != nil || id.ID != danaID {
		t.Fatalf("%+v %v", id, err)
	}
	if qs := f.queriesFrom("User"); len(qs) != 1 || !strings.HasSuffix(qs[0], "WHERE Username = 'dana@example.com' LIMIT 2") {
		t.Errorf("a Username match should need one query: %q", qs)
	}
	// Five rows share the email and exactly one is an active Standard user,
	// but the query limit is reached: the rows are a subset, so ambiguous.
	_, err = c.ResolveIdentity(ctx, integration.User{Email: "many@example.com"})
	if d := integration.ToDecision(err); d.Code != integration.CodeUserAmbiguous || !strings.Contains(d.Text, "at least 4") {
		t.Errorf("limit reached: %v", err)
	}
	if qs := f.queriesFrom("User"); !strings.HasSuffix(qs[len(qs)-1], "WHERE Email = 'many@example.com' LIMIT 4") {
		t.Errorf("match_field query: %q", qs[len(qs)-1])
	}
	// Two rows with one Username: the exact lookup does not pick either.
	_, err = c.ResolveIdentity(ctx, integration.User{Email: "dup@example.com"})
	if d := integration.ToDecision(err); d.Code != integration.CodeUserAmbiguous {
		t.Errorf("duplicate Username: %v", err)
	}
	// match_field Username is one exact query, LIMIT 2.
	f2 := newFake(t)
	byUsername := newConn(t, f2, map[string]string{"match_field": matchUsername}, secret.Secret{})
	if _, err := byUsername.ResolveIdentity(ctx, integration.User{Email: "nobody@example.com"}); integration.ToDecision(err).Code != integration.CodeUserNotFound {
		t.Errorf("unknown username: %v", err)
	}
	if qs := f2.queriesFrom("User"); len(qs) != 1 || !strings.HasSuffix(qs[0], "WHERE Username = 'nobody@example.com' LIMIT 2") {
		t.Errorf("username queries: %q", qs)
	}
	if _, err := byUsername.ResolveIdentity(ctx, integration.User{Email: "dup@example.com"}); integration.ToDecision(err).Code != integration.CodeUserAmbiguous {
		t.Errorf("duplicate username by Username: %v", err)
	}
	// match_field FederationIdentifier never consults Username: a federation
	// id that happens to equal another user's Username must not resolve.
	f3 := newFake(t)
	f3.users = append(f3.users, userRow{ID: "00500000000000JAAA", IsActive: true, Username: "fed@example.com", Email: "fed-other@example.com", FederationIdentifier: "someone-else", UserType: "Standard"})
	byFed := newConn(t, f3, map[string]string{"match_field": matchFederationID}, secret.Secret{})
	if _, err := byFed.ResolveIdentity(ctx, integration.User{Email: "fed@example.com"}); integration.ToDecision(err).Code != integration.CodeUserNotFound {
		t.Errorf("federation id equal to a Username: %v", err)
	}
	if qs := f3.queriesFrom("User"); len(qs) != 1 || !strings.Contains(qs[0], "WHERE FederationIdentifier = 'fed@example.com' LIMIT 4") {
		t.Errorf("federation queries: %q", qs)
	}
}

// Finding: zero ObjectPermissions rows for an object that does not exist is
// unknown, not deny; the describe that tells them apart is cached.
func TestObjectMissingIsUnknown(t *testing.T) {
	f, c := setup(t)
	expect(t, check(t, c, bob, "object.read", "object:Ghost__c"), integration.CodeResourceNotVisible, "does not exist or is not visible")
	expect(t, check(t, c, bob, "object.edit", "object:Ghost__c"), integration.CodeResourceNotVisible, "Ghost__c")
	if n := f.describeCalls("Ghost__c"); n != 1 {
		t.Errorf("Ghost__c described %d times, want 1 (cached)", n)
	}
	// An object that exists with no rows is still a deny, and its describe
	// is cached too.
	expect(t, check(t, c, bob, "object.read", "object:Invoice__c"), integration.CodeDenied, "Invoice__c")
	expect(t, check(t, c, bob, "object.create", "object:Invoice__c"), integration.CodeDenied, "Invoice__c")
	if n := f.describeCalls("Invoice__c"); n != 1 {
		t.Errorf("Invoice__c described %d times, want 1 (cached)", n)
	}
	// Rows present: no describe at all.
	expect(t, check(t, c, bob, "object.edit", "object:Account"), integration.CodeDenied, "")
	if n := f.describeCalls("Account"); n != 0 {
		t.Errorf("Account described %d times, want 0", n)
	}
	// Describe failures other than 404 are errors, never deny.
	f.errors["describe:Nope__c"] = sfErr{403, "INSUFFICIENT_ACCESS"}
	expect(t, check(t, c, bob, "object.read", "object:Nope__c"), integration.CodeCredentialRejected, "Nope__c")
	f.errors["describe:Nope__c"] = sfErr{500, "UNKNOWN_EXCEPTION"}
	expect(t, check(t, c, bob, "object.read", "object:Nope__c"), integration.CodeUpstreamError, "")
	// The describe path is the sObject's own.
	for _, call := range f.srv.Calls() {
		if strings.Contains(call.Path, "/sobjects/Ghost__c") && call.Path != "/inst/services/data/"+testVersion+"/sobjects/Ghost__c/describe" {
			t.Errorf("describe path %s", call.Path)
		}
	}
}

// Finding: a managed package's permission set is permset:<ns>__<Name> and
// the namespace is part of the match.
func TestPermSetNamespace(t *testing.T) {
	f, c := setup(t)
	expect(t, check(t, c, dana, "permset.assigned", "permset:acme__Billing"), integration.CodeAllowed, "acme__Billing")
	qs := f.queriesFrom("PermissionSetAssignment")
	if len(qs) != 1 || qs[0] != "SELECT Id FROM PermissionSetAssignment WHERE AssigneeId = '"+danaID+"' AND PermissionSet.Name = 'Billing' AND PermissionSet.NamespacePrefix = 'acme'" {
		t.Errorf("query %q", qs)
	}
	// The unprefixed name matches only sets without a namespace, and the
	// prefixed one only the package's set.
	expect(t, check(t, c, dana, "permset.assigned", "permset:Billing"), integration.CodeDenied, "Billing")
	expect(t, check(t, c, bob, "permset.assigned", "permset:Billing"), integration.CodeAllowed, "Billing")
	expect(t, check(t, c, bob, "permset.assigned", "permset:acme__Billing"), integration.CodeDenied, "acme__Billing")
	expect(t, check(t, c, dana, "permset.assigned", "permset:other__Billing"), integration.CodeDenied, "other__Billing")
	before := len(f.queriesFrom("PermissionSetAssignment"))
	for _, bad := range []string{"permset:acme__", "permset:__Billing", "permset:a__b__c", "permset:1ns__Billing", "permset:acme__Bill'ing", "permset:ac me__Billing"} {
		expect(t, check(t, c, dana, "permset.assigned", bad), integration.CodeInvalidRequest, "")
	}
	if n := len(f.queriesFrom("PermissionSetAssignment")); n != before {
		t.Error("a malformed permset resource reached the query")
	}
}

// Finding: upstream error codes and MaxAccessLevel are validated before they
// reach a decision text or a log line.
func TestUpstreamStringsSanitised(t *testing.T) {
	f, c := setup(t)
	f.errors["UserRecordAccess"] = sfErr{400, "INVALID_TYPE " + itest.Canary}
	expect(t, check(t, c, dana, "record.read", "record:"+acctID), integration.CodeUpstreamError, "")
	f.errors["UserRecordAccess"] = sfErr{403, "insufficient-access " + itest.Canary}
	expect(t, check(t, c, dana, "record.read", "record:"+acctID), integration.CodeCredentialRejected, "")
	f.errors["UserRecordAccess"] = sfErr{400, "MALFORMED_QUERY"}
	d := check(t, c, dana, "record.read", "record:"+acctID)
	expect(t, d, integration.CodeUnsupported, "MALFORMED_QUERY")
	delete(f.errors, "UserRecordAccess")
	f.recordAccess[bobID+"|"+acctID] = recordAccessRow{RecordID: acctID, HasReadAccess: true, MaxAccessLevel: itest.Canary}
	expect(t, check(t, c, bob, "record.read", "record:"+acctID), integration.CodeAllowed, "max access level unknown")
	f.recordAccess[bobID+"|"+acctID] = recordAccessRow{RecordID: acctID, MaxAccessLevel: "None"}
	expect(t, check(t, c, bob, "record.read", "record:"+acctID), integration.CodeDenied, "max access level None")
	// The apiError's own string, which reaches logs, carries no raw code.
	e := decodeAPIError(&httpx.Response{Status: 400, Body: []byte(`[{"errorCode":"BAD code","message":"m"},{"errorCode":"INVALID_FIELD"},{"errorCode":"x"}]`)})
	if got := e.Error(); got != "salesforce: HTTP 400 unknown error,INVALID_FIELD" {
		t.Errorf("apiError: %q", got)
	}
}

// Finding: instance_url from the token response is used only when its host
// is the configured url's or a Salesforce domain.
func TestInstanceURLUntrustedHost(t *testing.T) {
	f := newFake(t)
	f.instanceURL = "https://evil.example.com/inst"
	deps, logs := itest.Deps(t, f.srv)
	s := itest.Settings("sf", "salesforce", baseValues(f.srv.URL), map[string]secret.Secret{"credential": keySecret(t)})
	c, err := Integration{}.New(context.Background(), s, deps)
	if err != nil {
		t.Fatal(err)
	}
	expect(t, check(t, c, dana, "record.read", "record:"+acctID), integration.CodeAllowed, "")
	for _, call := range f.srv.Calls() {
		if strings.HasPrefix(call.Path, "/inst/") {
			t.Errorf("used the untrusted instance_url: %s", call.Path)
		}
	}
	if !strings.Contains(logs.String(), "untrusted host") || !strings.Contains(logs.String(), "evil.example.com") {
		t.Errorf("no debug log about the ignored instance_url:\n%s", logs.String())
	}
	conn := &Connection{url: "https://acme.my.salesforce.com", logger: deps.Logger}
	for _, cs := range []struct {
		inst string
		want string
	}{
		{"https://acme.my.salesforce.com", "https://acme.my.salesforce.com"},
		{"https://ACME.my.salesforce.com/", "https://ACME.my.salesforce.com"},
		{"https://na139.salesforce.com", "https://na139.salesforce.com"},
		{"https://acme--dev.sandbox.my.salesforce.com", "https://acme--dev.sandbox.my.salesforce.com"},
		{"https://acme.lightning.force.com", "https://acme.lightning.force.com"},
		{"https://acme.my.salesforce.mil", "https://acme.my.salesforce.mil"},
		{"https://salesforce.com", "https://acme.my.salesforce.com"},
		{"https://evilsalesforce.com", "https://acme.my.salesforce.com"},
		{"https://acme.my.salesforce.com.evil.example", "https://acme.my.salesforce.com"},
		{"https://user@acme.my.salesforce.com", "https://acme.my.salesforce.com"},
		{"http://acme.my.salesforce.com", "https://acme.my.salesforce.com"},
		{"https://acme.my.salesforce.com?x=1", "https://acme.my.salesforce.com"},
		{"", "https://acme.my.salesforce.com"},
	} {
		conn.setInstanceURL(cs.inst)
		if got := conn.apiBase(); got != cs.want {
			t.Errorf("instance_url %q -> base %q, want %q", cs.inst, got, cs.want)
		}
	}
}

// --- checks -----------------------------------------------------------------

func TestRecordQueryShapeAndUnknowns(t *testing.T) {
	f, c := setup(t)
	expect(t, check(t, c, bob, "record.read", "record:"+acctID), integration.CodeAllowed, "Read")
	qs := f.queriesFrom("UserRecordAccess")
	want := "SELECT RecordId, HasReadAccess, HasEditAccess, HasDeleteAccess, HasTransferAccess, HasAllAccess, MaxAccessLevel FROM UserRecordAccess WHERE UserId = '" + bobID + "' AND RecordId = '" + acctID + "'"
	if len(qs) != 1 || qs[0] != want {
		t.Errorf("query %q\nwant  %q", qs, want)
	}
	expect(t, check(t, c, dana, "record.read", "record:"+hiddenID), integration.CodeResourceNotVisible, "not visible")
	if _, ok := integration.FindAction(Integration{}, "record.create"); ok {
		t.Error("record.create must not be an action; records are created per object")
	}
}

func TestRecordCreateHint(t *testing.T) {
	_, c := setup(t)
	id, _ := c.ResolveIdentity(context.Background(), dana)
	_, err := c.Check(context.Background(), integration.CheckRequest{User: dana, Identity: id, ActionName: "record.create"})
	if d := integration.ToDecision(err); d.Code != integration.CodeInvalidRequest || !strings.Contains(d.Text, "object.create") {
		t.Errorf("record.create: %v", err)
	}
}

func TestObjectQueryShapeAndUnknowns(t *testing.T) {
	f, c := setup(t)
	expect(t, check(t, c, bob, "object.read", "object:Account"), integration.CodeAllowed, "profile Minimum Access")
	expectQuery(t, f.queriesFrom("ObjectPermissions"), "SELECT PermissionsRead, PermissionsCreate, PermissionsEdit, PermissionsDelete, PermissionsViewAllRecords, PermissionsModifyAllRecords, Parent.IsOwnedByProfile, Parent.Name FROM ObjectPermissions WHERE SobjectType = 'Account' AND ParentId IN <assigned>")
	// Zero rows for an object that exists: nothing grants it, a deny.
	expect(t, check(t, c, bob, "object.read", "object:Invoice__c"), integration.CodeDenied, "Invoice__c")
	// The object does not exist: unknown.
	f.errors["ObjectPermissions"] = sfErr{400, "INVALID_TYPE"}
	expect(t, check(t, c, bob, "object.read", "object:Nope__c"), integration.CodeUnsupported, "Nope__c")
	delete(f.errors, "ObjectPermissions")
	f.errors["ObjectPermissions"] = sfErr{400, "INVALID_FIELD"}
	expect(t, check(t, c, bob, "object.read", "object:Account"), integration.CodeUnsupported, "INVALID_FIELD")
}

func TestFieldQueryShapeAndUnknowns(t *testing.T) {
	f, c := setup(t)
	expect(t, check(t, c, bob, "field.read", "field:Account.Rating"), integration.CodeAllowed, "permission set Readers")
	expectQuery(t, f.queriesFrom("FieldPermissions"), "SELECT PermissionsRead, PermissionsEdit, Parent.IsOwnedByProfile, Parent.Name FROM FieldPermissions WHERE SobjectType = 'Account' AND Field = 'Account.Rating' AND ParentId IN <assigned>")
	expect(t, check(t, c, bob, "field.read", "field:Account.Name"), integration.CodeUnsupported, "no FieldPermissions rows")
}

func TestSystemPermissionDescribe(t *testing.T) {
	f, c := setup(t)
	expect(t, check(t, c, dana, "system.permission", "permission:PermissionsViewSetup"), integration.CodeAllowed, "profile Sales")
	expectQuery(t, f.queriesFrom("PermissionSet"), "SELECT Id, Name, IsOwnedByProfile FROM PermissionSet WHERE PermissionsViewSetup = true AND Id IN <assigned>")
	expect(t, check(t, c, dana, "system.permission", "permission:PermissionsNotAThing"), integration.CodeInvalidRequest, "PermissionsNotAThing")
	if len(f.queriesFrom("PermissionSet")) != 1 {
		t.Error("an unknown permission name reached the query")
	}
	describes := 0
	for _, call := range f.srv.Calls() {
		if strings.HasSuffix(call.Path, "/sobjects/PermissionSet/describe") {
			describes++
		}
	}
	if describes != 1 {
		t.Errorf("describe fetched %d times, want 1 (cached)", describes)
	}
	// Shape violations never reach the describe either.
	before := len(f.srv.Calls())
	expect(t, check(t, c, dana, "system.permission", "permission:ApiEnabled"), integration.CodeInvalidRequest, "")
	expect(t, check(t, c, dana, "system.permission", "permission:PermissionsApiEnabled = true OR Id != null"), integration.CodeInvalidRequest, "")
	for _, call := range f.srv.Calls()[before:] {
		if strings.HasSuffix(call.Path, "/describe") || strings.HasSuffix(call.Path, "/query") && strings.Contains(call.Query.Get("q"), "FROM PermissionSet ") {
			t.Errorf("shape violation reached %s", call.Path)
		}
	}
}

func TestPermissionSetGroupStatus(t *testing.T) {
	f, c := setup(t)
	f.groups[danaID] = []string{groupID}
	expect(t, check(t, c, dana, "object.read", "object:Account"), integration.CodeAllowed, "")
	if qs := f.queriesFrom("PermissionSetGroup"); len(qs) != 1 || !strings.Contains(qs[0], "WHERE Id IN ('"+groupID+"')") {
		t.Errorf("group query: %q", qs)
	}
	f.mu.Lock()
	f.groupStatus[groupID] = "Outdated"
	f.mu.Unlock()
	expect(t, check(t, c, dana, "object.read", "object:Account"), integration.CodeUnsupported, "not yet recalculated")
	expect(t, check(t, c, dana, "field.read", "field:Account.Rating"), integration.CodeUnsupported, "Group_1AAA")
	expect(t, check(t, c, dana, "system.permission", "permission:PermissionsApiEnabled"), integration.CodeUnsupported, "")
	// Assignments to groups, and the group object, may not exist in the org.
	f.errors["PermissionSetAssignment"] = sfErr{400, "INVALID_FIELD"}
	expect(t, check(t, c, dana, "object.read", "object:Account"), integration.CodeAllowed, "")
}

func TestErrorMapping(t *testing.T) {
	f, c := setup(t)
	cases := []struct {
		err  sfErr
		code integration.Code
	}{
		{sfErr{403, "REQUEST_LIMIT_EXCEEDED"}, integration.CodeUpstreamRateLimit},
		{sfErr{403, "API_DISABLED_FOR_ORG"}, integration.CodeCredentialRejected},
		{sfErr{403, "INSUFFICIENT_ACCESS"}, integration.CodeCredentialRejected},
		{sfErr{404, "NOT_FOUND"}, integration.CodeResourceNotVisible},
		{sfErr{400, "MALFORMED_QUERY"}, integration.CodeUnsupported},
		{sfErr{400, "INVALID_TYPE"}, integration.CodeUnsupported},
		{sfErr{400, "SOMETHING_ELSE"}, integration.CodeUpstreamError},
		{sfErr{429, "REQUEST_LIMIT_EXCEEDED"}, integration.CodeUpstreamRateLimit},
	}
	for _, cs := range cases {
		f.errors["UserRecordAccess"] = cs.err
		d := check(t, c, dana, "record.read", "record:"+acctID)
		if d.Code != cs.code {
			t.Errorf("%d %s -> %s (%s), want %s", cs.err.status, cs.err.code, d.Code, d.Text, cs.code)
		}
		if strings.Contains(d.Text, itest.Canary) {
			t.Errorf("upstream message leaked: %s", d.Text)
		}
	}
}

func TestBadResources(t *testing.T) {
	f, c := setup(t)
	before := len(f.srv.Calls())
	cases := []struct{ action, resource string }{
		{"record.read", "object:Account"},
		{"record.read", "record:001"},
		{"record.read", "record:001000000000001AAA'"},
		{"record.read", "record:" + acctID + "?x=1"},
		{"object.read", "record:" + acctID},
		{"object.read", "object:Account'"},
		{"object.read", "object:Account Name"},
		{"object.read", "object:"},
		{"field.read", "field:Account"},
		{"field.read", "field:Account.Rating.Sub"},
		{"field.read", "field:Account.Rating'"},
		{"field.edit", "object:Account"},
		{"system.permission", "permission:ApiEnabled"},
		{"system.permission", "permset:X"},
		{"permset.assigned", "permset:Sales Ops"},
		{"permset.assigned", "permission:PermissionsApiEnabled"},
		{"user.active", "user:not-an-email"},
		{"user.active", "user:Dana <dana@example.com>"},
		{"user.active", "object:Account"},
		{"user.active", "record:" + acctID},
		{"user.active", "user:bob@example.com"},
	}
	for _, cs := range cases {
		d := check(t, c, dana, cs.action, cs.resource)
		if d.Code != integration.CodeInvalidRequest {
			t.Errorf("%s %s -> %s: %s", cs.action, cs.resource, d.Code, d.Text)
		}
	}
	// Only identity lookups happened: no permission query was sent for any of them.
	for _, call := range f.srv.Calls()[before:] {
		q := call.Query.Get("q")
		if q != "" && !strings.Contains(q, "FROM User ") && !strings.Contains(q, "FROM UserLogin ") {
			t.Errorf("invalid resource reached a query: %s", q)
		}
	}
}

func TestFailures(t *testing.T) {
	f, c := setup(t)
	expect(t, check(t, c, dana, "record.read", "record:"+acctID), integration.CodeAllowed, "")
	itest.FailureCases(t, f.srv, func() integration.Decision {
		return check(t, c, dana, "record.read", "record:"+acctID)
	})
	// Also with no token cached yet: the failure hits the token endpoint.
	f2 := newFake(t)
	c2 := newConn(t, f2, nil, secret.Secret{})
	itest.FailureCases(t, f2.srv, func() integration.Decision {
		return check(t, c2, dana, "record.read", "record:"+acctID)
	})
}

func TestProbe(t *testing.T) {
	f, c := setup(t)
	r, err := c.Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.Summary, "14000 of 15000") || !strings.Contains(r.Summary, testUsername) || !strings.Contains(r.Summary, testVersion) || !strings.Contains(r.Summary, "3 permission fields") {
		t.Errorf("summary %q", r.Summary)
	}
	if len(r.Warnings) != 1 || !strings.Contains(r.Warnings[0], "View All") {
		t.Errorf("warnings %q", r.Warnings)
	}
	if qs := f.queriesFrom("User"); len(qs) != 1 || qs[0] != "SELECT Id, Username, IsActive FROM User WHERE Username = '"+testUsername+"'" {
		t.Errorf("probe user query %q", qs)
	}
	if qs := f.queriesFrom("UserLogin"); len(qs) != 1 || qs[0] != "SELECT IsFrozen FROM UserLogin WHERE UserId = '005000000000000AAA'" {
		t.Errorf("probe frozen query %q", qs)
	}
	f.mu.Lock()
	f.remaining = 1200
	f.mu.Unlock()
	r, _ = c.Probe(context.Background())
	if len(r.Warnings) != 2 || !strings.Contains(r.Warnings[0], "10%") {
		t.Errorf("low-limit warnings %q", r.Warnings)
	}
	f3 := newFake(t)
	f3.users = f3.users[1:] // no row for the integration user
	c3 := newConn(t, f3, nil, secret.Secret{})
	r, err = c3.Probe(context.Background())
	if err != nil || len(r.Warnings) != 2 || !strings.Contains(r.Warnings[0], testUsername) {
		t.Errorf("missing integration user: %+v %v", r, err)
	}
	f3.srv.Fail(itest.FailUnauthorized)
	if _, err := c3.Probe(context.Background()); integration.ToDecision(err).Code != integration.CodeCredentialRejected {
		t.Errorf("probe with a rejected credential: %v", err)
	}
	f3.srv.Fail(itest.FailNone)
	f4 := newFake(t)
	f4.describeFields = []string{"Id", "Name"}
	c4 := newConn(t, f4, nil, secret.Secret{})
	if _, err := c4.Probe(context.Background()); err == nil {
		t.Error("probe accepted a describe without permission fields")
	}
}

func TestNewValidation(t *testing.T) {
	f := newFake(t)
	deps, _ := itest.Deps(t, f.srv)
	try := func(values map[string]string, cred secret.Secret) error {
		v := baseValues(f.srv.URL)
		for k, val := range values {
			v[k] = val
		}
		secrets := map[string]secret.Secret{}
		if !cred.IsZero() {
			secrets["credential"] = cred
		}
		_, err := Integration{}.New(context.Background(), itest.Settings("sf", "salesforce", v, secrets), deps)
		return err
	}
	if err := try(nil, keySecret(t)); err != nil {
		t.Errorf("valid settings: %v", err)
	}
	if err := try(nil, secret.Secret{}); err == nil {
		t.Error("missing credential accepted")
	}
	for _, bad := range []map[string]string{
		{"username": ""},
		{"client_id": ""},
		{"url": ""},
		{"api_version": ""},
		{"api_version": "66.0"},
		{"api_version": "v66"},
		{"api_version": "latest"},
		{"auth_flow": "password"},
		{"match_field": "Alias"},
		{"token_ttl": "soon"},
		{"token_ttl": "10s"},
	} {
		if err := try(bad, keySecret(t)); err == nil {
			t.Errorf("settings %v accepted", bad)
		}
	}
	if err := try(map[string]string{"auth_flow": flowClientCredentials, "username": ""}, itest.Literal("consumer")); err != nil {
		t.Errorf("client_credentials without username: %v", err)
	}
	// Field validators agree with New.
	for _, fld := range (Integration{}).Fields() {
		if fld.Validate == nil {
			continue
		}
		switch fld.Name {
		case "api_version":
			if fld.Validate("v66.0") != nil || fld.Validate("66") == nil {
				t.Error("api_version validator")
			}
		case "token_ttl":
			if fld.Validate("15m") != nil || fld.Validate("x") == nil {
				t.Error("token_ttl validator")
			}
		case "username":
			if fld.Validate("a@b.c") != nil || fld.Validate("a'b") == nil {
				t.Error("username validator")
			}
		case "audience":
			if fld.Validate("https://test.salesforce.com") != nil || fld.Validate("http://evil") == nil {
				t.Error("audience validator")
			}
		}
	}
	if err := integration.ValidateFields(Integration{}.Fields()); err != nil {
		t.Error(err)
	}
}

func TestBadKeyAndNoLeak(t *testing.T) {
	f := newFake(t)
	deps, logs := itest.Deps(t, f.srv)
	s := itest.Settings("sf", "salesforce", baseValues(f.srv.URL), map[string]secret.Secret{"credential": itest.Literal("not-a-key")})
	c, err := Integration{}.New(context.Background(), s, deps)
	if err != nil {
		t.Fatal(err)
	}
	d := check(t, c, dana, "record.read", "record:"+acctID)
	if d.Code != integration.CodeCredentialRejected || strings.Contains(d.Text, itest.Canary) {
		t.Errorf("bad key: %s %s", d.Code, d.Text)
	}
	if f.tokenCount() != 0 {
		t.Error("a token request was sent without a signed assertion")
	}
	// A rejected assertion: the error_description carries the canary.
	f2 := newFake(t)
	f2.lenientJWT = true // the claim mismatch is the point
	c2 := newConn(t, f2, map[string]string{"username": "someone-else@acme.example"}, secret.Secret{})
	d = check(t, c2, dana, "record.read", "record:"+acctID)
	if d.Code != integration.CodeCredentialRejected || strings.Contains(d.Text, itest.Canary) {
		t.Errorf("rejected assertion: %s %s", d.Code, d.Text)
	}
	itest.AssertNoCanary(t, logs.String())
}

func TestActionsListed(t *testing.T) {
	seen := map[string]bool{}
	for _, a := range (Integration{}).Actions() {
		if a.Pattern || a.Description == "" {
			t.Errorf("action %+v", a)
		}
		seen[a.Name] = true
	}
	for _, want := range []string{"record.read", "record.edit", "record.delete", "record.transfer", "record.share", "object.read", "object.create", "object.edit", "object.delete", "object.view_all", "object.modify_all", "field.read", "field.edit", "system.permission", "permset.assigned", "user.active"} {
		if !seen[want] {
			t.Errorf("action %s missing", want)
		}
	}
	if len(seen) != 16 {
		t.Errorf("%d actions, want 16", len(seen))
	}
}

// --- allow/deny per action (coverage gate) ----------------------------------

func TestAction_record_read_allow(t *testing.T) {
	_, c := setup(t)
	expect(t, check(t, c, dana, "record.read", "record:"+acctID), integration.CodeAllowed, "HasReadAccess")
}
func TestAction_record_read_deny(t *testing.T) {
	f, c := setup(t)
	f.recordAccess[bobID+"|"+acctID] = recordAccessRow{RecordID: acctID, MaxAccessLevel: "None"}
	expect(t, check(t, c, bob, "record.read", "record:"+acctID), integration.CodeDenied, "HasReadAccess")
}
func TestAction_record_edit_allow(t *testing.T) {
	_, c := setup(t)
	expect(t, check(t, c, dana, "record.edit", "record:"+acctID), integration.CodeAllowed, "HasEditAccess")
}
func TestAction_record_edit_deny(t *testing.T) {
	_, c := setup(t)
	expect(t, check(t, c, bob, "record.edit", "record:"+acctID), integration.CodeDenied, "HasEditAccess")
}
func TestAction_record_delete_allow(t *testing.T) {
	_, c := setup(t)
	expect(t, check(t, c, dana, "record.delete", "record:"+acctID), integration.CodeAllowed, "HasDeleteAccess")
}
func TestAction_record_delete_deny(t *testing.T) {
	_, c := setup(t)
	expect(t, check(t, c, bob, "record.delete", "record:"+acctID), integration.CodeDenied, "HasDeleteAccess")
}
func TestAction_record_transfer_allow(t *testing.T) {
	_, c := setup(t)
	expect(t, check(t, c, dana, "record.transfer", "record:"+acctID), integration.CodeAllowed, "HasTransferAccess")
}
func TestAction_record_transfer_deny(t *testing.T) {
	_, c := setup(t)
	expect(t, check(t, c, bob, "record.transfer", "record:"+acctID), integration.CodeDenied, "HasTransferAccess")
}
func TestAction_record_share_allow(t *testing.T) {
	_, c := setup(t)
	expect(t, check(t, c, dana, "record.share", "record:"+acctID), integration.CodeAllowed, "HasAllAccess")
}
func TestAction_record_share_deny(t *testing.T) {
	_, c := setup(t)
	expect(t, check(t, c, bob, "record.share", "record:"+acctID), integration.CodeDenied, "HasAllAccess")
}
func TestAction_object_read_allow(t *testing.T) {
	_, c := setup(t)
	expect(t, check(t, c, dana, "object.read", "object:Account"), integration.CodeAllowed, "profile Sales")
}
func TestAction_object_read_deny(t *testing.T) {
	_, c := setup(t)
	expect(t, check(t, c, bob, "object.read", "object:Invoice__c"), integration.CodeDenied, "")
}
func TestAction_object_create_allow(t *testing.T) {
	_, c := setup(t)
	expect(t, check(t, c, dana, "object.create", "object:Account"), integration.CodeAllowed, "PermissionsCreate")
}
func TestAction_object_create_deny(t *testing.T) {
	_, c := setup(t)
	expect(t, check(t, c, bob, "object.create", "object:Account"), integration.CodeDenied, "2 assigned")
}
func TestAction_object_edit_allow(t *testing.T) {
	_, c := setup(t)
	expect(t, check(t, c, dana, "object.edit", "object:Account"), integration.CodeAllowed, "PermissionsEdit")
}
func TestAction_object_edit_deny(t *testing.T) {
	_, c := setup(t)
	expect(t, check(t, c, bob, "object.edit", "object:Account"), integration.CodeDenied, "PermissionsEdit")
}
func TestAction_object_delete_allow(t *testing.T) {
	_, c := setup(t)
	expect(t, check(t, c, dana, "object.delete", "object:Account"), integration.CodeAllowed, "PermissionsDelete")
}
func TestAction_object_delete_deny(t *testing.T) {
	_, c := setup(t)
	expect(t, check(t, c, bob, "object.delete", "object:Account"), integration.CodeDenied, "PermissionsDelete")
}
func TestAction_object_view_all_allow(t *testing.T) {
	_, c := setup(t)
	expect(t, check(t, c, dana, "object.view_all", "object:Account"), integration.CodeAllowed, "PermissionsViewAllRecords")
}
func TestAction_object_view_all_deny(t *testing.T) {
	_, c := setup(t)
	expect(t, check(t, c, bob, "object.view_all", "object:Account"), integration.CodeDenied, "PermissionsViewAllRecords")
}
func TestAction_object_modify_all_allow(t *testing.T) {
	_, c := setup(t)
	expect(t, check(t, c, dana, "object.modify_all", "object:Account"), integration.CodeAllowed, "PermissionsModifyAllRecords")
}
func TestAction_object_modify_all_deny(t *testing.T) {
	_, c := setup(t)
	expect(t, check(t, c, bob, "object.modify_all", "object:Account"), integration.CodeDenied, "PermissionsModifyAllRecords")
}
func TestAction_field_read_allow(t *testing.T) {
	_, c := setup(t)
	expect(t, check(t, c, dana, "field.read", "field:Account.Rating"), integration.CodeAllowed, "Account.Rating")
}
func TestAction_field_read_deny(t *testing.T) {
	_, c := setup(t)
	expect(t, check(t, c, bob, "field.read", "field:Account.Secret__c"), integration.CodeDenied, "Account.Secret__c")
}
func TestAction_field_edit_allow(t *testing.T) {
	_, c := setup(t)
	expect(t, check(t, c, dana, "field.edit", "field:Account.Rating"), integration.CodeAllowed, "PermissionsEdit")
}
func TestAction_field_edit_deny(t *testing.T) {
	_, c := setup(t)
	expect(t, check(t, c, bob, "field.edit", "field:Account.Rating"), integration.CodeDenied, "PermissionsEdit")
}
func TestAction_system_permission_allow(t *testing.T) {
	_, c := setup(t)
	expect(t, check(t, c, dana, "system.permission", "permission:PermissionsApiEnabled"), integration.CodeAllowed, "PermissionsApiEnabled")
}
func TestAction_system_permission_deny(t *testing.T) {
	_, c := setup(t)
	expect(t, check(t, c, bob, "system.permission", "permission:PermissionsViewSetup"), integration.CodeDenied, "PermissionsViewSetup")
}
func TestAction_permset_assigned_allow(t *testing.T) {
	f, c := setup(t)
	expect(t, check(t, c, dana, "permset.assigned", "permset:Sales_Ops"), integration.CodeAllowed, "Sales_Ops")
	qs := f.queriesFrom("PermissionSetAssignment")
	if len(qs) != 1 || qs[0] != "SELECT Id FROM PermissionSetAssignment WHERE AssigneeId = '"+danaID+"' AND PermissionSet.Name = 'Sales_Ops' AND PermissionSet.NamespacePrefix = null" {
		t.Errorf("query %q", qs)
	}
}
func TestAction_permset_assigned_deny(t *testing.T) {
	_, c := setup(t)
	expect(t, check(t, c, bob, "permset.assigned", "permset:Sales_Ops"), integration.CodeDenied, "Sales_Ops")
}
func TestAction_user_active_allow(t *testing.T) {
	_, c := setup(t)
	expect(t, check(t, c, dana, "user.active", "user:dana@example.com"), integration.CodeAllowed, "active")
	expect(t, check(t, c, dana, "user.active", "user:Dana@Example.com"), integration.CodeAllowed, "active")
	expect(t, check(t, c, dana, "user.active", "record:"+danaID), integration.CodeAllowed, "active")
}
func TestAction_user_active_deny(t *testing.T) {
	_, c := setup(t)
	expect(t, check(t, c, ian, "user.active", "user:ian@example.com"), integration.CodeDenied, "inactive")
	expect(t, check(t, c, fred, "user.active", "record:"+fredID), integration.CodeDenied, "frozen")
}
