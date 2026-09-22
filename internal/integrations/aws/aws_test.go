package aws

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/roee-hersh/hallpass/internal/integration"
	"github.com/roee-hersh/hallpass/internal/integration/itest"
	"github.com/roee-hersh/hallpass/internal/secret"
)

const (
	acct        = "123456789012"
	roleARN     = "arn:aws:iam::123456789012:role/hallpass-read"
	icRoleARN   = "arn:aws:iam::999999999999:role/hallpass-ic-read"
	storeID     = "d-1234567890"
	instanceARN = "arn:aws:sso:::instance/ssoins-0123456789abcdef"

	baseKey   = "AKIA" + itest.Canary + "base"
	targetKey = "ASIA" + itest.Canary + "target"
	icKey     = "ASIA" + itest.Canary + "ic"
	imdsKey   = "ASIA" + itest.Canary + "imds"

	psRO  = "arn:aws:sso:::permissionSet/ssoins-0123456789abcdef/ps-aaaaaaaaaaaaaaaa"
	psDev = "arn:aws:sso:::permissionSet/ssoins-0123456789abcdef/ps-bbbbbbbbbbbbbbbb"
	psAdm = "arn:aws:sso:::permissionSet/ssoins-0123456789abcdef/ps-cccccccccccccccc"

	roleRO    = "arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_ReadOnly_0123456789abcdef"
	roleDev   = "arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/eu-west-1/AWSReservedSSO_Developer_fedcba9876543210"
	roleAdmin = "arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Admin_00000000000000ff"

	bucketKey = "arn:aws:s3:::bucket/key"
)

var staticCred = secret.Literal(`{"access_key_id":"` + baseKey + `","secret_access_key":"` + itest.Canary + `secret"}`)

type icUserRec struct {
	id, userName, display, status string
}

type fakeRole struct{ name, path, arn string }

// fakeAWS serves STS, IAM, Identity Store, SSO Admin and IMDS on one server.
type fakeAWS struct {
	t  *testing.T
	mu sync.Mutex

	baseKey    string
	externalID string

	stsCalls, listRolesCalls, simulateCalls, getUserIDCalls int

	users          map[string]icUserRec // by email
	userNames      map[string]string    // userName -> email
	groups         map[string][]string  // user id -> group ids
	assignments    map[string][]string  // principal id -> permission set ARNs
	rowAccount     map[string]string    // permission set ARN -> AccountId to emit instead of acct
	permissionSets map[string]string    // ARN -> name
	roles          []fakeRole
	rolesPerPage   int
	iamUsers       map[string]string // user name -> ARN
	instances      []map[string]string

	policy         map[string]string // principal|action|resource -> decision
	missing        []string
	orgDenied      bool
	boundaryDenied bool
	evalOnly       bool
	evalDecision   string // overrides EvalDecision when resource-specific results are present
	pageSplit      bool
	simErr         string // IAM error code returned by SimulatePrincipalPolicy
	fail           string // "throttle" or "denied": every signed call fails
}

func newFake(t *testing.T) *fakeAWS {
	return &fakeAWS{
		t:       t,
		baseKey: baseKey,
		users: map[string]icUserRec{
			"dana@example.com": {id: "u-dana", userName: "dana", display: "Dana D"},
			"bob@example.com":  {id: "u-bob", userName: "bob", display: "Bob B"},
			"off@example.com":  {id: "u-off", userName: "off", display: "Off", status: "DISABLED"},
			"adm@example.com":  {id: "u-adm", userName: "adm", display: "Adm"},
		},
		userNames:   map[string]string{"lee@example.com": "lee@example.com"},
		groups:      map[string][]string{"u-dana": {"g-platform", "g-empty"}},
		assignments: map[string][]string{"u-dana": {psRO}, "g-platform": {psDev}, "u-off": {psRO}, "u-adm": {psAdm}, "u-lee": {psRO}},
		permissionSets: map[string]string{
			psRO: "ReadOnly", psDev: "Developer", psAdm: "Adm",
		},
		roles: []fakeRole{
			{name: "AWSReservedSSO_ReadOnly_0123456789abcdef", path: ssoPathPrefix, arn: roleRO},
			{name: "AWSReservedSSO_Admin_00000000000000ff", path: ssoPathPrefix, arn: roleAdmin},
			{name: "AWSReservedSSO_Developer_fedcba9876543210", path: ssoPathPrefix + "eu-west-1/", arn: roleDev},
			{name: "AWSReservedSSO_Other_1111111111111111", path: ssoPathPrefix, arn: "arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Other_1111111111111111"},
			{name: "AWSReservedSSO_ReadOnlyExtra_2222222222222222", path: ssoPathPrefix, arn: "arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_ReadOnlyExtra_2222222222222222"},
		},
		rolesPerPage: 3,
		iamUsers: map[string]string{
			"dana":            "arn:aws:iam::123456789012:user/dana",
			"lee@example.com": "arn:aws:iam::123456789012:user/lee@example.com",
		},
		instances: []map[string]string{{"InstanceArn": instanceARN, "IdentityStoreId": storeID}},
		policy: map[string]string{
			roleRO + "|s3:GetObject|" + bucketKey:                           "allowed",
			roleDev + "|s3:PutObject|" + bucketKey:                          "allowed",
			roleRO + "|ec2:TerminateInstances|*":                            "explicitDeny",
			roleDev + "|ec2:TerminateInstances|*":                           "explicitDeny",
			roleDev + "|ec2:StopInstances|*":                                "explicitDeny",
			"arn:aws:iam::123456789012:user/dana|s3:GetObject|" + bucketKey: "allowed",
			"arn:aws:iam::123456789012:role/Deployer|s3:GetObject|*":        "allowed",
			"arn:aws:iam::123456789012:role/PlatformAdmin|s3:GetObject|*":   "allowed",
		},
	}
}

func (f *fakeAWS) user(email string) (icUserRec, bool) {
	u, ok := f.users[email]
	if ok {
		return u, true
	}
	for e, name := range f.userNames {
		if name == email {
			return icUserRec{id: "u-" + strings.Split(e, "@")[0], userName: name, display: name}, true
		}
	}
	return icUserRec{}, false
}

// credentialScope returns the access key id and signing service of a SigV4 header.
func credentialScope(auth string) (akid, region, service string) {
	_, rest, ok := strings.Cut(auth, "Credential=")
	if !ok {
		return "", "", ""
	}
	cred, _, _ := strings.Cut(rest, ",")
	parts := strings.Split(cred, "/")
	if len(parts) != 5 {
		return "", "", ""
	}
	return parts[0], parts[2], parts[3]
}

func xmlError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "text/xml")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<ErrorResponse><Error><Type>Sender</Type><Code>%s</Code><Message>%s</Message></Error><RequestId>r</RequestId></ErrorResponse>`, code, msg)
}

func jsonError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"__type":"com.amazonaws.identitystore#%s","Message":"%s"}`, code, msg)
}

func (f *fakeAWS) handler(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	// IMDSv2 (unsigned).
	switch {
	case r.Method == "PUT" && r.URL.Path == "/latest/api/token":
		if r.Header.Get("X-aws-ec2-metadata-token-ttl-seconds") == "" {
			w.WriteHeader(400)
			return
		}
		w.Write([]byte("imds-token"))
		return
	case strings.HasPrefix(r.URL.Path, "/latest/meta-data/"):
		if r.Header.Get("X-aws-ec2-metadata-token") != "imds-token" {
			w.WriteHeader(401)
			return
		}
		if r.URL.Path == "/latest/meta-data/iam/security-credentials/" {
			w.Write([]byte("instance-role\n"))
			return
		}
		if r.URL.Path == "/latest/meta-data/iam/security-credentials/instance-role" {
			json.NewEncoder(w).Encode(map[string]string{"AccessKeyId": imdsKey, "SecretAccessKey": itest.Canary + "imds", "Token": itest.Canary + "imdstok", "Expiration": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
			return
		}
		w.WriteHeader(404)
		return
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 ") || r.Header.Get("X-Amz-Date") == "" {
		xmlError(w, 403, "MissingAuthenticationToken", "unsigned")
		return
	}
	akid, region, service := credentialScope(auth)
	if target := r.Header.Get("X-Amz-Target"); target != "" {
		if f.fail == "throttle" {
			jsonError(w, 400, "ThrottlingException", "slow down")
			return
		}
		if f.fail == "denied" {
			jsonError(w, 403, "AccessDeniedException", "no")
			return
		}
		if r.Header.Get("Content-Type") != "application/x-amz-json-1.1" {
			jsonError(w, 400, "ValidationException", "content type")
			return
		}
		if akid != icKey || r.Header.Get("X-Amz-Security-Token") == "" || region != "eu-west-1" {
			jsonError(w, 403, "AccessDeniedException", "wrong credential for identity center")
			return
		}
		var in map[string]any
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			jsonError(w, 400, "ValidationException", "body")
			return
		}
		f.serveJSON(w, target, service, in)
		return
	}
	if f.fail == "throttle" {
		xmlError(w, 400, "Throttling", "Rate exceeded")
		return
	}
	if f.fail == "denied" {
		xmlError(w, 403, "AccessDenied", "not authorized")
		return
	}
	if err := r.ParseForm(); err != nil {
		xmlError(w, 400, "MalformedInput", "form")
		return
	}
	f.serveQuery(w, r.Form, akid, region, service, r.Header.Get("X-Amz-Security-Token") != "")
}

func (f *fakeAWS) serveQuery(w http.ResponseWriter, form url.Values, akid, region, service string, hasToken bool) {
	action := form.Get("Action")
	w.Header().Set("Content-Type", "text/xml")
	switch action {
	case "AssumeRole":
		f.stsCalls++
		if service != "sts" || region != "eu-west-1" || form.Get("Version") != "2011-06-15" {
			xmlError(w, 400, "InvalidAction", "bad sts call")
			return
		}
		if akid != f.baseKey {
			xmlError(w, 403, "InvalidClientTokenId", "unknown key")
			return
		}
		if form.Get("ExternalId") != f.externalID || form.Get("RoleSessionName") == "" {
			xmlError(w, 403, "AccessDenied", "external id or session name")
			return
		}
		var key string
		switch form.Get("RoleArn") {
		case roleARN:
			key = targetKey
		case icRoleARN:
			key = icKey
		default:
			xmlError(w, 403, "AccessDenied", "cannot assume")
			return
		}
		fmt.Fprintf(w, `<AssumeRoleResponse><AssumeRoleResult><Credentials><AccessKeyId>%s</AccessKeyId><SecretAccessKey>%s</SecretAccessKey><SessionToken>%s</SessionToken><Expiration>%s</Expiration></Credentials><AssumedRoleUser><Arn>arn:aws:sts::%s:assumed-role/x/s</Arn></AssumedRoleUser></AssumeRoleResult></AssumeRoleResponse>`,
			key, itest.Canary+"assumed", itest.Canary+"token", time.Now().Add(time.Hour).UTC().Format(time.RFC3339), acct)
		return
	case "GetCallerIdentity":
		if service != "sts" || akid != targetKey || !hasToken {
			xmlError(w, 403, "AccessDenied", "wrong credential")
			return
		}
		fmt.Fprintf(w, `<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>arn:aws:sts::%s:assumed-role/hallpass-read/hallpass</Arn><Account>%s</Account></GetCallerIdentityResult></GetCallerIdentityResponse>`, acct, acct)
		return
	}
	// IAM
	if service != "iam" || region != "us-east-1" || akid != targetKey || !hasToken {
		xmlError(w, 403, "AccessDenied", "wrong credential for iam")
		return
	}
	if form.Get("Version") != "2010-05-08" {
		xmlError(w, 400, "InvalidAction", "version")
		return
	}
	switch action {
	case "ListRoles":
		f.listRolesCalls++
		if form.Get("PathPrefix") != ssoPathPrefix {
			xmlError(w, 400, "ValidationError", "prefix")
			return
		}
		start := 0
		if m := form.Get("Marker"); m != "" {
			start, _ = strconv.Atoi(m)
		}
		end := start + f.rolesPerPage
		if end > len(f.roles) {
			end = len(f.roles)
		}
		var b strings.Builder
		b.WriteString(`<ListRolesResponse><ListRolesResult><Roles>`)
		for _, r := range f.roles[start:end] {
			fmt.Fprintf(&b, `<member><Path>%s</Path><RoleName>%s</RoleName><Arn>%s</Arn></member>`, r.path, r.name, r.arn)
		}
		b.WriteString(`</Roles>`)
		if end < len(f.roles) {
			fmt.Fprintf(&b, `<IsTruncated>true</IsTruncated><Marker>%d</Marker>`, end)
		} else {
			b.WriteString(`<IsTruncated>false</IsTruncated>`)
		}
		b.WriteString(`</ListRolesResult></ListRolesResponse>`)
		w.Write([]byte(b.String()))
	case "GetUser":
		arn, ok := f.iamUsers[form.Get("UserName")]
		if !ok {
			xmlError(w, 404, "NoSuchEntity", "no user")
			return
		}
		fmt.Fprintf(w, `<GetUserResponse><GetUserResult><User><Path>/</Path><UserName>%s</UserName><UserId>AIDA%s</UserId><Arn>%s</Arn></User></GetUserResult></GetUserResponse>`, form.Get("UserName"), strings.ToUpper(form.Get("UserName")), arn)
	case "SimulatePrincipalPolicy":
		f.simulateCalls++
		if f.simErr != "" {
			xmlError(w, 400, f.simErr, "simulate failed")
			return
		}
		principal := form.Get("PolicySourceArn")
		act := form.Get("ActionNames.member.1")
		res := form.Get("ResourceArns.member.1")
		if res == "" {
			res = "*"
		}
		if form.Get("MaxItems") != "100" || form.Get("ActionNames.member.2") != "" {
			xmlError(w, 400, "ValidationError", "params")
			return
		}
		dec, ok := f.policy[principal+"|"+act+"|"+res]
		if !ok {
			dec = f.policy[principal+"|"+act+"|*"]
		}
		if dec == "" {
			dec = "implicitDeny"
		}
		var b strings.Builder
		b.WriteString(`<SimulatePrincipalPolicyResponse><SimulatePrincipalPolicyResult><EvaluationResults>`)
		if f.pageSplit && form.Get("Marker") == "" {
			b.WriteString(`<member><EvalActionName>s3:ListAllMyBuckets</EvalActionName><EvalDecision>allowed</EvalDecision><EvalResourceName>*</EvalResourceName></member>`)
			b.WriteString(`</EvaluationResults><IsTruncated>true</IsTruncated><Marker>page2</Marker></SimulatePrincipalPolicyResult></SimulatePrincipalPolicyResponse>`)
			w.Write([]byte(b.String()))
			return
		}
		evalDec := dec
		if f.evalDecision != "" && !f.evalOnly {
			evalDec = f.evalDecision
		}
		fmt.Fprintf(&b, `<member><EvalActionName>%s</EvalActionName><EvalDecision>%s</EvalDecision><EvalResourceName>%s</EvalResourceName>`, act, evalDec, res)
		if f.orgDenied {
			b.WriteString(`<OrganizationsDecisionDetail><AllowedByOrganizations>false</AllowedByOrganizations></OrganizationsDecisionDetail>`)
		} else {
			b.WriteString(`<OrganizationsDecisionDetail><AllowedByOrganizations>true</AllowedByOrganizations></OrganizationsDecisionDetail>`)
		}
		if f.boundaryDenied {
			b.WriteString(`<PermissionsBoundaryDecisionDetail><AllowedByPermissionsBoundary>false</AllowedByPermissionsBoundary></PermissionsBoundaryDecisionDetail>`)
		}
		if f.evalOnly {
			if len(f.missing) > 0 {
				b.WriteString(`<MissingContextValues>`)
				for _, m := range f.missing {
					fmt.Fprintf(&b, `<member>%s</member>`, m)
				}
				b.WriteString(`</MissingContextValues>`)
			}
		} else {
			fmt.Fprintf(&b, `<ResourceSpecificResults><member><EvalResourceName>%s</EvalResourceName><EvalResourceDecision>%s</EvalResourceDecision>`, res, dec)
			if len(f.missing) > 0 {
				b.WriteString(`<MissingContextValues>`)
				for _, m := range f.missing {
					fmt.Fprintf(&b, `<member>%s</member>`, m)
				}
				b.WriteString(`</MissingContextValues>`)
			}
			b.WriteString(`</member></ResourceSpecificResults>`)
		}
		b.WriteString(`</member></EvaluationResults><IsTruncated>false</IsTruncated></SimulatePrincipalPolicyResult></SimulatePrincipalPolicyResponse>`)
		w.Write([]byte(b.String()))
	default:
		xmlError(w, 400, "InvalidAction", action)
	}
}

func (f *fakeAWS) serveJSON(w http.ResponseWriter, target, service string, in map[string]any) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	str := func(m map[string]any, k string) string {
		s, _ := m[k].(string)
		return s
	}
	sub := func(m map[string]any, k string) map[string]any {
		s, _ := m[k].(map[string]any)
		return s
	}
	page := func(items []string, token string) ([]string, string) {
		start := 0
		if token != "" {
			start, _ = strconv.Atoi(token)
		}
		if start >= len(items) {
			return nil, ""
		}
		end := start + 1
		next := ""
		if end < len(items) {
			next = strconv.Itoa(end)
		}
		return items[start:end], next
	}
	svc, op, _ := strings.Cut(target, ".")
	if (svc == "AWSIdentityStore" && service != "identitystore") || (svc == "SWBExternalService" && service != "sso") {
		jsonError(w, 403, "AccessDeniedException", "signing name")
		return
	}
	if svc == "AWSIdentityStore" && str(in, "IdentityStoreId") != storeID {
		jsonError(w, 400, "ValidationException", "store")
		return
	}
	if svc == "SWBExternalService" && op != "ListInstances" && str(in, "InstanceArn") != instanceARN {
		jsonError(w, 400, "ValidationException", "instance")
		return
	}
	switch target {
	case "AWSIdentityStore.GetUserId":
		f.getUserIDCalls++
		ua := sub(sub(in, "AlternateIdentifier"), "UniqueAttribute")
		path, val := str(ua, "AttributePath"), str(ua, "AttributeValue")
		var u icUserRec
		var ok bool
		switch path {
		case "emails.value":
			u, ok = f.users[val]
		case "userName":
			if e, found := f.userNames[val]; found {
				u, ok = f.user(e)
			}
			for _, rec := range f.users {
				if rec.userName == val {
					u, ok = rec, true
				}
			}
		default:
			jsonError(w, 400, "ValidationException", "path")
			return
		}
		if !ok {
			jsonError(w, 400, "ResourceNotFoundException", "no user")
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"IdentityStoreId": storeID, "UserId": u.id})
	case "AWSIdentityStore.DescribeUser":
		id := str(in, "UserId")
		for e := range f.users {
			u := f.users[e]
			if u.id == id {
				out := map[string]any{"UserId": id, "UserName": u.userName, "DisplayName": u.display, "IdentityStoreId": storeID, "Emails": []map[string]any{{"Value": e, "Primary": true}}}
				if u.status != "" {
					out["UserStatus"] = u.status
				}
				json.NewEncoder(w).Encode(out)
				return
			}
		}
		for e, name := range f.userNames {
			if u, _ := f.user(name); u.id == id {
				json.NewEncoder(w).Encode(map[string]any{"UserId": id, "UserName": name, "DisplayName": e})
				return
			}
		}
		jsonError(w, 400, "ResourceNotFoundException", "no user")
	case "AWSIdentityStore.ListGroupMembershipsForMember":
		id := str(sub(in, "MemberId"), "UserId")
		items, next := page(f.groups[id], str(in, "NextToken"))
		out := map[string]any{"GroupMemberships": []map[string]string{}}
		for _, g := range items {
			out["GroupMemberships"] = append(out["GroupMemberships"].([]map[string]string), map[string]string{"GroupId": g, "MemberId": id, "MembershipId": "m-" + g})
		}
		if next != "" {
			out["NextToken"] = next
		}
		json.NewEncoder(w).Encode(out)
	case "SWBExternalService.ListAccountAssignmentsForPrincipal":
		if str(sub(in, "Filter"), "AccountId") != acct {
			jsonError(w, 400, "ValidationException", "filter")
			return
		}
		typ := str(in, "PrincipalType")
		id := str(in, "PrincipalId")
		if (typ == "USER") != strings.HasPrefix(id, "u-") || (typ == "GROUP") != strings.HasPrefix(id, "g-") {
			jsonError(w, 400, "ValidationException", "principal type")
			return
		}
		items, next := page(f.assignments[id], str(in, "NextToken"))
		out := map[string]any{"AccountAssignments": []map[string]string{}}
		for _, ps := range items {
			rowAcct := acct
			if a, ok := f.rowAccount[ps]; ok {
				rowAcct = a
			}
			out["AccountAssignments"] = append(out["AccountAssignments"].([]map[string]string), map[string]string{"AccountId": rowAcct, "PermissionSetArn": ps, "PrincipalId": id, "PrincipalType": typ})
		}
		if next != "" {
			out["NextToken"] = next
		}
		json.NewEncoder(w).Encode(out)
	case "SWBExternalService.DescribePermissionSet":
		name, ok := f.permissionSets[str(in, "PermissionSetArn")]
		if !ok {
			jsonError(w, 400, "ResourceNotFoundException", "no ps")
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"PermissionSet": map[string]string{"Name": name, "PermissionSetArn": str(in, "PermissionSetArn")}})
	case "SWBExternalService.ListInstances":
		json.NewEncoder(w).Encode(map[string]any{"Instances": f.instances})
	default:
		jsonError(w, 400, "UnknownOperationException", target)
	}
}

type env struct {
	srv  *itest.Server
	f    *fakeAWS
	conn integration.Connection
	c    *Connection
	now  time.Time
}

func setup(t *testing.T, values map[string]string, cred secret.Secret) *env {
	t.Helper()
	srv := itest.NewServer(t)
	srv.UseSpec(itest.AnySpec(itest.SpecFromEnv(t, "aws-sts"), itest.SpecFromEnv(t, "aws-iam"), itest.SpecFromEnv(t, "aws-identitystore"), itest.SpecFromEnv(t, "aws-sso-admin")), itest.SpecOptions{IgnorePaths: []string{`^/latest/`}})
	f := newFake(t)
	srv.Handle("", "/*", f.handler)
	deps, _ := itest.Deps(t, srv)
	e := &env{srv: srv, f: f, now: time.Unix(1_700_000_000, 0)}
	deps.Now = func() time.Time { e.f.mu.Lock(); defer e.f.mu.Unlock(); return e.now }
	testEndpoints = map[string]string{"sts": srv.URL, "iam": srv.URL, "identitystore": srv.URL, "sso": srv.URL, "imds": srv.URL}
	t.Cleanup(func() { testEndpoints = nil })
	v := map[string]string{
		"account_id": acct, "role_arn": roleARN, "partition": "aws", "region": "eu-west-1",
		"identity_mode": "identity_center", "identity_center_role_arn": icRoleARN, "identity_center_region": "eu-west-1",
		"identity_store_id": storeID, "sso_instance_arn": instanceARN, "implicit_deny_as": "deny", "session_name": "hallpass",
	}
	for k, val := range values {
		if val == "" {
			delete(v, k)
			continue
		}
		v[k] = val
	}
	if cred.IsZero() {
		cred = staticCred
	}
	s := itest.Settings("aws-prod", "aws", v, map[string]secret.Secret{"credential": cred})
	conn, err := Integration{}.New(context.Background(), s, deps)
	if err != nil {
		t.Fatal(err)
	}
	e.conn = conn
	e.c = conn.(*Connection)
	e.c.plain.Sleep = func(context.Context, time.Duration) error { return nil }
	return e
}

func (e *env) advance(d time.Duration) {
	e.f.mu.Lock()
	e.now = e.now.Add(d)
	e.f.mu.Unlock()
}

var (
	dana = integration.User{Email: "dana@example.com", Groups: []string{"platform-team"}}
	bob  = integration.User{Email: "bob@example.com"}
	lee  = integration.User{Email: "lee@example.com"}
	off  = integration.User{Email: "off@example.com"}
	adm  = integration.User{Email: "adm@example.com"}
)

func check(t *testing.T, e *env, u integration.User, action, resource string) integration.Decision {
	t.Helper()
	return itest.Check(t, e.conn, Integration{}, u, action, resource)
}

func lastForm(t *testing.T, e *env, action string) url.Values {
	t.Helper()
	calls := e.srv.Calls()
	for i := len(calls) - 1; i >= 0; i-- {
		form, err := url.ParseQuery(string(calls[i].Body))
		if err == nil && form.Get("Action") == action {
			return form
		}
	}
	t.Fatalf("no %s call recorded", action)
	return nil
}

func TestStaticCredentialAndAssumeRoleCaching(t *testing.T) {
	e := setup(t, nil, secret.Secret{})
	d := check(t, e, dana, "s3.read", bucketKey)
	itest.ExpectCode(t, d, integration.CodeAllowed)
	if !strings.Contains(d.Text, "permission set ReadOnly") {
		t.Errorf("text %q should name the permission set", d.Text)
	}
	for i := 0; i < 5; i++ {
		itest.ExpectCode(t, check(t, e, dana, "s3.read", bucketKey), integration.CodeAllowed)
		itest.ExpectCode(t, check(t, e, bob, "s3.read", bucketKey), integration.CodeDenied)
	}
	e.f.mu.Lock()
	sts := e.f.stsCalls
	e.f.mu.Unlock()
	if sts != 2 {
		t.Errorf("AssumeRole called %d times, want 2 (account role and Identity Center role)", sts)
	}
	form := lastForm(t, e, "AssumeRole")
	if form.Get("RoleSessionName") != "hallpass" {
		t.Errorf("session name %q", form.Get("RoleSessionName"))
	}
	// The connection keeps no identity cache of its own: the engine's
	// identity cache (identity_cache_seconds) is the only one, so every
	// ResolveIdentity call reaches Identity Store. Eleven checks, two of them
	// for bob with one GetUserId each, and dana's ten with one each.
	e.f.mu.Lock()
	n := e.f.getUserIDCalls
	e.f.mu.Unlock()
	if n != 11 {
		t.Errorf("GetUserId called %d times for eleven checks, want 11 (identity cached in the connection)", n)
	}
	// A credential that is neither JSON nor ambient: the error never carries it.
	bad := setup(t, nil, secret.Literal(itest.Canary+"raw-key"))
	d = check(t, bad, dana, "s3.read", bucketKey)
	if d.Outcome != integration.Unknown || strings.Contains(d.Text, itest.Canary) {
		t.Errorf("bad credential: %s %s", d.Code, d.Text)
	}
	_, err := bad.c.accountCreds.Credentials(context.Background())
	if err == nil || strings.Contains(err.Error(), itest.Canary) {
		t.Errorf("credential error leaks: %v", err)
	}
}

func TestExternalID(t *testing.T) {
	e := setup(t, map[string]string{"external_id": "ext-1"}, secret.Secret{})
	e.f.externalID = "ext-1"
	itest.ExpectCode(t, check(t, e, dana, "s3.read", bucketKey), integration.CodeAllowed)
	if lastForm(t, e, "AssumeRole").Get("ExternalId") != "ext-1" {
		t.Error("ExternalId not sent")
	}
}

func TestAmbientIMDS(t *testing.T) {
	e := setup(t, nil, secret.Literal("ambient:imds"))
	e.f.baseKey = imdsKey
	itest.ExpectCode(t, check(t, e, dana, "s3.read", bucketKey), integration.CodeAllowed)
	var token, creds bool
	for _, c := range e.srv.Calls() {
		if c.Method == "PUT" && c.Path == "/latest/api/token" {
			token = true
		}
		if c.Path == "/latest/meta-data/iam/security-credentials/instance-role" {
			creds = true
		}
	}
	if !token || !creds {
		t.Error("IMDSv2 token and credential calls not made")
	}
	itest.ExpectCode(t, check(t, e, dana, "s3.read", bucketKey), integration.CodeAllowed)
	e.f.mu.Lock()
	defer e.f.mu.Unlock()
	if e.f.stsCalls != 2 {
		t.Errorf("AssumeRole called %d times", e.f.stsCalls)
	}
	bogus := setup(t, nil, secret.Literal("ambient:bogus"))
	d := check(t, bogus, dana, "s3.read", bucketKey)
	if d.Outcome != integration.Unknown {
		t.Error(d)
	}
}

func TestIdentityCenter(t *testing.T) {
	e := setup(t, nil, secret.Secret{})
	id, err := e.conn.ResolveIdentity(context.Background(), dana)
	if err != nil {
		t.Fatal(err)
	}
	nat := id.Native.(*native)
	if id.ID != "u-dana" || id.Display != "dana" || len(id.Groups) != 2 || len(nat.Principals) != 2 || len(nat.Missing) != 0 {
		t.Fatalf("%+v %+v", id, nat)
	}
	if nat.Principals[0].ARN != roleRO || nat.Principals[1].ARN != roleDev {
		t.Errorf("principals %+v", nat.Principals)
	}
	if strings.Join(nat.PermissionSets, ",") != "ReadOnly,Developer" {
		t.Errorf("permission sets %v", nat.PermissionSets)
	}
	// Role list: paginated (5 roles, 3 per page = 2 requests).
	form := lastForm(t, e, "ListRoles")
	if form.Get("Marker") != "3" || form.Get("PathPrefix") != ssoPathPrefix {
		t.Errorf("ListRoles form %v", form)
	}
	// Group-inherited permission set allows what the user's own does not.
	d := check(t, e, dana, "s3.write", bucketKey)
	itest.ExpectCode(t, d, integration.CodeAllowed)
	if !strings.Contains(d.Text, "permission set Developer") {
		t.Error(d.Text)
	}
	// No assignments at all.
	d = check(t, e, bob, "s3.read", bucketKey)
	itest.ExpectCode(t, d, integration.CodeDenied)
	if !strings.Contains(d.Text, "no permission set assigned in account "+acct) {
		t.Error(d.Text)
	}
	// userName fallback.
	e.srv.Reset()
	id, err = e.conn.ResolveIdentity(context.Background(), lee)
	if err != nil || id.ID != "u-lee" {
		t.Fatalf("%+v %v", id, err)
	}
	var paths []string
	for _, c := range e.srv.Calls() {
		if c.Header.Get("X-Amz-Target") == "AWSIdentityStore.GetUserId" {
			var in struct {
				AlternateIdentifier struct {
					UniqueAttribute struct{ AttributePath, AttributeValue string }
				}
			}
			c.JSON(t, &in)
			paths = append(paths, in.AlternateIdentifier.UniqueAttribute.AttributePath+"="+in.AlternateIdentifier.UniqueAttribute.AttributeValue)
		}
	}
	if strings.Join(paths, " ") != "emails.value=lee@example.com userName=lee@example.com" {
		t.Errorf("GetUserId lookups: %v", paths)
	}
	// Unknown user.
	itest.ExpectCode(t, check(t, e, integration.User{Email: "nobody@example.com"}, "s3.read", bucketKey), integration.CodeUserNotFound)
	// DISABLED user is denied even though the permission set allows.
	d = check(t, e, off, "s3.read", bucketKey)
	itest.ExpectCode(t, d, integration.CodeDenied)
	if !strings.Contains(d.Text, "disabled") {
		t.Error(d.Text)
	}
	// Anchored matching: permission set "Adm" must not match AWSReservedSSO_Admin_*.
	d = check(t, e, adm, "s3.read", bucketKey)
	itest.ExpectCode(t, d, integration.CodeResourceNotVisible)
	if !strings.Contains(d.Text, "Adm ") || strings.Contains(d.Text, "Admin") {
		t.Error(d.Text)
	}
	if _, ok := matchSSORole([]ssoRole{{Name: "AWSReservedSSO_Admin_00000000000000ff", ARN: roleAdmin}}, "Adm"); ok {
		t.Error("prefix match accepted")
	}
	if _, ok := matchSSORole([]ssoRole{{Name: "AWSReservedSSO_Adm_00000000000000ff", ARN: "x"}}, "Adm"); !ok {
		t.Error("exact match rejected")
	}
	if _, ok := matchSSORole([]ssoRole{{Name: "AWSReservedSSO_Read.Only_00000000000000ff", ARN: "x"}}, "Read-Only"); ok {
		t.Error("regexp metacharacters not quoted")
	}
	// The role list is cached across users.
	e.f.mu.Lock()
	lr := e.f.listRolesCalls
	e.f.mu.Unlock()
	if lr != 2 {
		t.Errorf("ListRoles requests = %d, want 2 (one paginated listing)", lr)
	}
	// After the cache TTL the list is fetched again.
	e.advance(11 * time.Minute)
	itest.ExpectCode(t, check(t, e, dana, "s3.read", bucketKey), integration.CodeAllowed)
	e.f.mu.Lock()
	lr = e.f.listRolesCalls
	e.f.mu.Unlock()
	if lr != 4 {
		t.Errorf("ListRoles requests after TTL = %d, want 4", lr)
	}
}

func TestStaticMap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "roles.txt")
	os.WriteFile(path, []byte("# comment\n\nDana@example.com arn:aws:iam::123456789012:role/Deployer\nplatform-team arn:aws:iam::123456789012:role/PlatformAdmin\n"), 0o600)
	e := setup(t, map[string]string{"identity_mode": "static_map", "role_map_file": path, "identity_center_role_arn": "", "identity_center_region": "", "identity_store_id": "", "sso_instance_arn": ""}, secret.Secret{})
	d := check(t, e, integration.User{Email: "dana@example.com"}, "s3.read", "all")
	itest.ExpectCode(t, d, integration.CodeAllowed)
	if !strings.Contains(d.Text, "role Deployer") {
		t.Error(d.Text)
	}
	if lastForm(t, e, "SimulatePrincipalPolicy").Get("ResourceArns.member.1") != "" {
		t.Error("ResourceArns sent for *")
	}
	d = check(t, e, integration.User{Email: "bob@example.com", Groups: []string{"Platform-Team"}}, "s3.read", "all")
	itest.ExpectCode(t, d, integration.CodeAllowed)
	if !strings.Contains(d.Text, "role PlatformAdmin") {
		t.Error(d.Text)
	}
	itest.ExpectCode(t, check(t, e, bob, "s3.read", "all"), integration.CodeUserNotFound)
	// A miss for one set of groups says nothing about another: the same
	// email arriving with a mapped group resolves (the engine keys its
	// negative identity cache by groups for this reason).
	itest.ExpectCode(t, check(t, e, integration.User{Email: "bob@example.com", Groups: []string{"platform-team"}}, "s3.read", "all"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, e, integration.User{Email: "dana@example.com"}, "ec2.stop", "all"), integration.CodeDenied)
	e.f.mu.Lock()
	sts := e.f.stsCalls
	e.f.mu.Unlock()
	if sts != 1 {
		t.Errorf("AssumeRole called %d times, want 1", sts)
	}
	// Re-read after 60 s.
	os.WriteFile(path, []byte("bob@example.com arn:aws:iam::123456789012:role/Deployer\n"), 0o600)
	itest.ExpectCode(t, check(t, e, bob, "s3.read", "all"), integration.CodeUserNotFound)
	e.advance(61 * time.Second)
	itest.ExpectCode(t, check(t, e, bob, "s3.read", "all"), integration.CodeAllowed)
	// A broken re-read keeps the previous map.
	os.WriteFile(path, []byte("bob@example.com not-an-arn\n"), 0o600)
	e.advance(61 * time.Second)
	itest.ExpectCode(t, check(t, e, bob, "s3.read", "all"), integration.CodeAllowed)

	// New rejects a missing or malformed file.
	for _, bad := range []string{filepath.Join(t.TempDir(), "missing"), path} {
		s := itest.Settings("x", "aws", map[string]string{"account_id": acct, "role_arn": roleARN, "region": "eu-west-1", "identity_mode": "static_map", "role_map_file": bad}, map[string]secret.Secret{"credential": staticCred})
		deps, _ := itest.Deps(t, e.srv)
		if _, err := (Integration{}).New(context.Background(), s, deps); err == nil {
			t.Errorf("New accepted role_map_file %s", bad)
		}
	}
}

func TestIAMUser(t *testing.T) {
	e := setup(t, map[string]string{"identity_mode": "iam_user"}, secret.Secret{})
	d := check(t, e, integration.User{Email: "dana@example.com"}, "s3.read", bucketKey)
	itest.ExpectCode(t, d, integration.CodeAllowed)
	if !strings.Contains(d.Text, "user dana") {
		t.Error(d.Text)
	}
	if lastForm(t, e, "SimulatePrincipalPolicy").Get("PolicySourceArn") != "arn:aws:iam::123456789012:user/dana" {
		t.Error("principal is not the user ARN")
	}
	id, err := e.conn.ResolveIdentity(context.Background(), lee)
	if err != nil || id.Display != "lee@example.com" || id.Attr("arn") != "arn:aws:iam::123456789012:user/lee@example.com" {
		t.Fatalf("%+v %v", id, err)
	}
	itest.ExpectCode(t, check(t, e, integration.User{Email: "nobody@example.com"}, "s3.read", bucketKey), integration.CodeUserNotFound)
	itest.ExpectCode(t, check(t, e, lee, "s3.read", bucketKey), integration.CodeDenied)
	e.f.mu.Lock()
	sts := e.f.stsCalls
	e.f.mu.Unlock()
	if sts != 1 {
		t.Errorf("AssumeRole called %d times, want 1", sts)
	}
}

func TestSimulateDecisions(t *testing.T) {
	e := setup(t, nil, secret.Secret{})
	// explicitDeny on every principal.
	d := check(t, e, dana, "ec2.terminate", "all")
	itest.ExpectCode(t, d, integration.CodeDenied)
	if !strings.Contains(d.Text, "explicitly deny") {
		t.Error(d.Text)
	}
	// implicitDeny (one explicit, one implicit) -> deny by default.
	d = check(t, e, dana, "ec2.stop", "all")
	itest.ExpectCode(t, d, integration.CodeDenied)
	if strings.Contains(d.Text, "explicitly") {
		t.Error(d.Text)
	}
	// implicit_deny_as: unknown.
	u := setup(t, map[string]string{"implicit_deny_as": "unknown"}, secret.Secret{})
	itest.ExpectCode(t, check(t, u, dana, "ec2.stop", "all"), integration.CodeUnsupported)
	itest.ExpectCode(t, check(t, u, dana, "ec2.terminate", "all"), integration.CodeDenied)
	itest.ExpectCode(t, check(t, u, dana, "s3.read", bucketKey), integration.CodeAllowed)

	// The resource-specific result and EvalDecision must agree on allowed;
	// otherwise the more restrictive of the two wins.
	e.f.mu.Lock()
	e.f.evalDecision = "implicitDeny" // resource says allowed
	e.f.mu.Unlock()
	d = check(t, e, dana, "s3.read", bucketKey)
	itest.ExpectCode(t, d, integration.CodeDenied)
	if strings.Contains(d.Text, "explicitly") {
		t.Error(d.Text)
	}
	e.f.mu.Lock()
	e.f.evalDecision = "explicitDeny" // resource says allowed
	e.f.mu.Unlock()
	d = check(t, e, dana, "s3.read", bucketKey)
	itest.ExpectCode(t, d, integration.CodeDenied)
	if !strings.Contains(d.Text, "explicitly deny") {
		t.Error(d.Text)
	}
	e.f.mu.Lock()
	e.f.evalDecision = "allowed" // resource says explicitDeny
	e.f.mu.Unlock()
	d = check(t, e, dana, "ec2.terminate", "all")
	itest.ExpectCode(t, d, integration.CodeDenied)
	if !strings.Contains(d.Text, "explicitly deny") {
		t.Error(d.Text)
	}
	e.f.mu.Lock()
	e.f.evalDecision = "allowed" // resource says allowed: both agree
	e.f.mu.Unlock()
	itest.ExpectCode(t, check(t, e, dana, "s3.read", bucketKey), integration.CodeAllowed)
	// Without resource-specific results EvalDecision is used.
	e.f.mu.Lock()
	e.f.evalDecision, e.f.evalOnly = "", true
	e.f.mu.Unlock()
	itest.ExpectCode(t, check(t, e, dana, "s3.read", bucketKey), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, e, dana, "ec2.terminate", "all"), integration.CodeDenied)

	// Missing context values -> unknown naming the keys.
	e.f.mu.Lock()
	e.f.evalOnly, e.f.missing = false, []string{"aws:MultiFactorAuthPresent", "aws:SourceIp"}
	e.f.mu.Unlock()
	d = check(t, e, dana, "ec2.stop", "all")
	itest.ExpectCode(t, d, integration.CodeUnsupported)
	if !strings.Contains(d.Text, "aws:MultiFactorAuthPresent, aws:SourceIp") || !strings.Contains(d.Text, "context_entries") {
		t.Error(d.Text)
	}
	e.f.mu.Lock()
	e.f.evalOnly = true
	e.f.mu.Unlock()
	itest.ExpectCode(t, check(t, e, dana, "ec2.stop", "all"), integration.CodeUnsupported)
	e.f.mu.Lock()
	e.f.evalOnly, e.f.missing = false, nil
	e.f.mu.Unlock()

	// SCP and permissions boundary are named in the deny text.
	e.f.mu.Lock()
	e.f.orgDenied = true
	e.f.mu.Unlock()
	d = check(t, e, dana, "ec2.terminate", "all")
	itest.ExpectCode(t, d, integration.CodeDenied)
	if !strings.Contains(d.Text, "denied by SCP") {
		t.Error(d.Text)
	}
	e.f.mu.Lock()
	e.f.orgDenied, e.f.boundaryDenied = false, true
	e.f.mu.Unlock()
	d = check(t, e, dana, "ec2.stop", "all")
	itest.ExpectCode(t, d, integration.CodeDenied)
	if !strings.Contains(d.Text, "permissions boundary") {
		t.Error(d.Text)
	}
	e.f.mu.Lock()
	e.f.boundaryDenied = false
	e.f.mu.Unlock()

	// Cross-account resource -> unknown, no simulation.
	e.srv.Reset()
	d = check(t, e, dana, "raw:sqs:SendMessage", "arn:aws:sqs:eu-west-1:210987654321:queue")
	itest.ExpectCode(t, d, integration.CodeUnsupported)
	if !strings.Contains(d.Text, "210987654321") {
		t.Error(d.Text)
	}
	for _, c := range e.srv.Calls() {
		if strings.Contains(string(c.Body), "SimulatePrincipalPolicy") {
			t.Error("cross-account resource was simulated")
		}
	}
	// Same-account ARN is fine.
	e.f.mu.Lock()
	e.f.policy[roleRO+"|sqs:SendMessage|arn:aws:sqs:eu-west-1:123456789012:queue"] = "allowed"
	e.f.mu.Unlock()
	itest.ExpectCode(t, check(t, e, dana, "raw:sqs:SendMessage", "arn:aws:sqs:eu-west-1:123456789012:queue"), integration.CodeAllowed)

	// Simulation errors.
	e.f.mu.Lock()
	e.f.simErr = "PolicyEvaluation"
	e.f.mu.Unlock()
	itest.ExpectCode(t, check(t, e, dana, "s3.read", bucketKey), integration.CodeUnsupported)
	e.f.mu.Lock()
	e.f.simErr = "NoSuchEntity"
	before := e.f.listRolesCalls
	e.f.mu.Unlock()
	d = check(t, e, dana, "s3.read", bucketKey)
	itest.ExpectCode(t, d, integration.CodeResourceNotVisible)
	// The text is honest about what refreshes: the engine holds the identity
	// (and so the vanished principal) until identity_cache_seconds expires.
	if !strings.Contains(d.Text, "vanished") || !strings.Contains(d.Text, "identity_cache_seconds") || strings.Contains(d.Text, "cache will refresh") {
		t.Error(d.Text)
	}
	e.f.mu.Lock()
	e.f.simErr = ""
	e.f.mu.Unlock()
	// The role list was dropped: the next resolve lists roles again.
	itest.ExpectCode(t, check(t, e, dana, "s3.read", bucketKey), integration.CodeAllowed)
	e.f.mu.Lock()
	after := e.f.listRolesCalls
	e.f.mu.Unlock()
	if after != before+2 {
		t.Errorf("ListRoles requests after NoSuchEntity = %d, want %d (role list not dropped)", after, before+2)
	}
}

// The connection has no identity cache: the engine's identity_cache_seconds
// cache is the only one, keyed by email and groups, so nothing here can hold
// a stale identity beyond it.
func TestNoConnectionIdentityCache(t *testing.T) {
	e := setup(t, nil, secret.Secret{})
	for i := 0; i < 3; i++ {
		if _, err := e.conn.ResolveIdentity(context.Background(), dana); err != nil {
			t.Fatal(err)
		}
	}
	e.f.mu.Lock()
	n := e.f.getUserIDCalls
	e.f.mu.Unlock()
	if n != 3 {
		t.Errorf("GetUserId called %d times for three resolves, want 3", n)
	}
	iam := setup(t, map[string]string{"identity_mode": "iam_user"}, secret.Secret{})
	iam.srv.Reset()
	for i := 0; i < 2; i++ {
		if _, err := iam.conn.ResolveIdentity(context.Background(), dana); err != nil {
			t.Fatal(err)
		}
	}
	getUser := 0
	for _, c := range iam.srv.Calls() {
		if strings.Contains(string(c.Body), "Action=GetUser") {
			getUser++
		}
	}
	if getUser != 2 {
		t.Errorf("GetUser called %d times for two resolves, want 2", getUser)
	}
}

func TestSimulateRequestShape(t *testing.T) {
	e := setup(t, map[string]string{"context_entries": "aws:MultiFactorAuthPresent=boolean:true; aws:SourceIp=ip:10.0.0.1;aws:PrincipalTag/team=stringList:a, b"}, secret.Secret{})
	itest.ExpectCode(t, check(t, e, dana, "s3.read", bucketKey), integration.CodeAllowed)
	form := lastForm(t, e, "SimulatePrincipalPolicy")
	want := map[string]string{
		"Version":                                "2010-05-08",
		"PolicySourceArn":                        roleRO,
		"ActionNames.member.1":                   "s3:GetObject",
		"ResourceArns.member.1":                  bucketKey,
		"MaxItems":                               "100",
		"ContextEntries.member.1.ContextKeyName": "aws:MultiFactorAuthPresent",
		"ContextEntries.member.1.ContextKeyType": "boolean",
		"ContextEntries.member.1.ContextKeyValues.member.1": "true",
		"ContextEntries.member.2.ContextKeyName":            "aws:SourceIp",
		"ContextEntries.member.2.ContextKeyType":            "ip",
		"ContextEntries.member.2.ContextKeyValues.member.1": "10.0.0.1",
		"ContextEntries.member.3.ContextKeyName":            "aws:PrincipalTag/team",
		"ContextEntries.member.3.ContextKeyType":            "stringList",
		"ContextEntries.member.3.ContextKeyValues.member.1": "a",
		"ContextEntries.member.3.ContextKeyValues.member.2": "b",
	}
	for k, v := range want {
		if form.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, form.Get(k), v)
		}
	}
	if form.Get("ContextEntries.member.4.ContextKeyName") != "" {
		t.Error("extra context entry")
	}
	// ReadOnly allowed, so it was the last (and only) principal simulated.
	if form.Get("PolicySourceArn") != roleRO {
		t.Error("last simulate was not for ReadOnly")
	}
	for _, bad := range []string{"x", "k=string", "k=blob:1", "a=string:1;a=string:2", "bad key=string:1"} {
		if _, err := parseContextEntries(bad); err == nil {
			t.Errorf("context_entries %q accepted", bad)
		}
	}
	// Pagination of EvaluationResults.
	e.f.mu.Lock()
	e.f.pageSplit = true
	e.f.mu.Unlock()
	e.srv.Reset()
	itest.ExpectCode(t, check(t, e, dana, "ec2.terminate", "all"), integration.CodeDenied)
	var markers []string
	for _, c := range e.srv.Calls() {
		form, _ := url.ParseQuery(string(c.Body))
		if form.Get("Action") == "SimulatePrincipalPolicy" {
			markers = append(markers, form.Get("Marker"))
		}
	}
	if strings.Join(markers, ",") != ",page2,,page2" {
		t.Errorf("markers %v", markers)
	}
}

func TestRawActionsAndResources(t *testing.T) {
	for _, ok := range []string{"raw:s3:GetObject", "raw:iam:*", "raw:ec2:Describe*", "raw:secretsmanager:GetSecretValue", "raw:execute-api:Invoke"} {
		if _, matched := (Integration{}).MatchAction(ok); !matched {
			t.Errorf("MatchAction(%q) rejected", ok)
		}
	}
	for _, bad := range []string{"raw:S3:GetObject", "raw:s3", "raw:s3:", "raw:s3:Get-Object", "s3:GetObject", "raw:s3:GetObject:x", "raw::GetObject", "raw:s3:Get/Object"} {
		if _, matched := (Integration{}).MatchAction(bad); matched {
			t.Errorf("MatchAction(%q) accepted", bad)
		}
	}
	if _, ok := integration.FindAction(Integration{}, "raw:<service>:<Action>"); ok {
		t.Error("the pattern's own name must not match")
	}
	e := setup(t, nil, secret.Secret{})
	e.f.mu.Lock()
	e.f.policy[roleRO+"|iam:*|*"] = "allowed"
	e.f.mu.Unlock()
	itest.ExpectCode(t, check(t, e, dana, "raw:iam:*", "all"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, e, dana, "raw:kms:Decrypt", "arn:aws:kms:eu-west-1:123456789012:key/abc"), integration.CodeDenied)
	for _, bad := range []string{"bucket:x", "arn:aws:s3:::b?x=1", "arn:aws-cn:s3:::b", "all:x", "arn:aws:s3", "arn:aws:s3:::", "arn:aws:s3:us-east-1:12345:b", "arn:foo:s3:::b", "arn"} {
		d := check(t, e, dana, "s3.read", bad)
		if d.Code != integration.CodeInvalidRequest {
			t.Errorf("resource %q -> %s: %s", bad, d.Code, d.Text)
		}
	}
	if err := integration.ValidateFields((Integration{}).Fields()); err != nil {
		t.Error(err)
	}
}

func TestFieldValidation(t *testing.T) {
	fields := map[string]integration.Field{}
	for _, f := range (Integration{}).Fields() {
		fields[f.Name] = f
	}
	good := map[string]string{
		"account_id": acct, "role_arn": roleARN, "region": "us-gov-west-1", "identity_store_id": storeID,
		"sso_instance_arn": "arn:aws-us-gov:sso:::instance/ins-0123456789abcdef", "context_entries": "aws:SourceIp=ip:10.0.0.1",
		"session_name": "hallpass-prod", "identity_center_region": "cn-north-1",
	}
	for k, v := range good {
		if err := fields[k].Validate(v); err != nil {
			t.Errorf("%s=%q: %v", k, v, err)
		}
	}
	bad := map[string]string{
		"account_id": "12345678901", "role_arn": "arn:aws:iam::123456789012:user/x", "region": "eu-west", "identity_store_id": "d-123",
		"sso_instance_arn": "arn:aws:sso:::instance/x", "context_entries": "k", "session_name": "a", "identity_center_region": "EU-WEST-1",
	}
	for k, v := range bad {
		if err := fields[k].Validate(v); err == nil {
			t.Errorf("%s=%q accepted", k, v)
		}
	}
	srv := itest.NewServer(t)
	srv.UseSpec(itest.AnySpec(itest.SpecFromEnv(t, "aws-sts"), itest.SpecFromEnv(t, "aws-iam"), itest.SpecFromEnv(t, "aws-identitystore"), itest.SpecFromEnv(t, "aws-sso-admin")), itest.SpecOptions{IgnorePaths: []string{`^/latest/`}})
	deps, _ := itest.Deps(t, srv)
	base := map[string]string{"account_id": acct, "role_arn": roleARN, "region": "eu-west-1", "identity_mode": "identity_center",
		"identity_center_role_arn": icRoleARN, "identity_center_region": "eu-west-1", "identity_store_id": storeID, "sso_instance_arn": instanceARN}
	try := func(over map[string]string) error {
		v := map[string]string{}
		for k, val := range base {
			v[k] = val
		}
		for k, val := range over {
			if val == "" {
				delete(v, k)
			} else {
				v[k] = val
			}
		}
		_, err := (Integration{}).New(context.Background(), itest.Settings("x", "aws", v, map[string]secret.Secret{"credential": staticCred}), deps)
		return err
	}
	if err := try(nil); err != nil {
		t.Fatal(err)
	}
	for name, over := range map[string]map[string]string{
		"role in other account":   {"role_arn": icRoleARN},
		"role in other partition": {"role_arn": "arn:aws-us-gov:iam::123456789012:role/x"},
		"no ic role":              {"identity_center_role_arn": ""},
		"no ic region":            {"identity_center_region": ""},
		"no store":                {"identity_store_id": ""},
		"no instance":             {"sso_instance_arn": ""},
		"no map file":             {"identity_mode": "static_map"},
		"bad context":             {"context_entries": "x"},
	} {
		if err := try(over); err == nil {
			t.Errorf("%s: New accepted", name)
		}
	}
	if err := try(map[string]string{"identity_mode": "iam_user", "identity_center_role_arn": "", "identity_center_region": "", "identity_store_id": "", "sso_instance_arn": ""}); err != nil {
		t.Errorf("iam_user: %v", err)
	}
	_, err := (Integration{}).New(context.Background(), itest.Settings("x", "aws", base, nil), deps)
	if err == nil {
		t.Error("missing credential accepted")
	}
}

func TestFailures(t *testing.T) {
	e := setup(t, nil, secret.Secret{})
	itest.ExpectCode(t, check(t, e, dana, "s3.read", bucketKey), integration.CodeAllowed)
	itest.FailureCases(t, e.srv, func() integration.Decision {
		return check(t, e, dana, "s3.read", bucketKey)
	})
	// Fresh connection: the failure hits AssumeRole itself.
	fresh := setup(t, nil, secret.Secret{})
	itest.FailureCases(t, fresh.srv, func() integration.Decision {
		return check(t, fresh, dana, "s3.read", bucketKey)
	})
}

func TestAWSErrorBodies(t *testing.T) {
	for _, tc := range []struct {
		fail string
		code integration.Code
	}{{"throttle", integration.CodeUpstreamRateLimit}, {"denied", integration.CodeCredentialRejected}} {
		// On a fresh connection the error comes from AssumeRole (XML).
		e := setup(t, nil, secret.Secret{})
		e.f.mu.Lock()
		e.f.fail = tc.fail
		e.f.mu.Unlock()
		itest.ExpectCode(t, check(t, e, dana, "s3.read", bucketKey), tc.code)
		// With credentials in hand the error comes from Identity Store (JSON).
		e2 := setup(t, nil, secret.Secret{})
		if _, err := e2.c.icCreds.Credentials(context.Background()); err != nil {
			t.Fatal(err)
		}
		e2.f.mu.Lock()
		e2.f.fail = tc.fail
		e2.f.mu.Unlock()
		itest.ExpectCode(t, check(t, e2, dana, "s3.read", bucketKey), tc.code)
		// And from IAM (XML) once the identity is cached.
		e3 := setup(t, nil, secret.Secret{})
		itest.ExpectCode(t, check(t, e3, dana, "s3.read", bucketKey), integration.CodeAllowed)
		e3.f.mu.Lock()
		e3.f.fail = tc.fail
		e3.f.mu.Unlock()
		itest.ExpectCode(t, check(t, e3, dana, "s3.read", bucketKey), tc.code)
	}
}

func TestProbe(t *testing.T) {
	e := setup(t, nil, secret.Secret{})
	r, err := e.conn.Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.Summary, "assumed-role/hallpass-read") || !strings.Contains(r.Summary, "5 AWSReservedSSO roles") {
		t.Error(r.Summary)
	}
	if len(r.Warnings) != 1 || !strings.Contains(r.Warnings[0], "discloses") {
		t.Errorf("warnings %v", r.Warnings)
	}
	e.f.mu.Lock()
	e.f.instances = []map[string]string{{"InstanceArn": instanceARN, "IdentityStoreId": "d-0000000000"}}
	e.f.mu.Unlock()
	r, _ = e.conn.Probe(context.Background())
	if len(r.Warnings) != 2 || !strings.Contains(r.Warnings[0], "d-0000000000") {
		t.Errorf("warnings %v", r.Warnings)
	}
	e.f.mu.Lock()
	e.f.instances = nil
	e.f.mu.Unlock()
	r, _ = e.conn.Probe(context.Background())
	if len(r.Warnings) != 2 || !strings.Contains(r.Warnings[0], "did not list") {
		t.Errorf("warnings %v", r.Warnings)
	}
	e.f.mu.Lock()
	e.f.fail = "denied"
	e.f.mu.Unlock()
	if _, err := e.conn.Probe(context.Background()); err == nil {
		t.Error("probe succeeded with access denied")
	}
	// iam_user mode skips the Identity Center check.
	u := setup(t, map[string]string{"identity_mode": "iam_user"}, secret.Secret{})
	r, err = u.conn.Probe(context.Background())
	if err != nil || len(r.Warnings) != 1 {
		t.Errorf("%+v %v", r, err)
	}
}

func TestMoreRestrictive(t *testing.T) {
	for _, tc := range []struct{ a, b, want string }{
		{"allowed", "allowed", "allowed"},
		{"allowed", "implicitDeny", "implicitDeny"},
		{"implicitDeny", "allowed", "implicitDeny"},
		{"allowed", "explicitDeny", "explicitDeny"},
		{"explicitDeny", "allowed", "explicitDeny"},
		{"implicitDeny", "explicitDeny", "explicitDeny"},
		{"explicitDeny", "implicitDeny", "explicitDeny"},
		{"allowed", "bogus", "bogus"},
	} {
		if got := moreRestrictive(tc.a, tc.b); got != tc.want {
			t.Errorf("moreRestrictive(%s, %s) = %s, want %s", tc.a, tc.b, got, tc.want)
		}
	}
}

// An "allowed" evaluated with condition keys missing is not an allow: IAM
// skipped every statement conditioned on those keys, including denies.
func TestAllowedWithMissingContextIsUnknown(t *testing.T) {
	e := setup(t, nil, secret.Secret{})
	itest.ExpectCode(t, check(t, e, dana, "s3.read", bucketKey), integration.CodeAllowed)
	e.f.mu.Lock()
	e.f.missing = []string{"aws:MultiFactorAuthPresent"}
	e.f.mu.Unlock()
	// Resource-specific result carries the missing keys.
	d := check(t, e, dana, "s3.read", bucketKey)
	itest.ExpectCode(t, d, integration.CodeUnsupported)
	if !strings.Contains(d.Text, "aws:MultiFactorAuthPresent") || !strings.Contains(d.Text, "context_entries") {
		t.Error(d.Text)
	}
	// Action-level result carries them.
	e.f.mu.Lock()
	e.f.evalOnly = true
	e.f.mu.Unlock()
	d = check(t, e, dana, "s3.read", bucketKey)
	itest.ExpectCode(t, d, integration.CodeUnsupported)
	if !strings.Contains(d.Text, "aws:MultiFactorAuthPresent") {
		t.Error(d.Text)
	}
	// Every principal is still simulated: an allow without missing keys on
	// a later principal settles the check.
	e.srv.Reset()
	e.f.mu.Lock()
	e.f.evalOnly, e.f.missing = false, nil
	e.f.mu.Unlock()
	itest.ExpectCode(t, check(t, e, dana, "s3.write", bucketKey), integration.CodeAllowed)
	n := 0
	for _, c := range e.srv.Calls() {
		if strings.Contains(string(c.Body), "Action=SimulatePrincipalPolicy") {
			n++
		}
	}
	if n != 2 {
		t.Errorf("SimulatePrincipalPolicy calls = %d, want 2", n)
	}
	// Once the keys are supplied the allow stands (the fake reports no
	// missing keys then).
	itest.ExpectCode(t, check(t, e, dana, "s3.read", bucketKey), integration.CodeAllowed)
}

// A user with no permission set in the account is an implicit deny, so
// implicit_deny_as decides between deny and unknown.
func TestNoPermissionSetHonoursImplicitDenyAs(t *testing.T) {
	e := setup(t, nil, secret.Secret{})
	d := check(t, e, bob, "s3.read", bucketKey)
	itest.ExpectCode(t, d, integration.CodeDenied)
	if !strings.Contains(d.Text, "no permission set assigned in account "+acct) {
		t.Error(d.Text)
	}
	u := setup(t, map[string]string{"implicit_deny_as": "unknown"}, secret.Secret{})
	d = check(t, u, bob, "s3.read", bucketKey)
	itest.ExpectCode(t, d, integration.CodeUnsupported)
	if !strings.Contains(d.Text, "no permission set assigned in account "+acct) {
		t.Error(d.Text)
	}
}

// An assignment row counts only when its AccountId is exactly this
// account: rows for another account or with no AccountId are skipped.
func TestAssignmentRowsRequireExactAccount(t *testing.T) {
	for _, rowAcct := range []string{"", "210987654321"} {
		e := setup(t, nil, secret.Secret{})
		e.f.mu.Lock()
		e.f.assignments["u-bob"] = []string{psRO}
		e.f.rowAccount = map[string]string{psRO: rowAcct}
		e.f.mu.Unlock()
		id, err := e.conn.ResolveIdentity(context.Background(), bob)
		if err != nil {
			t.Fatal(err)
		}
		nat := id.Native.(*native)
		if len(nat.PermissionSets) != 0 || len(nat.Principals) != 0 {
			t.Errorf("AccountId %q: permission sets %v principals %+v, want none", rowAcct, nat.PermissionSets, nat.Principals)
		}
		d := check(t, e, bob, "s3.read", bucketKey)
		itest.ExpectCode(t, d, integration.CodeDenied)
		if !strings.Contains(d.Text, "no permission set assigned") {
			t.Error(d.Text)
		}
	}
	// The exact account still counts.
	e := setup(t, nil, secret.Secret{})
	e.f.mu.Lock()
	e.f.assignments["u-bob"] = []string{psRO}
	e.f.rowAccount = map[string]string{psRO: acct}
	e.f.mu.Unlock()
	itest.ExpectCode(t, check(t, e, bob, "s3.read", bucketKey), integration.CodeAllowed)
}

func TestSimulateXMLDecoding(t *testing.T) {
	body := `<SimulatePrincipalPolicyResponse><SimulatePrincipalPolicyResult><EvaluationResults><member>
<EvalActionName>s3:GetObject</EvalActionName><EvalDecision>implicitDeny</EvalDecision><EvalResourceName>arn:aws:s3:::b/k</EvalResourceName>
<MissingContextValues><member>aws:SourceIp</member></MissingContextValues>
<OrganizationsDecisionDetail><AllowedByOrganizations>false</AllowedByOrganizations></OrganizationsDecisionDetail>
<PermissionsBoundaryDecisionDetail><AllowedByPermissionsBoundary>false</AllowedByPermissionsBoundary></PermissionsBoundaryDecisionDetail>
<ResourceSpecificResults><member><EvalResourceName>arn:aws:s3:::b/k</EvalResourceName><EvalResourceDecision>explicitDeny</EvalResourceDecision>
<MissingContextValues><member>aws:MultiFactorAuthPresent</member></MissingContextValues></member></ResourceSpecificResults>
</member></EvaluationResults><IsTruncated>true</IsTruncated><Marker>abc</Marker></SimulatePrincipalPolicyResult></SimulatePrincipalPolicyResponse>`
	var out simulateResponse
	if err := xml.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	r := out.Result
	if !r.IsTruncated || r.Marker != "abc" || len(r.Results) != 1 {
		t.Fatalf("%+v", r)
	}
	ev := r.Results[0]
	if ev.Decision != "implicitDeny" || ev.Missing[0] != "aws:SourceIp" || ev.Org.Allowed == nil || *ev.Org.Allowed || ev.Boundary.Allowed == nil || *ev.Boundary.Allowed {
		t.Errorf("%+v", ev)
	}
	if len(ev.Resources) != 1 || ev.Resources[0].Decision != "explicitDeny" || ev.Resources[0].Missing[0] != "aws:MultiFactorAuthPresent" {
		t.Errorf("%+v", ev.Resources)
	}
}

// Allow/deny tests per alias action (coverage gate).

func aliasAllow(t *testing.T, name string) {
	t.Helper()
	e := setup(t, nil, secret.Secret{})
	act := aliases[name].action
	e.f.mu.Lock()
	e.f.policy[roleRO+"|"+act+"|*"] = "allowed"
	e.f.mu.Unlock()
	d := check(t, e, dana, name, "all")
	itest.ExpectCode(t, d, integration.CodeAllowed)
	if lastForm(t, e, "SimulatePrincipalPolicy").Get("ActionNames.member.1") != act {
		t.Errorf("%s did not simulate %s", name, act)
	}
}

func aliasDeny(t *testing.T, name string) {
	t.Helper()
	e := setup(t, nil, secret.Secret{})
	act := aliases[name].action
	e.f.mu.Lock()
	e.f.policy[roleRO+"|"+act+"|*"] = "explicitDeny"
	e.f.policy[roleDev+"|"+act+"|*"] = "explicitDeny"
	e.f.mu.Unlock()
	itest.ExpectCode(t, check(t, e, dana, name, "all"), integration.CodeDenied)
}

func TestAction_s3_read_allow(t *testing.T)             { aliasAllow(t, "s3.read") }
func TestAction_s3_read_deny(t *testing.T)              { aliasDeny(t, "s3.read") }
func TestAction_s3_write_allow(t *testing.T)            { aliasAllow(t, "s3.write") }
func TestAction_s3_write_deny(t *testing.T)             { aliasDeny(t, "s3.write") }
func TestAction_s3_list_allow(t *testing.T)             { aliasAllow(t, "s3.list") }
func TestAction_s3_list_deny(t *testing.T)              { aliasDeny(t, "s3.list") }
func TestAction_ec2_stop_allow(t *testing.T)            { aliasAllow(t, "ec2.stop") }
func TestAction_ec2_stop_deny(t *testing.T)             { aliasDeny(t, "ec2.stop") }
func TestAction_ec2_start_allow(t *testing.T)           { aliasAllow(t, "ec2.start") }
func TestAction_ec2_start_deny(t *testing.T)            { aliasDeny(t, "ec2.start") }
func TestAction_ec2_terminate_allow(t *testing.T)       { aliasAllow(t, "ec2.terminate") }
func TestAction_ec2_terminate_deny(t *testing.T)        { aliasDeny(t, "ec2.terminate") }
func TestAction_lambda_invoke_allow(t *testing.T)       { aliasAllow(t, "lambda.invoke") }
func TestAction_lambda_invoke_deny(t *testing.T)        { aliasDeny(t, "lambda.invoke") }
func TestAction_iam_passrole_allow(t *testing.T)        { aliasAllow(t, "iam.passrole") }
func TestAction_iam_passrole_deny(t *testing.T)         { aliasDeny(t, "iam.passrole") }
func TestAction_secretsmanager_read_allow(t *testing.T) { aliasAllow(t, "secretsmanager.read") }
func TestAction_secretsmanager_read_deny(t *testing.T)  { aliasDeny(t, "secretsmanager.read") }
func TestAction_ssm_session_allow(t *testing.T)         { aliasAllow(t, "ssm.session") }
func TestAction_ssm_session_deny(t *testing.T)          { aliasDeny(t, "ssm.session") }
func TestAction_sts_assume_allow(t *testing.T)          { aliasAllow(t, "sts.assume") }
func TestAction_sts_assume_deny(t *testing.T)           { aliasDeny(t, "sts.assume") }
func TestAction_rds_delete_allow(t *testing.T)          { aliasAllow(t, "rds.delete") }
func TestAction_rds_delete_deny(t *testing.T)           { aliasDeny(t, "rds.delete") }
func TestAction_eks_describe_allow(t *testing.T)        { aliasAllow(t, "eks.describe") }
func TestAction_eks_describe_deny(t *testing.T)         { aliasDeny(t, "eks.describe") }

func TestAliasesListed(t *testing.T) {
	for _, a := range aliasList {
		if _, ok := integration.FindAction(Integration{}, a.name); !ok {
			t.Errorf("alias %s not listed", a.name)
		}
		if !rawActionRe.MatchString(a.action) {
			t.Errorf("alias %s expands to %q, not an IAM action", a.name, a.action)
		}
	}
}
