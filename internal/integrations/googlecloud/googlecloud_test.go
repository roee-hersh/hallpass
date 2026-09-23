package googlecloud

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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/roee-hersh/hallpass/internal/authx"
	"github.com/roee-hersh/hallpass/internal/catalog"
	"github.com/roee-hersh/hallpass/internal/integration"
	"github.com/roee-hersh/hallpass/internal/integration/itest"
	"github.com/roee-hersh/hallpass/internal/secret"
)

const (
	saEmail   = "hallpass@proj.iam.gserviceaccount.com"
	projectRN = "//cloudresourcemanager.googleapis.com/projects/acme-prod"
)

var (
	dana = integration.User{Email: "dana@example.com"}
	bob  = integration.User{Email: "bob@example.com"}
)

// The allow and deny states of the v3 response, as the fake emits them.
const (
	allowGranted    = "ALLOW_ACCESS_STATE_GRANTED"
	allowNotGranted = "ALLOW_ACCESS_STATE_NOT_GRANTED"
	allowUnknownCon = "ALLOW_ACCESS_STATE_UNKNOWN_CONDITIONAL"
	allowUnknownInf = "ALLOW_ACCESS_STATE_UNKNOWN_INFO"
	denyNotDenied   = "DENY_ACCESS_STATE_NOT_DENIED"
	denyUnknownInf  = "DENY_ACCESS_STATE_UNKNOWN_INFO"
)

// tupleKey identifies one question the fake has an answer for.
type tupleKey struct{ principal, permission, resource string }

// answer is the fake's response to one question.
type answer struct {
	overall string
	allow   string
	deny    string
}

// fakeTroubleshooter is an in-memory token endpoint, metadata server and
// Policy Troubleshooter.
type fakeTroubleshooter struct {
	t   *testing.T
	key *rsa.PrivateKey
	kid string
	mu  sync.Mutex

	tokens    map[string]bool // minted access tokens
	minted    int
	expire401 int // next n API calls answer 401
	metaCalls int
	answers   map[tupleKey]answer
	// status, when non-zero, makes the troubleshooter answer that HTTP
	// status with reason.
	status int
	reason string
	// wantQuota is the X-Goog-User-Project every call must carry ("" for none).
	wantQuota string
	// rawBody, when set, is returned verbatim with status 200.
	rawBody string
}

// testKey is generated once per package.
var testKey = sync.OnceValues(func() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
})

func newFake(t *testing.T) *fakeTroubleshooter {
	key, err := testKey()
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeTroubleshooter{t: t, key: key, kid: itest.Canary + "kid", tokens: map[string]bool{}, answers: map[tupleKey]answer{}}
	grant := answer{stateCanAccess, allowGranted, denyNotDenied}
	nogrant := answer{stateCannotAccess, allowNotGranted, denyNotDenied}
	// dana holds everything on acme-prod and its resources, bob nothing.
	for _, a := range actionList {
		for _, typ := range a.types {
			perm := a.permission
			if a.name == "iam.set" {
				perm = setIamPolicyPermissions[typ]
			}
			f.answers[tupleKey{"dana@example.com", perm, sample(typ)}] = grant
			f.answers[tupleKey{"bob@example.com", perm, sample(typ)}] = nogrant
		}
	}
	f.answers[tupleKey{"dana@example.com", "storage.objects.delete", projectRN}] = grant
	f.answers[tupleKey{"dana@example.com", "compute.instances.setMetadata", projectRN}] = grant
	f.answers[tupleKey{"dana@example.com", "iam.googleapis.com/roles.create", projectRN}] = grant
	// A deny policy takes dana's bucket deletion away.
	f.answers[tupleKey{"dana@example.com", "storage.buckets.delete", "//storage.googleapis.com/projects/_/buckets/denied"}] = answer{stateCannotAccess, allowGranted, denyDenied}
	// A conditional binding, and a policy hallpass cannot read.
	f.answers[tupleKey{"dana@example.com", "storage.objects.get", "//storage.googleapis.com/projects/_/buckets/conditional"}] = answer{stateUnknownConditional, allowUnknownCon, denyNotDenied}
	f.answers[tupleKey{"dana@example.com", "storage.objects.get", "//storage.googleapis.com/projects/_/buckets/hidden"}] = answer{stateUnknownInfo, allowUnknownInf, denyUnknownInf}
	// The probe: the service account may get the scope project.
	f.answers[tupleKey{saEmail, "resourcemanager.projects.get", projectRN}] = grant
	return f
}

// samples is one resource per type, and sample its full resource name.
var samples = map[string]string{
	"project":        "project:acme-prod",
	"folder":         "folder:123456789",
	"organization":   "organization:987654321",
	"bucket":         "bucket:acme-data",
	"object":         "object:acme-data/reports/2026/q1.csv",
	"dataset":        "dataset:acme-prod/analytics",
	"table":          "table:acme-prod/analytics/events",
	"secret":         "secret:acme-prod/db-password",
	"serviceaccount": "serviceaccount:deployer@acme-prod.iam.gserviceaccount.com",
	"instance":       "instance:acme-prod/europe-west1-b/web-1",
	"service":        "service:acme-prod/europe-west1/api",
	"cluster":        "cluster:acme-prod/europe-west1/main",
	"name":           "name://pubsub.googleapis.com/projects/acme-prod/topics/events",
}

func sample(typ string) string {
	r, err := catalog.ParseResource(samples[typ])
	if err != nil {
		panic(err)
	}
	full, err := fullResourceName(r)
	if err != nil {
		panic(err)
	}
	return full
}

func (f *fakeTroubleshooter) tokenURL(srv *itest.Server) string { return srv.URL + "/token" }

// token is the OAuth token endpoint: it verifies the JWT bearer assertion.
func (f *fakeTroubleshooter) token(srv *itest.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		defer f.mu.Unlock()
		fail := func(code string) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"error":"` + code + `","error_description":"` + itest.Canary + `desc"}`))
		}
		if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
			fail("unsupported_grant_type")
			return
		}
		a := r.Form.Get("assertion")
		parts := strings.Split(a, ".")
		if len(parts) != 3 {
			fail("invalid_request")
			return
		}
		hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
		var hdr map[string]any
		_ = json.Unmarshal(hb, &hdr)
		if hdr["alg"] != "RS256" || hdr["typ"] != "JWT" || hdr["kid"] != f.kid {
			f.t.Errorf("assertion header %v", hdr)
			fail("invalid_request")
			return
		}
		sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
		if err := authx.Verify(&f.key.PublicKey, authx.RS256, []byte(parts[0]+"."+parts[1]), sig); err != nil {
			f.t.Errorf("assertion signature: %v", err)
			fail("invalid_grant")
			return
		}
		var cl struct {
			claims
			Sub string `json:"sub"`
		}
		_ = authx.DecodeJWTClaims(a, &cl)
		now := time.Now().Unix()
		if cl.Iss != saEmail || cl.Aud != f.tokenURL(srv) || cl.Sub != "" || cl.Scope != scopeCloudPlatform ||
			cl.Iat > now+5 || cl.Exp != cl.Iat+3600 {
			f.t.Errorf("assertion claims %+v", cl)
			fail("invalid_grant")
			return
		}
		f.minted++
		tok := fmt.Sprintf("%stoken%d", itest.Canary, f.minted)
		f.tokens[tok] = true
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": tok, "expires_in": 3599, "token_type": "Bearer"})
	}
}

// metadata is the GCE metadata server.
func (f *fakeTroubleshooter) metadata(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Metadata-Flavor") != "Google" {
		w.WriteHeader(403)
		return
	}
	switch r.URL.Path {
	case "/computeMetadata/v1/instance/service-accounts/default/token":
		f.metaCalls++
		tok := fmt.Sprintf("%smeta%d", itest.Canary, f.metaCalls)
		f.tokens[tok] = true
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": tok, "expires_in": 3599, "token_type": "Bearer"})
	case "/computeMetadata/v1/instance/service-accounts/default/email":
		_, _ = w.Write([]byte(saEmail))
	default:
		w.WriteHeader(404)
	}
}

// apiErr writes a Google error body the way the real API does: a long
// message first, then status and details, so the reason sits well past the
// 256-byte snippet httpx keeps and can only be read from the whole body.
func apiErr(w http.ResponseWriter, status int, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	msg := itest.Canary + " Quota exceeded for quota metric 'Troubleshoot requests' and limit 'Troubleshoot requests per minute' of service 'policytroubleshooter.googleapis.com' for consumer 'project_number:123456789012'. " + strings.Repeat("padding ", 20)
	details := "[]"
	if reason != "" {
		details = fmt.Sprintf(`[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"%s","domain":"googleapis.com"}]`, reason)
	}
	_, _ = w.Write([]byte(fmt.Sprintf(`{"error":{"code":%d,"message":"%s","status":"PERMISSION_DENIED","details":%s}}`, status, msg, details)))
}

// troubleshoot serves POST /v3/iam:troubleshoot.
func (f *fakeTroubleshooter) troubleshoot(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.expire401 > 0 {
		f.expire401--
		apiErr(w, 401, "ACCESS_TOKEN_EXPIRED")
		return
	}
	if !f.tokens[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")] {
		apiErr(w, 401, "ACCESS_TOKEN_TYPE_UNSUPPORTED")
		return
	}
	if got := r.Header.Get("X-Goog-User-Project"); got != f.wantQuota {
		f.t.Errorf("X-Goog-User-Project = %q, want %q", got, f.wantQuota)
	}
	if r.Header.Get("Content-Type") != "application/json" {
		f.t.Errorf("content type %q", r.Header.Get("Content-Type"))
	}
	if f.status != 0 {
		apiErr(w, f.status, f.reason)
		return
	}
	var body struct {
		AccessTuple accessTuple `json:"accessTuple"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apiErr(w, 400, "INVALID_ARGUMENT")
		return
	}
	tp := body.AccessTuple
	if tp.Principal == "" || tp.Permission == "" || !strings.HasPrefix(tp.FullResourceName, "//") {
		f.t.Errorf("bad access tuple %+v", tp)
		apiErr(w, 400, "INVALID_ARGUMENT")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if f.rawBody != "" {
		_, _ = w.Write([]byte(f.rawBody))
		return
	}
	a, ok := f.answers[tupleKey{tp.Principal, tp.Permission, tp.FullResourceName}]
	if !ok {
		a = answer{stateCannotAccess, allowNotGranted, denyNotDenied}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"overallAccessState": a.overall,
		"accessTuple":        map[string]any{"principal": tp.Principal, "permission": tp.Permission, "fullResourceName": tp.FullResourceName, "permissionFqdn": itest.Canary + "fqdn"},
		"allowPolicyExplanation": map[string]any{"allowAccessState": a.allow, "relevance": "HEURISTIC_RELEVANCE_HIGH",
			"explainedPolicies": []map[string]any{{"fullResourceName": tp.FullResourceName, "policy": map[string]any{"bindings": []map[string]any{{"role": "roles/" + itest.Canary, "members": []string{"user:" + tp.Principal}}}}}}},
		"denyPolicyExplanation": map[string]any{"denyAccessState": a.deny, "permissionDeniable": true, "relevance": "HEURISTIC_RELEVANCE_NORMAL"},
	})
}

func mustPKCS8(t *testing.T, k *rsa.PrivateKey) []byte {
	t.Helper()
	b, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (f *fakeTroubleshooter) keyJSON(t *testing.T, srv *itest.Server) secret.Secret {
	t.Helper()
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustPKCS8(t, f.key)})
	b, err := json.Marshal(map[string]string{
		"type": "service_account", "project_id": "proj", "private_key_id": f.kid, "private_key": string(pemKey),
		"client_email": saEmail, "client_id": "123", "token_uri": f.tokenURL(srv),
	})
	if err != nil {
		t.Fatal(err)
	}
	return secret.Literal(string(b))
}

func specOptions() itest.SpecOptions {
	return itest.SpecOptions{IgnorePaths: []string{`^/token$`, `/computeMetadata/`}}
}

// stubWorkspace stands in for a googleworkspace connection.
type stubWorkspace struct {
	users map[string]integration.Identity
}

func (s stubWorkspace) ResolveIdentity(_ context.Context, u integration.User) (integration.Identity, error) {
	id, ok := s.users[strings.ToLower(u.Email)]
	if !ok {
		return integration.Identity{}, integration.UserNotFound("no Workspace account for %s", u.Email)
	}
	return id, nil
}

func (stubWorkspace) Check(context.Context, integration.CheckRequest) (integration.Decision, error) {
	return integration.Decision{}, nil
}

func (stubWorkspace) Probe(context.Context) (integration.ProbeResult, error) {
	return integration.ProbeResult{}, nil
}

func setup(t *testing.T, values map[string]string) (*itest.Server, *fakeTroubleshooter, integration.Connection) {
	t.Helper()
	srv := itest.NewServer(t)
	srv.UseSpec(itest.SpecFromEnv(t, "google-policytroubleshooter"), specOptions())
	f := newFake(t)
	srv.Handle("POST", "/token", f.token(srv))
	srv.Handle("POST", "/v3/iam:troubleshoot", f.troubleshoot)
	srv.Handle("GET", "/computeMetadata/*", f.metadata)
	deps, _ := itest.Deps(t, srv)
	deps.Connection = func(id string) (integration.Connection, error) {
		if id != "gws" {
			return nil, fmt.Errorf("no connection %q", id)
		}
		return stubWorkspace{users: map[string]integration.Identity{
			"dana@example.com":     {ID: "dana@example.com", Attrs: map[string]string{"suspended": "false", "archived": "false"}},
			"d.alias@example.com":  {ID: "dana@example.com", Attrs: map[string]string{"suspended": "false", "archived": "false"}},
			"sus@example.com":      {ID: "sus@example.com", Attrs: map[string]string{"suspended": "true", "archived": "false"}},
			"nostatus@example.com": {ID: "nostatus@example.com"},
		}}, nil
	}
	v := map[string]string{"scope": "project:acme-prod", "token_url": f.tokenURL(srv), "api_url": srv.URL, "metadata_url": srv.URL}
	for k, val := range values {
		v[k] = val
	}
	f.wantQuota = v["quota_project"]
	secrets := map[string]secret.Secret{}
	if v["auth_mode"] != modeKeyless {
		secrets["credential"] = f.keyJSON(t, srv)
	}
	s := itest.Settings("gcp", "googlecloud", v, secrets)
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

// --- the action table -------------------------------------------------------

// allowDeny runs one action on the resource for dana (allowed) and bob
// (not granted) and checks the permission that reached the fake.
func allowDeny(t *testing.T, action, resource, permission string, want bool) {
	t.Helper()
	srv, _, c := setup(t, nil)
	u, code := bob, integration.CodeDenied
	if want {
		u, code = dana, integration.CodeAllowed
	}
	d := check(t, c, u, action, resource)
	itest.ExpectCode(t, d, code)
	last := srv.LastCall()
	if last.Path != "/v3/iam:troubleshoot" {
		t.Fatalf("last call %s %s", last.Method, last.Path)
	}
	var body struct {
		AccessTuple accessTuple `json:"accessTuple"`
	}
	last.JSON(t, &body)
	if body.AccessTuple.Permission != permission || body.AccessTuple.Principal != u.Email {
		t.Errorf("sent %+v, want permission %s for %s", body.AccessTuple, permission, u.Email)
	}
	if !strings.Contains(d.Text, permission) {
		t.Errorf("text %q does not name the permission", d.Text)
	}
}

func TestAction_project_view_allow(t *testing.T) {
	allowDeny(t, "project.view", samples["project"], "resourcemanager.projects.get", true)
}
func TestAction_project_view_deny(t *testing.T) {
	allowDeny(t, "project.view", samples["project"], "resourcemanager.projects.get", false)
}
func TestAction_iam_set_allow(t *testing.T) {
	allowDeny(t, "iam.set", samples["bucket"], "storage.buckets.setIamPolicy", true)
}
func TestAction_iam_set_deny(t *testing.T) {
	allowDeny(t, "iam.set", samples["project"], "resourcemanager.projects.setIamPolicy", false)
}
func TestAction_storage_read_allow(t *testing.T) {
	allowDeny(t, "storage.read", samples["object"], "storage.objects.get", true)
}
func TestAction_storage_read_deny(t *testing.T) {
	allowDeny(t, "storage.read", samples["bucket"], "storage.objects.get", false)
}
func TestAction_storage_write_allow(t *testing.T) {
	allowDeny(t, "storage.write", samples["bucket"], "storage.objects.create", true)
}
func TestAction_storage_write_deny(t *testing.T) {
	allowDeny(t, "storage.write", samples["object"], "storage.objects.create", false)
}
func TestAction_storage_delete_allow(t *testing.T) {
	allowDeny(t, "storage.delete", samples["object"], "storage.objects.delete", true)
}
func TestAction_storage_delete_deny(t *testing.T) {
	allowDeny(t, "storage.delete", samples["bucket"], "storage.objects.delete", false)
}
func TestAction_storage_list_allow(t *testing.T) {
	allowDeny(t, "storage.list", samples["bucket"], "storage.objects.list", true)
}
func TestAction_storage_list_deny(t *testing.T) {
	allowDeny(t, "storage.list", samples["bucket"], "storage.objects.list", false)
}
func TestAction_bucket_delete_allow(t *testing.T) {
	allowDeny(t, "bucket.delete", samples["bucket"], "storage.buckets.delete", true)
}
func TestAction_bucket_delete_deny(t *testing.T) {
	allowDeny(t, "bucket.delete", samples["bucket"], "storage.buckets.delete", false)
}
func TestAction_bigquery_read_allow(t *testing.T) {
	allowDeny(t, "bigquery.read", samples["table"], "bigquery.tables.getData", true)
}
func TestAction_bigquery_read_deny(t *testing.T) {
	allowDeny(t, "bigquery.read", samples["dataset"], "bigquery.tables.getData", false)
}
func TestAction_bigquery_write_allow(t *testing.T) {
	allowDeny(t, "bigquery.write", samples["dataset"], "bigquery.tables.updateData", true)
}
func TestAction_bigquery_write_deny(t *testing.T) {
	allowDeny(t, "bigquery.write", samples["table"], "bigquery.tables.updateData", false)
}
func TestAction_bigquery_delete_allow(t *testing.T) {
	allowDeny(t, "bigquery.delete", samples["table"], "bigquery.tables.delete", true)
}
func TestAction_bigquery_delete_deny(t *testing.T) {
	allowDeny(t, "bigquery.delete", samples["table"], "bigquery.tables.delete", false)
}
func TestAction_secret_read_allow(t *testing.T) {
	allowDeny(t, "secret.read", samples["secret"], "secretmanager.versions.access", true)
}
func TestAction_secret_read_deny(t *testing.T) {
	allowDeny(t, "secret.read", samples["secret"], "secretmanager.versions.access", false)
}
func TestAction_serviceaccount_actas_allow(t *testing.T) {
	allowDeny(t, "serviceaccount.actas", samples["serviceaccount"], "iam.serviceAccounts.actAs", true)
}
func TestAction_serviceaccount_actas_deny(t *testing.T) {
	allowDeny(t, "serviceaccount.actas", samples["serviceaccount"], "iam.serviceAccounts.actAs", false)
}
func TestAction_compute_start_allow(t *testing.T) {
	allowDeny(t, "compute.start", samples["instance"], "compute.instances.start", true)
}
func TestAction_compute_start_deny(t *testing.T) {
	allowDeny(t, "compute.start", samples["instance"], "compute.instances.start", false)
}
func TestAction_compute_stop_allow(t *testing.T) {
	allowDeny(t, "compute.stop", samples["instance"], "compute.instances.stop", true)
}
func TestAction_compute_stop_deny(t *testing.T) {
	allowDeny(t, "compute.stop", samples["instance"], "compute.instances.stop", false)
}
func TestAction_compute_delete_allow(t *testing.T) {
	allowDeny(t, "compute.delete", samples["instance"], "compute.instances.delete", true)
}
func TestAction_compute_delete_deny(t *testing.T) {
	allowDeny(t, "compute.delete", samples["instance"], "compute.instances.delete", false)
}
func TestAction_run_deploy_allow(t *testing.T) {
	allowDeny(t, "run.deploy", samples["service"], "run.services.update", true)
}
func TestAction_run_deploy_deny(t *testing.T) {
	allowDeny(t, "run.deploy", samples["service"], "run.services.update", false)
}
func TestAction_gke_access_allow(t *testing.T) {
	allowDeny(t, "gke.access", samples["cluster"], "container.clusters.get", true)
}
func TestAction_gke_access_deny(t *testing.T) {
	allowDeny(t, "gke.access", samples["cluster"], "container.clusters.get", false)
}

// --- resources and actions ----------------------------------------------------

func TestFullResourceNames(t *testing.T) {
	want := map[string]string{
		"project":        projectRN,
		"folder":         "//cloudresourcemanager.googleapis.com/folders/123456789",
		"organization":   "//cloudresourcemanager.googleapis.com/organizations/987654321",
		"bucket":         "//storage.googleapis.com/projects/_/buckets/acme-data",
		"object":         "//storage.googleapis.com/projects/_/buckets/acme-data/objects/reports/2026/q1.csv",
		"dataset":        "//bigquery.googleapis.com/projects/acme-prod/datasets/analytics",
		"table":          "//bigquery.googleapis.com/projects/acme-prod/datasets/analytics/tables/events",
		"secret":         "//secretmanager.googleapis.com/projects/acme-prod/secrets/db-password",
		"serviceaccount": "//iam.googleapis.com/projects/acme-prod/serviceAccounts/deployer@acme-prod.iam.gserviceaccount.com",
		"instance":       "//compute.googleapis.com/projects/acme-prod/zones/europe-west1-b/instances/web-1",
		"service":        "//run.googleapis.com/projects/acme-prod/locations/europe-west1/services/api",
		"cluster":        "//container.googleapis.com/projects/acme-prod/locations/europe-west1/clusters/main",
		"name":           "//pubsub.googleapis.com/projects/acme-prod/topics/events",
	}
	for typ, full := range want {
		if got := sample(typ); got != full {
			t.Errorf("%s: %s, want %s", typ, got, full)
		}
	}
	_, _, c := setup(t, nil)
	for typ := range samples {
		d := check(t, c, dana, "raw:storage.objects.delete", samples[typ])
		if d.Code != integration.CodeAllowed && d.Code != integration.CodeDenied {
			t.Errorf("raw on %s: %s (%s)", typ, d.Code, d.Text)
		}
	}
}

func TestProjectNumbersAndObjectNames(t *testing.T) {
	srv, f, c := setup(t, nil)
	f.mu.Lock()
	f.answers[tupleKey{"dana@example.com", "secretmanager.versions.access", "//secretmanager.googleapis.com/projects/123456789012/secrets/db-password"}] = answer{stateCanAccess, allowGranted, denyNotDenied}
	f.answers[tupleKey{"dana@example.com", "storage.objects.get", "//storage.googleapis.com/projects/_/buckets/acme-data/objects/reports/Q1 2026 (final).pdf"}] = answer{stateCanAccess, allowGranted, denyNotDenied}
	f.mu.Unlock()
	itest.ExpectCode(t, check(t, c, dana, "secret.read", "secret:123456789012/db-password"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, dana, "project.view", "project:123456789012"), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, dana, "storage.read", "object:acme-data/reports/Q1 2026 (final).pdf"), integration.CodeAllowed)
	var body struct {
		AccessTuple accessTuple `json:"accessTuple"`
	}
	srv.LastCall().JSON(t, &body)
	if body.AccessTuple.FullResourceName != "//storage.googleapis.com/projects/_/buckets/acme-data/objects/reports/Q1 2026 (final).pdf" {
		t.Errorf("object name changed: %q", body.AccessTuple.FullResourceName)
	}
}

func TestRawActions(t *testing.T) {
	srv, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, dana, "raw:storage.objects.delete", "project:acme-prod"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, dana, "raw:compute.instances.setMetadata", "project:acme-prod"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, dana, "raw:iam.googleapis.com/roles.create", "project:acme-prod"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, bob, "raw:storage.objects.delete", "project:acme-prod"), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, dana, "raw:storage.objects.delete", "name://storage.googleapis.com/projects/_/buckets/x"), integration.CodeDenied)
	n := len(srv.Calls())
	for _, bad := range []string{"raw:", "raw:storage", "raw:Storage.objects.get", "raw:storage.objects.get x", "raw:storage..get", "raw:a.b.c.d.e.f.g", "storage.objects.get"} {
		if _, ok := (Integration{}).MatchAction(bad); ok {
			t.Errorf("%q matched", bad)
		}
	}
	if len(srv.Calls()) != n {
		t.Error("a rejected action reached the upstream")
	}
}

func TestRejectsBadResources(t *testing.T) {
	srv, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, dana, "project.view", "project:acme-prod"), integration.CodeAllowed)
	n := len(srv.Calls())
	cases := []struct{ action, resource string }{
		{"project.view", "project:Acme"},
		{"project.view", "project:ab"},
		{"project.view", "project:acme-prod?x=1"},
		{"project.view", "bucket:acme-data"},
		{"project.view", "user:dana@example.com"},
		{"iam.set", "object:acme-data/x"},
		{"iam.set", "name://storage.googleapis.com/projects/_/buckets/x"},
		{"storage.read", "instance:acme-prod/z/web-1"},
		{"storage.read", "bucket:AB"},
		{"storage.read", "object:acme-data"},
		{"storage.read", "object:acme-data/../etc"},
		{"storage.read", "object:acme-data/a/../etc"},
		{"storage.read", "object:acme-data/a/.."},
		{"storage.read", "object:acme-data/./a"},
		{"bigquery.read", "table:acme-prod/analytics"},
		{"bigquery.read", "dataset:acme-prod/a b"},
		{"secret.read", "secret:acme-prod/x/y"},
		{"serviceaccount.actas", "serviceaccount:123-compute@developer.gserviceaccount.com"},
		{"serviceaccount.actas", "serviceaccount:dana@example.com"},
		{"compute.stop", "instance:acme-prod/web-1"},
		{"compute.stop", "instance:acme-prod/europe-west1-b/Web_1"},
		{"run.deploy", "service:acme-prod/europe-west1/api/x"},
		{"gke.access", "cluster:acme-prod/europe-west1/"},
		{"storage.read", "name:https://storage.googleapis.com/x"},
		{"storage.read", "name://storage.googleapis.com/projects/../x"},
		{"storage.read", "name://evil.example.com/projects/x"},
		{"storage.read", "name://storage.googleapis.com/x y"},
		{"storage.read", "name://storage.googleapis.com/"},
		{"storage.read", "name://storage.googleapis.com/a/./b"},
	}
	for _, tc := range cases {
		d := check(t, c, dana, tc.action, tc.resource)
		if d.Code != integration.CodeInvalidRequest {
			t.Errorf("%s %s: %s (%s), want invalid_request", tc.action, tc.resource, d.Code, d.Text)
		}
	}
	if len(srv.Calls()) != n {
		t.Error("a rejected resource reached the upstream")
	}
}

// --- decisions ----------------------------------------------------------------

func TestDenyPolicy(t *testing.T) {
	_, _, c := setup(t, nil)
	d := check(t, c, dana, "bucket.delete", "bucket:denied")
	itest.ExpectCode(t, d, integration.CodeDenied)
	if !strings.Contains(d.Text, "deny policy") {
		t.Error(d.Text)
	}
	d = check(t, c, bob, "bucket.delete", "bucket:acme-data")
	itest.ExpectCode(t, d, integration.CodeDenied)
	if !strings.Contains(d.Text, "no allow policy") {
		t.Error(d.Text)
	}
}

func TestUnknownStates(t *testing.T) {
	_, f, c := setup(t, nil)
	d := check(t, c, dana, "storage.read", "bucket:conditional")
	itest.ExpectCode(t, d, integration.CodeUnsupported)
	if !strings.Contains(d.Text, "condition") {
		t.Error(d.Text)
	}
	d = check(t, c, dana, "storage.read", "bucket:hidden")
	itest.ExpectCode(t, d, integration.CodeResourceNotVisible)
	if !strings.Contains(d.Text, "securityReviewer") {
		t.Error(d.Text)
	}
	f.mu.Lock()
	f.rawBody = `{"overallAccessState":"OVERALL_ACCESS_STATE_UNSPECIFIED"}`
	f.mu.Unlock()
	itest.ExpectCode(t, check(t, c, dana, "storage.read", "bucket:acme-data"), integration.CodeUpstreamError)
	f.mu.Lock()
	f.rawBody = `{"overallAccessState":"` + itest.Canary + `"}`
	f.mu.Unlock()
	itest.ExpectCode(t, check(t, c, dana, "storage.read", "bucket:acme-data"), integration.CodeUpstreamError)
	f.mu.Lock()
	f.rawBody = "not json"
	f.mu.Unlock()
	itest.ExpectCode(t, check(t, c, dana, "storage.read", "bucket:acme-data"), integration.CodeUpstreamError)
}

func TestAPIErrors(t *testing.T) {
	_, f, c := setup(t, nil)
	set := func(status int, reason string) {
		f.mu.Lock()
		f.status, f.reason = status, reason
		f.mu.Unlock()
	}
	set(403, "SERVICE_DISABLED")
	itest.ExpectCode(t, check(t, c, dana, "project.view", "project:acme-prod"), integration.CodeCredentialRejected)
	set(403, "")
	itest.ExpectCode(t, check(t, c, dana, "project.view", "project:acme-prod"), integration.CodeCredentialRejected)
	set(403, "RATE_LIMIT_EXCEEDED")
	itest.ExpectCode(t, check(t, c, dana, "project.view", "project:acme-prod"), integration.CodeUpstreamRateLimit)
	set(429, "")
	itest.ExpectCode(t, check(t, c, dana, "project.view", "project:acme-prod"), integration.CodeUpstreamRateLimit)
	set(418, "")
	itest.ExpectCode(t, check(t, c, dana, "project.view", "project:acme-prod"), integration.CodeUpstreamError)
	set(400, "INVALID_ARGUMENT")
	itest.ExpectCode(t, check(t, c, dana, "project.view", "project:acme-prod"), integration.CodeInvalidRequest)
	set(404, "NOT_FOUND")
	itest.ExpectCode(t, check(t, c, dana, "project.view", "project:acme-prod"), integration.CodeResourceNotVisible)
	set(0, "")
	itest.ExpectCode(t, check(t, c, dana, "project.view", "project:acme-prod"), integration.CodeAllowed)
}

func TestFailures(t *testing.T) {
	srv, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, dana, "project.view", "project:acme-prod"), integration.CodeAllowed)
	itest.FailureCases(t, srv, func() integration.Decision {
		return check(t, c, dana, "project.view", "project:acme-prod")
	})
}

func TestFailuresAtTokenEndpoint(t *testing.T) {
	srv, _, c := setup(t, nil)
	itest.FailureCases(t, srv, func() integration.Decision {
		return check(t, c, dana, "project.view", "project:acme-prod")
	})
}

// --- authentication -------------------------------------------------------------

func TestTokenCachedAndRefreshedOn401(t *testing.T) {
	srv, f, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, dana, "project.view", "project:acme-prod"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, bob, "project.view", "project:acme-prod"), integration.CodeDenied)
	f.mu.Lock()
	if f.minted != 1 {
		t.Errorf("minted %d tokens, want 1", f.minted)
	}
	f.expire401 = 1
	f.mu.Unlock()
	itest.ExpectCode(t, check(t, c, dana, "project.view", "project:acme-prod"), integration.CodeAllowed)
	f.mu.Lock()
	if f.minted != 2 {
		t.Errorf("minted %d tokens after a 401, want 2", f.minted)
	}
	f.expire401 = 2
	f.mu.Unlock()
	itest.ExpectCode(t, check(t, c, dana, "project.view", "project:acme-prod"), integration.CodeCredentialRejected)
	for _, call := range srv.Calls() {
		if call.Path == "/v3/iam:troubleshoot" && !strings.HasPrefix(call.Header.Get("Authorization"), "Bearer "+itest.Canary) {
			t.Errorf("call without the minted bearer: %q", call.Header.Get("Authorization"))
		}
	}
}

func TestKeyless(t *testing.T) {
	srv, f, c := setup(t, map[string]string{"auth_mode": modeKeyless})
	itest.ExpectCode(t, check(t, c, dana, "project.view", "project:acme-prod"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, bob, "project.view", "project:acme-prod"), integration.CodeDenied)
	f.mu.Lock()
	if f.metaCalls != 1 || f.minted != 0 {
		t.Errorf("metadata token fetched %d times (want 1), key tokens %d (want 0)", f.metaCalls, f.minted)
	}
	f.mu.Unlock()
	r, err := c.Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.Summary, saEmail) {
		t.Error(r.Summary)
	}
	for _, call := range srv.Calls() {
		if strings.HasPrefix(call.Path, "/computeMetadata/") && call.Header.Get("Metadata-Flavor") != "Google" {
			t.Error("metadata call without Metadata-Flavor")
		}
	}
}

func TestQuotaProject(t *testing.T) {
	_, _, c := setup(t, map[string]string{"quota_project": "acme-billing"})
	itest.ExpectCode(t, check(t, c, dana, "project.view", "project:acme-prod"), integration.CodeAllowed)
}

func TestBadKey(t *testing.T) {
	srv := itest.NewServer(t)
	srv.UseSpec(itest.SpecFromEnv(t, "google-policytroubleshooter"), specOptions())
	deps, _ := itest.Deps(t, srv)
	for _, cred := range []string{"not json", `{"client_email":"x@y.z"}`, `{"client_email":"x@y.z","private_key":"nope"}`} {
		s := itest.Settings("gcp", "googlecloud", map[string]string{"scope": "project:acme-prod", "token_url": srv.URL + "/token", "api_url": srv.URL},
			map[string]secret.Secret{"credential": secret.Literal(itest.Canary + cred)})
		c, err := (Integration{}).New(context.Background(), s, deps)
		if err != nil {
			t.Fatal(err)
		}
		d := check(t, c, dana, "project.view", "project:acme-prod")
		itest.ExpectCode(t, d, integration.CodeCredentialRejected)
		itest.AssertNoCanary(t, d.Text)
	}
	if len(srv.Calls()) != 0 {
		t.Error("a bad key reached the network")
	}
}

func TestNewRejectsBadSettings(t *testing.T) {
	srv := itest.NewServer(t)
	deps, _ := itest.Deps(t, srv)
	deps.Connection = func(id string) (integration.Connection, error) { return nil, fmt.Errorf("no connection %q", id) }
	cases := []map[string]string{
		{},                            // no scope
		{"scope": "bucket:x"},         // wrong type
		{"scope": "project:Acme"},     // bad id
		{"scope": "project:acme?x=1"}, // query
		{"scope": "project:acme-prod", "auth_mode": "magic"},
		{"scope": "project:acme-prod", "quota_project": "Bad Project"},
		{"scope": "project:acme-prod", "googleworkspace_connection": "nope"},
	}
	for _, v := range cases {
		s := itest.Settings("gcp", "googlecloud", v, map[string]secret.Secret{"credential": secret.Literal("{}")})
		if _, err := (Integration{}).New(context.Background(), s, deps); err == nil {
			t.Errorf("New accepted %v", v)
		}
	}
	s := itest.Settings("gcp", "googlecloud", map[string]string{"scope": "project:acme-prod"}, nil)
	if _, err := (Integration{}).New(context.Background(), s, deps); err == nil {
		t.Error("New accepted key mode without a credential")
	}
	if err := integration.ValidateFields((Integration{}).Fields()); err != nil {
		t.Error(err)
	}
	for _, f := range (Integration{}).Fields() {
		if f.Validate == nil {
			continue
		}
		if err := f.Validate(""); err != nil {
			t.Errorf("field %s rejects the empty value: %v", f.Name, err)
		}
	}
}

// --- identity -------------------------------------------------------------------

func TestIdentityWithoutWorkspace(t *testing.T) {
	srv, _, c := setup(t, nil)
	// Any address is passed through; the troubleshooter answers for it.
	d := check(t, c, integration.User{Email: " Nobody@Example.com "}, "project.view", "project:acme-prod")
	itest.ExpectCode(t, d, integration.CodeDenied)
	var body struct {
		AccessTuple accessTuple `json:"accessTuple"`
	}
	srv.LastCall().JSON(t, &body)
	if body.AccessTuple.Principal != "nobody@example.com" {
		t.Errorf("principal %q", body.AccessTuple.Principal)
	}
	itest.ExpectCode(t, check(t, c, integration.User{Email: "not an email"}, "project.view", "project:acme-prod"), integration.CodeInvalidRequest)
}

func TestIdentityWithWorkspace(t *testing.T) {
	srv, _, c := setup(t, map[string]string{"googleworkspace_connection": "gws"})
	itest.ExpectCode(t, check(t, c, dana, "project.view", "project:acme-prod"), integration.CodeAllowed)
	// An alias resolves to the primary address, which is the principal.
	d := check(t, c, integration.User{Email: "d.alias@example.com"}, "project.view", "project:acme-prod")
	itest.ExpectCode(t, d, integration.CodeAllowed)
	var body struct {
		AccessTuple accessTuple `json:"accessTuple"`
	}
	srv.LastCall().JSON(t, &body)
	if body.AccessTuple.Principal != "dana@example.com" {
		t.Errorf("principal %q, want the primary address", body.AccessTuple.Principal)
	}
	n := len(srv.Calls())
	itest.ExpectCode(t, check(t, c, bob, "project.view", "project:acme-prod"), integration.CodeUserNotFound)
	d = check(t, c, integration.User{Email: "sus@example.com"}, "project.view", "project:acme-prod")
	itest.ExpectCode(t, d, integration.CodeDenied)
	if !strings.Contains(d.Text, "suspended") {
		t.Error(d.Text)
	}
	itest.ExpectCode(t, check(t, c, integration.User{Email: "nostatus@example.com"}, "project.view", "project:acme-prod"), integration.CodeUnsupported)
	if len(srv.Calls()) != n {
		t.Error("an unknown, suspended or status-less user reached the troubleshooter")
	}
}

// --- probe ------------------------------------------------------------------------

func TestProbe(t *testing.T) {
	srv, f, c := setup(t, nil)
	r, err := c.Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.Summary, saEmail) || !strings.Contains(r.Summary, "project:acme-prod") || !strings.Contains(r.Summary, stateCanAccess) {
		t.Error(r.Summary)
	}
	joined := strings.Join(r.Warnings, "\n")
	if strings.Contains(joined, "securityReviewer") || !strings.Contains(joined, "googleworkspace_connection") || !strings.Contains(joined, "discloses") {
		t.Errorf("warnings: %q", joined)
	}
	var body struct {
		AccessTuple accessTuple `json:"accessTuple"`
	}
	srv.LastCall().JSON(t, &body)
	if body.AccessTuple.Principal != saEmail || body.AccessTuple.Permission != "resourcemanager.projects.get" || body.AccessTuple.FullResourceName != projectRN {
		t.Errorf("probe asked %+v", body.AccessTuple)
	}

	// The role is missing under the scope.
	f.mu.Lock()
	f.answers[tupleKey{saEmail, "resourcemanager.projects.get", projectRN}] = answer{stateUnknownInfo, allowUnknownInf, denyUnknownInf}
	f.mu.Unlock()
	r, err = c.Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(r.Warnings, "\n"), "securityReviewer") {
		t.Errorf("warnings: %q", r.Warnings)
	}

	// The API is disabled.
	f.mu.Lock()
	f.status, f.reason = 403, "SERVICE_DISABLED"
	f.mu.Unlock()
	if _, err := c.Probe(context.Background()); err == nil {
		t.Error("probe passed with the API disabled")
	} else {
		itest.AssertNoCanary(t, err.Error())
	}
}

func TestProbeReportsKeyErrors(t *testing.T) {
	srv := itest.NewServer(t)
	deps, _ := itest.Deps(t, srv)
	s := itest.Settings("gcp", "googlecloud", map[string]string{"scope": "project:acme-prod", "token_url": srv.URL + "/token", "api_url": srv.URL},
		map[string]secret.Secret{"credential": secret.Literal(`{"client_email":"x@y.z","private_key":"` + itest.Canary + `"}`)})
	c, err := (Integration{}).New(context.Background(), s, deps)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Probe(context.Background())
	if err == nil || !strings.Contains(err.Error(), "PEM RSA key") {
		t.Errorf("probe error %v, want the key parsing cause", err)
	}
	itest.AssertNoCanary(t, integration.ToDecision(err).Text)
}

func TestProbeScopes(t *testing.T) {
	for _, tc := range []struct{ scope, permission, full string }{
		{"folder:123456789", "resourcemanager.folders.get", "//cloudresourcemanager.googleapis.com/folders/123456789"},
		{"organization:987654321", "resourcemanager.organizations.get", "//cloudresourcemanager.googleapis.com/organizations/987654321"},
	} {
		srv, f, c := setup(t, map[string]string{"scope": tc.scope})
		f.mu.Lock()
		f.answers[tupleKey{saEmail, tc.permission, tc.full}] = answer{stateCannotAccess, allowNotGranted, denyNotDenied}
		f.mu.Unlock()
		r, err := c.Probe(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(r.Summary, stateCannotAccess) {
			t.Error(r.Summary)
		}
		var body struct {
			AccessTuple accessTuple `json:"accessTuple"`
		}
		srv.LastCall().JSON(t, &body)
		if body.AccessTuple.Permission != tc.permission || body.AccessTuple.FullResourceName != tc.full {
			t.Errorf("probe asked %+v", body.AccessTuple)
		}
	}
}

func TestProbeWithWorkspace(t *testing.T) {
	_, _, c := setup(t, map[string]string{"googleworkspace_connection": "gws"})
	r, err := c.Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(r.Warnings, "\n"), "googleworkspace_connection") {
		t.Errorf("warnings: %q", r.Warnings)
	}
}

func TestCatalog(t *testing.T) {
	seen := map[string]bool{}
	for _, a := range (Integration{}).Actions() {
		if seen[a.Name] {
			t.Errorf("action %s listed twice", a.Name)
		}
		seen[a.Name] = true
		if a.Description == "" {
			t.Errorf("action %s has no description", a.Name)
		}
	}
	if !seen[rawPattern] {
		t.Error("raw pattern not listed")
	}
	if _, ok := integration.FindAction(Integration{}, "raw:storage.objects.get"); !ok {
		t.Error("raw:storage.objects.get not matched")
	}
}
