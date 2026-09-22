package authx

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/roee-hersh/hallpass/internal/httpx"
	"github.com/roee-hersh/hallpass/internal/integration"
	"github.com/roee-hersh/hallpass/internal/integration/itest"
)

func plainClient(t *testing.T, srv *itest.Server) *httpx.Client {
	t.Helper()
	deps, _ := itest.Deps(t, srv)
	hc, err := deps.HTTPClient(itest.Settings("aws", "aws", nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	return &httpx.Client{HTTP: hc, Logger: deps.Logger, Sleep: func(context.Context, time.Duration) error { return nil }}
}

func TestQueryParamsForm(t *testing.T) {
	f := QueryParams{"RoleArn": "arn", "ActionNames": []string{"s3:GetObject", "s3:PutObject"}, "DurationSeconds": 900, "Flag": true}.Form("AssumeRole", "2011-06-15")
	want := url.Values{"Action": {"AssumeRole"}, "Version": {"2011-06-15"}, "RoleArn": {"arn"}, "ActionNames.member.1": {"s3:GetObject"}, "ActionNames.member.2": {"s3:PutObject"}, "DurationSeconds": {"900"}, "Flag": {"true"}}
	if f.Encode() != want.Encode() {
		t.Fatalf("got %s", f.Encode())
	}
}

func TestErrorDecoding(t *testing.T) {
	e := DecodeXMLError(403, []byte(`<ErrorResponse><Error><Type>Sender</Type><Code>AccessDenied</Code><Message>User is not authorized</Message></Error><RequestId>x</RequestId></ErrorResponse>`))
	if e.Code != "AccessDenied" || !e.AccessDenied() || e.Throttled() {
		t.Errorf("%+v", e)
	}
	e = DecodeXMLError(400, []byte(`<ErrorResponse><Error><Code>Throttling</Code><Message>Rate exceeded</Message></Error></ErrorResponse>`))
	if !e.Throttled() {
		t.Error("throttling")
	}
	e = DecodeXMLError(503, []byte("garbage"))
	if e.Code != "HTTP503" {
		t.Error(e.Code)
	}
	h := http.Header{}
	h.Set("x-amzn-ErrorType", "ThrottlingException:http://internal.amazon.com/coral/com.amazon.coral.availability/")
	e = DecodeJSONError(400, h, []byte(`{"__type":"com.amazonaws.identitystore#ThrottlingException","message":"slow down","RetryAfterSeconds":2}`))
	if e.Code != "ThrottlingException" || !e.Throttled() || e.RetryAfterSeconds != 2 || e.Message != "slow down" {
		t.Errorf("%+v", e)
	}
	e = DecodeJSONError(400, http.Header{}, []byte(`{"__type":"AccessDeniedException","Message":"nope"}`))
	if e.Code != "AccessDeniedException" || !e.AccessDenied() || e.Message != "nope" {
		t.Errorf("%+v", e)
	}
	if c := ClassifyAWSError(&AWSError{Status: 400, Code: "Throttling"}); c.Code != integration.CodeUpstreamRateLimit {
		t.Error(c)
	}
	if c := ClassifyAWSError(&AWSError{Status: 403, Code: "AccessDenied"}); c.Code != integration.CodeCredentialRejected {
		t.Error(c)
	}
	if c := ClassifyAWSError(&AWSError{Status: 400, Code: "MalformedPolicyDocument"}); c.Code != integration.CodeUpstreamError {
		t.Error(c)
	}
	if c := ClassifyAWSError(context.DeadlineExceeded); c.Code != integration.CodeUpstreamTimeout {
		t.Error(c)
	}
}

func TestSTSAssumeRoleAndQueryClient(t *testing.T) {
	srv := itest.NewServer(t)
	var calls atomic.Int32
	srv.Handle("POST", "/", func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		r.ParseForm()
		auth := r.Header.Get("Authorization")
		switch r.Form.Get("Action") {
		case "AssumeRole":
			if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=AKIA"+itest.Canary+"/") || !strings.Contains(auth, "/us-east-1/sts/aws4_request") || r.Header.Get("X-Amz-Date") == "" {
				w.WriteHeader(403)
				w.Write([]byte(`<ErrorResponse><Error><Code>SignatureDoesNotMatch</Code><Message>bad</Message></Error></ErrorResponse>`))
				return
			}
			if r.Form.Get("RoleArn") != "arn:aws:iam::123456789012:role/hallpass" || r.Form.Get("ExternalId") != "ext" || r.Form.Get("RoleSessionName") == "" {
				w.WriteHeader(400)
				w.Write([]byte(`<ErrorResponse><Error><Code>ValidationError</Code><Message>bad params</Message></Error></ErrorResponse>`))
				return
			}
			w.Write([]byte(`<AssumeRoleResponse><AssumeRoleResult><Credentials><AccessKeyId>ASIA` + itest.Canary + `</AccessKeyId><SecretAccessKey>` + itest.Canary + `secret</SecretAccessKey><SessionToken>` + itest.Canary + `tok</SessionToken><Expiration>` + time.Now().Add(time.Hour).UTC().Format(time.RFC3339) + `</Expiration></Credentials><AssumedRoleUser><Arn>arn:aws:sts::123456789012:assumed-role/hallpass/s</Arn></AssumedRoleUser></AssumeRoleResult></AssumeRoleResponse>`))
		case "AssumeRoleWithWebIdentity":
			if auth != "" || r.Form.Get("WebIdentityToken") != "oidc-"+itest.Canary {
				w.WriteHeader(400)
				w.Write([]byte(`<ErrorResponse><Error><Code>InvalidIdentityToken</Code><Message>bad</Message></Error></ErrorResponse>`))
				return
			}
			w.Write([]byte(`<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>ASIAWEB</AccessKeyId><SecretAccessKey>s</SecretAccessKey><SessionToken>t</SessionToken><Expiration>` + time.Now().Add(time.Hour).UTC().Format(time.RFC3339) + `</Expiration></Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>`))
		case "GetCallerIdentity":
			if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=ASIA") || r.Header.Get("X-Amz-Security-Token") == "" {
				w.WriteHeader(403)
				w.Write([]byte(`<ErrorResponse><Error><Code>AccessDenied</Code><Message>no</Message></Error></ErrorResponse>`))
				return
			}
			w.Write([]byte(`<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>arn:aws:sts::123456789012:assumed-role/hallpass/s</Arn></GetCallerIdentityResult></GetCallerIdentityResponse>`))
		default:
			w.WriteHeader(400)
		}
	})
	c := plainClient(t, srv)
	base := StaticProvider{Creds: AWSCredentials{AccessKeyID: "AKIA" + itest.Canary, SecretAccessKey: itest.Canary + "base"}}
	sts := &STSClient{HTTP: c, Endpoint: srv.URL, Region: "us-east-1", Creds: base}
	ctx := context.Background()

	if _, err := sts.AssumeRole(ctx, "not-an-arn", "s", "", 0); err == nil {
		t.Error("bad arn accepted")
	}
	prov := AssumeRoleProvider(sts, "arn:aws:iam::123456789012:role/hallpass", "hallpass", "ext")
	creds, err := prov.Credentials(ctx)
	if err != nil || !strings.HasPrefix(creds.AccessKeyID, "ASIA") || creds.SessionToken == "" || creds.Expiry.IsZero() {
		t.Fatalf("%+v %v", creds, err)
	}
	n := calls.Load()
	prov.Credentials(ctx)
	if calls.Load() != n {
		t.Error("assumed credentials not cached")
	}
	// Use the assumed credentials on a signed Query call.
	client := &AWSClient{HTTP: c, Endpoint: srv.URL, Region: "us-east-1", Service: "sts", Creds: prov}
	var out struct {
		Result struct {
			Arn string `xml:"Arn"`
		} `xml:"GetCallerIdentityResult"`
	}
	if err := client.Query(ctx, "GetCallerIdentity", stsVersion, QueryParams{}, &out); err != nil || !strings.Contains(out.Result.Arn, "assumed-role") {
		t.Fatalf("%+v %v", out, err)
	}
	// Web identity is unsigned.
	wi, err := sts.AssumeRoleWithWebIdentity(ctx, "arn:aws:iam::123456789012:role/irsa", "s", "oidc-"+itest.Canary)
	if err != nil || wi.AccessKeyID != "ASIAWEB" {
		t.Fatalf("%+v %v", wi, err)
	}
	// A wrong base credential surfaces as an AWSError.
	bad := &STSClient{HTTP: c, Endpoint: srv.URL, Region: "us-east-1", Creds: StaticProvider{Creds: AWSCredentials{AccessKeyID: "AKIAWRONG", SecretAccessKey: "x"}}}
	_, err = bad.AssumeRole(ctx, "arn:aws:iam::123456789012:role/hallpass", "s", "ext", 0)
	if ClassifyAWSError(err).Code != integration.CodeCredentialRejected {
		t.Errorf("wrong creds -> %v", err)
	}
}

func TestJSON11(t *testing.T) {
	srv := itest.NewServer(t)
	srv.Handle("POST", "/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/x-amz-json-1.1" || !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256") {
			w.WriteHeader(400)
			return
		}
		switch r.Header.Get("X-Amz-Target") {
		case "AWSIdentityStore.GetUserId":
			var in map[string]any
			json.NewDecoder(r.Body).Decode(&in)
			if in["IdentityStoreId"] != "d-123" {
				w.WriteHeader(400)
				w.Write([]byte(`{"__type":"ValidationException","message":"bad"}`))
				return
			}
			w.Write([]byte(`{"IdentityStoreId":"d-123","UserId":"u-1"}`))
		case "AWSIdentityStore.Throttle":
			w.WriteHeader(400)
			w.Write([]byte(`{"__type":"ThrottlingException","message":"slow","RetryAfterSeconds":1}`))
		}
	})
	c := plainClient(t, srv)
	client := &AWSClient{HTTP: c, Endpoint: srv.URL, Region: "eu-west-1", Service: "identitystore", Creds: StaticProvider{Creds: AWSCredentials{AccessKeyID: "AKIA", SecretAccessKey: "s"}}}
	var out struct{ UserId string }
	if err := client.JSON11(context.Background(), "AWSIdentityStore.GetUserId", map[string]any{"IdentityStoreId": "d-123"}, &out); err != nil || out.UserId != "u-1" {
		t.Fatal(out, err)
	}
	err := client.JSON11(context.Background(), "AWSIdentityStore.Throttle", map[string]any{}, nil)
	if ClassifyAWSError(err).Code != integration.CodeUpstreamRateLimit {
		t.Errorf("throttle -> %v", err)
	}
}

func TestCredentialChain(t *testing.T) {
	// Container endpoint with an authorization token file.
	container := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/credentials/abc" || r.Header.Get("Authorization") != "podtoken-"+itest.Canary {
			w.WriteHeader(403)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"AccessKeyId": "ASIACONT", "SecretAccessKey": "s", "Token": "t", "Expiration": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
	}))
	defer container.Close()
	env := Env{
		Getenv: func(k string) string {
			switch k {
			case "AWS_CONTAINER_CREDENTIALS_FULL_URI":
				return container.URL + "/v2/credentials/abc"
			case "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE":
				return "/token"
			}
			return ""
		},
		ReadFile: func(string) ([]byte, error) { return []byte("podtoken-" + itest.Canary + "\n"), nil },
	}
	hc, _ := httpx.NewHTTPClient(httpx.Options{})
	plain := &httpx.Client{HTTP: hc}
	prov, err := AmbientProvider("auto", env, plain, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	creds, err := prov.Credentials(context.Background())
	if err != nil || creds.AccessKeyID != "ASIACONT" {
		t.Fatalf("%+v %v", creds, err)
	}
	if err := validateContainerURI("http://evil.example/creds"); err == nil {
		t.Error("non-allowlisted http host accepted")
	}
	for _, ok := range []string{"http://169.254.170.2/x", "http://169.254.170.23/x", "http://127.0.0.1:8080/x", "http://localhost/x", "https://anything.example/x"} {
		if err := validateContainerURI(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}

	// IMDSv2: PUT token, then role name, then credentials.
	imds := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "PUT" && r.URL.Path == "/latest/api/token":
			if r.Header.Get("X-aws-ec2-metadata-token-ttl-seconds") == "" {
				w.WriteHeader(400)
				return
			}
			w.Write([]byte("imds-token"))
		case r.Header.Get("X-aws-ec2-metadata-token") != "imds-token":
			w.WriteHeader(401)
		case r.URL.Path == "/latest/meta-data/iam/security-credentials/":
			w.Write([]byte("instance-role\n"))
		case r.URL.Path == "/latest/meta-data/iam/security-credentials/instance-role":
			json.NewEncoder(w).Encode(map[string]string{"AccessKeyId": "ASIAIMDS", "SecretAccessKey": "s", "Token": "t", "Expiration": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
		default:
			w.WriteHeader(404)
		}
	}))
	defer imds.Close()
	empty := Env{Getenv: func(string) string { return "" }, ReadFile: func(string) ([]byte, error) { return nil, nil }}
	prov, _ = AmbientProvider("imds", empty, plain, nil, imds.URL)
	creds, err = prov.Credentials(context.Background())
	if err != nil || creds.AccessKeyID != "ASIAIMDS" {
		t.Fatalf("imds: %+v %v", creds, err)
	}
	prov, _ = AmbientProvider("auto", empty, plain, nil, imds.URL)
	if creds, err = prov.Credentials(context.Background()); err != nil || creds.AccessKeyID != "ASIAIMDS" {
		t.Fatalf("auto -> imds: %+v %v", creds, err)
	}

	// Env keys win in auto mode.
	keys := Env{Getenv: func(k string) string {
		return map[string]string{"AWS_ACCESS_KEY_ID": "AKIAENV", "AWS_SECRET_ACCESS_KEY": "s"}[k]
	}}
	prov, _ = AmbientProvider("auto", keys, plain, nil, "")
	if creds, _ = prov.Credentials(context.Background()); creds.AccessKeyID != "AKIAENV" {
		t.Error("env keys")
	}
	if _, err := AmbientProvider("bogus", empty, plain, nil, ""); err == nil {
		t.Error("bad mode")
	}
	if _, err := StaticFromJSON([]byte(`{"access_key_id":"a","secret_access_key":"b","session_token":"c"}`)); err != nil {
		t.Error(err)
	}
	if _, err := StaticFromJSON([]byte(`{"access_key_id":"a"}`)); err == nil {
		t.Error("incomplete json accepted")
	}
}

func TestCachedProviderRefresh(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	var n atomic.Int32
	p := &CachedProvider{Now: func() time.Time { return now }, Fetch: func(context.Context) (AWSCredentials, error) {
		n.Add(1)
		return AWSCredentials{AccessKeyID: "k", SecretAccessKey: "s", Expiry: now.Add(time.Hour)}, nil
	}}
	p.Credentials(context.Background())
	now = now.Add(50 * time.Minute)
	p.Credentials(context.Background())
	if n.Load() != 1 {
		t.Fatal("refetched early")
	}
	now = now.Add(6 * time.Minute)
	p.Credentials(context.Background())
	if n.Load() != 2 {
		t.Fatal("not refreshed 5 minutes before expiry")
	}
}
