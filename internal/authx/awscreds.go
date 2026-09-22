package authx

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/roee-hersh/hallpass/internal/httpx"
)

func xmlUnmarshal(b []byte, v any) error {
	if err := xml.Unmarshal(b, v); err != nil {
		return fmt.Errorf("decode xml: %w", err)
	}
	return nil
}

// Env abstracts the environment for tests.
type Env struct {
	Getenv   func(string) string
	ReadFile func(string) ([]byte, error)
}

// OSEnv is the real environment.
var OSEnv = Env{Getenv: os.Getenv, ReadFile: os.ReadFile}

// StaticFromJSON parses a credential JSON file/secret:
// {"access_key_id":"...","secret_access_key":"...","session_token":"..."}.
func StaticFromJSON(b []byte) (AWSCredentials, error) {
	var j struct {
		AccessKeyID     string `json:"access_key_id"`
		SecretAccessKey string `json:"secret_access_key"`
		SessionToken    string `json:"session_token"`
	}
	if err := json.Unmarshal(b, &j); err != nil {
		return AWSCredentials{}, fmt.Errorf("credential JSON: %w", err)
	}
	if j.AccessKeyID == "" || j.SecretAccessKey == "" {
		return AWSCredentials{}, errors.New("credential JSON needs access_key_id and secret_access_key")
	}
	return AWSCredentials{AccessKeyID: j.AccessKeyID, SecretAccessKey: j.SecretAccessKey, SessionToken: j.SessionToken}, nil
}

// containerResponse is the ECS/EKS Pod Identity credential document.
type containerResponse struct {
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	Token           string `json:"Token"`
	Expiration      string `json:"Expiration"`
}

func (c containerResponse) toCreds() (AWSCredentials, error) {
	if c.AccessKeyID == "" || c.SecretAccessKey == "" {
		return AWSCredentials{}, errors.New("credential document has no keys")
	}
	out := AWSCredentials{AccessKeyID: c.AccessKeyID, SecretAccessKey: c.SecretAccessKey, SessionToken: c.Token}
	if c.Expiration != "" {
		exp, err := time.Parse(time.RFC3339, c.Expiration)
		if err != nil {
			return AWSCredentials{}, fmt.Errorf("bad expiration %q", c.Expiration)
		}
		out.Expiry = exp
	}
	return out, nil
}

// ContainerProvider reads credentials from the ECS container endpoint or
// the EKS Pod Identity agent:
//
//	AWS_CONTAINER_CREDENTIALS_RELATIVE_URI  -> http://169.254.170.2{uri}
//	AWS_CONTAINER_CREDENTIALS_FULL_URI      -> the URI itself
//	AWS_CONTAINER_AUTHORIZATION_TOKEN[_FILE] -> Authorization header,
//	                                          the file re-read on every refresh
//
// UNVERIFIED: the allowed hosts for a full URI (loopback, 169.254.170.2,
// 169.254.170.23 and fd00:ec2::23 over http; anything over https) match the
// SDKs' documented rules.
type ContainerProvider struct {
	HTTP *httpx.Client
	Env  Env
}

// Configured reports whether the environment names a container endpoint.
func (p ContainerProvider) Configured() bool {
	return p.Env.Getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI") != "" || p.Env.Getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI") != ""
}

// Credentials implements CredentialProvider (uncached).
func (p ContainerProvider) Credentials(ctx context.Context) (AWSCredentials, error) {
	var endpoint string
	if rel := p.Env.Getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"); rel != "" {
		endpoint = "http://169.254.170.2" + rel
	} else if full := p.Env.Getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI"); full != "" {
		if err := validateContainerURI(full); err != nil {
			return AWSCredentials{}, err
		}
		endpoint = full
	} else {
		return AWSCredentials{}, errors.New("no container credential endpoint in the environment")
	}
	hdr := http.Header{}
	if f := p.Env.Getenv("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE"); f != "" {
		b, err := p.Env.ReadFile(f)
		if err != nil {
			return AWSCredentials{}, fmt.Errorf("container authorization token file: %w", err)
		}
		hdr.Set("Authorization", strings.TrimSpace(string(b)))
	} else if t := p.Env.Getenv("AWS_CONTAINER_AUTHORIZATION_TOKEN"); t != "" {
		hdr.Set("Authorization", t)
	}
	resp, err := p.HTTP.Do(ctx, &httpx.Request{Method: http.MethodGet, Path: endpoint, Header: hdr})
	if err != nil {
		return AWSCredentials{}, fmt.Errorf("container credentials: %w", err)
	}
	var doc containerResponse
	if err := json.Unmarshal(resp.Body, &doc); err != nil {
		return AWSCredentials{}, fmt.Errorf("container credentials: %w", err)
	}
	return doc.toCreds()
}

func validateContainerURI(full string) error {
	u, err := url.Parse(full)
	if err != nil {
		return fmt.Errorf("AWS_CONTAINER_CREDENTIALS_FULL_URI: %w", err)
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme != "http" {
		return errors.New("AWS_CONTAINER_CREDENTIALS_FULL_URI must be http or https")
	}
	host := u.Hostname()
	if host == "localhost" || host == "169.254.170.2" || host == "169.254.170.23" || host == "fd00:ec2::23" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("AWS_CONTAINER_CREDENTIALS_FULL_URI host %q is not allowed over http", host)
}

// WebIdentityProvider assumes a role with an OIDC token file (IRSA):
// AWS_ROLE_ARN, AWS_WEB_IDENTITY_TOKEN_FILE, AWS_ROLE_SESSION_NAME.
type WebIdentityProvider struct {
	STS *STSClient
	Env Env
}

// Configured reports whether the environment has IRSA variables.
func (p WebIdentityProvider) Configured() bool {
	return p.Env.Getenv("AWS_ROLE_ARN") != "" && p.Env.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE") != ""
}

// Credentials implements CredentialProvider (uncached).
func (p WebIdentityProvider) Credentials(ctx context.Context) (AWSCredentials, error) {
	arn := p.Env.Getenv("AWS_ROLE_ARN")
	file := p.Env.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE")
	if arn == "" || file == "" {
		return AWSCredentials{}, errors.New("AWS_ROLE_ARN and AWS_WEB_IDENTITY_TOKEN_FILE are not set")
	}
	tok, err := p.Env.ReadFile(file)
	if err != nil {
		return AWSCredentials{}, fmt.Errorf("web identity token: %w", err)
	}
	name := p.Env.Getenv("AWS_ROLE_SESSION_NAME")
	if name == "" {
		name = SessionName("hallpass")
	}
	return p.STS.AssumeRoleWithWebIdentity(ctx, arn, name, strings.TrimSpace(string(tok)))
}

// IMDSProvider reads instance role credentials with IMDSv2.
type IMDSProvider struct {
	HTTP *httpx.Client
	// Base defaults to http://169.254.169.254.
	Base string
}

// Credentials implements CredentialProvider (uncached).
func (p IMDSProvider) Credentials(ctx context.Context) (AWSCredentials, error) {
	base := p.Base
	if base == "" {
		base = "http://169.254.169.254"
	}
	idem := true
	tokResp, err := p.HTTP.Do(ctx, &httpx.Request{Method: http.MethodPut, Path: base + "/latest/api/token",
		Header: http.Header{"X-aws-ec2-metadata-token-ttl-seconds": {"21600"}}, Idempotent: &idem})
	if err != nil {
		return AWSCredentials{}, fmt.Errorf("imds token: %w", err)
	}
	token := strings.TrimSpace(string(tokResp.Body))
	if token == "" {
		return AWSCredentials{}, errors.New("imds: empty token")
	}
	hdr := http.Header{"X-aws-ec2-metadata-token": {token}}
	roleResp, err := p.HTTP.Do(ctx, &httpx.Request{Method: http.MethodGet, Path: base + "/latest/meta-data/iam/security-credentials/", Header: hdr})
	if err != nil {
		return AWSCredentials{}, fmt.Errorf("imds role: %w", err)
	}
	role := strings.TrimSpace(strings.SplitN(string(roleResp.Body), "\n", 2)[0])
	if role == "" {
		return AWSCredentials{}, errors.New("imds: no instance role")
	}
	credResp, err := p.HTTP.Do(ctx, &httpx.Request{Method: http.MethodGet, Path: base + "/latest/meta-data/iam/security-credentials/" + httpx.PathEscape(role), Header: hdr})
	if err != nil {
		return AWSCredentials{}, fmt.Errorf("imds credentials: %w", err)
	}
	var doc containerResponse
	if err := json.Unmarshal(credResp.Body, &doc); err != nil {
		return AWSCredentials{}, fmt.Errorf("imds credentials: %w", err)
	}
	return doc.toCreds()
}

// EnvProvider reads AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN.
type EnvProvider struct{ Env Env }

// Configured reports whether static keys are in the environment.
func (p EnvProvider) Configured() bool {
	return p.Env.Getenv("AWS_ACCESS_KEY_ID") != "" && p.Env.Getenv("AWS_SECRET_ACCESS_KEY") != ""
}

// Credentials implements CredentialProvider.
func (p EnvProvider) Credentials(context.Context) (AWSCredentials, error) {
	if !p.Configured() {
		return AWSCredentials{}, errors.New("AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are not set")
	}
	return AWSCredentials{AccessKeyID: p.Env.Getenv("AWS_ACCESS_KEY_ID"), SecretAccessKey: p.Env.Getenv("AWS_SECRET_ACCESS_KEY"), SessionToken: p.Env.Getenv("AWS_SESSION_TOKEN")}, nil
}

// AmbientProvider picks a credential source. mode is one of:
//
//	auto          env keys, then container, then web identity, then IMDS
//	container     the container endpoint only
//	web_identity  IRSA only
//	imds          the instance metadata service only
//
// The result is cached and refreshed before expiry.
func AmbientProvider(mode string, env Env, plain *httpx.Client, sts *STSClient, imdsBase string) (CredentialProvider, error) {
	var fetch func(ctx context.Context) (AWSCredentials, error)
	switch mode {
	case "container":
		fetch = ContainerProvider{HTTP: plain, Env: env}.Credentials
	case "web_identity":
		fetch = WebIdentityProvider{STS: sts, Env: env}.Credentials
	case "imds":
		fetch = IMDSProvider{HTTP: plain, Base: imdsBase}.Credentials
	case "auto", "":
		switch {
		case (EnvProvider{Env: env}).Configured():
			return EnvProvider{Env: env}, nil
		case (ContainerProvider{Env: env}).Configured():
			fetch = ContainerProvider{HTTP: plain, Env: env}.Credentials
		case (WebIdentityProvider{Env: env}).Configured():
			fetch = WebIdentityProvider{STS: sts, Env: env}.Credentials
		default:
			fetch = IMDSProvider{HTTP: plain, Base: imdsBase}.Credentials
		}
	default:
		return nil, fmt.Errorf("unknown ambient credential mode %q", mode)
	}
	return &CachedProvider{Fetch: fetch}, nil
}
