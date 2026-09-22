package authx

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/roee-hersh/hallpass/internal/httpx"
)

// STSClient calls AWS STS over the Query protocol.
type STSClient struct {
	HTTP     *httpx.Client
	Endpoint string // https://sts.{region}.amazonaws.com
	Region   string
	// Creds signs AssumeRole. AssumeRoleWithWebIdentity is unsigned.
	Creds CredentialProvider
}

const stsVersion = "2011-06-15"

type stsCredentials struct {
	AccessKeyID     string `xml:"AccessKeyId"`
	SecretAccessKey string `xml:"SecretAccessKey"`
	SessionToken    string `xml:"SessionToken"`
	Expiration      string `xml:"Expiration"`
}

type assumeRoleResponse struct {
	Result struct {
		Credentials stsCredentials `xml:"Credentials"`
		AssumedRole struct {
			Arn string `xml:"Arn"`
		} `xml:"AssumedRoleUser"`
	} `xml:"AssumeRoleResult"`
}

type assumeRoleWithWebIdentityResponse struct {
	Result struct {
		Credentials stsCredentials `xml:"Credentials"`
	} `xml:"AssumeRoleWithWebIdentityResult"`
}

func (c stsCredentials) toCreds() (AWSCredentials, error) {
	if c.AccessKeyID == "" || c.SecretAccessKey == "" {
		return AWSCredentials{}, errors.New("sts: response has no credentials")
	}
	exp, err := time.Parse(time.RFC3339, c.Expiration)
	if err != nil {
		return AWSCredentials{}, fmt.Errorf("sts: bad expiration %q", c.Expiration)
	}
	return AWSCredentials{AccessKeyID: c.AccessKeyID, SecretAccessKey: c.SecretAccessKey, SessionToken: c.SessionToken, Expiry: exp}, nil
}

var roleARNRe = regexp.MustCompile(`^arn:(aws|aws-us-gov|aws-cn):iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}$`)

// ValidateRoleARN checks the shape of an IAM role ARN.
func ValidateRoleARN(arn string) error {
	if !roleARNRe.MatchString(arn) {
		return fmt.Errorf("%q is not an IAM role ARN", arn)
	}
	return nil
}

// AssumeRole calls sts:AssumeRole. duration 0 means the STS default (1 h).
func (s *STSClient) AssumeRole(ctx context.Context, roleARN, sessionName, externalID string, duration time.Duration) (AWSCredentials, error) {
	if err := ValidateRoleARN(roleARN); err != nil {
		return AWSCredentials{}, err
	}
	params := QueryParams{"RoleArn": roleARN, "RoleSessionName": sessionName}
	if externalID != "" {
		params["ExternalId"] = externalID
	}
	if duration > 0 {
		params["DurationSeconds"] = int(duration.Seconds())
	}
	client := &AWSClient{HTTP: s.HTTP, Endpoint: s.Endpoint, Region: s.Region, Service: "sts", Creds: s.Creds}
	var out assumeRoleResponse
	if err := client.Query(ctx, "AssumeRole", stsVersion, params, &out); err != nil {
		return AWSCredentials{}, err
	}
	return out.Result.Credentials.toCreds()
}

// AssumeRoleWithWebIdentity exchanges an OIDC token (IRSA) for credentials.
// The call is unsigned.
func (s *STSClient) AssumeRoleWithWebIdentity(ctx context.Context, roleARN, sessionName, token string) (AWSCredentials, error) {
	if err := ValidateRoleARN(roleARN); err != nil {
		return AWSCredentials{}, err
	}
	form := QueryParams{"RoleArn": roleARN, "RoleSessionName": sessionName, "WebIdentityToken": token}.Form("AssumeRoleWithWebIdentity", stsVersion)
	idem := true
	resp, err := s.HTTP.Do(ctx, &httpx.Request{
		Method: http.MethodPost, Path: s.Endpoint + "/", Form: form, Idempotent: &idem, Accept4xx: true,
		Header: http.Header{"Accept": {"application/xml"}},
	})
	if err != nil {
		return AWSCredentials{}, err
	}
	if resp.Status >= 400 {
		return AWSCredentials{}, DecodeXMLError(resp.Status, resp.Body)
	}
	var out assumeRoleWithWebIdentityResponse
	if err := xmlUnmarshal(resp.Body, &out); err != nil {
		return AWSCredentials{}, err
	}
	return out.Result.Credentials.toCreds()
}

// CachedProvider caches credentials and refreshes them 5 minutes before
// expiry. Concurrent refreshes are collapsed.
type CachedProvider struct {
	Fetch func(ctx context.Context) (AWSCredentials, error)
	Now   func() time.Time
	Early time.Duration

	mu    sync.Mutex
	creds AWSCredentials
	wait  chan struct{}
	err   error
}

// Credentials implements CredentialProvider.
func (p *CachedProvider) Credentials(ctx context.Context) (AWSCredentials, error) {
	now := time.Now()
	if p.Now != nil {
		now = p.Now()
	}
	early := p.Early
	if early == 0 {
		early = 5 * time.Minute
	}
	p.mu.Lock()
	if !p.creds.IsZero() && (p.creds.Expiry.IsZero() || now.Before(p.creds.Expiry.Add(-early))) {
		c := p.creds
		p.mu.Unlock()
		return c, nil
	}
	if p.wait != nil {
		ch := p.wait
		p.mu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			return AWSCredentials{}, ctx.Err()
		}
		p.mu.Lock()
		c, err := p.creds, p.err
		p.mu.Unlock()
		return c, err
	}
	ch := make(chan struct{})
	p.wait = ch
	p.mu.Unlock()

	c, err := p.Fetch(ctx)
	p.mu.Lock()
	p.wait = nil
	p.err = err
	if err == nil {
		p.creds = c
	}
	p.mu.Unlock()
	close(ch)
	return c, err
}

// StaticProvider returns fixed credentials.
type StaticProvider struct{ Creds AWSCredentials }

// Credentials implements CredentialProvider.
func (s StaticProvider) Credentials(context.Context) (AWSCredentials, error) {
	if s.Creds.IsZero() {
		return AWSCredentials{}, errors.New("no AWS credentials")
	}
	return s.Creds, nil
}

// AssumeRoleProvider returns a cached provider that assumes roleARN with
// the STS client's own credentials.
func AssumeRoleProvider(sts *STSClient, roleARN, sessionName, externalID string) *CachedProvider {
	return &CachedProvider{Fetch: func(ctx context.Context) (AWSCredentials, error) {
		return sts.AssumeRole(ctx, roleARN, sessionName, externalID, 0)
	}}
}

// SessionName builds a valid RoleSessionName from a prefix.
func SessionName(prefix string) string {
	name := prefix + "-" + strconv.FormatInt(time.Now().Unix(), 10)
	if len(name) > 64 {
		name = name[:64]
	}
	return name
}
