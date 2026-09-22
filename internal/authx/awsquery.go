package authx

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/roee-hersh/hallpass/internal/httpx"
	"github.com/roee-hersh/hallpass/internal/integration"
)

// AWSError is a decoded AWS service error (XML for Query-protocol services
// such as IAM and STS, JSON for JSON-1.1 services such as Identity Store).
type AWSError struct {
	Status  int
	Code    string
	Message string
	// RetryAfterSeconds is set by services that send it (Identity Center).
	RetryAfterSeconds int
}

func (e *AWSError) Error() string {
	s := fmt.Sprintf("aws: HTTP %d %s", e.Status, e.Code)
	if e.Message != "" {
		s += ": " + truncate(e.Message, 200)
	}
	return s
}

// Throttled reports whether the error is a rate limit.
func (e *AWSError) Throttled() bool {
	switch e.Code {
	case "Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyRequestsException", "RequestThrottled", "RequestThrottledException":
		return true
	}
	return e.Status == 429
}

// AccessDenied reports whether the caller lacks permission.
func (e *AWSError) AccessDenied() bool {
	switch e.Code {
	case "AccessDenied", "AccessDeniedException", "UnauthorizedAccess", "UnrecognizedClientException", "InvalidClientTokenId", "ExpiredToken", "ExpiredTokenException", "SignatureDoesNotMatch", "InvalidSignatureException", "IncompleteSignature", "AuthFailure":
		return true
	}
	return e.Status == 401 || e.Status == 403
}

type xmlErrorResponse struct {
	Error struct {
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	} `xml:"Error"`
	// Some services put the error at the top level.
	Code    string `xml:"Code"`
	Message string `xml:"Message"`
}

// DecodeXMLError parses a Query-protocol error body.
func DecodeXMLError(status int, body []byte) *AWSError {
	var x xmlErrorResponse
	_ = xml.Unmarshal(body, &x)
	code, msg := x.Error.Code, x.Error.Message
	if code == "" {
		code, msg = x.Code, x.Message
	}
	if code == "" {
		code = "HTTP" + strconv.Itoa(status)
	}
	return &AWSError{Status: status, Code: code, Message: msg}
}

// DecodeJSONError parses a JSON-1.1 error body and the x-amzn-ErrorType
// header.
func DecodeJSONError(status int, header http.Header, body []byte) *AWSError {
	var j struct {
		Type              string `json:"__type"`
		Message           string `json:"message"`
		MessageCap        string `json:"Message"`
		RetryAfterSeconds int    `json:"RetryAfterSeconds"`
	}
	_ = json.Unmarshal(body, &j)
	code := j.Type
	if h := header.Get("x-amzn-ErrorType"); h != "" {
		code = h
	}
	// "com.amazonaws.service#ThrottlingException:http://..." -> ThrottlingException
	if i := strings.Index(code, "#"); i >= 0 {
		code = code[i+1:]
	}
	if i := strings.Index(code, ":"); i >= 0 {
		code = code[:i]
	}
	if code == "" {
		code = "HTTP" + strconv.Itoa(status)
	}
	msg := j.Message
	if msg == "" {
		msg = j.MessageCap
	}
	return &AWSError{Status: status, Code: code, Message: msg, RetryAfterSeconds: j.RetryAfterSeconds}
}

// ClassifyAWSError maps an AWS call failure to an integration error.
func ClassifyAWSError(err error) *integration.Error {
	var ae *AWSError
	if errors.As(err, &ae) {
		switch {
		case ae.Throttled():
			return integration.Wrap(integration.CodeUpstreamRateLimit, err, "AWS throttled the request (%s)", ae.Code)
		case ae.AccessDenied():
			return integration.Wrap(integration.CodeCredentialRejected, err, "AWS rejected hallpass's credential or denied the call (%s)", ae.Code)
		case ae.Status >= 500:
			return integration.Wrap(integration.CodeUpstreamError, err, "AWS returned %s", ae.Code)
		default:
			return integration.Wrap(integration.CodeUpstreamError, err, "AWS returned %s", ae.Code)
		}
	}
	return httpx.Classify(err)
}

// QueryParams builds Query-protocol form values. Lists are encoded as
// Name.member.N (1-based); nested lists of structs are expressed by the
// caller as flattened keys such as "ContextEntries.member.1.ContextKeyName".
type QueryParams map[string]any

// Form encodes the params with Action and Version.
func (p QueryParams) Form(action, version string) url.Values {
	v := url.Values{"Action": {action}, "Version": {version}}
	keys := make([]string, 0, len(p))
	for k := range p {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		switch val := p[k].(type) {
		case string:
			v.Set(k, val)
		case int:
			v.Set(k, strconv.Itoa(val))
		case int64:
			v.Set(k, strconv.FormatInt(val, 10))
		case bool:
			v.Set(k, strconv.FormatBool(val))
		case []string:
			for i, s := range val {
				v.Set(k+".member."+strconv.Itoa(i+1), s)
			}
		default:
			v.Set(k, fmt.Sprint(val))
		}
	}
	return v
}

// CredentialProvider yields AWS credentials, refreshing as needed.
type CredentialProvider interface {
	Credentials(ctx context.Context) (AWSCredentials, error)
}

// AWSClient signs and sends requests to one AWS service endpoint.
type AWSClient struct {
	HTTP *httpx.Client
	// Endpoint is the full base URL, e.g. https://iam.amazonaws.com.
	Endpoint string
	// Region is the signing region; Service the signing name.
	Region  string
	Service string
	Creds   CredentialProvider
}

// Query sends a Query-protocol request (form POST) and decodes the XML
// response into out. Errors are *AWSError or transport errors.
func (c *AWSClient) Query(ctx context.Context, action, version string, params QueryParams, out any) error {
	form := params.Form(action, version)
	body := []byte(form.Encode())
	hdr := http.Header{"Content-Type": {"application/x-www-form-urlencoded; charset=utf-8"}, "Accept": {"application/xml"}}
	resp, err := c.send(ctx, body, hdr)
	if err != nil {
		return err
	}
	if resp.Status >= 400 {
		return DecodeXMLError(resp.Status, resp.Body)
	}
	if out != nil {
		if err := xml.Unmarshal(resp.Body, out); err != nil {
			return fmt.Errorf("decode %s response: %w", action, err)
		}
	}
	return nil
}

// JSON11 sends a JSON-1.1 request with X-Amz-Target and decodes the reply.
func (c *AWSClient) JSON11(ctx context.Context, target string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	if in == nil {
		body = []byte("{}")
	}
	hdr := http.Header{"Content-Type": {"application/x-amz-json-1.1"}, "X-Amz-Target": {target}}
	resp, err := c.send(ctx, body, hdr)
	if err != nil {
		return err
	}
	if resp.Status >= 400 {
		return DecodeJSONError(resp.Status, resp.Header, resp.Body)
	}
	if out != nil && len(bytes.TrimSpace(resp.Body)) > 0 {
		if err := json.Unmarshal(resp.Body, out); err != nil {
			return fmt.Errorf("decode %s response: %w", target, err)
		}
	}
	return nil
}

func (c *AWSClient) send(ctx context.Context, body []byte, hdr http.Header) (*httpx.Response, error) {
	creds, err := c.Creds.Credentials(ctx)
	if err != nil {
		return nil, err
	}
	idem := true // every call hallpass makes is a read
	req := &httpx.Request{Method: http.MethodPost, Path: c.Endpoint + "/", Body: body, Header: hdr, Idempotent: &idem, Accept4xx: true}
	client := *c.HTTP
	signer := SigV4Signer{Region: c.Region, Service: c.Service}
	client.Auth = func(_ context.Context, r *http.Request) error {
		signer.Sign(r, body, creds)
		return nil
	}
	return client.Do(ctx, req)
}

// DNSSuffix returns the DNS suffix of a partition.
func DNSSuffix(partition string) string {
	switch partition {
	case "aws-cn":
		return "amazonaws.com.cn"
	default:
		return "amazonaws.com"
	}
}

// RegionalEndpoint builds https://{service}.{region}.{suffix}.
func RegionalEndpoint(partition, service, region string) string {
	return "https://" + service + "." + region + "." + DNSSuffix(partition)
}

// IAMEndpoint returns the global IAM endpoint and its signing region.
// The China endpoint is UNVERIFIED.
func IAMEndpoint(partition string) (endpoint, region string) {
	switch partition {
	case "aws-us-gov":
		return "https://iam.us-gov.amazonaws.com", "us-gov-west-1"
	case "aws-cn":
		// UNVERIFIED: China partition IAM endpoint and signing region.
		return "https://iam.cn-north-1.amazonaws.com.cn", "cn-north-1"
	default:
		return "https://iam.amazonaws.com", "us-east-1"
	}
}
