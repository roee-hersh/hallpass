package authx

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// AWSCredentials are static or temporary AWS credentials.
type AWSCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	// Expiry is zero for static keys.
	Expiry time.Time
}

// IsZero reports whether no credentials are present.
func (c AWSCredentials) IsZero() bool { return c.AccessKeyID == "" }

// SigV4Signer signs requests with AWS Signature Version 4 (header form).
//
// The canonical request follows the SigV4 specification: the URI path is
// URI-encoded once (S3 excluded, not needed here), query parameters are
// encoded and sorted by key then value, headers are lower-cased, trimmed and
// sorted, and the payload hash is SHA-256 of the body.
type SigV4Signer struct {
	Region  string
	Service string
	// Now is the clock (default time.Now).
	Now func() time.Time
}

const (
	amzDateFormat = "20060102T150405Z"
	dateFormat    = "20060102"
	algorithm     = "AWS4-HMAC-SHA256"
	emptyHash     = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// Sign adds X-Amz-Date, X-Amz-Security-Token (when present) and
// Authorization to req. body is the request payload (nil for none). The
// Host header is always signed.
func (s SigV4Signer) Sign(req *http.Request, body []byte, creds AWSCredentials) {
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	t := now().UTC()
	s.SignAt(req, body, creds, t)
}

// SignAt is Sign with an explicit time. Tests use it.
func (s SigV4Signer) SignAt(req *http.Request, body []byte, creds AWSCredentials, t time.Time) {
	amzDate := t.UTC().Format(amzDateFormat)
	if req.Header.Get("X-Amz-Date") == "" {
		req.Header.Set("X-Amz-Date", amzDate)
	} else {
		amzDate = req.Header.Get("X-Amz-Date")
	}
	if creds.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", creds.SessionToken)
	}
	payloadHash := emptyHash
	if len(body) > 0 {
		sum := sha256.Sum256(body)
		payloadHash = hex.EncodeToString(sum[:])
	}
	canonReq, signedHeaders := canonicalRequest(req, payloadHash)
	date := amzDate[:8]
	scope := date + "/" + s.Region + "/" + s.Service + "/aws4_request"
	sts := stringToSign(amzDate, scope, canonReq)
	sig := signature(creds.SecretAccessKey, date, s.Region, s.Service, sts)
	req.Header.Set("Authorization", algorithm+" Credential="+creds.AccessKeyID+"/"+scope+", SignedHeaders="+signedHeaders+", Signature="+sig)
}

// CanonicalRequest is exported for the test-suite comparison.
func (s SigV4Signer) CanonicalRequest(req *http.Request, body []byte) (string, string) {
	payloadHash := emptyHash
	if len(body) > 0 {
		sum := sha256.Sum256(body)
		payloadHash = hex.EncodeToString(sum[:])
	}
	return canonicalRequest(req, payloadHash)
}

// StringToSign is exported for the test-suite comparison.
func (s SigV4Signer) StringToSign(amzDate, canonReq string) string {
	scope := amzDate[:8] + "/" + s.Region + "/" + s.Service + "/aws4_request"
	return stringToSign(amzDate, scope, canonReq)
}

func canonicalRequest(req *http.Request, payloadHash string) (string, string) {
	// Headers: lower-case names, trimmed and space-collapsed values, sorted.
	// Host is always included. Values of repeated headers are joined by ",".
	names := map[string][]string{}
	for k, vs := range req.Header {
		lk := strings.ToLower(k)
		if lk == "authorization" || lk == "content-length" || lk == "user-agent" || lk == "expect" {
			continue
		}
		for _, v := range vs {
			names[lk] = append(names[lk], collapseSpaces(strings.TrimSpace(v)))
		}
	}
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	names["host"] = []string{host}
	keys := make([]string, 0, len(names))
	for k := range names {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var ch strings.Builder
	for _, k := range keys {
		ch.WriteString(k)
		ch.WriteString(":")
		ch.WriteString(strings.Join(names[k], ","))
		ch.WriteString("\n")
	}
	signedHeaders := strings.Join(keys, ";")

	canon := req.Method + "\n" + canonicalURI(req.URL) + "\n" + canonicalQuery(req.URL.RawQuery) + "\n" + ch.String() + "\n" + signedHeaders + "\n" + payloadHash
	return canon, signedHeaders
}

func collapseSpaces(s string) string {
	var b strings.Builder
	space := false
	for _, r := range s {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			if !space {
				b.WriteByte(' ')
			}
			space = true
			continue
		}
		space = false
		b.WriteRune(r)
	}
	return b.String()
}

// canonicalURI normalises the path (dot segments removed, duplicate slashes
// collapsed) and URI-encodes each segment.
func canonicalURI(u *url.URL) string {
	p := u.EscapedPath()
	if p == "" {
		p = "/"
	}
	// Remove dot segments as RFC 3986 section 5.2.4 does.
	p = removeDotSegments(p)
	segs := strings.Split(p, "/")
	for i, s := range segs {
		// Decode once, then encode with the AWS rules.
		dec, err := url.PathUnescape(s)
		if err != nil {
			dec = s
		}
		segs[i] = awsEscape(dec)
	}
	out := strings.Join(segs, "/")
	if out == "" {
		out = "/"
	}
	if !strings.HasPrefix(out, "/") {
		out = "/" + out
	}
	return out
}

func removeDotSegments(p string) string {
	var out []string
	for _, seg := range strings.Split(p, "/") {
		switch seg {
		case ".", "":
			continue
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		default:
			out = append(out, seg)
		}
	}
	res := "/" + strings.Join(out, "/")
	if strings.HasSuffix(p, "/") && res != "/" {
		res += "/"
	}
	return res
}

// awsEscape percent-encodes everything except unreserved characters.
func awsEscape(s string) string {
	const hexDigits = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hexDigits[c>>4])
		b.WriteByte(hexDigits[c&15])
	}
	return b.String()
}

// canonicalQuery parses the raw query, encodes each key and value with the
// AWS rules, and sorts by key then value.
func canonicalQuery(raw string) string {
	if raw == "" {
		return ""
	}
	type kv struct{ k, v string }
	var pairs []kv
	for _, part := range strings.Split(raw, "&") {
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		dk, err := url.QueryUnescape(k)
		if err != nil {
			dk = k
		}
		dv, err := url.QueryUnescape(v)
		if err != nil {
			dv = v
		}
		pairs = append(pairs, kv{awsEscape(dk), awsEscape(dv)})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].k != pairs[j].k {
			return pairs[i].k < pairs[j].k
		}
		return pairs[i].v < pairs[j].v
	})
	parts := make([]string, len(pairs))
	for i, p := range pairs {
		parts[i] = p.k + "=" + p.v
	}
	return strings.Join(parts, "&")
}

func stringToSign(amzDate, scope, canonReq string) string {
	sum := sha256.Sum256([]byte(canonReq))
	return algorithm + "\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(sum[:])
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func signature(secret, date, region, service, sts string) string {
	kDate := hmacSHA256([]byte("AWS4"+secret), date)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	kSigning := hmacSHA256(kService, "aws4_request")
	return hex.EncodeToString(hmacSHA256(kSigning, sts))
}
