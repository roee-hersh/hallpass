package authx

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestSigV4Suite runs the official AWS Signature Version 4 test suite
// (vendored under testdata/aws-sig-v4-test-suite from botocore). Each case
// has the raw request (.req), the expected canonical request (.creq), string
// to sign (.sts) and Authorization header (.authz). Credentials, region and
// service are those the suite documents.
func TestSigV4Suite(t *testing.T) {
	root := filepath.Join("testdata", "aws-sig-v4-test-suite")
	dirs, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	creds := AWSCredentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"}
	signer := SigV4Signer{Region: "us-east-1", Service: "service"}
	ran := 0
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		name := d.Name()
		reqFile := filepath.Join(root, name, name+".req")
		raw, err := os.ReadFile(reqFile)
		if err != nil {
			continue
		}
		t.Run(name, func(t *testing.T) {
			req, body := parseRawRequest(t, raw)
			if name == "post-sts-header-before" {
				// The token is part of the signed headers in this case.
				creds := creds
				creds.SessionToken = req.Header.Get("X-Amz-Security-Token")
				checkCase(t, root, name, signer, req, body, creds)
				return
			}
			if name == "post-sts-header-after" {
				// The token header is added after signing and must not be signed.
				checkCase(t, root, name, signer, req, body, creds)
				return
			}
			checkCase(t, root, name, signer, req, body, creds)
		})
		ran++
	}
	if ran < 20 {
		t.Fatalf("only %d suite cases found", ran)
	}
}

func checkCase(t *testing.T, root, name string, signer SigV4Signer, req *http.Request, body []byte, creds AWSCredentials) {
	t.Helper()
	want := func(ext string) (string, bool) {
		b, err := os.ReadFile(filepath.Join(root, name, name+"."+ext))
		if err != nil {
			return "", false
		}
		// The vectors carry no carriage returns; a checkout with CRLF
		// conversion must not change what they mean.
		return strings.ReplaceAll(string(b), "\r", ""), true
	}
	creq, _ := signer.CanonicalRequest(req, body)
	if w, ok := want("creq"); ok && creq != w {
		t.Errorf("canonical request mismatch\n got:\n%s\nwant:\n%s", creq, w)
	}
	amzDate := req.Header.Get("X-Amz-Date")
	sts := signer.StringToSign(amzDate, creq)
	if w, ok := want("sts"); ok && sts != w {
		t.Errorf("string to sign mismatch\n got:\n%s\nwant:\n%s", sts, w)
	}
	ts, err := time.Parse(amzDateFormat, amzDate)
	if err != nil {
		t.Fatal(err)
	}
	signer.SignAt(req, body, creds, ts)
	if w, ok := want("authz"); ok && req.Header.Get("Authorization") != w {
		t.Errorf("authorization mismatch\n got: %s\nwant: %s", req.Header.Get("Authorization"), w)
	}
}

// parseRawRequest reads the suite's raw HTTP request. The suite uses
// non-canonical forms (duplicate headers, odd whitespace, unencoded paths)
// that net/http's parser would normalise, so it is parsed by hand.
func parseRawRequest(t *testing.T, raw []byte) (*http.Request, []byte) {
	t.Helper()
	sc := bufio.NewReader(bytes.NewReader(raw))
	line, err := sc.ReadString('\n')
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	line = strings.TrimRight(line, "\r\n")
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		t.Fatalf("bad request line %q", line)
	}
	method, target := parts[0], parts[1]
	// The request-target is used verbatim: the signer must normalise it.
	u, err := parseTarget(target)
	if err != nil {
		t.Fatal(err)
	}
	req := &http.Request{Method: method, URL: u, Header: http.Header{}}
	var lastKey string
	for {
		l, err := sc.ReadString('\n')
		l = strings.TrimRight(l, "\r\n")
		if l == "" {
			break
		}
		if strings.HasPrefix(l, " ") || strings.HasPrefix(l, "\t") {
			// Continuation line of a multiline header value.
			vals := req.Header[lastKey]
			vals[len(vals)-1] += "\n" + strings.TrimLeft(l, " \t")
			if err != nil {
				break
			}
			continue
		}
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			t.Fatalf("bad header line %q", l)
		}
		ck := http.CanonicalHeaderKey(k)
		lastKey = ck
		if ck == "Host" {
			req.Host = v
		}
		req.Header[ck] = append(req.Header[ck], v)
		if err != nil {
			break
		}
	}
	body, _ := io.ReadAll(sc)
	return req, body
}
