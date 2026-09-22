// Package authx holds the authentication helpers integrations share: JWT
// signing (RS256, PS256), OAuth 2.0 client credentials and JWT bearer
// exchanges, a token cache, and (in other files) AWS SigV4 and STS.
//
// Nothing here is vendor specific; each integration composes what it needs.
package authx

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

// Alg is a JWS signing algorithm.
type Alg string

const (
	// RS256 is RSASSA-PKCS1-v1_5 with SHA-256 (GitHub Apps, Google, Salesforce).
	RS256 Alg = "RS256"
	// PS256 is RSASSA-PSS with SHA-256 (Microsoft Entra certificate credentials).
	PS256 Alg = "PS256"
)

// ParseRSAPrivateKey reads a PEM private key: PKCS#1 ("RSA PRIVATE KEY")
// or PKCS#8 ("PRIVATE KEY"). Encrypted keys are not supported.
func ParseRSAPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	for {
		block, rest := pem.Decode(pemBytes)
		if block == nil {
			return nil, errors.New("no PEM private key found")
		}
		switch block.Type {
		case "RSA PRIVATE KEY":
			return x509.ParsePKCS1PrivateKey(block.Bytes)
		case "PRIVATE KEY":
			k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			rk, ok := k.(*rsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("PKCS#8 key is %T, not RSA", k)
			}
			return rk, nil
		case "ENCRYPTED PRIVATE KEY":
			return nil, errors.New("encrypted private keys are not supported; store the key unencrypted in a file secret")
		}
		pemBytes = rest
	}
}

// ParseCertificate reads the first PEM certificate.
func ParseCertificate(pemBytes []byte) (*x509.Certificate, error) {
	for {
		block, rest := pem.Decode(pemBytes)
		if block == nil {
			return nil, errors.New("no PEM certificate found")
		}
		if block.Type == "CERTIFICATE" {
			return x509.ParseCertificate(block.Bytes)
		}
		pemBytes = rest
	}
}

// CertThumbprintSHA256 is the base64url SHA-256 of the DER certificate, the
// value of the JOSE "x5t#S256" header.
func CertThumbprintSHA256(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// Header is the JOSE header. Extra keys go in Extra.
type Header struct {
	Alg   Alg
	Typ   string // "JWT" unless empty
	Kid   string
	X5tS  string // x5t#S256
	Extra map[string]any
}

// SignJWT builds and signs a compact JWS. claims is marshalled as JSON.
// It returns header.payload.signature.
func SignJWT(key *rsa.PrivateKey, h Header, claims any) (string, error) {
	if key == nil {
		return "", errors.New("no signing key")
	}
	hdr := map[string]any{"alg": string(h.Alg)}
	if h.Typ != "" {
		hdr["typ"] = h.Typ
	} else if h.Typ == "" {
		hdr["typ"] = "JWT"
	}
	if h.Kid != "" {
		hdr["kid"] = h.Kid
	}
	if h.X5tS != "" {
		hdr["x5t#S256"] = h.X5tS
	}
	for k, v := range h.Extra {
		hdr[k] = v
	}
	hb, err := json.Marshal(hdr)
	if err != nil {
		return "", err
	}
	var pb []byte
	switch c := claims.(type) {
	case []byte:
		pb = c
	case string:
		pb = []byte(c)
	default:
		pb, err = json.Marshal(claims)
		if err != nil {
			return "", err
		}
	}
	signingInput := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb)
	sig, err := Sign(key, h.Alg, []byte(signingInput))
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// Sign signs data with the algorithm.
func Sign(key *rsa.PrivateKey, alg Alg, data []byte) ([]byte, error) {
	sum := sha256.Sum256(data)
	switch alg {
	case RS256:
		return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	case PS256:
		return rsa.SignPSS(rand.Reader, key, crypto.SHA256, sum[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	default:
		return nil, fmt.Errorf("unsupported algorithm %q", alg)
	}
}

// Verify checks a signature made by Sign. Tests and probes use it.
func Verify(pub *rsa.PublicKey, alg Alg, data, sig []byte) error {
	sum := sha256.Sum256(data)
	switch alg {
	case RS256:
		return rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig)
	case PS256:
		return rsa.VerifyPSS(pub, crypto.SHA256, sum[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	default:
		return fmt.Errorf("unsupported algorithm %q", alg)
	}
}

// StandardClaims are the registered claims most exchanges need.
type StandardClaims struct {
	Iss   string         `json:"iss,omitempty"`
	Sub   string         `json:"sub,omitempty"`
	Aud   string         `json:"aud,omitempty"`
	Exp   int64          `json:"exp,omitempty"`
	Nbf   int64          `json:"nbf,omitempty"`
	Iat   int64          `json:"iat,omitempty"`
	Jti   string         `json:"jti,omitempty"`
	Scope string         `json:"scope,omitempty"`
	Extra map[string]any `json:"-"`
}

// MarshalJSON merges Extra into the registered claims.
func (c StandardClaims) MarshalJSON() ([]byte, error) {
	type plain StandardClaims
	b, err := json.Marshal(plain(c))
	if err != nil {
		return nil, err
	}
	if len(c.Extra) == 0 {
		return b, nil
	}
	m := map[string]any{}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	for k, v := range c.Extra {
		m[k] = v
	}
	return json.Marshal(m)
}

// DecodeJWTClaims parses the payload of a compact JWS without verifying it.
// It is for reading expiry out of tokens hallpass itself received.
func DecodeJWTClaims(token string, v any) error {
	parts := splitN(token, '.', 3)
	if len(parts) != 3 {
		return errors.New("not a compact JWS")
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return err
	}
	return json.Unmarshal(pb, v)
}

func splitN(s string, sep byte, n int) []string {
	var out []string
	for len(out) < n-1 {
		i := indexByte(s, sep)
		if i < 0 {
			break
		}
		out = append(out, s[:i])
		s = s[i+1:]
	}
	return append(out, s)
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// NewJTI returns a random 128-bit identifier as hex-free base64url.
func NewJTI() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Unix returns t as a JWT NumericDate.
func Unix(t time.Time) int64 { return t.Unix() }
