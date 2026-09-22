package authx

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestParseKeys(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pkcs1 := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	der8, _ := x509.MarshalPKCS8PrivateKey(key)
	pkcs8 := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der8})
	for _, in := range [][]byte{pkcs1, pkcs8, append([]byte("junk\n"), pkcs8...)} {
		k, err := ParseRSAPrivateKey(in)
		if err != nil || k.N.Cmp(key.N) != 0 {
			t.Fatal(err)
		}
	}
	for _, bad := range [][]byte{[]byte("nope"), pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte{1}}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}})} {
		if _, err := ParseRSAPrivateKey(bad); err == nil {
			t.Error("accepted bad key")
		}
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "hallpass"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, err := ParseCertificate(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	if err != nil {
		t.Fatal(err)
	}
	if th := CertThumbprintSHA256(cert); len(th) != 43 || strings.ContainsAny(th, "+/=") {
		t.Errorf("thumbprint %q", th)
	}
	if _, err := ParseCertificate(pkcs8); err == nil {
		t.Error("key accepted as certificate")
	}
}

func TestSignJWT(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	for _, alg := range []Alg{RS256, PS256} {
		tok, err := SignJWT(key, Header{Alg: alg, Kid: "k1", X5tS: "th"}, StandardClaims{Iss: "me", Aud: "you", Exp: 123, Extra: map[string]any{"scope": "a b", "custom": true}})
		if err != nil {
			t.Fatal(err)
		}
		parts := strings.Split(tok, ".")
		if len(parts) != 3 {
			t.Fatal(tok)
		}
		hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
		var hdr map[string]any
		json.Unmarshal(hb, &hdr)
		if hdr["alg"] != string(alg) || hdr["typ"] != "JWT" || hdr["kid"] != "k1" || hdr["x5t#S256"] != "th" {
			t.Errorf("header %v", hdr)
		}
		var claims map[string]any
		if err := DecodeJWTClaims(tok, &claims); err != nil || claims["iss"] != "me" || claims["scope"] != "a b" || claims["custom"] != true || claims["exp"].(float64) != 123 {
			t.Errorf("claims %v %v", claims, err)
		}
		if _, has := claims["sub"]; has {
			t.Error("empty claims must be omitted")
		}
		sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
		if err := Verify(&key.PublicKey, alg, []byte(parts[0]+"."+parts[1]), sig); err != nil {
			t.Errorf("%s: %v", alg, err)
		}
		other := RS256
		if alg == RS256 {
			other = PS256
		}
		if err := Verify(&key.PublicKey, other, []byte(parts[0]+"."+parts[1]), sig); err == nil {
			t.Errorf("%s signature verified as %s", alg, other)
		}
	}
	if _, err := SignJWT(nil, Header{Alg: RS256}, "{}"); err == nil {
		t.Error("nil key")
	}
	if _, err := SignJWT(key, Header{Alg: "HS256"}, "{}"); err == nil {
		t.Error("unsupported alg")
	}
	if err := DecodeJWTClaims("a.b", nil); err == nil {
		t.Error("bad token")
	}
	j, err := NewJTI()
	if err != nil || len(j) != 22 {
		t.Error(j, err)
	}
}

// TestRFC7515A2 signs the RFC 7515 Appendix A.2 example with its key and
// checks the signature byte for byte. RS256 is deterministic, so the
// signature must match the RFC exactly.
func TestRFC7515A2(t *testing.T) {
	if rfcKeyN == "" {
		t.Skip("vector not vendored")
	}
	key := &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: b64int(t, rfcKeyN), E: 65537}, D: b64int(t, rfcKeyD)}
	key.Primes = []*big.Int{b64int(t, rfcKeyP), b64int(t, rfcKeyQ)}
	key.Precompute()
	signingInput := rfcA2Header + "." + rfcA2Payload
	sig, err := Sign(key, RS256, []byte(signingInput))
	if err != nil {
		t.Fatal(err)
	}
	if got := base64.RawURLEncoding.EncodeToString(sig); got != rfcA2Signature {
		t.Fatalf("signature mismatch\n got %s\nwant %s", got, rfcA2Signature)
	}
}

func b64int(t *testing.T, s string) *big.Int {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return new(big.Int).SetBytes(b)
}
