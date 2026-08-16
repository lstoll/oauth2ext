package clientjwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"lds.li/oauth2ext/jwt"
)

func testSignerAndKeys(t *testing.T) (*jwt.SigningIdentity, *jwt.VerificationKeySet) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jwt.NewSigningIdentity(key, jwt.ES256, "client-key")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := jwt.NewVerificationKeySetFromSigner(signer)
	if err != nil {
		t.Fatal(err)
	}
	return signer, keys
}

func verifyAssertion(t *testing.T, keys *jwt.VerificationKeySet, compact, clientID, audience string) *jwt.VerifiedJWT {
	t.Helper()
	verifier, err := jwt.NewVerifier(keys, jwt.ValidationPolicy{
		ExpectedIssuer:    clientID,
		ExpectedAudiences: []string{audience},
		AllowedAlgorithms: []jwt.Algorithm{jwt.ES256},
		Type:              jwt.TypeJWTOrAbsent,
		RequireIssuedAt:   true,
		ClockSkew:         jwt.DefaultClockSkew,
	})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := verifier.Verify(compact)
	if err != nil {
		t.Fatal(err)
	}
	return verified
}

func TestAssertionRoundTrip(t *testing.T) {
	signer, keys := testSignerAndKeys(t)
	compact, err := Sign(t.Context(), signer, SignOptions{ClientID: "client", Audience: "https://as.example/token", Algorithm: jwt.ES256})
	if err != nil {
		t.Fatal(err)
	}
	verified := verifyAssertion(t, keys, compact, "client", "https://as.example/token")
	if subject, err := verified.Subject(); err != nil || subject != "client" {
		t.Fatalf("subject: got %q, err %v", subject, err)
	}
	if jti, err := verified.JWTID(); err != nil || jti == "" {
		t.Fatalf("jti: got %q, err %v", jti, err)
	}
}

func TestAssertionRejectsWrongAudience(t *testing.T) {
	signer, keys := testSignerAndKeys(t)
	compact, err := Sign(t.Context(), signer, SignOptions{ClientID: "client", Audience: "https://as.example/token", Algorithm: jwt.ES256})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := jwt.NewVerifier(keys, jwt.ValidationPolicy{
		ExpectedIssuer:    "client",
		ExpectedAudiences: []string{"https://other.example/token"},
		AllowedAlgorithms: []jwt.Algorithm{jwt.ES256},
		Type:              jwt.TypeJWTOrAbsent,
		RequireIssuedAt:   true,
		ClockSkew:         jwt.DefaultClockSkew,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = verifier.Verify(compact)
	var verr *jwt.VerificationError
	if !errors.As(err, &verr) || verr.Code() != jwt.VerificationErrorCodeAudience {
		t.Fatalf("error: got %v", err)
	}
}

func TestAssertionRejectsExpired(t *testing.T) {
	signer, keys := testSignerAndKeys(t)
	now := time.Now()
	compact, err := Sign(t.Context(), signer, SignOptions{ClientID: "client", Audience: "https://as.example/token", Algorithm: jwt.ES256, IssuedAt: now.Add(-2 * time.Hour), Expiry: now.Add(-time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := jwt.NewVerifier(keys, jwt.ValidationPolicy{
		ExpectedIssuer:    "client",
		ExpectedAudiences: []string{"https://as.example/token"},
		AllowedAlgorithms: []jwt.Algorithm{jwt.ES256},
		Type:              jwt.TypeJWTOrAbsent,
		RequireIssuedAt:   true,
		ClockSkew:         0,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = verifier.Verify(compact)
	var verr *jwt.VerificationError
	if !errors.As(err, &verr) || verr.Code() != jwt.VerificationErrorCodeExpired {
		t.Fatalf("error: got %v", err)
	}
}

func TestAssertionRequiresSupportedAlgorithm(t *testing.T) {
	signer, _ := testSignerAndKeys(t)
	for _, test := range []struct {
		name      string
		algorithm jwt.Algorithm
	}{
		{name: "missing"},
		{name: "unsupported", algorithm: jwt.RS256},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := Sign(t.Context(), signer, SignOptions{
				ClientID:  "client",
				Audience:  "https://as.example/token",
				Algorithm: test.algorithm,
			})
			if err == nil {
				t.Fatal("Sign unexpectedly succeeded")
			}
		})
	}
}

func TestAssertionCertificateThumbprintRequiresCertificate(t *testing.T) {
	signer, _ := testSignerAndKeys(t)
	_, err := Sign(t.Context(), signer, SignOptions{
		ClientID: "client", Audience: "https://as.example/token", Algorithm: jwt.ES256,
		CertificateThumbprint: true,
	})
	if err == nil {
		t.Fatal("Sign unexpectedly succeeded without a configured certificate")
	}
}

func certificateSignerAndKeys(t *testing.T) (*jwt.SigningIdentity, *jwt.VerificationKeySet, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "client"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jwt.NewSigningIdentity(key, jwt.ES256, "client-key", cert)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := jwt.NewVerificationKeySetFromSigner(signer)
	if err != nil {
		t.Fatal(err)
	}
	return signer, keys, cert
}

func TestAssertionIncludesCertificateThumbprint(t *testing.T) {
	signer, keys, cert := certificateSignerAndKeys(t)
	compact, err := Sign(t.Context(), signer, SignOptions{
		ClientID: "client", Audience: "https://as.example/token", Algorithm: jwt.ES256,
		CertificateThumbprint: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	verifyAssertion(t, keys, compact, "client", "https://as.example/token")
	headerBytes, err := base64.RawURLEncoding.DecodeString(strings.Split(compact, ".")[0])
	if err != nil {
		t.Fatal(err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		t.Fatal(err)
	}
	thumbprint := sha256.Sum256(cert.Raw)
	want := base64.RawURLEncoding.EncodeToString(thumbprint[:])
	if got, _ := header["x5t#S256"].(string); got != want {
		t.Fatalf("x5t#S256: got %q, want %q", got, want)
	}
	if got, _ := header["kid"].(string); got != "client-key" {
		t.Fatalf("kid changed: got %q", got)
	}
}
