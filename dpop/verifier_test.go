package dpop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"maps"
	"math/big"
	"strings"
	"testing"
	"time"
	"uuid"

	jwtint "lds.li/oauth2ext/internal/jwt"
	"lds.li/oauth2ext/jwt"
)

// Example DPoP token from RFC 9449 Appendix A.1
// Header: {"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","x":"l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs","y":"9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA","crv":"P-256"}}
// Claims: {"jti":"-BwC3ESc6acc2lTc","htm":"POST","htu":"https://server.example.com/token","iat":1562262616}
// Note: This is an example token, but the signature may not be valid for the given JWK.
// For a real test, we'd need to generate a token with a known private key.
const rfc9449ExampleToken = "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwiaWF0IjoxNTYyMjYyNjE2fQ.2-GxA6T8lP4vfrg8v-FdWP0A0zdrj8igiMLvqRMUvwnQg4PtFLbdLXiOSsX0x7NVY-FNyJK70nfbV37xRZT3Lg"

func TestDPoPVerifier_ExampleToken(t *testing.T) {
	// Try to verify the token
	// Note: This example token may not have a valid signature, so we expect it might fail
	dv := &Verifier{
		// set our time to when the e.g token was made.
		now: time.Unix(1562262616, 0).Add(10 * time.Minute),
	}

	// Extract thumbprint from the token header for validation
	header, err := parseJWTHeader(rfc9449ExampleToken)
	if err != nil {
		t.Fatalf("failed to parse JWT header: %v", err)
	}
	jwk, _ := header["jwk"].(map[string]any)
	if len(jwk) == 0 {
		t.Fatal("jwk header is missing")
	}
	expectedThumbprint, err := jwtint.ThumbprintMap(jwk)
	if err != nil {
		t.Fatalf("failed to calculate thumbprint: %v", err)
	}

	validator, err := NewValidator(&ValidatorOpts{
		ExpectedThumbprint: expectedThumbprint,
	})
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	verifiedJWT, err := dv.VerifyAndDecode(rfc9449ExampleToken, validator)
	if err != nil {
		t.Fatalf("failed to verify and decode DPoP token: %v", err)
	}

	// If verification succeeds, check the results
	if verifiedJWT == nil {
		t.Error("VerifiedJWT is nil")
	}

	t.Logf("Successfully verified DPoP token with thumbprint: %s", expectedThumbprint)
}

// generateTestKey generates a test ECDSA P-256 key pair for testing.
func generateTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}
	return privKey
}

func TestDPoPVerifier_RoundTrip(t *testing.T) {
	// Generate a test ECDSA key
	privKey := generateTestKey(t)
	signer := mustSigner(t, privKey)

	now := time.Now()
	opts := ProofOptions{
		HTTPMethod:  "POST",
		HTTPURI:     "https://server.example.com/token",
		IssuedAt:    now,
		Nonce:       "server-nonce",
		AccessToken: "access-token",
	}

	token, err := Sign(t.Context(), signer, opts)
	if err != nil {
		t.Fatalf("failed to encode DPoP token: %v", err)
	}

	expectedThumbprint := signer.KeyID()

	// Create validator with expected thumbprint
	validator, err := NewValidator(&ValidatorOpts{
		ExpectedThumbprint: expectedThumbprint,
	})
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	verifier := &Verifier{}
	proof, err := verifier.VerifyAndDecode(token, validator)
	if err != nil {
		t.Fatalf("failed to verify and decode DPoP token: %v", err)
	}

	if _, err := uuid.Parse(proof.JWTID); err != nil {
		t.Fatalf("jti is not a UUID: %q: %v", proof.JWTID, err)
	}
	if proof.HTTPMethod != opts.HTTPMethod || proof.HTTPURI != opts.HTTPURI {
		t.Fatalf("unexpected verified proof: %+v", proof)
	}
	if proof.Nonce != opts.Nonce {
		t.Fatalf("nonce: got %q, want %q", proof.Nonce, opts.Nonce)
	}
	if proof.AccessTokenHash != hashAccessToken(opts.AccessToken) {
		t.Fatalf("ath: got %q, want %q", proof.AccessTokenHash, hashAccessToken(opts.AccessToken))
	}

	t.Logf("Successfully completed DPoP round-trip with thumbprint: %s", expectedThumbprint)
}

func TestDPoPVerifier_RejectsMissingJWK(t *testing.T) {
	privKey := generateTestKey(t)
	now := time.Now()
	token := mustSignClaims(t, mustSigner(t, privKey), map[string]any{
		"jti": "test",
		"iat": now.Unix(),
	}, jwt.SignOptions{Type: "dpop+jwt", SkipKeyID: true})

	// DPoPVerifier should reject tokens without jwk header
	// We need to extract thumbprint from a valid token structure, but this token doesn't have jwk
	// So we'll create a validator with an empty thumbprint - it should fail during header parsing
	validator, err := NewValidator(&ValidatorOpts{
		IgnoreThumbprint: true,
	})
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	verifier := &Verifier{}
	_, err = verifier.VerifyAndDecode(token, validator)
	if err == nil {
		t.Error("expected error for token without jwk header")
	}
	t.Logf("correctly rejected token without jwk: %v", err)
}

func TestDPoPVerifier_RejectsExpiredToken(t *testing.T) {
	// Create a DPoP token that is expired (issued in the past beyond validity window)
	privKey := generateTestKey(t)
	signer := mustSigner(t, privKey)

	issuedAt := time.Now().Add(-20 * time.Minute)
	opts := ProofOptions{
		HTTPMethod: "POST",
		HTTPURI:    "https://server.example.com/token",
		IssuedAt:   issuedAt,
	}
	token, err := Sign(t.Context(), signer, opts)
	if err != nil {
		t.Fatalf("failed to encode DPoP token: %v", err)
	}

	expectedThumbprint := signer.KeyID()

	validator, err := NewValidator(&ValidatorOpts{
		ExpectedThumbprint: expectedThumbprint,
	})
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	// DPoPVerifier should reject expired tokens
	verifier := &Verifier{}
	_, err = verifier.VerifyAndDecode(token, validator)
	if err == nil {
		t.Error("expected error for expired token")
	}
	t.Logf("correctly rejected expired token: %v", err)
}

func TestDPoPVerifier_RequiresDPoPClaims(t *testing.T) {
	key := generateTestKey(t)
	signer := mustSigner(t, key)
	validator, err := NewValidator(&ValidatorOpts{ExpectedThumbprint: signer.KeyID()})
	if err != nil {
		t.Fatal(err)
	}
	baseClaims := map[string]any{
		"jti": "proof-id",
		"iat": time.Now().Unix(),
		"htm": "POST",
		"htu": "https://server.example.com/token",
	}
	for _, claim := range []string{"jti", "iat", "htm", "htu"} {
		t.Run(claim, func(t *testing.T) {
			payload := maps.Clone(baseClaims)
			delete(payload, claim)
			compact := mustSignClaims(t, signer, payload, dpopSignOpts())
			if _, err := new(Verifier).VerifyAndDecode(compact, validator); err == nil || !strings.Contains(err.Error(), claim+" claim is required") {
				t.Fatalf("error: got %v, want missing %s claim", err, claim)
			}
		})
	}
}

func TestJWKThumbprint_Calculation(t *testing.T) {
	// Test that thumbprint calculation works correctly
	// The JWK from the RFC example:
	jwk := map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs",
		"y":   "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA",
	}

	thumbprint, err := jwtint.ThumbprintMap(jwk)
	if err != nil {
		t.Fatalf("failed to calculate thumbprint: %v", err)
	}

	if thumbprint == "" {
		t.Error("thumbprint is empty")
	}

	// The thumbprint should be a base64url-encoded string (43 characters for SHA-256)
	if len(thumbprint) != 43 {
		t.Errorf("thumbprint has unexpected length: got %d, expected 43", len(thumbprint))
	}

	// Calculate again - should be the same
	thumbprint2, err := jwtint.ThumbprintMap(jwk)
	if err != nil {
		t.Fatalf("failed to calculate thumbprint second time: %v", err)
	}

	if thumbprint != thumbprint2 {
		t.Error("thumbprint calculation is not deterministic")
	}

	t.Logf("JWK thumbprint: %s", thumbprint)
}

func TestDPoPVerifier_HTM_HTU_Validation(t *testing.T) {
	privKey := generateTestKey(t)
	signer := mustSigner(t, privKey)

	now := time.Now()
	opts := ProofOptions{
		HTTPMethod: "POST",
		HTTPURI:    "https://server.example.com/token",
		IssuedAt:   now,
	}

	token, err := Sign(t.Context(), signer, opts)
	if err != nil {
		t.Fatalf("failed to encode DPoP token: %v", err)
	}

	expectedThumbprint := signer.KeyID()

	htm := "POST"
	htu := "https://server.example.com/token"

	t.Run("Valid HTM and HTU", func(t *testing.T) {
		validator, err := NewValidator(&ValidatorOpts{
			ExpectedThumbprint: expectedThumbprint,
			ExpectedHTM:        &htm,
			ExpectedHTU:        &htu,
		})
		if err != nil {
			t.Fatalf("failed to create validator: %v", err)
		}

		verifier := &Verifier{}
		_, err = verifier.VerifyAndDecode(token, validator)
		if err != nil {
			t.Fatalf("verification failed: %v", err)
		}
	})

	t.Run("Equivalent normalized HTU", func(t *testing.T) {
		equivalentHTU := "HTTPS://SERVER.EXAMPLE.COM:443/token"
		validator, err := NewValidator(&ValidatorOpts{
			ExpectedThumbprint: expectedThumbprint,
			ExpectedHTM:        &htm,
			ExpectedHTU:        &equivalentHTU,
		})
		if err != nil {
			t.Fatalf("failed to create validator: %v", err)
		}

		verifier := &Verifier{}
		if _, err := verifier.VerifyAndDecode(token, validator); err != nil {
			t.Fatalf("verification failed: %v", err)
		}
	})

	t.Run("HTM mismatch", func(t *testing.T) {
		wrongHTM := "GET"
		validator, err := NewValidator(&ValidatorOpts{
			ExpectedThumbprint: expectedThumbprint,
			ExpectedHTM:        &wrongHTM,
			ExpectedHTU:        &htu,
		})
		if err != nil {
			t.Fatalf("failed to create validator: %v", err)
		}

		verifier := &Verifier{}
		_, err = verifier.VerifyAndDecode(token, validator)
		if err == nil {
			t.Fatal("expected error for HTM mismatch")
		}
		if !strings.Contains(err.Error(), "htm claim mismatch") {
			t.Errorf("expected htm mismatch error, got: %v", err)
		}
	})

	t.Run("HTU mismatch", func(t *testing.T) {
		wrongHTU := "https://other.example.com/token"
		validator, err := NewValidator(&ValidatorOpts{
			ExpectedThumbprint: expectedThumbprint,
			ExpectedHTM:        &htm,
			ExpectedHTU:        &wrongHTU,
		})
		if err != nil {
			t.Fatalf("failed to create validator: %v", err)
		}

		verifier := &Verifier{}
		_, err = verifier.VerifyAndDecode(token, validator)
		if err == nil {
			t.Fatal("expected error for HTU mismatch")
		}
		if !strings.Contains(err.Error(), "htu claim mismatch") {
			t.Errorf("expected htu mismatch error, got: %v", err)
		}
	})

	t.Run("No validation when options not provided", func(t *testing.T) {
		validator, err := NewValidator(&ValidatorOpts{
			ExpectedThumbprint: expectedThumbprint,
		})
		if err != nil {
			t.Fatalf("failed to create validator: %v", err)
		}

		verifier := &Verifier{}
		_, err = verifier.VerifyAndDecode(token, validator)
		if err != nil {
			t.Fatalf("verification failed: %v", err)
		}
	})

	t.Run("Malformed percent-encoding in htu", func(t *testing.T) {
		validator, err := NewValidator(&ValidatorOpts{
			ExpectedThumbprint: expectedThumbprint,
			ExpectedHTM:        &htm,
			ExpectedHTU:        &htu,
		})
		if err != nil {
			t.Fatalf("failed to create validator: %v", err)
		}
		compact := mustSignClaims(t, signer, map[string]any{
			"jti": uuid.NewV4().String(),
			"iat": now.Unix(),
			"htm": "POST",
			"htu": "https://server.example.com/token%",
		}, dpopSignOpts())
		if _, err := new(Verifier).VerifyAndDecode(compact, validator); err == nil {
			t.Fatal("expected error for malformed htu percent-encoding")
		}
	})
}

// testLeafCertChain returns a leaf ECDSA key, leaf cert, and CA cert (leaf signed by CA).
func testLeafCertChain(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate, *x509.Certificate) {
	t.Helper()
	caPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("CA key: %v", err)
	}
	caTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caPriv.PublicKey, caPriv)
	if err != nil {
		t.Fatalf("CreateCertificate CA: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("ParseCertificate CA: %v", err)
	}

	leafPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	leafTpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		// Client auth only — not TLS server auth. Matches many real issuing
		// templates and would fail x509.Verify with default KeyUsages unless we
		// pass ExtKeyUsageAny (see crypto/x509.VerifyOptions.KeyUsages).
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, caCert, &leafPriv.PublicKey, caPriv)
	if err != nil {
		t.Fatalf("CreateCertificate leaf: %v", err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("ParseCertificate leaf: %v", err)
	}

	return leafPriv, leafCert, caCert
}

func TestSignerRejectsMismatchedCertificateLeaf(t *testing.T) {
	_, leafCert, caCert := testLeafCertChain(t)
	wrongPriv := generateTestKey(t)
	_, err := jwt.NewSigner(wrongPriv, "", "", leafCert, caCert)
	if err == nil {
		t.Fatal("expected error when signer key does not match leaf certificate")
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDPoPVerifier_TrustedRoots_X5C(t *testing.T) {
	leafPriv, leafCert, caCert := testLeafCertChain(t)

	signer := mustSignerWithCerts(t, leafPriv, []*x509.Certificate{leafCert, caCert})
	token, err := Sign(t.Context(), signer, ProofOptions{
		HTTPMethod: "POST",
		HTTPURI:    "https://server.example.com/token",
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	expectedTP := signer.KeyID()
	val, err := NewValidator(&ValidatorOpts{ExpectedThumbprint: expectedTP})
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}

	v := &Verifier{TrustedRoots: roots}
	proof, err := v.VerifyAndDecode(token, val)
	if err != nil {
		t.Fatalf("VerifyAndDecode: %v", err)
	}
	if proof.Thumbprint != expectedTP {
		t.Errorf("thumbprint: got %q want %q", proof.Thumbprint, expectedTP)
	}
	if proof.CertificateChain == nil {
		t.Fatal("expected CertificateChain when using TrustedRoots")
	}
	if len(proof.CertificateChain) != 2 {
		t.Fatalf("CertificateChain len: got %d want 2", len(proof.CertificateChain))
	}
	if !proof.CertificateChain[0].Equal(leafCert) {
		t.Error("chain[0] does not match leaf")
	}
	if !proof.CertificateChain[1].Equal(caCert) {
		t.Error("chain[1] does not match CA")
	}
}

func TestDPoPVerifier_TrustedRoots_RequiresX5C(t *testing.T) {
	_, _, caCert := testLeafCertChain(t)
	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	privKey := generateTestKey(t)
	signer := mustSigner(t, privKey)
	token, err := Sign(t.Context(), signer, ProofOptions{
		HTTPMethod: "POST",
		HTTPURI:    "https://server.example.com/token",
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	val, err := NewValidator(&ValidatorOpts{
		IgnoreThumbprint: true,
	})
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}

	v := &Verifier{TrustedRoots: roots}
	_, err = v.VerifyAndDecode(token, val)
	if err == nil {
		t.Fatal("expected error when TrustedRoots is set but x5c is absent")
	}
	if !strings.Contains(err.Error(), "x5c header is required") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDPoPVerifier_TrustedRoots_WrongRoot(t *testing.T) {
	leafPriv, leafCert, caCert := testLeafCertChain(t)

	otherPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("other CA key: %v", err)
	}
	otherTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(99),
		Subject:               pkix.Name{CommonName: "other-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	otherDER, err := x509.CreateCertificate(rand.Reader, otherTpl, otherTpl, &otherPriv.PublicKey, otherPriv)
	if err != nil {
		t.Fatalf("other CA cert: %v", err)
	}
	otherCA, err := x509.ParseCertificate(otherDER)
	if err != nil {
		t.Fatalf("parse other CA: %v", err)
	}

	signer := mustSignerWithCerts(t, leafPriv, []*x509.Certificate{leafCert, caCert})
	token, err := Sign(t.Context(), signer, ProofOptions{
		HTTPMethod: "POST",
		HTTPURI:    "https://server.example.com/token",
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	wrongRoots := x509.NewCertPool()
	wrongRoots.AddCert(otherCA)

	val, err := NewValidator(&ValidatorOpts{
		IgnoreThumbprint: true,
	})
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}

	v := &Verifier{TrustedRoots: wrongRoots}
	_, err = v.VerifyAndDecode(token, val)
	if err == nil {
		t.Fatal("expected chain verification failure")
	}
	if !strings.Contains(err.Error(), "certificate chain verification failed") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRequireOptionalJWKMatchesLeaf(t *testing.T) {
	_, leafCert, _ := testLeafCertChain(t)
	otherJWK, _, err := jwtint.PublicJWK(generateTestKey(t).Public())
	if err != nil {
		t.Fatal(err)
	}
	if err := requireOptionalJWKMatchesLeaf(&otherJWK, leafCert.PublicKey); err == nil {
		t.Fatal("expected jwk / x5c mismatch error")
	} else if !strings.Contains(err.Error(), "jwk does not match x5c leaf") {
		t.Errorf("unexpected error: %v", err)
	}

	matching, _, err := jwtint.PublicJWK(leafCert.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := requireOptionalJWKMatchesLeaf(&matching, leafCert.PublicKey); err != nil {
		t.Fatalf("matching jwk: %v", err)
	}
	if err := requireOptionalJWKMatchesLeaf(nil, leafCert.PublicKey); err != nil {
		t.Fatalf("omitted jwk: %v", err)
	}
}
