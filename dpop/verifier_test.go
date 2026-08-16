package dpop

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
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

	// Extract thumbprint from the token header for validation.
	header, err := jwtint.ParseCompactJWS(rfc9449ExampleToken, dpopSignatureAlgorithms)
	if err != nil {
		t.Fatalf("failed to parse JWT header: %v", err)
	}
	if header.Header.JSONWebKey == nil {
		t.Fatal("jwk header is missing")
	}
	expectedThumbprint, err := jwkThumbprint(header.Header.JSONWebKey)
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

	expectedThumbprint := signerThumbprint(t, signer)

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

func TestSign_AllowsSupportedAsymmetricAlgorithms(t *testing.T) {
	_, edPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jwt.NewSigningIdentity(edPrivate, jwt.EdDSA, "")
	if err != nil {
		t.Fatal(err)
	}
	compact, err := Sign(t.Context(), signer, ProofOptions{HTTPMethod: "GET", HTTPURI: "https://server.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := jwtint.ParseCompactJWS(compact, dpopSignatureAlgorithms)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Header.Algorithm != string(jwt.EdDSA) {
		t.Fatalf("algorithm: got %q, want %q", parsed.Header.Algorithm, jwt.EdDSA)
	}
}

func TestDPoP_SignVerify_AllSupportedAlgorithms(t *testing.T) {
	tests := []struct {
		name string
		alg  jwt.Algorithm
		key  func(t *testing.T) crypto.Signer
	}{
		{name: "RS256", alg: jwt.RS256, key: func(t *testing.T) crypto.Signer {
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal(err)
			}
			return key
		}},
		{name: "RS384", alg: jwt.RS384, key: func(t *testing.T) crypto.Signer {
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal(err)
			}
			return key
		}},
		{name: "RS512", alg: jwt.RS512, key: func(t *testing.T) crypto.Signer {
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal(err)
			}
			return key
		}},
		{name: "PS256", alg: jwt.PS256, key: func(t *testing.T) crypto.Signer {
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal(err)
			}
			return key
		}},
		{name: "PS384", alg: jwt.PS384, key: func(t *testing.T) crypto.Signer {
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal(err)
			}
			return key
		}},
		{name: "PS512", alg: jwt.PS512, key: func(t *testing.T) crypto.Signer {
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal(err)
			}
			return key
		}},
		{name: "ES256", alg: jwt.ES256, key: func(t *testing.T) crypto.Signer { return generateTestKey(t) }},
		{name: "ES384", alg: jwt.ES384, key: func(t *testing.T) crypto.Signer {
			key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			return key
		}},
		{name: "ES512", alg: jwt.ES512, key: func(t *testing.T) crypto.Signer {
			key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			return key
		}},
		{name: "EdDSA", alg: jwt.EdDSA, key: func(t *testing.T) crypto.Signer {
			_, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			return key
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer := mustSignerConfig(t, tt.key(t), tt.alg, nil)
			proof, err := Sign(t.Context(), signer, ProofOptions{HTTPMethod: "GET", HTTPURI: "https://server.example"})
			if err != nil {
				t.Fatal(err)
			}
			thumbprint := signerThumbprint(t, signer)
			validator, err := NewValidator(&ValidatorOpts{ExpectedThumbprint: thumbprint})
			if err != nil {
				t.Fatal(err)
			}
			verified, err := (&Verifier{}).VerifyAndDecode(proof, validator)
			if err != nil {
				t.Fatal(err)
			}
			if verified.Thumbprint != thumbprint {
				t.Fatalf("thumbprint: got %q, want %q", verified.Thumbprint, thumbprint)
			}
		})
	}
}

func TestDPoPRejectsRedundantSigner(t *testing.T) {
	a := generateTestKey(t)
	b, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	aIdentity, err := jwt.NewSigningIdentity(a, jwt.ES256, "a")
	if err != nil {
		t.Fatal(err)
	}
	bIdentity, err := jwt.NewSigningIdentity(b, jwt.RS256, "b")
	if err != nil {
		t.Fatal(err)
	}
	signingKeys, err := jwt.NewSigningKeySet(aIdentity, bIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signingKeys.Sign(t.Context(), map[string]any{"sub": "test"}, jwt.SignOptions{}); err == nil {
		t.Fatal("expected exact algorithm for multi-identity signer")
	}
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

	expectedThumbprint := signerThumbprint(t, signer)

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
	validator, err := NewValidator(&ValidatorOpts{ExpectedThumbprint: signerThumbprint(t, signer)})
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

	expectedThumbprint := signerThumbprint(t, signer)

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
	_, err := jwt.NewSigningIdentity(wrongPriv, "", "", leafCert, caCert)
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
		HTTPMethod:          "POST",
		HTTPURI:             "https://server.example.com/token",
		IncludeCertificates: true,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	expectedTP := signerThumbprint(t, signer)
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

func TestDPoPSignOmitsCertificatesByDefault(t *testing.T) {
	leafPriv, leafCert, caCert := testLeafCertChain(t)
	signer := mustSignerWithCerts(t, leafPriv, []*x509.Certificate{leafCert, caCert})
	proof, err := Sign(t.Context(), signer, ProofOptions{HTTPMethod: "GET", HTTPURI: "https://server.example"})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := jwtint.ParseCompactJWS(proof, dpopSignatureAlgorithms)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := parsed.Header.ExtraHeaders["x5c"]; ok {
		t.Fatal("x5c should be omitted unless explicitly requested")
	}
}

func TestDPoPSignRequiresConfiguredCertificatesWhenRequested(t *testing.T) {
	signer := mustSigner(t, generateTestKey(t))
	_, err := Sign(t.Context(), signer, ProofOptions{
		HTTPMethod:          "GET",
		HTTPURI:             "https://server.example",
		IncludeCertificates: true,
	})
	if err == nil || !strings.Contains(err.Error(), "has no certificate chain") {
		t.Fatalf("error: got %v, want missing certificate chain", err)
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

func TestDPoPVerifier_TrustedRoots_RequiresEmbeddedJWK(t *testing.T) {
	leafPriv, leafCert, caCert := testLeafCertChain(t)
	signer := mustSignerWithCerts(t, leafPriv, []*x509.Certificate{leafCert, caCert})
	token := mustSignClaims(t, signer, map[string]any{
		"jti": uuid.NewV4().String(), "iat": time.Now().Unix(),
		"htm": "GET", "htu": "https://server.example",
	}, jwt.SignOptions{Type: "dpop+jwt", SkipKeyID: true, Certificates: jwt.RequireCertificates})
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	validator, err := NewValidator(&ValidatorOpts{IgnoreThumbprint: true})
	if err != nil {
		t.Fatal(err)
	}
	_, err = (&Verifier{TrustedRoots: roots}).VerifyAndDecode(token, validator)
	if err == nil || !strings.Contains(err.Error(), "jwk header is missing") {
		t.Fatalf("error: got %v, want missing embedded jwk", err)
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
		HTTPMethod:          "POST",
		HTTPURI:             "https://server.example.com/token",
		IncludeCertificates: true,
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

func TestRequireJWKMatchesLeaf(t *testing.T) {
	_, leafCert, _ := testLeafCertChain(t)
	otherJWK, _, err := jwtint.PublicJWK(generateTestKey(t).Public())
	if err != nil {
		t.Fatal(err)
	}
	if err := requireJWKMatchesLeaf(&otherJWK, leafCert.PublicKey); err == nil {
		t.Fatal("expected jwk / x5c mismatch error")
	} else if !strings.Contains(err.Error(), "jwk does not match x5c leaf") {
		t.Errorf("unexpected error: %v", err)
	}

	matching, _, err := jwtint.PublicJWK(leafCert.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := requireJWKMatchesLeaf(&matching, leafCert.PublicKey); err != nil {
		t.Fatalf("matching jwk: %v", err)
	}
	if err := requireJWKMatchesLeaf(nil, leafCert.PublicKey); err == nil {
		t.Fatal("expected missing jwk error")
	}
}
