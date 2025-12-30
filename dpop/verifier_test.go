package dpop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/tink-crypto/tink-go/v2/jwt"
)

// Example DPoP token from RFC 9449 Appendix A.1
// Header: {"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","x":"l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfVWAWBFs","y":"9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA","crv":"P-256"}}
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
	jwkRaw, ok := header["jwk"]
	if !ok {
		t.Fatal("jwk header is missing")
	}
	expectedThumbprint, err := calculateJWKThumbprint(jwkRaw)
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

	// Create signer using the constructor - it automatically creates the JWK
	signer, err := NewSigner(privKey)
	if err != nil {
		t.Fatalf("failed to create encoder: %v", err)
	}

	// Create DPoP token with typ header
	// DPoP tokens typically don't have an explicit expiration - they use iat with
	// a validity window, so we mark it WithoutExpiration
	now := time.Now()
	opts := &jwt.RawJWTOptions{
		WithoutExpiration: true,
		CustomClaims: map[string]any{
			"htm": "POST",
			"htu": "https://server.example.com/token",
		},
		IssuedAt: &now,
	}

	// SignAndEncode now automatically includes the jwk header
	token, err := signer.SignAndEncode(opts)
	if err != nil {
		t.Fatalf("failed to encode DPoP token: %v", err)
	}

	// Calculate expected thumbprint from the encoder's JWK
	expectedThumbprint, err := calculateJWKThumbprint(signer.jwk)
	if err != nil {
		t.Fatalf("failed to calculate expected thumbprint: %v", err)
	}

	// Create validator with expected thumbprint
	validator, err := NewValidator(&ValidatorOpts{
		ExpectedThumbprint: expectedThumbprint,
	})
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	// Verify using DPoPVerifier (which uses Tink internally)
	verifier := &Verifier{}
	verifiedJWT, err := verifier.VerifyAndDecode(token, validator)
	if err != nil {
		t.Fatalf("failed to verify and decode DPoP token: %v", err)
	}

	// Verify the JWT is not nil
	if verifiedJWT == nil {
		t.Error("verifiedJWT is nil")
	}

	t.Logf("Successfully completed DPoP round-trip with thumbprint: %s", expectedThumbprint)
}

func TestDPoPVerifier_RejectsMissingJWK(t *testing.T) {
	// Create a token without the jwk header using encodeWithHeaders directly
	privKey := generateTestKey(t)

	signer, err := NewSigner(privKey)
	if err != nil {
		t.Fatalf("failed to create encoder: %v", err)
	}

	now := time.Now()
	opts := &jwt.RawJWTOptions{
		TypeHeader:        stringPtr("dpop+jwt"),
		WithoutExpiration: true,
		IssuedAt:          &now,
	}
	rawJWT, err := jwt.NewRawJWT(opts)
	if err != nil {
		t.Fatalf("failed to create raw JWT: %v", err)
	}

	// Encode without jwk header by passing empty additionalHeaders
	token, err := signer.encodeWithHeaders(rawJWT, nil)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	// DPoPVerifier should reject tokens without jwk header
	// We need to extract thumbprint from a valid token structure, but this token doesn't have jwk
	// So we'll create a validator with an empty thumbprint - it should fail during header parsing
	validator, err := NewValidator(&ValidatorOpts{
		ExpectedThumbprint: "", // Will fail during verification
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

	signer, err := NewSigner(privKey)
	if err != nil {
		t.Fatalf("failed to create encoder: %v", err)
	}

	// Issue token 20 minutes ago (default validity is 10 minutes)
	issuedAt := time.Now().Add(-20 * time.Minute)
	opts := &jwt.RawJWTOptions{
		TypeHeader:        stringPtr("dpop+jwt"),
		WithoutExpiration: true,
		IssuedAt:          &issuedAt,
		CustomClaims: map[string]any{
			"htm": "POST",
			"htu": "https://server.example.com/token",
		},
	}
	token, err := signer.SignAndEncode(opts)
	if err != nil {
		t.Fatalf("failed to encode DPoP token: %v", err)
	}

	// Calculate thumbprint for validation
	expectedThumbprint, err := calculateJWKThumbprint(signer.jwk)
	if err != nil {
		t.Fatalf("failed to calculate thumbprint: %v", err)
	}

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

func TestJWKThumbprint_Calculation(t *testing.T) {
	// Test that thumbprint calculation works correctly
	// The JWK from the RFC example:
	jwk := map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfVWAWBFs",
		"y":   "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA",
	}

	thumbprint, err := calculateJWKThumbprint(jwk)
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
	thumbprint2, err := calculateJWKThumbprint(jwk)
	if err != nil {
		t.Fatalf("failed to calculate thumbprint second time: %v", err)
	}

	if thumbprint != thumbprint2 {
		t.Error("thumbprint calculation is not deterministic")
	}

	t.Logf("JWK thumbprint: %s", thumbprint)
}

func stringPtr(s string) *string {
	return &s
}

func TestDPoPVerifier_HTM_HTU_Validation(t *testing.T) {
	privKey := generateTestKey(t)
	signer, err := NewSigner(privKey)
	if err != nil {
		t.Fatalf("failed to create encoder: %v", err)
	}

	now := time.Now()
	opts := &jwt.RawJWTOptions{
		WithoutExpiration: true,
		CustomClaims: map[string]any{
			"htm": "POST",
			"htu": "https://server.example.com/token",
		},
		IssuedAt: &now,
	}

	token, err := signer.SignAndEncode(opts)
	if err != nil {
		t.Fatalf("failed to encode DPoP token: %v", err)
	}

	// Calculate thumbprint for validation
	expectedThumbprint, err := calculateJWKThumbprint(signer.jwk)
	if err != nil {
		t.Fatalf("failed to calculate thumbprint: %v", err)
	}

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
}

func TestDPoPVerifier_AllowUnsetHTMHTU(t *testing.T) {
	privKey := generateTestKey(t)
	signer, err := NewSigner(privKey)
	if err != nil {
		t.Fatalf("failed to create encoder: %v", err)
	}

	expectedThumbprint, err := calculateJWKThumbprint(signer.jwk)
	if err != nil {
		t.Fatalf("failed to calculate thumbprint: %v", err)
	}

	htm := "POST"
	htu := "https://server.example.com/token"

	t.Run("AllowUnsetHTMHTU=false rejects missing htm", func(t *testing.T) {
		// Create token without htm claim
		now := time.Now()
		opts := &jwt.RawJWTOptions{
			WithoutExpiration: true,
			CustomClaims: map[string]any{
				"htu": htu,
			},
			IssuedAt: &now,
		}
		token, err := signer.SignAndEncode(opts)
		if err != nil {
			t.Fatalf("failed to encode DPoP token: %v", err)
		}

		validator, err := NewValidator(&ValidatorOpts{
			ExpectedThumbprint: expectedThumbprint,
			ExpectedHTM:        &htm,
			AllowUnsetHTMHTU:   false,
		})
		if err != nil {
			t.Fatalf("failed to create validator: %v", err)
		}

		verifier := &Verifier{}
		_, err = verifier.VerifyAndDecode(token, validator)
		if err == nil {
			t.Fatal("expected error for missing htm claim when AllowUnsetHTMHTU=false")
		}
		if !strings.Contains(err.Error(), "htm claim missing") {
			t.Errorf("expected htm missing error, got: %v", err)
		}
	})

	t.Run("AllowUnsetHTMHTU=false rejects missing htu", func(t *testing.T) {
		// Create token without htu claim
		now := time.Now()
		opts := &jwt.RawJWTOptions{
			WithoutExpiration: true,
			CustomClaims: map[string]any{
				"htm": htm,
			},
			IssuedAt: &now,
		}
		token, err := signer.SignAndEncode(opts)
		if err != nil {
			t.Fatalf("failed to encode DPoP token: %v", err)
		}

		validator, err := NewValidator(&ValidatorOpts{
			ExpectedThumbprint: expectedThumbprint,
			ExpectedHTU:        &htu,
			AllowUnsetHTMHTU:   false,
		})
		if err != nil {
			t.Fatalf("failed to create validator: %v", err)
		}

		verifier := &Verifier{}
		_, err = verifier.VerifyAndDecode(token, validator)
		if err == nil {
			t.Fatal("expected error for missing htu claim when AllowUnsetHTMHTU=false")
		}
		if !strings.Contains(err.Error(), "htu claim missing") {
			t.Errorf("expected htu missing error, got: %v", err)
		}
	})

	t.Run("AllowUnsetHTMHTU=true allows missing htm", func(t *testing.T) {
		// Create token without htm claim
		now := time.Now()
		opts := &jwt.RawJWTOptions{
			WithoutExpiration: true,
			CustomClaims: map[string]any{
				"htu": htu,
			},
			IssuedAt: &now,
		}
		token, err := signer.SignAndEncode(opts)
		if err != nil {
			t.Fatalf("failed to encode DPoP token: %v", err)
		}

		validator, err := NewValidator(&ValidatorOpts{
			ExpectedThumbprint: expectedThumbprint,
			ExpectedHTM:        &htm,
			AllowUnsetHTMHTU:   true,
		})
		if err != nil {
			t.Fatalf("failed to create validator: %v", err)
		}

		verifier := &Verifier{}
		_, err = verifier.VerifyAndDecode(token, validator)
		if err != nil {
			t.Fatalf("verification should succeed with missing htm when AllowUnsetHTMHTU=true: %v", err)
		}
	})

	t.Run("AllowUnsetHTMHTU=true allows missing htu", func(t *testing.T) {
		// Create token without htu claim
		now := time.Now()
		opts := &jwt.RawJWTOptions{
			WithoutExpiration: true,
			CustomClaims: map[string]any{
				"htm": htm,
			},
			IssuedAt: &now,
		}
		token, err := signer.SignAndEncode(opts)
		if err != nil {
			t.Fatalf("failed to encode DPoP token: %v", err)
		}

		validator, err := NewValidator(&ValidatorOpts{
			ExpectedThumbprint: expectedThumbprint,
			ExpectedHTU:        &htu,
			AllowUnsetHTMHTU:   true,
		})
		if err != nil {
			t.Fatalf("failed to create validator: %v", err)
		}

		verifier := &Verifier{}
		_, err = verifier.VerifyAndDecode(token, validator)
		if err != nil {
			t.Fatalf("verification should succeed with missing htu when AllowUnsetHTMHTU=true: %v", err)
		}
	})

	t.Run("AllowUnsetHTMHTU=true still validates when claims exist", func(t *testing.T) {
		// Create token with both claims
		now := time.Now()
		opts := &jwt.RawJWTOptions{
			WithoutExpiration: true,
			CustomClaims: map[string]any{
				"htm": htm,
				"htu": htu,
			},
			IssuedAt: &now,
		}
		token, err := signer.SignAndEncode(opts)
		if err != nil {
			t.Fatalf("failed to encode DPoP token: %v", err)
		}

		validator, err := NewValidator(&ValidatorOpts{
			ExpectedThumbprint: expectedThumbprint,
			ExpectedHTM:        &htm,
			ExpectedHTU:        &htu,
			AllowUnsetHTMHTU:   true,
		})
		if err != nil {
			t.Fatalf("failed to create validator: %v", err)
		}

		verifier := &Verifier{}
		_, err = verifier.VerifyAndDecode(token, validator)
		if err != nil {
			t.Fatalf("verification should succeed with matching claims: %v", err)
		}
	})

	t.Run("AllowUnsetHTMHTU=true still rejects mismatched claims", func(t *testing.T) {
		// Create token with mismatched htm
		now := time.Now()
		opts := &jwt.RawJWTOptions{
			WithoutExpiration: true,
			CustomClaims: map[string]any{
				"htm": "GET", // Different from expected
				"htu": htu,
			},
			IssuedAt: &now,
		}
		token, err := signer.SignAndEncode(opts)
		if err != nil {
			t.Fatalf("failed to encode DPoP token: %v", err)
		}

		validator, err := NewValidator(&ValidatorOpts{
			ExpectedThumbprint: expectedThumbprint,
			ExpectedHTM:        &htm,
			ExpectedHTU:        &htu,
			AllowUnsetHTMHTU:   true,
		})
		if err != nil {
			t.Fatalf("failed to create validator: %v", err)
		}

		verifier := &Verifier{}
		_, err = verifier.VerifyAndDecode(token, validator)
		if err == nil {
			t.Fatal("expected error for mismatched htm claim even when AllowUnsetHTMHTU=true")
		}
		if !strings.Contains(err.Error(), "htm claim mismatch") {
			t.Errorf("expected htm mismatch error, got: %v", err)
		}
	})
}
