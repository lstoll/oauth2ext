package dpop

import (
	"encoding/base64"
	"testing"
)

func TestJWKThumbprint_RFC7638_Example(t *testing.T) {
	// Test using the exact RSA JWK example from RFC 7638
	// This verifies our implementation matches the RFC specification
	jwk := map[string]any{
		"kty": "RSA",
		"n":   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
		"e":   "AQAB",
		"alg": "RS256",
		"kid": "2011-04-29",
	}

	thumbprint, err := calculateJWKThumbprint(jwk)
	if err != nil {
		t.Fatalf("failed to calculate thumbprint: %v", err)
	}

	// Expected SHA-256 hash from RFC 7638 (as byte array)
	expectedHash := []byte{
		55, 54, 203, 177, 120, 124, 184, 48, 156, 119, 238, 140, 55, 5, 197,
		225, 111, 251, 158, 133, 151, 21, 144, 31, 30, 76, 89, 177, 17, 130,
		245, 123,
	}

	// Convert expected hash to base64url
	expectedThumbprint := base64.RawURLEncoding.EncodeToString(expectedHash)

	if thumbprint != expectedThumbprint {
		t.Errorf("thumbprint does not match RFC 7638 example:\n  got:      %s\n  expected: %s", thumbprint, expectedThumbprint)
	}

	t.Logf("RFC 7638 example thumbprint: %s", thumbprint)
}
