// Package jwt provides a DPoP (Demonstrating Proof-of-Possession) token verifier.
package jwt

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"sort"
	"strings"

	"github.com/tink-crypto/tink-go/v2/jwt"
)

// DPoPResult contains the verified JWT and the JWK thumbprint.
type DPoPResult struct {
	VerifiedJWT *jwt.VerifiedJWT
	Thumbprint  string // Base64url-encoded SHA-256 hash of the canonical JWK (RFC 7638)
}

// DPoPDecoder verifies DPoP tokens using JWK from the header.
type DPoPDecoder struct{}

// NewDPoPDecoder creates a new DPoPDecoder.
func NewDPoPDecoder() *DPoPDecoder {
	return &DPoPDecoder{}
}

// NewDPoPValidator creates a Tink JWT validator configured for DPoP tokens.
// It validates that the token has typ="dpop+jwt" in the header.
func NewDPoPValidator(opts *jwt.ValidatorOpts) (*jwt.Validator, error) {
	if opts == nil {
		opts = &jwt.ValidatorOpts{}
	}
	// Set the expected type header to "dpop+jwt"
	typ := "dpop+jwt"
	opts.ExpectedTypeHeader = &typ
	return jwt.NewValidator(opts)
}

// VerifyAndDecode verifies a DPoP token and returns the verified JWT along with the JWK thumbprint.
// The token must have typ="dpop+jwt" and a jwk header parameter.
func (d *DPoPDecoder) VerifyAndDecode(compact string, validator *jwt.Validator) (*DPoPResult, error) {
	// Step 1: Parse the JWT header to get raw bytes for thumbprint calculation
	headerB64, _, _, ok := parseToken(compact)
	if !ok {
		return nil, fmt.Errorf("malformed JWT: expected format header.payload.signature")
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		return nil, fmt.Errorf("decoding header: %w", err)
	}

	// Parse header to extract jwk
	var header map[string]any
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("unmarshaling header: %w", err)
	}

	// Step 2: Extract jwk header (validator will check typ)
	jwkRaw, ok := header["jwk"]
	if !ok {
		return nil, fmt.Errorf("jwk header is missing")
	}

	// Step 3: Calculate JWK thumbprint using the exact jwk value from header
	// We use the exact value to avoid re-marshaling issues
	thumbprint, err := calculateJWKThumbprint(jwkRaw)
	if err != nil {
		return nil, fmt.Errorf("calculating JWK thumbprint: %w", err)
	}

	// Step 4: Convert JWK to JWK Set format for Tink
	// Tink requires the "alg" field in the JWK, so we need to add it from the header
	alg, ok := header["alg"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid alg in header")
	}

	// Convert jwk to map to add alg field
	jwkMap, ok := jwkRaw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("jwk is not a map")
	}

	// Create a copy to avoid modifying the original
	jwkForTink := make(map[string]any)
	maps.Copy(jwkForTink, jwkMap)
	jwkForTink["alg"] = alg

	// Marshal the JWK with alg for Tink
	jwkWithAlgJSON, err := json.Marshal(jwkForTink)
	if err != nil {
		return nil, fmt.Errorf("marshaling jwk with alg: %w", err)
	}

	jwkSetJSON := fmt.Sprintf(`{"keys":[%s]}`, string(jwkWithAlgJSON))

	// Step 5: Create keyset handle from JWK Set
	handle, err := jwt.JWKSetToPublicKeysetHandle([]byte(jwkSetJSON))
	if err != nil {
		return nil, fmt.Errorf("creating keyset handle from JWK: %w", err)
	}

	// Step 6: Use Tink verifier to verify the signature and decode
	verifier, err := jwt.NewVerifier(handle)
	if err != nil {
		return nil, fmt.Errorf("creating tink verifier: %w", err)
	}

	verifiedJWT, err := verifier.VerifyAndDecode(compact, validator)
	if err != nil {
		return nil, fmt.Errorf("verifying JWT: %w", err)
	}

	return &DPoPResult{
		VerifiedJWT: verifiedJWT,
		Thumbprint:  thumbprint,
	}, nil
}

// calculateJWKThumbprint calculates the JWK thumbprint according to RFC 7638.
// The thumbprint is the base64url encoding of the SHA-256 hash of the canonical JSON
// representation of the JWK (with keys sorted and no whitespace).
// It uses the exact values from the jwk parameter to avoid re-marshaling issues.
func calculateJWKThumbprint(jwk any) (string, error) {
	// Convert to map for canonicalization
	jwkMap, ok := jwk.(map[string]any)
	if !ok {
		return "", fmt.Errorf("jwk is not a map")
	}

	// Create a canonical representation by sorting keys and removing whitespace
	// We use the exact values from the jwk to avoid re-marshaling issues
	canonical, err := canonicalizeJWK(jwkMap)
	if err != nil {
		return "", fmt.Errorf("canonicalizing JWK: %w", err)
	}

	// Calculate SHA-256 hash
	hash := sha256.Sum256(canonical)

	// Base64url encode
	thumbprint := base64.RawURLEncoding.EncodeToString(hash[:])

	return thumbprint, nil
}

// canonicalizeJWK creates a canonical JSON representation of a JWK according to RFC 7638.
// Keys are sorted alphabetically, and the JSON has no whitespace.
// It uses the exact values from the jwk map to avoid re-marshaling issues.
func canonicalizeJWK(jwk map[string]any) ([]byte, error) {
	// Extract kty (key type) - required for all key types
	kty, ok := jwk["kty"].(string)
	if !ok {
		return nil, fmt.Errorf("missing required member: kty")
	}

	// Determine required members based on key type (RFC 7638)
	var requiredKeys []string
	canonicalMap := make(map[string]any)

	canonicalMap["kty"] = kty

	switch kty {
	case "EC":
		// EC keys require: kty, crv, x, y
		crv, ok := jwk["crv"].(string)
		if !ok {
			return nil, fmt.Errorf("missing required member for EC key: crv")
		}
		x, ok := jwk["x"].(string)
		if !ok {
			return nil, fmt.Errorf("missing required member for EC key: x")
		}
		y, ok := jwk["y"].(string)
		if !ok {
			return nil, fmt.Errorf("missing required member for EC key: y")
		}
		canonicalMap["crv"] = crv
		canonicalMap["x"] = x
		canonicalMap["y"] = y
		requiredKeys = []string{"crv", "kty", "x", "y"}

	case "RSA":
		// RSA keys require: kty, n, e
		n, ok := jwk["n"].(string)
		if !ok {
			return nil, fmt.Errorf("missing required member for RSA key: n")
		}
		e, ok := jwk["e"].(string)
		if !ok {
			return nil, fmt.Errorf("missing required member for RSA key: e")
		}
		canonicalMap["e"] = e
		canonicalMap["n"] = n
		requiredKeys = []string{"e", "kty", "n"}

	case "OKP":
		// OKP (Octet Key Pair) keys require: kty, crv, x
		crv, ok := jwk["crv"].(string)
		if !ok {
			return nil, fmt.Errorf("missing required member for OKP key: crv")
		}
		x, ok := jwk["x"].(string)
		if !ok {
			return nil, fmt.Errorf("missing required member for OKP key: x")
		}
		canonicalMap["crv"] = crv
		canonicalMap["x"] = x
		requiredKeys = []string{"crv", "kty", "x"}

	default:
		return nil, fmt.Errorf("unsupported key type for thumbprint: %s", kty)
	}

	// Sort keys lexicographically (RFC 7638 requires this)
	sort.Strings(requiredKeys)

	// Build canonical JSON manually to ensure no whitespace
	// Use the exact string values from the jwk to avoid any re-encoding issues
	var parts []string
	for _, k := range requiredKeys {
		v := canonicalMap[k]
		valStr, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("unexpected non-string value for key %s", k)
		}
		// JSON encode the value to handle any special characters
		// This is safe because we're using the exact string value from the header
		valJSON, err := json.Marshal(valStr)
		if err != nil {
			return nil, fmt.Errorf("marshaling value for key %s: %w", k, err)
		}
		keyJSON, err := json.Marshal(k)
		if err != nil {
			return nil, fmt.Errorf("marshaling key %s: %w", k, err)
		}
		parts = append(parts, string(keyJSON)+":"+string(valJSON))
	}

	canonicalJSON := "{" + strings.Join(parts, ",") + "}"

	return []byte(canonicalJSON), nil
}
