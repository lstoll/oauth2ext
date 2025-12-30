// Package jwt provides a DPoP (Demonstrating Proof-of-Possession) token verifier.
package jwt

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/tink-crypto/tink-go/v2/jwt"
	"google.golang.org/protobuf/types/known/structpb"
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

	// Parse header using structpb for strict JSON handling
	var header structpb.Struct
	if err := header.UnmarshalJSON(headerJSON); err != nil {
		return nil, fmt.Errorf("unmarshaling header: %w", err)
	}

	// Step 2: Extract jwk header (validator will check typ)
	jwkVal, ok := header.Fields["jwk"]
	if !ok {
		return nil, fmt.Errorf("jwk header is missing")
	}
	if _, ok := jwkVal.Kind.(*structpb.Value_StructValue); !ok {
		return nil, fmt.Errorf("jwk header is not a struct")
	}
	jwkStruct := jwkVal.GetStructValue()
	if jwkStruct == nil {
		return nil, fmt.Errorf("jwk header is not a struct")
	}

	// Step 3: Calculate JWK thumbprint using the exact jwk value from header
	// We use the exact value to avoid re-marshaling issues
	thumbprint, err := calculateJWKThumbprint(jwkStruct)
	if err != nil {
		return nil, fmt.Errorf("calculating JWK thumbprint: %w", err)
	}

	// Step 4: Convert JWK to JWK Set format for Tink
	// Tink requires the "alg" field in the JWK, so we need to add it from the header
	algVal, ok := header.Fields["alg"]
	if !ok {
		return nil, fmt.Errorf("missing alg in header")
	}
	if _, ok := algVal.Kind.(*structpb.Value_StringValue); !ok {
		return nil, fmt.Errorf("alg in header is not a string")
	}
	alg := algVal.GetStringValue()
	if alg == "" {
		return nil, fmt.Errorf("alg is empty")
	}

	// Create a copy of the JWK struct and add alg field
	jwkForTink := &structpb.Struct{
		Fields: make(map[string]*structpb.Value, len(jwkStruct.Fields)+1),
	}
	for k, v := range jwkStruct.Fields {
		jwkForTink.Fields[k] = v
	}
	jwkForTink.Fields["alg"] = structpb.NewStringValue(alg)

	// Marshal the JWK with alg for Tink
	jwkWithAlgJSON, err := jwkForTink.MarshalJSON()
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
func calculateJWKThumbprint(jwk *structpb.Struct) (string, error) {
	// Create a canonical representation by sorting keys and removing whitespace
	// We use the exact values from the jwk to avoid re-marshaling issues
	canonical, err := canonicalizeJWK(jwk)
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
// It uses the exact values from the jwk struct to avoid re-marshaling issues.
func canonicalizeJWK(jwk *structpb.Struct) ([]byte, error) {
	// Extract kty (key type) - required for all key types
	ktyVal, ok := jwk.Fields["kty"]
	if !ok {
		return nil, fmt.Errorf("missing required member: kty")
	}
	if _, ok := ktyVal.Kind.(*structpb.Value_StringValue); !ok {
		return nil, fmt.Errorf("kty is not a string")
	}
	kty := ktyVal.GetStringValue()
	if kty == "" {
		return nil, fmt.Errorf("kty is empty")
	}

	// Determine required members based on key type (RFC 7638)
	var requiredKeys []string
	canonicalMap := make(map[string]string)

	canonicalMap["kty"] = kty

	switch kty {
	case "EC":
		// EC keys require: kty, crv, x, y
		crvVal, ok := jwk.Fields["crv"]
		if !ok {
			return nil, fmt.Errorf("missing required member for EC key: crv")
		}
		if _, ok := crvVal.Kind.(*structpb.Value_StringValue); !ok {
			return nil, fmt.Errorf("crv is not a string")
		}
		crv := crvVal.GetStringValue()
		if crv == "" {
			return nil, fmt.Errorf("crv is empty")
		}
		xVal, ok := jwk.Fields["x"]
		if !ok {
			return nil, fmt.Errorf("missing required member for EC key: x")
		}
		if _, ok := xVal.Kind.(*structpb.Value_StringValue); !ok {
			return nil, fmt.Errorf("x is not a string")
		}
		x := xVal.GetStringValue()
		if x == "" {
			return nil, fmt.Errorf("x is empty")
		}
		yVal, ok := jwk.Fields["y"]
		if !ok {
			return nil, fmt.Errorf("missing required member for EC key: y")
		}
		if _, ok := yVal.Kind.(*structpb.Value_StringValue); !ok {
			return nil, fmt.Errorf("y is not a string")
		}
		y := yVal.GetStringValue()
		if y == "" {
			return nil, fmt.Errorf("y is empty")
		}
		canonicalMap["crv"] = crv
		canonicalMap["x"] = x
		canonicalMap["y"] = y
		requiredKeys = []string{"crv", "kty", "x", "y"}

	case "RSA":
		// RSA keys require: kty, n, e
		nVal, ok := jwk.Fields["n"]
		if !ok {
			return nil, fmt.Errorf("missing required member for RSA key: n")
		}
		if _, ok := nVal.Kind.(*structpb.Value_StringValue); !ok {
			return nil, fmt.Errorf("n is not a string")
		}
		n := nVal.GetStringValue()
		if n == "" {
			return nil, fmt.Errorf("n is empty")
		}
		eVal, ok := jwk.Fields["e"]
		if !ok {
			return nil, fmt.Errorf("missing required member for RSA key: e")
		}
		if _, ok := eVal.Kind.(*structpb.Value_StringValue); !ok {
			return nil, fmt.Errorf("e is not a string")
		}
		e := eVal.GetStringValue()
		if e == "" {
			return nil, fmt.Errorf("e is empty")
		}
		canonicalMap["e"] = e
		canonicalMap["n"] = n
		requiredKeys = []string{"e", "kty", "n"}

	case "OKP":
		// OKP (Octet Key Pair) keys require: kty, crv, x
		crvVal, ok := jwk.Fields["crv"]
		if !ok {
			return nil, fmt.Errorf("missing required member for OKP key: crv")
		}
		if _, ok := crvVal.Kind.(*structpb.Value_StringValue); !ok {
			return nil, fmt.Errorf("crv is not a string")
		}
		crv := crvVal.GetStringValue()
		if crv == "" {
			return nil, fmt.Errorf("crv is empty")
		}
		xVal, ok := jwk.Fields["x"]
		if !ok {
			return nil, fmt.Errorf("missing required member for OKP key: x")
		}
		if _, ok := xVal.Kind.(*structpb.Value_StringValue); !ok {
			return nil, fmt.Errorf("x is not a string")
		}
		x := xVal.GetStringValue()
		if x == "" {
			return nil, fmt.Errorf("x is empty")
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
		valStr := canonicalMap[k]
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
