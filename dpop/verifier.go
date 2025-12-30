package dpop

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"time"

	"github.com/tink-crypto/tink-go/v2/jwt"
	"lds.li/oauth2ext/internal/th"
)

// DefaultValidityAfterIssue is the default validity after the issue time for a
// DPoP token, if it has no explicit expiry.
const DefaultValidityAfterIssue = 10 * time.Minute

// DPoPResult contains the verified JWT and the JWK thumbprint.
type DPoPResult struct {
	VerifiedJWT *jwt.VerifiedJWT
	// Thumbprint is the Base64url-encoded SHA-256 hash of the canonical JWK
	// (RFC 7638)
	Thumbprint string
}

type DPoPVerifier struct {
	// ValidityAfterIssue is the validity after the issue time for a DPoP
	// token, if it has no explicit expiry. Defaults to
	// DefaultValidityAfterIssue.
	ValidityAfterIssue time.Duration

	now time.Time
}

// VerifyOptions contains optional parameters for DPoP verification.
type VerifyOptions struct {
	// ExpectedHTM is the expected HTTP method. If set, the htm claim must match.
	ExpectedHTM string
	// ExpectedHTU is the expected HTTP URI. If set, the htu claim must match.
	ExpectedHTU string
}

// VerifyAndDecode verifies a DPoP token and returns the verified JWT along
// with the JWK thumbprint. Use VerifyAndDecodeWithOptions for additional validation.
func (d *DPoPVerifier) VerifyAndDecode(compact string) (*DPoPResult, error) {
	return d.VerifyAndDecodeWithOptions(compact, nil)
}

// VerifyAndDecodeWithOptions verifies a DPoP token with optional HTM/HTU validation
// and returns the verified JWT along with the JWK thumbprint.
func (d *DPoPVerifier) VerifyAndDecodeWithOptions(compact string, opts *VerifyOptions) (*DPoPResult, error) {
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

	validator, err := jwt.NewValidator(&jwt.ValidatorOpts{
		ExpectedTypeHeader:     th.Ptr("dpop+jwt"),
		AllowMissingExpiration: true,
	})
	if err != nil {
		return nil, fmt.Errorf("creating validator: %w", err)
	}

	verifiedJWT, err := verifier.VerifyAndDecode(compact, validator)
	if err != nil {
		return nil, fmt.Errorf("verifying JWT: %w", err)
	}

	now := time.Now()
	if !d.now.IsZero() {
		now = d.now
	}

	if !verifiedJWT.HasExpiration() {
		iat, err := verifiedJWT.IssuedAt()
		if err != nil {
			return nil, fmt.Errorf("getting issued at: %w", err)
		}
		vp := d.ValidityAfterIssue
		if vp == 0 {
			vp = DefaultValidityAfterIssue
		}
		if now.After(iat.Add(vp)) {
			return nil, fmt.Errorf("token expired")
		}
	}

	// Validate HTM and HTU claims if requested
	if opts != nil && (opts.ExpectedHTM != "" || opts.ExpectedHTU != "") {
		// Parse the payload to extract custom claims
		payload, err := verifiedJWT.JSONPayload()
		if err != nil {
			return nil, fmt.Errorf("getting JWT payload: %w", err)
		}

		var claims map[string]any
		if err := json.Unmarshal(payload, &claims); err != nil {
			return nil, fmt.Errorf("unmarshaling JWT payload: %w", err)
		}

		// Validate htm claim
		if opts.ExpectedHTM != "" {
			htm, ok := claims["htm"].(string)
			if !ok {
				return nil, fmt.Errorf("htm claim missing or not a string")
			}
			if htm != opts.ExpectedHTM {
				return nil, fmt.Errorf("htm claim mismatch: got %q, want %q", htm, opts.ExpectedHTM)
			}
		}

		// Validate htu claim
		if opts.ExpectedHTU != "" {
			htu, ok := claims["htu"].(string)
			if !ok {
				return nil, fmt.Errorf("htu claim missing or not a string")
			}
			if htu != opts.ExpectedHTU {
				return nil, fmt.Errorf("htu claim mismatch: got %q, want %q", htu, opts.ExpectedHTU)
			}
		}
	}

	return &DPoPResult{
		VerifiedJWT: verifiedJWT,
		Thumbprint:  thumbprint,
	}, nil
}
