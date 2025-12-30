package dpop

import (
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

type Verifier struct {
	// ValidityAfterIssue is the validity after the issue time for a DPoP token,
	// if it has no explicit expiry. Defaults to DefaultValidityAfterIssue.
	ValidityAfterIssue time.Duration

	now time.Time
}

// Proof is the result of verifying a DPoP token.
type Proof struct {
	// VerifiedJWT is the verified JWT.
	VerifiedJWT *jwt.VerifiedJWT
	// Thumbprint is the JWK thumbprint.
	Thumbprint string
}

// ValidatorOpts parameters for DPoP token validation.
type ValidatorOpts struct {
	// ExpectedThumbprint is the expected JWK thumbprint. The token must match
	// this.
	ExpectedThumbprint string
	// IgnoreThumbprint is used to ignore the thumbprint check, this is useful
	// for the initial validation before the thumbprint is bound to the token.
	IgnoreThumbprint bool
	// ExpectedHTM is the expected HTTP method. If set, the htm claim must match.
	ExpectedHTM *string
	// ExpectedHTU is the expected HTTP URI. If set, the htu claim must match.
	ExpectedHTU *string
	// AllowUnsetHTMHTU is used to allow the htm and htu claims to be unset. If
	// this is true, the expected values will only be checked if the claims are
	// set.
	AllowUnsetHTMHTU bool
}

// Validator is used to validate DPoP tokens
type Validator struct {
	opts *ValidatorOpts
}

func NewValidator(opts *ValidatorOpts) (*Validator, error) {
	return &Validator{
		opts: opts,
	}, nil
}

// VerifyAndDecode verifies a DPoP token and returns the verified JWT along with
// the JWK thumbprint.
func (d *Verifier) VerifyAndDecode(compact string, validator *Validator) (*Proof, error) {
	header, err := parseJWTHeader(compact)
	if err != nil {
		return nil, fmt.Errorf("parsing JWT header: %w", err)
	}

	jwkRaw, ok := header["jwk"]
	if !ok {
		return nil, fmt.Errorf("jwk header is missing")
	}

	thumbprint, err := calculateJWKThumbprint(jwkRaw)
	if err != nil {
		return nil, fmt.Errorf("calculating JWK thumbprint: %w", err)
	}

	// Firstly, make sure the thumbprint matches the expected one. Can fail fase
	// if it doesn't
	if !validator.opts.IgnoreThumbprint && thumbprint != validator.opts.ExpectedThumbprint {
		return nil, fmt.Errorf("JWK thumbprint mismatch: got %q, want %q", thumbprint, validator.opts.ExpectedThumbprint)
	}

	// we need to make sure we have an alg for the JWK, for tink to handle it.
	// We rely on it to validate the specified alg matches the key type.
	alg, ok := header["alg"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid alg in header")
	}

	jwkMap, ok := jwkRaw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("jwk is not a map")
	}

	jwkForTink := make(map[string]any)
	maps.Copy(jwkForTink, jwkMap)
	jwkForTink["alg"] = alg

	jwkWithAlgJSON, err := json.Marshal(jwkForTink)
	if err != nil {
		return nil, fmt.Errorf("marshaling jwk with alg: %w", err)
	}

	handle, err := jwt.JWKSetToPublicKeysetHandle(fmt.Appendf(nil, `{"keys":[%s]}`, string(jwkWithAlgJSON)))
	if err != nil {
		return nil, fmt.Errorf("creating keyset handle from JWK: %w", err)
	}

	verifier, err := jwt.NewVerifier(handle)
	if err != nil {
		return nil, fmt.Errorf("creating tink verifier: %w", err)
	}

	tinkValidator, err := jwt.NewValidator(&jwt.ValidatorOpts{
		ExpectedTypeHeader:     th.Ptr("dpop+jwt"),
		AllowMissingExpiration: true,
	})
	if err != nil {
		return nil, fmt.Errorf("creating validator: %w", err)
	}

	verifiedJWT, err := verifier.VerifyAndDecode(compact, tinkValidator)
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

	if validator.opts.ExpectedHTM != nil {
		if !verifiedJWT.HasStringClaim("htm") {
			if !validator.opts.AllowUnsetHTMHTU {
				return nil, fmt.Errorf("htm claim missing")
			}
			// If AllowUnsetHTMHTU is true, we allow the claim to be missing
		} else {
			// Claim exists, so we must validate it matches
			htm, err := verifiedJWT.StringClaim("htm")
			if err != nil {
				return nil, fmt.Errorf("getting htm claim: %w", err)
			}
			if htm != *validator.opts.ExpectedHTM {
				return nil, fmt.Errorf("htm claim mismatch: got %q, want %q", htm, *validator.opts.ExpectedHTM)
			}
		}
	}

	if validator.opts.ExpectedHTU != nil {
		if !verifiedJWT.HasStringClaim("htu") {
			if !validator.opts.AllowUnsetHTMHTU {
				return nil, fmt.Errorf("htu claim missing")
			}
			// If AllowUnsetHTMHTU is true, we allow the claim to be missing
		} else {
			// Claim exists, so we must validate it matches
			htu, err := verifiedJWT.StringClaim("htu")
			if err != nil {
				return nil, fmt.Errorf("getting htu claim: %w", err)
			}
			if htu != *validator.opts.ExpectedHTU {
				return nil, fmt.Errorf("htu claim mismatch: got %q, want %q", htu, *validator.opts.ExpectedHTU)
			}
		}
	}

	return &Proof{
		VerifiedJWT: verifiedJWT,
		Thumbprint:  thumbprint,
	}, nil
}
