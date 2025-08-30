package jwt

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejson "github.com/go-jose/go-jose/v4/json"
	"github.com/go-jose/go-jose/v4/jwt"
)

const defaultValidTimeBuffer = 10 * time.Second

type verifyOpts struct {
	Issuer          string
	WantType        string
	WantAnyAudience jwt.Audience
	SkipAudience    bool
	WantAnyACR      []string
	ValidTimeBuffer time.Duration
	SupportedAlgs   []jose.SignatureAlgorithm
}

type claimsWithVerifyFields struct {
	jwt.Claims
	ACR string `json:"acr,omitzero"`
}

type verifiedJWT struct {
	payload []byte
}

func (v *verifiedJWT) UnmarshalClaims(dest any) error {
	return josejson.Unmarshal(v.payload, dest)
}

// verifyToken is a low-level function that verifies the raw JWT against the
// keyset for this provider. It uses the opts to determine what counts as valid.
// the raw payload is returned if successful, otherwise an error is returned.
func verifyToken(ctx context.Context, keyset PublicKeyset, rawJWT string, opts verifyOpts) (*verifiedJWT, error) {
	supportedAlgs := opts.SupportedAlgs
	if len(supportedAlgs) == 0 {
		supportedAlgs = []jose.SignatureAlgorithm{jose.RS256} // spec says this is mandatory
	}

	sig, err := jose.ParseSignedCompact(rawJWT, supportedAlgs)
	if err != nil {
		return nil, err
	}

	if len(sig.Signatures) != 1 {
		return nil, fmt.Errorf("expected 1 signature, got %d", len(sig.Signatures))
	}
	sigHeader := sig.Signatures[0].Header

	typHdr, ok := sigHeader.ExtraHeaders[jose.HeaderType].(string)
	if opts.WantType == "" {
		if ok && typHdr != "" {
			return nil, fmt.Errorf("unexpected type header %q", typHdr)
		}
	} else {
		if !ok || typHdr != opts.WantType {
			return nil, fmt.Errorf("wanted type header %q, got %q", opts.WantType, typHdr)
		}
	}

	keys, err := keyset.GetKeysByKID(ctx, sigHeader.KeyID)
	if err != nil {
		return nil, fmt.Errorf("getting keys by kid %q: %w", sigHeader.KeyID, err)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no key found for kid %q", sigHeader.KeyID)
	}

	var payload []byte
	var verifyErr error

	for _, key := range keys {
		payload, err = sig.Verify(key.Key)
		if err == nil {
			// Verification successful
			break
		}
		verifyErr = errors.Join(verifyErr, err)
	}

	if len(payload) == 0 {
		return nil, fmt.Errorf("verifying signature failed: %w", verifyErr)
	}

	var claims claimsWithVerifyFields
	if err := josejson.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("unmarshalling claims: %w", err)
	}

	// verify against the options
	if claims.Issuer != opts.Issuer {
		return nil, fmt.Errorf("invalid issuer: got %q, want %q", claims.Issuer, opts.Issuer)
	}

	if !opts.SkipAudience {
		if len(opts.WantAnyAudience) == 0 {
			return nil, fmt.Errorf("no audience specified, and not skipped")
		} else if !slices.ContainsFunc(claims.Audience, func(a string) bool {
			return slices.Contains(opts.WantAnyAudience, a)
		}) {
			return nil, fmt.Errorf("audience %q not in acceptable list %v", claims.Audience, opts.WantAnyAudience)
		}
	}

	if len(opts.WantAnyACR) > 0 {
		if !slices.Contains(opts.WantAnyACR, claims.ACR) {
			return nil, fmt.Errorf("acr %q not in acceptable list %v", claims.ACR, opts.WantAnyACR)
		}
	}

	validTimeBuffer := opts.ValidTimeBuffer
	if validTimeBuffer == 0 {
		validTimeBuffer = defaultValidTimeBuffer
	}

	if claims.Expiry.Time().Before(time.Now().Add(validTimeBuffer)) {
		return nil, fmt.Errorf("token has expired (exp %s)", claims.Expiry.Time())
	}

	if claims.NotBefore.Time().After(time.Now().Add(-validTimeBuffer)) {
		return nil, fmt.Errorf("token not yet valid (nbf %s)", claims.NotBefore.Time())
	}

	return &verifiedJWT{payload: payload}, nil
}

func algsToJOSEAlgs[T ~string](algs []T) []jose.SignatureAlgorithm {
	supportedAlgs := make([]jose.SignatureAlgorithm, len(algs))
	for i, alg := range algs {
		supportedAlgs[i] = jose.SignatureAlgorithm(alg)
	}
	return supportedAlgs
}
