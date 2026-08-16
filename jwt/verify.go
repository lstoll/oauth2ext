package jwt

import (
	"fmt"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	jwtint "lds.li/oauth2ext/internal/jwt"
)

const maxTokenBytes = 256 << 10 // 256 KiB

// Verifier is an immutable verifier bound to a stable, reloadable key-set
// handle and a cloned, validated policy.
type Verifier struct {
	keys    *VerificationKeySet
	policy  ValidationPolicy
	allowed []jose.SignatureAlgorithm
}

// NewVerifier validates and clones policy, binding it to keys. The key set may
// later be atomically replaced without changing this verifier's policy.
func NewVerifier(keys *VerificationKeySet, policy ValidationPolicy) (*Verifier, error) {
	if keys == nil || keys.state.Load() == nil {
		return nil, fmt.Errorf("%w: invalid key set", ErrKey)
	}
	if err := policy.validate(); err != nil {
		return nil, err
	}
	allowed, err := toJoseAlgorithms(policy.AllowedAlgorithms)
	if err != nil {
		return nil, err
	}
	policy.ExpectedAudiences = append([]string(nil), policy.ExpectedAudiences...)
	policy.AllowedAlgorithms = append([]Algorithm(nil), policy.AllowedAlgorithms...)
	return &Verifier{keys: keys, policy: policy, allowed: allowed}, nil
}

// Verify verifies a compact JWT and returns an opaque verified token.
func (v *Verifier) Verify(compact string) (*VerifiedJWT, error) {
	if v == nil || v.keys == nil {
		return nil, fmt.Errorf("%w: invalid verifier", ErrKey)
	}
	policy := v.policy
	if len(compact) > maxTokenBytes {
		return nil, verificationErrorf(VerificationErrorCodeInvalidToken, "token exceeds %d bytes", maxTokenBytes)
	}
	tok, err := jwtint.ParseCompactJWS(compact, v.allowed)
	if err != nil {
		return nil, mapParseError(err)
	}
	header := tok.Header
	if err := rejectTokenControlledKeys(header); err != nil {
		return nil, err
	}

	typ, present, err := typeHeader(header)
	if err != nil {
		return nil, err
	}
	if err := validateType(typ, present, policy); err != nil {
		return nil, err
	}

	verificationKeys, err := v.keys.matchingKeys(string(header.Algorithm), header.KeyID)
	if err != nil {
		return nil, verificationErrorf(VerificationErrorCodeKey, "%v", err)
	}
	if len(verificationKeys) == 0 {
		return nil, verificationErrorf(VerificationErrorCodeKey, "no key for algorithm %q and kid %q", header.Algorithm, header.KeyID)
	}

	var lastErr error
	for _, key := range verificationKeys {
		payload, err := tok.Verify(key)
		if err != nil {
			lastErr = err
			continue
		}
		raw, claims, err := jwtint.DecodeJSONObject(payload)
		if err != nil {
			return nil, mapClaimsError(err)
		}
		if err := validateClaims(claims, policy, time.Now()); err != nil {
			return nil, err
		}
		return &VerifiedJWT{
			payload: raw,
			claims:  claims,
			alg:     Algorithm(header.Algorithm),
		}, nil
	}
	return nil, mapClaimsError(lastErr)
}

func rejectTokenControlledKeys(header jose.Header) error {
	if header.JSONWebKey != nil {
		return verificationErrorf(VerificationErrorCodeInvalidToken, "token-controlled key sources are not allowed")
	}
	if headerString(header, "jku") != "" || headerString(header, "x5u") != "" {
		return verificationErrorf(VerificationErrorCodeInvalidToken, "token-controlled key sources are not allowed")
	}
	if _, ok := header.ExtraHeaders[jose.HeaderKey("crit")]; ok {
		return verificationErrorf(VerificationErrorCodeInvalidToken, "critical headers are not supported")
	}
	return nil
}

func validateType(typ string, present bool, policy ValidationPolicy) error {
	switch policy.Type {
	case TypeAny:
		return nil
	case TypeAbsent:
		if !present {
			return nil
		}
		return verificationErrorf(VerificationErrorCodeType, "typ must be absent, got %q", typ)
	case TypeExact:
		if typ == policy.ExpectedType {
			return nil
		}
		return verificationErrorf(VerificationErrorCodeType, "typ mismatch: got %q, want %q", typ, policy.ExpectedType)
	case TypeJWTOrAbsent:
		if !present || strings.EqualFold(typ, "JWT") {
			return nil
		}
		return verificationErrorf(VerificationErrorCodeType, "typ must be absent or JWT, got %q", typ)
	}
	return verificationErrorf(VerificationErrorCodeType, "invalid typ policy")
}

func typeHeader(header jose.Header) (string, bool, error) {
	if header.ExtraHeaders == nil {
		return "", false, nil
	}
	value, ok := header.ExtraHeaders[jose.HeaderType]
	if !ok {
		return "", false, nil
	}
	typ, ok := value.(string)
	if !ok {
		return "", true, verificationErrorf(VerificationErrorCodeType, "typ header is not a string")
	}
	return typ, true, nil
}
