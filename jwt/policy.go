package jwt

import (
	"fmt"
	"slices"
	"time"
)

const (
	// DefaultClockSkew is the recommended leeway for protocol-level validators.
	// Low-level validation remains strict unless this value is selected explicitly.
	DefaultClockSkew = time.Minute
	// MaxClockSkew is the largest leeway accepted by ValidationPolicy.
	MaxClockSkew = 10 * time.Minute
)

// TypePolicy controls how a JWT typ header is handled.
type TypePolicy uint8

const (
	// TypePolicyUnspecified is invalid. Callers must choose a type policy.
	TypePolicyUnspecified TypePolicy = iota
	// TypeAny accepts an absent typ or any string value.
	TypeAny
	// TypeAbsent requires typ to be absent.
	TypeAbsent
	// TypeExact requires ExpectedType exactly.
	TypeExact
	// TypeJWTOrAbsent accepts either an absent typ or typ "JWT".
	TypeJWTOrAbsent
)

// ValidationPolicy configures signature verification and RFC 7519 claim validation.
type ValidationPolicy struct {
	// ExpectedIssuer is the exact issuer URL the token must contain. Exactly one
	// of ExpectedIssuer and IgnoreIssuer must be set.
	ExpectedIssuer string
	// IgnoreIssuer explicitly disables issuer validation.
	IgnoreIssuer bool
	// ExpectedAudiences lists acceptable audience values. Exactly one of
	// ExpectedAudiences and IgnoreAudiences must be set.
	ExpectedAudiences []string
	// IgnoreAudiences disables audience validation.
	IgnoreAudiences bool
	// AllowedAlgorithms is the caller allowlist of JWS algorithms.
	// Provider verification also requires this to be set explicitly by the
	// token-profile validator.
	AllowedAlgorithms []Algorithm
	// Type explicitly controls typ handling. TypePolicyUnspecified is invalid;
	// callers must choose the intended token type semantics.
	Type TypePolicy
	// ExpectedType is required when Type is TypeExact.
	ExpectedType string
	// ClockSkew is the leeway applied to exp, nbf, and iat validation.
	ClockSkew time.Duration
	// AllowMissingExpiration permits tokens without an exp claim.
	// By default, expiration is required.
	AllowMissingExpiration bool
	// RequireIssuedAt requires the iat claim.
	RequireIssuedAt bool
}

func (p ValidationPolicy) validate() error {
	if len(p.AllowedAlgorithms) == 0 {
		return fmt.Errorf("%w: AllowedAlgorithms must not be empty", ErrPolicy)
	}
	if (p.ExpectedIssuer != "") == p.IgnoreIssuer {
		return policyChoiceError("ExpectedIssuer", "IgnoreIssuer")
	}
	if (len(p.ExpectedAudiences) > 0) == p.IgnoreAudiences {
		return policyChoiceError("ExpectedAudiences", "IgnoreAudiences")
	}
	if slices.Contains(p.ExpectedAudiences, "") {
		return fmt.Errorf("%w: ExpectedAudiences must not contain an empty value", ErrPolicy)
	}
	switch p.Type {
	case TypeAny, TypeAbsent, TypeJWTOrAbsent:
		if p.ExpectedType != "" {
			return fmt.Errorf("%w: ExpectedType is only valid with TypeExact", ErrPolicy)
		}
	case TypeExact:
		if p.ExpectedType == "" {
			return fmt.Errorf("%w: ExpectedType is required with TypeExact", ErrPolicy)
		}
	default:
		return fmt.Errorf("%w: invalid Type", ErrPolicy)
	}
	if p.ClockSkew < 0 || p.ClockSkew > MaxClockSkew {
		return fmt.Errorf("%w: ClockSkew must be between 0 and %s", ErrPolicy, MaxClockSkew)
	}
	return nil
}

func policyChoiceError(expected, ignore string) error {
	return fmt.Errorf("%w: exactly one of %s and %s must be set", ErrPolicy, expected, ignore)
}
