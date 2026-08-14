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
	// ExpectedType requires an exact JOSE typ header match. When empty, the typ
	// header must be absent or explicitly empty.
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
	if p.ClockSkew < 0 || p.ClockSkew > MaxClockSkew {
		return fmt.Errorf("%w: ClockSkew must be between 0 and %s", ErrPolicy, MaxClockSkew)
	}
	return nil
}

func policyChoiceError(expected, ignore string) error {
	return fmt.Errorf("%w: exactly one of %s and %s must be set", ErrPolicy, expected, ignore)
}
