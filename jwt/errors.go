package jwt

import (
	"errors"
	"fmt"

	jose "github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
)

var (
	// ErrPolicy indicates the validation policy is incomplete or contradictory.
	ErrPolicy = errors.New("jwt: invalid validation policy")
	// ErrClaim indicates a verified claim is missing or has an unexpected type.
	ErrClaim = errors.New("jwt: invalid claim")
	// ErrKey indicates a locally supplied JSON Web Key Set is invalid.
	ErrKey = errors.New("jwt: invalid verification key")
	// ErrSizeLimit indicates locally supplied data exceeded a configured size limit.
	ErrSizeLimit = errors.New("jwt: size limit exceeded")
)

// VerificationErrorCode classifies why an untrusted token failed verification.
type VerificationErrorCode uint8

const (
	// VerificationErrorCodeUnknown is the zero value and is not returned by verification.
	VerificationErrorCodeUnknown VerificationErrorCode = iota
	// VerificationErrorCodeInvalidToken indicates malformed or unsupported token data.
	VerificationErrorCodeInvalidToken
	// VerificationErrorCodeSignature indicates signature verification failed.
	VerificationErrorCodeSignature
	// VerificationErrorCodeInvalidAlgorithm indicates the token used a disallowed algorithm.
	VerificationErrorCodeInvalidAlgorithm
	// VerificationErrorCodeKey indicates no suitable verification key was found.
	VerificationErrorCodeKey
	// VerificationErrorCodeType indicates the typ header did not match policy.
	VerificationErrorCodeType
	// VerificationErrorCodeIssuer indicates the issuer did not match policy.
	VerificationErrorCodeIssuer
	// VerificationErrorCodeAudience indicates the audience did not match policy.
	VerificationErrorCodeAudience
	// VerificationErrorCodeExpired indicates the token has expired.
	VerificationErrorCodeExpired
	// VerificationErrorCodeNotYetValid indicates the token cannot be used yet.
	VerificationErrorCodeNotYetValid
	// VerificationErrorCodeClaim indicates another registered claim failure.
	VerificationErrorCodeClaim
)

// VerificationError reports a token verification failure. The Error message is
// intentionally generic, exposing only if the token is expired or that
// verification failed. For more information, use [errors.AsType].
type VerificationError struct {
	code    VerificationErrorCode
	details string
}

// Error returns a generic message safe to expose to an untrusted caller.
func (e *VerificationError) Error() string {
	if e.code == VerificationErrorCodeExpired {
		return "jwt: token is expired"
	}
	return "jwt: verification failed"
}

// Code returns the verification failure classification.
func (e *VerificationError) Code() VerificationErrorCode {
	if e == nil {
		return VerificationErrorCodeUnknown
	}
	return e.code
}

// Details returns diagnostic information that may contain token or policy
// values. It must not be exposed to an untrusted caller.
func (e *VerificationError) Details() string {
	if e == nil {
		return ""
	}
	return e.details
}

func verificationErrorf(code VerificationErrorCode, format string, args ...any) error {
	return &VerificationError{code: code, details: fmt.Sprintf(format, args...)}
}

func mapParseError(err error) error {
	if err == nil {
		return nil
	}
	if algorithmErr, ok := errors.AsType[*jose.ErrUnexpectedSignatureAlgorithm](err); ok {
		return verificationErrorf(VerificationErrorCodeInvalidAlgorithm, "token uses algorithm %q", algorithmErr.Got)
	}
	return verificationErrorf(VerificationErrorCodeInvalidToken, "parsing compact JWT: %v", err)
}

func mapClaimsError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, jose.ErrCryptoFailure) {
		return verificationErrorf(VerificationErrorCodeSignature, "verifying signature: %v", err)
	}
	return verificationErrorf(VerificationErrorCodeInvalidToken, "decoding verified claims: %v", err)
}

func mapValidateError(err error, claims josejwt.Claims, policy ValidationPolicy) error {
	switch {
	case errors.Is(err, josejwt.ErrExpired):
		return verificationErrorf(VerificationErrorCodeExpired, "token is expired")
	case errors.Is(err, josejwt.ErrNotValidYet):
		return verificationErrorf(VerificationErrorCodeNotYetValid, "token is not yet valid")
	case errors.Is(err, josejwt.ErrInvalidIssuer):
		return verificationErrorf(VerificationErrorCodeIssuer, "issuer mismatch: got %q, want %q", claims.Issuer, policy.ExpectedIssuer)
	case errors.Is(err, josejwt.ErrInvalidAudience):
		return verificationErrorf(VerificationErrorCodeAudience, "audience mismatch: got %v, want one of %v", []string(claims.Audience), policy.ExpectedAudiences)
	case errors.Is(err, josejwt.ErrIssuedInTheFuture):
		return verificationErrorf(VerificationErrorCodeClaim, "iat is in the future")
	default:
		return verificationErrorf(VerificationErrorCodeClaim, "validating registered claims: %v", err)
	}
}
