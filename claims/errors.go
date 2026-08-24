package claims

import "fmt"

// VerificationError reports an OpenID Connect ID-token profile validation
// failure. Error is intentionally generic. Details may contain token or policy
// values and must not be exposed to an untrusted caller.
type VerificationError struct {
	details string
}

// Error returns a generic message safe to expose to an untrusted caller.
func (e *VerificationError) Error() string {
	return "claims: ID token verification failed"
}

// Details returns diagnostic information for trusted logs and debugging.
func (e *VerificationError) Details() string {
	if e == nil {
		return ""
	}
	return e.details
}

func verificationErrorf(format string, args ...any) error {
	return &VerificationError{details: fmt.Sprintf(format, args...)}
}
