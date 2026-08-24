package jwt

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestVerificationErrorHidesDetails(t *testing.T) {
	err := verificationErrorf(
		VerificationErrorCodeIssuer,
		"issuer mismatch: got %q, want %q",
		"attacker.example",
		"issuer.example",
	)
	if got := err.Error(); got != "jwt: verification failed" {
		t.Fatalf("Error: got %q, want generic message", got)
	}
	wrapped := fmt.Errorf("verifying bearer token: %w", err)
	if strings.Contains(wrapped.Error(), "attacker.example") || strings.Contains(wrapped.Error(), "issuer.example") {
		t.Fatalf("wrapped error leaked details: %q", wrapped)
	}
	verificationErr, ok := errors.AsType[*VerificationError](wrapped)
	if !ok {
		t.Fatalf("wrapped error does not contain *VerificationError: %v", wrapped)
	}
	if verificationErr.Code() != VerificationErrorCodeIssuer {
		t.Fatalf("Code: got %v, want %v", verificationErr.Code(), VerificationErrorCodeIssuer)
	}
	if got := verificationErr.Details(); !strings.Contains(got, "attacker.example") || !strings.Contains(got, "issuer.example") {
		t.Fatalf("Details: got %q", got)
	}
}

func TestNilVerificationErrorAccessors(t *testing.T) {
	var err *VerificationError
	if err.Code() != VerificationErrorCodeUnknown {
		t.Fatalf("Code: got %v, want unknown", err.Code())
	}
	if err.Details() != "" {
		t.Fatalf("Details: got %q, want empty", err.Details())
	}
}
