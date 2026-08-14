package jwt

import (
	"errors"
	"testing"

	"lds.li/oauth2ext/jwttest"
)

type testSigner struct {
	signer *jwttest.Signer
	keySet *KeySet
}

func requireVerificationError(t *testing.T, err error, code VerificationErrorCode) {
	t.Helper()
	verificationErr, ok := errors.AsType[*VerificationError](err)
	if !ok {
		t.Fatalf("error: got %T %v, want *VerificationError", err, err)
	}
	if verificationErr.Code() != code {
		t.Fatalf("code: got %v, want %v; details: %s", verificationErr.Code(), code, verificationErr.Details())
	}
	wantPublicError := "jwt: verification failed"
	if code == VerificationErrorCodeExpired {
		wantPublicError = "jwt: token is expired"
	}
	if got := err.Error(); got != wantPublicError {
		t.Fatalf("public error: got %q, want %q", got, wantPublicError)
	}
	if verificationErr.Details() == "" {
		t.Fatal("verification error has no diagnostic details")
	}
}

func newTestSigner(t *testing.T) *testSigner {
	return newTestSignerWithType(t, "")
}

func newTestSignerWithType(t *testing.T, typ string) *testSigner {
	t.Helper()
	s := jwttest.NewSignerWithType(t, typ)
	ks, err := ParseJWKSet(s.JWKS())
	if err != nil {
		t.Fatal(err)
	}
	return &testSigner{signer: s, keySet: ks}
}

func (s *testSigner) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	compact, err := s.signer.SignClaims(claims)
	if err != nil {
		t.Fatal(err)
	}
	return compact
}
