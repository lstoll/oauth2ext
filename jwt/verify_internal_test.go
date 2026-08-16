package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	jwtint "lds.li/oauth2ext/internal/jwt"
)

type testSigner struct {
	local  *Signer
	key    *ecdsa.PrivateKey
	keySet *VerificationKeySet
	typ    string
	jwks   []byte
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
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	local, err := NewSigner(key, ES256, "")
	if err != nil {
		t.Fatal(err)
	}
	jwk, _, err := jwtint.PublicJWK(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	jwk.KeyID = local.PublicKeys()[0].KeyID
	jwk.Algorithm = string(ES256)
	jwk.Use = "sig"
	jwks, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
	if err != nil {
		t.Fatal(err)
	}
	ks, err := ParseVerificationKeySet(jwks)
	if err != nil {
		t.Fatal(err)
	}
	return &testSigner{local: local, key: key, keySet: ks, typ: typ, jwks: jwks}
}

func (s *testSigner) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	compact, err := s.local.Sign(t.Context(), claims, SignOptions{Type: s.typ})
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func (s *testSigner) signRaw(t *testing.T, payload []byte) string {
	t.Helper()
	joseOpts := new(jose.SignerOptions)
	if s.typ != "" {
		joseOpts.WithType(jose.ContentType(s.typ))
	}
	joseOpts.WithHeader("kid", s.local.PublicKeys()[0].KeyID)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: s.key}, joseOpts)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := signed.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return compact
}
