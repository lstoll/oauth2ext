package jwttest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"testing"

	"lds.li/oauth2ext/jwt"
)

// Signer is an ES256 jwt.Signer for tests, plus a public JWKS.
type Signer struct {
	local *jwt.Signer
	key   *ecdsa.PrivateKey
	typ   string
}

// NewSigner creates an ES256 test signer without a typ header.
func NewSigner(t *testing.T) *Signer {
	return NewSignerWithType(t, "")
}

// NewSignerWithType creates an ES256 test signer with the given typ header. An
// empty value omits the header.
func NewSignerWithType(t *testing.T, typ string) *Signer {
	if t == nil {
		panic("jwttest: nil *testing.T")
	}
	t.Helper()
	if !testing.Testing() {
		panic("jwttest: NewSigner used in a non-test binary")
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	local, err := jwt.NewSigner(key, jwt.ES256, "")
	if err != nil {
		t.Fatal(err)
	}
	return &Signer{local: local, key: key, typ: typ}
}

// Sign signs a JSON object payload and returns a compact JWT.
func (s *Signer) Sign(payload []byte) (string, error) {
	return s.local.Sign(context.Background(), json.RawMessage(payload), jwt.SignOptions{Type: s.typ})
}

// SignClaims marshals claims with json.Marshal and signs the result.
func (s *Signer) SignClaims(claims any) (string, error) {
	return s.local.Sign(context.Background(), claims, jwt.SignOptions{Type: s.typ})
}

// JWKS returns the public JWKS bytes for this signer.
func (s *Signer) JWKS() []byte {
	set, err := jwt.NewVerificationKeySetFromSigner(s.local)
	if err != nil {
		panic(fmt.Sprintf("constructing jwks: %v", err))
	}
	b, err := set.JWKS(context.Background())
	if err != nil {
		panic(fmt.Sprintf("marshaling jwks: %v", err))
	}
	return b
}
