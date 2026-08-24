package jwttest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
)

// Signer signs JWT payloads for tests using go-jose.
type Signer struct {
	key    *ecdsa.PrivateKey
	kid    string
	signer jose.Signer
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
	if !testing.Testing() {
		panic("jwttest: NewSigner used in a non-test binary")
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("generating key: %v", err))
	}

	var randVal [4]byte
	if _, err := rand.Read(randVal[:]); err != nil {
		panic(fmt.Sprintf("reading random value: %v", err))
	}
	kid := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(randVal[:])

	options := (&jose.SignerOptions{}).WithHeader("kid", kid)
	if typ != "" {
		options.WithType(jose.ContentType(typ))
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, options)
	if err != nil {
		panic(fmt.Sprintf("creating signer: %v", err))
	}

	return &Signer{key: key, kid: kid, signer: signer}
}

// Sign signs a JSON payload and returns a compact JWT.
func (s *Signer) Sign(payload []byte) (string, error) {
	obj, err := s.signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("signing: %w", err)
	}
	return obj.CompactSerialize()
}

// SignClaims marshals claims with json.Marshal and signs the result.
func (s *Signer) SignClaims(claims any) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshaling claims: %w", err)
	}
	return s.Sign(payload)
}

// JWKS returns the public JWKS bytes for this signer.
func (s *Signer) JWKS() []byte {
	jwk := jose.JSONWebKey{
		Key:       s.key.Public(),
		KeyID:     s.kid,
		Algorithm: string(jose.ES256),
		Use:       "sig",
	}
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}
	b, err := json.Marshal(set)
	if err != nil {
		panic(fmt.Sprintf("marshaling jwks: %v", err))
	}
	return b
}
