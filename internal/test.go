package internal

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

type TestSigner struct {
	key *ecdsa.PrivateKey
	kid string
}

func NewTestSigner(t testing.TB) *TestSigner {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var randVal [4]byte
	if _, err := rand.Read(randVal[:]); err != nil {
		t.Fatal(err)
	}

	return &TestSigner{key: key, kid: base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(randVal[:])}
}

func (t *TestSigner) Sign(claims any, typ string) (string, error) {
	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	extraHeaders := map[jose.HeaderKey]any{
		"kid": t.kid,
	}
	if typ != "" {
		extraHeaders["typ"] = typ
	}

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       t.key,
	}, &jose.SignerOptions{
		ExtraHeaders: extraHeaders,
	})
	if err != nil {
		return "", err
	}

	sig, err := signer.Sign(claimsBytes)
	if err != nil {
		return "", err
	}

	return sig.CompactSerialize()
}

func (t *TestSigner) JWKS() []byte {
	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				KeyID:     t.kid,
				Key:       &t.key.PublicKey,
				Algorithm: string(jose.ES256),
			},
		},
	}
	jwksb, err := json.Marshal(jwks)
	if err != nil {
		panic(fmt.Sprintf("Failed to marshal JWKS: %v", err))
	}
	return jwksb
}
