package internal

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"log"
	"testing"

	"github.com/tink-crypto/tink-go/v2/jwt"
	"github.com/tink-crypto/tink-go/v2/keyset"
)

type TestSigner struct {
	handle *keyset.Handle
	kid    string
}

func NewTestSigner(t testing.TB) *TestSigner {
	h, err := keyset.NewHandle(jwt.ES256Template())
	if err != nil {
		t.Fatal(err)
	}

	var randVal [4]byte
	if _, err := rand.Read(randVal[:]); err != nil {
		t.Fatal(err)
	}

	return &TestSigner{handle: h, kid: base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(randVal[:])}
}

func (t *TestSigner) Sign(raw *jwt.RawJWT) (string, error) {
	signer, err := jwt.NewSigner(t.handle)
	if err != nil {
		return "", fmt.Errorf("creating signer: %w", err)
	}

	return signer.SignAndEncode(raw)
}

func (t *TestSigner) JWKS() []byte {
	pubh, err := t.handle.Public()
	if err != nil {
		panic(fmt.Sprintf("creating public handle: %v", err))
	}
	publicJWKset, err := jwt.JWKSetFromPublicKeysetHandle(pubh)
	if err != nil {
		log.Fatal(err)
	}

	return publicJWKset
}
