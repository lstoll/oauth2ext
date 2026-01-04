package internal

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"log"

	"github.com/tink-crypto/tink-go/v2/jwt"
	"github.com/tink-crypto/tink-go/v2/keyset"
)

type TestSigner struct {
	handle *keyset.Handle
	kid    string
}

func NewTestSigner() *TestSigner {
	h, err := keyset.NewHandle(jwt.ES256Template())
	if err != nil {
		panic(fmt.Sprintf("creating handle: %v", err))
	}

	var randVal [4]byte
	if _, err := rand.Read(randVal[:]); err != nil {
		panic(fmt.Sprintf("reading random value: %v", err))
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
