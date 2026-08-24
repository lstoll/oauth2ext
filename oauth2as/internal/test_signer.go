package internal

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"lds.li/oauth2ext/jwt"
	"lds.li/oauth2ext/oauth2as"
)

func NewTestSigner(t testing.TB, algorithms ...jwt.Algorithm) *oauth2as.LocalJWTSigner {
	t.Helper()
	if len(algorithms) == 0 {
		algorithms = []jwt.Algorithm{jwt.ES256}
	}
	keys := make([]oauth2as.SigningKey, 0, len(algorithms))
	for _, algorithm := range algorithms {
		switch algorithm {
		case jwt.ES256:
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			keys = append(keys, oauth2as.SigningKey{Algorithm: algorithm, Key: key})
		case jwt.RS256:
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal(err)
			}
			keys = append(keys, oauth2as.SigningKey{Algorithm: algorithm, Key: key})
		default:
			t.Fatalf("unsupported test algorithm %q", algorithm)
		}
	}
	signer, err := oauth2as.NewLocalJWTSigner(oauth2as.LocalJWTSignerConfig{SigningKeys: keys})
	if err != nil {
		t.Fatal(err)
	}
	return signer
}
