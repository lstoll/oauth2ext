package internal

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base32"
	"fmt"
	"testing"

	"github.com/go-jose/go-jose/v4"
	josejson "github.com/go-jose/go-jose/v4/json"
	"github.com/lstoll/oauth2ext/jwt"
)

type testSignerKey struct {
	kid  string
	alg  string
	priv crypto.PrivateKey
	pub  crypto.PublicKey
}

type TestSigner struct {
	algs []string
	keys []testSignerKey
}

func NewTestSigner(t testing.TB, algs ...string) *TestSigner {
	genKID := func() string {
		var randVal [4]byte
		if _, err := rand.Read(randVal[:]); err != nil {
			t.Fatal(err)
		}
		return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(randVal[:])
	}

	ts := &TestSigner{
		algs: algs,
	}

	for _, alg := range algs {
		switch alg {
		case "ES256":
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			ts.keys = append(ts.keys, testSignerKey{kid: genKID(), alg: alg, priv: key, pub: key.Public()})
		case "RS256":
			key, err := rsa.GenerateKey(rand.Reader, 1024) // do not use 1024 outside of tests!
			if err != nil {
				t.Fatal(err)
			}
			ts.keys = append(ts.keys, testSignerKey{kid: genKID(), alg: alg, priv: key, pub: key.Public()})
		default:
			t.Fatalf("unsupported algorithm: %s", alg)
		}
	}

	return ts
}

func (t *TestSigner) SignWithAlgorithm(ctx context.Context, alg, typHdr string, payload []byte) (string, error) {
	var key *testSignerKey
	for _, k := range t.keys {
		if k.alg == alg {
			key = &k
			break
		}
	}
	if key == nil {
		return "", fmt.Errorf("key not found for algorithm: %s", alg)
	}

	extraHeaders := map[jose.HeaderKey]any{
		"kid": key.kid,
	}
	if typHdr != "" {
		extraHeaders["typ"] = typHdr
	}

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.SignatureAlgorithm(key.alg),
		Key:       key.priv,
	}, &jose.SignerOptions{
		ExtraHeaders: extraHeaders,
	})
	if err != nil {
		return "", err
	}

	sig, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}

	return sig.CompactSerialize()
}

func (t *TestSigner) SignClaimsWithAlgorithm(alg, typHdr string, claims any) (string, error) {
	cb, err := josejson.Marshal(claims)
	if err != nil {
		return "", err
	}

	return t.SignWithAlgorithm(context.Background(), alg, typHdr, cb)
}

func (t *TestSigner) SupportedAlgorithms() []string {
	return t.algs
}
func (t *TestSigner) GetKeysByKID(ctx context.Context, kid string) ([]jwt.PublicKey, error) {
	var res []jwt.PublicKey
	for _, k := range t.keys {
		if k.kid == kid {
			res = append(res, jwt.PublicKey{KeyID: k.kid, Alg: jwt.SigningAlg(k.alg), Key: k.pub})
		}
	}
	return res, nil
}
func (t *TestSigner) GetKeys(ctx context.Context) ([]jwt.PublicKey, error) {
	var res []jwt.PublicKey
	for _, k := range t.keys {
		res = append(res, jwt.PublicKey{KeyID: k.kid, Alg: jwt.SigningAlg(k.alg), Key: k.pub})
	}
	return res, nil
}
