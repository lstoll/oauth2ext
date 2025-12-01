package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"sync"
	"testing"

	"github.com/tink-crypto/tink-go/v2/jwt"
	"github.com/tink-crypto/tink-go/v2/keyset"
)

type TestSigner struct {
	handles   map[string]*keyset.Handle
	handlesMu sync.Mutex
}

func NewTestSigner(t testing.TB, algs ...string) *TestSigner {
	if len(algs) == 0 {
		algs = []string{"ES256"}
	}
	ts := &TestSigner{
		handles: make(map[string]*keyset.Handle, len(algs)),
	}
	for _, alg := range algs {
		switch alg {
		case "ES256":
			handle, err := keyset.NewHandle(jwt.ES256Template())
			if err != nil {
				t.Fatal(err)
			}
			ts.handles[alg] = handle
		case "RS256":
			handle, err := keyset.NewHandle(jwt.RS256_2048_F4_Key_Template())
			if err != nil {
				t.Fatal(err)
			}
			ts.handles[alg] = handle
		default:
			t.Fatalf("unsupported algorithm: %s", alg)
		}
	}

	return ts
}

func (t *TestSigner) SignerForAlgorithm(ctx context.Context, alg string) (jwt.Signer, error) {
	t.handlesMu.Lock()
	defer t.handlesMu.Unlock()

	handle, ok := t.handles[alg]
	if !ok {
		return nil, fmt.Errorf("key not found for algorithm: %s", alg)
	}
	signer, err := jwt.NewSigner(handle)
	if err != nil {
		return nil, err
	}

	return signer, nil
}

func (t *TestSigner) SupportedAlgorithms() []string {
	res := make([]string, 0, len(t.handles))
	for k := range maps.Keys(t.handles) {
		res = append(res, k)
	}
	return res
}

// JWKS returns the JSON Web Key Set for this signer.
func (t *TestSigner) JWKS(context.Context) ([]byte, error) {
	t.handlesMu.Lock()
	defer t.handlesMu.Unlock()

	var docs [][]byte
	for _, v := range t.handles {
		pubh, err := v.Public()
		if err != nil {
			return nil, err
		}
		jwks, err := jwt.JWKSetFromPublicKeysetHandle(pubh)
		if err != nil {
			return nil, err
		}
		docs = append(docs, jwks)
	}

	return mergeJWKS(docs...)
}

func mergeJWKS(jwksDocs ...[]byte) ([]byte, error) {
	var allKeys []any

	for _, doc := range jwksDocs {
		var jwks map[string]any
		if err := json.Unmarshal(doc, &jwks); err != nil {
			return nil, err
		}

		// Extract and merge the "keys" array
		if keysVal, ok := jwks["keys"]; ok {
			if keys, ok := keysVal.([]any); ok {
				allKeys = append(allKeys, keys...)
			}
		}
	}

	merged := map[string]any{
		"keys": allKeys,
	}

	return json.Marshal(merged)
}
