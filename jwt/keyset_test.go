package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
)

func TestKeySetJSONRoundTrip(t *testing.T) {
	signer := newTestSigner(t)
	data, err := json.Marshal(signer.keySet)
	if err != nil {
		t.Fatal(err)
	}
	var ks KeySet
	if err := json.Unmarshal(data, &ks); err != nil {
		t.Fatal(err)
	}
	if len(ks.jwks.Keys) != 1 {
		t.Fatalf("keys: got %d want 1", len(ks.jwks.Keys))
	}
}

func TestParseJWKSetRejectsSmallRSAKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       &key.PublicKey,
		Algorithm: string(RS256),
		Use:       "sig",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ParseJWKSet(data)
	if !errors.Is(err, ErrKey) {
		t.Fatalf("error: got %v, want ErrKey", err)
	}
}

func TestParseJWKSetClassifiesMalformedDocument(t *testing.T) {
	_, err := ParseJWKSet([]byte(`{"keys":`))
	if !errors.Is(err, ErrKey) {
		t.Fatalf("error: got %v, want ErrKey", err)
	}
}

func TestParseJWKSetRejectsDuplicateMembers(t *testing.T) {
	signer := newTestSigner(t)
	var document map[string]json.RawMessage
	if err := json.Unmarshal(signer.signer.JWKS(), &document); err != nil {
		t.Fatal(err)
	}
	keys := document["keys"]
	data := fmt.Appendf(nil, `{"keys":%s,"keys":%s}`, keys, keys)
	_, err := ParseJWKSet(data)
	if !errors.Is(err, ErrKey) {
		t.Fatalf("error: got %v, want ErrKey", err)
	}
}

func TestParseJWKSetEnforcesKeyOperations(t *testing.T) {
	signer := newTestSigner(t)
	var document map[string]any
	if err := json.Unmarshal(signer.signer.JWKS(), &document); err != nil {
		t.Fatal(err)
	}
	key := document["keys"].([]any)[0].(map[string]any)

	for _, tt := range []struct {
		name       string
		operations any
		wantError  bool
	}{
		{name: "verify", operations: []string{"verify"}},
		{name: "sign and verify", operations: []string{"sign", "verify"}},
		{name: "encrypt only", operations: []string{"encrypt"}, wantError: true},
		{name: "wrong type", operations: "verify", wantError: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			key["key_ops"] = tt.operations
			data, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			_, err = ParseJWKSet(data)
			if tt.wantError && !errors.Is(err, ErrKey) {
				t.Fatalf("error: got %v, want ErrKey", err)
			}
			if !tt.wantError && err != nil {
				t.Fatal(err)
			}
		})
	}
}
