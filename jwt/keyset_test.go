package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
)

func TestKeySetJSONRoundTrip(t *testing.T) {
	signer := newTestSigner(t)
	data, err := json.Marshal(signer.keySet)
	if err != nil {
		t.Fatal(err)
	}
	var ks VerificationKeySet
	if err := json.Unmarshal(data, &ks); err != nil {
		t.Fatal(err)
	}
	if len(ks.state.Load().jwks.Keys) != 1 {
		t.Fatalf("keys: got %d want 1", len(ks.state.Load().jwks.Keys))
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
	_, err = ParseVerificationJWKS(data)
	if !errors.Is(err, ErrKey) {
		t.Fatalf("error: got %v, want ErrKey", err)
	}
}

func TestParseJWKSetClassifiesMalformedDocument(t *testing.T) {
	_, err := ParseVerificationJWKS([]byte(`{"keys":`))
	if !errors.Is(err, ErrKey) {
		t.Fatalf("error: got %v, want ErrKey", err)
	}
}

func TestParseJWKSetFiltersIneligibleAndUnknownKeys(t *testing.T) {
	signer := newTestSigner(t)
	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(signer.jwks, &doc); err != nil {
		t.Fatal(err)
	}
	data := fmt.Appendf(nil, `{"keys":[%s,{"kty":"RSA","use":"enc","n":"bad","e":"bad"},{"kty":"FUTURE","x":"ignored"},{"kty":"EC","crv":"P-999","alg":"ES256","x":"bad","y":"bad"},{"kty":"RSA","alg":"future-alg","n":"bad","e":"bad"}]}`, doc.Keys[0])
	keys, err := ParseVerificationJWKS(data)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(keys.state.Load().jwks.Keys); got != 1 {
		t.Fatalf("keys: got %d, want 1", got)
	}
	private := fmt.Appendf(nil, `{"keys":[{"kty":"FUTURE","d":"secret"}]}`)
	if _, err := ParseVerificationJWKS(private); !errors.Is(err, ErrKey) {
		t.Fatalf("private unknown key error = %v, want ErrKey", err)
	}
	for _, malformed := range []string{`{"keys":[null]}`, `{"keys":[{}]}`, `{"keys":[{"kty":"RSA","n":"bad","e":"bad"}]}`} {
		if _, err := ParseVerificationJWKS([]byte(malformed)); !errors.Is(err, ErrKey) {
			t.Errorf("ParseVerificationJWKS(%s) error = %v, want ErrKey", malformed, err)
		}
	}
}

func TestParseJWKSetRejectsDuplicateMembers(t *testing.T) {
	signer := newTestSigner(t)
	var document map[string]json.RawMessage
	if err := json.Unmarshal(signer.jwks, &document); err != nil {
		t.Fatal(err)
	}
	keys := document["keys"]
	data := fmt.Appendf(nil, `{"keys":%s,"keys":%s}`, keys, keys)
	_, err := ParseVerificationJWKS(data)
	if !errors.Is(err, ErrKey) {
		t.Fatalf("error: got %v, want ErrKey", err)
	}
}

func TestParseJWKSetEnforcesKeyOperations(t *testing.T) {
	signer := newTestSigner(t)
	var document map[string]any
	if err := json.Unmarshal(signer.jwks, &document); err != nil {
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
		{name: "encrypt only", operations: []string{"encrypt"}},
		{name: "wrong type", operations: "verify", wantError: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			key["key_ops"] = tt.operations
			data, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			_, err = ParseVerificationJWKS(data)
			if tt.wantError && !errors.Is(err, ErrKey) {
				t.Fatalf("error: got %v, want ErrKey", err)
			}
			if !tt.wantError && err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNewVerificationKeySet(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ks, err := NewVerificationKeySet(VerificationKey{Key: key.Public(), Algorithm: ES256, KeyID: "key-1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ks.JWKS(); err != nil {
		t.Fatal(err)
	}
}

func TestEmptyVerificationKeySetIsValid(t *testing.T) {
	ks, err := NewVerificationKeySet()
	if err != nil {
		t.Fatal(err)
	}
	data, err := ks.JWKS()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseVerificationJWKS([]byte(`{"keys":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := ks.Replace(parsed); err != nil {
		t.Fatal(err)
	}
	if got := len(ks.state.Load().jwks.Keys); got != 0 {
		t.Fatalf("keys: got %d, want 0", got)
	}
	if string(data) == "" {
		t.Fatal("empty key set did not marshal")
	}
	for _, malformed := range []string{`{}`, `{"keys":null}`} {
		if _, err := ParseVerificationJWKS([]byte(malformed)); !errors.Is(err, ErrKey) {
			t.Fatalf("ParseVerificationJWKS(%s) error = %v, want ErrKey", malformed, err)
		}
	}
}

func TestNewVerificationKeyDefaults(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	got, err := NewVerificationKey(key.Public(), "", "")
	if err != nil {
		t.Fatal(err)
	}
	if got.Algorithm != ES256 || got.KeyID == "" {
		t.Fatalf("key defaults = (%q, %q)", got.Algorithm, got.KeyID)
	}
}

//nolint:staticcheck // Deliberately mutate deprecated ECDSA coordinates to test deep-copy isolation.
func TestVerificationKeySetClonesPublicKeyInputs(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	originalX := new(big.Int).Set(key.X)
	verificationKey, err := NewVerificationKey(&key.PublicKey, "", "")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := NewVerificationKeySet(verificationKey)
	if err != nil {
		t.Fatal(err)
	}
	key.X.SetInt64(1)
	verificationKey.Key.(*ecdsa.PublicKey).X.SetInt64(2) //nolint:staticcheck // Test deep-copy isolation.
	stored := keys.state.Load().jwks.Keys[0].Key.(*ecdsa.PublicKey)
	if stored.X.Cmp(originalX) != 0 {
		t.Fatal("mutating constructor inputs changed stored verification key")
	}
}

func TestNewVerificationKeyRejectsUnsupportedAlgorithm(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewVerificationKey(key.Public(), "unsupported", "kid"); err == nil {
		t.Fatal("unsupported algorithm accepted")
	}
}

func TestNewVerificationKeySetRejectsDuplicates(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewVerificationKeySet(
		VerificationKey{Key: key.Public(), Algorithm: ES256, KeyID: "one"},
		VerificationKey{Key: key.Public(), Algorithm: ES256, KeyID: "two"},
	)
	if !errors.Is(err, ErrKey) {
		t.Fatalf("error: got %v, want ErrKey", err)
	}
}

func TestParseVerificationJWKSToleratesRemoteQuirks(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := jose.JSONWebKey{Key: key.Public(), KeyID: "k1", Algorithm: "ES256", Use: "sig"}
	dup := pub
	mismatched := jose.JSONWebKey{Key: key.Public(), KeyID: "k2", Algorithm: "ES384", Use: "sig"}
	body, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pub, dup, mismatched}})
	if err != nil {
		t.Fatal(err)
	}
	set, err := ParseVerificationJWKS(body)
	if err != nil {
		t.Fatalf("duplicate and alg-mismatched remote keys should be tolerated: %v", err)
	}
	keys, err := set.matchingKeys("ES256", "k1")
	if err != nil || len(keys) == 0 {
		t.Fatalf("matchingKeys: %v, %d keys", err, len(keys))
	}
	if keys, err := set.matchingKeys("ES384", "k2"); err == nil && len(keys) != 0 {
		t.Fatal("alg-mismatched key should have been ignored")
	}
}

// mldsaJWKMap returns the public AKP JWK for an ML-DSA key as a generic map.
func mldsaJWKMap(t *testing.T, params mldsa.Parameters, alg Algorithm) map[string]any {
	t.Helper()
	identity, err := NewSigningIdentity(newMLDSAKey(t, params), alg, "")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := NewVerificationKeySetFromSigner(identity)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(keys)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Keys) != 1 {
		t.Fatalf("keys: %d", len(doc.Keys))
	}
	return doc.Keys[0]
}

func jwksDoc(t *testing.T, keys ...map[string]any) []byte {
	t.Helper()
	data, err := json.Marshal(map[string]any{"keys": keys})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestParseJWKSetRejectsAKPPrivateMaterial(t *testing.T) {
	jwk := mldsaJWKMap(t, mldsa.MLDSA44(), MLDSA44)
	jwk["priv"] = "AAAA"
	if _, err := ParseVerificationJWKS(jwksDoc(t, jwk)); !errors.Is(err, ErrKey) || !strings.Contains(err.Error(), "private") {
		t.Fatalf("error: got %v, want ErrKey about private material", err)
	}
}

func TestParseJWKSetAKPRequiresAlg(t *testing.T) {
	jwk := mldsaJWKMap(t, mldsa.MLDSA44(), MLDSA44)
	delete(jwk, "alg")
	if _, err := ParseVerificationJWKS(jwksDoc(t, jwk)); !errors.Is(err, ErrKey) {
		t.Fatalf("error: got %v, want ErrKey", err)
	}
}

func TestParseJWKSetSkipsAKPWithNonMLDSAAlg(t *testing.T) {
	skipped := mldsaJWKMap(t, mldsa.MLDSA44(), MLDSA44)
	skipped["alg"] = "SLH-DSA-SHA2-128s"
	good := mldsaJWKMap(t, mldsa.MLDSA65(), MLDSA65)
	keys, err := ParseVerificationJWKS(jwksDoc(t, skipped, good))
	if err != nil {
		t.Fatal(err)
	}
	got := keys.state.Load().jwks.Keys
	if len(got) != 1 || got[0].Algorithm != string(MLDSA65) {
		t.Fatalf("keys: got %+v, want only the ML-DSA-65 key", got)
	}
}

func TestClonePublicKeyMLDSA(t *testing.T) {
	pub := newMLDSAKey(t, mldsa.MLDSA44()).PublicKey()
	got, ok := clonePublicKey(pub).(*mldsa.PublicKey)
	if !ok || got == nil || got == pub || !got.Equal(pub) {
		t.Fatalf("clone: got %p, original %p", got, pub)
	}
	if got, ok := clonePublicKey(new(mldsa.PublicKey)).(*mldsa.PublicKey); !ok || got != nil {
		t.Fatalf("zero key clone: %v", got)
	}
}
