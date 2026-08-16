package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func TestSignerRoundTrip(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewSigner(key, "", "key-1")
	if err != nil {
		t.Fatal(err)
	}
	compact, err := signer.Sign(t.Context(), map[string]any{"sub": "alice"}, SignOptions{Type: "at+jwt"})
	if err != nil {
		t.Fatal(err)
	}
	header := decodeProtectedHeader(t, compact)
	if header["alg"] != "ES256" || header["typ"] != "at+jwt" || header["kid"] != "key-1" {
		t.Fatalf("unexpected header: %v", header)
	}
	keys, err := NewVerificationKeySetFromSigner(signer)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := keys.VerifyJWT(compact, ValidationPolicy{IgnoreIssuer: true, IgnoreAudiences: true, AllowedAlgorithms: []Algorithm{ES256}, ExpectedType: "at+jwt", AllowMissingExpiration: true})
	if err != nil {
		t.Fatal(err)
	}
	if subject, err := verified.Subject(); err != nil || subject != "alice" {
		t.Fatalf("subject: got %q, err %v", subject, err)
	}
}

func TestSignerHeaderOptions(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewSigner(key, ES256, "key-1")
	if err != nil {
		t.Fatal(err)
	}
	compact, err := signer.Sign(t.Context(), map[string]any{"sub": "alice"}, SignOptions{Type: "dpop+jwt", SkipKeyID: true, IncludeJWK: true})
	if err != nil {
		t.Fatal(err)
	}
	header := decodeProtectedHeader(t, compact)
	if _, ok := header["kid"]; ok {
		t.Fatalf("kid should be omitted: %v", header)
	}
	if jwk, ok := header["jwk"].(map[string]any); !ok || jwk["kty"] != "EC" {
		t.Fatalf("jwk header: %v", header["jwk"])
	}
}

func TestSignerRejectsIncompatibleAlgorithm(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = NewSigner(key, RS256, ""); err == nil || !strings.Contains(err.Error(), "incompatible") {
		t.Fatalf("error: got %v", err)
	}
}

func TestSignerMultipleKeysAndReplace(t *testing.T) {
	a, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewSignerFromKeys(SignerConfig{Keys: []SigningKey{{Signer: a, Algorithm: ES256, KeyID: "a"}, {Signer: b, Algorithm: RS256, KeyID: "b"}}, PreferredAlgorithms: []Algorithm{RS256, ES256}})
	if err != nil {
		t.Fatal(err)
	}
	compact, err := signer.Sign(t.Context(), map[string]any{"sub": "alice"}, SignOptions{Algorithms: []Algorithm{ES256}})
	if err != nil {
		t.Fatal(err)
	}
	if decodeProtectedHeader(t, compact)["alg"] != "ES256" {
		t.Fatal("did not honor exact algorithm")
	}
	next, err := NewSigner(a, ES256, "next")
	if err != nil {
		t.Fatal(err)
	}
	if err := signer.Replace(next); err != nil {
		t.Fatal(err)
	}
	if got := signer.PublicKeys()[0].KeyID; got != "next" {
		t.Fatalf("kid=%q", got)
	}
}

func TestSignerInfersAlgorithmForEachConfiguredKey(t *testing.T) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewSignerFromKeys(SignerConfig{Keys: []SigningKey{{Signer: ec}, {Signer: rsaKey}}})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := signer.Algorithms(), []Algorithm{ES256, RS256}; !slices.Equal(got, want) {
		t.Fatalf("algorithms=%v, want %v", got, want)
	}
}

func decodeProtectedHeader(t *testing.T, compact string) map[string]any {
	t.Helper()
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT should have 3 parts, got %d", len(parts))
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatal(err)
	}
	return header
}
