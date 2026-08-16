package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestSignerRoundTrip(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewSigningIdentity(key, "", "key-1")
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
	verified, err := verifyJWT(t, keys, compact, ValidationPolicy{IgnoreIssuer: true, IgnoreAudiences: true, AllowedAlgorithms: []Algorithm{ES256}, Type: TypeExact, ExpectedType: "at+jwt", AllowMissingExpiration: true})
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
	signer, err := NewSigningIdentity(key, ES256, "key-1")
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

func TestVerificationKeySnapshotCannotMutateSigningIdentity(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := NewSigningIdentity(key, ES256, "key-1")
	if err != nil {
		t.Fatal(err)
	}
	snapshot := identity.VerificationKey()
	snapshot.Key.(*ecdsa.PublicKey).X.SetInt64(1) //nolint:staticcheck // Exercise legacy mutable-coordinate isolation.
	keys, err := NewVerificationKeySetFromSigner(identity)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := identity.Sign(t.Context(), map[string]any{"sub": "alice"}, SignOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyJWT(t, keys, compact, ValidationPolicy{IgnoreIssuer: true, IgnoreAudiences: true, AllowedAlgorithms: []Algorithm{ES256}, Type: TypeAny, AllowMissingExpiration: true}); err != nil {
		t.Fatalf("mutating returned public-key snapshot changed signer: %v", err)
	}
}

func TestSignerRejectsIncompatibleAlgorithm(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = NewSigningIdentity(key, RS256, ""); err == nil || !strings.Contains(err.Error(), "incompatible") {
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
	aIdentity, err := NewSigningIdentity(a, ES256, "a")
	if err != nil {
		t.Fatal(err)
	}
	bIdentity, err := NewSigningIdentity(b, RS256, "b")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewSigningKeySet(aIdentity, bIdentity)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := signer.Sign(t.Context(), map[string]any{"sub": "alice"}, SignOptions{Algorithm: ES256})
	if err != nil {
		t.Fatal(err)
	}
	if decodeProtectedHeader(t, compact)["alg"] != "ES256" {
		t.Fatal("did not honor exact algorithm")
	}
	nextIdentity, err := NewSigningIdentity(a, ES256, "next")
	if err != nil {
		t.Fatal(err)
	}
	next, err := NewSigningKeySet(nextIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if err := signer.Replace(next); err != nil {
		t.Fatal(err)
	}
	if got := signer.verificationKeys()[0].KeyID; got != "next" {
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
	ecIdentity, err := NewSigningIdentity(ec, "", "")
	if err != nil {
		t.Fatal(err)
	}
	rsaIdentity, err := NewSigningIdentity(rsaKey, "", "")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewSigningKeySet(ecIdentity, rsaIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if !signer.SupportsAlgorithm(ES256) || !signer.SupportsAlgorithm(RS256) {
		t.Fatal("signing key set lost an active algorithm")
	}
}

func TestSigningKeySetRejectsDuplicateActiveAlgorithms(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := NewSigningIdentity(key, ES256, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewSigningKeySet(identity, identity); err == nil {
		t.Fatal("expected duplicate active algorithm to be rejected")
	}
}

func TestSigningKeySetRejectsDuplicateKeyMaterialAcrossAlgorithms(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsIdentity, err := NewSigningIdentity(key, RS256, "rs")
	if err != nil {
		t.Fatal(err)
	}
	psIdentity, err := NewSigningIdentity(key, PS256, "ps")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewSigningKeySet(rsIdentity, psIdentity); err == nil {
		t.Fatal("expected duplicate public key thumbprint to be rejected")
	}
}

func TestSigningKeySetRejectsDuplicateKeyIDs(t *testing.T) {
	keyA, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyB, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	identityA, err := NewSigningIdentity(keyA, RS256, "shared")
	if err != nil {
		t.Fatal(err)
	}
	identityB, err := NewSigningIdentity(keyB, PS256, "shared")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewSigningKeySet(identityA, identityB); err == nil {
		t.Fatal("expected duplicate key ID to be rejected")
	}
}

func TestSignerThumbprintIsNotKeyID(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewSigningIdentity(key, ES256, "application-key")
	if err != nil {
		t.Fatal(err)
	}
	if thumbprint := signer.Thumbprint(); thumbprint == signer.KeyID() {
		t.Fatal("custom key ID must not be treated as an RFC 7638 thumbprint")
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
