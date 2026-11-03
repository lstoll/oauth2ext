package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
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
	snapshot.Key.(*ecdsa.PublicKey).X.SetInt64(1) //nolint:staticcheck // Test deep-copy isolation.
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

type mldsaCase struct {
	alg    Algorithm
	params mldsa.Parameters
}

func mldsaCases() []mldsaCase {
	return []mldsaCase{
		{MLDSA44, mldsa.MLDSA44()},
		{MLDSA65, mldsa.MLDSA65()},
		{MLDSA87, mldsa.MLDSA87()},
	}
}

func newMLDSAKey(t testing.TB, params mldsa.Parameters) *mldsa.PrivateKey {
	t.Helper()
	key, err := mldsa.GenerateKey(params)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// TestMLDSARoundTripThroughJWKS checks our ML-DSA wiring: algorithm inference,
// key/algorithm binding, and publishing then parsing an AKP JWKS.
func TestMLDSARoundTripThroughJWKS(t *testing.T) {
	for _, tc := range mldsaCases() {
		t.Run(string(tc.alg), func(t *testing.T) {
			key := newMLDSAKey(t, tc.params)
			wrong := MLDSA65
			if tc.alg == MLDSA65 {
				wrong = MLDSA44
			}
			if _, err := NewSigningIdentity(key, wrong, ""); err == nil {
				t.Fatalf("%s key accepted with algorithm %s", tc.alg, wrong)
			}
			identity, err := NewSigningIdentity(key, "", "")
			if err != nil {
				t.Fatal(err)
			}
			if identity.Algorithm() != tc.alg {
				t.Fatalf("algorithm: got %q, want %q", identity.Algorithm(), tc.alg)
			}
			compact, err := identity.Sign(t.Context(), map[string]any{"sub": "alice"}, SignOptions{})
			if err != nil {
				t.Fatal(err)
			}
			keys, err := NewVerificationKeySetFromSigner(identity)
			if err != nil {
				t.Fatal(err)
			}
			jwks, err := json.Marshal(keys)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := ParseVerificationJWKS(jwks)
			if err != nil {
				t.Fatal(err)
			}
			policy := ValidationPolicy{IgnoreIssuer: true, IgnoreAudiences: true, AllowedAlgorithms: []Algorithm{tc.alg}, Type: TypeAny, AllowMissingExpiration: true}
			if _, err := verifyJWT(t, parsed, compact, policy); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type restrictedSigner struct {
	crypto.Signer
	algs []Algorithm
}

func (r restrictedSigner) SupportedAlgorithms() []Algorithm { return r.algs }

func TestSignerRespectsSupportedAlgorithms(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pkcs1Only := restrictedSigner{key, []Algorithm{RS256}}
	if _, err := NewSigningIdentity(pkcs1Only, PS256, ""); err == nil {
		t.Error("PS256 accepted for a signer that only supports RS256")
	}
	pssOnly := restrictedSigner{key, []Algorithm{PS256}}
	identity, err := NewSigningIdentity(pssOnly, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if identity.Algorithm() != PS256 {
		t.Errorf("inferred %s, want PS256 for a signer that only supports PS256", identity.Algorithm())
	}
}
