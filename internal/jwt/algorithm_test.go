package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestInferAlgorithm(t *testing.T) {
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		key  crypto.PublicKey
		want string
	}{
		{name: "P-256", key: p256.Public(), want: "ES256"},
		{name: "RSA", key: rsaKey.Public(), want: "RS256"},
		{name: "Ed25519", key: edPub, want: "EdDSA"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := InferAlgorithm(tt.key)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("algorithm: got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestInferAlgorithmRejectsSmallRSAKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := InferAlgorithm(key.Public()); err == nil {
		t.Fatal("expected error")
	}
}

func TestSignerSupportsAlgorithm(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if !SignerSupportsAlgorithm(rsaKey, "RS256") || !SignerSupportsAlgorithm(rsaKey, "PS256") {
		t.Fatal("RSA key should support RS256 and PS256")
	}
	if SignerSupportsAlgorithm(rsaKey, "ES256") {
		t.Fatal("RSA key should not support ES256")
	}
}

func mldsaParams() map[string]mldsa.Parameters {
	return map[string]mldsa.Parameters{
		"ML-DSA-44": mldsa.MLDSA44(),
		"ML-DSA-65": mldsa.MLDSA65(),
		"ML-DSA-87": mldsa.MLDSA87(),
	}
}

func TestInferAlgorithmMLDSA(t *testing.T) {
	for want, params := range mldsaParams() {
		t.Run(want, func(t *testing.T) {
			key, err := mldsa.GenerateKey(params)
			if err != nil {
				t.Fatal(err)
			}
			got, err := InferAlgorithm(key.PublicKey())
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Fatalf("algorithm: got %q, want %q", got, want)
			}
			if err := ValidatePublicKey(key.PublicKey()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPublicKeySupportsAlgorithmMLDSA(t *testing.T) {
	algs := []string{"ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "EdDSA", "ES256", "RS256"}
	for keyAlg, params := range mldsaParams() {
		key, err := mldsa.GenerateKey(params)
		if err != nil {
			t.Fatal(err)
		}
		for _, alg := range algs {
			if got, want := PublicKeySupportsAlgorithm(key.PublicKey(), alg), alg == keyAlg; got != want {
				t.Errorf("%s key supports %s: got %v, want %v", keyAlg, alg, got, want)
			}
		}
	}
}

func TestValidatePublicKeyRejectsInvalidMLDSA(t *testing.T) {
	if err := ValidatePublicKey((*mldsa.PublicKey)(nil)); err == nil {
		t.Fatal("nil ML-DSA key accepted")
	}
	if err := ValidatePublicKey(new(mldsa.PublicKey)); err == nil {
		t.Fatal("zero ML-DSA key accepted")
	}
	if _, err := InferAlgorithm(new(mldsa.PublicKey)); err == nil {
		t.Fatal("InferAlgorithm accepted zero ML-DSA key")
	}
	if PublicKeySupportsAlgorithm(new(mldsa.PublicKey), "ML-DSA-44") {
		t.Fatal("zero ML-DSA key supports ML-DSA-44")
	}
}
