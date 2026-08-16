package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
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
