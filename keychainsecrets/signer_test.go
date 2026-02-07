//go:build darwin

package keychainsecrets

import (
	"crypto/ecdsa"
	"os"
	"testing"
)

const testSignerLabel = "oauth2ext-test-signer"

func TestSigner(t *testing.T) {
	if os.Getenv("TEST_KEYCHAIN") == "" {
		t.Skip("TEST_KEYCHAIN not set")
		return
	}

	signer, err := NewSEPSigner(testSignerLabel)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}
	if signer == nil {
		t.Fatal("signer is nil")
	}
	pub1 := signer.Public()
	pub1ecdsa, ok := pub1.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("public key is not an ECDSA public key")
	}

	signer2, err := NewSEPSigner(testSignerLabel)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}
	pub2 := signer2.Public()
	pub2ecdsa, ok := pub2.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("public key is not an ECDSA public key")
	}

	if !pub1ecdsa.Equal(pub2ecdsa) {
		t.Fatal("public keys are not equal")
	}
}
