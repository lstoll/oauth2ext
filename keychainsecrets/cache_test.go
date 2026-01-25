//go:build darwin

package keychainsecrets

import (
	"os"
	"testing"

	"lds.li/oauth2ext/internal/platformsecrets"
)

const (
	issuer1         = "https://issuer1.test"
	issuer1ClientID = "clientID"
)

func TestKeychainCredentialCache(t *testing.T) {
	if os.Getenv("TEST_KEYCHAIN") == "" {
		t.Skip("TEST_KEYCHAIN not set")
		return
	}

	cache := &KeychainCredentialCache{}

	if !cache.Available() {
		t.Fatal("cache is not available")
	}

	platformsecrets.TestCache(t, cache)
}

func TestKeychainCredentialCacheExisting(t *testing.T) {
	// This test requires access to macOS Keychain. It assumes a test is already
	// run _by the same test executable_, and just reads the existing value
	if os.Getenv("TEST_KEYCHAIN_CREDENTIAL_CACHE") == "" || os.Getenv("TEST_KEYCHAIN_CREDENTIAL_CACHE_EXISTING") == "" {
		t.Skip("TEST_KEYCHAIN_CREDENTIAL_CACHE and TEST_KEYCHAIN_CREDENTIAL_CACHE_EXISTING not set")
		return
	}

	cache := &KeychainCredentialCache{}

	if !cache.Available() {
		t.Fatal("cache is not available")
	}

	if tok, err := cache.Get(issuer1, issuer1ClientID); err != nil || tok == nil {
		t.Fatalf("failed to get existing value, got tok: %v err: %v", t, err)
	}
}
