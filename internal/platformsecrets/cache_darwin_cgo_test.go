//go:build darwin && cgo

package platformsecrets

import (
	"os"
	"testing"
)

func TestKeychainCredentialCache(t *testing.T) {
	// This test requires access to macOS Keychain
	if os.Getenv("TEST_KEYCHAIN_CREDENTIAL_CACHE") == "" || os.Getenv("TEST_KEYCHAIN_CREDENTIAL_CACHE_EXISTING") != "" {
		t.Skip("TEST_KEYCHAIN_CREDENTIAL_CACHE not set, or TEST_KEYCHAIN_CREDENTIAL_CACHE_EXISTING is set")
		return
	}

	cache := &KeychainCredentialCache{}

	if !cache.Available() {
		t.Fatal("cache is not available")
	}

	TestCache(t, cache)
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
