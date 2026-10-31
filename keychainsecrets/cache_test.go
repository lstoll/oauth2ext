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
	testService     = "oauth2ext-keychainsecrets-test"
)

func TestKeychainCredentialCache(t *testing.T) {
	if os.Getenv("TEST_KEYCHAIN") == "" {
		t.Skip("TEST_KEYCHAIN not set")
		return
	}

	// Entries are left in place for TestKeychainCredentialCacheExisting and
	// TestKeychainCredentialCacheOtherBinary, run later by CI.
	cache := &KeychainCredentialCache{Service: testService}

	if !cache.Available() {
		t.Fatal("cache is not available")
	}

	platformsecrets.TestCache(t, cache)
}

func TestKeychainCredentialCacheDPoPKeys(t *testing.T) {
	// Secure Enclave keys need hardware, which CI VMs lack.
	if os.Getenv("TEST_KEYCHAIN") == "" || os.Getenv("TEST_SECURE_ENCLAVE") == "" {
		t.Skip("TEST_KEYCHAIN and TEST_SECURE_ENCLAVE not set")
		return
	}

	cache := &KeychainCredentialCache{Service: testService + "-dpop"}
	t.Cleanup(func() { _ = cache.DeleteAll() })

	platformsecrets.TestStore(t, cache)
}

func TestKeychainCredentialCacheExisting(t *testing.T) {
	// This test requires access to macOS Keychain. It assumes a test is already
	// run _by the same test executable_, and just reads the existing value
	if os.Getenv("TEST_KEYCHAIN_CREDENTIAL_CACHE") == "" || os.Getenv("TEST_KEYCHAIN_CREDENTIAL_CACHE_EXISTING") == "" {
		t.Skip("TEST_KEYCHAIN_CREDENTIAL_CACHE and TEST_KEYCHAIN_CREDENTIAL_CACHE_EXISTING not set")
		return
	}

	cache := &KeychainCredentialCache{Service: testService}

	if !cache.Available() {
		t.Fatal("cache is not available")
	}

	if cred, err := cache.Get(issuer1, issuer1ClientID); err != nil || cred == nil {
		t.Fatalf("failed to get existing value, got cred: %v err: %v", cred, err)
	}
}

func TestKeychainCredentialCacheOtherBinary(t *testing.T) {
	// This test requires access to macOS Keychain. It assumes the entry was
	// written by a different build of this test executable, so the binary
	// identity doesn't match and the entry must be a miss.
	if os.Getenv("TEST_KEYCHAIN_CREDENTIAL_CACHE_OTHER_BINARY") == "" {
		t.Skip("TEST_KEYCHAIN_CREDENTIAL_CACHE_OTHER_BINARY not set")
		return
	}

	cache := &KeychainCredentialCache{Service: testService}
	t.Cleanup(func() { _ = cache.DeleteAll() })

	if cred, err := cache.Get(issuer1, issuer1ClientID); err != nil || cred != nil {
		t.Fatalf("entry from another binary was not a miss, got cred: %v err: %v", cred, err)
	}
}
