package tokencache

import (
	"crypto"

	"golang.org/x/oauth2"
)

// Credential is a cached token, and the DPoP key it is bound to.
type Credential struct {
	Token *oauth2.Token
	// DPoPKey is the opaque handle for the key the token is bound to, as
	// returned by DPoPKeyStore.NewDPoPKey. It is nil for bearer tokens. Handles
	// are only meaningful to the store that created them.
	DPoPKey []byte
}

// CredentialCache is capable of caching and retrieving OpenID Connect tokens.
// At this time, CredentialCache implementations are not required to be
// goroutine safe. Code that uses a CredentialCache should synchronize access to
// the caches if goroutine safety is needed. This can also be used for regular
// oauth2 tokens, the issuer should be a unique URL representing the
// authorization server.
type CredentialCache interface {
	// Get returns a credential from cache for the given issuer, and unique key
	// for this token. The key should take in to account the unique properties
	// for this token, e.g client ID/scopes/ACRs. Cache misses are _not_
	// considered an error, so a cache miss will be returned as `(nil, nil)`
	Get(issuer, key string) (*Credential, error)
	// Set sets a credential in the cache for the given issuer and key,
	// replacing any existing entry.
	Set(issuer, key string, cred *Credential) error
	// Available returns true if the credential cache is supported on this
	// platform or environment.
	Available() bool
}

// DPoPKeyStore creates and loads per-credential DPoP keys. Keys are
// represented by opaque handles that are stored alongside the token they are
// bound to, so each login gets its own key and discarding a credential
// discards its key. Implementations should not need to clean up keys whose
// handles are dropped; hardware-backed stores achieve this by making the
// handle a device-bound wrapped key.
type DPoPKeyStore interface {
	// NewDPoPKey creates a new key, returning its handle and a signer for it.
	NewDPoPKey() (handle []byte, signer crypto.Signer, err error)
	// LoadDPoPKey returns a signer for a handle returned by NewDPoPKey.
	LoadDPoPKey(handle []byte) (crypto.Signer, error)
}

// Store is a credential cache that can also create the DPoP keys whose
// handles it holds. Platform backends implement Store, as their key handles
// are only usable with that platform.
type Store interface {
	CredentialCache
	DPoPKeyStore
}
