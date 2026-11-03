package tokencache

import (
	"crypto"
	"slices"

	"golang.org/x/oauth2"
	"lds.li/oauth2ext/jwt"
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
	// algs is never empty and is ordered most preferred first: the store
	// creates a key for the first algorithm it can, moving on when one is
	// unsupported or unavailable (e.g. hardware without ML-DSA), and returns
	// an error if it can create none of them.
	//
	// The signer is assumed to support every algorithm its key type allows
	// (an RSA key: both RS* and PS*). A signer that can do less, such as a
	// hardware RSA key limited to one padding, should implement
	// jwt.AlgorithmSigner, both here and from LoadDPoPKey.
	NewDPoPKey(algs []jwt.Algorithm) (handle []byte, signer crypto.Signer, err error)
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

// DefaultDPoPAlgorithms is used when the server's accepted DPoP algorithms are
// not known. ES256 is the most widely supported.
var DefaultDPoPAlgorithms = []jwt.Algorithm{jwt.ES256}

// DefaultDPoPPreference orders the DPoP algorithms used when
// Config.DPoPPreference is nil, most preferred first. ES256 comes first as the
// most widely deployed, then the other classical algorithms. ML-DSA (RFC 9964)
// is permitted by RFC 9449 as an asymmetric JWS algorithm but is not yet widely
// deployed for DPoP, and its proofs are much larger, so it is only used when the
// server accepts nothing else. This order may change as DPoP specifications and
// deployments evolve.
var DefaultDPoPPreference = []jwt.Algorithm{
	jwt.ES256, jwt.EdDSA, jwt.ES384, jwt.ES512,
	jwt.PS256, jwt.PS384, jwt.PS512,
	jwt.RS256, jwt.RS384, jwt.RS512,
	jwt.MLDSA65, jwt.MLDSA87, jwt.MLDSA44,
}

// orderDPoPAlgorithms returns the members of preference that are also in
// accepted, in preference order.
func orderDPoPAlgorithms(accepted, preference []jwt.Algorithm) []jwt.Algorithm {
	var out []jwt.Algorithm
	for _, alg := range preference {
		if slices.Contains(accepted, alg) && !slices.Contains(out, alg) {
			out = append(out, alg)
		}
	}
	return out
}
