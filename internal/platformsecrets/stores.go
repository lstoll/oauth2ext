package platformsecrets

import (
	"crypto"

	"lds.li/oauth2ext/tokencache"
)

var (
	platformCaches  = []tokencache.CredentialCache{&MemCredentialCache{}}
	platformSigners = []func() (crypto.Signer, error){}
)

// RegisterCredentialCache registers a credential cache. This is intended to be
// called by platform specific packages (e.g. tpmsecrets) in their init
// functions.
func RegisterCredentialCache(c tokencache.CredentialCache) {
	platformCaches = append([]tokencache.CredentialCache{c}, platformCaches...)
}

// BestCredentialCache returns the most preferred available credential client
// for the platform and environment.
func BestCredentialCache() tokencache.CredentialCache {
	for _, c := range platformCaches {
		if c.Available() {
			return c
		}
	}

	return &MemCredentialCache{}
}

// RegisterPlatformSigner registers a signer. This is intended to be called by
// platform specific packages (e.g. tpmsecrets) in their init functions.
func RegisterPlatformSigner(f func() (crypto.Signer, error)) {
	platformSigners = append([]func() (crypto.Signer, error){f}, platformSigners...)
}

// BestPlatformSigner returns the most preferred available signer for the
// platform and environment, to be used for signing DPoP proofs in CLI tools.
func BestPlatformSigner() (crypto.Signer, error) {
	for _, s := range platformSigners {
		signer, err := s()
		if err != nil {
			continue
		}
		return signer, nil
	}

	return &MemSigner{}, nil
}
