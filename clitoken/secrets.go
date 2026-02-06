package clitoken

import (
	"crypto"

	"lds.li/oauth2ext/internal/platformsecrets"
	"lds.li/oauth2ext/tokencache"
)

// BestCredentialCache returns the most preferred available credential client
// for the platform and environment. If no caches are registered, a simple
// in-memory cache is returned.
//
// Caches can be registered for platforms with the following imports:
// * macOS, using Keychain: `import _ "lds.li/oauth2ext/keychainsecrets/auto`
// * Windows/Linux, using TPM: `import _ "lds.li/oauth2ext/tpmsecrets/auto`
func BestCredentialCache() tokencache.CredentialCache {
	pc := platformsecrets.BestCredentialCache()
	if pc != nil {
		return pc
	}
	return &MemCredentialCache{}
}

// BestSigner returns the most preferred available signer for the platform and
// environment, to be used for signing DPoP proofs in CLI tools. If no signers
// are registered, a simple in-memory signer is returned.
//
// Signers can be registered for platforms with the following imports:
// * macOS, using Keychain: `import _ "lds.li/oauth2ext/keychainsecrets/auto`
// * Windows/Linux, using TPM: `import _ "lds.li/oauth2ext/tpmsecrets/auto`
func BestSigner() crypto.Signer {
	ps := platformsecrets.BestPlatformSigner()
	if ps != nil {
		return ps
	}
	return &MemSigner{}
}
