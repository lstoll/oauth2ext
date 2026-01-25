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
// As a migration path a default cache that uses either the keychain API
// (darwin, cgo) or the /usr/bin/security command (darwin, !cgo) will be
// returned. This will be removed in a future version.
//
// Caches can be registered for platforms with the following imports: * macOS,
// using Keychain: `import _ "lds.li/oauth2ext/keychainsecrets/auto` *
// Windows/Linux, using TPM: `import _ "lds.li/oauth2ext/tpmsecrets/auto`
func BestCredentialCache() tokencache.CredentialCache {
	return platformsecrets.BestCredentialCache()
}

// BestSigner returns the most preferred available signer for the platform and
// environment, to be used for signing DPoP proofs in CLI tools. If no signers
// are registered, a simple in-memory signer is returned.
//
// As a migration path a default signer that uses the SEP will be returned
// if the binary is compiled with cgo on darwin. This will be removed in a
// future version.
//
// Signers can be registered for platforms with the following imports:
// * macOS, using Keychain: `import _ "lds.li/oauth2ext/keychainsecrets/auto`
// * Windows/Linux, using TPM: `import _ "lds.li/oauth2ext/tpmsecrets/auto`
func BestSigner() (crypto.Signer, error) {
	return platformsecrets.BestPlatformSigner()
}
