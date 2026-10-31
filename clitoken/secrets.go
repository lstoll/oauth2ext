package clitoken

import (
	"lds.li/oauth2ext/internal/platformsecrets"
	"lds.li/oauth2ext/tokencache"
)

// BestStore returns the most preferred available credential store for the
// platform and environment. It caches credentials and creates their DPoP keys.
// If no stores are registered, a simple in-memory store is returned.
//
// Stores can be registered for platforms with the following imports:
// * macOS, using Keychain and the Secure Enclave: `import _ "lds.li/oauth2ext/keychainsecrets/auto`
// * Windows/Linux, using TPM: `import _ "lds.li/oauth2ext/tpmsecrets/auto`
func BestStore() tokencache.Store {
	if s := platformsecrets.Best(); s != nil {
		return s
	}
	return &MemCredentialCache{}
}
