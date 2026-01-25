//go:build darwin

package auto

import (
	"crypto"

	"lds.li/oauth2ext/internal/platformsecrets"
	"lds.li/oauth2ext/keychainsecrets"
)

func init() {
	platformsecrets.RegisterPlatformSigner(func() (crypto.Signer, error) {
		return keychainsecrets.NewSEPSigner()
	})

	platformsecrets.RegisterCredentialCache(&keychainsecrets.KeychainCredentialCache{})
}
