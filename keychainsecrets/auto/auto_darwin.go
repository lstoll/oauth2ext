//go:build darwin

package auto

import (
	"crypto"

	"lds.li/oauth2ext/internal/platformsecrets"
	"lds.li/oauth2ext/keychainsecrets"
)

const sepSignerLabel = "oauth2ext-cli-sep"

func init() {
	platformsecrets.RegisterPlatformSigner(func() (crypto.Signer, error) {
		return keychainsecrets.NewSEPSigner(sepSignerLabel)
	})
	platformsecrets.RegisterCredentialCache(&keychainsecrets.KeychainCredentialCache{})
}
