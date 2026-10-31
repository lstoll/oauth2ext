//go:build darwin

package auto

import (
	"lds.li/oauth2ext/internal/platformsecrets"
	"lds.li/oauth2ext/keychainsecrets"
)

func init() {
	platformsecrets.Register(&keychainsecrets.KeychainCredentialCache{})
}
