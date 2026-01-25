//go:build darwin && !cgo

package platformsecrets

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"golang.org/x/oauth2"
	"lds.li/oauth2ext/oidc"
	"lds.li/oauth2ext/tokencache"
)

func init() {
	platformCaches = append(platformCaches, &KeychainCLICredentialCache{})
}

// KeychainCLICredentialCache uses /usr/bin/security to store items. This is
// flexible and doesn't require CGO, however any other process can read the
// items via the command
type KeychainCLICredentialCache struct{}

var _ tokencache.CredentialCache = &KeychainCLICredentialCache{}

func (k *KeychainCLICredentialCache) Get(issuer, key string) (*oauth2.Token, error) {
	cmd := exec.Command(
		"/usr/bin/security",
		"find-generic-password",
		"-s", issuer,
		"-a", key,
		"-w",
	)

	out, err := cmd.CombinedOutput()
	if err != nil {
		if bytes.Contains(out, []byte("could not be found")) {
			return nil, nil
		}

		return nil, fmt.Errorf("%s: %w", string(out), err)
	}

	var token oidc.TokenWithID
	if err := json.Unmarshal(out, &token); err != nil {
		return nil, fmt.Errorf("failed to decode token: %w", err)
	}

	return token.Token, nil
}

func (k *KeychainCLICredentialCache) Set(issuer, key string, token *oauth2.Token) error {
	b, err := json.Marshal(oidc.TokenWithID{Token: token})
	if err != nil {
		return fmt.Errorf("failed to encode token: %w", err)
	}

	cmd := exec.Command(
		"/usr/bin/security",
		"add-generic-password",
		"-s", issuer,
		"-a", key,
		"-w", string(b),
		"-U",
	)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w", string(out), err)
	}

	return nil
}

func (k *KeychainCLICredentialCache) Available() bool {
	if runtime.GOOS != "darwin" {
		return false
	}

	_, err := os.Stat("/usr/bin/security")

	return err == nil
}
