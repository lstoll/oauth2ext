package clitoken

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"github.com/lstoll/oauth2ext/oidc"
	"github.com/lstoll/oauth2ext/tokencache"
	"golang.org/x/oauth2"
)

var (
	// platformCache is registered by any platform specific caches, and should be
	// preferred
	platformCaches []tokencache.CredentialCache
	// genericCaches is a list in preference order of non-platform specific caches
	genericCaches = []tokencache.CredentialCache{&KeychainCLICredentialCache{}, &NullCredentialCache{}}
)

type PassphrasePromptFunc func(prompt string) (passphrase string, err error)

// BestCredentialCache returns the most preferred available credential client
// for the platform and environment.
func BestCredentialCache() tokencache.CredentialCache {
	for _, c := range append(platformCaches, genericCaches...) {
		if c.Available() {
			return c
		}
	}

	return &NullCredentialCache{}
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

// MemoryWriteThroughCredentialCache is a write-through cache for another
// underlying CredentialCache. If a credential has been previously requested
// from the underlying store, it is read from memory the next time it is
// requested.
//
// MemoryWriteThroughCredentialCache is useful when the underlying store
// requires user input (e.g., a passphrase) or is otherwise expensive.
type MemoryWriteThroughCredentialCache struct {
	tokencache.CredentialCache

	m map[string]*oauth2.Token
}

var _ tokencache.CredentialCache = &MemoryWriteThroughCredentialCache{}

func (c *MemoryWriteThroughCredentialCache) Get(issuer, key string) (*oauth2.Token, error) {
	cacheKey := c.cacheKey(issuer, key)

	if token := c.m[cacheKey]; token != nil {
		return token, nil
	}

	token, err := c.CredentialCache.Get(issuer, key)
	if err != nil {
		return nil, err
	}

	if c.m == nil {
		c.m = make(map[string]*oauth2.Token)
	}
	c.m[cacheKey] = token

	return token, nil
}

func (c *MemoryWriteThroughCredentialCache) Set(issuer, key string, token *oauth2.Token) error {
	err := c.CredentialCache.Set(issuer, key, token)
	if err != nil {
		return err
	}

	cacheKey := c.cacheKey(issuer, key)

	if c.m == nil {
		c.m = make(map[string]*oauth2.Token)
	}
	c.m[cacheKey] = token

	return nil
}

func (c *MemoryWriteThroughCredentialCache) Available() bool {
	return true
}

func (c *MemoryWriteThroughCredentialCache) cacheKey(issuer, key string) string {
	return fmt.Sprintf(
		"%s;%s",
		issuer,
		key,
	)
}

// NullCredentialCache will not cache tokens. Used it to opt out of caching.
type NullCredentialCache struct{}

var _ tokencache.CredentialCache = &NullCredentialCache{}

func (c *NullCredentialCache) Get(issuer, key string) (*oauth2.Token, error) {
	return nil, nil
}

func (c *NullCredentialCache) Set(issuer, key string, token *oauth2.Token) error {
	return nil
}

func (c *NullCredentialCache) Available() bool {
	return true
}
