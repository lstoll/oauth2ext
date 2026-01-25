package platformsecrets

import (
	"fmt"
	"sync"

	"golang.org/x/oauth2"
	"lds.li/oauth2ext/tokencache"
)

// MemCredentialCache is a simple in-memory credential cache.
type MemCredentialCache struct {
	m   map[string]*oauth2.Token
	mMu sync.RWMutex
}

var _ tokencache.CredentialCache = &MemCredentialCache{}

func (c *MemCredentialCache) Get(issuer, key string) (*oauth2.Token, error) {
	c.mMu.RLock()
	defer c.mMu.RUnlock()

	cacheKey := c.cacheKey(issuer, key)

	if token := c.m[cacheKey]; token != nil {
		return token, nil
	}

	return nil, nil
}

func (c *MemCredentialCache) Set(issuer, key string, token *oauth2.Token) error {
	c.mMu.Lock()
	defer c.mMu.Unlock()

	cacheKey := c.cacheKey(issuer, key)
	if c.m == nil {
		c.m = make(map[string]*oauth2.Token)
	}
	c.m[cacheKey] = token

	return nil
}

func (c *MemCredentialCache) Available() bool {
	return true
}

func (c *MemCredentialCache) cacheKey(issuer, key string) string {
	return fmt.Sprintf(
		"%s;%s",
		issuer,
		key,
	)
}
