package clitoken

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"sync"

	"lds.li/oauth2ext/tokencache"
)

// MemCredentialCache is a simple in-memory credential store, that exists as a
// fallback for the process lifetime only. Its DPoP keys are software keys,
// whose handles contain the private key.
type MemCredentialCache struct {
	m   map[string]*tokencache.Credential
	mMu sync.RWMutex
}

var _ tokencache.Store = &MemCredentialCache{}

func (c *MemCredentialCache) Get(issuer, key string) (*tokencache.Credential, error) {
	c.mMu.RLock()
	defer c.mMu.RUnlock()

	if cred := c.m[c.cacheKey(issuer, key)]; cred != nil {
		return cred, nil
	}

	return nil, nil
}

func (c *MemCredentialCache) Set(issuer, key string, cred *tokencache.Credential) error {
	c.mMu.Lock()
	defer c.mMu.Unlock()

	if c.m == nil {
		c.m = make(map[string]*tokencache.Credential)
	}
	c.m[c.cacheKey(issuer, key)] = cred

	return nil
}

func (c *MemCredentialCache) Available() bool {
	return true
}

// NewDPoPKey creates a P-256 software key.
func (c *MemCredentialCache) NewDPoPKey() ([]byte, crypto.Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating key: %w", err)
	}
	handle, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshalling key: %w", err)
	}
	return handle, key, nil
}

func (c *MemCredentialCache) LoadDPoPKey(handle []byte) (crypto.Signer, error) {
	key, err := x509.ParsePKCS8PrivateKey(handle)
	if err != nil {
		return nil, fmt.Errorf("parsing key: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("key of type %T is not a signer", key)
	}
	return signer, nil
}

func (c *MemCredentialCache) cacheKey(issuer, key string) string {
	return fmt.Sprintf("%s;%s", issuer, key)
}
