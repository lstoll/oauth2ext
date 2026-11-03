package clitoken

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"sync"

	"lds.li/oauth2ext/jwt"
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

// NewDPoPKey creates a software key for the first of algs this store supports:
// any of the ECDSA, EdDSA, RSA (2048-bit, for PS* and RS*) or ML-DSA
// algorithms. The handle is the PKCS8 encoding of the private key.
func (c *MemCredentialCache) NewDPoPKey(algs []jwt.Algorithm) ([]byte, crypto.Signer, error) {
	for _, alg := range algs {
		var (
			key crypto.Signer
			err error
		)
		switch alg {
		case jwt.MLDSA44:
			key, err = mldsa.GenerateKey(mldsa.MLDSA44())
		case jwt.MLDSA65:
			key, err = mldsa.GenerateKey(mldsa.MLDSA65())
		case jwt.MLDSA87:
			key, err = mldsa.GenerateKey(mldsa.MLDSA87())
		case jwt.ES256:
			key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		case jwt.ES384:
			key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		case jwt.ES512:
			key, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		case jwt.EdDSA:
			_, key, err = ed25519.GenerateKey(rand.Reader)
		case jwt.PS256, jwt.PS384, jwt.PS512, jwt.RS256, jwt.RS384, jwt.RS512:
			key, err = rsa.GenerateKey(rand.Reader, 2048)
		default:
			continue
		}
		if err != nil {
			return nil, nil, fmt.Errorf("generating %s key: %w", alg, err)
		}
		handle, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, nil, fmt.Errorf("marshalling key: %w", err)
		}
		return handle, key, nil
	}
	return nil, nil, fmt.Errorf("no supported DPoP algorithm among %v", algs)
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
