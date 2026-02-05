package clitoken

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"sync"
)

// MemSigner is a simple fallback signer, that exists for the process lifetime
// only.
type MemSigner struct {
	key     crypto.Signer
	keyOnce sync.Once
}

func (m *MemSigner) Public() crypto.PublicKey {
	m.initKey()
	return m.key.Public()
}

func (m *MemSigner) Sign(randrdr io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	m.initKey()
	return m.key.Sign(randrdr, digest, opts)
}

func (m *MemSigner) initKey() {
	m.keyOnce.Do(func() {
		var err error
		m.key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
	})
}
