package clitoken

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"sync"
)

var (
	// platformCache is registered by any platform specific caches, and should be
	// preferred
	platformSigners []func() (crypto.Signer, error)
	// genericCaches is a list in preference order of non-platform specific caches
	genericSigners = []func() (crypto.Signer, error){
		func() (crypto.Signer, error) {
			return &localSigner{}, nil
		},
	}
)

// BestPlatformSigner returns the most preferred available signer for the
// platform and environment, to be used for signing DPoP proofs in CLI tools.
func BestPlatformSigner() (crypto.Signer, error) {
	for _, s := range append(platformSigners, genericSigners...) {
		signer, err := s()
		if err != nil {
			continue
		}
		return signer, nil
	}

	return &localSigner{}, nil
}

var (
	localSignerKey  crypto.Signer
	localSignerOnce sync.Once
)

// localSigner is a fallback signer, that exists for the process lifetime only.
type localSigner struct{}

func (*localSigner) Public() crypto.PublicKey {
	localSignerOnce.Do(func() {
		var err error
		localSignerKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
	})
	return localSignerKey.Public()
}

func (*localSigner) Sign(randrdr io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	localSignerOnce.Do(func() {
		var err error
		localSignerKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
	})
	return localSignerKey.Sign(randrdr, digest, opts)
}
