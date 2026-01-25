//go:build darwin && cgo

package platformsecrets

import (
	"crypto"
	"errors"
	"io"
	"runtime"

	"lds.li/oauth2ext/internal/keychain"
)

const sepSignerLabel = "oauth2ext-cli-sep"

func init() {
	platformSigners = append(platformSigners, newDarwinSEPSigner)
}

type darwinSEPSigner struct {
	identity *keychain.CTKIdentity
	signer   crypto.Signer
}

var _ crypto.Signer = &darwinSEPSigner{}

func newDarwinSEPSigner() (crypto.Signer, error) {
	identity, err := keychain.GetCTKIdentity(sepSignerLabel, nil)
	if err != nil {
		var kcErr *keychain.Error
		if !errors.As(err, &kcErr) || kcErr.Code != keychain.KeychainErrorCodeItemNotFound {
			return nil, err
		}

		// Identity doesn't exist, create it
		_, err = keychain.CreateCTKIdentity(sepSignerLabel, keychain.CTKKeyTypeP256)
		if err != nil {
			return nil, err
		}

		// Get the identity with signing capability
		identity, err = keychain.GetCTKIdentity(sepSignerLabel, nil)
		if err != nil {
			return nil, err
		}
	}

	// Get the signer from the identity
	signer, err := identity.Signer()
	if err != nil {
		identity.Close()
		return nil, err
	}

	dss := &darwinSEPSigner{
		identity: identity,
		signer:   signer,
	}

	runtime.AddCleanup(dss, func(identity *keychain.CTKIdentity) {
		identity.Close()
	}, identity)

	return dss, nil
}

func (d *darwinSEPSigner) Public() crypto.PublicKey {
	return d.signer.Public()
}

func (d *darwinSEPSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return d.signer.Sign(rand, digest, opts)
}
