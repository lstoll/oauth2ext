//go:build darwin

package keychainsecrets

import (
	"crypto"
	"errors"
	"io"
	"runtime"

	"lds.li/keychain"
)

const sepSignerLabel = "oauth2ext-cli-sep"

type darwinSEPSigner struct {
	identity keychain.Identity
	signer   crypto.Signer
}

var _ crypto.Signer = &darwinSEPSigner{}

func NewSEPSigner() (crypto.Signer, error) {
	identity, err := keychain.GetCTKIdentity(sepSignerLabel, nil)
	if err != nil {
		var kcErr *keychain.ErrSecOSStatus
		if !errors.As(err, &kcErr) || kcErr.Code() != keychain.ErrSecOSStatusCodeItemNotFound {
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

	runtime.AddCleanup(dss, func(identity keychain.Identity) {
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
