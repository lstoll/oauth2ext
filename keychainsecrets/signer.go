//go:build darwin

package keychainsecrets

import (
	"crypto"
	"errors"
	"io"

	"lds.li/keychain"
)

const sepSignerLabel = "oauth2ext-cli-sep"

type darwinSEPSigner struct {
	identity *keychain.Identity
	signer   crypto.Signer
}

var _ crypto.Signer = &darwinSEPSigner{}

func NewSEPSigner() (crypto.Signer, error) {
	identity, err := keychain.GetIdentity(keychain.IdentityQuery{
		Label: sepSignerLabel,
		Type:  keychain.IdentityQueryTypeCTK,
	})
	if err != nil {
		var kcErr *keychain.Error
		if !errors.As(err, &kcErr) || kcErr.Code() != keychain.ErrorCodeItemNotFound {
			return nil, err
		}

		// Identity doesn't exist, create it
		_, err = keychain.CreateCTKIdentity(sepSignerLabel, keychain.CTKKeyTypeP256)
		if err != nil {
			return nil, err
		}

		// Get the identity with signing capability
		identity, err = keychain.GetIdentity(keychain.IdentityQuery{
			Label: sepSignerLabel,
			Type:  keychain.IdentityQueryTypeCTK,
		})
		if err != nil {
			return nil, err
		}
	}

	// Get the signer from the identity
	signer, err := identity.Signer()
	if err != nil {
		return nil, err
	}

	dss := &darwinSEPSigner{
		identity: identity,
		signer:   signer,
	}

	return dss, nil
}

func (d *darwinSEPSigner) Public() crypto.PublicKey {
	return d.signer.Public()
}

func (d *darwinSEPSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return d.signer.Sign(rand, digest, opts)
}
