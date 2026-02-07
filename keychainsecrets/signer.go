//go:build darwin

package keychainsecrets

import (
	"crypto"
	"errors"
	"io"

	"lds.li/keychain"
)

type darwinSEPSigner struct {
	identity *keychain.Identity
	signer   crypto.Signer
}

var _ crypto.Signer = &darwinSEPSigner{}

type sepSignerOpts struct{}

type SepSignerOpt func(opts *sepSignerOpts)

// NewSEPSigner returns a secure-enclave backed signer for the given label. If
// one does not exist, a CTK identity will be created.
func NewSEPSigner(label string, opts ...SepSignerOpt) (crypto.Signer, error) {
	identity, err := keychain.GetIdentity(keychain.IdentityQuery{
		Label: label,
		Type:  keychain.IdentityQueryTypeCTK,
	})
	if err != nil {
		var kcErr *keychain.Error
		if !errors.As(err, &kcErr) || kcErr.Code() != keychain.ErrorCodeItemNotFound {
			return nil, err
		}

		// Identity doesn't exist, create it
		_, err = keychain.CreateCTKIdentity(label, keychain.CTKKeyTypeP256)
		if err != nil {
			return nil, err
		}

		// Get the identity with signing capability
		identity, err = keychain.GetIdentity(keychain.IdentityQuery{
			Label: label,
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
