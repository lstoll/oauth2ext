package oauth2as

import (
	"context"

	"github.com/tink-crypto/tink-go/v2/jwt"
)

type AlgorithmSigner interface {
	// JWKS returns the JSON Web Key Set for this signer.
	JWKS(ctx context.Context) ([]byte, error)
	// SignWithAlgorithm should sign the payload with the given algorithm and
	// type header, and return the compact representation of the signed token.
	SignerForAlgorithm(ctx context.Context, alg string) (jwt.Signer, error)
	// SupportedAlgorithms returns the list of JWT algorithms supported by this
	// signer.
	SupportedAlgorithms() []string
}
