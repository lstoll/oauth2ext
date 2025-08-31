package oauth2as

import (
	"context"

	"github.com/lstoll/oauth2ext/jwt"
)

type AlgorithmSigner interface {
	// PubliKeyset is used for verifying issued tokens, e.g in the Userinfo
	// endpoint.
	jwt.PublicKeyset
	// SignWithAlgorithm should sign the payload with the given algorithm and
	// type header, and return the compact representation of the signed token.
	SignWithAlgorithm(ctx context.Context, alg, typHdr string, payload []byte) (string, error)
	// SupportedAlgorithms returns the list of algorithms supported by this
	// signer.
	SupportedAlgorithms() []string
}
