package oauth2as

import (
	"context"

	"lds.li/oauth2ext/jwt"
)

type AlgorithmSigner interface {
	// PublicKeyset is used to verify issued tokens, i.e in the Userinfo
	// endpoint.
	jwt.PublicKeyset
	// SignWithAlgorithm should sign the payload with the given algorithm and
	// type header, and return the compact representation of the signed token.
	SignWithAlgorithm(ctx context.Context, alg, typHdr string, payload []byte) (string, error)
	// SupportedAlgorithms returns the list of JWT algorithms supported by this
	// signer.
	SupportedAlgorithms() []string
}
