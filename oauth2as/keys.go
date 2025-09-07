package oauth2as

import (
	"context"

	"github.com/lstoll/oauth2ext/jwt"
	"github.com/lstoll/oauth2ext/oauth2as/discovery"
)

type AlgorithmSigner interface {
	// KeySet is used to determine the set of keys to serve on the discovery
	// endpoint.
	discovery.Keyset
	// VerificationKeyset is used to verify issued tokens, e.g in the Userinfo
	// endpoint.
	jwt.PublicKeyset
	// SignWithAlgorithm should sign the payload with the given algorithm and
	// type header, and return the compact representation of the signed token.
	SignWithAlgorithm(ctx context.Context, alg, typHdr string, payload []byte) (string, error)
	// SupportedAlgorithms returns the list of algorithms supported by this
	// signer.
	SupportedAlgorithms() []string
}
