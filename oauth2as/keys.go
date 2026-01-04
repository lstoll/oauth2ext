package oauth2as

import (
	"github.com/tink-crypto/tink-go/v2/jwt"
)

// AlgorithmSigner extends the tink [jwt.Signer] interface to allow for signing
// with a specific algorithm, when multiple algorithms are supported.
type AlgorithmSigner interface {
	jwt.Signer
	SignAndEncodeForAlgorithm(alg string, rawJWT *jwt.RawJWT) (string, error)
}
