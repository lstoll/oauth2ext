package jwt

import (
	"fmt"

	jose "github.com/go-jose/go-jose/v4"
)

// Algorithm identifies a JWS signing algorithm.
type Algorithm string

const (
	RS256 Algorithm = "RS256"
	RS384 Algorithm = "RS384"
	RS512 Algorithm = "RS512"
	PS256 Algorithm = "PS256"
	PS384 Algorithm = "PS384"
	PS512 Algorithm = "PS512"
	ES256 Algorithm = "ES256"
	ES384 Algorithm = "ES384"
	ES512 Algorithm = "ES512"
	EdDSA Algorithm = "EdDSA"
)

func (a Algorithm) jose() (jose.SignatureAlgorithm, error) {
	switch a {
	case RS256:
		return jose.RS256, nil
	case RS384:
		return jose.RS384, nil
	case RS512:
		return jose.RS512, nil
	case PS256:
		return jose.PS256, nil
	case PS384:
		return jose.PS384, nil
	case PS512:
		return jose.PS512, nil
	case ES256:
		return jose.ES256, nil
	case ES384:
		return jose.ES384, nil
	case ES512:
		return jose.ES512, nil
	case EdDSA:
		return jose.EdDSA, nil
	default:
		return "", fmt.Errorf("%w: unsupported AllowedAlgorithms value %q", ErrPolicy, a)
	}
}

func toJoseAlgorithms(algs []Algorithm) ([]jose.SignatureAlgorithm, error) {
	if len(algs) == 0 {
		return nil, fmt.Errorf("%w: no allowed algorithms", ErrPolicy)
	}
	out := make([]jose.SignatureAlgorithm, len(algs))
	for i, alg := range algs {
		j, err := alg.jose()
		if err != nil {
			return nil, err
		}
		out[i] = j
	}
	return out, nil
}
