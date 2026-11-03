package jwt

import (
	"crypto"
	"fmt"
	"slices"

	jose "github.com/go-jose/go-jose/v4"
	jwtint "lds.li/oauth2ext/internal/jwt"
)

// Algorithm identifies a JWS signing algorithm.
type Algorithm string

const (
	RS256   Algorithm = "RS256"
	RS384   Algorithm = "RS384"
	RS512   Algorithm = "RS512"
	PS256   Algorithm = "PS256"
	PS384   Algorithm = "PS384"
	PS512   Algorithm = "PS512"
	ES256   Algorithm = "ES256"
	ES384   Algorithm = "ES384"
	ES512   Algorithm = "ES512"
	EdDSA   Algorithm = "EdDSA"
	MLDSA44 Algorithm = "ML-DSA-44"
	MLDSA65 Algorithm = "ML-DSA-65"
	MLDSA87 Algorithm = "ML-DSA-87"
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
	case MLDSA44:
		return jose.MLDSA44, nil
	case MLDSA65:
		return jose.MLDSA65, nil
	case MLDSA87:
		return jose.MLDSA87, nil
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

// AlgorithmSigner is a crypto.Signer that reports which JWS algorithms it can
// produce. Implement it when a key can do less than its key type allows, such
// as a hardware RSA key restricted to PKCS#1 v1.5 (RS*) or to PSS (PS*).
// Signers that don't implement it are assumed to support every algorithm
// their key type allows.
type AlgorithmSigner interface {
	crypto.Signer
	SupportedAlgorithms() []Algorithm
}

// SignerSupportsAlgorithm reports whether signer can produce alg: the key
// type must allow it and, if signer is an AlgorithmSigner, it must be listed.
func SignerSupportsAlgorithm(signer crypto.Signer, alg Algorithm) bool {
	if !jwtint.SignerSupportsAlgorithm(signer, string(alg)) {
		return false
	}
	if as, ok := signer.(AlgorithmSigner); ok {
		return slices.Contains(as.SupportedAlgorithms(), alg)
	}
	return true
}

// inferSignerAlgorithm picks the key type's default algorithm, or for an
// AlgorithmSigner that doesn't support it, the first algorithm it lists that
// the key type allows.
func inferSignerAlgorithm(signer crypto.Signer) (Algorithm, error) {
	inferred, err := jwtint.InferAlgorithm(signer.Public())
	if err != nil {
		return "", err
	}
	as, ok := signer.(AlgorithmSigner)
	if !ok || SignerSupportsAlgorithm(signer, Algorithm(inferred)) {
		return Algorithm(inferred), nil
	}
	for _, alg := range as.SupportedAlgorithms() {
		if SignerSupportsAlgorithm(signer, alg) {
			return alg, nil
		}
	}
	return "", fmt.Errorf("signer supports none of its listed algorithms %v", as.SupportedAlgorithms())
}
