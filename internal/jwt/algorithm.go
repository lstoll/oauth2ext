package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"slices"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/cryptosigner"
)

// InferAlgorithm returns the default JWS algorithm for pub.
//
// go-jose's cryptosigner.Opaque.Algs lists every compatible algorithm (RSA
// yields RS* and PS*), so callers that need a single choice still have to
// pick. This uses ES256/384/512 from the curve, RS256 for RSA, and EdDSA
// for Ed25519.
func InferAlgorithm(pub crypto.PublicKey) (string, error) {
	if err := ValidatePublicKey(pub); err != nil {
		return "", err
	}
	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		return ecdsaAlgorithm(key)
	case *rsa.PublicKey:
		return "RS256", nil
	case ed25519.PublicKey:
		return "EdDSA", nil
	default:
		return "", fmt.Errorf("unsupported public key type: %T", pub)
	}
}

// ValidatePublicKey reports whether pub can be used with this module's JWS
// algorithms.
func ValidatePublicKey(pub crypto.PublicKey) error {
	switch key := pub.(type) {
	case *rsa.PublicKey:
		return validateRSA(key)
	case *ecdsa.PublicKey:
		_, err := ecdsaAlgorithm(key)
		return err
	case ed25519.PublicKey:
		if len(key) != ed25519.PublicKeySize {
			return fmt.Errorf("invalid Ed25519 public key")
		}
		return nil
	default:
		return fmt.Errorf("unsupported public key type: %T", pub)
	}
}

// SignerSupportsAlgorithm reports whether signer can produce alg.
func SignerSupportsAlgorithm(signer crypto.Signer, alg string) bool {
	if signer == nil || alg == "" {
		return false
	}
	want := jose.SignatureAlgorithm(alg)
	return slices.Contains(cryptosigner.Opaque(signer).Algs(), want)
}

// PublicKeySupportsAlgorithm reports whether pub is suitable for alg. It is
// intentionally stricter than merely accepting a key family: EC algorithms
// are bound to their named curve and EdDSA is bound to Ed25519.
func PublicKeySupportsAlgorithm(pub crypto.PublicKey, alg string) bool {
	if err := ValidatePublicKey(pub); err != nil {
		return false
	}
	switch key := pub.(type) {
	case *rsa.PublicKey:
		switch alg {
		case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
			return true
		}
	case *ecdsa.PublicKey:
		want, err := ecdsaAlgorithm(key)
		return err == nil && alg == want
	case ed25519.PublicKey:
		return alg == "EdDSA"
	}
	return false
}

func validateRSA(key *rsa.PublicKey) error {
	if key == nil || key.N == nil || key.N.BitLen() < 2048 {
		return fmt.Errorf("RSA key must be at least 2048 bits")
	}
	if key.E < 3 || key.E%2 == 0 {
		return fmt.Errorf("RSA key has an invalid public exponent")
	}
	return nil
}

func ecdsaAlgorithm(key *ecdsa.PublicKey) (string, error) {
	if key == nil {
		return "", fmt.Errorf("unsupported public key type: %T", key)
	}
	switch key.Curve {
	case elliptic.P256():
		return "ES256", nil
	case elliptic.P384():
		return "ES384", nil
	case elliptic.P521():
		return "ES512", nil
	default:
		name := ""
		if key.Curve != nil {
			name = key.Curve.Params().Name
		}
		return "", fmt.Errorf("unsupported ECDSA curve %q", name)
	}
}
