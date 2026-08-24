package dpop

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	jsonv2 "encoding/json/v2"
	"fmt"

	jose "github.com/go-jose/go-jose/v4"
)

// publicKeyToJWK creates the public JWK carried by a DPoP proof.
func publicKeyToJWK(pubKey crypto.PublicKey) (map[string]any, error) {
	if _, err := determineAlgorithmFromKey(pubKey); err != nil {
		return nil, err
	}
	encoded, err := jsonv2.Marshal(jose.JSONWebKey{Key: pubKey})
	if err != nil {
		return nil, fmt.Errorf("marshaling public JWK: %w", err)
	}
	var result map[string]any
	if err := jsonv2.Unmarshal(encoded, &result); err != nil {
		return nil, fmt.Errorf("decoding public JWK: %w", err)
	}
	return result, nil
}

// determineAlgorithmFromKey determines the JWT algorithm from a public key type.
func determineAlgorithmFromKey(pubKey any) (string, error) {
	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		if key.N == nil || key.N.BitLen() < 2048 {
			return "", fmt.Errorf("RSA key must be at least 2048 bits")
		}
		if key.E < 3 || key.E%2 == 0 {
			return "", fmt.Errorf("RSA key has an invalid public exponent")
		}
		return "RS256", nil
	case *ecdsa.PublicKey:
		switch key.Curve {
		case elliptic.P256():
			return "ES256", nil
		case elliptic.P384():
			return "ES384", nil
		case elliptic.P521():
			return "ES512", nil
		default:
			return "", fmt.Errorf("unsupported ECDSA curve %q", key.Curve.Params().Name)
		}
	default:
		return "", fmt.Errorf("unsupported public key type: %T", pubKey)
	}
}

// calculateJWKThumbprint calculates the JWK thumbprint per RFC 7638.
func calculateJWKThumbprint(jwk map[string]any) (string, error) {
	key, err := parsePublicJWK(jwk)
	if err != nil {
		return "", err
	}
	return jwkThumbprint(key)
}
