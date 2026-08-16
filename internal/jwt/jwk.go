package jwt

import (
	"crypto"
	"encoding/base64"
	"fmt"

	jose "github.com/go-jose/go-jose/v4"
)

// PublicJWK returns the public JWK for pub and its RFC 7638 SHA-256 thumbprint.
func PublicJWK(pub crypto.PublicKey) (jose.JSONWebKey, string, error) {
	if err := ValidatePublicKey(pub); err != nil {
		return jose.JSONWebKey{}, "", err
	}
	jwk := jose.JSONWebKey{Key: pub}
	if !jwk.Valid() || !jwk.IsPublic() {
		return jose.JSONWebKey{}, "", fmt.Errorf("key must be a valid public key")
	}
	thumbprint, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return jose.JSONWebKey{}, "", fmt.Errorf("calculating JWK thumbprint: %w", err)
	}
	return jwk, base64.RawURLEncoding.EncodeToString(thumbprint), nil
}
