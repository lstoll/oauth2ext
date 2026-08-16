package jwt

import (
	"crypto"
	"encoding/base64"
	jsonv2 "encoding/json/v2"
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

// PublicJWKMap returns the public JWK as a JSON object and its thumbprint.
func PublicJWKMap(pub crypto.PublicKey) (map[string]any, string, error) {
	jwk, kid, err := PublicJWK(pub)
	if err != nil {
		return nil, "", err
	}
	encoded, err := jsonv2.Marshal(jwk)
	if err != nil {
		return nil, "", fmt.Errorf("marshaling public JWK: %w", err)
	}
	var object map[string]any
	if err := jsonv2.Unmarshal(encoded, &object); err != nil {
		return nil, "", fmt.Errorf("decoding public JWK: %w", err)
	}
	if object == nil {
		return nil, "", fmt.Errorf("public JWK is not an object")
	}
	return object, kid, nil
}

// ThumbprintMap returns the RFC 7638 SHA-256 thumbprint of a public JWK object.
func ThumbprintMap(jwk map[string]any) (string, error) {
	if len(jwk) == 0 {
		return "", fmt.Errorf("jwk is missing")
	}
	encoded, err := jsonv2.Marshal(jwk)
	if err != nil {
		return "", fmt.Errorf("marshaling jwk: %w", err)
	}
	var key jose.JSONWebKey
	if err := jsonv2.Unmarshal(encoded, &key); err != nil {
		return "", fmt.Errorf("parsing jwk: %w", err)
	}
	if !key.Valid() || !key.IsPublic() {
		return "", fmt.Errorf("jwk must be a valid public key")
	}
	thumbprint, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(thumbprint), nil
}
