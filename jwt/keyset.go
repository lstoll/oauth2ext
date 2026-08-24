package jwt

import (
	"crypto/rsa"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"fmt"
	"slices"

	jose "github.com/go-jose/go-jose/v4"
)

const maxJWKSBytes = 1 << 20 // 1 MiB

// KeySet is an opaque set of public verification keys.
type KeySet struct {
	jwks jose.JSONWebKeySet
}

// MarshalJSON encodes the key set as a JWKS document.
func (k KeySet) MarshalJSON() ([]byte, error) {
	return jsonv2.Marshal(k.jwks)
}

// UnmarshalJSON decodes a JWKS document into the key set.
func (k *KeySet) UnmarshalJSON(data []byte) error {
	if len(data) > maxJWKSBytes {
		return fmt.Errorf("%w: jwks exceeds %d bytes", ErrSizeLimit, maxJWKSBytes)
	}
	var jwks jose.JSONWebKeySet
	if err := jsonv2.Unmarshal(data, &jwks); err != nil {
		return fmt.Errorf("%w: malformed jwks: %v", ErrKey, err)
	}
	var policy struct {
		Keys []struct {
			KeyOps jsontext.Value `json:"key_ops"`
		} `json:"keys"`
	}
	if err := jsonv2.Unmarshal(data, &policy); err != nil {
		return fmt.Errorf("%w: malformed jwks policy: %v", ErrKey, err)
	}
	if len(jwks.Keys) == 0 {
		return fmt.Errorf("%w: jwks contains no keys", ErrKey)
	}
	if len(policy.Keys) != len(jwks.Keys) {
		return fmt.Errorf("%w: inconsistent jwks key count", ErrKey)
	}
	for i, key := range jwks.Keys {
		if !key.Valid() {
			return fmt.Errorf("%w: jwk %d is invalid", ErrKey, i)
		}
		if !key.IsPublic() {
			return fmt.Errorf("%w: jwk %d is not a public key", ErrKey, i)
		}
		if rsaKey, ok := key.Key.(*rsa.PublicKey); ok && rsaKey.N.BitLen() < 2048 {
			return fmt.Errorf("%w: jwk %d has a %d-bit RSA modulus; minimum is 2048", ErrKey, i, rsaKey.N.BitLen())
		}
		if rsaKey, ok := key.Key.(*rsa.PublicKey); ok && (rsaKey.E < 3 || rsaKey.E%2 == 0) {
			return fmt.Errorf("%w: jwk %d has an invalid RSA exponent", ErrKey, i)
		}
		if raw := policy.Keys[i].KeyOps; len(raw) > 0 {
			if raw.Kind() != jsontext.KindBeginArray {
				return fmt.Errorf("%w: jwk %d key_ops is not an array", ErrKey, i)
			}
			var operations []string
			if err := jsonv2.Unmarshal(raw, &operations); err != nil {
				return fmt.Errorf("%w: jwk %d has invalid key_ops: %v", ErrKey, i, err)
			}
			if !slices.Contains(operations, "verify") {
				return fmt.Errorf("%w: jwk %d key_ops does not permit verification", ErrKey, i)
			}
		}
	}
	k.jwks = jwks
	return nil
}

// ParseJWKSet parses a JWKS document.
func ParseJWKSet(data []byte) (*KeySet, error) {
	var ks KeySet
	if err := ks.UnmarshalJSON(data); err != nil {
		return nil, err
	}
	return &ks, nil
}

func (k *KeySet) matchingKeys(alg, kid string) ([]any, error) {
	var candidates []jose.JSONWebKey
	if kid != "" {
		candidates = k.jwks.Key(kid)
	} else {
		candidates = k.jwks.Keys
	}

	var matches []jose.JSONWebKey
	for _, key := range candidates {
		if key.Algorithm != "" && key.Algorithm != alg {
			continue
		}
		if key.Use != "" && key.Use != "sig" {
			continue
		}
		matches = append(matches, key)
	}
	if len(matches) == 0 {
		return nil, nil
	}
	if kid == "" && len(matches) > 1 {
		return nil, fmt.Errorf("%w: multiple keys match without kid", ErrKey)
	}
	keys := make([]any, len(matches))
	for i, key := range matches {
		keys[i] = key.Key
	}
	return keys, nil
}

func headerString(h jose.Header, key jose.HeaderKey) string {
	if h.ExtraHeaders == nil {
		return ""
	}
	v, ok := h.ExtraHeaders[key]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}
