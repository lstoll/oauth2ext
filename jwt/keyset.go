package jwt

import (
	"context"
	"crypto"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"fmt"
	"sync/atomic"

	jose "github.com/go-jose/go-jose/v4"
	jwtint "lds.li/oauth2ext/internal/jwt"
)

const maxJWKSBytes = 1 << 20 // 1 MiB

// VerificationKey is one explicitly algorithm-bound public verification key.
// KeyID and Algorithm are required when constructing a local key set.
type VerificationKey struct {
	Key       crypto.PublicKey
	Algorithm Algorithm
	KeyID     string
}

type keySetState struct{ jwks jose.JSONWebKeySet }

// VerificationKeySet is an opaque, reloadable set of public verification
// keys. It is a stable handle: Replace atomically changes the keys observed by
// existing users of the handle.
type VerificationKeySet struct{ state atomic.Pointer[keySetState] }

// NewVerificationKeySet constructs a verified, publication-ready key set. Each
// key must name exactly one compatible signing algorithm.
func NewVerificationKeySet(keys ...VerificationKey) (*VerificationKeySet, error) {
	jwks := make([]jose.JSONWebKey, 0, len(keys))
	for i, key := range keys {
		if key.Key == nil || key.Algorithm == "" || key.KeyID == "" {
			return nil, fmt.Errorf("jwt: verification key %d requires key, algorithm, and kid", i)
		}
		jwk, err := publicJWK(key.Key, key.Algorithm, key.KeyID)
		if err != nil {
			return nil, fmt.Errorf("jwt: verification key %d: %w", i, err)
		}
		jwks = append(jwks, jwk)
	}
	return newVerificationKeySet(jwks)
}

// NewVerificationKeySetFromSigner takes a snapshot of signer's public keys, optionally
// adding verification-only keys. Later replacements of signer do not affect
// the returned key set.
func NewVerificationKeySetFromSigner(signer *Signer, extras ...VerificationKey) (*VerificationKeySet, error) {
	if signer == nil {
		return nil, fmt.Errorf("jwt: signer is required")
	}
	keys := append(signer.PublicKeys(), extras...)
	return NewVerificationKeySet(keys...)
}

// Replace atomically adopts next's current validated key snapshot.
func (k *VerificationKeySet) Replace(next *VerificationKeySet) error {
	if k == nil || next == nil {
		return fmt.Errorf("jwt: key set is required")
	}
	state := next.state.Load()
	if state == nil {
		return fmt.Errorf("jwt: replacement key set is invalid")
	}
	k.state.Store(state)
	return nil
}

// MarshalJSON encodes the current key set as a JWKS document.
func (k *VerificationKeySet) MarshalJSON() ([]byte, error) {
	if k == nil || k.state.Load() == nil {
		return nil, fmt.Errorf("jwt: invalid key set")
	}
	return jsonv2.Marshal(k.state.Load().jwks)
}

// JWKS returns the current JWKS JSON. It supports discovery publishers that
// already expose their key material as bytes.
func (k *VerificationKeySet) JWKS(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return k.MarshalJSON()
}

// UnmarshalJSON decodes and atomically installs a JWKS document.
func (k *VerificationKeySet) UnmarshalJSON(data []byte) error {
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
	if len(policy.Keys) != len(jwks.Keys) {
		return fmt.Errorf("%w: inconsistent jwks key count", ErrKey)
	}
	state, err := validateKeySet(jwks.Keys, false, policy.Keys)
	if err != nil {
		return err
	}
	k.state.Store(state)
	return nil
}

// ParseVerificationKeySet parses a JWKS document.
func ParseVerificationKeySet(data []byte) (*VerificationKeySet, error) {
	var ks VerificationKeySet
	if err := ks.UnmarshalJSON(data); err != nil {
		return nil, err
	}
	return &ks, nil
}

func newVerificationKeySet(keys []jose.JSONWebKey) (*VerificationKeySet, error) {
	state, err := validateKeySet(keys, true, nil)
	if err != nil {
		return nil, err
	}
	ks := new(VerificationKeySet)
	ks.state.Store(state)
	return ks, nil
}

func publicJWK(key crypto.PublicKey, algorithm Algorithm, kid string) (jose.JSONWebKey, error) {
	if err := jwtint.ValidatePublicKey(key); err != nil {
		return jose.JSONWebKey{}, err
	}
	if !jwtint.PublicKeySupportsAlgorithm(key, string(algorithm)) {
		return jose.JSONWebKey{}, fmt.Errorf("algorithm %s is incompatible with key type %T", algorithm, key)
	}
	return jose.JSONWebKey{Key: key, KeyID: kid, Algorithm: string(algorithm), Use: "sig"}, nil
}

func validateKeySet(keys []jose.JSONWebKey, requireAlgorithm bool, policy []struct {
	KeyOps jsontext.Value `json:"key_ops"`
}) (*keySetState, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: jwks contains no keys", ErrKey)
	}
	seenThumbprints := map[string]struct{}{}
	seenKids := map[string]struct{}{}
	copyKeys := make([]jose.JSONWebKey, len(keys))
	for i, key := range keys {
		if !key.Valid() {
			return nil, fmt.Errorf("%w: jwk %d is invalid", ErrKey, i)
		}
		if !key.IsPublic() {
			return nil, fmt.Errorf("%w: jwk %d is not a public key", ErrKey, i)
		}
		if err := jwtint.ValidatePublicKey(key.Key); err != nil {
			return nil, fmt.Errorf("%w: jwk %d: %v", ErrKey, i, err)
		}
		if requireAlgorithm && (key.Algorithm == "" || key.KeyID == "") {
			return nil, fmt.Errorf("%w: jwk %d requires alg and kid", ErrKey, i)
		}
		if key.Algorithm != "" && !jwtint.PublicKeySupportsAlgorithm(key.Key, key.Algorithm) {
			return nil, fmt.Errorf("%w: jwk %d algorithm %q is incompatible with its key", ErrKey, i, key.Algorithm)
		}
		if key.Use != "" && key.Use != "sig" {
			return nil, fmt.Errorf("%w: jwk %d is not a signing key", ErrKey, i)
		}
		if len(policy) > 0 && len(policy[i].KeyOps) > 0 {
			raw := policy[i].KeyOps
			if raw.Kind() != jsontext.KindBeginArray {
				return nil, fmt.Errorf("%w: jwk %d key_ops is not an array", ErrKey, i)
			}
			var operations []string
			if err := jsonv2.Unmarshal(raw, &operations); err != nil {
				return nil, fmt.Errorf("%w: jwk %d has invalid key_ops: %v", ErrKey, i, err)
			}
			ok := false
			for _, operation := range operations {
				ok = ok || operation == "verify"
			}
			if !ok {
				return nil, fmt.Errorf("%w: jwk %d key_ops does not permit verification", ErrKey, i)
			}
		}
		thumb, err := key.Thumbprint(crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("%w: jwk %d thumbprint: %v", ErrKey, i, err)
		}
		if _, ok := seenThumbprints[string(thumb)]; ok {
			return nil, fmt.Errorf("%w: duplicate public key", ErrKey)
		}
		seenThumbprints[string(thumb)] = struct{}{}
		if key.KeyID != "" {
			if _, ok := seenKids[key.KeyID]; ok {
				return nil, fmt.Errorf("%w: duplicate kid %q", ErrKey, key.KeyID)
			}
			seenKids[key.KeyID] = struct{}{}
		}
		copyKeys[i] = key
	}
	return &keySetState{jwks: jose.JSONWebKeySet{Keys: copyKeys}}, nil
}

func (k *VerificationKeySet) matchingKeys(alg, kid string) ([]any, error) {
	if k == nil || k.state.Load() == nil {
		return nil, fmt.Errorf("%w: invalid key set", ErrKey)
	}
	jwks := k.state.Load().jwks
	candidates := jwks.Keys
	if kid != "" {
		candidates = jwks.Key(kid)
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
	result := make([]any, len(matches))
	for i := range matches {
		result[i] = matches[i].Key
	}
	return result, nil
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
