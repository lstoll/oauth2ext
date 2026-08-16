package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"fmt"
	"math/big"
	"sync/atomic"

	jose "github.com/go-jose/go-jose/v4"
	jwtint "lds.li/oauth2ext/internal/jwt"
)

// Copy the legacy mutable coordinates too, so callers cannot mutate our snapshot.
//
//nolint:staticcheck // SA1019: intentional deep copy of caller-owned ECDSA coordinates.
func clonePublicKey(key crypto.PublicKey) crypto.PublicKey {
	switch k := key.(type) {
	case *rsa.PublicKey:
		if k == nil || k.N == nil {
			return (*rsa.PublicKey)(nil)
		}
		return &rsa.PublicKey{N: new(big.Int).Set(k.N), E: k.E}
	case *ecdsa.PublicKey:
		if k == nil {
			return (*ecdsa.PublicKey)(nil)
		}
		out := &ecdsa.PublicKey{Curve: k.Curve}
		if k.X != nil {
			out.X = new(big.Int).Set(k.X)
		}
		if k.Y != nil {
			out.Y = new(big.Int).Set(k.Y)
		}
		return out
	case ed25519.PublicKey:
		return append(ed25519.PublicKey(nil), k...)
	default:
		return nil
	}
}

const maxJWKSBytes = 1 << 20 // 1 MiB

// VerificationKey is one explicitly algorithm-bound public verification key.
// KeyID and Algorithm are required when constructing a local key set.
type VerificationKey struct {
	Key       crypto.PublicKey
	Algorithm Algorithm
	KeyID     string
}

// NewVerificationKey builds a public verification key with a safe default
// algorithm and RFC 7638 SHA-256 thumbprint kid when omitted.
func NewVerificationKey(key crypto.PublicKey, algorithm Algorithm, kid string) (VerificationKey, error) {
	if err := jwtint.ValidatePublicKey(key); err != nil {
		return VerificationKey{}, fmt.Errorf("jwt: %w", err)
	}
	if algorithm == "" {
		a, err := jwtint.InferAlgorithm(key)
		if err != nil {
			return VerificationKey{}, fmt.Errorf("jwt: %w", err)
		}
		algorithm = Algorithm(a)
	}
	if !jwtint.PublicKeySupportsAlgorithm(key, string(algorithm)) {
		return VerificationKey{}, fmt.Errorf("jwt: algorithm %s is incompatible with key type %T", algorithm, key)
	}
	_, inferred, err := jwtint.PublicJWK(key)
	if err != nil {
		return VerificationKey{}, fmt.Errorf("jwt: %w", err)
	}
	if kid == "" {
		kid = inferred
	}
	return VerificationKey{Key: clonePublicKey(key), Algorithm: algorithm, KeyID: kid}, nil
}

type keySetState struct{ jwks jose.JSONWebKeySet }

// VerificationKeySet is an opaque, reloadable set of public verification
// keys. It is a stable handle: Replace atomically changes the keys observed by
// existing users of the handle.
type VerificationKeySet struct{ state atomic.Pointer[keySetState] }

// NewVerificationKeySet constructs a verified, publication-ready key set. Each
// key must name exactly one compatible signing algorithm. An empty set is
// valid and represents a state with no trusted signing keys.
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

// NewVerificationKeySetFromSigner takes a snapshot of signer's active public
// keys, optionally adding verification-only keys. Later replacements of the
// signer do not affect the returned key set. During rotation, publish a key set
// containing new public keys before replacing the signer, and retain old keys
// until all tokens signed with them have expired.
func NewVerificationKeySetFromSigner(signer Signer, extras ...VerificationKey) (*VerificationKeySet, error) {
	if signer == nil {
		return nil, fmt.Errorf("jwt: signer is required")
	}
	keys := append(signer.verificationKeys(), extras...)
	return NewVerificationKeySet(keys...)
}

// Replace atomically adopts next's current validated key snapshot. When this
// set verifies tokens from a signing key set, publish the replacement key set
// before switching the signer and retain old keys until their tokens expire.
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
	if k == nil {
		return nil, fmt.Errorf("jwt: invalid key set")
	}
	state := k.state.Load()
	if state == nil {
		return nil, fmt.Errorf("jwt: invalid key set")
	}
	return jsonv2.Marshal(state.jwks)
}

// JWKS returns the current JWKS JSON. It supports discovery publishers that
// already expose their key material as bytes.
func (k *VerificationKeySet) JWKS() ([]byte, error) {
	return k.MarshalJSON()
}

// UnmarshalJSON decodes and atomically installs a JWKS document.
func (k *VerificationKeySet) UnmarshalJSON(data []byte) error {
	if len(data) > maxJWKSBytes {
		return fmt.Errorf("%w: jwks exceeds %d bytes", ErrSizeLimit, maxJWKSBytes)
	}
	var policy struct {
		Keys []jsontext.Value `json:"keys"`
	}
	if err := jsonv2.Unmarshal(data, &policy); err != nil {
		return fmt.Errorf("%w: malformed jwks policy: %v", ErrKey, err)
	}
	// Distinguish a valid empty array (which clears trust) from a missing or
	// null keys member.
	var document map[string]jsontext.Value
	if err := jsonv2.Unmarshal(data, &document); err != nil {
		return fmt.Errorf("%w: malformed jwks: %v", ErrKey, err)
	}
	keysRaw, ok := document["keys"]
	if !ok || keysRaw.Kind() != jsontext.KindBeginArray || policy.Keys == nil {
		return fmt.Errorf("%w: jwks keys must be an array", ErrKey)
	}
	keys := make([]jose.JSONWebKey, 0, len(policy.Keys))
	for i, raw := range policy.Keys {
		var meta map[string]jsontext.Value
		if err := jsonv2.Unmarshal(raw, &meta); err != nil {
			return fmt.Errorf("%w: malformed jwk %d: %v", ErrKey, i, err)
		}
		if meta == nil {
			return fmt.Errorf("%w: jwk %d must be an object", ErrKey, i)
		}
		for _, private := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
			if _, exists := meta[private]; exists {
				return fmt.Errorf("%w: jwk %d contains private key material", ErrKey, i)
			}
		}
		var eligibility struct {
			Kty    string         `json:"kty"`
			Curve  string         `json:"crv"`
			Use    string         `json:"use"`
			Alg    string         `json:"alg"`
			KeyOps jsontext.Value `json:"key_ops"`
		}
		if err := jsonv2.Unmarshal(raw, &eligibility); err != nil {
			return fmt.Errorf("%w: malformed jwk %d: %v", ErrKey, i, err)
		}
		if eligibility.Kty == "" {
			return fmt.Errorf("%w: jwk %d requires kty", ErrKey, i)
		}
		if eligibility.Use != "" && eligibility.Use != "sig" {
			continue
		}
		if eligibility.KeyOps.Kind() != 0 {
			if eligibility.KeyOps.Kind() != jsontext.KindBeginArray {
				return fmt.Errorf("%w: jwk %d key_ops is not an array", ErrKey, i)
			}
			var ops []string
			if err := jsonv2.Unmarshal(eligibility.KeyOps, &ops); err != nil {
				return fmt.Errorf("%w: jwk %d has invalid key_ops: %v", ErrKey, i, err)
			}
			verify := false
			for _, op := range ops {
				verify = verify || op == "verify"
			}
			if !verify {
				continue
			}
		}
		switch eligibility.Kty {
		case "RSA", "EC", "OKP":
		default:
			continue
		}
		if eligibility.Alg != "" {
			if _, err := Algorithm(eligibility.Alg).jose(); err != nil {
				continue
			}
		}
		if eligibility.Kty == "EC" {
			if eligibility.Curve == "" {
				return fmt.Errorf("%w: jwk %d requires crv", ErrKey, i)
			}
			if eligibility.Curve != "P-256" && eligibility.Curve != "P-384" && eligibility.Curve != "P-521" {
				continue
			}
		}
		if eligibility.Kty == "OKP" {
			if eligibility.Curve == "" {
				return fmt.Errorf("%w: jwk %d requires crv", ErrKey, i)
			}
			if eligibility.Curve != "Ed25519" {
				continue
			}
		}
		var key jose.JSONWebKey
		if err := jsonv2.Unmarshal(raw, &key); err != nil {
			return fmt.Errorf("%w: malformed eligible jwk %d: %v", ErrKey, i, err)
		}
		keys = append(keys, key)
	}
	state, err := validateKeySet(keys, false)
	if err != nil {
		return err
	}
	k.state.Store(state)
	return nil
}

// ParseVerificationJWKS parses a JWKS document for verification. It ignores
// encryption-only keys, unsupported key types, and unsupported algorithms;
// malformed documents, private material, and malformed eligible keys fail.
// An explicit empty keys array is valid and removes all trust when installed.
func ParseVerificationJWKS(data []byte) (*VerificationKeySet, error) {
	var ks VerificationKeySet
	if err := ks.UnmarshalJSON(data); err != nil {
		return nil, err
	}
	return &ks, nil
}

func newVerificationKeySet(keys []jose.JSONWebKey) (*VerificationKeySet, error) {
	state, err := validateKeySet(keys, true)
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
	return jose.JSONWebKey{Key: clonePublicKey(key), KeyID: kid, Algorithm: string(algorithm), Use: "sig"}, nil
}

func validateKeySet(keys []jose.JSONWebKey, requireAlgorithm bool) (*keySetState, error) {
	// An empty key set is a valid state, including for atomic key retirement.
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
		key.Key = clonePublicKey(key.Key)
		copyKeys[i] = key
	}
	return &keySetState{jwks: jose.JSONWebKeySet{Keys: copyKeys}}, nil
}

func (k *VerificationKeySet) matchingKeys(alg, kid string) ([]any, error) {
	if k == nil {
		return nil, fmt.Errorf("%w: invalid key set", ErrKey)
	}
	state := k.state.Load()
	if state == nil {
		return nil, fmt.Errorf("%w: invalid key set", ErrKey)
	}
	jwks := state.jwks
	candidates := jwks.Keys
	if kid != "" {
		candidates = jwks.Key(kid)
	}
	var matches []jose.JSONWebKey
	for _, key := range candidates {
		if !jwtint.PublicKeySupportsAlgorithm(key.Key, alg) {
			continue
		}
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
