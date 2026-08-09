package oauth2as

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	jsonv2 "encoding/json/v2"
	"fmt"
	"slices"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/cryptosigner"
	"lds.li/oauth2ext/jwt"
)

const maxSigningPayloadBytes = 256 << 10

// JWTSigningInput is a server-constructed JWT payload and protected type header.
type JWTSigningInput struct {
	Type    string
	Payload []byte
}

// JWTSigner signs server-constructed JWTs using an explicitly selected algorithm.
type JWTSigner interface {
	Algorithms(context.Context) ([]jwt.Algorithm, error)
	SignJWT(context.Context, jwt.Algorithm, JWTSigningInput) (string, error)
}

// JWTVerifier verifies JWTs against an explicit validation policy.
type JWTVerifier interface {
	VerifyJWT(context.Context, string, jwt.ValidationPolicy) (*jwt.VerifiedJWT, error)
}

// SigningKey associates an active private signing key with one algorithm.
type SigningKey struct {
	Algorithm jwt.Algorithm
	Key       crypto.Signer
}

// LocalJWTSignerConfig configures an immutable in-process signer and key set.
type LocalJWTSignerConfig struct {
	SigningKeys      []SigningKey
	VerificationKeys []crypto.PublicKey
}

type localSigningKey struct {
	signer crypto.Signer
	kid    string
}

// LocalJWTSigner signs with local or crypto.Signer-backed keys, publishes their
// public keys, and can verify tokens against the same key set.
type LocalJWTSigner struct {
	signing map[jwt.Algorithm]localSigningKey
	algs    []jwt.Algorithm
	jwks    []byte
	keys    *jwt.KeySet
}

// NewLocalJWTSigner constructs a signer with exactly one active key for each
// configured algorithm. VerificationKeys are published but never used to sign.
func NewLocalJWTSigner(config LocalJWTSignerConfig) (*LocalJWTSigner, error) {
	if len(config.SigningKeys) == 0 {
		return nil, fmt.Errorf("oauth2as: at least one signing key is required")
	}

	result := &LocalJWTSigner{signing: make(map[jwt.Algorithm]localSigningKey, len(config.SigningKeys))}
	seenThumbprints := make(map[string]struct{}, len(config.SigningKeys)+len(config.VerificationKeys))
	publicKeys := make([]jose.JSONWebKey, 0, len(config.SigningKeys)+len(config.VerificationKeys))

	for i, configured := range config.SigningKeys {
		if configured.Algorithm == "" {
			return nil, fmt.Errorf("oauth2as: signing key %d has no algorithm", i)
		}
		if configured.Key == nil {
			return nil, fmt.Errorf("oauth2as: signing key %d is nil", i)
		}
		if _, exists := result.signing[configured.Algorithm]; exists {
			return nil, fmt.Errorf("oauth2as: multiple active signing keys for %s", configured.Algorithm)
		}
		if err := validateSigner(configured.Key, configured.Algorithm); err != nil {
			return nil, fmt.Errorf("oauth2as: signing key %d: %w", i, err)
		}
		jwk, kid, err := publicJWK(configured.Key.Public())
		if err != nil {
			return nil, fmt.Errorf("oauth2as: signing key %d: %w", i, err)
		}
		if _, duplicate := seenThumbprints[kid]; duplicate {
			return nil, fmt.Errorf("oauth2as: duplicate key thumbprint %q", kid)
		}
		seenThumbprints[kid] = struct{}{}
		jwk.Algorithm = string(configured.Algorithm)
		jwk.Use = "sig"
		jwk.KeyID = kid
		publicKeys = append(publicKeys, jwk)
		result.signing[configured.Algorithm] = localSigningKey{signer: configured.Key, kid: kid}
		result.algs = append(result.algs, configured.Algorithm)
	}

	for i, key := range config.VerificationKeys {
		jwk, kid, err := publicJWK(key)
		if err != nil {
			return nil, fmt.Errorf("oauth2as: verification key %d: %w", i, err)
		}
		if _, duplicate := seenThumbprints[kid]; duplicate {
			return nil, fmt.Errorf("oauth2as: duplicate key thumbprint %q", kid)
		}
		seenThumbprints[kid] = struct{}{}
		jwk.Use = "sig"
		jwk.KeyID = kid
		publicKeys = append(publicKeys, jwk)
	}

	slices.Sort(result.algs)
	slices.SortFunc(publicKeys, func(a, b jose.JSONWebKey) int {
		if a.KeyID < b.KeyID {
			return -1
		}
		if a.KeyID > b.KeyID {
			return 1
		}
		return 0
	})

	encoded, err := jsonv2.Marshal(jose.JSONWebKeySet{Keys: publicKeys})
	if err != nil {
		return nil, fmt.Errorf("oauth2as: marshaling JWKS: %w", err)
	}
	parsed, err := jwt.ParseJWKSet(encoded)
	if err != nil {
		return nil, fmt.Errorf("oauth2as: validating JWKS: %w", err)
	}
	result.jwks = encoded
	result.keys = parsed
	return result, nil
}

// NewLocalJWTSignerForKey constructs a single-algorithm signer, inferring
// ES256/384/512, RS256, or EdDSA from the primary key.
func NewLocalJWTSignerForKey(primary crypto.Signer, verificationKeys ...crypto.PublicKey) (*LocalJWTSigner, error) {
	if primary == nil {
		return nil, fmt.Errorf("oauth2as: primary signing key is required")
	}
	algorithm, err := inferredAlgorithm(primary.Public())
	if err != nil {
		return nil, err
	}
	return NewLocalJWTSigner(LocalJWTSignerConfig{
		SigningKeys:      []SigningKey{{Algorithm: algorithm, Key: primary}},
		VerificationKeys: verificationKeys,
	})
}

func (s *LocalJWTSigner) Algorithms(ctx context.Context) ([]jwt.Algorithm, error) {
	if s == nil || s.signing == nil {
		return nil, fmt.Errorf("oauth2as: invalid local JWT signer")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return slices.Clone(s.algs), nil
}

func (s *LocalJWTSigner) SignJWT(ctx context.Context, algorithm jwt.Algorithm, input JWTSigningInput) (string, error) {
	if s == nil || s.signing == nil {
		return "", fmt.Errorf("oauth2as: invalid local JWT signer")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	key, ok := s.signing[algorithm]
	if !ok {
		return "", fmt.Errorf("oauth2as: no active signing key for %s", algorithm)
	}
	if len(input.Payload) == 0 || len(input.Payload) > maxSigningPayloadBytes {
		return "", fmt.Errorf("oauth2as: signing payload must be between 1 and %d bytes", maxSigningPayloadBytes)
	}
	var payload map[string]any
	if err := jsonv2.Unmarshal(input.Payload, &payload); err != nil || payload == nil {
		return "", fmt.Errorf("oauth2as: signing payload must be a JSON object: %v", err)
	}

	opts := new(jose.SignerOptions).WithHeader("kid", key.kid)
	if input.Type != "" {
		opts.WithType(jose.ContentType(input.Type))
	}
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.SignatureAlgorithm(algorithm),
		Key:       cryptosigner.Opaque(key.signer),
	}, opts)
	if err != nil {
		return "", fmt.Errorf("oauth2as: creating JWS signer: %w", err)
	}
	signed, err := signer.Sign(input.Payload)
	if err != nil {
		return "", fmt.Errorf("oauth2as: signing JWT: %w", err)
	}
	compact, err := signed.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("oauth2as: serializing JWT: %w", err)
	}
	return compact, nil
}

// JWKS returns a copy of the deterministic public JWK set.
func (s *LocalJWTSigner) JWKS(ctx context.Context) ([]byte, error) {
	if s == nil || len(s.jwks) == 0 {
		return nil, fmt.Errorf("oauth2as: invalid local JWT signer")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return slices.Clone(s.jwks), nil
}

func (s *LocalJWTSigner) VerifyJWT(ctx context.Context, compact string, policy jwt.ValidationPolicy) (*jwt.VerifiedJWT, error) {
	if s == nil || s.keys == nil {
		return nil, fmt.Errorf("oauth2as: invalid local JWT signer")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return s.keys.VerifyJWT(compact, policy)
}

func publicJWK(key crypto.PublicKey) (jose.JSONWebKey, string, error) {
	jwk := jose.JSONWebKey{Key: key}
	if !jwk.Valid() || !jwk.IsPublic() {
		return jose.JSONWebKey{}, "", fmt.Errorf("key must be a valid public key")
	}
	if rsaKey, ok := key.(*rsa.PublicKey); ok {
		if rsaKey.N == nil || rsaKey.N.BitLen() < 2048 {
			return jose.JSONWebKey{}, "", fmt.Errorf("RSA key must be at least 2048 bits")
		}
		if rsaKey.E < 3 || rsaKey.E%2 == 0 {
			return jose.JSONWebKey{}, "", fmt.Errorf("RSA key has an invalid exponent")
		}
	}
	thumbprint, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return jose.JSONWebKey{}, "", fmt.Errorf("calculating JWK thumbprint: %w", err)
	}
	return jwk, base64.RawURLEncoding.EncodeToString(thumbprint), nil
}

func validateSigner(signer crypto.Signer, algorithm jwt.Algorithm) error {
	if _, _, err := publicJWK(signer.Public()); err != nil {
		return err
	}
	for _, supported := range cryptosigner.Opaque(signer).Algs() {
		if string(supported) == string(algorithm) {
			return nil
		}
	}
	return fmt.Errorf("algorithm %s is incompatible with key type %T", algorithm, signer.Public())
}

func inferredAlgorithm(key crypto.PublicKey) (jwt.Algorithm, error) {
	switch key := key.(type) {
	case *ecdsa.PublicKey:
		switch key.Curve {
		case elliptic.P256():
			return jwt.ES256, nil
		case elliptic.P384():
			return jwt.ES384, nil
		case elliptic.P521():
			return jwt.ES512, nil
		default:
			return "", fmt.Errorf("oauth2as: unsupported ECDSA curve %q", key.Curve.Params().Name)
		}
	case *rsa.PublicKey:
		return jwt.RS256, nil
	case ed25519.PublicKey:
		return jwt.EdDSA, nil
	default:
		return "", fmt.Errorf("oauth2as: unsupported signing key type %T", key)
	}
}
