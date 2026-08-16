package jwt

import (
	"context"
	"crypto"
	crand "crypto/rand"
	"crypto/x509"
	"encoding/base64"
	jsonv2 "encoding/json/v2"
	"fmt"
	"math/big"
	"slices"
	"sync/atomic"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/cryptosigner"
	jwtint "lds.li/oauth2ext/internal/jwt"
)

const maxSigningPayloadBytes = 256 << 10

// CertificateMode controls whether x5c is emitted for this token.
type CertificateMode uint8

const (
	OmitCertificates CertificateMode = iota
	IncludeCertificatesIfAvailable
	RequireCertificates
)

// SignOptions are per-token JOSE header and algorithm choices. They request
// signer-owned material; callers never supply a kid, JWK, or certificate.
type SignOptions struct {
	Type         string
	Algorithms   []Algorithm // ordered acceptable algorithms; empty uses preference
	SkipKeyID    bool
	IncludeJWK   bool
	Certificates CertificateMode
}

// SigningKey configures one concrete signing identity. Each key resolves to
// exactly one algorithm. An empty Algorithm uses the key type's safe default;
// specify non-default RSA choices such as PS256 explicitly.
type SigningKey struct {
	Signer       crypto.Signer
	Algorithm    Algorithm
	KeyID        string
	Certificates []*x509.Certificate
}

// SignerConfig configures a concrete, reloadable signer.
type SignerConfig struct {
	Keys                []SigningKey
	PreferredAlgorithms []Algorithm
}

type signingKey struct {
	signer    crypto.Signer
	algorithm Algorithm
	kid       string
	jwk       map[string]any
	x5c       []string
	public    crypto.PublicKey
}
type signerState struct {
	keys      []signingKey
	preferred []Algorithm
}

// Signer signs compact JWTs. It has no protocol knowledge: header choices are
// supplied by SignOptions and key identity remains on the signer.
type Signer struct{ state atomic.Pointer[signerState] }

// NewSigner constructs a signer from one crypto.Signer. It infers the default
// algorithm when omitted, while NewSignerFromKeys requires explicit algorithms.
func NewSigner(key crypto.Signer, algorithm Algorithm, kid string, certificates ...*x509.Certificate) (*Signer, error) {
	if key == nil {
		return nil, fmt.Errorf("jwt: signer is required")
	}
	if algorithm == "" {
		inferred, err := jwtint.InferAlgorithm(key.Public())
		if err != nil {
			return nil, fmt.Errorf("jwt: %w", err)
		}
		algorithm = Algorithm(inferred)
	}
	return newSigner([]SigningKey{{Signer: key, Algorithm: algorithm, KeyID: kid, Certificates: certificates}}, nil)
}

// NewSignerFromKeys constructs a signer that can choose among distinct keys
// for redundancy. The candidate order is randomized for each Sign call.
func NewSignerFromKeys(config SignerConfig) (*Signer, error) {
	if len(config.Keys) == 0 {
		return nil, fmt.Errorf("jwt: at least one signing key is required")
	}
	return newSigner(config.Keys, config.PreferredAlgorithms)
}

func newSigner(configured []SigningKey, preferred []Algorithm) (*Signer, error) {
	keys := make([]signingKey, 0, len(configured))
	seenThumbprints, seenKids := map[string]struct{}{}, map[string]struct{}{}
	for i, configuredKey := range configured {
		if configuredKey.Signer == nil {
			return nil, fmt.Errorf("jwt: signing key %d requires a signer", i)
		}
		if err := jwtint.ValidatePublicKey(configuredKey.Signer.Public()); err != nil {
			return nil, fmt.Errorf("jwt: signing key %d: %w", i, err)
		}
		if configuredKey.Algorithm == "" {
			inferred, err := jwtint.InferAlgorithm(configuredKey.Signer.Public())
			if err != nil {
				return nil, fmt.Errorf("jwt: signing key %d: %w", i, err)
			}
			configuredKey.Algorithm = Algorithm(inferred)
		}
		if !jwtint.SignerSupportsAlgorithm(configuredKey.Signer, string(configuredKey.Algorithm)) {
			return nil, fmt.Errorf("jwt: signing key %d: algorithm %s is incompatible with key type %T", i, configuredKey.Algorithm, configuredKey.Signer.Public())
		}
		jwk, inferredKID, err := jwtint.PublicJWKMap(configuredKey.Signer.Public())
		if err != nil {
			return nil, fmt.Errorf("jwt: signing key %d: %w", i, err)
		}
		kid := configuredKey.KeyID
		if kid == "" {
			kid = inferredKID
		}
		publicJWK := jose.JSONWebKey{Key: configuredKey.Signer.Public()}
		thumb, err := publicJWK.Thumbprint(crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("jwt: signing key %d thumbprint: %w", i, err)
		}
		if _, ok := seenThumbprints[string(thumb)]; ok {
			return nil, fmt.Errorf("jwt: duplicate public signing key")
		}
		seenThumbprints[string(thumb)] = struct{}{}
		if _, ok := seenKids[kid]; ok {
			return nil, fmt.Errorf("jwt: duplicate kid %q", kid)
		}
		seenKids[kid] = struct{}{}
		x5c, err := encodeCertificateChain(configuredKey.Signer.Public(), configuredKey.Certificates)
		if err != nil {
			return nil, fmt.Errorf("jwt: signing key %d: %w", i, err)
		}
		keys = append(keys, signingKey{signer: configuredKey.Signer, algorithm: configuredKey.Algorithm, kid: kid, jwk: jwk, x5c: x5c, public: configuredKey.Signer.Public()})
	}
	if len(preferred) == 0 {
		for _, key := range keys {
			if !containsAlgorithm(preferred, key.algorithm) {
				preferred = append(preferred, key.algorithm)
			}
		}
	}
	for _, algorithm := range preferred {
		if algorithm == "" || containsAlgorithm(preferredBefore(preferred, algorithm), algorithm) || !hasAlgorithm(keys, algorithm) {
			return nil, fmt.Errorf("jwt: invalid preferred algorithm %q", algorithm)
		}
	}
	s := new(Signer)
	s.state.Store(&signerState{keys: keys, preferred: append([]Algorithm(nil), preferred...)})
	return s, nil
}

func preferredBefore(all []Algorithm, target Algorithm) []Algorithm {
	for i, alg := range all {
		if alg == target {
			return all[:i]
		}
	}
	return nil
}
func containsAlgorithm(algorithms []Algorithm, target Algorithm) bool {
	return slices.Contains(algorithms, target)
}
func hasAlgorithm(keys []signingKey, target Algorithm) bool {
	for _, key := range keys {
		if key.algorithm == target {
			return true
		}
	}
	return false
}

// Replace atomically adopts next's current validated key snapshot.
func (s *Signer) Replace(next *Signer) error {
	if s == nil || next == nil {
		return fmt.Errorf("jwt: signer is required")
	}
	state := next.state.Load()
	if state == nil {
		return fmt.Errorf("jwt: replacement signer is invalid")
	}
	s.state.Store(state)
	return nil
}

// Algorithms returns the signer's preferred algorithms in order.
func (s *Signer) Algorithms() []Algorithm {
	if s == nil || s.state.Load() == nil {
		return nil
	}
	return append([]Algorithm(nil), s.state.Load().preferred...)
}

// KeyID returns the key id for a single-key signer. It returns empty for a
// multi-key signer, where callers must not assume which redundant key wins.
func (s *Signer) KeyID() string {
	if s == nil || s.state.Load() == nil || len(s.state.Load().keys) != 1 {
		return ""
	}
	return s.state.Load().keys[0].kid
}

// PublicKeys returns a snapshot suitable for building a VerificationKeySet.
func (s *Signer) PublicKeys() []VerificationKey {
	if s == nil || s.state.Load() == nil {
		return nil
	}
	state := s.state.Load()
	result := make([]VerificationKey, len(state.keys))
	for i, key := range state.keys {
		result[i] = VerificationKey{Key: key.public, Algorithm: key.algorithm, KeyID: key.kid}
	}
	return result
}

// Sign marshals claims as a JSON object and produces a compact JWS. It tries
// redundant keys for each allowed algorithm before falling back to the next
// caller-allowed algorithm.
func (s *Signer) Sign(ctx context.Context, claims any, options SignOptions) (string, error) {
	if s == nil || s.state.Load() == nil {
		return "", fmt.Errorf("jwt: invalid signer")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	payload, err := jsonv2.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("jwt: marshaling claims: %w", err)
	}
	if len(payload) == 0 || len(payload) > maxSigningPayloadBytes {
		return "", fmt.Errorf("jwt: signing payload must be between 1 and %d bytes", maxSigningPayloadBytes)
	}
	var object map[string]any
	if err := jsonv2.Unmarshal(payload, &object); err != nil || object == nil {
		return "", fmt.Errorf("jwt: claims must marshal to a JSON object")
	}
	state := s.state.Load()
	algorithms := options.Algorithms
	if len(algorithms) == 0 {
		algorithms = state.preferred
	}
	if len(algorithms) == 0 {
		return "", fmt.Errorf("jwt: no signing algorithms")
	}
	var lastErr error
	for _, algorithm := range algorithms {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		candidates := make([]signingKey, 0)
		for _, key := range state.keys {
			if key.algorithm == algorithm {
				candidates = append(candidates, key)
			}
		}
		if len(candidates) == 0 {
			lastErr = fmt.Errorf("jwt: no key for algorithm %s", algorithm)
			continue
		}
		shuffleSigningKeys(candidates)
		for _, key := range candidates {
			compact, err := signWithKey(ctx, key, payload, options)
			if err == nil {
				return compact, nil
			}
			lastErr = err
		}
	}
	return "", fmt.Errorf("jwt: signing failed: %w", lastErr)
}

func signWithKey(ctx context.Context, key signingKey, payload []byte, options SignOptions) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	opts := new(jose.SignerOptions)
	if options.Type != "" {
		opts.WithType(jose.ContentType(options.Type))
	}
	if !options.SkipKeyID {
		opts.WithHeader("kid", key.kid)
	}
	if options.IncludeJWK {
		opts.WithHeader("jwk", key.jwk)
	}
	switch options.Certificates {
	case RequireCertificates:
		if len(key.x5c) == 0 {
			return "", fmt.Errorf("jwt: key %q has no certificate chain", key.kid)
		}
		fallthrough
	case IncludeCertificatesIfAvailable:
		if len(key.x5c) != 0 {
			opts.WithHeader("x5c", key.x5c)
		}
	case OmitCertificates:
	default:
		return "", fmt.Errorf("jwt: unknown certificate mode %d", options.Certificates)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.SignatureAlgorithm(key.algorithm), Key: cryptosigner.Opaque(key.signer)}, opts)
	if err != nil {
		return "", fmt.Errorf("jwt: creating JWS signer: %w", err)
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("jwt: signing: %w", err)
	}
	compact, err := signed.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("jwt: serializing JWT: %w", err)
	}
	return compact, nil
}

func shuffleSigningKeys(keys []signingKey) {
	for i := len(keys) - 1; i > 0; i-- {
		n, err := crand.Int(crand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return
		}
		j := int(n.Int64())
		keys[i], keys[j] = keys[j], keys[i]
	}
}

func encodeCertificateChain(publicKey crypto.PublicKey, chain []*x509.Certificate) ([]string, error) {
	if len(chain) == 0 {
		return nil, nil
	}
	if chain[0] == nil || !publicKeysEqual(chain[0].PublicKey, publicKey) {
		return nil, fmt.Errorf("leaf certificate public key does not match signer")
	}
	encoded := make([]string, len(chain))
	for i, certificate := range chain {
		if certificate == nil {
			return nil, fmt.Errorf("certificate chain contains a nil certificate")
		}
		encoded[i] = base64.StdEncoding.EncodeToString(certificate.Raw)
	}
	return encoded, nil
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	equal, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && equal.Equal(b)
}
