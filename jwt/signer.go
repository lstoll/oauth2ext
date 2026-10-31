package jwt

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	jsonv2 "encoding/json/v2"
	"fmt"
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

// SignOptions are per-token JOSE presentation choices. Key-derived headers
// remain owned by the signer. Algorithm is exact when set; an empty value
// selects the identity's algorithm and is rejected by a signing key set when
// more than one active algorithm is available.
type SignOptions struct {
	Type         string
	Algorithm    Algorithm
	SkipKeyID    bool
	IncludeJWK   bool
	Certificates CertificateMode
	// CertificateThumbprint emits the signer-derived x5t#S256 header. It
	// requires a configured certificate chain.
	CertificateThumbprint bool
}

// Signer signs compact JWTs. The unexported marker prevents external types
// from implementing this interface and bypassing library-owned JOSE policy.
type Signer interface {
	Sign(context.Context, any, SignOptions) (string, error)
	SupportsAlgorithm(Algorithm) bool
	signerMarker()
	verificationKeys() []VerificationKey
}

// SigningIdentity is one immutable signing identity: a validated private key,
// one algorithm, and signer-derived public presentation data. Construct it with
// NewSigningIdentity; its state cannot be replaced or mutated through this API.
type SigningIdentity struct {
	signer     crypto.Signer
	algorithm  Algorithm
	kid        string
	thumbprint string
	x5tS256    string
	jwk        jose.JSONWebKey
	x5c        []string
	public     crypto.PublicKey
}

// NewSigningIdentity validates key and constructs one immutable signing
// identity. An empty algorithm uses the key type's safe default. An empty kid
// derives the RFC 7638 SHA-256 thumbprint. The caller-owned crypto.Signer must
// keep its public key and signing behavior stable for the identity's lifetime.
func NewSigningIdentity(key crypto.Signer, algorithm Algorithm, kid string, certificates ...*x509.Certificate) (*SigningIdentity, error) {
	if key == nil {
		return nil, fmt.Errorf("jwt: signer is required")
	}
	public := key.Public()
	if err := jwtint.ValidatePublicKey(public); err != nil {
		return nil, fmt.Errorf("jwt: %w", err)
	}
	public = clonePublicKey(public)
	if algorithm == "" {
		inferred, err := jwtint.InferAlgorithm(public)
		if err != nil {
			return nil, fmt.Errorf("jwt: %w", err)
		}
		algorithm = Algorithm(inferred)
	}
	if !jwtint.SignerSupportsAlgorithm(key, string(algorithm)) {
		return nil, fmt.Errorf("jwt: algorithm %s is incompatible with key type %T", algorithm, public)
	}
	jwk, inferredKID, err := jwtint.PublicJWK(public)
	if err != nil {
		return nil, fmt.Errorf("jwt: %w", err)
	}
	thumb, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("jwt: calculating thumbprint: %w", err)
	}
	if kid == "" {
		kid = inferredKID
	}
	x5c, err := encodeCertificateChain(public, certificates)
	if err != nil {
		return nil, fmt.Errorf("jwt: %w", err)
	}
	var x5tS256 string
	if len(certificates) > 0 {
		thumbprint := sha256.Sum256(certificates[0].Raw)
		x5tS256 = base64.RawURLEncoding.EncodeToString(thumbprint[:])
	}
	return &SigningIdentity{
		signer: key, algorithm: algorithm, kid: kid,
		thumbprint: base64.RawURLEncoding.EncodeToString(thumb),
		x5tS256:    x5tS256, jwk: jwk, x5c: x5c, public: public,
	}, nil
}

func (s *SigningIdentity) signerMarker() {}

func (s *SigningIdentity) SupportsAlgorithm(algorithm Algorithm) bool {
	return s != nil && s.algorithm == algorithm
}

// Algorithm returns this identity's exact signing algorithm.
func (s *SigningIdentity) Algorithm() Algorithm {
	if s == nil {
		return ""
	}
	return s.algorithm
}

// KeyID returns this identity's signer-derived or configured key identifier.
func (s *SigningIdentity) KeyID() string {
	if s == nil {
		return ""
	}
	return s.kid
}

// Thumbprint returns this identity's RFC 7638 SHA-256 thumbprint.
func (s *SigningIdentity) Thumbprint() string {
	if s == nil {
		return ""
	}
	return s.thumbprint
}

// VerificationKey returns the public verification key for this identity.
func (s *SigningIdentity) VerificationKey() VerificationKey {
	if s == nil {
		return VerificationKey{}
	}
	return VerificationKey{Key: clonePublicKey(s.public), Algorithm: s.algorithm, KeyID: s.kid}
}

func (s *SigningIdentity) verificationKeys() []VerificationKey {
	if s == nil {
		return nil
	}
	return []VerificationKey{s.VerificationKey()}
}

// Sign signs with this identity. If Algorithm is omitted, this identity's
// configured algorithm is used; a different algorithm is rejected.
func (s *SigningIdentity) Sign(ctx context.Context, claims any, options SignOptions) (string, error) {
	if s == nil {
		return "", fmt.Errorf("jwt: invalid signing identity")
	}
	if options.Algorithm == "" {
		options.Algorithm = s.algorithm
	}
	if options.Algorithm != s.algorithm {
		return "", fmt.Errorf("jwt: requested algorithm %s does not match signing identity algorithm %s", options.Algorithm, s.algorithm)
	}
	return signWithIdentity(ctx, s, claims, options)
}

// SigningKeySet is an atomically replaceable collection of active signing
// identities, with at most one per algorithm. It never randomly selects among
// identities.
type SigningKeySet struct {
	state atomic.Pointer[signingKeySetState]
}

type signingKeySetState struct {
	identities map[Algorithm]*SigningIdentity
	ordered    []*SigningIdentity
}

// NewSigningKeySet constructs an active set from one or more identities.
func NewSigningKeySet(identities ...*SigningIdentity) (*SigningKeySet, error) {
	state, err := newSigningKeySetState(identities)
	if err != nil {
		return nil, err
	}
	s := new(SigningKeySet)
	s.state.Store(state)
	return s, nil
}

func newSigningKeySetState(identities []*SigningIdentity) (*signingKeySetState, error) {
	if len(identities) == 0 {
		return nil, fmt.Errorf("jwt: at least one signing identity is required")
	}
	set := make(map[Algorithm]*SigningIdentity, len(identities))
	seenKids := make(map[string]struct{}, len(identities))
	seenThumbprints := make(map[string]struct{}, len(identities))
	for i, identity := range identities {
		if identity == nil {
			return nil, fmt.Errorf("jwt: signing identity %d is required", i)
		}
		if _, ok := set[identity.algorithm]; ok {
			return nil, fmt.Errorf("jwt: duplicate active signing algorithm %q", identity.algorithm)
		}
		if _, ok := seenKids[identity.kid]; ok {
			return nil, fmt.Errorf("jwt: duplicate active key ID %q", identity.kid)
		}
		if _, ok := seenThumbprints[identity.thumbprint]; ok {
			return nil, fmt.Errorf("jwt: duplicate active public-key thumbprint")
		}
		set[identity.algorithm] = identity
		seenKids[identity.kid] = struct{}{}
		seenThumbprints[identity.thumbprint] = struct{}{}
	}
	return &signingKeySetState{identities: set, ordered: append([]*SigningIdentity(nil), identities...)}, nil
}

func (s *SigningKeySet) signerMarker() {}

func (s *SigningKeySet) SupportsAlgorithm(algorithm Algorithm) bool {
	if s == nil {
		return false
	}
	state := s.state.Load()
	return state != nil && state.identities[algorithm] != nil
}

// Replace atomically adopts next's active identity snapshot. Publish the new
// verification key set before switching the signer; retain old verification
// keys until tokens signed with them expire, then retire them.
func (s *SigningKeySet) Replace(next *SigningKeySet) error {
	if s == nil || next == nil {
		return fmt.Errorf("jwt: signing key set is required")
	}
	state := next.state.Load()
	if state == nil {
		return fmt.Errorf("jwt: replacement signing key set is invalid")
	}
	s.state.Store(state)
	return nil
}

func (s *SigningKeySet) verificationKeys() []VerificationKey {
	if s == nil {
		return nil
	}
	state := s.state.Load()
	if state == nil {
		return nil
	}
	keys := make([]VerificationKey, 0, len(state.ordered))
	for _, identity := range state.ordered {
		keys = append(keys, identity.VerificationKey())
	}
	return keys
}

// Sign signs using the exact requested algorithm. An omitted algorithm is
// accepted only when this aggregate has one active identity.
func (s *SigningKeySet) Sign(ctx context.Context, claims any, options SignOptions) (string, error) {
	if s == nil {
		return "", fmt.Errorf("jwt: invalid signing key set")
	}
	state := s.state.Load()
	if state == nil {
		return "", fmt.Errorf("jwt: invalid signing key set")
	}
	algorithm := options.Algorithm
	if algorithm == "" {
		if len(state.identities) != 1 {
			return "", fmt.Errorf("jwt: exact algorithm is required for a signing key set with multiple identities")
		}
		for alg := range state.identities {
			algorithm = alg
		}
	}
	identity := state.identities[algorithm]
	if identity == nil {
		return "", fmt.Errorf("jwt: no active signing identity for algorithm %s", algorithm)
	}
	options.Algorithm = algorithm
	return signWithIdentity(ctx, identity, claims, options)
}

func signWithIdentity(ctx context.Context, identity *SigningIdentity, claims any, options SignOptions) (string, error) {
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
	opts := new(jose.SignerOptions)
	if options.Type != "" {
		opts.WithType(jose.ContentType(options.Type))
	}
	if !options.SkipKeyID {
		opts.WithHeader("kid", identity.kid)
	}
	if options.IncludeJWK {
		opts.WithHeader("jwk", identity.jwk)
	}
	switch options.Certificates {
	case RequireCertificates:
		if len(identity.x5c) == 0 {
			return "", fmt.Errorf("jwt: key %q has no certificate chain", identity.kid)
		}
		fallthrough
	case IncludeCertificatesIfAvailable:
		if len(identity.x5c) != 0 {
			opts.WithHeader("x5c", identity.x5c)
		}
	case OmitCertificates:
	default:
		return "", fmt.Errorf("jwt: unknown certificate mode %d", options.Certificates)
	}
	if options.CertificateThumbprint {
		if len(identity.x5c) == 0 {
			return "", fmt.Errorf("jwt: key %q has no certificate chain", identity.kid)
		}
		opts.WithHeader("x5t#S256", identity.x5tS256)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.SignatureAlgorithm(identity.algorithm), Key: cryptosigner.Opaque(identity.signer)}, opts)
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
