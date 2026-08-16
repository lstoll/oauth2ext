package dpop

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"math"
	"slices"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	jwtint "lds.li/oauth2ext/internal/jwt"
)

const (
	// DefaultValidityAfterIssue is the default maximum age of a DPoP proof.
	DefaultValidityAfterIssue = 10 * time.Minute
	// DefaultClockSkew is the default allowance for clock differences.
	DefaultClockSkew = time.Minute
	// MaxClockSkew is the largest accepted clock-skew allowance.
	MaxClockSkew = 10 * time.Minute
)

// Verifier validates DPoP proofs and records accepted proofs for replay
// protection. Configure a Verifier before its first use. It is safe for
// concurrent use after configuration, but must not be copied or mutated after
// verification begins.
type Verifier struct {
	// ValidityAfterIssue is the maximum age of a DPoP proof. It defaults to
	// DefaultValidityAfterIssue.
	ValidityAfterIssue time.Duration
	// ClockSkew is the clock-difference allowance. It defaults to
	// DefaultClockSkew and is capped at MaxClockSkew.
	ClockSkew time.Duration

	// TrustedRoots, when non-nil, requires and validates an x5c header. When
	// nil, the proof is verified with its embedded jwk header.
	TrustedRoots *x509.CertPool

	// ReplayStore atomically detects reused proofs. Nil uses a bounded,
	// process-local in-memory store; multi-replica deployments must provide a
	// shared store for cross-node replay protection.
	ReplayStore ReplayStore
	// ReplayCacheMaxEntries bounds the default in-memory ReplayStore. It
	// defaults to DefaultReplayCacheMaxEntries and is used on first verification.
	// Size it for the maximum proofs accepted during the configured validity
	// window; reaching the limit fails closed.
	ReplayCacheMaxEntries int
	// DisableReplayProtection explicitly permits proof reuse. It should only be
	// used where replay protection is provided by another trusted layer.
	DisableReplayProtection bool

	now                time.Time
	replayMu           sync.Mutex
	defaultReplayStore ReplayStore
}

// Proof is a verified DPoP proof.
type Proof struct {
	Thumbprint       string
	CertificateChain []*x509.Certificate
	JWTID            string
	HTTPMethod       string
	HTTPURI          string
	IssuedAt         time.Time
	ExpiresAt        *time.Time
	Nonce            string
	AccessTokenHash  string
}

// ValidatorOpts contains request-specific DPoP checks.
type ValidatorOpts struct {
	ExpectedThumbprint string
	IgnoreThumbprint   bool
	ExpectedHTM        *string
	ExpectedHTU        *string
	// ExpectedAccessToken, when non-empty, requires ath to be the SHA-256
	// hash of this exact access token. Resource servers should set this when
	// validating a DPoP-bound access token.
	ExpectedAccessToken string
}

type Validator struct {
	opts ValidatorOpts
}

func NewValidator(opts *ValidatorOpts) (*Validator, error) {
	if opts == nil {
		return nil, fmt.Errorf("dpop: validator options are required")
	}
	if (opts.ExpectedThumbprint != "") == opts.IgnoreThumbprint {
		return nil, fmt.Errorf("dpop: exactly one of ExpectedThumbprint and IgnoreThumbprint must be set")
	}
	if opts.ExpectedHTM != nil && *opts.ExpectedHTM == "" {
		return nil, fmt.Errorf("dpop: ExpectedHTM must not be empty")
	}
	if opts.ExpectedHTU != nil && *opts.ExpectedHTU == "" {
		return nil, fmt.Errorf("dpop: ExpectedHTU must not be empty")
	}
	cloned := *opts
	if opts.ExpectedHTM != nil {
		cloned.ExpectedHTM = new(*opts.ExpectedHTM)
	}
	if opts.ExpectedHTU != nil {
		normalized, err := normalizeHTU(*opts.ExpectedHTU)
		if err != nil {
			return nil, fmt.Errorf("dpop: invalid ExpectedHTU: %w", err)
		}
		cloned.ExpectedHTU = new(normalized)
	}
	if opts.ExpectedAccessToken != "" {
		cloned.ExpectedAccessToken = opts.ExpectedAccessToken
	}
	return &Validator{opts: cloned}, nil
}

// VerifyAndDecode verifies a compact DPoP proof and applies validator.
func (v *Verifier) VerifyAndDecode(compact string, validator *Validator) (*Proof, error) {
	return v.VerifyAndDecodeContext(context.Background(), compact, validator)
}

// VerifyAndDecodeContext verifies a compact DPoP proof, applies validator,
// and atomically records it for replay protection.
func (v *Verifier) VerifyAndDecodeContext(ctx context.Context, compact string, validator *Validator) (*Proof, error) {
	if v == nil {
		return nil, fmt.Errorf("dpop: verifier is nil")
	}
	if validator == nil {
		return nil, fmt.Errorf("dpop: validator is nil")
	}
	header, err := parseJWTHeader(compact)
	if err != nil {
		return nil, fmt.Errorf("parsing JWT header: %w", err)
	}
	algorithm, err := requiredHeaderString(header, "alg")
	if err != nil {
		return nil, err
	}
	if typ, err := requiredHeaderString(header, "typ"); err != nil {
		return nil, err
	} else if typ != "dpop+jwt" {
		return nil, fmt.Errorf("typ header mismatch: got %q, want %q", typ, "dpop+jwt")
	}
	for _, forbidden := range []string{"crit", "jku", "x5u"} {
		if _, ok := header[forbidden]; ok {
			return nil, fmt.Errorf("unsupported %s header", forbidden)
		}
	}

	signed, err := jose.ParseSigned(compact, []jose.SignatureAlgorithm{jose.SignatureAlgorithm(algorithm)})
	if err != nil {
		return nil, fmt.Errorf("parsing signed proof: %w", err)
	}
	if len(signed.Signatures) != 1 {
		return nil, fmt.Errorf("DPoP proof must have exactly one signature")
	}
	protected := signed.Signatures[0].Protected

	var publicKey any
	var thumbprint string
	var certificateChain []*x509.Certificate
	if v.TrustedRoots == nil {
		thumbprint, publicKey, err = verifyMaterialFromJWK(protected.JSONWebKey)
	} else {
		thumbprint, publicKey, certificateChain, err = v.verifyMaterialFromX5C(protected)
	}
	if err != nil {
		return nil, err
	}
	if err := validateAlgorithmKey(algorithm, publicKey); err != nil {
		return nil, err
	}
	if !validator.opts.IgnoreThumbprint && thumbprint != validator.opts.ExpectedThumbprint {
		return nil, fmt.Errorf("JWK thumbprint mismatch: got %q, want %q", thumbprint, validator.opts.ExpectedThumbprint)
	}

	payloadJSON, err := signed.Verify(publicKey)
	if err != nil {
		return nil, fmt.Errorf("verifying JWT: %w", err)
	}
	var claims map[string]any
	if err := jsonv2.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, fmt.Errorf("decoding DPoP claims: %w", err)
	}
	if claims == nil {
		return nil, fmt.Errorf("DPoP payload is not an object")
	}

	clockSkew, err := v.clockSkew()
	if err != nil {
		return nil, err
	}
	proof, err := validateProofClaims(claims, validator.opts, v.validationTime(), v.validity(), clockSkew)
	if err != nil {
		return nil, err
	}
	proof.Thumbprint = thumbprint
	proof.CertificateChain = slices.Clone(certificateChain)
	if !v.DisableReplayProtection {
		deadline := proof.IssuedAt.Add(v.validity()).Add(clockSkew)
		if proof.ExpiresAt != nil {
			expiryDeadline := proof.ExpiresAt.Add(clockSkew)
			if expiryDeadline.Before(deadline) {
				deadline = expiryDeadline
			}
		}
		if err := v.replayStore().CheckAndRecord(ctx, proof.Thumbprint, proof.JWTID, deadline); err != nil {
			return nil, fmt.Errorf("recording DPoP proof for replay protection: %w", err)
		}
	}
	return proof, nil
}

func (v *Verifier) replayStore() ReplayStore {
	if v.ReplayStore != nil {
		return v.ReplayStore
	}
	v.replayMu.Lock()
	defer v.replayMu.Unlock()
	if v.defaultReplayStore == nil {
		maxEntries := v.ReplayCacheMaxEntries
		if maxEntries == 0 {
			maxEntries = DefaultReplayCacheMaxEntries
		}
		// A non-positive configured capacity cannot safely provide replay
		// protection, so install a store that fails closed.
		if maxEntries < 0 {
			v.defaultReplayStore = replayStoreError{fmt.Errorf("dpop: ReplayCacheMaxEntries must be positive")}
		} else {
			v.defaultReplayStore = newInMemoryReplayStore(maxEntries)
		}
	}
	return v.defaultReplayStore
}

type replayStoreError struct{ err error }

func (s replayStoreError) CheckAndRecord(context.Context, string, string, time.Time) error {
	return s.err
}

func (v *Verifier) validationTime() time.Time {
	if !v.now.IsZero() {
		return v.now
	}
	return time.Now()
}

func (v *Verifier) validity() time.Duration {
	if v.ValidityAfterIssue == 0 {
		return DefaultValidityAfterIssue
	}
	return v.ValidityAfterIssue
}

func (v *Verifier) clockSkew() (time.Duration, error) {
	if v.ClockSkew < 0 || v.ClockSkew > MaxClockSkew {
		return 0, fmt.Errorf("dpop: ClockSkew must be between 0 and %s", MaxClockSkew)
	}
	if v.ClockSkew == 0 {
		return DefaultClockSkew, nil
	}
	return v.ClockSkew, nil
}

func validateProofClaims(claims map[string]any, opts ValidatorOpts, now time.Time, validity, clockSkew time.Duration) (*Proof, error) {
	if validity < 0 {
		return nil, fmt.Errorf("dpop: ValidityAfterIssue must not be negative")
	}
	jti, err := requiredStringClaim(claims, "jti")
	if err != nil {
		return nil, err
	}
	iat, err := requiredNumericDate(claims, "iat")
	if err != nil {
		return nil, err
	}
	if iat.After(now.Add(clockSkew)) {
		return nil, fmt.Errorf("iat claim is in the future")
	}
	if now.After(iat.Add(validity).Add(clockSkew)) {
		return nil, fmt.Errorf("token expired")
	}

	proof := &Proof{JWTID: jti, IssuedAt: iat}
	if value, ok := claims["exp"]; ok {
		expiresAt, err := numericDate(value, "exp")
		if err != nil {
			return nil, err
		}
		if now.After(expiresAt.Add(clockSkew)) {
			return nil, fmt.Errorf("token expired")
		}
		proof.ExpiresAt = &expiresAt
	}
	proof.HTTPMethod, err = requiredStringClaim(claims, "htm")
	if err != nil {
		return nil, err
	}
	proof.HTTPURI, err = requiredStringClaim(claims, "htu")
	if err != nil {
		return nil, err
	}
	proof.Nonce, err = optionalStringClaim(claims, "nonce")
	if err != nil {
		return nil, err
	}
	proof.AccessTokenHash, err = optionalStringClaim(claims, "ath")
	if err != nil {
		return nil, err
	}
	if opts.ExpectedHTM != nil {
		if proof.HTTPMethod != *opts.ExpectedHTM {
			return nil, fmt.Errorf("htm claim mismatch: got %q, want %q", proof.HTTPMethod, *opts.ExpectedHTM)
		}
	}
	if opts.ExpectedHTU != nil {
		normalized, err := normalizeHTU(proof.HTTPURI)
		if err != nil {
			return nil, fmt.Errorf("invalid htu claim: %w", err)
		}
		if normalized != *opts.ExpectedHTU {
			return nil, fmt.Errorf("htu claim mismatch: got %q, want %q", proof.HTTPURI, *opts.ExpectedHTU)
		}
	}
	if opts.ExpectedAccessToken != "" {
		want := hashAccessToken(opts.ExpectedAccessToken)
		if proof.AccessTokenHash == "" || subtle.ConstantTimeCompare([]byte(proof.AccessTokenHash), []byte(want)) != 1 {
			return nil, fmt.Errorf("ath claim mismatch")
		}
	}
	return proof, nil
}

func requiredHeaderString(header map[string]any, name string) (string, error) {
	value, ok := header[name]
	if !ok {
		return "", fmt.Errorf("%s header is missing", name)
	}
	text, ok := value.(string)
	if !ok || text == "" {
		return "", fmt.Errorf("%s header is not a non-empty string", name)
	}
	return text, nil
}

func requiredStringClaim(claims map[string]any, name string) (string, error) {
	value, err := optionalStringClaim(claims, name)
	if err != nil {
		return "", err
	}
	if value == "" {
		return "", fmt.Errorf("%s claim is required", name)
	}
	return value, nil
}

func optionalStringClaim(claims map[string]any, name string) (string, error) {
	value, ok := claims[name]
	if !ok {
		return "", nil
	}
	text, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("%s claim is not a string", name)
	}
	return text, nil
}

func requiredNumericDate(claims map[string]any, name string) (time.Time, error) {
	value, ok := claims[name]
	if !ok {
		return time.Time{}, fmt.Errorf("%s claim is required", name)
	}
	return numericDate(value, name)
}

func numericDate(value any, name string) (time.Time, error) {
	number, ok := value.(float64)
	if !ok || math.IsNaN(number) || math.IsInf(number, 0) {
		return time.Time{}, fmt.Errorf("%s claim is not a JSON number", name)
	}
	seconds, fraction := math.Modf(number)
	if seconds < math.MinInt64 || seconds >= math.MaxInt64 {
		return time.Time{}, fmt.Errorf("%s claim is outside the supported range", name)
	}
	return time.Unix(int64(seconds), int64(fraction*float64(time.Second))), nil
}

func jwkThumbprint(key *jose.JSONWebKey) (string, error) {
	thumbprint, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(thumbprint), nil
}

func verifyMaterialFromJWK(key *jose.JSONWebKey) (string, any, error) {
	if key == nil {
		return "", nil, fmt.Errorf("jwk header is missing")
	}
	if !key.Valid() || !key.IsPublic() {
		return "", nil, fmt.Errorf("jwk must be a valid public key")
	}
	thumbprint, err := jwkThumbprint(key)
	if err != nil {
		return "", nil, fmt.Errorf("calculating JWK thumbprint: %w", err)
	}
	return thumbprint, key.Key, nil
}

func (v *Verifier) verifyMaterialFromX5C(header jose.Header) (string, any, []*x509.Certificate, error) {
	chains, err := header.Certificates(x509.VerifyOptions{
		Roots:     v.TrustedRoots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		if errors.Is(err, jose.ErrMissingX5cHeader) {
			return "", nil, nil, fmt.Errorf("x5c header is required when Verifier.TrustedRoots is set")
		}
		return "", nil, nil, fmt.Errorf("verifying certificate chain: certificate chain verification failed: %w", err)
	}
	if len(chains) == 0 || len(chains[0]) == 0 {
		return "", nil, nil, fmt.Errorf("verifying certificate chain: certificate chain verification failed")
	}
	chain := chains[0]
	thumbprint, err := jwkThumbprint(&jose.JSONWebKey{Key: chain[0].PublicKey})
	if err != nil {
		return "", nil, nil, fmt.Errorf("calculating JWK thumbprint: %w", err)
	}
	if err := requireOptionalJWKMatchesLeaf(header.JSONWebKey, chain[0].PublicKey); err != nil {
		return "", nil, nil, err
	}
	return thumbprint, chain[0].PublicKey, chain, nil
}

func requireOptionalJWKMatchesLeaf(jwk *jose.JSONWebKey, leaf crypto.PublicKey) error {
	if jwk == nil {
		return nil
	}
	if !jwk.Valid() || !jwk.IsPublic() {
		return fmt.Errorf("jwk must be a valid public key")
	}
	pub, ok := jwk.Key.(crypto.PublicKey)
	if !ok {
		return fmt.Errorf("jwk must be a valid public key")
	}
	eq, ok := pub.(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !eq.Equal(leaf) {
		return fmt.Errorf("jwk does not match x5c leaf certificate public key")
	}
	return nil
}

func validateAlgorithmKey(algorithm string, key any) error {
	publicKey, ok := key.(crypto.PublicKey)
	if !ok {
		return fmt.Errorf("unsupported DPoP public key type %T", key)
	}
	if err := jwtint.ValidatePublicKey(publicKey); err != nil {
		return err
	}
	switch publicKey.(type) {
	case *rsa.PublicKey:
		if algorithm != "RS256" && algorithm != "RS384" && algorithm != "RS512" {
			return fmt.Errorf("algorithm %q does not match RSA key", algorithm)
		}
	case *ecdsa.PublicKey:
		want, err := jwtint.InferAlgorithm(publicKey)
		if err != nil {
			return err
		}
		if algorithm != want {
			return fmt.Errorf("algorithm %q does not match ECDSA key; want %q", algorithm, want)
		}
	default:
		return fmt.Errorf("unsupported DPoP public key type %T", key)
	}
	return nil
}
