package dpop

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	jsonv2 "encoding/json/v2"
	"fmt"
	"math"
	"slices"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

const (
	// DefaultValidityAfterIssue is the default maximum age of a DPoP proof.
	DefaultValidityAfterIssue = 10 * time.Minute
	// DefaultClockSkew is the default allowance for clock differences.
	DefaultClockSkew = time.Minute
	// MaxClockSkew is the largest accepted clock-skew allowance.
	MaxClockSkew = 10 * time.Minute
)

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

	now time.Time
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
		cloned.ExpectedHTU = new(*opts.ExpectedHTU)
	}
	if opts.ExpectedAccessToken != "" {
		cloned.ExpectedAccessToken = opts.ExpectedAccessToken
	}
	return &Validator{opts: cloned}, nil
}

// VerifyAndDecode verifies a compact DPoP proof and applies validator.
func (v *Verifier) VerifyAndDecode(compact string, validator *Validator) (*Proof, error) {
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

	var publicKey any
	var thumbprint string
	var certificateChain []*x509.Certificate
	if v.TrustedRoots == nil {
		thumbprint, publicKey, err = verifyMaterialFromJWK(header)
	} else {
		thumbprint, publicKey, certificateChain, err = v.verifyMaterialFromX5C(header)
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

	signed, err := jose.ParseSigned(compact, []jose.SignatureAlgorithm{jose.SignatureAlgorithm(algorithm)})
	if err != nil {
		return nil, fmt.Errorf("parsing signed proof: %w", err)
	}
	if len(signed.Signatures) != 1 {
		return nil, fmt.Errorf("DPoP proof must have exactly one signature")
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
	return proof, nil
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
		if proof.HTTPURI != *opts.ExpectedHTU {
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

func parsePublicJWK(value any) (*jose.JSONWebKey, error) {
	object, ok := value.(map[string]any)
	if !ok || len(object) == 0 {
		return nil, fmt.Errorf("jwk header is missing")
	}
	encoded, err := jsonv2.Marshal(object)
	if err != nil {
		return nil, fmt.Errorf("marshaling jwk: %w", err)
	}
	var key jose.JSONWebKey
	if err := jsonv2.Unmarshal(encoded, &key); err != nil {
		return nil, fmt.Errorf("parsing jwk: %w", err)
	}
	if !key.Valid() || !key.IsPublic() {
		return nil, fmt.Errorf("jwk must be a valid public key")
	}
	return &key, nil
}

func jwkThumbprint(key *jose.JSONWebKey) (string, error) {
	thumbprint, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(thumbprint), nil
}

func verifyMaterialFromJWK(header map[string]any) (string, any, error) {
	key, err := parsePublicJWK(header["jwk"])
	if err != nil {
		return "", nil, err
	}
	thumbprint, err := jwkThumbprint(key)
	if err != nil {
		return "", nil, fmt.Errorf("calculating JWK thumbprint: %w", err)
	}
	return thumbprint, key.Key, nil
}

func (v *Verifier) verifyMaterialFromX5C(header map[string]any) (string, any, []*x509.Certificate, error) {
	x5c, ok := header["x5c"].([]any)
	if !ok || len(x5c) == 0 {
		return "", nil, nil, fmt.Errorf("x5c header is required when Verifier.TrustedRoots is set")
	}
	chain, err := parseAndVerifyCertChain(v.TrustedRoots, x5c)
	if err != nil {
		return "", nil, nil, fmt.Errorf("verifying certificate chain: %w", err)
	}
	leafJWK := &jose.JSONWebKey{Key: chain[0].PublicKey}
	thumbprint, err := jwkThumbprint(leafJWK)
	if err != nil {
		return "", nil, nil, fmt.Errorf("calculating JWK thumbprint: %w", err)
	}
	if value, ok := header["jwk"]; ok {
		headerJWK, err := parsePublicJWK(value)
		if err != nil {
			return "", nil, nil, err
		}
		headerThumbprint, err := jwkThumbprint(headerJWK)
		if err != nil {
			return "", nil, nil, err
		}
		if headerThumbprint != thumbprint {
			return "", nil, nil, fmt.Errorf("jwk does not match x5c leaf certificate public key")
		}
	}
	return thumbprint, chain[0].PublicKey, chain, nil
}

func validateAlgorithmKey(algorithm string, key any) error {
	switch publicKey := key.(type) {
	case *rsa.PublicKey:
		if algorithm != "RS256" && algorithm != "RS384" && algorithm != "RS512" {
			return fmt.Errorf("algorithm %q does not match RSA key", algorithm)
		}
		if _, err := determineAlgorithmFromKey(publicKey); err != nil {
			return err
		}
	case *ecdsa.PublicKey:
		want, err := determineAlgorithmFromKey(publicKey)
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

func parseAndVerifyCertChain(roots *x509.CertPool, encoded []any) ([]*x509.Certificate, error) {
	if roots == nil {
		return nil, fmt.Errorf("trusted roots are not set")
	}
	certificates := make([]*x509.Certificate, 0, len(encoded))
	for i, value := range encoded {
		text, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("x5c[%d] is not a string", i)
		}
		der, err := base64.StdEncoding.DecodeString(text)
		if err != nil {
			return nil, fmt.Errorf("decoding x5c[%d]: %w", i, err)
		}
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("parsing x5c[%d]: %w", i, err)
		}
		certificates = append(certificates, certificate)
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range certificates[1:] {
		intermediates.AddCert(certificate)
	}
	if _, err := certificates[0].Verify(x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         roots,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, fmt.Errorf("certificate chain verification failed: %w", err)
	}
	return certificates, nil
}
