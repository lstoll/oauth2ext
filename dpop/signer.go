package dpop

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	jsonv2 "encoding/json/v2"
	"fmt"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/cryptosigner"
)

// ProofOptions contains the claims used to create a DPoP proof. IssuedAt and
// JWTID are generated when omitted.
type ProofOptions struct {
	HTTPMethod string
	HTTPURI    string
	IssuedAt   time.Time
	JWTID      string
	Nonce      string
	// AccessToken, when set, is hashed into the ath claim.
	AccessToken string
}

// Signer signs DPoP proofs with a crypto.Signer.
type Signer struct {
	signer crypto.Signer
	jwk    map[string]any
	thumb  string
	x5c    []string
}

// NewSigner creates a Signer using signer. The key must be an RSA key of at
// least 2048 bits or an ECDSA P-256, P-384, or P-521 key.
func NewSigner(signer crypto.Signer) (*Signer, error) {
	if signer == nil {
		return nil, fmt.Errorf("dpop: signer is required")
	}
	if _, err := determineAlgorithmFromKey(signer.Public()); err != nil {
		return nil, err
	}
	jwk, err := publicKeyToJWK(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("creating JWK: %w", err)
	}
	thumbprint, err := calculateJWKThumbprint(jwk)
	if err != nil {
		return nil, fmt.Errorf("calculating JWK thumbprint: %w", err)
	}
	return &Signer{signer: signer, jwk: jwk, thumb: thumbprint}, nil
}

// Thumbprint returns the RFC 7638 SHA-256 thumbprint of the signing key.
func (s *Signer) Thumbprint() (string, error) {
	if s == nil || s.thumb == "" {
		return "", fmt.Errorf("dpop: invalid signer")
	}
	return s.thumb, nil
}

// NewSignerWithCertificateChain returns a Signer that includes an x5c header.
// The leaf certificate must contain the signer's public key.
//
// This is an experimental, non-standard DPoP extension intended for enterprise
// deployments. Sending a certificate chain can disclose identifying data.
func NewSignerWithCertificateChain(signer crypto.Signer, chain []*x509.Certificate) (*Signer, error) {
	if signer == nil {
		return nil, fmt.Errorf("dpop: signer is required")
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("certificate chain is empty")
	}
	if !leafCertMatchesSigner(chain[0], signer.Public()) {
		return nil, fmt.Errorf("leaf certificate public key does not match signer")
	}
	s, err := NewSigner(signer)
	if err != nil {
		return nil, err
	}
	s.x5c = make([]string, len(chain))
	for i, certificate := range chain {
		s.x5c[i] = base64.StdEncoding.EncodeToString(certificate.Raw)
	}
	return s, nil
}

func leafCertMatchesSigner(leaf *x509.Certificate, publicKey crypto.PublicKey) bool {
	if leaf == nil {
		return false
	}
	switch certificateKey := leaf.PublicKey.(type) {
	case *ecdsa.PublicKey:
		signerKey, ok := publicKey.(*ecdsa.PublicKey)
		return ok && certificateKey.Equal(signerKey)
	case *rsa.PublicKey:
		signerKey, ok := publicKey.(*rsa.PublicKey)
		return ok && certificateKey.Equal(signerKey)
	default:
		return false
	}
}

// SignAndEncode creates and signs a compact DPoP proof.
func (s *Signer) SignAndEncode(options ProofOptions) (string, error) {
	if s == nil || s.signer == nil {
		return "", fmt.Errorf("dpop: invalid signer")
	}
	if options.HTTPMethod == "" {
		return "", fmt.Errorf("dpop: HTTPMethod is required")
	}
	if options.HTTPURI == "" {
		return "", fmt.Errorf("dpop: HTTPURI is required")
	}
	if options.IssuedAt.IsZero() {
		options.IssuedAt = time.Now()
	}
	if options.JWTID == "" {
		options.JWTID = rand.Text()
	}
	payload := map[string]any{
		"jti": options.JWTID,
		"htm": options.HTTPMethod,
		"htu": options.HTTPURI,
		"iat": float64(options.IssuedAt.Unix()) + float64(options.IssuedAt.Nanosecond())/float64(time.Second),
	}
	if options.Nonce != "" {
		payload["nonce"] = options.Nonce
	}
	if options.AccessToken != "" {
		payload["ath"] = hashAccessToken(options.AccessToken)
	}
	return s.signPayload(payload, nil, true)
}

func hashAccessToken(accessToken string) string {
	digest := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

// signPayload exists for malformed-proof tests. defaultHeaders controls whether
// the signer's jwk and x5c values are included.
func (s *Signer) signPayload(payload map[string]any, headers map[string]any, defaultHeaders bool) (string, error) {
	algorithm, err := determineAlgorithmFromKey(s.signer.Public())
	if err != nil {
		return "", fmt.Errorf("determining algorithm: %w", err)
	}
	signerOptions := new(jose.SignerOptions).WithType("dpop+jwt")
	if defaultHeaders {
		signerOptions.WithHeader("jwk", s.jwk)
		if len(s.x5c) > 0 {
			signerOptions.WithHeader("x5c", s.x5c)
		}
	}
	for name, value := range headers {
		signerOptions.WithHeader(jose.HeaderKey(name), value)
	}
	jwsSigner, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.SignatureAlgorithm(algorithm),
		Key:       cryptosigner.Opaque(s.signer),
	}, signerOptions)
	if err != nil {
		return "", fmt.Errorf("creating JWS signer: %w", err)
	}
	payloadJSON, err := jsonv2.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("encoding payload: %w", err)
	}
	signed, err := jwsSigner.Sign(payloadJSON)
	if err != nil {
		return "", fmt.Errorf("signing: %w", err)
	}
	compact, err := signed.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("serializing proof: %w", err)
	}
	return compact, nil
}
