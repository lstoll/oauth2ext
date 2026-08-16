package clientjwt

import (
	"context"
	"fmt"
	"time"
	"uuid"

	"lds.li/oauth2ext/jwt"
)

const (
	// AssertionType is the client_assertion_type value for JWT client
	// authentication.
	AssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	// AuthMethod is the OIDC token_endpoint_auth_method for this package.
	AuthMethod = "private_key_jwt"
	// DefaultTTL is the lifetime of a freshly minted assertion.
	DefaultTTL = time.Minute
)

// SignOptions controls one private_key_jwt client assertion. Zero IssuedAt
// and Expiry use the current time and DefaultTTL. Empty JWTID is generated.
type SignOptions struct {
	ClientID string
	Audience string
	// CertificateThumbprint requests an x5t#S256 JOSE header from the
	// configured signing identity. It fails when the signer has no certificate.
	CertificateThumbprint bool
	// Algorithm is the exact signing algorithm registered with the
	// authorization server.
	Algorithm jwt.Algorithm
	IssuedAt  time.Time
	Expiry    time.Time
	JWTID     string
}

// Sign creates a private_key_jwt client assertion with signer-owned JOSE
// headers and key material. The core jwt package performs all JWS encoding.
func Sign(ctx context.Context, signer jwt.Signer, options SignOptions) (string, error) {
	if signer == nil {
		return "", fmt.Errorf("clientjwt: signer is required")
	}
	if options.ClientID == "" {
		return "", fmt.Errorf("clientjwt: ClientID is required")
	}
	if options.Audience == "" {
		return "", fmt.Errorf("clientjwt: Audience is required")
	}
	if options.Algorithm == "" {
		return "", fmt.Errorf("clientjwt: Algorithm is required")
	}
	if !signer.SupportsAlgorithm(options.Algorithm) {
		return "", fmt.Errorf("clientjwt: signer does not support algorithm %s", options.Algorithm)
	}
	now := time.Now()
	if options.IssuedAt.IsZero() {
		options.IssuedAt = now
	}
	if options.Expiry.IsZero() {
		options.Expiry = options.IssuedAt.Add(DefaultTTL)
	}
	if !options.Expiry.After(options.IssuedAt) {
		return "", fmt.Errorf("clientjwt: Expiry must be after IssuedAt")
	}
	if options.JWTID == "" {
		options.JWTID = uuid.NewV4().String()
	}
	if options.JWTID == "" {
		return "", fmt.Errorf("clientjwt: JWTID is required")
	}

	return signer.Sign(ctx, map[string]any{
		"iss": options.ClientID,
		"sub": options.ClientID,
		"aud": options.Audience,
		"jti": options.JWTID,
		"iat": options.IssuedAt.Unix(),
		"exp": options.Expiry.Unix(),
	}, jwt.SignOptions{Algorithm: options.Algorithm, CertificateThumbprint: options.CertificateThumbprint})
}
