// Package jwt provides a JWT verifier implementation that validates x5c certificate chains.
package jwt

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"github.com/tink-crypto/tink-go/v2/jwt"
)

var _ jwt.Verifier = (*X5CDecoder)(nil)

// X5CDecoder verifies JWTs using x5c certificate chains validated against a trusted root bundle.
type X5CDecoder struct {
	// TrustedRoots is the certificate pool containing trusted root CAs.
	// If nil, the system certificate pool will be used.
	TrustedRoots *x509.CertPool
}

// NewX5CDecoder creates a new X5CDecoder with the given trusted root certificates.
// If trustedRoots is nil, the system certificate pool will be used.
func NewX5CDecoder(trustedRoots *x509.CertPool) *X5CDecoder {
	return &X5CDecoder{
		TrustedRoots: trustedRoots,
	}
}

// VerifyAndDecode implements the tink jwt.Verifier interface.
// It validates the JWT signature using the x5c certificate chain.
func (d *X5CDecoder) VerifyAndDecode(compact string, validator *jwt.Validator) (*jwt.VerifiedJWT, error) {
	// Step 1: Parse the JWT header to extract x5c
	header, err := parseJWTHeader(compact)
	if err != nil {
		return nil, fmt.Errorf("parsing JWT header: %w", err)
	}

	// Step 2: Check for x5c header - fail immediately if not present
	x5c, ok := header["x5c"].([]any)
	if !ok || len(x5c) == 0 {
		return nil, fmt.Errorf("x5c header is missing or empty")
	}

	// Step 3: Parse and verify the certificate chain
	certChain, err := d.parseAndVerifyCertChain(x5c)
	if err != nil {
		return nil, fmt.Errorf("verifying certificate chain: %w", err)
	}

	// Step 4: Extract public key from the first certificate (leaf cert)
	leafCert := certChain[0]
	pubKey := leafCert.PublicKey

	// Step 5: Create a keyset handle from the public key
	handle, err := createKeysetHandleFromPublicKey(pubKey, header)
	if err != nil {
		return nil, fmt.Errorf("creating keyset handle: %w", err)
	}

	// Step 6: Use tink verifier to verify the signature and decode
	verifier, err := jwt.NewVerifier(handle)
	if err != nil {
		return nil, fmt.Errorf("creating tink verifier: %w", err)
	}

	verifiedJWT, err := verifier.VerifyAndDecode(compact, validator)
	if err != nil {
		return nil, fmt.Errorf("verifying JWT: %w", err)
	}

	return verifiedJWT, nil
}

// parseAndVerifyCertChain parses the x5c certificate chain and verifies it against trusted roots.
func (d *X5CDecoder) parseAndVerifyCertChain(x5c []any) ([]*x509.Certificate, error) {
	// Parse certificates from base64 strings
	certs := make([]*x509.Certificate, 0, len(x5c))
	for i, certB64 := range x5c {
		certStr, ok := certB64.(string)
		if !ok {
			return nil, fmt.Errorf("x5c[%d] is not a string", i)
		}

		certDER, err := base64.StdEncoding.DecodeString(certStr)
		if err != nil {
			return nil, fmt.Errorf("decoding x5c[%d]: %w", i, err)
		}

		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			return nil, fmt.Errorf("parsing x5c[%d]: %w", i, err)
		}

		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates in x5c chain")
	}

	// Verify the certificate chain
	// The first certificate is the leaf, the rest form the chain
	leafCert := certs[0]
	intermediates := certs[1:]

	// Build options for verification
	opts := x509.VerifyOptions{
		Intermediates: x509.NewCertPool(),
	}

	// Add intermediate certificates to the pool
	for _, intermediate := range intermediates {
		opts.Intermediates.AddCert(intermediate)
	}

	// Set trusted roots
	if d.TrustedRoots != nil {
		opts.Roots = d.TrustedRoots
	} else {
		// Use system certificate pool
		systemRoots, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("getting system cert pool: %w", err)
		}
		opts.Roots = systemRoots
	}

	// Verify the chain
	_, err := leafCert.Verify(opts)
	if err != nil {
		return nil, fmt.Errorf("certificate chain verification failed: %w", err)
	}

	return certs, nil
}
