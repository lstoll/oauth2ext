package jwt

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"

	"github.com/tink-crypto/tink-go/v2/jwt"
)

// generateTestCert creates a simple self-signed x509 certificate for testing
func generateTestCert(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate) {
	// Generate a private key
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	// Create a certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Test Org"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"Test City"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Create a self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return privKey, cert
}

func TestEncoder_WithX5CHeader(t *testing.T) {
	// Generate a test certificate
	privKey, cert := generateTestCert(t)

	// Create an encoder with the certificate chain
	encoder := &Encoder{
		KID:       "test-key-id",
		Signer:    privKey,
		CertChain: []*x509.Certificate{cert},
	}

	// Create a simple JWT payload
	now := time.Now()
	opts := &jwt.RawJWTOptions{
		Issuer:    stringPtr("test-issuer"),
		Subject:   stringPtr("test-subject"),
		Audience:  stringPtr("test-audience"),
		IssuedAt:  &now,
		ExpiresAt: timePtr(now.Add(1 * time.Hour)),
	}

	rawJWT, err := jwt.NewRawJWT(opts)
	if err != nil {
		t.Fatalf("failed to create raw JWT: %v", err)
	}

	// Sign and encode the JWT
	token, err := encoder.SignAndEncode(rawJWT)
	if err != nil {
		t.Fatalf("failed to sign and encode JWT: %v", err)
	}

	// Verify the token is not empty
	if token == "" {
		t.Fatal("encoded token is empty")
	}

	// Verify the token has the expected format (header.payload.signature)
	parts := splitToken(token)
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts in JWT, got %d", len(parts))
	}

	// Decode and verify the header contains x5c
	headerJSON, err := base64Decode(parts[0])
	if err != nil {
		t.Fatalf("failed to decode header: %v", err)
	}

	var header map[string]any
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatalf("failed to unmarshal header: %v", err)
	}

	// Verify x5c header is present
	x5c, ok := header["x5c"].([]any)
	if !ok {
		t.Fatal("x5c header is missing or has wrong type")
	}

	if len(x5c) != 1 {
		t.Fatalf("expected 1 certificate in x5c, got %d", len(x5c))
	}

	// Verify the certificate in x5c matches our certificate
	certB64, ok := x5c[0].(string)
	if !ok {
		t.Fatal("x5c certificate is not a string")
	}

	// Decode and compare
	decodedCertDER, err := base64.StdEncoding.DecodeString(certB64)
	if err != nil {
		t.Fatalf("failed to decode x5c certificate: %v", err)
	}

	decodedCert, err := x509.ParseCertificate(decodedCertDER)
	if err != nil {
		t.Fatalf("failed to parse decoded certificate: %v", err)
	}

	if !decodedCert.Equal(cert) {
		t.Fatal("decoded certificate does not match original certificate")
	}

	t.Logf("Successfully encoded JWT with x5c header: %s", token[:50]+"...")
}

func TestEncoder_WithoutX5CHeader(t *testing.T) {
	// Generate a test certificate (we'll use the key but not the cert)
	privKey, _ := generateTestCert(t)

	// Create an encoder without the certificate chain
	encoder := &Encoder{
		KID:       "test-key-id",
		Signer:    privKey,
		CertChain: nil, // No certificate chain
	}

	// Create a simple JWT payload
	now := time.Now()
	opts := &jwt.RawJWTOptions{
		Issuer:    stringPtr("test-issuer"),
		Subject:   stringPtr("test-subject"),
		Audience:  stringPtr("test-audience"),
		IssuedAt:  &now,
		ExpiresAt: timePtr(now.Add(1 * time.Hour)),
	}

	rawJWT, err := jwt.NewRawJWT(opts)
	if err != nil {
		t.Fatalf("failed to create raw JWT: %v", err)
	}

	// Sign and encode the JWT
	token, err := encoder.SignAndEncode(rawJWT)
	if err != nil {
		t.Fatalf("failed to sign and encode JWT: %v", err)
	}

	// Verify the token is not empty
	if token == "" {
		t.Fatal("encoded token is empty")
	}

	// Decode and verify the header does NOT contain x5c
	parts := splitToken(token)
	headerJSON, err := base64Decode(parts[0])
	if err != nil {
		t.Fatalf("failed to decode header: %v", err)
	}

	var header map[string]any
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatalf("failed to unmarshal header: %v", err)
	}

	// Verify x5c header is NOT present
	if _, ok := header["x5c"]; ok {
		t.Fatal("x5c header should not be present when CertChain is empty")
	}

	t.Logf("Successfully encoded JWT without x5c header: %s", token[:50]+"...")
}

func TestEncoderDecoder_RoundTrip(t *testing.T) {
	// Generate a test certificate
	privKey, cert := generateTestCert(t)

	// Create a trusted root pool with our certificate (since it's self-signed)
	trustedRoots := x509.NewCertPool()
	trustedRoots.AddCert(cert)

	// Create encoder
	encoder := &Encoder{
		KID:       "test-key-id",
		Signer:    privKey,
		CertChain: []*x509.Certificate{cert},
	}

	// Create decoder
	decoder := NewX5CDecoder(trustedRoots)

	// Create a JWT payload with various claims
	now := time.Now()
	opts := &jwt.RawJWTOptions{
		Issuer:    stringPtr("test-issuer"),
		Subject:   stringPtr("test-subject"),
		Audience:  stringPtr("test-audience"),
		IssuedAt:  &now,
		ExpiresAt: timePtr(now.Add(1 * time.Hour)),
		CustomClaims: map[string]any{
			"custom_claim": "custom_value",
			"number":       42,
		},
	}

	rawJWT, err := jwt.NewRawJWT(opts)
	if err != nil {
		t.Fatalf("failed to create raw JWT: %v", err)
	}

	// Encode the JWT
	token, err := encoder.SignAndEncode(rawJWT)
	if err != nil {
		t.Fatalf("failed to sign and encode JWT: %v", err)
	}

	// Create a validator
	validatorOpts := &jwt.ValidatorOpts{
		ExpectedIssuer:   stringPtr("test-issuer"),
		ExpectedAudience: stringPtr("test-audience"),
	}
	validator, err := jwt.NewValidator(validatorOpts)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	// Decode and verify the JWT
	verifiedJWT, err := decoder.VerifyAndDecode(token, validator)
	if err != nil {
		t.Fatalf("failed to verify and decode JWT: %v", err)
	}

	// Verify claims
	iss, err := verifiedJWT.Issuer()
	if err != nil {
		t.Fatalf("failed to get issuer: %v", err)
	}
	if iss != "test-issuer" {
		t.Errorf("expected issuer 'test-issuer', got %q", iss)
	}

	sub, err := verifiedJWT.Subject()
	if err != nil {
		t.Fatalf("failed to get subject: %v", err)
	}
	if sub != "test-subject" {
		t.Errorf("expected subject 'test-subject', got %q", sub)
	}

	aud, err := verifiedJWT.Audiences()
	if err != nil {
		t.Fatalf("failed to get audiences: %v", err)
	}
	if len(aud) != 1 || aud[0] != "test-audience" {
		t.Errorf("expected audience 'test-audience', got %v", aud)
	}

	// Verify custom claims
	if !verifiedJWT.HasStringClaim("custom_claim") {
		t.Error("missing custom_claim")
	}
	customClaim, err := verifiedJWT.StringClaim("custom_claim")
	if err != nil {
		t.Fatalf("failed to get custom_claim: %v", err)
	}
	if customClaim != "custom_value" {
		t.Errorf("expected custom_claim 'custom_value', got %q", customClaim)
	}

	t.Logf("Successfully completed round-trip: encode -> decode -> verify")
}

func TestEncoderDecoder_RoundTrip_ECDSA_ES384(t *testing.T) {
	// Test with ES384 (P-384 curve)
	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	// Create a self-signed certificate
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	// Create trusted root pool
	trustedRoots := x509.NewCertPool()
	trustedRoots.AddCert(cert)

	// Create encoder
	encoder := &Encoder{
		KID:       "test-key-id-384",
		Signer:    privKey,
		CertChain: []*x509.Certificate{cert},
	}

	// Create decoder
	decoder := NewX5CDecoder(trustedRoots)

	// Create and encode JWT
	now := time.Now()
	opts := &jwt.RawJWTOptions{
		Issuer:    stringPtr("test-issuer-384"),
		Subject:   stringPtr("test-subject-384"),
		IssuedAt:  &now,
		ExpiresAt: timePtr(now.Add(1 * time.Hour)),
	}

	rawJWT, err := jwt.NewRawJWT(opts)
	if err != nil {
		t.Fatalf("failed to create raw JWT: %v", err)
	}

	token, err := encoder.SignAndEncode(rawJWT)
	if err != nil {
		t.Fatalf("failed to sign and encode JWT: %v", err)
	}

	// Verify and decode
	validatorOpts := &jwt.ValidatorOpts{
		ExpectedIssuer: stringPtr("test-issuer-384"),
	}
	validator, err := jwt.NewValidator(validatorOpts)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	verifiedJWT, err := decoder.VerifyAndDecode(token, validator)
	if err != nil {
		t.Fatalf("failed to verify and decode JWT: %v", err)
	}

	// Verify it worked
	iss, err := verifiedJWT.Issuer()
	if err != nil {
		t.Fatalf("failed to get issuer: %v", err)
	}
	if iss != "test-issuer-384" {
		t.Errorf("expected issuer 'test-issuer-384', got %q", iss)
	}

	t.Logf("Successfully completed ES384 round-trip")
}

func TestX5CDecoder_RejectsMissingX5C(t *testing.T) {
	// Create a JWT without x5c header using a different encoder
	privKey, _ := generateTestCert(t)

	encoder := &Encoder{
		KID:       "test-key-id",
		Signer:    privKey,
		CertChain: nil, // No certificate chain
	}

	now := time.Now()
	opts := &jwt.RawJWTOptions{
		Issuer:    stringPtr("test-issuer"),
		Subject:   stringPtr("test-subject"),
		IssuedAt:  &now,
		ExpiresAt: timePtr(now.Add(1 * time.Hour)),
	}

	rawJWT, err := jwt.NewRawJWT(opts)
	if err != nil {
		t.Fatalf("failed to create raw JWT: %v", err)
	}

	token, err := encoder.SignAndEncode(rawJWT)
	if err != nil {
		t.Fatalf("failed to sign and encode JWT: %v", err)
	}

	// Try to decode with X5CDecoder - should fail
	trustedRoots := x509.NewCertPool()
	decoder := NewX5CDecoder(trustedRoots)

	validatorOpts := &jwt.ValidatorOpts{
		ExpectedIssuer: stringPtr("test-issuer"),
	}
	validator, err := jwt.NewValidator(validatorOpts)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	_, err = decoder.VerifyAndDecode(token, validator)
	if err == nil {
		t.Fatal("expected error when decoding JWT without x5c header, got nil")
	}

	if !strings.Contains(err.Error(), "x5c header is missing") {
		t.Errorf("expected error about missing x5c header, got: %v", err)
	}

	t.Logf("Correctly rejected JWT without x5c header: %v", err)
}

func TestX5CDecoder_RejectsUntrustedCert(t *testing.T) {
	// Generate two different certificates
	privKey1, cert1 := generateTestCert(t)
	_, cert2 := generateTestCert(t)

	// Create encoder with cert1
	encoder := &Encoder{
		KID:       "test-key-id",
		Signer:    privKey1,
		CertChain: []*x509.Certificate{cert1},
	}

	// Create decoder with only cert2 in trusted roots (different cert)
	trustedRoots := x509.NewCertPool()
	trustedRoots.AddCert(cert2)
	decoder := NewX5CDecoder(trustedRoots)

	// Create and encode JWT
	now := time.Now()
	opts := &jwt.RawJWTOptions{
		Issuer:    stringPtr("test-issuer"),
		Subject:   stringPtr("test-subject"),
		IssuedAt:  &now,
		ExpiresAt: timePtr(now.Add(1 * time.Hour)),
	}

	rawJWT, err := jwt.NewRawJWT(opts)
	if err != nil {
		t.Fatalf("failed to create raw JWT: %v", err)
	}

	token, err := encoder.SignAndEncode(rawJWT)
	if err != nil {
		t.Fatalf("failed to sign and encode JWT: %v", err)
	}

	// Try to decode - should fail because cert1 is not trusted
	validatorOpts := &jwt.ValidatorOpts{
		ExpectedIssuer: stringPtr("test-issuer"),
	}
	validator, err := jwt.NewValidator(validatorOpts)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	_, err = decoder.VerifyAndDecode(token, validator)
	if err == nil {
		t.Fatal("expected error when decoding JWT with untrusted certificate, got nil")
	}

	if !strings.Contains(err.Error(), "certificate chain verification failed") {
		t.Errorf("expected error about certificate verification, got: %v", err)
	}

	t.Logf("Correctly rejected JWT with untrusted certificate: %v", err)
}

// Helper functions
func stringPtr(s string) *string {
	return &s
}

func timePtr(t time.Time) *time.Time {
	return &t
}

func splitToken(token string) []string {
	header, claims, sig, ok := parseToken(token)
	if !ok {
		return nil
	}
	return []string{header, claims, sig}
}

func base64Decode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}
