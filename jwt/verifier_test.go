package jwt

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/lstoll/oauth2ext/internal"
)

func TestVerifyToken(t *testing.T) {
	// Create valid claims
	now := time.Now()
	validClaims := jwt.Claims{
		Issuer:    "https://test-issuer.com",
		Subject:   "test-subject",
		Audience:  jwt.Audience{"test-audience"},
		Expiry:    jwt.NewNumericDate(now.Add(1 * time.Hour)),
		NotBefore: jwt.NewNumericDate(now.Add(-1 * time.Hour)),
		IssuedAt:  jwt.NewNumericDate(now),
	}

	testSigner := internal.NewTestSigner(t)

	validKeyset, err := NewStaticKeysetFromJWKS(testSigner.JWKS())
	if err != nil {
		t.Fatalf("Failed to create keyset from signer: %v", err)
	}

	// Create keyset with wrong key
	wrongSigner := internal.NewTestSigner(t)
	if err != nil {
		t.Fatalf("Failed to generate wrong key: %v", err)
	}
	wrongKeyset, err := NewStaticKeysetFromJWKS(wrongSigner.JWKS())
	if err != nil {
		t.Fatalf("Failed to create keyset from wrong signer: %v", err)
	}

	tests := []struct {
		name        string
		setupToken  func() (string, error)
		setupKeyset func() PublicKeyset
		opts        verifyOpts
		wantErr     bool
		errContains string
	}{
		{
			name: "valid token",
			setupToken: func() (string, error) {
				return testSigner.Sign(validClaims, "")
			},
			setupKeyset: func() PublicKeyset { return validKeyset },
			opts: verifyOpts{
				Issuer:          "https://test-issuer.com",
				WantAnyAudience: jwt.Audience{"test-audience"},
				SupportedAlgs:   []jose.SignatureAlgorithm{jose.ES256},
			},
			wantErr: false,
		},
		{
			name: "valid token with type header",
			setupToken: func() (string, error) {
				return testSigner.Sign(validClaims, "JWT")
			},
			setupKeyset: func() PublicKeyset { return validKeyset },
			opts: verifyOpts{
				Issuer:          "https://test-issuer.com",
				WantType:        "JWT",
				WantAnyAudience: jwt.Audience{"test-audience"},
				SupportedAlgs:   []jose.SignatureAlgorithm{jose.ES256},
			},
			wantErr: false,
		},
		{
			name: "wrong type header",
			setupToken: func() (string, error) {
				return testSigner.Sign(validClaims, "JWT")
			},
			setupKeyset: func() PublicKeyset { return validKeyset },
			opts: verifyOpts{
				Issuer:          "https://test-issuer.com",
				WantType:        "ID_TOKEN",
				WantAnyAudience: jwt.Audience{"test-audience"},
				SupportedAlgs:   []jose.SignatureAlgorithm{jose.ES256},
			},
			wantErr:     true,
			errContains: "wanted type header",
		},
		{
			name: "unexpected type header",
			setupToken: func() (string, error) {
				return testSigner.Sign(validClaims, "JWT")
			},
			setupKeyset: func() PublicKeyset { return validKeyset },
			opts: verifyOpts{
				Issuer:          "https://test-issuer.com",
				WantAnyAudience: jwt.Audience{"test-audience"},
				SupportedAlgs:   []jose.SignatureAlgorithm{jose.ES256},
			},
			wantErr:     true,
			errContains: "unexpected type header",
		},
		{
			name: "wrong issuer",
			setupToken: func() (string, error) {
				claims := validClaims
				claims.Issuer = "https://wrong-issuer.com"
				return testSigner.Sign(claims, "")
			},
			setupKeyset: func() PublicKeyset { return validKeyset },
			opts: verifyOpts{
				Issuer:          "https://test-issuer.com",
				WantAnyAudience: jwt.Audience{"test-audience"},
				SupportedAlgs:   []jose.SignatureAlgorithm{jose.ES256},
			},
			wantErr:     true,
			errContains: "invalid issuer",
		},
		{
			name: "wrong audience",
			setupToken: func() (string, error) {
				claims := validClaims
				claims.Audience = jwt.Audience{"wrong-audience"}
				return testSigner.Sign(claims, "")
			},
			setupKeyset: func() PublicKeyset { return validKeyset },
			opts: verifyOpts{
				Issuer:          "https://test-issuer.com",
				WantAnyAudience: jwt.Audience{"test-audience"},
				SupportedAlgs:   []jose.SignatureAlgorithm{jose.ES256},
			},
			wantErr:     true,
			errContains: "audience",
		},
		{
			name: "expired token",
			setupToken: func() (string, error) {
				claims := validClaims
				claims.Expiry = jwt.NewNumericDate(time.Now().Add(-1 * time.Hour))
				return testSigner.Sign(claims, "")
			},
			setupKeyset: func() PublicKeyset { return validKeyset },
			opts: verifyOpts{
				Issuer:          "https://test-issuer.com",
				WantAnyAudience: jwt.Audience{"test-audience"},
				SupportedAlgs:   []jose.SignatureAlgorithm{jose.ES256},
			},
			wantErr:     true,
			errContains: "token has expired",
		},
		{
			name: "token not yet valid",
			setupToken: func() (string, error) {
				claims := validClaims
				claims.NotBefore = jwt.NewNumericDate(time.Now().Add(1 * time.Hour))
				return testSigner.Sign(claims, "")
			},
			setupKeyset: func() PublicKeyset { return validKeyset },
			opts: verifyOpts{
				Issuer:          "https://test-issuer.com",
				WantAnyAudience: jwt.Audience{"test-audience"},
				SupportedAlgs:   []jose.SignatureAlgorithm{jose.ES256},
			},
			wantErr:     true,
			errContains: "token not yet valid",
		},
		{
			name: "wrong key",
			setupToken: func() (string, error) {
				return testSigner.Sign(validClaims, "")
			},
			setupKeyset: func() PublicKeyset { return wrongKeyset },
			opts: verifyOpts{
				Issuer:          "https://test-issuer.com",
				WantAnyAudience: jwt.Audience{"test-audience"},
				SupportedAlgs:   []jose.SignatureAlgorithm{jose.ES256},
			},
			wantErr:     true,
			errContains: "no key found for kid",
		},
		{
			name: "unsupported algorithm",
			setupToken: func() (string, error) {
				return testSigner.Sign(validClaims, "")
			},
			setupKeyset: func() PublicKeyset { return validKeyset },
			opts: verifyOpts{
				Issuer:          "https://test-issuer.com",
				WantAnyAudience: jwt.Audience{"test-audience"},
				SupportedAlgs:   []jose.SignatureAlgorithm{jose.RS256},
			},
			wantErr:     true,
			errContains: "unexpected signature algorithm",
		},
		{
			name: "skip audience validation",
			setupToken: func() (string, error) {
				claims := validClaims
				claims.Audience = jwt.Audience{"wrong-audience"}
				return testSigner.Sign(claims, "")
			},
			setupKeyset: func() PublicKeyset { return validKeyset },
			opts: verifyOpts{
				Issuer:        "https://test-issuer.com",
				SkipAudience:  true,
				SupportedAlgs: []jose.SignatureAlgorithm{jose.ES256},
			},
			wantErr: false,
		},
		{
			name: "valid ACR",
			setupToken: func() (string, error) {
				claims := claimsWithVerifyFields{
					Claims: validClaims,
					ACR:    "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
				}
				return testSigner.Sign(claims, "")
			},
			setupKeyset: func() PublicKeyset { return validKeyset },
			opts: verifyOpts{
				Issuer:          "https://test-issuer.com",
				WantAnyAudience: jwt.Audience{"test-audience"},
				WantAnyACR:      []string{"urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"},
				SupportedAlgs:   []jose.SignatureAlgorithm{jose.ES256},
			},
			wantErr: false,
		},
		{
			name: "invalid ACR",
			setupToken: func() (string, error) {
				claims := claimsWithVerifyFields{
					Claims: validClaims,
					ACR:    "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
				}
				return testSigner.Sign(claims, "")
			},
			setupKeyset: func() PublicKeyset { return validKeyset },
			opts: verifyOpts{
				Issuer:          "https://test-issuer.com",
				WantAnyAudience: jwt.Audience{"test-audience"},
				WantAnyACR:      []string{"urn:oasis:names:tc:SAML:2.0:ac:classes:TwoFactorContract"},
				SupportedAlgs:   []jose.SignatureAlgorithm{jose.ES256},
			},
			wantErr:     true,
			errContains: "acr",
		},
		{
			name: "custom time buffer",
			setupToken: func() (string, error) {
				claims := validClaims
				// Token expires in 30 seconds, but we set buffer to 15 seconds
				claims.Expiry = jwt.NewNumericDate(time.Now().Add(30 * time.Second))
				return testSigner.Sign(claims, "")
			},
			setupKeyset: func() PublicKeyset { return validKeyset },
			opts: verifyOpts{
				Issuer:          "https://test-issuer.com",
				WantAnyAudience: jwt.Audience{"test-audience"},
				ValidTimeBuffer: 15 * time.Second,
				SupportedAlgs:   []jose.SignatureAlgorithm{jose.ES256},
			},
			wantErr: false,
		},
		{
			name: "malformed JWT",
			setupToken: func() (string, error) {
				return "not.a.jwt", nil
			},
			setupKeyset: func() PublicKeyset { return validKeyset },
			opts: verifyOpts{
				Issuer:          "https://test-issuer.com",
				WantAnyAudience: jwt.Audience{"test-audience"},
				SupportedAlgs:   []jose.SignatureAlgorithm{jose.ES256},
			},
			wantErr:     true,
			errContains: "illegal base64 data",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			token, err := tt.setupToken()
			if err != nil {
				t.Fatalf("Failed to setup token: %v", err)
			}

			keyset := tt.setupKeyset()

			_, err = verifyToken(ctx, keyset, token, tt.opts)
			if tt.wantErr {
				if err == nil {
					t.Errorf("verifyToken() expected error but got none")
					return
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("verifyToken() error = %v, want error containing %q", err, tt.errContains)
				}
			} else {
				if err != nil {
					t.Errorf("verifyToken() unexpected error = %v", err)
				}
			}
		})
	}
}
