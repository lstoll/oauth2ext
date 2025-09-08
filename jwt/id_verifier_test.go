package jwt

import (
	"context"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
	"lds.li/oauth2ext/internal"
)

func TestIDTokenVerifier_VerifyRaw(t *testing.T) {
	// Create valid ID token claims
	now := time.Now()
	validClaims := IDClaims{
		Issuer:    "https://test-issuer.com",
		Subject:   "test-subject",
		Audience:  StrOrSlice{"test-client-id"},
		Expiry:    UnixTime(now.Add(1 * time.Hour).Unix()),
		NotBefore: UnixTime(now.Add(-1 * time.Hour).Unix()),
		IssuedAt:  UnixTime(now.Unix()),
		AuthTime:  UnixTime(now.Add(-5 * time.Minute).Unix()),
		Nonce:     "test-nonce",
		ACR:       "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
		AMR:       []string{"pwd", "otp"},
		AZP:       "test-client-id",
	}

	testSigner := internal.NewTestSigner(t)

	validKeyset, err := NewStaticKeysetFromJWKS(testSigner.JWKS())
	if err != nil {
		t.Fatalf("Failed to create keyset from signer: %v", err)
	}

	// Create keyset with wrong key
	wrongSigner := internal.NewTestSigner(t)
	wrongKeyset, err := NewStaticKeysetFromJWKS(wrongSigner.JWKS())
	if err != nil {
		t.Fatalf("Failed to create keyset from wrong signer: %v", err)
	}

	tests := []struct {
		name           string
		setupToken     func() (string, error)
		setupVerifier  func() *IDTokenVerifier
		wantErr        bool
		errContains    string
		validateClaims func(*testing.T, *IDClaims)
	}{
		{
			name: "valid id token",
			setupToken: func() (string, error) {
				return testSigner.Sign(validClaims, "")
			},
			setupVerifier: func() *IDTokenVerifier {
				return &IDTokenVerifier{
					Provider: &StaticIssuer{
						IssuerURL:     "https://test-issuer.com",
						Keyset:        validKeyset,
						SupportedAlgs: []string{"ES256"},
					},
					ClientID: "test-client-id",
				}
			},
			wantErr: false,
			validateClaims: func(t *testing.T, claims *IDClaims) {
				if claims.Subject != "test-subject" {
					t.Errorf("expected subject %q, got %q", "test-subject", claims.Subject)
				}
				if claims.AuthTime != validClaims.AuthTime {
					t.Errorf("expected auth_time %v, got %v", validClaims.AuthTime, claims.AuthTime)
				}
				if claims.Nonce != "test-nonce" {
					t.Errorf("expected nonce %q, got %q", "test-nonce", claims.Nonce)
				}
				if claims.ACR != "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport" {
					t.Errorf("expected ACR %q, got %q", "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport", claims.ACR)
				}
				if len(claims.AMR) != 2 || claims.AMR[0] != "pwd" || claims.AMR[1] != "otp" {
					t.Errorf("expected AMR [pwd otp], got %v", claims.AMR)
				}
				if claims.AZP != "test-client-id" {
					t.Errorf("expected AZP %q, got %q", "test-client-id", claims.AZP)
				}
			},
		},
		{
			name: "wrong client id",
			setupToken: func() (string, error) {
				return testSigner.Sign(validClaims, "")
			},
			setupVerifier: func() *IDTokenVerifier {
				return &IDTokenVerifier{
					Provider: &StaticIssuer{
						IssuerURL:     "https://test-issuer.com",
						Keyset:        validKeyset,
						SupportedAlgs: []string{"ES256"},
					},
					ClientID: "wrong-client-id",
				}
			},
			wantErr:     true,
			errContains: "audience",
		},
		{
			name: "ignore client id",
			setupToken: func() (string, error) {
				claims := validClaims
				claims.Audience = StrOrSlice{"wrong-client-id"}
				return testSigner.Sign(claims, "")
			},
			setupVerifier: func() *IDTokenVerifier {
				return &IDTokenVerifier{
					Provider: &StaticIssuer{
						IssuerURL:     "https://test-issuer.com",
						Keyset:        validKeyset,
						SupportedAlgs: []string{"ES256"},
					},
					ClientID:       "test-client-id",
					IgnoreClientID: true,
				}
			},
			wantErr: false,
		},
		{
			name: "valid ACR",
			setupToken: func() (string, error) {
				return testSigner.Sign(validClaims, "")
			},
			setupVerifier: func() *IDTokenVerifier {
				return &IDTokenVerifier{
					Provider: &StaticIssuer{
						IssuerURL:     "https://test-issuer.com",
						Keyset:        validKeyset,
						SupportedAlgs: []string{"ES256"},
					},
					ClientID:   "test-client-id",
					WantAnyACR: []string{"urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"},
				}
			},
			wantErr: false,
		},
		{
			name: "invalid ACR",
			setupToken: func() (string, error) {
				return testSigner.Sign(validClaims, "")
			},
			setupVerifier: func() *IDTokenVerifier {
				return &IDTokenVerifier{
					Provider: &StaticIssuer{
						IssuerURL:     "https://test-issuer.com",
						Keyset:        validKeyset,
						SupportedAlgs: []string{"ES256"},
					},
					ClientID:   "test-client-id",
					WantAnyACR: []string{"urn:oasis:names:tc:SAML:2.0:ac:classes:TwoFactorContract"},
				}
			},
			wantErr:     true,
			errContains: "acr",
		},
		{
			name: "multiple valid ACRs",
			setupToken: func() (string, error) {
				return testSigner.Sign(validClaims, "")
			},
			setupVerifier: func() *IDTokenVerifier {
				return &IDTokenVerifier{
					Provider: &StaticIssuer{
						IssuerURL:     "https://test-issuer.com",
						Keyset:        validKeyset,
						SupportedAlgs: []string{"ES256"},
					},
					ClientID: "test-client-id",
					WantAnyACR: []string{
						"urn:oasis:names:tc:SAML:2.0:ac:classes:TwoFactorContract",
						"urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
					},
				}
			},
			wantErr: false,
		},
		{
			name: "wrong issuer",
			setupToken: func() (string, error) {
				claims := validClaims
				claims.Issuer = "https://wrong-issuer.com"
				return testSigner.Sign(claims, "")
			},
			setupVerifier: func() *IDTokenVerifier {
				return &IDTokenVerifier{
					Provider: &StaticIssuer{
						IssuerURL:     "https://test-issuer.com",
						Keyset:        validKeyset,
						SupportedAlgs: []string{"ES256"},
					},
					ClientID: "test-client-id",
				}
			},
			wantErr:     true,
			errContains: "invalid issuer",
		},
		{
			name: "expired token",
			setupToken: func() (string, error) {
				claims := validClaims
				claims.Expiry = UnixTime(time.Now().Add(-1 * time.Hour).Unix())
				return testSigner.Sign(claims, "")
			},
			setupVerifier: func() *IDTokenVerifier {
				return &IDTokenVerifier{
					Provider: &StaticIssuer{
						IssuerURL:     "https://test-issuer.com",
						Keyset:        validKeyset,
						SupportedAlgs: []string{"ES256"},
					},
					ClientID: "test-client-id",
				}
			},
			wantErr:     true,
			errContains: "token has expired",
		},
		{
			name: "token not yet valid",
			setupToken: func() (string, error) {
				claims := validClaims
				claims.NotBefore = UnixTime(time.Now().Add(1 * time.Hour).Unix())
				return testSigner.Sign(claims, "")
			},
			setupVerifier: func() *IDTokenVerifier {
				return &IDTokenVerifier{
					Provider: &StaticIssuer{
						IssuerURL:     "https://test-issuer.com",
						Keyset:        validKeyset,
						SupportedAlgs: []string{"ES256"},
					},
					ClientID: "test-client-id",
				}
			},
			wantErr:     true,
			errContains: "token not yet valid",
		},
		{
			name: "wrong key",
			setupToken: func() (string, error) {
				return testSigner.Sign(validClaims, "")
			},
			setupVerifier: func() *IDTokenVerifier {
				return &IDTokenVerifier{
					Provider: &StaticIssuer{
						IssuerURL:     "https://test-issuer.com",
						Keyset:        wrongKeyset,
						SupportedAlgs: []string{"ES256"},
					},
					ClientID: "test-client-id",
				}
			},
			wantErr:     true,
			errContains: "no key found for kid",
		},
		{
			name: "override keyset",
			setupToken: func() (string, error) {
				return testSigner.Sign(validClaims, "")
			},
			setupVerifier: func() *IDTokenVerifier {
				return &IDTokenVerifier{
					Provider: &StaticIssuer{
						IssuerURL:     "https://test-issuer.com",
						Keyset:        wrongKeyset, // This should be ignored
						SupportedAlgs: []string{"ES256"},
					},
					OverrideKeyset: validKeyset, // This should be used
					ClientID:       "test-client-id",
				}
			},
			wantErr: false,
		},
		{
			name: "malformed JWT",
			setupToken: func() (string, error) {
				return "not.a.jwt", nil
			},
			setupVerifier: func() *IDTokenVerifier {
				return &IDTokenVerifier{
					Provider: &StaticIssuer{
						IssuerURL:     "https://test-issuer.com",
						Keyset:        validKeyset,
						SupportedAlgs: []string{"ES256"},
					},
					ClientID: "test-client-id",
				}
			},
			wantErr:     true,
			errContains: "illegal base64 data",
		},
		{
			name: "missing required claims",
			setupToken: func() (string, error) {
				// Create claims missing required fields
				incompleteClaims := IDClaims{
					Issuer:  "https://test-issuer.com",
					Subject: "test-subject",
					// Missing Audience, Expiry, IssuedAt
				}
				return testSigner.Sign(incompleteClaims, "")
			},
			setupVerifier: func() *IDTokenVerifier {
				return &IDTokenVerifier{
					Provider: &StaticIssuer{
						IssuerURL:     "https://test-issuer.com",
						Keyset:        validKeyset,
						SupportedAlgs: []string{"ES256"},
					},
					ClientID: "test-client-id",
				}
			},
			wantErr:     true,
			errContains: "audience",
		},
		{
			name: "token with extra claims",
			setupToken: func() (string, error) {
				// Create a token with extra claims that will be included in the JWT
				// but not automatically unmarshaled to the Extra field due to json:"-" tag
				claims := validClaims
				// Note: Extra claims would need to be handled separately if needed
				return testSigner.Sign(claims, "")
			},
			setupVerifier: func() *IDTokenVerifier {
				return &IDTokenVerifier{
					Provider: &StaticIssuer{
						IssuerURL:     "https://test-issuer.com",
						Keyset:        validKeyset,
						SupportedAlgs: []string{"ES256"},
					},
					ClientID: "test-client-id",
				}
			},
			wantErr: false,
			// Note: Extra claims are not automatically unmarshaled due to json:"-" tag
			// They would need to be handled separately if needed
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			token, err := tt.setupToken()
			if err != nil {
				t.Fatalf("Failed to setup token: %v", err)
			}

			verifier := tt.setupVerifier()

			claims, err := verifier.VerifyRaw(ctx, token)
			if tt.wantErr {
				if err == nil {
					t.Errorf("VerifyRaw() expected error but got none")
					return
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("VerifyRaw() error = %v, want error containing %q", err, tt.errContains)
				}
			} else {
				if err != nil {
					t.Errorf("VerifyRaw() unexpected error = %v", err)
					return
				}
				if tt.validateClaims != nil {
					tt.validateClaims(t, claims)
				}
			}
		})
	}
}

func TestIDTokenVerifier_Verify(t *testing.T) {
	// Create valid ID token claims
	now := time.Now()
	validClaims := IDClaims{
		Issuer:    "https://test-issuer.com",
		Subject:   "test-subject",
		Audience:  StrOrSlice{"test-client-id"},
		Expiry:    UnixTime(now.Add(1 * time.Hour).Unix()),
		NotBefore: UnixTime(now.Add(-1 * time.Hour).Unix()),
		IssuedAt:  UnixTime(now.Unix()),
	}

	testSigner := internal.NewTestSigner(t)

	validKeyset, err := NewStaticKeysetFromJWKS(testSigner.JWKS())
	if err != nil {
		t.Fatalf("Failed to create keyset from signer: %v", err)
	}

	tests := []struct {
		name          string
		setupToken    func() *oauth2.Token
		setupVerifier func() *IDTokenVerifier
		wantErr       bool
		errContains   string
	}{
		{
			name: "valid token with id_token",
			setupToken: func() *oauth2.Token {
				idToken, err := testSigner.Sign(validClaims, "")
				if err != nil {
					t.Fatalf("Failed to sign token: %v", err)
				}
				return (&oauth2.Token{}).WithExtra(map[string]any{
					"id_token": idToken,
				})
			},
			setupVerifier: func() *IDTokenVerifier {
				return &IDTokenVerifier{
					Provider: &StaticIssuer{
						IssuerURL:     "https://test-issuer.com",
						Keyset:        validKeyset,
						SupportedAlgs: []string{"ES256"},
					},
					ClientID: "test-client-id",
				}
			},
			wantErr: false,
		},
		{
			name: "token without id_token",
			setupToken: func() *oauth2.Token {
				return (&oauth2.Token{}).WithExtra(map[string]any{
					"access_token": "some-access-token",
				})
			},
			setupVerifier: func() *IDTokenVerifier {
				return &IDTokenVerifier{
					Provider: &StaticIssuer{
						IssuerURL:     "https://test-issuer.com",
						Keyset:        validKeyset,
						SupportedAlgs: []string{"ES256"},
					},
					ClientID: "test-client-id",
				}
			},
			wantErr:     true,
			errContains: "no id_token found in token",
		},
		{
			name: "token with wrong id_token type",
			setupToken: func() *oauth2.Token {
				return (&oauth2.Token{}).WithExtra(map[string]any{
					"id_token": 123, // Not a string
				})
			},
			setupVerifier: func() *IDTokenVerifier {
				return &IDTokenVerifier{
					Provider: &StaticIssuer{
						IssuerURL:     "https://test-issuer.com",
						Keyset:        validKeyset,
						SupportedAlgs: []string{"ES256"},
					},
					ClientID: "test-client-id",
				}
			},
			wantErr:     true,
			errContains: "no id_token found in token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			token := tt.setupToken()
			verifier := tt.setupVerifier()

			_, err := verifier.Verify(ctx, token)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Verify() expected error but got none")
					return
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("Verify() error = %v, want error containing %q", err, tt.errContains)
				}
			} else {
				if err != nil {
					t.Errorf("Verify() unexpected error = %v", err)
				}
			}
		})
	}
}
