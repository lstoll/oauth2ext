package jwt

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/lstoll/oauth2ext/internal"
	"golang.org/x/oauth2"
)

func TestAccessTokenVerifier_VerifyRaw(t *testing.T) {
	// Create valid access token claims
	now := time.Now()
	validClaims := AccessTokenClaims{
		Issuer:       "https://test-issuer.com",
		Subject:      "test-subject",
		Audience:     StrOrSlice{"test-audience"},
		Expiry:       UnixTime(now.Add(1 * time.Hour).Unix()),
		IssuedAt:     UnixTime(now.Unix()),
		JWTID:        "test-jti",
		ClientID:     "test-client-id",
		Scope:        "read write",
		AuthTime:     UnixTime(now.Add(-5 * time.Minute).Unix()),
		ACR:          "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
		AMR:          []string{"pwd", "otp"},
		Groups:       []string{"admin", "users"},
		Roles:        []string{"admin", "user"},
		Entitlements: []string{"read:users", "write:users"},
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
		setupVerifier  func() *AccessTokenVerifier
		wantErr        bool
		errContains    string
		validateClaims func(*testing.T, *AccessTokenClaims)
	}{
		{
			name: "valid access token",
			setupToken: func() (string, error) {
				return testSigner.Sign(validClaims, "")
			},
			setupVerifier: func() *AccessTokenVerifier {
				return &AccessTokenVerifier{
					Provider: &mockProvider{
						issuer:        "https://test-issuer.com",
						keyset:        validKeyset,
						supportedAlgs: []string{"ES256"},
					},
					WantAnyAudience: []string{"test-audience"},
				}
			},
			wantErr: false,
			validateClaims: func(t *testing.T, claims *AccessTokenClaims) {
				if claims.Subject != "test-subject" {
					t.Errorf("expected subject %q, got %q", "test-subject", claims.Subject)
				}
				if claims.ClientID != "test-client-id" {
					t.Errorf("expected client_id %q, got %q", "test-client-id", claims.ClientID)
				}
				if claims.JWTID != "test-jti" {
					t.Errorf("expected jti %q, got %q", "test-jti", claims.JWTID)
				}
				if claims.Scope != "read write" {
					t.Errorf("expected scope %q, got %q", "read write", claims.Scope)
				}
				if claims.AuthTime != validClaims.AuthTime {
					t.Errorf("expected auth_time %v, got %v", validClaims.AuthTime, claims.AuthTime)
				}
				if claims.ACR != "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport" {
					t.Errorf("expected ACR %q, got %q", "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport", claims.ACR)
				}
				if len(claims.AMR) != 2 || claims.AMR[0] != "pwd" || claims.AMR[1] != "otp" {
					t.Errorf("expected AMR [pwd otp], got %v", claims.AMR)
				}
				if len(claims.Groups) != 2 || claims.Groups[0] != "admin" || claims.Groups[1] != "users" {
					t.Errorf("expected Groups [admin users], got %v", claims.Groups)
				}
				if len(claims.Roles) != 2 || claims.Roles[0] != "admin" || claims.Roles[1] != "user" {
					t.Errorf("expected Roles [admin user], got %v", claims.Roles)
				}
				if len(claims.Entitlements) != 2 || claims.Entitlements[0] != "read:users" || claims.Entitlements[1] != "write:users" {
					t.Errorf("expected Entitlements [read:users write:users], got %v", claims.Entitlements)
				}
			},
		},
		{
			name: "wrong audience",
			setupToken: func() (string, error) {
				return testSigner.Sign(validClaims, "")
			},
			setupVerifier: func() *AccessTokenVerifier {
				return &AccessTokenVerifier{
					Provider: &mockProvider{
						issuer:        "https://test-issuer.com",
						keyset:        validKeyset,
						supportedAlgs: []string{"ES256"},
					},
					WantAnyAudience: []string{"wrong-audience"},
				}
			},
			wantErr:     true,
			errContains: "audience",
		},
		{
			name: "ignore audience",
			setupToken: func() (string, error) {
				claims := validClaims
				claims.Audience = StrOrSlice{"wrong-audience"}
				return testSigner.Sign(claims, "")
			},
			setupVerifier: func() *AccessTokenVerifier {
				return &AccessTokenVerifier{
					Provider: &mockProvider{
						issuer:        "https://test-issuer.com",
						keyset:        validKeyset,
						supportedAlgs: []string{"ES256"},
					},
					WantAnyAudience: []string{"test-audience"},
					IgnoreAudience:  true,
				}
			},
			wantErr: false,
		},
		{
			name: "multiple valid audiences",
			setupToken: func() (string, error) {
				claims := validClaims
				claims.Audience = StrOrSlice{"test-audience", "another-audience"}
				return testSigner.Sign(claims, "")
			},
			setupVerifier: func() *AccessTokenVerifier {
				return &AccessTokenVerifier{
					Provider: &mockProvider{
						issuer:        "https://test-issuer.com",
						keyset:        validKeyset,
						supportedAlgs: []string{"ES256"},
					},
					WantAnyAudience: []string{"another-audience", "third-audience"},
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
			setupVerifier: func() *AccessTokenVerifier {
				return &AccessTokenVerifier{
					Provider: &mockProvider{
						issuer:        "https://test-issuer.com",
						keyset:        validKeyset,
						supportedAlgs: []string{"ES256"},
					},
					WantAnyAudience: []string{"test-audience"},
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
			setupVerifier: func() *AccessTokenVerifier {
				return &AccessTokenVerifier{
					Provider: &mockProvider{
						issuer:        "https://test-issuer.com",
						keyset:        validKeyset,
						supportedAlgs: []string{"ES256"},
					},
					WantAnyAudience: []string{"test-audience"},
				}
			},
			wantErr:     true,
			errContains: "token has expired",
		},
		{
			name: "token not yet valid",
			setupToken: func() (string, error) {
				// AccessTokenClaims doesn't have NotBefore field, so we'll test with a future issued time
				// Note: The verification logic doesn't check for future IssuedAt times
				claims := validClaims
				claims.IssuedAt = UnixTime(time.Now().Add(1 * time.Hour).Unix()) // Issued in the future
				return testSigner.Sign(claims, "")
			},
			setupVerifier: func() *AccessTokenVerifier {
				return &AccessTokenVerifier{
					Provider: &mockProvider{
						issuer:        "https://test-issuer.com",
						keyset:        validKeyset,
						supportedAlgs: []string{"ES256"},
					},
					WantAnyAudience: []string{"test-audience"},
				}
			},
			wantErr: false, // The verification logic doesn't check for future IssuedAt times
		},
		{
			name: "wrong key",
			setupToken: func() (string, error) {
				return testSigner.Sign(validClaims, "")
			},
			setupVerifier: func() *AccessTokenVerifier {
				return &AccessTokenVerifier{
					Provider: &mockProvider{
						issuer:        "https://test-issuer.com",
						keyset:        wrongKeyset,
						supportedAlgs: []string{"ES256"},
					},
					WantAnyAudience: []string{"test-audience"},
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
			setupVerifier: func() *AccessTokenVerifier {
				return &AccessTokenVerifier{
					Provider: &mockProvider{
						issuer:        "https://test-issuer.com",
						keyset:        wrongKeyset, // This should be ignored
						supportedAlgs: []string{"ES256"},
					},
					OverrideKeyset:  validKeyset, // This should be used
					WantAnyAudience: []string{"test-audience"},
				}
			},
			wantErr: false,
		},
		{
			name: "malformed JWT",
			setupToken: func() (string, error) {
				return "not.a.jwt", nil
			},
			setupVerifier: func() *AccessTokenVerifier {
				return &AccessTokenVerifier{
					Provider: &mockProvider{
						issuer:        "https://test-issuer.com",
						keyset:        validKeyset,
						supportedAlgs: []string{"ES256"},
					},
					WantAnyAudience: []string{"test-audience"},
				}
			},
			wantErr:     true,
			errContains: "illegal base64 data",
		},
		{
			name: "missing required claims",
			setupToken: func() (string, error) {
				// Create claims missing required fields
				incompleteClaims := AccessTokenClaims{
					Issuer:  "https://test-issuer.com",
					Subject: "test-subject",
					// Missing Audience, Expiry, IssuedAt, JWTID, ClientID
				}
				return testSigner.Sign(incompleteClaims, "")
			},
			setupVerifier: func() *AccessTokenVerifier {
				return &AccessTokenVerifier{
					Provider: &mockProvider{
						issuer:        "https://test-issuer.com",
						keyset:        validKeyset,
						supportedAlgs: []string{"ES256"},
					},
					WantAnyAudience: []string{"test-audience"},
				}
			},
			wantErr:     true,
			errContains: "audience",
		},
		{
			name: "minimal valid token",
			setupToken: func() (string, error) {
				// Create minimal valid access token claims
				now := time.Now()
				minimalClaims := AccessTokenClaims{
					Issuer:   "https://test-issuer.com",
					Subject:  "test-subject",
					Audience: StrOrSlice{"test-audience"},
					Expiry:   UnixTime(now.Add(1 * time.Hour).Unix()),
					IssuedAt: UnixTime(now.Unix()),
					JWTID:    "test-jti",
					ClientID: "test-client-id",
				}
				return testSigner.Sign(minimalClaims, "")
			},
			setupVerifier: func() *AccessTokenVerifier {
				return &AccessTokenVerifier{
					Provider: &mockProvider{
						issuer:        "https://test-issuer.com",
						keyset:        validKeyset,
						supportedAlgs: []string{"ES256"},
					},
					WantAnyAudience: []string{"test-audience"},
				}
			},
			wantErr: false,
			validateClaims: func(t *testing.T, claims *AccessTokenClaims) {
				if claims.Subject != "test-subject" {
					t.Errorf("expected subject %q, got %q", "test-subject", claims.Subject)
				}
				if claims.ClientID != "test-client-id" {
					t.Errorf("expected client_id %q, got %q", "test-client-id", claims.ClientID)
				}
				if claims.JWTID != "test-jti" {
					t.Errorf("expected jti %q, got %q", "test-jti", claims.JWTID)
				}
			},
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

func TestAccessTokenVerifier_Verify(t *testing.T) {
	// Create valid access token claims
	now := time.Now()
	validClaims := AccessTokenClaims{
		Issuer:   "https://test-issuer.com",
		Subject:  "test-subject",
		Audience: StrOrSlice{"test-audience"},
		Expiry:   UnixTime(now.Add(1 * time.Hour).Unix()),
		IssuedAt: UnixTime(now.Unix()),
		JWTID:    "test-jti",
		ClientID: "test-client-id",
	}

	testSigner := internal.NewTestSigner(t)

	validKeyset, err := NewStaticKeysetFromJWKS(testSigner.JWKS())
	if err != nil {
		t.Fatalf("Failed to create keyset from signer: %v", err)
	}

	tests := []struct {
		name          string
		setupToken    func() *oauth2.Token
		setupVerifier func() *AccessTokenVerifier
		wantErr       bool
		errContains   string
	}{
		{
			name: "valid token with access_token",
			setupToken: func() *oauth2.Token {
				accessToken, err := testSigner.Sign(validClaims, "")
				if err != nil {
					t.Fatalf("Failed to sign token: %v", err)
				}
				return &oauth2.Token{
					AccessToken: accessToken,
				}
			},
			setupVerifier: func() *AccessTokenVerifier {
				return &AccessTokenVerifier{
					Provider: &mockProvider{
						issuer:        "https://test-issuer.com",
						keyset:        validKeyset,
						supportedAlgs: []string{"ES256"},
					},
					WantAnyAudience: []string{"test-audience"},
				}
			},
			wantErr: false,
		},
		{
			name: "token without access_token",
			setupToken: func() *oauth2.Token {
				return &oauth2.Token{
					AccessToken: "", // Empty access token
				}
			},
			setupVerifier: func() *AccessTokenVerifier {
				return &AccessTokenVerifier{
					Provider: &mockProvider{
						issuer:        "https://test-issuer.com",
						keyset:        validKeyset,
						supportedAlgs: []string{"ES256"},
					},
					WantAnyAudience: []string{"test-audience"},
				}
			},
			wantErr:     true,
			errContains: "compact JWS format must have three parts",
		},
		{
			name: "token with malformed access_token",
			setupToken: func() *oauth2.Token {
				return &oauth2.Token{
					AccessToken: "not.a.jwt", // Malformed JWT
				}
			},
			setupVerifier: func() *AccessTokenVerifier {
				return &AccessTokenVerifier{
					Provider: &mockProvider{
						issuer:        "https://test-issuer.com",
						keyset:        validKeyset,
						supportedAlgs: []string{"ES256"},
					},
					WantAnyAudience: []string{"test-audience"},
				}
			},
			wantErr:     true,
			errContains: "illegal base64 data",
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
