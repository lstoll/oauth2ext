package oauth2as

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tink-crypto/tink-go/v2/jwt"
	"lds.li/oauth2ext/dpop"
	"lds.li/oauth2ext/oauth2as/internal/oauth2"
	"lds.li/oauth2ext/oauth2as/internal/token"
	"lds.li/oauth2ext/oidc"
)

// dpopVerifierAdapter adapts dpop.DPoPVerifier to oauth2as.DPoPVerifier
type dpopVerifierAdapter struct {
	verifier *dpop.DPoPVerifier
}

func (d *dpopVerifierAdapter) VerifyAndDecode(req *http.Request) (string, error) {
	dpopHeader := req.Header.Get("DPoP")
	if dpopHeader == "" {
		return "", fmt.Errorf("no DPoP header")
	}

	// Extract expected HTM and HTU from request
	result, err := d.verifier.VerifyAndDecodeWithOptions(dpopHeader, &dpop.VerifyOptions{
		ExpectedHTM: req.Method,
		ExpectedHTU: req.URL.String(),
	})
	if err != nil {
		return "", err
	}
	return result.Thumbprint, nil
}

func TestDPoPTokenFlow(t *testing.T) {
	const (
		issuer       = "https://issuer"
		clientID     = "client-id"
		clientSecret = "client-secret"
		redirectURI  = "https://redirect"
		userID       = "test-user"
	)

	// Generate DPoP key
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	encoder, err := dpop.NewDPopEncoder(privKey)
	if err != nil {
		t.Fatalf("failed to create encoder: %v", err)
	}

	// Setup server with DPoP verifier
	s := NewMemStorage()
	signer, verifier := testSignerVerifier(t)

	var capturedTokenRequest *TokenRequest

	server := &Server{
		config: Config{
			Issuer:   issuer,
			Storage:  s,
			Signer:   signer,
			Verifier: verifier,
			DPoPVerifier: &dpopVerifierAdapter{
				verifier: &dpop.DPoPVerifier{},
			},
			TokenHandler: func(_ context.Context, req *TokenRequest) (*TokenResponse, error) {
				capturedTokenRequest = req
				return &TokenResponse{}, nil
			},
			Clients: staticClientSource{
				{
					ID:           clientID,
					Secrets:      []string{clientSecret},
					RedirectURLs: []string{redirectURI},
					Opts:         []ClientOpt{ClientOptSkipPKCE()},
				},
			},
		},
		now: time.Now,
	}

	t.Run("Initial token exchange with DPoP", func(t *testing.T) {
		// Create a grant
		codeToken := newCodeGrant(t, server.config.Storage)

		// Create DPoP proof
		now := time.Now()
		dpopProof, err := encoder.SignAndEncode(&jwt.RawJWTOptions{
			WithoutExpiration: true,
			IssuedAt:          &now,
			CustomClaims: map[string]any{
				"htm": http.MethodPost,
				"htu": "/token",
			},
		})
		if err != nil {
			t.Fatalf("failed to create DPoP proof: %v", err)
		}

		// Create request with DPoP header
		req := httptest.NewRequest(http.MethodPost, "/token", nil)
		req.Header.Set("DPoP", dpopProof)

		treq := &oauth2.TokenRequest{
			GrantType:    oauth2.GrantTypeAuthorizationCode,
			Code:         codeToken,
			RedirectURI:  redirectURI,
			ClientID:     clientID,
			ClientSecret: clientSecret,
		}

		_, err = server.codeToken(context.Background(), req, treq)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify DPoP info was passed to token handler
		if !capturedTokenRequest.DPoPBound {
			t.Error("expected DPoPBound to be true")
		}
		if capturedTokenRequest.DPoPThumbprint == "" {
			t.Error("expected DPoPThumbprint to be set")
		}
		t.Logf("DPoP thumbprint from token request: %s", capturedTokenRequest.DPoPThumbprint)

		// Verify grant was updated with thumbprint
		grant, err := server.config.Storage.GetGrant(context.Background(), capturedTokenRequest.GrantID)
		if err != nil {
			t.Fatalf("failed to get grant: %v", err)
		}
		if grant == nil {
			t.Fatal("grant not found")
		}
		dpopThumbprintFromMetadata := ""
		if grant.Metadata != nil {
			dpopThumbprintFromMetadata = grant.Metadata[MetadataDPoPThumbprint]
		}
		t.Logf("Grant DPoP thumbprint from metadata: %s", dpopThumbprintFromMetadata)
		if dpopThumbprintFromMetadata == "" {
			t.Error("expected grant to have DPoP thumbprint in metadata")
		}
	})

	t.Run("Refresh with DPoP enforcement", func(t *testing.T) {
		// Create a DPoP-bound grant with refresh token
		grantID := uuid.New()
		refreshToken := token.New(tokenUsageRefresh)
		dpopThumbprint := "test-thumbprint-123"

		grant := &StoredGrant{
			ID:            grantID,
			UserID:        userID,
			ClientID:      clientID,
			GrantedScopes: []string{oidc.ScopeOpenID, oidc.ScopeOfflineAccess},
			RefreshToken:  refreshToken.Stored(),
			GrantedAt:     time.Now(),
			ExpiresAt:     time.Now().Add(24 * time.Hour),
			Metadata: map[string]string{
				MetadataDPoPThumbprint: dpopThumbprint,
			},
		}

		if err := server.config.Storage.CreateGrant(context.Background(), grant); err != nil {
			t.Fatalf("failed to create grant: %v", err)
		}

		// Create DPoP proof
		now := time.Now()
		dpopProof, err := encoder.SignAndEncode(&jwt.RawJWTOptions{
			WithoutExpiration: true,
			IssuedAt:          &now,
			CustomClaims: map[string]any{
				"htm": http.MethodPost,
				"htu": "/token",
			},
		})
		if err != nil {
			t.Fatalf("failed to create DPoP proof: %v", err)
		}

		// Calculate expected thumbprint by verifying the proof
		testReq := httptest.NewRequest(http.MethodPost, "/token", nil)
		testReq.Header.Set("DPoP", dpopProof)
		expectedThumbprint, err := server.config.DPoPVerifier.VerifyAndDecode(testReq)
		if err != nil {
			t.Fatalf("failed to verify proof: %v", err)
		}

		// Update grant with correct thumbprint in metadata
		if grant.Metadata == nil {
			grant.Metadata = make(map[string]string)
		}
		grant.Metadata[MetadataDPoPThumbprint] = expectedThumbprint
		if err := server.config.Storage.UpdateGrant(context.Background(), grant); err != nil {
			t.Fatalf("failed to update grant: %v", err)
		}

		t.Run("Refresh succeeds with valid DPoP proof", func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/token", nil)
			req.Header.Set("DPoP", dpopProof)

			treq := &oauth2.TokenRequest{
				GrantType:    oauth2.GrantTypeRefreshToken,
				RefreshToken: refreshToken.User(),
				ClientID:     clientID,
				ClientSecret: clientSecret,
			}

			capturedTokenRequest = nil
			_, err = server.refreshToken(context.Background(), req, treq)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Verify DPoP info was passed to token handler
			if !capturedTokenRequest.DPoPBound {
				t.Error("expected DPoPBound to be true")
			}
			if capturedTokenRequest.DPoPThumbprint == "" {
				t.Error("expected DPoPThumbprint to be set")
			}
		})

		t.Run("Refresh fails without DPoP proof", func(t *testing.T) {
			// Recreate grant since previous test consumed it
			refreshToken2 := token.New(tokenUsageRefresh)
			grant2 := &StoredGrant{
				ID:            uuid.New(),
				UserID:        userID,
				ClientID:      clientID,
				GrantedScopes: []string{oidc.ScopeOpenID, oidc.ScopeOfflineAccess},
				RefreshToken:  refreshToken2.Stored(),
				GrantedAt:     time.Now(),
				ExpiresAt:     time.Now().Add(24 * time.Hour),
				Metadata: map[string]string{
					MetadataDPoPThumbprint: expectedThumbprint,
				},
			}
			if err := server.config.Storage.CreateGrant(context.Background(), grant2); err != nil {
				t.Fatalf("failed to create grant: %v", err)
			}

			// Request without DPoP header
			req := httptest.NewRequest(http.MethodPost, "/token", nil)

			treq := &oauth2.TokenRequest{
				GrantType:    oauth2.GrantTypeRefreshToken,
				RefreshToken: refreshToken2.User(),
				ClientID:     clientID,
				ClientSecret: clientSecret,
			}

			_, err := server.refreshToken(context.Background(), req, treq)
			if err == nil {
				t.Fatal("expected error when DPoP proof is missing")
			}

			tokenErr, ok := err.(*oauth2.TokenError)
			if !ok {
				t.Fatalf("expected TokenError, got %T", err)
			}
			if tokenErr.ErrorCode != oauth2.TokenErrorCodeInvalidGrant {
				t.Errorf("expected invalid_grant error, got %s", tokenErr.ErrorCode)
			}
		})

		t.Run("Refresh fails with wrong DPoP key", func(t *testing.T) {
			// Generate different key
			wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatalf("failed to generate key: %v", err)
			}
			wrongEncoder, err := dpop.NewDPopEncoder(wrongKey)
			if err != nil {
				t.Fatalf("failed to create encoder: %v", err)
			}

			// Recreate grant
			refreshToken3 := token.New(tokenUsageRefresh)
			grant3 := &StoredGrant{
				ID:            uuid.New(),
				UserID:        userID,
				ClientID:      clientID,
				GrantedScopes: []string{oidc.ScopeOpenID, oidc.ScopeOfflineAccess},
				RefreshToken:  refreshToken3.Stored(),
				GrantedAt:     time.Now(),
				ExpiresAt:     time.Now().Add(24 * time.Hour),
				Metadata: map[string]string{
					MetadataDPoPThumbprint: expectedThumbprint,
				},
			}
			if err := server.config.Storage.CreateGrant(context.Background(), grant3); err != nil {
				t.Fatalf("failed to create grant: %v", err)
			}

			// Create DPoP proof with wrong key
			now := time.Now()
			wrongProof, err := wrongEncoder.SignAndEncode(&jwt.RawJWTOptions{
				WithoutExpiration: true,
				IssuedAt:          &now,
				CustomClaims: map[string]any{
					"htm": http.MethodPost,
					"htu": "/token",
				},
			})
			if err != nil {
				t.Fatalf("failed to create DPoP proof: %v", err)
			}

			req := httptest.NewRequest(http.MethodPost, "/token", nil)
			req.Header.Set("DPoP", wrongProof)

			treq := &oauth2.TokenRequest{
				GrantType:    oauth2.GrantTypeRefreshToken,
				RefreshToken: refreshToken3.User(),
				ClientID:     clientID,
				ClientSecret: clientSecret,
			}

			_, err = server.refreshToken(context.Background(), req, treq)
			if err == nil {
				t.Fatal("expected error when DPoP key doesn't match")
			}

			tokenErr, ok := err.(*oauth2.TokenError)
			if !ok {
				t.Fatalf("expected TokenError, got %T", err)
			}
			if tokenErr.ErrorCode != oauth2.TokenErrorCodeInvalidGrant {
				t.Errorf("expected invalid_grant error, got %s", tokenErr.ErrorCode)
			}
		})
	})
}
