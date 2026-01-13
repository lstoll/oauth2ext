package oauth2as

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tink-crypto/tink-go/v2/jwt"
	"lds.li/oauth2ext/dpop"
	"lds.li/oauth2ext/internal/th"
	"lds.li/oauth2ext/oauth2as/internal/oauth2"
	"lds.li/oauth2ext/oauth2as/internal/token"
	"lds.li/oauth2ext/oidc"
)

func TestDPoPTokenFlow(t *testing.T) {
	const (
		issuer       = "https://issuer"
		clientID     = "client-id"
		clientSecret = "client-secret"
		redirectURI  = "https://redirect"
		userID       = "test-user"
	)

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	dpopSigner, err := dpop.NewSigner(privKey)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	s := NewMemStorage()
	signer, verifier := testSignerVerifier(t)

	var capturedTokenRequest *TokenRequest

	server := &Server{
		config: Config{
			Issuer:       issuer,
			Storage:      s,
			Signer:       signer,
			Verifier:     verifier,
			DPoPVerifier: &dpop.Verifier{},
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
		codeToken := newCodeGrant(t, server.config.Storage)

		now := time.Now()
		dpopProof, err := dpopSigner.SignAndEncode(&jwt.RawJWTOptions{
			WithoutExpiration: true,
			IssuedAt:          &now,
			CustomClaims: map[string]any{
				"htm": http.MethodPost,
				"htu": issuer + "/token",
			},
		})
		if err != nil {
			t.Fatalf("failed to create DPoP proof: %v", err)
		}

		req := httptest.NewRequest(http.MethodPost, "/token", nil)
		req.Host = "localhost"
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

		// Verify grant was updated with thumbprint
		grant, err := server.config.Storage.GetGrant(context.Background(), capturedTokenRequest.GrantID)
		if err != nil {
			t.Fatalf("failed to get grant: %v", err)
		}

		var addState storedAdditionalState
		if len(grant.AdditionalState) > 0 {
			if err := json.Unmarshal(grant.AdditionalState, &addState); err != nil {
				t.Fatalf("failed to unmarshal additional state: %v", err)
			}
		}

		dpopThumbprintFromMetadata := ""
		if addState.DPoPThumbprint != nil {
			dpopThumbprintFromMetadata = *addState.DPoPThumbprint
		}

		t.Logf("Grant DPoP thumbprint from metadata: %s", dpopThumbprintFromMetadata)
		if dpopThumbprintFromMetadata == "" {
			t.Error("expected grant to have DPoP thumbprint in metadata")
		}
	})

	t.Run("Refresh with DPoP enforcement", func(t *testing.T) {
		// Create a DPoP-bound grant with refresh token
		dpopThumbprint := "test-thumbprint-123"

		addState := storedAdditionalState{
			DPoPThumbprint: &dpopThumbprint,
		}
		addStateBytes, _ := json.Marshal(addState)

		grant := &StoredGrant{
			UserID:          userID,
			ClientID:        clientID,
			GrantedScopes:   []string{oidc.ScopeOpenID, oidc.ScopeOfflineAccess},
			GrantedAt:       time.Now(),
			ExpiresAt:       time.Now().Add(24 * time.Hour),
			AdditionalState: addStateBytes,
		}

		grantID, err := server.config.Storage.CreateGrant(context.Background(), grant)
		if err != nil {
			t.Fatalf("failed to create grant: %v", err)
		}

		refreshToken := token.New(tokenUsageRefresh, grantID, userID)
		refreshTokenID := newUUIDv4()

		// Create token entry for the refresh token
		err = server.config.Storage.CreateRefreshToken(context.Background(), userID, grantID, refreshTokenID, &StoredRefreshToken{
			Token:            refreshToken.Stored(),
			GrantID:          grantID,
			UserID:           userID,
			ValidUntil:       time.Now().Add(24 * time.Hour),
			StorageExpiresAt: time.Now().Add(24 * time.Hour),
		})
		if err != nil {
			t.Fatalf("failed to create refresh token: %v", err)
		}
		refreshTokenStr := refreshToken.ToUser(refreshTokenID)

		now := time.Now()
		dpopProof, err := dpopSigner.SignAndEncode(&jwt.RawJWTOptions{
			WithoutExpiration: true,
			IssuedAt:          &now,
			CustomClaims: map[string]any{
				"htm": http.MethodPost,
				"htu": issuer + "/token",
			},
		})
		if err != nil {
			t.Fatalf("failed to create DPoP proof: %v", err)
		}

		// Calculate expected thumbprint by verifying the proof
		validator, err := dpop.NewValidator(&dpop.ValidatorOpts{
			ExpectedHTM:      th.Ptr(http.MethodPost),
			ExpectedHTU:      th.Ptr(issuer + "/token"),
			IgnoreThumbprint: true,
			AllowUnsetHTMHTU: true,
		})
		if err != nil {
			t.Fatalf("failed to create validator: %v", err)
		}
		result, err := server.config.DPoPVerifier.VerifyAndDecode(dpopProof, validator)
		if err != nil {
			t.Fatalf("failed to verify proof: %v", err)
		}
		expectedThumbprint := result.Thumbprint

		// Update grant with correct thumbprint in metadata
		addState.DPoPThumbprint = &expectedThumbprint
		addStateBytes, _ = json.Marshal(addState)
		grant.AdditionalState = addStateBytes

		if err := server.config.Storage.UpdateGrant(context.Background(), grantID, grant); err != nil {
			t.Fatalf("failed to update grant: %v", err)
		}

		t.Run("Refresh succeeds with valid DPoP proof", func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/token", nil)
			req.Host = "localhost"
			req.Header.Set("DPoP", dpopProof)

			treq := &oauth2.TokenRequest{
				GrantType:    oauth2.GrantTypeRefreshToken,
				RefreshToken: refreshTokenStr,
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
		})

		t.Run("Refresh fails without DPoP proof", func(t *testing.T) {
			// Recreate grant since previous test consumed it
			addState := storedAdditionalState{
				DPoPThumbprint: &expectedThumbprint,
			}
			addStateBytes, _ := json.Marshal(addState)

			grant2 := &StoredGrant{
				UserID:          userID,
				ClientID:        clientID,
				GrantedScopes:   []string{oidc.ScopeOpenID, oidc.ScopeOfflineAccess},
				GrantedAt:       time.Now(),
				ExpiresAt:       time.Now().Add(24 * time.Hour),
				AdditionalState: addStateBytes,
			}
			grantID2, err := server.config.Storage.CreateGrant(context.Background(), grant2)
			if err != nil {
				t.Fatalf("failed to create grant: %v", err)
			}

			refreshToken2 := token.New(tokenUsageRefresh, grantID2, userID)
			refreshTokenID2 := newUUIDv4()

			// Create token entry for the refresh token
			err = server.config.Storage.CreateRefreshToken(context.Background(), userID, grantID2, refreshTokenID2, &StoredRefreshToken{
				Token:            refreshToken2.Stored(),
				GrantID:          grantID2,
				UserID:           userID,
				ValidUntil:       time.Now().Add(24 * time.Hour),
				StorageExpiresAt: time.Now().Add(24 * time.Hour),
			})
			if err != nil {
				t.Fatalf("failed to create refresh token: %v", err)
			}
			refreshTokenStr2 := refreshToken2.ToUser(refreshTokenID2)

			// Request without DPoP header
			req := httptest.NewRequest(http.MethodPost, "/token", nil)

			treq := &oauth2.TokenRequest{
				GrantType:    oauth2.GrantTypeRefreshToken,
				RefreshToken: refreshTokenStr2,
				ClientID:     clientID,
				ClientSecret: clientSecret,
			}

			_, err = server.refreshToken(context.Background(), req, treq)
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
			wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatalf("failed to generate key: %v", err)
			}
			wrongSigner, err := dpop.NewSigner(wrongKey)
			if err != nil {
				t.Fatalf("failed to create signer: %v", err)
			}

			addState := storedAdditionalState{
				DPoPThumbprint: &expectedThumbprint,
			}
			addStateBytes, _ := json.Marshal(addState)

			grant3 := &StoredGrant{
				UserID:          userID,
				ClientID:        clientID,
				GrantedScopes:   []string{oidc.ScopeOpenID, oidc.ScopeOfflineAccess},
				GrantedAt:       time.Now(),
				ExpiresAt:       time.Now().Add(24 * time.Hour),
				AdditionalState: addStateBytes,
			}
			grantID3, err := server.config.Storage.CreateGrant(context.Background(), grant3)
			if err != nil {
				t.Fatalf("failed to create grant: %v", err)
			}

			refreshToken3 := token.New(tokenUsageRefresh, grantID3, userID)
			refreshTokenID3 := newUUIDv4()

			// Create token entry for the refresh token
			err = server.config.Storage.CreateRefreshToken(context.Background(), userID, grantID3, refreshTokenID3, &StoredRefreshToken{
				Token:            refreshToken3.Stored(),
				GrantID:          grantID3,
				UserID:           userID,
				ValidUntil:       time.Now().Add(24 * time.Hour),
				StorageExpiresAt: time.Now().Add(24 * time.Hour),
			})
			if err != nil {
				t.Fatalf("failed to create refresh token: %v", err)
			}
			refreshTokenStr3 := refreshToken3.ToUser(refreshTokenID3)

			// Create DPoP proof with wrong key
			now := time.Now()
			wrongProof, err := wrongSigner.SignAndEncode(&jwt.RawJWTOptions{
				WithoutExpiration: true,
				IssuedAt:          &now,
				CustomClaims: map[string]any{
					"htm": http.MethodPost,
					"htu": issuer + "/token",
				},
			})
			if err != nil {
				t.Fatalf("failed to create DPoP proof: %v", err)
			}

			req := httptest.NewRequest(http.MethodPost, "/token", nil)
			req.Host = "localhost"
			req.Header.Set("DPoP", wrongProof)

			treq := &oauth2.TokenRequest{
				GrantType:    oauth2.GrantTypeRefreshToken,
				RefreshToken: refreshTokenStr3,
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
